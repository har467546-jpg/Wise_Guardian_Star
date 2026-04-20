from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET

from app.scanner.port_catalog import resolve_scan_ports
from app.scanner.port_scanner import AsyncPortScanner, PortScanResult, PortScannerConfig
from app.utils.net import find_local_ipv4_interface_for_network

logger = logging.getLogger(__name__)


class DiscoveryLivenessError(RuntimeError):
    """Raised when host liveness discovery cannot produce trustworthy results."""


@dataclass(slots=True)
class HostLiveness:
    ip: str
    icmp_alive: bool
    tcp_alive: bool


@dataclass(slots=True)
class HostDiscoveryRecord:
    ip: str
    sources: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)

    def merge(self, *, source: str, evidence: str | None = None) -> None:
        normalized_source = source.strip().lower()
        if normalized_source:
            self.sources.add(normalized_source)
        normalized_evidence = str(evidence or "").strip()
        if normalized_evidence and normalized_evidence not in self.evidence:
            self.evidence.append(normalized_evidence)

    def to_host_payload(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "discovery_sources": sorted(self.sources),
            "discovery_evidence": list(self.evidence),
        }


@dataclass(slots=True)
class DiscoveryConfig:
    liveness_ports: tuple[int, ...] = (22, 80, 443, 8080, 8443)
    liveness_mode: str = "multi_source"
    service_ports: tuple[int, ...] = (
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        111,
        135,
        139,
        143,
        443,
        445,
        465,
        587,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        2376,
        3000,
        3306,
        3389,
        5432,
        5601,
        5672,
        5900,
        5984,
        6379,
        6443,
        7001,
        8000,
        8080,
        8081,
        8443,
        9000,
        9090,
        9200,
        9300,
        11211,
        27017,
    )
    high_backdoor_ports: tuple[int, ...] = (
        1337,
        4444,
        5555,
        6666,
        6667,
        6969,
        7007,
        10001,
        10008,
        12345,
        12346,
        16000,
        20001,
        30001,
        40001,
        50001,
        19191,
        20034,
        27374,
        31337,
        32764,
        54321,
        55555,
        60000,
        65000,
    )
    portset_mode: str = "top1000_plus_custom"
    top_ports_limit: int = 1000
    nmap_min_rate: int = 100000
    icmp_timeout: float = 1.0
    nmap_liveness_timeout_seconds: int = 90
    nmap_full_scan_timeout_seconds: int = 90
    tcp_connect_timeout: float = 0.8
    banner_timeout: float = 1.5
    enable_arp_discovery: bool = True
    enable_fping: bool = True
    nmap_host_discovery_profile: str = "balanced"
    host_concurrency: int = 256
    full_scan_host_concurrency: int = 8
    service_probe_host_concurrency: int = 32
    port_concurrency: int = 256


@dataclass(slots=True)
class DiscoveryResult:
    ip: str
    hostname: str | None
    ports: list[int]
    services: list[dict[str, object]]
    discovery_sources: list[str] = field(default_factory=list)
    discovery_evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "ports": self.ports,
            "services": self.services,
            "discovery_sources": list(self.discovery_sources),
            "discovery_evidence": list(self.discovery_evidence),
        }


class AsyncNetworkDiscovery:
    def __init__(
        self,
        config: DiscoveryConfig | None = None,
        port_scanner: AsyncPortScanner | None = None,
    ) -> None:
        self.config = config or DiscoveryConfig()
        self.port_scanner = port_scanner or AsyncPortScanner(
            PortScannerConfig(
                tcp_connect_timeout=self.config.tcp_connect_timeout,
                banner_timeout=self.config.banner_timeout,
                port_concurrency=self.config.port_concurrency,
            )
        )
        self._host_semaphore = asyncio.Semaphore(self.config.host_concurrency)
        self._full_scan_host_semaphore = asyncio.Semaphore(max(1, self.config.full_scan_host_concurrency))
        self._service_probe_host_semaphore = asyncio.Semaphore(max(1, self.config.service_probe_host_concurrency))
        self._liveness_ports = sorted(set(self.config.liveness_ports))
        self._liveness_mode = self._normalize_liveness_mode(self.config.liveness_mode)
        self._scan_ports = list(
            resolve_scan_ports(
                curated_ports=self.config.service_ports,
                high_backdoor_ports=self.config.high_backdoor_ports,
                mode=self.config.portset_mode,
                top_ports_limit=self.config.top_ports_limit,
            )
        )

    @property
    def scan_ports(self) -> tuple[int, ...]:
        return tuple(self._scan_ports)

    async def discover(self, cidr: str, include_services: bool = True) -> list[DiscoveryResult]:
        network = ipaddress.ip_network(cidr, strict=False)
        if self._liveness_mode in {"nmap_icmp", "multi_source"}:
            live_hosts = await self._discover_live_hosts_with_sources(str(network))
            if include_services:
                return await self.scan_known_hosts([record.to_host_payload() for record in live_hosts])
            return await self._build_liveness_only_results(live_hosts)
        tasks = [asyncio.create_task(self._discover_host(str(host), include_services=include_services)) for host in network.hosts()]
        results = await asyncio.gather(*tasks)
        discovered = [item for item in results if item is not None]
        return sorted(discovered, key=lambda item: item.ip)

    async def scan_known_hosts(self, hosts: list[dict[str, object]]) -> list[DiscoveryResult]:
        tasks = [
            asyncio.create_task(self._scan_known_host_entry(host))
            for host in hosts
            if isinstance(host, dict)
        ]
        results = await asyncio.gather(*tasks)
        discovered = [item for item in results if item is not None]
        return sorted(discovered, key=lambda item: item.ip)

    async def scan_known_hosts_ports_only(self, hosts: list[dict[str, object]]) -> list[DiscoveryResult]:
        if self._should_use_nmap_full_port_scan():
            tasks = [
                asyncio.create_task(self._scan_known_host_ports_only_with_nmap_entry(host))
                for host in hosts
                if isinstance(host, dict)
            ]
            results = await asyncio.gather(*tasks)
            discovered = [item for item in results if item is not None]
            return sorted(discovered, key=lambda item: item.ip)
        tasks = [
            asyncio.create_task(self._scan_known_host_ports_only_entry(host))
            for host in hosts
            if isinstance(host, dict)
        ]
        results = await asyncio.gather(*tasks)
        discovered = [item for item in results if item is not None]
        return sorted(discovered, key=lambda item: item.ip)

    async def probe_known_open_ports(self, hosts: list[dict[str, object]]) -> list[DiscoveryResult]:
        tasks = [
            asyncio.create_task(self._probe_known_open_ports_entry(host))
            for host in hosts
            if isinstance(host, dict)
        ]
        results = await asyncio.gather(*tasks)
        discovered = [item for item in results if item is not None]
        return sorted(discovered, key=lambda item: item.ip)

    async def _scan_known_host_entry(self, host: dict[str, object]) -> DiscoveryResult | None:
        async with self._service_probe_host_semaphore:
            return await self._scan_host_services(
                ip=str(host.get("ip") or "").strip(),
                known_hostname=host.get("hostname") if isinstance(host.get("hostname"), str) else None,
                discovery_sources=self._extract_host_list(host.get("discovery_sources")),
                discovery_evidence=self._extract_host_list(host.get("discovery_evidence")),
            )

    async def _scan_known_host_ports_only_entry(self, host: dict[str, object]) -> DiscoveryResult | None:
        async with self._full_scan_host_semaphore:
            return await self._scan_host_ports(
                ip=str(host.get("ip") or "").strip(),
                known_hostname=host.get("hostname") if isinstance(host.get("hostname"), str) else None,
                discovery_sources=self._extract_host_list(host.get("discovery_sources")),
                discovery_evidence=self._extract_host_list(host.get("discovery_evidence")),
            )

    async def _scan_known_host_ports_only_with_nmap_entry(self, host: dict[str, object]) -> DiscoveryResult | None:
        async with self._full_scan_host_semaphore:
            return await self._scan_host_ports_with_nmap(
                ip=str(host.get("ip") or "").strip(),
                known_hostname=host.get("hostname") if isinstance(host.get("hostname"), str) else None,
                discovery_sources=self._extract_host_list(host.get("discovery_sources")),
                discovery_evidence=self._extract_host_list(host.get("discovery_evidence")),
            )

    async def _probe_known_open_ports_entry(self, host: dict[str, object]) -> DiscoveryResult | None:
        raw_ports = host.get("ports")
        open_ports: list[int] = []
        if isinstance(raw_ports, list):
            for item in raw_ports:
                value = item.get("port") if isinstance(item, dict) else item
                try:
                    port = int(value)
                except (TypeError, ValueError):
                    continue
                if 1 <= port <= 65535:
                    open_ports.append(port)
        async with self._service_probe_host_semaphore:
            return await self._probe_host_open_ports(
                ip=str(host.get("ip") or "").strip(),
                open_ports=sorted(set(open_ports)),
                known_hostname=host.get("hostname") if isinstance(host.get("hostname"), str) else None,
                discovery_sources=self._extract_host_list(host.get("discovery_sources")),
                discovery_evidence=self._extract_host_list(host.get("discovery_evidence")),
            )

    async def _discover_host(self, ip: str, *, include_services: bool) -> DiscoveryResult | None:
        async with self._host_semaphore:
            icmp_task = asyncio.create_task(self.icmp_ping(ip))
            tcp_task = asyncio.create_task(self.tcp_host_probe(ip))
            icmp_alive, liveness_results = await asyncio.gather(icmp_task, tcp_task)
            tcp_alive = any(result.is_open for result in liveness_results)
            if not (icmp_alive or tcp_alive):
                return None
            discovery_sources: list[str] = []
            discovery_evidence: list[str] = []
            if icmp_alive:
                discovery_sources.append("icmp_ping")
                discovery_evidence.append("icmp_ping_success")
            if tcp_alive:
                discovery_sources.append("tcp_connect")
                discovery_evidence.append(
                    "tcp_connect_open_ports="
                    + ",".join(str(result.port) for result in liveness_results if result.is_open)
                )

            if include_services:
                return await self._scan_host_services(
                    ip,
                    liveness_results=liveness_results,
                    discovery_sources=discovery_sources,
                    discovery_evidence=discovery_evidence,
                )

            return DiscoveryResult(
                ip=ip,
                hostname=None,
                ports=[],
                services=[],
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )

    async def _scan_host_ports(
        self,
        ip: str,
        *,
        known_hostname: str | None = None,
        discovery_sources: list[str] | None = None,
        discovery_evidence: list[str] | None = None,
    ) -> DiscoveryResult | None:
        if not ip:
            return None
        port_results = await self.port_scanner.scan_ports(ip, list(self._scan_ports))
        return DiscoveryResult(
            ip=ip,
            hostname=known_hostname,
            ports=[result.port for result in port_results if result.is_open],
            services=[],
            discovery_sources=list(discovery_sources or []),
            discovery_evidence=list(discovery_evidence or []),
        )

    async def _scan_host_ports_with_nmap(
        self,
        ip: str,
        *,
        known_hostname: str | None = None,
        discovery_sources: list[str] | None = None,
        discovery_evidence: list[str] | None = None,
    ) -> DiscoveryResult | None:
        if not ip:
            return None
        if not self._has_nmap():
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )

        cmd = [
            "nmap",
            "-Pn",
            "-n",
            "-T5",
            "--min-rate",
            str(max(1, int(self.config.nmap_min_rate))),
            "--open",
            "-p-",
            ip,
            "-oX",
            "-",
        ]
        timeout_seconds = max(1, int(self.config.nmap_full_scan_timeout_seconds))
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=float(timeout_seconds))
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.warning("nmap full port scan timeout for host=%s, fallback to python scanner", ip)
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )
        except FileNotFoundError:
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("nmap full port scan failed for host=%s: %s, fallback to python scanner", ip, exc)
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )

        if process.returncode not in {0, 1}:
            logger.warning(
                "nmap full port scan non-zero exit for host=%s: rc=%s stderr=%s, fallback to python scanner",
                ip,
                process.returncode,
                stderr.decode("utf-8", errors="ignore").strip(),
            )
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )

        open_ports = self.parse_nmap_full_scan_xml_output(ip, stdout.decode("utf-8", errors="ignore"))
        if open_ports is None:
            logger.warning("nmap full port scan XML parse failed for host=%s, fallback to python scanner", ip)
            return await self._scan_host_ports(
                ip,
                known_hostname=known_hostname,
                discovery_sources=discovery_sources,
                discovery_evidence=discovery_evidence,
            )

        return DiscoveryResult(
            ip=ip,
            hostname=known_hostname,
            ports=open_ports,
            services=[],
            discovery_sources=list(discovery_sources or []),
            discovery_evidence=list(discovery_evidence or []),
        )

    async def _scan_host_services(
        self,
        ip: str,
        *,
        known_hostname: str | None = None,
        liveness_results: list[PortScanResult] | None = None,
        discovery_sources: list[str] | None = None,
        discovery_evidence: list[str] | None = None,
    ) -> DiscoveryResult | None:
        if not ip:
            return None
        port_results, service_results = await self.port_scanner.scan_host(
            ip,
            list(self._scan_ports),
            liveness_results=liveness_results,
        )
        hostname = self._pick_hostname(service_results) or known_hostname

        return DiscoveryResult(
            ip=ip,
            hostname=hostname,
            ports=[result.port for result in port_results if result.is_open],
            services=[result.to_dict() for result in service_results],
            discovery_sources=list(discovery_sources or []),
            discovery_evidence=list(discovery_evidence or []),
        )

    async def _probe_host_open_ports(
        self,
        ip: str,
        *,
        open_ports: list[int],
        known_hostname: str | None = None,
        discovery_sources: list[str] | None = None,
        discovery_evidence: list[str] | None = None,
    ) -> DiscoveryResult | None:
        if not ip:
            return None
        port_results = [PortScanResult(port=port, is_open=True, probe_method="connect") for port in open_ports]
        service_results = await self.port_scanner.probe_services(ip, port_results)
        hostname = self._pick_hostname(service_results) or known_hostname
        return DiscoveryResult(
            ip=ip,
            hostname=hostname,
            ports=sorted(open_ports),
            services=[result.to_dict() for result in service_results],
            discovery_sources=list(discovery_sources or []),
            discovery_evidence=list(discovery_evidence or []),
        )

    async def icmp_ping(self, ip: str) -> bool:
        timeout = str(max(1, int(self.config.icmp_timeout)))
        try:
            process = await asyncio.create_subprocess_exec(
                "ping",
                "-c",
                "1",
                "-W",
                timeout,
                ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return False
        except Exception as exc:  # pragma: no cover - subprocess dependent
            logger.debug("icmp ping failed for %s: %s", ip, exc)
            return False

        try:
            await asyncio.wait_for(process.wait(), timeout=self.config.icmp_timeout + 1)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            return False
        return process.returncode == 0

    async def tcp_host_probe(self, ip: str) -> list[PortScanResult]:
        return await self.port_scanner.probe_liveness_batch(ip, list(self._liveness_ports))

    async def _build_liveness_only_results(self, live_hosts: list[HostDiscoveryRecord]) -> list[DiscoveryResult]:
        tasks = [asyncio.create_task(self._build_liveness_only_result(record)) for record in live_hosts]
        if not tasks:
            return []
        results = await asyncio.gather(*tasks)
        return sorted(results, key=lambda item: ipaddress.ip_address(item.ip))

    async def _build_liveness_only_result(self, record: HostDiscoveryRecord) -> DiscoveryResult:
        async with self._host_semaphore:
            return DiscoveryResult(
                ip=record.ip,
                hostname=None,
                ports=[],
                services=[],
                discovery_sources=sorted(record.sources),
                discovery_evidence=list(record.evidence),
            )

    async def _discover_live_hosts_with_sources(self, cidr: str) -> list[HostDiscoveryRecord]:
        network = ipaddress.ip_network(cidr, strict=False)
        records: dict[str, HostDiscoveryRecord] = {}
        errors: list[str] = []
        attempted_sources = 0

        if self._liveness_mode == "nmap_icmp":
            if not self._has_nmap():
                raise DiscoveryLivenessError("nmap 不可用，无法执行批量 nmap 探活")
            attempted_sources += 1
            self._merge_host_candidates(
                records,
                await self._discover_live_hosts_with_nmap(str(network)),
                source="nmap_host_discovery",
            )
            return sorted(records.values(), key=lambda item: ipaddress.ip_address(item.ip))

        local_interface = find_local_ipv4_interface_for_network(network) if isinstance(network, ipaddress.IPv4Network) else None
        if self.config.enable_arp_discovery and local_interface is not None:
            attempted_sources += 1
            arp_error: DiscoveryLivenessError | None = None
            if self._has_arp_scan():
                try:
                    self._merge_host_candidates(
                        records,
                        await self._discover_live_hosts_with_arp_scan(str(network), interface_name=local_interface.name),
                        source="arp_scan",
                    )
                except DiscoveryLivenessError as exc:
                    arp_error = exc
                    errors.append(str(exc))
            if not self._has_arp_scan() and self._has_arping():
                try:
                    self._merge_host_candidates(
                        records,
                        await self._discover_live_hosts_with_arping(str(network), interface_name=local_interface.name),
                        source="arping",
                    )
                except DiscoveryLivenessError as exc:
                    arp_error = exc
                    errors.append(str(exc))
            if not self._has_arp_scan() and not self._has_arping():
                errors.append(f"同网段 {network} 缺少 arp-scan/arping，可用 ARP 探活已跳过")
            elif arp_error is not None and self._has_arping():
                try:
                    self._merge_host_candidates(
                        records,
                        await self._discover_live_hosts_with_arping(str(network), interface_name=local_interface.name),
                        source="arping",
                    )
                except DiscoveryLivenessError as exc:
                    errors.append(str(exc))

        if self.config.enable_fping and self._has_fping():
            attempted_sources += 1
            try:
                self._merge_host_candidates(
                    records,
                    await self._discover_live_hosts_with_fping(str(network)),
                    source="fping",
                )
            except DiscoveryLivenessError as exc:
                errors.append(str(exc))

        if self._has_nmap():
            attempted_sources += 1
            try:
                self._merge_host_candidates(
                    records,
                    await self._discover_live_hosts_with_nmap(str(network)),
                    source="nmap_host_discovery",
                )
            except DiscoveryLivenessError as exc:
                errors.append(str(exc))

        if attempted_sources == 0:
            raise DiscoveryLivenessError("未找到可用的主机发现工具")
        if not records and errors and attempted_sources == len(errors):
            raise DiscoveryLivenessError("；".join(errors))
        return sorted(records.values(), key=lambda item: ipaddress.ip_address(item.ip))

    @staticmethod
    def _merge_host_candidates(
        records: dict[str, HostDiscoveryRecord],
        hosts: list[str],
        *,
        source: str,
    ) -> None:
        for ip in hosts:
            record = records.get(ip)
            if record is None:
                record = HostDiscoveryRecord(ip=ip)
                records[ip] = record
            record.merge(source=source, evidence=f"{source}:{ip}")

    @staticmethod
    def _pick_hostname(service_results: list[object]) -> str | None:
        for result in service_results:
            hostname_hint = getattr(result, "hostname_hint", None)
            if hostname_hint:
                return hostname_hint
        return None

    @staticmethod
    def _normalize_liveness_mode(value: str | None) -> str:
        normalized = (value or "multi_source").strip().lower()
        if normalized == "icmp_only":
            return "nmap_icmp"
        if normalized in {"hybrid", "tcp_connect"}:
            return "tcp_connect"
        if normalized not in {"multi_source", "nmap_icmp", "tcp_connect"}:
            return "multi_source"
        return normalized

    @staticmethod
    def _has_nmap() -> bool:
        return shutil.which("nmap") is not None

    @staticmethod
    def _has_arp_scan() -> bool:
        return shutil.which("arp-scan") is not None

    @staticmethod
    def _has_arping() -> bool:
        return shutil.which("arping") is not None

    @staticmethod
    def _has_fping() -> bool:
        return shutil.which("fping") is not None

    def _should_use_nmap_full_port_scan(self) -> bool:
        return bool(
            self.config.portset_mode == "full"
            and self._scan_ports
            and len(self._scan_ports) == 65535
            and self._scan_ports[0] == 1
            and self._scan_ports[-1] == 65535
        )

    @classmethod
    def parse_nmap_ping_xml_output(cls, output: str) -> list[str]:
        try:
            root = ET.fromstring(output)
        except ET.ParseError as exc:
            raise DiscoveryLivenessError("nmap 批量 ICMP 探活 XML 解析失败") from exc

        live_hosts: set[str] = set()
        for host in root.findall("host"):
            status_node = host.find("status")
            if status_node is None or status_node.get("state") != "up":
                continue
            address_node = next(
                (node for node in host.findall("address") if node.get("addrtype") == "ipv4"),
                None,
            )
            if address_node is None:
                continue
            ip = (address_node.get("addr") or "").strip()
            if not ip:
                continue
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            live_hosts.add(ip)
        return sorted(live_hosts, key=ipaddress.ip_address)

    async def _discover_live_hosts_with_nmap(self, cidr: str) -> list[str]:
        if not self._has_nmap():
            raise DiscoveryLivenessError("nmap 不可用，无法执行批量 nmap 探活")

        cmd = [
            "nmap",
            "-sn",
            "-n",
            "-PE",
            "-PS22,80,443,445,3389",
            "-PA80,443,445,3389",
        ]
        if self.config.nmap_host_discovery_profile.strip().lower() == "aggressive":
            cmd.append("-PU53,161")
        cmd.extend(
            [
                "-T4",
                "--min-rate",
                str(max(1, int(self.config.nmap_min_rate))),
                cidr,
                "-oX",
                "-",
            ]
        )
        timeout_seconds = max(1, int(self.config.nmap_liveness_timeout_seconds))
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=float(timeout_seconds))
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise DiscoveryLivenessError(f"nmap 批量探活超时（>{timeout_seconds}秒）") from exc
        except FileNotFoundError as exc:
            raise DiscoveryLivenessError("nmap 不可用，无法执行批量探活") from exc
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("nmap liveness discovery failed for cidr=%s: %s", cidr, exc)
            raise DiscoveryLivenessError(f"nmap 批量探活执行失败: {exc}") from exc

        if process.returncode not in {0, 1}:
            stderr_text = stderr.decode("utf-8", errors="ignore").strip()
            message = f"nmap 批量探活失败，退出码={process.returncode}"
            if stderr_text:
                message = f"{message}: {stderr_text}"
            raise DiscoveryLivenessError(message)

        return self.parse_nmap_ping_xml_output(stdout.decode("utf-8", errors="ignore"))

    async def _discover_live_hosts_with_fping(self, cidr: str) -> list[str]:
        cmd = ["fping", "-a", "-q", "-r0", "-g", cidr]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=float(max(5, int(self.config.nmap_liveness_timeout_seconds))),
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise DiscoveryLivenessError("fping 批量探活超时") from exc
        except FileNotFoundError as exc:
            raise DiscoveryLivenessError("fping 不可用") from exc
        except Exception as exc:  # pragma: no cover - runtime dependent
            raise DiscoveryLivenessError(f"fping 批量探活失败: {exc}") from exc

        if process.returncode not in {0, 1}:
            stderr_text = stderr.decode("utf-8", errors="ignore").strip()
            raise DiscoveryLivenessError(f"fping 批量探活失败: {stderr_text or process.returncode}")

        discovered: set[str] = set()
        for raw_line in stdout.decode("utf-8", errors="ignore").splitlines():
            candidate = raw_line.strip()
            if not candidate:
                continue
            try:
                discovered.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        return sorted(discovered, key=ipaddress.ip_address)

    async def _discover_live_hosts_with_arp_scan(self, cidr: str, *, interface_name: str) -> list[str]:
        cmd = [
            "arp-scan",
            "--interface",
            interface_name,
            "--retry=1",
            "--timeout=250",
            "--ignoredups",
            "--plain",
            cidr,
        ]
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30.0)
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise DiscoveryLivenessError(f"arp-scan 扫描 {cidr} 超时") from exc
        except FileNotFoundError as exc:
            raise DiscoveryLivenessError("arp-scan 不可用") from exc
        except Exception as exc:  # pragma: no cover - runtime dependent
            raise DiscoveryLivenessError(f"arp-scan 执行失败: {exc}") from exc

        if process.returncode not in {0, 1}:
            stderr_text = stderr.decode("utf-8", errors="ignore").strip()
            raise DiscoveryLivenessError(f"arp-scan 执行失败: {stderr_text or process.returncode}")
        return self.parse_arp_scan_output(stdout.decode("utf-8", errors="ignore"))

    async def _discover_live_hosts_with_arping(self, cidr: str, *, interface_name: str) -> list[str]:
        network = ipaddress.ip_network(cidr, strict=False)
        if not isinstance(network, ipaddress.IPv4Network):
            return []
        if network.num_addresses > 1024:
            raise DiscoveryLivenessError(f"arping 回退不支持大网段 {cidr}")

        semaphore = asyncio.Semaphore(64)
        tasks = [
            asyncio.create_task(self._arping_one_host(semaphore, interface_name=interface_name, ip=str(host)))
            for host in network.hosts()
        ]
        results = [item for item in await asyncio.gather(*tasks) if item]
        return sorted(set(results), key=ipaddress.ip_address)

    async def _arping_one_host(
        self,
        semaphore: asyncio.Semaphore,
        *,
        interface_name: str,
        ip: str,
    ) -> str | None:
        async with semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    "arping",
                    "-c",
                    "1",
                    "-w",
                    "1",
                    "-I",
                    interface_name,
                    ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except Exception:
                return None
            return ip if process.returncode == 0 else None

    @staticmethod
    def parse_arp_scan_output(output: str) -> list[str]:
        discovered: set[str] = set()
        for raw_line in output.splitlines():
            parts = raw_line.strip().split()
            if not parts:
                continue
            candidate = parts[0].strip()
            try:
                discovered.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue
        return sorted(discovered, key=ipaddress.ip_address)

    @staticmethod
    def _extract_host_list(value: object) -> list[str]:
        if not isinstance(value, list):
            return []
        normalized: list[str] = []
        for item in value:
            text = str(item or "").strip()
            if text:
                normalized.append(text)
        return normalized

    @classmethod
    def parse_nmap_full_scan_xml_output(cls, ip: str, output: str) -> list[int] | None:
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return None

        open_ports: set[int] = set()
        for host in root.findall("host"):
            address_node = next(
                (node for node in host.findall("address") if node.get("addrtype") == "ipv4"),
                None,
            )
            if address_node is None or (address_node.get("addr") or "").strip() != ip:
                continue
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for port_node in ports_node.findall("port"):
                if port_node.get("protocol") != "tcp":
                    continue
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                try:
                    port = int(port_node.get("portid") or "")
                except ValueError:
                    continue
                if 1 <= port <= 65535:
                    open_ports.add(port)
        return sorted(open_ports)
