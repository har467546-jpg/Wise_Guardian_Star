from __future__ import annotations

import asyncio
import logging
import random
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID

from app.scanner.service_fingerprint import ServiceFingerprint, fingerprint_service

logger = logging.getLogger(__name__)

HTTP_PLAIN_PORTS = {80, 2375, 3000, 5601, 7001, 8000, 8080, 8081, 8180, 9000, 9090, 9200}
HTTP_TLS_PORTS = {443, 8443, 2376, 6443}
FTP_PORTS = {21, 2121}
RPCBIND_PORTS = {111}
REXEC_PORTS = {512}
RLOGIN_PORTS = {513}
RSH_PORTS = {514}
RMI_PORTS = {1099}
IRC_PORTS = {6667}
AJP_PORTS = {8009}

PROTOCOL_PROBE_REGISTRY: tuple[tuple[set[int], tuple[str, ...]], ...] = (
    (FTP_PORTS, ("ftp",)),
    ({22}, ("ssh",)),
    (HTTP_TLS_PORTS, ("http_tls", "http_plain")),
    (HTTP_PLAIN_PORTS, ("http_plain", "http_tls")),
    (RPCBIND_PORTS, ("rpcbind",)),
    (REXEC_PORTS, ("rexec",)),
    (RLOGIN_PORTS, ("rlogin",)),
    (RSH_PORTS, ("rsh",)),
    (RMI_PORTS, ("java_rmi",)),
    ({6379}, ("redis",)),
    ({3306}, ("mysql",)),
    ({5432}, ("postgresql",)),
    ({25, 587}, ("smtp_plain",)),
    ({465}, ("smtp_tls",)),
    ({110}, ("pop3_plain",)),
    ({995}, ("pop3_tls",)),
    ({143}, ("imap_plain",)),
    ({993}, ("imap_tls",)),
    ({23}, ("telnet",)),
    (IRC_PORTS, ("irc",)),
    (AJP_PORTS, ("ajp",)),
    ({11211}, ("memcached",)),
)


@dataclass(slots=True)
class PortScannerConfig:
    tcp_connect_timeout: float = 0.8
    banner_timeout: float = 1.5
    port_concurrency: int = 128
    read_size: int = 4096


@dataclass(slots=True)
class PortScanResult:
    port: int
    is_open: bool
    probe_method: str


@dataclass(slots=True)
class ProtocolProbeObservation:
    probe_name: str
    banner: str | None = None
    certificate_names: list[str] = field(default_factory=list)
    transport_service: str | None = None
    application_service: str | None = None
    product_name: str | None = None
    product_version: str | None = None
    tls_detected: bool = False
    evidence: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ServiceProbeResult:
    port: int
    service: str
    banner: str | None
    version: str | None
    hostname_hint: str | None
    probe_method: str
    fingerprint: ServiceFingerprint = field(repr=False)

    def to_dict(self) -> dict[str, str | int | bool | list[str] | None]:
        return self.fingerprint.to_dict()


class AsyncPortScanner:
    def __init__(self, config: PortScannerConfig | None = None) -> None:
        self.config = config or PortScannerConfig()
        self._port_semaphore = asyncio.Semaphore(self.config.port_concurrency)
        self._raw_socket_available: bool | None = None

    async def probe_liveness_batch(self, ip: str, ports: list[int]) -> list[PortScanResult]:
        return await self._gather_port_batches(ip, ports, self.probe_liveness)

    async def scan_ports(self, ip: str, ports: list[int]) -> list[PortScanResult]:
        return await self.probe_liveness_batch(ip, ports)

    async def probe_services(
        self,
        ip: str,
        port_results: list[PortScanResult],
    ) -> list[ServiceProbeResult]:
        open_results = [result for result in port_results if result.is_open]
        if not open_results:
            return []
        tasks = [asyncio.create_task(self._scan_service(ip, result)) for result in open_results]
        services = await asyncio.gather(*tasks)
        service_results = [item for item in services if item is not None]
        return sorted(service_results, key=lambda item: item.port)

    async def probe_liveness(self, ip: str, port: int) -> PortScanResult:
        async with self._port_semaphore:
            if self._raw_socket_available is None:
                self._raw_socket_available = self._can_use_raw_sockets()

            if self._raw_socket_available:
                syn_result = await asyncio.to_thread(self._probe_with_syn_blocking, ip, port)
                if syn_result is not None:
                    return PortScanResult(port=port, is_open=syn_result, probe_method="syn")

            return await self._probe_with_connect(ip, port)

    async def scan_host(
        self,
        ip: str,
        ports: list[int],
        liveness_results: list[PortScanResult] | None = None,
    ) -> tuple[list[PortScanResult], list[ServiceProbeResult]]:
        port_results = liveness_results or await self.scan_ports(ip, ports)
        service_results = await self.probe_services(ip, port_results)
        return port_results, service_results

    async def _scan_service(self, ip: str, result: PortScanResult) -> ServiceProbeResult | None:
        async with self._port_semaphore:
            fingerprint = await self.probe_service(ip, result.port, probe_method=result.probe_method)
        return ServiceProbeResult(
            port=result.port,
            service=fingerprint.service,
            banner=fingerprint.banner,
            version=fingerprint.version,
            hostname_hint=fingerprint.hostname_hint,
            probe_method=fingerprint.probe_method,
            fingerprint=fingerprint,
        )

    async def probe_service(self, ip: str, port: int, *, probe_method: str = "connect") -> ServiceFingerprint:
        passive = await self._run_probe(ip, port, "passive_read")
        passive_fingerprint = self._build_fingerprint(
            port=port,
            probe_method=probe_method,
            passive=passive,
            active=None,
        )
        best = passive_fingerprint

        for candidate in self._probe_candidates_for_port(port):
            active = await self._run_probe(ip, port, candidate)
            if active is None:
                continue
            fingerprint = self._build_fingerprint(
                port=port,
                probe_method=probe_method,
                passive=passive,
                active=active,
            )
            if self._fingerprint_rank(fingerprint) > self._fingerprint_rank(best):
                best = fingerprint
            if self._fingerprint_rank(fingerprint) >= 3:
                return fingerprint
        return best

    async def _run_probe(self, ip: str, port: int, probe_name: str) -> ProtocolProbeObservation | None:
        method = getattr(self, f"_probe_{probe_name}", None)
        if method is None:
            return None
        try:
            return await method(ip, port)
        except Exception as exc:  # pragma: no cover - network dependent
            logger.debug("protocol probe failed for %s:%s probe=%s: %s", ip, port, probe_name, exc)
            return None

    def _build_fingerprint(
        self,
        *,
        port: int,
        probe_method: str,
        passive: ProtocolProbeObservation | None,
        active: ProtocolProbeObservation | None,
    ) -> ServiceFingerprint:
        observations = [item for item in [passive, active] if item is not None]
        banner = next((item.banner for item in reversed(observations) if item.banner), None)
        certificate_names = _unique_strings(
            [name for item in observations for name in item.certificate_names if isinstance(name, str)]
        )
        evidence = _unique_strings(
            [evidence for item in observations for evidence in item.evidence if isinstance(evidence, str)]
        )
        probe_chain = _unique_strings([item.probe_name for item in observations if item.probe_name != "passive_read"])
        if passive is not None:
            probe_chain.insert(0, "passive_read")
        active_observation = active or passive

        return fingerprint_service(
            port=port,
            banner=banner,
            certificate_names=certificate_names,
            probe_method=probe_method,
            transport_service=active_observation.transport_service if active_observation else None,
            application_service=active_observation.application_service if active_observation else None,
            product_name=active_observation.product_name if active_observation else None,
            product_version=active_observation.product_version if active_observation else None,
            tls_detected=bool(active_observation.tls_detected if active_observation else False),
            evidence=evidence,
            probe_chain=probe_chain,
        )

    @staticmethod
    def _fingerprint_rank(fingerprint: ServiceFingerprint) -> int:
        if fingerprint.product_name and fingerprint.product_version and any(item != "passive_read" for item in fingerprint.probe_chain):
            return 4
        if fingerprint.product_name or fingerprint.application_service not in {None, "", "unknown"}:
            return 3
        if fingerprint.transport_service not in {None, "", "unknown"}:
            return 2
        if fingerprint.service != "unknown":
            return 1
        return 0

    @staticmethod
    def _probe_candidates_for_port(port: int) -> tuple[str, ...]:
        for ports, probes in PROTOCOL_PROBE_REGISTRY:
            if port in ports:
                return probes
        return ()

    async def grab_banner(self, ip: str, port: int) -> tuple[str | None, list[str]]:
        fingerprint = await self.probe_service(ip, port)
        return fingerprint.banner, [fingerprint.hostname_hint] if fingerprint.hostname_hint else []

    async def _probe_with_connect(self, ip: str, port: int) -> PortScanResult:
        writer: asyncio.StreamWriter | None = None
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.config.tcp_connect_timeout,
            )
            return PortScanResult(port=port, is_open=True, probe_method="connect")
        except Exception:
            return PortScanResult(port=port, is_open=False, probe_method="connect")
        finally:
            if writer is not None:
                await _close_writer(writer)

    async def _gather_port_batches(self, ip: str, ports: list[int], probe) -> list[PortScanResult]:
        if not ports:
            return []
        batch_size = max(self.config.port_concurrency * 4, 256)
        results: list[PortScanResult] = []
        for index in range(0, len(ports), batch_size):
            batch = ports[index : index + batch_size]
            tasks = [asyncio.create_task(probe(ip, port)) for port in batch]
            results.extend(await asyncio.gather(*tasks))
        return sorted(results, key=lambda item: item.port)

    def _can_use_raw_sockets(self) -> bool:
        try:
            sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except OSError:
            return False
        finally:
            for sock in ("sender", "receiver"):
                handle = locals().get(sock)
                if handle is not None:
                    handle.close()
        return True

    def _probe_with_syn_blocking(self, ip: str, port: int) -> bool | None:
        try:
            source_ip = self._get_source_ip(ip, port)
            source_port = random.randint(32768, 60999)
            sequence = random.randint(0, 0xFFFFFFFF)
            packet = self._build_syn_packet(source_ip, ip, source_port, port, sequence)

            sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            receiver.settimeout(self.config.tcp_connect_timeout)

            sender.sendto(packet, (ip, port))

            deadline = time.monotonic() + self.config.tcp_connect_timeout
            while time.monotonic() < deadline:
                packet_bytes, _ = receiver.recvfrom(65535)
                if len(packet_bytes) < 40:
                    continue

                ip_header_length = (packet_bytes[0] & 0x0F) * 4
                src_ip = socket.inet_ntoa(packet_bytes[12:16])
                dst_ip = socket.inet_ntoa(packet_bytes[16:20])
                if src_ip != ip or dst_ip != source_ip:
                    continue

                tcp_header = packet_bytes[ip_header_length : ip_header_length + 20]
                src_port_recv, dst_port_recv, _, _, _, flags, _, _, _ = struct.unpack("!HHLLBBHHH", tcp_header)
                if src_port_recv != port or dst_port_recv != source_port:
                    continue
                if flags & 0x12 == 0x12:
                    return True
                if flags & 0x04:
                    return False
            return False
        except PermissionError:
            return None
        except socket.timeout:
            return False
        except OSError:
            return None
        finally:
            for sock in ("sender", "receiver"):
                handle = locals().get(sock)
                if handle is not None:
                    handle.close()

    def _get_source_ip(self, ip: str, port: int) -> str:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect((ip, port))
            return probe.getsockname()[0]
        finally:
            probe.close()

    def _build_syn_packet(self, source_ip: str, target_ip: str, source_port: int, target_port: int, sequence: int) -> bytes:
        ip_header = self._build_ip_header(source_ip, target_ip)
        tcp_header = self._build_tcp_header(source_ip, target_ip, source_port, target_port, sequence)
        return ip_header + tcp_header

    def _build_ip_header(self, source_ip: str, target_ip: str) -> bytes:
        version_ihl = (4 << 4) + 5
        total_length = 20 + 20
        packet_id = random.randint(0, 65535)
        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            0,
            total_length,
            packet_id,
            0,
            64,
            socket.IPPROTO_TCP,
            0,
            socket.inet_aton(source_ip),
            socket.inet_aton(target_ip),
        )
        checksum = _checksum(header)
        return struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            0,
            total_length,
            packet_id,
            0,
            64,
            socket.IPPROTO_TCP,
            checksum,
            socket.inet_aton(source_ip),
            socket.inet_aton(target_ip),
        )

    def _build_tcp_header(self, source_ip: str, target_ip: str, source_port: int, target_port: int, sequence: int) -> bytes:
        offset_reserved = 5 << 4
        flags = 0x02
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            source_port,
            target_port,
            sequence,
            0,
            offset_reserved,
            flags,
            socket.htons(64240),
            0,
            0,
        )
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(source_ip),
            socket.inet_aton(target_ip),
            0,
            socket.IPPROTO_TCP,
            len(tcp_header),
        )
        checksum = _checksum(pseudo_header + tcp_header)
        return struct.pack(
            "!HHLLBBHHH",
            source_port,
            target_port,
            sequence,
            0,
            offset_reserved,
            flags,
            socket.htons(64240),
            checksum,
            0,
        )

    async def _probe_passive_read(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="passive_read",
                banner=_decode_banner(raw),
                evidence=[f"passive_read_bytes={len(raw)}"] if raw else [],
            )
        finally:
            await _close_writer(writer)

    async def _probe_ssh(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            banner = await asyncio.wait_for(reader.readline(), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="ssh",
                banner=_decode_banner(banner),
                transport_service="ssh",
                application_service="ssh",
                evidence=["ssh_banner"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_ftp(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(
            ip,
            port,
            probe_name="ftp",
            transport_service="ftp",
            application_service="ftp",
        )

    async def _probe_rpcbind(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="rpcbind",
            transport_service="rpcbind",
            application_service="rpcbind",
            product_name="rpcbind",
        )

    async def _probe_http_plain(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_http(ip, port, use_tls=False, probe_name="http_plain")

    async def _probe_http_tls(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_http(ip, port, use_tls=True, probe_name="http_tls")

    async def _probe_http(self, ip: str, port: int, *, use_tls: bool, probe_name: str) -> ProtocolProbeObservation:
        context = None
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=ip if use_tls else None),
            timeout=self.config.banner_timeout,
        )
        try:
            certificate_names: list[str] = []
            if use_tls:
                ssl_object = writer.get_extra_info("ssl_object")
                certificate_names = self._extract_certificate_names(ssl_object)

            request = f"GET / HTTP/1.0\r\nHost: {ip}\r\nConnection: close\r\nAccept: */*\r\n\r\n".encode()
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(self.config.read_size), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name=probe_name,
                banner=raw.decode("iso-8859-1", errors="ignore").strip() or None,
                certificate_names=certificate_names,
                transport_service="https" if use_tls else "http",
                tls_detected=use_tls,
                evidence=["http_probe"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_redis(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            writer.write(b"PING\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="redis",
                banner=_decode_banner(raw),
                transport_service="redis",
                application_service="redis",
                product_name="redis",
                evidence=["redis_ping"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_mysql(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="mysql",
                banner=raw.decode("latin-1", errors="ignore").strip() or None,
                transport_service="mysql",
                application_service="mysql",
                product_name="mysql",
                evidence=["mysql_greeting"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_postgresql(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            writer.write(struct.pack("!II", 8, 80877103))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(64), timeout=self.config.banner_timeout)
            banner = _decode_banner(raw)
            if raw[:1] not in {b"S", b"N"}:
                raise OSError("unexpected PostgreSQL SSL negotiation response")
            return ProtocolProbeObservation(
                probe_name="postgresql",
                banner=banner,
                transport_service="postgresql",
                application_service="postgresql",
                product_name="postgresql",
                tls_detected=raw[:1] == b"S",
                evidence=[f"postgresql_ssl_response={banner or raw[:1].decode('latin-1', errors='ignore')}"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_rexec(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="rexec",
            transport_service="rexec",
            application_service="rexec",
            product_name="rexec",
        )

    async def _probe_rlogin(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="rlogin",
            transport_service="rlogin",
            application_service="rlogin",
            product_name="rlogin",
        )

    async def _probe_rsh(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="rsh",
            transport_service="rsh",
            application_service="rsh",
            product_name="rsh",
        )

    async def _probe_smtp_plain(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="smtp_plain", transport_service="smtp", application_service="smtp")

    async def _probe_smtp_tls(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="smtp_tls", transport_service="smtps", application_service="smtp", use_tls=True)

    async def _probe_pop3_plain(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="pop3_plain", transport_service="pop3", application_service="pop3")

    async def _probe_pop3_tls(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="pop3_tls", transport_service="pop3s", application_service="pop3", use_tls=True)

    async def _probe_imap_plain(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="imap_plain", transport_service="imap", application_service="imap")

    async def _probe_imap_tls(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_line_banner(ip, port, probe_name="imap_tls", transport_service="imaps", application_service="imap", use_tls=True)

    async def _probe_telnet(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            if not raw:
                writer.write(b"\r\n")
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="telnet",
                banner=_decode_banner(raw),
                transport_service="telnet",
                application_service="telnet",
                product_name="telnet",
                evidence=["telnet_probe"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_java_rmi(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="java_rmi",
            transport_service="java-rmi",
            application_service="java-rmi",
            product_name="java-rmi",
        )

    async def _probe_irc(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="irc",
            transport_service="irc",
            application_service="irc",
            product_name="irc",
            send_bytes=b"CAP LS\r\n",
        )

    async def _probe_ajp(self, ip: str, port: int) -> ProtocolProbeObservation:
        return await self._probe_protocol_hint(
            ip,
            port,
            probe_name="ajp",
            transport_service="ajp13",
            application_service="ajp13",
            product_name="ajp13",
        )

    async def _probe_memcached(self, ip: str, port: int) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            writer.write(b"version\r\n")
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(128), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name="memcached",
                banner=_decode_banner(raw),
                transport_service="memcached",
                application_service="memcached",
                product_name="memcached",
                evidence=["memcached_version"],
            )
        finally:
            await _close_writer(writer)

    async def _probe_line_banner(
        self,
        ip: str,
        port: int,
        *,
        probe_name: str,
        transport_service: str,
        application_service: str,
        use_tls: bool = False,
    ) -> ProtocolProbeObservation:
        context = None
        certificate_names: list[str] = []
        if use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=context, server_hostname=ip if use_tls else None),
            timeout=self.config.banner_timeout,
        )
        try:
            if use_tls:
                ssl_object = writer.get_extra_info("ssl_object")
                certificate_names = self._extract_certificate_names(ssl_object)
            raw = await asyncio.wait_for(reader.readline(), timeout=self.config.banner_timeout)
            return ProtocolProbeObservation(
                probe_name=probe_name,
                banner=_decode_banner(raw),
                certificate_names=certificate_names,
                transport_service=transport_service,
                application_service=application_service,
                tls_detected=use_tls,
                evidence=[probe_name],
            )
        finally:
            await _close_writer(writer)

    async def _probe_protocol_hint(
        self,
        ip: str,
        port: int,
        *,
        probe_name: str,
        transport_service: str,
        application_service: str,
        product_name: str,
        send_bytes: bytes | None = None,
    ) -> ProtocolProbeObservation:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=self.config.banner_timeout,
        )
        try:
            if send_bytes:
                writer.write(send_bytes)
                await writer.drain()
            try:
                raw = await asyncio.wait_for(reader.read(256), timeout=self.config.banner_timeout)
            except asyncio.TimeoutError:
                raw = b""
            return ProtocolProbeObservation(
                probe_name=probe_name,
                banner=_decode_banner(raw),
                transport_service=transport_service,
                application_service=application_service,
                product_name=product_name,
                evidence=[f"{probe_name}_probe"],
            )
        finally:
            await _close_writer(writer)

    def _extract_certificate_names(self, ssl_object: ssl.SSLObject | None) -> list[str]:
        if ssl_object is None:
            return []
        certificate_bytes = ssl_object.getpeercert(binary_form=True)
        if not certificate_bytes:
            return []

        names: list[str] = []
        certificate = x509.load_der_x509_certificate(certificate_bytes)
        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if attribute.value:
                names.append(attribute.value.lower())
        try:
            extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names.extend(item.lower() for item in extension.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        return list(dict.fromkeys(names))


def _decode_banner(raw: bytes) -> str | None:
    if not raw:
        return None
    return raw.decode("latin-1", errors="ignore").strip() or None


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        ordered.append(cleaned)
    return ordered


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


def _checksum(packet: bytes) -> int:
    if len(packet) % 2 == 1:
        packet += b"\0"
    words = struct.unpack(f"!{len(packet) // 2}H", packet)
    total = sum(words)
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF
