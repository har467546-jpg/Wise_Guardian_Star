from __future__ import annotations

import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.scanner.nmap_nse import compact_nse_results
from app.scanner.service_fingerprint import DEFAULT_SERVICE_BY_PORT, fingerprint_service, infer_service_aliases

logger = logging.getLogger(__name__)

RISKY_PORTS = {22, 3306, 5432, 6379}
WEB_PORTS = {80, 443, 8080, 8443}
DB_PORTS = {3306, 5432}
CACHE_PORTS = {6379}
ADMIN_PORTS = {22}

OS_HINT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ubuntu", "Ubuntu"),
    ("debian", "Debian"),
    ("centos", "CentOS"),
    ("rocky", "Rocky Linux"),
    ("alpine", "Alpine Linux"),
    ("windows", "Windows"),
)
BACKDOOR_RISK_NOTE = "命中高位后门特征端口列表"
BACKDOOR_VERSION_SKIP_REASON = "后门候选端口，已跳过版本识别"
BACKDOOR_NMAP_SKIP_REASON = "backdoor_candidate_policy"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _normalize_service(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower()
    return normalized or "unknown"


def _normalize_version(version: Any) -> str | None:
    if not isinstance(version, str):
        return None
    cleaned = version.strip()
    return cleaned or None


def _banner_evidence(banner: Any) -> str | None:
    if not isinstance(banner, str):
        return None
    cleaned = " ".join(banner.strip().split())
    if not cleaned:
        return None
    if len(cleaned) > 120:
        cleaned = f"{cleaned[:117]}..."
    return f"banner={cleaned}"


def _effective_service_name(record: dict[str, Any]) -> str:
    for key in ("application_service", "service", "service_name", "transport_service"):
        value = _normalize_service(record.get(key))
        if value != "unknown":
            return value
    return "unknown"


def _effective_product_name(record: dict[str, Any]) -> str | None:
    value = _normalize_service(record.get("product_name"))
    if value == "unknown":
        return None
    return value


def _effective_product_version(record: dict[str, Any]) -> str | None:
    for key in ("product_version", "version", "service_version"):
        value = _normalize_version(record.get(key))
        if value:
            return value
    return None


def get_nmap_skip_reason(port: int | None, record: dict[str, Any] | None, high_backdoor_ports: set[int]) -> str | None:
    normalized_port = _to_port(port)
    if normalized_port is None:
        return None
    if not isinstance(record, dict):
        return BACKDOOR_NMAP_SKIP_REASON if normalized_port in high_backdoor_ports else None
    high_backdoor_candidate = normalized_port in high_backdoor_ports or record.get("backdoor_candidate") is True
    if high_backdoor_candidate and not _has_explicit_service_evidence(record, normalized_port):
        return BACKDOOR_NMAP_SKIP_REASON
    fingerprint_json = record.get("fingerprint_json")
    if isinstance(fingerprint_json, dict) and fingerprint_json.get("backdoor_candidate") is True and not _has_explicit_service_evidence(record, normalized_port):
        return BACKDOOR_NMAP_SKIP_REASON
    return None


def is_nmap_enrichment_blocked(port: int | None, record: dict[str, Any] | None, high_backdoor_ports: set[int]) -> bool:
    return get_nmap_skip_reason(port, record, high_backdoor_ports) is not None


def _is_port_guess_only(record: dict[str, Any], port: int, service: str) -> bool:
    default_service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
    return (
        service == default_service
        and not record.get("banner")
        and not _effective_product_name(record)
        and not _effective_product_version(record)
        and _normalize_service(record.get("application_service")) in {"unknown", default_service}
        and _normalize_service(record.get("transport_service")) in {"unknown", default_service}
    )


def _has_explicit_service_evidence(record: dict[str, Any], port: int) -> bool:
    service = _effective_service_name(record)
    product_name = _effective_product_name(record)
    product_version = _effective_product_version(record)
    if product_name:
        return True
    if isinstance(record.get("banner"), str) and record.get("banner", "").strip():
        return True
    if isinstance(record.get("nse_summary"), dict) and int(record["nse_summary"].get("hit_count") or 0) > 0:
        return True
    if isinstance(record.get("nse"), dict) and any(
        isinstance(payload, dict) and payload.get("hit") is True for payload in record["nse"].values()
    ):
        return True
    aliases = set(infer_service_aliases(record))
    default_service = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
    if aliases and aliases != {default_service}:
        return True
    if service != "unknown" and service != default_service:
        return True
    if product_version and service != "unknown" and not _is_port_guess_only(record, port, service):
        return True
    return False


def enrich_python_service_record(port: int, record: dict[str, Any], identified_at: str | None = None) -> dict[str, Any]:
    service = _effective_service_name(record)
    transport_service = _normalize_service(record.get("transport_service") or record.get("service") or record.get("service_name"))
    if transport_service == "unknown" and service != "unknown":
        transport_service = service
    application_service = _normalize_service(record.get("application_service") or service)
    product_name = _effective_product_name(record)
    product_version = _effective_product_version(record)
    banner = record.get("banner")
    probe_method = str(record.get("probe_method") or "connect")
    hostname_hint = record.get("hostname_hint")
    tls_detected = bool(record.get("tls_detected") is True)
    evidence = [item for item in record.get("evidence", []) if isinstance(item, str)] if isinstance(record.get("evidence"), list) else []
    probe_chain = [item for item in record.get("probe_chain", []) if isinstance(item, str)] if isinstance(record.get("probe_chain"), list) else []

    if service == "unknown":
        confidence = 20
        reason = "未识别到有效服务特征"
    elif product_name and product_version:
        confidence = 95
        reason = "原生协议探测识别到产品与版本"
    elif product_name or (application_service != "unknown" and application_service != transport_service) or (transport_service != "unknown" and probe_chain):
        confidence = 80
        reason = "原生协议探测识别到协议或产品"
    elif _is_port_guess_only(record, port, service):
        confidence = 60
        reason = "仅基于端口默认映射推断服务"
    else:
        confidence = 80
        reason = "命中 banner 识别规则"

    merged_evidence: list[str] = [f"port={port}", f"service={service}", f"probe={probe_method}"]
    if transport_service != "unknown":
        merged_evidence.append(f"transport={transport_service}")
    if product_name:
        merged_evidence.append(f"product={product_name}")
    if product_version:
        merged_evidence.append(f"product_version={product_version}")
    banner_item = _banner_evidence(banner)
    if banner_item:
        merged_evidence.append(banner_item)
    merged_evidence.extend(evidence)

    return {
        "port": port,
        "service": service,
        "banner": banner if isinstance(banner, str) else None,
        "version": product_version,
        "hostname_hint": hostname_hint if isinstance(hostname_hint, str) else None,
        "probe_method": probe_method,
        "transport_service": transport_service if transport_service != "unknown" else None,
        "application_service": application_service if application_service != "unknown" else None,
        "product_name": product_name,
        "product_version": product_version,
        "tls_detected": tls_detected,
        "source": "py",
        "confidence": confidence,
        "reason": reason,
        "evidence": _unique_strings(merged_evidence),
        "probe_chain": _unique_strings(probe_chain),
        "nmap_service": None,
        "nmap_product": None,
        "identified_at": identified_at or _iso_now(),
        "service_aliases": infer_service_aliases(
            {
                "port": port,
                "service": service,
                "banner": banner if isinstance(banner, str) else None,
                "version": product_version,
                "product_name": product_name,
                "product_version": product_version,
                "transport_service": transport_service if transport_service != "unknown" else None,
                "application_service": application_service if application_service != "unknown" else None,
                "tls_detected": tls_detected,
            }
        ),
    }


def needs_nmap_enrichment(record: dict[str, Any], threshold: int) -> bool:
    service = _effective_service_name(record)
    confidence = int(record.get("confidence") or 0)
    product_name = _effective_product_name(record)
    product_version = _effective_product_version(record)
    if service == "unknown":
        return True
    if confidence < threshold:
        return True
    if product_name is None:
        return True
    if product_version is None:
        return True
    return False


def merge_service_records(
    py_record: dict[str, Any],
    nmap_record: dict[str, Any] | None,
    *,
    nmap_blocked: bool = False,
) -> dict[str, Any]:
    if nmap_blocked or not nmap_record:
        winner = dict(py_record)
        if nmap_blocked:
            winner["nmap_service"] = None
            winner["nmap_product"] = None
            if not winner.get("source"):
                winner["source"] = "py"
        return winner

    py_rank = _record_rank(py_record)
    nmap_rank = _record_rank(nmap_record)
    if nmap_rank > py_rank:
        winner = dict(nmap_record)
        fallback = py_record
    else:
        winner = dict(py_record)
        fallback = nmap_record

    winner["port"] = _to_port(winner.get("port")) or _to_port(fallback.get("port"))
    winner["banner"] = winner.get("banner") or fallback.get("banner")
    winner["hostname_hint"] = winner.get("hostname_hint") or fallback.get("hostname_hint")
    winner["transport_service"] = winner.get("transport_service") or fallback.get("transport_service")
    winner["application_service"] = winner.get("application_service") or fallback.get("application_service")
    winner["product_name"] = winner.get("product_name") or fallback.get("product_name")
    winner["product_version"] = winner.get("product_version") or fallback.get("product_version")
    winner["version"] = winner.get("product_version") or winner.get("version") or fallback.get("product_version") or fallback.get("version")
    winner["tls_detected"] = bool(winner.get("tls_detected") is True or fallback.get("tls_detected") is True)
    winner["nmap_service"] = nmap_record.get("nmap_service") or nmap_record.get("service")
    winner["nmap_product"] = nmap_record.get("nmap_product") or nmap_record.get("product_name")
    winner["evidence"] = _unique_strings(
        [item for item in py_record.get("evidence", []) if isinstance(item, str)]
        + [item for item in nmap_record.get("evidence", []) if isinstance(item, str)]
    )
    winner["probe_chain"] = _unique_strings(
        [item for item in py_record.get("probe_chain", []) if isinstance(item, str)]
        + [item for item in nmap_record.get("probe_chain", []) if isinstance(item, str)]
    )
    if not winner.get("identified_at"):
        winner["identified_at"] = _iso_now()

    winner["service"] = _effective_service_name(winner)
    if winner["service"] == "unknown":
        winner["service"] = _effective_service_name(fallback)
    winner["service_aliases"] = infer_service_aliases(winner)
    return winner


def apply_port_risk_annotation(record: dict[str, Any], high_backdoor_ports: set[int]) -> dict[str, Any]:
    annotated = dict(record)
    port = _to_port(annotated.get("port"))
    nmap_skip_reason = get_nmap_skip_reason(port, annotated, high_backdoor_ports)
    is_backdoor_candidate = bool((port is not None and port in high_backdoor_ports) or annotated.get("backdoor_candidate") is True)
    annotated["port_category"] = "high_backdoor_candidate" if is_backdoor_candidate else "standard"
    annotated["backdoor_candidate"] = is_backdoor_candidate
    annotated["risk_note"] = BACKDOOR_RISK_NOTE if is_backdoor_candidate else ""
    annotated["nmap_skipped"] = bool(nmap_skip_reason)
    annotated["nmap_skip_reason"] = nmap_skip_reason or ""
    if nmap_skip_reason:
        annotated["version"] = None
        annotated["product_version"] = None
        annotated["nmap_service"] = None
        annotated["nmap_product"] = None
        annotated["version_skipped"] = True
        annotated["version_skip_reason"] = BACKDOOR_VERSION_SKIP_REASON
    else:
        annotated["version_skipped"] = False
        annotated["version_skip_reason"] = ""
    return annotated


def to_fingerprint_json(record: dict[str, Any]) -> dict[str, Any]:
    port_category = str(record.get("port_category") or "standard")
    backdoor_candidate = bool(record.get("backdoor_candidate") is True)
    risk_note_raw = record.get("risk_note")
    risk_note = risk_note_raw.strip() if isinstance(risk_note_raw, str) else ""
    nmap_skipped = bool(record.get("nmap_skipped") is True)
    nmap_skip_reason_raw = record.get("nmap_skip_reason")
    nmap_skip_reason = nmap_skip_reason_raw.strip() if isinstance(nmap_skip_reason_raw, str) else ""
    version_skipped = bool(record.get("version_skipped") is True)
    version_skip_reason_raw = record.get("version_skip_reason")
    version_skip_reason = version_skip_reason_raw.strip() if isinstance(version_skip_reason_raw, str) else ""
    nse_last_phase_raw = record.get("nse_last_phase")
    nse_last_phase = nse_last_phase_raw.strip() if isinstance(nse_last_phase_raw, str) else ""
    nse_last_collected_at_raw = record.get("nse_last_collected_at")
    nse_last_collected_at = nse_last_collected_at_raw.strip() if isinstance(nse_last_collected_at_raw, str) else ""
    return {
        "confidence": int(record.get("confidence") or 0),
        "reason": str(record.get("reason") or ""),
        "source": str(record.get("source") or "py"),
        "evidence": record.get("evidence") if isinstance(record.get("evidence"), list) else [],
        "identified_at": str(record.get("identified_at") or _iso_now()),
        "probe_method": str(record.get("probe_method") or ""),
        "probe_chain": record.get("probe_chain") if isinstance(record.get("probe_chain"), list) else [],
        "banner": record.get("banner") if isinstance(record.get("banner"), str) else None,
        "hostname_hint": record.get("hostname_hint") if isinstance(record.get("hostname_hint"), str) else None,
        "transport_service": record.get("transport_service") if isinstance(record.get("transport_service"), str) else None,
        "application_service": record.get("application_service") if isinstance(record.get("application_service"), str) else None,
        "product_name": record.get("product_name") if isinstance(record.get("product_name"), str) else None,
        "product_version": record.get("product_version") if isinstance(record.get("product_version"), str) else None,
        "service_aliases": infer_service_aliases(record),
        "tls_detected": bool(record.get("tls_detected") is True),
        "nmap_service": record.get("nmap_service") if isinstance(record.get("nmap_service"), str) else None,
        "nmap_product": record.get("nmap_product") if isinstance(record.get("nmap_product"), str) else None,
        "port_category": "high_backdoor_candidate" if port_category == "high_backdoor_candidate" else "standard",
        "backdoor_candidate": backdoor_candidate,
        "risk_note": risk_note,
        "nmap_skipped": nmap_skipped,
        "nmap_skip_reason": nmap_skip_reason,
        "version_skipped": version_skipped,
        "version_skip_reason": version_skip_reason,
        "nse": compact_nse_results(record.get("nse") if isinstance(record.get("nse"), dict) else {}),
        "nse_summary": record.get("nse_summary") if isinstance(record.get("nse_summary"), dict) else {},
        "nse_last_phase": nse_last_phase,
        "nse_last_collected_at": nse_last_collected_at,
    }


def build_network_initial_snapshot(ip: str, hostname: str | None, services: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any], str]:
    service_names = [_effective_service_name(item) for item in services]
    ports = sorted({_to_port(item.get("port")) for item in services if _to_port(item.get("port")) is not None})
    known_services = [name for name in service_names if name != "unknown"]
    unknown_count = sum(1 for name in service_names if name == "unknown")
    nse_hit_count = sum(
        int((item.get("nse_summary") or {}).get("hit_count") or 0)
        for item in services
        if isinstance(item, dict) and isinstance(item.get("nse_summary"), dict)
    )

    os_guess = _guess_os_from_services(services)
    role_guess = _guess_role(ports, service_names)
    exposure_stats = {
        "open_port_count": len(ports),
        "web_port_count": len([port for port in ports if port in WEB_PORTS]),
        "risky_port_count": len([port for port in ports if port in RISKY_PORTS]),
        "known_service_count": len(known_services),
        "unknown_service_count": unknown_count,
    }

    observations: list[str] = [f"识别到 {len(ports)} 个开放端口"]
    if known_services:
        observations.append(f"已识别服务 {len(known_services)} 项")
    if unknown_count:
        observations.append(f"仍有 {unknown_count} 项服务未识别")
    if nse_hit_count:
        observations.append(f"NSE 命中 {nse_hit_count} 项脚本结果")
    if role_guess != "General service node":
        observations.append(f"用途推测为 {role_guess}")

    confidence_breakdown = {
        "high": len([item for item in services if int(item.get("confidence") or 0) >= 80]),
        "low": len([item for item in services if int(item.get("confidence") or 0) < 80]),
    }

    summary = {
        "ip": ip,
        "hostname": hostname,
        "os_guess": os_guess,
        "role_guess": role_guess,
        "exposure_stats": exposure_stats,
        "key_observations": observations,
    }
    detail = {
        "ports": ports,
        "services": services,
        "confidence_breakdown": confidence_breakdown,
        "nse_hit_count": nse_hit_count,
    }

    if services and confidence_breakdown["high"] > 0:
        status = "success"
    elif services:
        status = "partial"
    else:
        status = "failed"
    return summary, detail, status


def _guess_os_from_services(services: list[dict[str, Any]]) -> str | None:
    blob = " ".join(
        " ".join(
            [
                str(item.get("product_name") or ""),
                str(item.get("product_version") or ""),
                str(item.get("banner") or ""),
            ]
        )
        for item in services
        if isinstance(item, dict)
    ).lower()
    for needle, os_name in OS_HINT_PATTERNS:
        if needle in blob:
            return os_name
    return None


def _guess_role(ports: list[int], service_names: list[str]) -> str:
    port_set = set(ports)
    name_set = set(service_names)
    if port_set & DB_PORTS or name_set.intersection({"mysql", "postgresql"}):
        return "Database node"
    if port_set & CACHE_PORTS or "redis" in name_set:
        return "Cache node"
    if port_set & WEB_PORTS or name_set.intersection({"http", "https", "nginx", "apache", "tomcat", "kibana", "elasticsearch"}):
        return "Web service node"
    if port_set & ADMIN_PORTS or name_set.intersection({"ssh", "telnet"}):
        return "Remote administration node"
    return "General service node"


@dataclass(slots=True)
class AsyncNmapServiceEnricher:
    mode: str = "enrich"
    timeout_seconds: int = 8
    host_concurrency: int = 16
    version_intensity: int = 7
    last_timeout_count: int = 0
    last_error_count: int = 0

    async def enrich_hosts(self, targets: list[dict[str, Any]]) -> dict[str, dict[int, dict[str, Any]]]:
        self.last_timeout_count = 0
        self.last_error_count = 0
        if self.mode != "enrich":
            return {}
        if not self._has_nmap():
            logger.info("nmap not available, skip enrichment")
            return {}

        semaphore = asyncio.Semaphore(max(1, self.host_concurrency))
        tasks = [
            asyncio.create_task(self._run_one_target(semaphore, target))
            for target in targets
            if isinstance(target, dict) and target.get("ip") and target.get("ports")
        ]
        if not tasks:
            return {}

        results = await asyncio.gather(*tasks)
        self.last_timeout_count = sum(1 for _, _, status in results if status == "timeout")
        self.last_error_count = sum(1 for _, _, status in results if status == "error")
        return {ip: by_port for ip, by_port, _ in results if ip and by_port}

    def _has_nmap(self) -> bool:
        return shutil.which("nmap") is not None

    async def _run_one_target(
        self,
        semaphore: asyncio.Semaphore,
        target: dict[str, Any],
    ) -> tuple[str, dict[int, dict[str, Any]], str]:
        ip = str(target.get("ip"))
        ports = sorted({_to_port(item) for item in target.get("ports", []) if _to_port(item) is not None})
        blocked_ports = {_to_port(item) for item in target.get("blocked_ports", []) if _to_port(item) is not None}
        if blocked_ports:
            ports = [port for port in ports if port not in blocked_ports]
        if not ip or not ports:
            return ip, {}, "skipped"

        async with semaphore:
            cmd = [
                "nmap",
                "-Pn",
                "-n",
                "-sV",
                "--version-intensity",
                str(max(0, int(self.version_intensity))),
                "-p",
                ",".join(str(port) for port in ports),
                ip,
                "-oX",
                "-",
            ]
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=float(self.timeout_seconds))
            except asyncio.TimeoutError:
                logger.info("nmap enrichment timeout for host=%s", ip)
                return ip, {}, "timeout"
            except FileNotFoundError:
                return ip, {}, "error"
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.info("nmap enrichment failed for host=%s: %s", ip, exc)
                return ip, {}, "error"

            if process.returncode not in {0, 1}:
                logger.info(
                    "nmap enrichment non-zero exit for host=%s: rc=%s stderr=%s",
                    ip,
                    process.returncode,
                    stderr.decode("utf-8", errors="ignore"),
                )
                return ip, {}, "error"
            return ip, self.parse_xml_output(ip, stdout.decode("utf-8", errors="ignore")), "ok"

    @classmethod
    def parse_xml_output(cls, ip: str, output: str) -> dict[int, dict[str, Any]]:
        by_port: dict[int, dict[str, Any]] = {}
        try:
            root = ET.fromstring(output)
        except ET.ParseError:
            return by_port

        for host in root.findall("host"):
            address_node = host.find("address")
            if address_node is None or address_node.get("addr") != ip:
                continue
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for port_node in ports_node.findall("port"):
                port = _to_port(port_node.get("portid"))
                if port is None:
                    continue
                state_node = port_node.find("state")
                if state_node is None or state_node.get("state") != "open":
                    continue
                service_node = port_node.find("service")
                raw_name = (service_node.get("name") if service_node is not None else "") or ""
                raw_product = (service_node.get("product") if service_node is not None else "") or ""
                raw_version = (service_node.get("version") if service_node is not None else "") or ""
                raw_extrainfo = (service_node.get("extrainfo") if service_node is not None else "") or ""
                raw_tunnel = (service_node.get("tunnel") if service_node is not None else "") or ""

                evidence = [f"nmap_service={raw_name or 'unknown'}"]
                if raw_product:
                    evidence.append(f"nmap_product={raw_product}")
                if raw_version:
                    evidence.append(f"nmap_version={raw_version}")
                if raw_extrainfo:
                    evidence.append(f"nmap_extrainfo={raw_extrainfo}")
                if raw_tunnel:
                    evidence.append(f"nmap_tunnel={raw_tunnel}")
                for cpe in service_node.findall("cpe") if service_node is not None else []:
                    if cpe.text:
                        evidence.append(f"nmap_cpe={cpe.text.strip()}")

                banner_summary = " ".join(item for item in [raw_name, raw_product, raw_version, raw_extrainfo] if item).strip() or None
                tls_detected = raw_tunnel.lower() == "ssl"
                transport_service = cls._normalize_nmap_transport(raw_name, port, tls_detected)
                fingerprint = fingerprint_service(
                    port=port,
                    banner=banner_summary,
                    certificate_names=[],
                    probe_method="nmap",
                    transport_service=transport_service,
                    product_name=raw_product or raw_name,
                    product_version=raw_version or None,
                    tls_detected=tls_detected,
                    evidence=evidence,
                    probe_chain=["nmap"],
                    nmap_service=raw_name or None,
                    nmap_product=raw_product or None,
                )
                record = fingerprint.to_dict()
                if fingerprint.product_name and fingerprint.product_version:
                    confidence = 90
                    reason = "nmap 识别到产品与版本"
                elif fingerprint.application_service not in {None, "unknown"} or fingerprint.transport_service not in {None, "unknown"}:
                    confidence = 80
                    reason = "nmap 识别到协议或产品"
                else:
                    confidence = 20
                    reason = "nmap 未识别到明确服务"
                record.update(
                    {
                        "source": "nmap",
                        "confidence": confidence,
                        "reason": reason,
                        "identified_at": _iso_now(),
                        "service": _effective_service_name(record),
                        "version": record.get("product_version"),
                    }
                )
                by_port[port] = record
        return by_port

    @staticmethod
    def _normalize_nmap_transport(raw_service: str, port: int, tls_detected: bool) -> str:
        value = _normalize_service(raw_service)
        if tls_detected and "http" in value:
            return "https"
        if value == "ssl/http":
            return "https"
        if value in {"submission", "smtp"}:
            return "smtp"
        if value == "imap":
            return "imap"
        if value == "pop3":
            return "pop3"
        if value != "unknown":
            return value
        default = DEFAULT_SERVICE_BY_PORT.get(port, "unknown")
        if tls_detected and default == "http":
            return "https"
        return default


def _record_rank(record: dict[str, Any]) -> int:
    source = str(record.get("source") or "")
    product_name = _effective_product_name(record)
    product_version = _effective_product_version(record)
    service = _effective_service_name(record)
    if source == "py" and product_name and product_version:
        return 5
    if source == "nmap" and product_name and product_version:
        return 4
    if product_name:
        return 3
    if service != "unknown" and int(record.get("confidence") or 0) >= 80:
        return 2
    if service != "unknown":
        return 1
    return 0


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
