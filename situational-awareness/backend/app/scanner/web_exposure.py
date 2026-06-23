from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, field
from html import unescape
from typing import Any
from urllib.parse import urlparse


WEB_SERVICE_ALIASES = {"http", "https", "apache", "nginx", "tomcat", "php", "phpmyadmin", "twiki", "weblogic", "kibana"}
DEFAULT_HTTP_PORTS = {80, 8000, 8080, 8081, 8180, 9000, 9090, 9200}
DEFAULT_HTTPS_PORTS = {443, 8443, 6443, 2376}
CDN_CNAME_KEYWORDS = (
    ("cloudflare", "cloudflare"),
    ("cloudfront", "aws_cloudfront"),
    ("akamai", "akamai"),
    ("fastly", "fastly"),
    ("edgekey", "akamai"),
    ("edgesuite", "akamai"),
    ("edgecast", "edgecast"),
    ("azureedge", "azure_cdn"),
    ("trafficmanager", "azure_traffic_manager"),
    ("chinacache", "chinacache"),
    ("wscdns", "wscdns"),
    ("cdn.dnsv1", "dnspod"),
    ("kunlun", "alibaba_cdn"),
    ("alicdn", "alibaba_cdn"),
    ("tbcache", "alibaba_cdn"),
    ("txcdn", "tencent_cdn"),
    ("cdn", "generic_cdn"),
)
TITLE_RE = re.compile(r"<title[^>]*>(?P<title>.*?)</title>", re.IGNORECASE | re.DOTALL)
HEADER_LINE_RE = re.compile(r"^([^:\r\n]+):\s*(.*?)\s*$")


@dataclass(slots=True)
class WebExposureConfig:
    connect_timeout: float = 1.5
    read_timeout: float = 2.0
    read_size: int = 8192
    host_concurrency: int = 16


@dataclass(slots=True)
class WebExposureResult:
    port: int
    scheme: str
    url: str
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    location: str | None = None
    hostname_hint: str | None = None
    tls_subject_alt_names: list[str] = field(default_factory=list)
    dns: dict[str, Any] = field(default_factory=dict)
    cdn: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "scheme": self.scheme,
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "server": self.server,
            "location": self.location,
            "hostname_hint": self.hostname_hint,
            "tls_subject_alt_names": list(self.tls_subject_alt_names),
            "dns": dict(self.dns),
            "cdn": dict(self.cdn),
            "evidence": list(self.evidence),
            "error": self.error,
        }


class AsyncWebExposureScanner:
    def __init__(self, config: WebExposureConfig | None = None) -> None:
        self.config = config or WebExposureConfig()
        self._host_semaphore = asyncio.Semaphore(max(1, self.config.host_concurrency))

    async def enrich_hosts(self, hosts: list[dict[str, Any]]) -> dict[str, dict[int, dict[str, Any]]]:
        tasks = [
            asyncio.create_task(self._enrich_host(host))
            for host in hosts
            if isinstance(host, dict) and str(host.get("ip") or "").strip()
        ]
        if not tasks:
            return {}
        results = await asyncio.gather(*tasks)
        return {ip: by_port for ip, by_port in results if ip and by_port}

    async def _enrich_host(self, host: dict[str, Any]) -> tuple[str, dict[int, dict[str, Any]]]:
        ip = str(host.get("ip") or "").strip()
        if not ip:
            return "", {}
        async with self._host_semaphore:
            targets = self._build_targets(host)
            if not targets:
                return ip, {}

            dns_by_name: dict[str, dict[str, Any]] = {}
            names = sorted({target["hostname"] for target in targets if target.get("hostname")})
            if names:
                dns_results = await asyncio.gather(*(self._resolve_dns(name) for name in names))
                dns_by_name = {name: payload for name, payload in dns_results}

            by_port: dict[int, dict[str, Any]] = {}
            for target in targets:
                result = await self._probe_target(
                    ip=ip,
                    port=int(target["port"]),
                    scheme=str(target["scheme"]),
                    hostname=target.get("hostname") if isinstance(target.get("hostname"), str) else None,
                    dns=dns_by_name.get(str(target.get("hostname") or ""), {}),
                )
                by_port[result.port] = result.to_dict()
            return ip, by_port

    def _build_targets(self, host: dict[str, Any]) -> list[dict[str, Any]]:
        hostname = _normalize_hostname(host.get("hostname"))
        targets: list[dict[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is None:
                continue
            scheme = _scheme_for_service(service, port)
            if scheme is None:
                continue
            target_hostname = _normalize_hostname(service.get("hostname_hint")) or hostname
            key = (port, scheme)
            if key in seen:
                continue
            seen.add(key)
            targets.append({"port": port, "scheme": scheme, "hostname": target_hostname})
        return targets

    async def _resolve_dns(self, hostname: str) -> tuple[str, dict[str, Any]]:
        return hostname, await asyncio.to_thread(_resolve_dns_blocking, hostname)

    async def _probe_target(
        self,
        *,
        ip: str,
        port: int,
        scheme: str,
        hostname: str | None,
        dns: dict[str, Any],
    ) -> WebExposureResult:
        host_header = hostname or ip
        url = _build_url(host_header, port, scheme)
        request = f"GET / HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\nAccept: */*\r\n\r\n".encode("ascii", errors="ignore")
        tls_names: list[str] = []
        writer: asyncio.StreamWriter | None = None
        try:
            ssl_context = None
            if scheme == "https":
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_context, server_hostname=host_header if scheme == "https" else None),
                timeout=self.config.connect_timeout,
            )
            if scheme == "https":
                ssl_object = writer.get_extra_info("ssl_object")
                tls_names = _extract_certificate_names(ssl_object)
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(max(512, int(self.config.read_size))), timeout=self.config.read_timeout)
            parsed = _parse_http_response(raw)
            hostname_hint = _pick_hostname(tls_names) or _hostname_from_location(parsed.get("location")) or hostname
            cdn = _build_cdn_info(dns)
            evidence = _build_evidence(parsed, tls_names, dns, cdn)
            return WebExposureResult(
                port=port,
                scheme=scheme,
                url=url,
                status_code=parsed.get("status_code") if isinstance(parsed.get("status_code"), int) else None,
                title=parsed.get("title") if isinstance(parsed.get("title"), str) else None,
                server=parsed.get("server") if isinstance(parsed.get("server"), str) else None,
                location=parsed.get("location") if isinstance(parsed.get("location"), str) else None,
                hostname_hint=hostname_hint,
                tls_subject_alt_names=tls_names,
                dns=dns,
                cdn=cdn,
                evidence=evidence,
            )
        except Exception as exc:  # pragma: no cover - network timing dependent
            cdn = _build_cdn_info(dns)
            return WebExposureResult(
                port=port,
                scheme=scheme,
                url=url,
                hostname_hint=hostname,
                dns=dns,
                cdn=cdn,
                evidence=_build_evidence({}, [], dns, cdn),
                error=type(exc).__name__,
            )
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass


def merge_web_exposure_into_services(hosts: list[dict[str, Any]], exposure_map: dict[str, dict[int, dict[str, Any]]]) -> int:
    enriched_count = 0
    for host in hosts:
        if not isinstance(host, dict):
            continue
        ip = str(host.get("ip") or "").strip()
        by_port = exposure_map.get(ip, {})
        if not by_port:
            continue
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is None or port not in by_port:
                continue
            web = by_port[port]
            service["web"] = web
            if not service.get("hostname_hint") and isinstance(web.get("hostname_hint"), str):
                service["hostname_hint"] = web["hostname_hint"]
            evidence = service.get("evidence") if isinstance(service.get("evidence"), list) else []
            service["evidence"] = _unique_strings([*evidence, *[item for item in web.get("evidence", []) if isinstance(item, str)]])
            enriched_count += 1
    return enriched_count


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _normalize_hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().strip(".").lower()
    if not cleaned:
        return None
    try:
        ipaddress.ip_address(cleaned)
        return None
    except ValueError:
        return cleaned


def _scheme_for_service(service: dict[str, Any], port: int) -> str | None:
    tls_detected = bool(service.get("tls_detected") is True)
    labels = {
        str(service.get(key) or "").strip().lower()
        for key in ("service", "service_name", "transport_service", "application_service", "product_name")
        if str(service.get(key) or "").strip()
    }
    aliases = service.get("service_aliases")
    if isinstance(aliases, list):
        labels.update(str(item).strip().lower() for item in aliases if str(item).strip())
    if tls_detected or "https" in labels or port in DEFAULT_HTTPS_PORTS:
        if labels.intersection(WEB_SERVICE_ALIASES) or port in DEFAULT_HTTPS_PORTS:
            return "https"
    if labels.intersection(WEB_SERVICE_ALIASES) or port in DEFAULT_HTTP_PORTS:
        return "http"
    return None


def _build_url(host: str, port: int, scheme: str) -> str:
    default_port = 443 if scheme == "https" else 80
    host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port == default_port:
        return f"{scheme}://{host_part}/"
    return f"{scheme}://{host_part}:{port}/"


def _resolve_dns_blocking(hostname: str) -> dict[str, Any]:
    normalized_hostname = hostname.strip().strip(".").lower()
    cnames: list[str] = []
    try:
        official_name, aliases, _ = socket.gethostbyname_ex(hostname)
        candidates = [official_name, *aliases]
        for candidate in candidates:
            cname = candidate.strip().strip(".").lower()
            if cname and cname != normalized_hostname and cname not in cnames:
                cnames.append(cname)
    except Exception:
        cnames = []

    addresses: list[str] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            address = sockaddr[0]
            if address not in addresses:
                addresses.append(address)
    except Exception:
        addresses = []

    return {
        "hostname": hostname,
        "cnames": cnames,
        "addresses": addresses,
        "address_count": len(addresses),
    }


def _parse_http_response(raw: bytes) -> dict[str, Any]:
    text = raw.decode("iso-8859-1", errors="ignore")
    head, _, body = text.partition("\r\n\r\n")
    if not body:
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    status_code: int | None = None
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        match = HEADER_LINE_RE.match(line)
        if not match:
            continue
        key = match.group(1).strip().lower()
        value = match.group(2).strip()
        if key and value and key not in headers:
            headers[key] = value

    return {
        "status_code": status_code,
        "title": _extract_title(body),
        "server": _compact_text(headers.get("server"), 160),
        "location": _compact_text(headers.get("location"), 512),
    }


def _extract_title(body: str) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    return _compact_text(unescape(re.sub(r"\s+", " ", match.group("title"))), 160)


def _compact_text(value: str | None, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.replace("\x00", "").strip().split())
    if not cleaned:
        return None
    if len(cleaned) > limit:
        return f"{cleaned[: max(0, limit - 3)]}..."
    return cleaned


def _extract_certificate_names(ssl_object: ssl.SSLObject | None) -> list[str]:
    if ssl_object is None:
        return []
    try:
        cert = ssl_object.getpeercert()
    except Exception:
        return []
    names: list[str] = []
    if isinstance(cert, dict):
        for _, value in cert.get("subjectAltName", ()):
            if isinstance(value, str) and value.strip():
                names.append(value.strip().lower())
        subject = cert.get("subject")
        if isinstance(subject, tuple):
            for item in subject:
                if not isinstance(item, tuple):
                    continue
                for key, value in item:
                    if key == "commonName" and isinstance(value, str) and value.strip():
                        names.append(value.strip().lower())
    return _unique_strings([_strip_wildcard(name) for name in names if _normalize_hostname(_strip_wildcard(name))])


def _strip_wildcard(value: str) -> str:
    return value[2:] if value.startswith("*.") else value


def _pick_hostname(names: list[str]) -> str | None:
    for name in names:
        normalized = _normalize_hostname(name)
        if normalized:
            return normalized
    return None


def _hostname_from_location(location: Any) -> str | None:
    if not isinstance(location, str) or not location.strip():
        return None
    parsed = urlparse(location)
    return _normalize_hostname(parsed.hostname)


def _build_cdn_info(dns: dict[str, Any]) -> dict[str, Any]:
    cnames = [str(item).strip().lower() for item in dns.get("cnames", []) if str(item).strip()] if isinstance(dns, dict) else []
    addresses = [str(item).strip() for item in dns.get("addresses", []) if str(item).strip()] if isinstance(dns, dict) else []
    provider = None
    matched_keyword = None
    for cname in cnames:
        for keyword, candidate_provider in CDN_CNAME_KEYWORDS:
            if keyword in cname:
                provider = candidate_provider
                matched_keyword = keyword
                break
        if provider:
            break
    is_cdn = bool(provider or len(addresses) > 3)
    return {
        "detected": is_cdn,
        "provider_hint": provider,
        "matched_keyword": matched_keyword,
        "reason": "cname_keyword" if provider else ("multiple_addresses" if len(addresses) > 3 else ""),
    }


def _build_evidence(parsed: dict[str, Any], tls_names: list[str], dns: dict[str, Any], cdn: dict[str, Any]) -> list[str]:
    evidence: list[str] = ["web_probe"]
    status = parsed.get("status_code")
    if isinstance(status, int):
        evidence.append(f"http_status={status}")
    server = parsed.get("server")
    if isinstance(server, str) and server:
        evidence.append(f"server={server}")
    if tls_names:
        evidence.append(f"tls_san_count={len(tls_names)}")
    if isinstance(dns, dict) and dns.get("address_count"):
        evidence.append(f"dns_address_count={dns['address_count']}")
    if isinstance(cdn, dict) and cdn.get("detected") is True:
        provider = str(cdn.get("provider_hint") or "unknown")
        evidence.append(f"cdn={provider}")
    return _unique_strings(evidence)


def _unique_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        result.append(cleaned)
        seen.add(cleaned)
    return result
