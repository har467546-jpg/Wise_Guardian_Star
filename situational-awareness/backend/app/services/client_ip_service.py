from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Any

from app.core.config import settings


def resolve_client_ip(headers: Any, client_host: str | None) -> str | None:
    direct_ip = _parse_ip(client_host)
    if direct_ip is None:
        return _trim_ip(client_host)
    if not _is_trusted_proxy(direct_ip):
        return str(direct_ip)

    forwarded = _first_forwarded_ip(_header_value(headers, "x-forwarded-for"))
    if forwarded is not None:
        return str(forwarded)
    real_ip = _parse_ip(_header_value(headers, "x-real-ip"))
    if real_ip is not None:
        return str(real_ip)
    return str(direct_ip)


def is_trusted_proxy_ip(value: str | None) -> bool:
    parsed = _parse_ip(value)
    return bool(parsed and _is_trusted_proxy(parsed))


def _header_value(headers: Any, name: str) -> str:
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if callable(getter):
        return str(getter(name) or "")
    if isinstance(headers, dict):
        return str(headers.get(name) or headers.get(name.lower()) or headers.get(name.upper()) or "")
    return ""


def _first_forwarded_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    for part in str(value or "").split(","):
        parsed = _parse_ip(part)
        if parsed is not None:
            return parsed
    return None


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _trim_ip(value: str | None) -> str | None:
    text = str(value or "").strip()
    return text[:64] if text else None


def _is_trusted_proxy(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address in network for network in _trusted_proxy_networks())


@lru_cache(maxsize=8)
def _trusted_proxy_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in str(settings.SECURITY_TRUSTED_PROXY_CIDRS or "").split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(networks)
