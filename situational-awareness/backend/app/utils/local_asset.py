from __future__ import annotations

import ipaddress
import json
import os
import socket
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.core.config import settings
from app.utils.net import list_local_ipv4_addresses

RUNTIME_LOCAL_ASSET_HINTS_PATH = Path(__file__).resolve().parents[2] / ".runtime" / "local_asset_hints.json"


@dataclass(frozen=True, slots=True)
class LocalAssetMatcher:
    ips: frozenset[str]
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    hostnames: frozenset[str]


_MATCHER_CACHE: tuple[tuple[str, int | None], LocalAssetMatcher] | None = None


def clear_local_asset_matcher_cache() -> None:
    global _MATCHER_CACHE
    _MATCHER_CACHE = None


def get_local_asset_matcher() -> LocalAssetMatcher:
    global _MATCHER_CACHE
    runtime_mtime = _runtime_hints_mtime()
    cache_key = (str(settings.LOCAL_ASSET_IPS or ""), runtime_mtime)
    if _MATCHER_CACHE is not None and _MATCHER_CACHE[0] == cache_key:
        return _MATCHER_CACHE[1]

    ips: set[str] = {"127.0.0.1", "::1"}
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    hostnames: set[str] = {"localhost"}

    for token in [item.strip() for item in settings.LOCAL_ASSET_IPS.split(",") if item.strip()]:
        _apply_token_to_sets(token, ips=ips, networks=networks, hostnames=hostnames)

    runtime_hints = _load_runtime_local_asset_hints()
    for token in runtime_hints.get("ips", []):
        _apply_token_to_sets(token, ips=ips, networks=networks, hostnames=hostnames)
    for token in runtime_hints.get("networks", []):
        _apply_token_to_sets(token, ips=ips, networks=networks, hostnames=hostnames)
    for token in runtime_hints.get("hostnames", []):
        _apply_token_to_sets(token, ips=ips, networks=networks, hostnames=hostnames)

    candidate_hostnames = {
        socket.gethostname(),
        socket.getfqdn(),
        "host.docker.internal",
        "gateway.docker.internal",
    }
    for name in candidate_hostnames:
        if not name:
            continue
        hostnames.add(name.lower())
        hostnames.add(name.split(".")[0].lower())

    for local_ip in list_local_ipv4_addresses():
        try:
            ips.add(str(ipaddress.ip_address(local_ip)))
        except ValueError:
            continue

    matcher = LocalAssetMatcher(
        ips=frozenset(ips),
        networks=tuple(networks),
        hostnames=frozenset(hostnames),
    )
    _MATCHER_CACHE = (cache_key, matcher)
    return matcher


def remember_local_asset_hint(value: str | None) -> bool:
    normalized = _normalize_hint_value(value)
    if not normalized:
        return False

    current = _load_runtime_local_asset_hints()
    changed = False

    if "/" in normalized:
        bucket = "networks"
    else:
        try:
            ipaddress.ip_address(normalized)
            bucket = "ips"
        except ValueError:
            bucket = "hostnames"
            normalized = normalized.lower()

    values = [str(item).strip() for item in current.get(bucket, []) if str(item).strip()]
    if normalized not in values:
        values.append(normalized)
        values.sort()
        current[bucket] = values
        changed = True

    if not changed:
        return False

    _write_runtime_local_asset_hints(current)
    clear_local_asset_matcher_cache()
    return True


def _runtime_hints_mtime() -> int | None:
    try:
        return os.stat(RUNTIME_LOCAL_ASSET_HINTS_PATH).st_mtime_ns
    except FileNotFoundError:
        return None


def _load_runtime_local_asset_hints() -> dict[str, list[str]]:
    if not RUNTIME_LOCAL_ASSET_HINTS_PATH.exists():
        return {"ips": [], "networks": [], "hostnames": []}
    try:
        payload = json.loads(RUNTIME_LOCAL_ASSET_HINTS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {"ips": [], "networks": [], "hostnames": []}
    if not isinstance(payload, dict):
        return {"ips": [], "networks": [], "hostnames": []}
    return {
        "ips": [str(item).strip() for item in payload.get("ips", []) if str(item).strip()],
        "networks": [str(item).strip() for item in payload.get("networks", []) if str(item).strip()],
        "hostnames": [str(item).strip().lower() for item in payload.get("hostnames", []) if str(item).strip()],
    }


def _write_runtime_local_asset_hints(payload: dict[str, list[str]]) -> None:
    RUNTIME_LOCAL_ASSET_HINTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = RUNTIME_LOCAL_ASSET_HINTS_PATH.with_suffix(".tmp")
    temp_path.write_text(
        json.dumps(
            {
                "ips": sorted(set(payload.get("ips", []))),
                "networks": sorted(set(payload.get("networks", []))),
                "hostnames": sorted(set(payload.get("hostnames", []))),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    os.replace(temp_path, RUNTIME_LOCAL_ASSET_HINTS_PATH)


def _normalize_hint_value(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    candidate = raw
    if "://" in raw:
        parsed = urlsplit(raw)
        candidate = parsed.hostname or ""
    elif "/" in raw:
        parsed = urlsplit(raw)
        if parsed.hostname:
            candidate = parsed.hostname
    elif ":" in raw and raw.count(":") == 1:
        parsed = urlsplit(f"//{raw}")
        candidate = parsed.hostname or raw
    elif raw.startswith("[") and "]" in raw:
        parsed = urlsplit(f"//{raw}")
        candidate = parsed.hostname or raw

    candidate = candidate.strip().strip("[]")
    if not candidate:
        return None
    return candidate


def _apply_token_to_sets(
    token: str,
    *,
    ips: set[str],
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    hostnames: set[str],
) -> None:
    normalized = _normalize_hint_value(token)
    if not normalized:
        return
    if "/" in normalized:
        try:
            networks.append(ipaddress.ip_network(normalized, strict=False))
            return
        except ValueError:
            return
    try:
        ips.add(str(ipaddress.ip_address(normalized)))
        return
    except ValueError:
        pass
    hostnames.add(normalized.lower())


def resolve_local_asset(ip: str, hostname: str | None = None) -> tuple[bool, str | None]:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False, None

    matcher = get_local_asset_matcher()
    normalized_ip = str(ip_obj)

    if ip_obj.is_loopback:
        return True, "回环地址"

    if normalized_ip in matcher.ips:
        return True, "匹配平台本机 IP"

    for network in matcher.networks:
        if ip_obj in network:
            return True, f"命中本机配置网段 {network}"

    if hostname:
        normalized_hostname = hostname.strip().lower()
        if normalized_hostname in matcher.hostnames or normalized_hostname.split(".")[0] in matcher.hostnames:
            return True, "主机名匹配平台本机"

    return False, None
