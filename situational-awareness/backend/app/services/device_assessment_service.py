from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Sequence
from typing import Any

from app.db.models.asset import Asset

NETWORK_INFRASTRUCTURE_PORTS = {53, 67, 68, 69, 123, 161, 162}
NETWORK_INFRASTRUCTURE_SUPPORT_PORTS = {22, 80, 443}
DNS_SERVICE_NAMES = {"bind", "bind9", "dns", "dnsmasq", "domain", "named", "unbound"}
DHCP_SERVICE_NAMES = {"dhcp", "dhcpd", "dnsmasq", "isc-dhcp", "isc-dhcp-server", "kea", "kea-dhcp"}
NTP_SERVICE_NAMES = {"chrony", "chronyd", "ntp"}
SNMP_SERVICE_NAMES = {"snmp", "snmpd"}
ADMIN_SERVICE_NAMES = {"ssh", "telnet"}
GENERAL_WORKLOAD_SERVICE_NAMES = {
    "ajp13",
    "apache",
    "docker",
    "elasticsearch",
    "ftp",
    "http",
    "https",
    "irc",
    "java-rmi",
    "kibana",
    "mysql",
    "nginx",
    "nfs",
    "php",
    "phpmyadmin",
    "postgresql",
    "redis",
    "rexec",
    "rlogin",
    "rpcbind",
    "rsh",
    "samba",
    "smtp",
    "tomcat",
}
GENERAL_WORKLOAD_PORTS = {21, 25, 80, 111, 443, 445, 2049, 3306, 5432, 6379, 8009, 8080, 8443, 9200}
VIRTUAL_HINT_TOKENS = {"hyper-v", "kvm", "nat", "openvswitch", "ovs", "qemu", "virtual", "virtualbox", "vmware", "vswitch"}
IOT_HINT_TOKENS = {"access", "camera", "door", "dahua", "hikvision", "intercom", "iot", "printer", "rtsp", "sensor"}
VMWARE_MAC_PREFIXES = ("00:05:69", "00:0c:29", "00:1c:14", "00:50:56")
INFRASTRUCTURE_DEVICE_ROLES = {"dhcp_dns", "dhcp_service", "dns_resolver", "gateway", "gateway_dns", "network_infrastructure"}
ASSESSMENT_SOURCE_PRIORITY = {
    "asset_fields": 10,
    "campus_observation": 15,
    "network_discovery": 20,
    "ssh_collection": 30,
}


def build_discovery_host_device_assessment(host: dict[str, Any], *, cidr: str | None = None) -> dict[str, Any] | None:
    return build_asset_device_assessment(
        ip=str(host.get("ip") or "").strip() or None,
        cidr=cidr,
        hostname=str(host.get("hostname") or "").strip() or None,
        ports=host.get("ports"),
        service_records=host.get("services"),
        raw_evidence=host.get("discovery_evidence"),
        assessment_source="network_discovery",
    )


def build_asset_device_assessment(
    *,
    asset: Asset | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    hostname: str | None = None,
    vendor: str | None = None,
    mac_address: str | None = None,
    ports: Iterable[Any] | None = None,
    service_records: Sequence[Any] | None = None,
    service_names: Iterable[Any] | None = None,
    service_config_keys: Iterable[Any] | None = None,
    process_names: Iterable[Any] | None = None,
    raw_evidence: Iterable[Any] | None = None,
    explicit_device_role: str | None = None,
    assessment_source: str,
) -> dict[str, Any] | None:
    ip_text = _clean_text(ip) or _clean_text(getattr(asset, "ip", None))
    hostname_text = _clean_text(hostname) or _clean_text(getattr(asset, "hostname", None))
    vendor_text = _clean_text(vendor) or _clean_text(getattr(asset, "vendor", None))
    mac_text = _clean_text(mac_address) or _clean_text(getattr(asset, "mac_address", None))
    normalized_role = _normalize_name(explicit_device_role or getattr(asset, "device_role", None))

    open_ports = sorted(
        {
            *(_normalize_ports(ports)),
            *(_normalize_ports(_extract_asset_ports(asset))),
        }
    )
    names = sorted(
        {
            *(_normalize_names(service_names)),
            *(_collect_names_from_records(service_records)),
            *(_normalize_names(service_config_keys)),
            *(_normalize_names(process_names)),
        }
    )
    config_names = sorted({_normalize_name(item) for item in (service_config_keys or []) if _normalize_name(item)})
    process_name_list = sorted({_normalize_name(item) for item in (process_names or []) if _normalize_name(item)})
    evidence_lines = _compact_string_list(raw_evidence)

    text_blob = " ".join(
        filter(
            None,
            [
                normalized_role,
                hostname_text.lower() if hostname_text else "",
                vendor_text.lower() if vendor_text else "",
                " ".join(names),
                " ".join(evidence_lines).lower(),
            ],
        )
    )

    gateway_reason = _resolve_gateway_candidate_reason(ip_text, cidr)
    matched_dns_names = _matched_names(names, DNS_SERVICE_NAMES)
    matched_dhcp_names = _matched_names(names, DHCP_SERVICE_NAMES)
    matched_ntp_names = _matched_names(names, NTP_SERVICE_NAMES)
    matched_snmp_names = _matched_names(names, SNMP_SERVICE_NAMES)
    matched_workload_names = _matched_names(names, GENERAL_WORKLOAD_SERVICE_NAMES)

    infra_port_hits = sorted(port for port in open_ports if port in NETWORK_INFRASTRUCTURE_PORTS)
    dns_like = bool(53 in open_ports or matched_dns_names or _blob_contains_any(text_blob, ("bind", "dnsmasq", "dns", "named", "unbound")))
    dhcp_like = bool({67, 68} & set(open_ports) or matched_dhcp_names or _blob_contains_any(text_blob, ("dhcp", "dnsmasq", "isc-dhcp", "kea")))
    ntp_like = bool(123 in open_ports or matched_ntp_names or _blob_contains_any(text_blob, ("chrony", "chronyd", "ntp")))
    snmp_like = bool({161, 162} & set(open_ports) or matched_snmp_names or _blob_contains_any(text_blob, ("snmp", "snmpd")))
    infra_service_like = dns_like or dhcp_like or ntp_like or snmp_like
    low_surface_infra = bool(open_ports) and bool(infra_port_hits) and set(open_ports).issubset(
        NETWORK_INFRASTRUCTURE_PORTS | NETWORK_INFRASTRUCTURE_SUPPORT_PORTS
    )
    workload_like = bool(
        {port for port in open_ports if port in GENERAL_WORKLOAD_PORTS and port not in NETWORK_INFRASTRUCTURE_SUPPORT_PORTS}
        or matched_workload_names
    )

    if normalized_role in INFRASTRUCTURE_DEVICE_ROLES:
        infra_service_like = True
        if normalized_role in {"dhcp_dns", "dhcp_service"}:
            dhcp_like = True
        if normalized_role in {"dhcp_dns", "dns_resolver", "gateway_dns"}:
            dns_like = True
        if normalized_role in {"gateway", "gateway_dns"}:
            gateway_reason = gateway_reason or "explicit_role_hint"

    gateway_like = gateway_reason is not None and (infra_service_like or low_surface_infra or bool(infra_port_hits))
    infrastructure_like = gateway_like or low_surface_infra or (infra_service_like and not workload_like)

    virtual_like = _blob_contains_any(text_blob, tuple(VIRTUAL_HINT_TOKENS)) or _matches_mac_prefix(mac_text, VMWARE_MAC_PREFIXES)
    virtual_network_like = virtual_like and (
        infrastructure_like or _blob_contains_any(text_blob, ("nat", "openvswitch", "ovs", "vswitch"))
    )
    iot_like = _blob_contains_any(text_blob, tuple(IOT_HINT_TOKENS))

    if not any([infrastructure_like, virtual_network_like, iot_like, open_ports, names, normalized_role]):
        return None

    matched_traits: list[str] = []
    reasons: list[str] = []
    flags = {
        "is_infrastructure_device": False,
        "is_iot": False,
        "is_virtual_network_component": False,
    }
    asset_category: str | None = None
    device_role: str | None = None
    confidence = 55

    if normalized_role:
        matched_traits.append("explicit_role_hint")
        reasons.append(f"上游结果直接给出设备角色 {normalized_role}")

    if virtual_network_like:
        flags["is_virtual_network_component"] = True
        flags["is_infrastructure_device"] = infrastructure_like
        asset_category = "virtual_network_component"
        device_role = normalized_role or ("network_infrastructure" if infrastructure_like else None)
        confidence = 88
        reasons.append("厂商、MAC 或服务特征命中虚拟网络组件线索")

    elif infrastructure_like:
        flags["is_infrastructure_device"] = True
        asset_category = "network_infrastructure"
        if normalized_role in INFRASTRUCTURE_DEVICE_ROLES:
            device_role = normalized_role
        elif gateway_like and dns_like:
            device_role = "gateway_dns"
        elif gateway_like:
            device_role = "gateway"
        elif dhcp_like and dns_like:
            device_role = "dhcp_dns"
        elif dhcp_like:
            device_role = "dhcp_service"
        elif dns_like:
            device_role = "dns_resolver"
        else:
            device_role = "network_infrastructure"
        confidence = 80

    elif iot_like:
        flags["is_iot"] = True
        asset_category = "iot_device"
        confidence = 76
        reasons.append("主机名、厂商或服务特征命中 IoT 设备线索")

    else:
        asset_category = "general_endpoint"
        confidence = 62

    if infra_port_hits:
        matched_traits.append("infrastructure_ports")
        reasons.append(f"开放端口命中基础设施端口 {', '.join(str(port) for port in infra_port_hits)}")
        confidence += min(8, len(infra_port_hits) * 2)
    if matched_dns_names or dns_like:
        matched_traits.append("dns_signal")
        reasons.append(_format_signal_reason("识别到 DNS 相关服务", matched_dns_names))
        confidence += 4
    if matched_dhcp_names or dhcp_like:
        matched_traits.append("dhcp_signal")
        reasons.append(_format_signal_reason("识别到 DHCP 相关服务", matched_dhcp_names))
        confidence += 4
    if matched_ntp_names or ntp_like:
        matched_traits.append("ntp_signal")
        reasons.append(_format_signal_reason("识别到 NTP 相关服务", matched_ntp_names))
        confidence += 2
    if matched_snmp_names or snmp_like:
        matched_traits.append("snmp_signal")
        reasons.append(_format_signal_reason("识别到 SNMP 相关服务", matched_snmp_names))
        confidence += 2
    if low_surface_infra:
        matched_traits.append("low_surface_infrastructure")
        reasons.append("端口面较小，且集中在基础设施端口与常见管理端口")
        confidence += 6
    if gateway_reason:
        matched_traits.append("gateway_candidate")
        reasons.append(f"IP 命中网关候选位置：{_describe_gateway_reason(gateway_reason)}")
        confidence += 8
    if matched_workload_names:
        matched_traits.append("workload_signal")
        reasons.append(_format_signal_reason("识别到通用业务服务", matched_workload_names))
        confidence += 3
    elif asset_category == "general_endpoint" and open_ports:
        reasons.append(f"开放端口为 {', '.join(str(port) for port in open_ports[:6])}")
        confidence += min(6, len(open_ports))
    elif asset_category == "general_endpoint" and names:
        reasons.append(_format_signal_reason("识别到服务", names[:4]))
        confidence += min(6, len(names))

    if asset_category == "virtual_network_component":
        confidence = max(confidence, 88)
    elif asset_category == "network_infrastructure":
        confidence = max(confidence, 82)
    elif asset_category == "iot_device":
        confidence = max(confidence, 76)

    assessment = {
        "asset_category": asset_category,
        "device_role": device_role,
        "assessment_source": assessment_source,
        "confidence": min(99, confidence),
        "matched_traits": sorted(dict.fromkeys(matched_traits)),
        "reasons": _compact_string_list(reasons),
        "flags": flags,
        "evidence": _compact_mapping(
            {
                "ip": ip_text,
                "hostname": hostname_text,
                "vendor": vendor_text,
                "open_ports": open_ports,
                "service_names": names[:12],
                "process_names": process_name_list[:12],
                "service_config_keys": config_names[:12],
                "raw_evidence": evidence_lines[:8],
                "gateway_candidate_reason": gateway_reason,
                "explicit_device_role": normalized_role,
            }
        ),
    }
    return assessment


def apply_device_assessment_to_asset(asset: Asset, assessment: dict[str, Any] | None) -> dict[str, Any] | None:
    current = resolve_asset_device_assessment(asset)
    selected = select_preferred_device_assessment(current, assessment)
    if selected is None:
        return current

    asset.device_assessment_json = dict(selected)
    asset.asset_category = _clean_text(selected.get("asset_category"))
    asset.device_role = _clean_text(selected.get("device_role"))
    flags = selected.get("flags") if isinstance(selected.get("flags"), dict) else {}
    asset.is_infrastructure_device = bool(flags.get("is_infrastructure_device") is True)
    asset.is_iot = bool(flags.get("is_iot") is True)
    asset.is_virtual_network_component = bool(flags.get("is_virtual_network_component") is True)
    return selected


def resolve_asset_device_assessment(asset: Asset) -> dict[str, Any] | None:
    stored = asset.device_assessment_json if isinstance(asset.device_assessment_json, dict) else {}
    if stored and any(stored.get(key) for key in ("asset_category", "device_role", "flags")):
        payload = dict(stored)
        flags = payload.get("flags") if isinstance(payload.get("flags"), dict) else {}
        payload["asset_category"] = _clean_text(payload.get("asset_category")) or _clean_text(asset.asset_category)
        payload["device_role"] = _clean_text(payload.get("device_role")) or _clean_text(asset.device_role)
        payload["assessment_source"] = _clean_text(payload.get("assessment_source")) or _clean_text(asset.identity_source) or "asset_fields"
        payload["confidence"] = int(payload.get("confidence") or 0)
        payload["matched_traits"] = _compact_string_list(payload.get("matched_traits")) if isinstance(payload.get("matched_traits"), list) else []
        payload["reasons"] = _compact_string_list(payload.get("reasons")) if isinstance(payload.get("reasons"), list) else []
        payload["flags"] = {
            "is_infrastructure_device": bool(flags.get("is_infrastructure_device") is True or asset.is_infrastructure_device is True),
            "is_iot": bool(flags.get("is_iot") is True or asset.is_iot is True),
            "is_virtual_network_component": bool(
                flags.get("is_virtual_network_component") is True or asset.is_virtual_network_component is True
            ),
        }
        payload["evidence"] = payload.get("evidence") if isinstance(payload.get("evidence"), dict) else {}
        return payload

    fallback = build_asset_device_assessment(
        asset=asset,
        assessment_source=_clean_text(asset.identity_source) or "asset_fields",
        explicit_device_role=_clean_text(asset.device_role),
    )
    if fallback is None and (
        _clean_text(asset.asset_category)
        or _clean_text(asset.device_role)
        or asset.is_infrastructure_device
        or asset.is_iot
        or asset.is_virtual_network_component
    ):
        fallback = {
            "asset_category": _clean_text(asset.asset_category),
            "device_role": _clean_text(asset.device_role),
            "assessment_source": _clean_text(asset.identity_source) or "asset_fields",
            "confidence": 40,
            "matched_traits": [],
            "reasons": ["由资产现有字段回填设备判断结果"],
            "flags": {
                "is_infrastructure_device": bool(asset.is_infrastructure_device is True),
                "is_iot": bool(asset.is_iot is True),
                "is_virtual_network_component": bool(asset.is_virtual_network_component is True),
            },
            "evidence": {"backfilled_from_asset_fields": True},
        }
    if fallback is None:
        return None
    evidence = fallback.get("evidence") if isinstance(fallback.get("evidence"), dict) else {}
    evidence["backfilled_from_asset_fields"] = True
    fallback["evidence"] = evidence
    if not fallback.get("reasons"):
        fallback["reasons"] = ["由资产现有字段回填设备判断结果"]
    return fallback


def select_preferred_device_assessment(
    current: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if incoming is None:
        return current
    if current is None:
        return incoming
    if _assessment_score(incoming) >= _assessment_score(current):
        return incoming
    return current


def _assessment_score(assessment: dict[str, Any]) -> tuple[int, int, int, int]:
    source = _clean_text(assessment.get("assessment_source")) or ""
    matched_traits = assessment.get("matched_traits") if isinstance(assessment.get("matched_traits"), list) else []
    reasons = assessment.get("reasons") if isinstance(assessment.get("reasons"), list) else []
    return (
        int(assessment.get("confidence") or 0),
        ASSESSMENT_SOURCE_PRIORITY.get(source, 0),
        len(matched_traits),
        len(reasons),
    )


def _extract_asset_ports(asset: Asset | None) -> list[int]:
    if asset is None:
        return []
    ports: list[int] = []
    for item in getattr(asset, "ports", []) or []:
        state = _clean_text(getattr(item, "state", None))
        if state and state.lower() not in {"open", "listening"}:
            continue
        normalized_port = _to_port(getattr(item, "port", None))
        if normalized_port is not None:
            ports.append(normalized_port)
    return ports


def _collect_names_from_records(records: Sequence[Any] | None) -> set[str]:
    if not isinstance(records, Sequence):
        return set()
    names: set[str] = set()
    for item in records:
        if not isinstance(item, dict):
            continue
        for key in ("service", "application_service", "transport_service", "product_name", "nmap_service", "nmap_product", "name"):
            normalized = _normalize_name(item.get(key))
            if normalized:
                names.add(normalized)
        for alias in item.get("service_aliases") if isinstance(item.get("service_aliases"), list) else []:
            normalized = _normalize_name(alias)
            if normalized:
                names.add(normalized)
    return names


def _normalize_ports(values: Iterable[Any] | None) -> set[int]:
    ports: set[int] = set()
    if values is None:
        return ports
    for item in values:
        if isinstance(item, dict):
            normalized = _to_port(item.get("port"))
        else:
            normalized = _to_port(item)
        if normalized is not None:
            ports.add(normalized)
    return ports


def _normalize_names(values: Iterable[Any] | None) -> set[str]:
    names: set[str] = set()
    if values is None:
        return names
    for item in values:
        normalized = _normalize_name(item)
        if normalized:
            names.add(normalized)
    return names


def _matched_names(values: Iterable[str], expected: set[str]) -> list[str]:
    return sorted({item for item in values if item in expected})


def _normalize_name(value: Any) -> str | None:
    text = _clean_text(value)
    if not text:
        return None
    return text.lower()


def _clean_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _compact_string_list(values: Iterable[Any] | None) -> list[str]:
    if values is None:
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in values:
        text = _clean_text(item)
        if not text or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return items


def _compact_mapping(payload: dict[str, Any]) -> dict[str, Any]:
    compacted: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", [], {}):
            continue
        compacted[key] = value
    return compacted


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _blob_contains_any(blob: str, needles: Iterable[str]) -> bool:
    return any(needle in blob for needle in needles)


def _matches_mac_prefix(mac_address: str | None, prefixes: tuple[str, ...]) -> bool:
    if not mac_address:
        return False
    normalized = mac_address.lower()
    return normalized.startswith(prefixes)


def _resolve_gateway_candidate_reason(ip: str | None, cidr: str | None) -> str | None:
    if not ip or not cidr:
        return None
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        ip_value = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not isinstance(network, ipaddress.IPv4Network) or not isinstance(ip_value, ipaddress.IPv4Address):
        return None
    if ip_value not in network or network.num_addresses < 4:
        return None

    first_host = ipaddress.IPv4Address(int(network.network_address) + 1)
    last_host = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
    second_host = ipaddress.IPv4Address(int(network.network_address) + 2) if network.num_addresses >= 5 else None
    if ip_value == first_host:
        return "first_usable_host"
    if second_host is not None and ip_value == second_host:
        return "second_usable_host"
    if ip_value == last_host:
        return "last_usable_host"
    return None


def _describe_gateway_reason(reason: str) -> str:
    mapping = {
        "explicit_role_hint": "上游显式角色提示",
        "first_usable_host": "网段首个可用地址",
        "second_usable_host": "网段第二个可用地址",
        "last_usable_host": "网段最后一个可用地址",
    }
    return mapping.get(reason, reason)


def _format_signal_reason(prefix: str, matched_names: list[str]) -> str:
    if matched_names:
        return f"{prefix} {', '.join(matched_names[:4])}"
    return prefix
