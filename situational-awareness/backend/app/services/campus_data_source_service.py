from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.crypto import decrypt_text, encrypt_text
from app.db.models.campus_data_source import CampusDataSource

UTC = timezone.utc
_DHCP_HOSTNAME_RE = re.compile(r"client-hostname\s+\"(?P<hostname>[^\"]+)\"")
_DHCP_MAC_RE = re.compile(r"hardware\s+ethernet\s+(?P<mac>[0-9a-f:]{17})", re.IGNORECASE)
_DHCP_LEASE_RE = re.compile(r"lease\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\{(?P<body>.*?)\}", re.IGNORECASE | re.DOTALL)
_DNSMASQ_RE = re.compile(
    r"(?P<expiry>\d+)\s+(?P<mac>[0-9a-f:]{17})\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<hostname>\S+)",
    re.IGNORECASE,
)
_SNMP_IP_RE = re.compile(r"(?P<oid>(?:\d+\.)+)(?P<ip>\d+\.\d+\.\d+\.\d+)\s*=\s*[\w-]+:\s*(?P<value>.+)$")
_SNMP_MAC_RE = re.compile(r"(?P<oid>(?:\d+\.)+)(?P<ip>\d+\.\d+\.\d+\.\d+)\s*=\s*[\w-]+:\s*(?P<mac>[0-9A-Fa-f: -]+)$")
_MAC_SEP_RE = re.compile(r"[^0-9A-Fa-f]")


@dataclass(slots=True)
class CampusObservation:
    source_type: str
    observed_at: datetime
    ip: str | None = None
    mac_address: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    network_zone: str | None = None
    network_vlan: str | None = None
    device_role: str | None = None
    raw_evidence: list[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_type": self.source_type,
            "observed_at": self.observed_at.isoformat(),
            "ip": self.ip,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "network_zone": self.network_zone,
            "network_vlan": self.network_vlan,
            "device_role": self.device_role,
            "raw_evidence": list(self.raw_evidence or []),
        }


def upsert_campus_data_source(
    db: Session,
    source: CampusDataSource | None,
    *,
    scanner_zone_id: str,
    asset_id: str | None,
    name: str,
    source_type: str,
    enabled: bool,
    collection_interval_seconds: int,
    config_json: dict[str, Any],
    secret_plaintext: str | None = None,
) -> CampusDataSource:
    source = source or CampusDataSource(scanner_zone_id=scanner_zone_id, name=name, source_type=source_type)
    source.scanner_zone_id = scanner_zone_id
    source.asset_id = asset_id
    source.name = name
    source.source_type = source_type
    source.enabled = enabled
    source.collection_interval_seconds = collection_interval_seconds
    source.config_json = dict(config_json or {})
    if secret_plaintext is not None:
        source.secret_ciphertext = encrypt_text(secret_plaintext.strip()) if secret_plaintext.strip() else None
    db.add(source)
    db.commit()
    db.refresh(source)
    return source


def test_campus_data_source(source: CampusDataSource) -> tuple[bool, str, dict[str, Any]]:
    observations = collect_campus_data_source_observations(source)
    if not observations:
        return False, "未采集到有效观测数据", {"observation_count": 0}
    return True, f"采集成功，共 {len(observations)} 条观测", {"observation_count": len(observations)}


def collect_campus_data_source_observations(source: CampusDataSource) -> list[CampusObservation]:
    source_type = str(source.source_type or "").strip().lower()
    zone_name = str(getattr(source.scanner_zone, "name", "") or "").strip() or None
    if source_type == "dhcp_lease":
        return collect_dhcp_lease_observations(source.config_json, zone_name=zone_name)
    if source_type == "snmp_switch":
        secret = decrypt_text(source.secret_ciphertext) if source.secret_ciphertext else ""
        return collect_snmp_switch_observations(source.config_json, secret=secret, zone_name=zone_name)
    return []


def sync_campus_data_source(db: Session, source: CampusDataSource) -> tuple[list[CampusObservation], dict[str, Any]]:
    try:
        observations = collect_campus_data_source_observations(source)
        summary = {"observation_count": len(observations)}
        source.last_summary_json = summary
        source.last_collected_at = datetime.now(UTC)
        source.last_error = None
        db.add(source)
        db.commit()
        db.refresh(source)
        return observations, summary
    except Exception as exc:
        source.last_error = str(exc)
        source.last_collected_at = datetime.now(UTC)
        db.add(source)
        db.commit()
        db.refresh(source)
        raise


def collect_dhcp_lease_observations(config_json: dict[str, Any], *, zone_name: str | None = None) -> list[CampusObservation]:
    path_value = str(config_json.get("lease_file_path") or "").strip()
    if not path_value:
        return []
    payload = Path(path_value).read_text(encoding="utf-8")
    if "lease " in payload:
        return _parse_isc_dhcp_leases(payload, zone_name=zone_name)
    return _parse_dnsmasq_leases(payload, zone_name=zone_name)


def collect_snmp_switch_observations(
    config_json: dict[str, Any],
    *,
    secret: str,
    zone_name: str | None = None,
) -> list[CampusObservation]:
    host = str(config_json.get("host") or "").strip()
    if not host:
        return []
    command = [
        "snmpwalk",
        "-v2c",
        "-c",
        secret or str(config_json.get("community") or "public").strip(),
        host,
    ]
    base_oid = str(config_json.get("base_oid") or "").strip()
    if base_oid:
        command.append(base_oid)
    process = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    if process.returncode != 0:
        stderr = (process.stderr or "").strip()
        raise RuntimeError(stderr or f"snmpwalk 失败，退出码={process.returncode}")
    return parse_snmpwalk_output(process.stdout, zone_name=zone_name)


def parse_snmpwalk_output(output: str, *, zone_name: str | None = None) -> list[CampusObservation]:
    ip_to_mac: dict[str, str] = {}
    evidence: dict[str, list[str]] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        ip_match = _SNMP_IP_RE.search(line)
        if ip_match:
            ip = ip_match.group("ip")
            evidence.setdefault(ip, []).append(line)
        mac_match = _SNMP_MAC_RE.search(line)
        if mac_match:
            ip = mac_match.group("ip")
            normalized_mac = normalize_mac_address(mac_match.group("mac"))
            if normalized_mac:
                ip_to_mac[ip] = normalized_mac
                evidence.setdefault(ip, []).append(line)
    observations: list[CampusObservation] = []
    now = datetime.now(UTC)
    for ip, raw_lines in evidence.items():
        observations.append(
            CampusObservation(
                source_type="snmp_switch",
                observed_at=now,
                ip=ip if _valid_ipv4(ip) else None,
                mac_address=ip_to_mac.get(ip),
                network_zone=zone_name,
                raw_evidence=raw_lines,
            )
        )
    return observations


def normalize_mac_address(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    condensed = _MAC_SEP_RE.sub("", raw)
    if len(condensed) != 12:
        return None
    return ":".join(condensed[index : index + 2] for index in range(0, 12, 2)).lower()


def is_locally_administered_mac(mac_address: str | None) -> bool:
    normalized = normalize_mac_address(mac_address)
    if not normalized:
        return False
    first_octet = int(normalized.split(":")[0], 16)
    return bool(first_octet & 0b00000010)


def observations_within_window(
    left_time: datetime | None,
    right_time: datetime | None,
    *,
    window_seconds: int,
) -> bool:
    if left_time is None or right_time is None:
        return False
    return abs((left_time - right_time).total_seconds()) <= max(0, int(window_seconds))


def _parse_isc_dhcp_leases(payload: str, *, zone_name: str | None = None) -> list[CampusObservation]:
    observations: list[CampusObservation] = []
    now = datetime.now(UTC)
    for match in _DHCP_LEASE_RE.finditer(payload):
        ip = match.group("ip")
        body = match.group("body") or ""
        hostname_match = _DHCP_HOSTNAME_RE.search(body)
        mac_match = _DHCP_MAC_RE.search(body)
        observations.append(
            CampusObservation(
                source_type="dhcp_lease",
                observed_at=now,
                ip=ip if _valid_ipv4(ip) else None,
                mac_address=normalize_mac_address(mac_match.group("mac") if mac_match else None),
                hostname=(hostname_match.group("hostname").strip() if hostname_match else None) or None,
                network_zone=zone_name,
                raw_evidence=[f"lease {ip}"],
            )
        )
    return observations


def _parse_dnsmasq_leases(payload: str, *, zone_name: str | None = None) -> list[CampusObservation]:
    observations: list[CampusObservation] = []
    for raw_line in payload.splitlines():
        match = _DNSMASQ_RE.search(raw_line.strip())
        if match is None:
            continue
        expiry = datetime.fromtimestamp(int(match.group("expiry")), tz=UTC)
        observations.append(
            CampusObservation(
                source_type="dhcp_lease",
                observed_at=expiry,
                ip=match.group("ip"),
                mac_address=normalize_mac_address(match.group("mac")),
                hostname=None if match.group("hostname") == "*" else match.group("hostname"),
                network_zone=zone_name,
                raw_evidence=[raw_line.strip()],
            )
        )
    return observations


def build_time_window_anchor(
    *,
    observed_at: datetime | None,
    last_auth_time: datetime | None,
    last_seen_at: datetime | None,
) -> datetime | None:
    return observed_at or last_auth_time or last_seen_at


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False
