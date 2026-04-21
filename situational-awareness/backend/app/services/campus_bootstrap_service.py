from __future__ import annotations

import ipaddress
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.db.models.campus_data_source import CampusDataSource
from app.db.models.host_runner import HostRunner
from app.db.models.scanner_node_assignment import ScannerNodeAssignment
from app.db.models.scanner_zone import ScannerZone
from app.services.campus_data_source_service import upsert_campus_data_source

DEFAULT_DHCP_LEASE_CANDIDATES = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/NetworkManager/dnsmasq.leases",
)


def ensure_campus_auto_bootstrap(db: Session) -> dict[str, int]:
    if not bool(getattr(settings, "CAMPUS_AUTO_BOOTSTRAP_ENABLED", True)):
        return {"zone_count": 0, "assignment_count": 0, "data_source_count": 0}

    zone_count = 0
    assignment_count = 0
    data_source_count = 0
    runner_stmt = (
        select(HostRunner)
        .options(joinedload(HostRunner.asset))
        .where(HostRunner.install_status == "installed")
    )
    runners = db.scalars(runner_stmt).unique().all()
    for runner in runners:
        asset = getattr(runner, "asset", None)
        if asset is None:
            continue
        zone = _ensure_zone_for_runner(db, runner)
        if zone is not None:
            zone_count += 1
        assignment = _ensure_assignment_for_runner(db, runner, zone)
        if assignment is not None:
            assignment_count += 1
        source = _ensure_default_dhcp_source(db, zone)
        if source is not None:
            data_source_count += 1
    db.commit()
    return {
        "zone_count": zone_count,
        "assignment_count": assignment_count,
        "data_source_count": data_source_count,
    }


def _ensure_zone_for_runner(db: Session, runner: HostRunner) -> ScannerZone | None:
    asset = runner.asset
    if asset is None:
        return None
    inferred_cidrs = _infer_runner_cidrs(runner)
    if not inferred_cidrs:
        return None

    zone = None
    if runner.scanner_zone_id:
        zone = db.get(ScannerZone, runner.scanner_zone_id)
    if zone is None:
        zone_name = _default_zone_name(asset.hostname, str(asset.ip))
        zone = db.scalar(select(ScannerZone).where(ScannerZone.name == zone_name))
    if zone is None:
        zone = ScannerZone(
            name=_default_zone_name(asset.hostname, str(asset.ip)),
            zone_type=_infer_zone_type(asset),
            priority=100,
            enabled=True,
            cidrs_json=inferred_cidrs,
            default_scan_profile_json=_default_zone_profile(_infer_zone_type(asset)),
            allowed_data_source_types_json=["dhcp_lease", "snmp_switch"],
        )
    else:
        zone.cidrs_json = inferred_cidrs
        zone.zone_type = zone.zone_type or _infer_zone_type(asset)
        if not zone.default_scan_profile_json:
            zone.default_scan_profile_json = _default_zone_profile(zone.zone_type)
        if not zone.allowed_data_source_types_json:
            zone.allowed_data_source_types_json = ["dhcp_lease", "snmp_switch"]
    db.add(zone)
    db.flush()
    runner.scanner_zone_id = zone.id
    db.add(runner)
    return zone


def _ensure_assignment_for_runner(db: Session, runner: HostRunner, zone: ScannerZone | None) -> ScannerNodeAssignment | None:
    if zone is None:
        return None
    assignment = db.scalar(
        select(ScannerNodeAssignment).where(
            ScannerNodeAssignment.scanner_zone_id == zone.id,
            ScannerNodeAssignment.asset_id == runner.asset_id,
        )
    )
    if assignment is None:
        assignment = ScannerNodeAssignment(
            scanner_zone_id=zone.id,
            asset_id=runner.asset_id,
        )
    assignment.enabled = True
    assignment.priority = 100
    assignment.visible_cidrs_json = _infer_runner_cidrs(runner)
    assignment.max_concurrent_jobs = max(1, int(getattr(settings, "CAMPUS_ZONE_HOST_CONCURRENCY_LIMIT", 8)))
    db.add(assignment)
    db.flush()
    runner.visible_cidrs_json = assignment.visible_cidrs_json
    runner.max_concurrent_jobs = assignment.max_concurrent_jobs
    runner.node_role = "hybrid"
    db.add(runner)
    return assignment


def _ensure_default_dhcp_source(db: Session, zone: ScannerZone | None) -> CampusDataSource | None:
    if zone is None:
        return None
    configured_path = str(getattr(settings, "CAMPUS_BOOTSTRAP_DHCP_LEASE_PATH", "") or "").strip()
    lease_path = configured_path or next((candidate for candidate in DEFAULT_DHCP_LEASE_CANDIDATES if Path(candidate).exists()), "")
    if not lease_path:
        return None
    source = db.scalar(
        select(CampusDataSource).where(
            CampusDataSource.scanner_zone_id == zone.id,
            CampusDataSource.source_type == "dhcp_lease",
            CampusDataSource.name == f"{zone.name} DHCP",
        )
    )
    return upsert_campus_data_source(
        db,
        source,
        scanner_zone_id=zone.id,
        asset_id=None,
        name=f"{zone.name} DHCP",
        source_type="dhcp_lease",
        enabled=True,
        collection_interval_seconds=max(60, int(getattr(settings, "CAMPUS_DHCP_DEFAULT_INTERVAL_SECONDS", 1800))),
        config_json={"lease_file_path": lease_path},
        secret_plaintext=None,
    )


def _infer_runner_cidrs(runner: HostRunner) -> list[str]:
    values = [str(item).strip() for item in (runner.visible_cidrs_json or []) if str(item).strip()]
    if values:
        return values
    host_facts = runner.capabilities_json.get("host_facts") if isinstance(runner.capabilities_json, dict) else {}
    if isinstance(host_facts, dict):
        raw_cidrs = host_facts.get("local_ipv4_cidrs")
        if isinstance(raw_cidrs, list):
            normalized = [str(item).strip() for item in raw_cidrs if str(item).strip()]
            if normalized:
                return normalized
    asset = runner.asset
    if asset is None or not asset.ip:
        return []
    try:
        network = ipaddress.ip_network(f"{asset.ip}/24", strict=False)
    except ValueError:
        return []
    return [str(network)]


def _default_zone_name(hostname: str | None, ip: str) -> str:
    return f"自动分区-{hostname or ip}"


def _infer_zone_type(asset) -> str:
    category = str(getattr(asset, "asset_category", "") or "").strip().lower()
    zone = str(getattr(asset, "network_zone", "") or "").strip().lower()
    hostname = str(getattr(asset, "hostname", "") or "").strip().lower()
    if "server" in category or "server" in zone:
        return "server"
    if "dorm" in zone or "宿舍" in zone or "dorm" in hostname:
        return "dormitory"
    if "iot" in category or "camera" in hostname:
        return "iot"
    return "office"


def _default_zone_profile(zone_type: str) -> dict[str, object]:
    normalized = str(zone_type or "").strip().lower()
    if normalized in {"dormitory", "wireless", "office"}:
        return {
            "portset_mode": str(getattr(settings, "CAMPUS_DEFAULT_PORTSET_MODE", "top1000_plus_custom") or "top1000_plus_custom"),
            "allow_full_scan": False,
            "nmap_min_rate": max(1, int(getattr(settings, "CAMPUS_ZONE_NMAP_MIN_RATE", 5000))),
            "nmap_version_intensity": 5,
            "nmap_full_scan_timeout_seconds": 45,
        }
    if normalized == "server":
        return {
            "portset_mode": str(getattr(settings, "CAMPUS_DEFAULT_PORTSET_MODE", "top1000_plus_custom") or "top1000_plus_custom"),
            "allow_full_scan": bool(getattr(settings, "CAMPUS_ALLOW_FULL_SCAN_DEFAULT", False)),
            "nmap_min_rate": max(1, int(getattr(settings, "CAMPUS_ZONE_NMAP_MIN_RATE", 5000))),
            "nmap_version_intensity": 7,
            "nmap_full_scan_timeout_seconds": 90,
        }
    if normalized == "iot":
        return {
            "portset_mode": "curated",
            "allow_full_scan": False,
            "nmap_min_rate": max(1, int(getattr(settings, "CAMPUS_ZONE_NMAP_MIN_RATE", 5000))),
            "nmap_version_intensity": 3,
            "nmap_full_scan_timeout_seconds": 30,
        }
    return {
        "portset_mode": str(getattr(settings, "CAMPUS_DEFAULT_PORTSET_MODE", "top1000_plus_custom") or "top1000_plus_custom"),
        "allow_full_scan": False,
        "nmap_min_rate": max(1, int(getattr(settings, "CAMPUS_ZONE_NMAP_MIN_RATE", 5000))),
        "nmap_version_intensity": 5,
        "nmap_full_scan_timeout_seconds": 45,
    }
