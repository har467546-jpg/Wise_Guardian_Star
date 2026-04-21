from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.db.models.asset import Asset
from app.db.models.campus_data_source import CampusDataSource
from app.db.models.discovery_job_execution import DiscoveryJobExecution
from app.db.models.host_runner import HostRunner
from app.db.models.scanner_node_assignment import ScannerNodeAssignment
from app.db.models.scanner_zone import ScannerZone


def list_scanner_zones(db: Session, *, page: int, page_size: int) -> tuple[list[ScannerZone], int]:
    stmt = select(ScannerZone).order_by(ScannerZone.priority.asc(), ScannerZone.name.asc())
    total = len(db.scalars(select(ScannerZone.id)).all())
    items = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return items, total


def get_scanner_zone(db: Session, zone_id: str | None) -> ScannerZone | None:
    if not zone_id:
        return None
    return db.get(ScannerZone, zone_id)


def list_scanner_node_assignments(db: Session, *, zone_id: str) -> list[ScannerNodeAssignment]:
    stmt = (
        select(ScannerNodeAssignment)
        .where(ScannerNodeAssignment.scanner_zone_id == zone_id)
        .options(joinedload(ScannerNodeAssignment.asset).joinedload(Asset.host_runner))
        .order_by(ScannerNodeAssignment.priority.asc(), ScannerNodeAssignment.created_at.asc())
    )
    return db.scalars(stmt).unique().all()


def list_campus_data_sources(db: Session, *, zone_id: str | None = None) -> list[CampusDataSource]:
    stmt = select(CampusDataSource).order_by(CampusDataSource.name.asc())
    if zone_id:
        stmt = stmt.where(CampusDataSource.scanner_zone_id == zone_id)
    return db.scalars(stmt).all()


def list_discovery_job_executions(db: Session, *, job_id: str) -> list[DiscoveryJobExecution]:
    stmt = (
        select(DiscoveryJobExecution)
        .where(DiscoveryJobExecution.discovery_job_id == job_id)
        .order_by(DiscoveryJobExecution.created_at.asc())
    )
    return db.scalars(stmt).all()


def find_matching_scanner_zones(db: Session, cidr: str) -> list[ScannerZone]:
    target = ipaddress.ip_network(cidr, strict=False)
    matched: list[tuple[int, ScannerZone]] = []
    for zone in db.scalars(select(ScannerZone).where(ScannerZone.enabled.is_(True))).all():
        for raw_cidr in zone.cidrs_json or []:
            try:
                zone_network = ipaddress.ip_network(str(raw_cidr), strict=False)
            except ValueError:
                continue
            if _networks_overlap(target, zone_network):
                matched.append((int(zone.priority or 100), zone))
                break
    matched.sort(key=lambda item: (item[0], str(item[1].name).lower()))
    return [zone for _, zone in matched]


def choose_scanner_node_for_zone(
    db: Session,
    *,
    zone: ScannerZone,
    target_cidr: str,
) -> ScannerNodeAssignment | None:
    target = ipaddress.ip_network(target_cidr, strict=False)
    assignments = list_scanner_node_assignments(db, zone_id=zone.id)
    candidates: list[tuple[int, ScannerNodeAssignment]] = []
    for assignment in assignments:
        if not assignment.enabled:
            continue
        asset = assignment.asset
        host_runner = getattr(asset, "host_runner", None) if asset is not None else None
        if host_runner is None:
            continue
        if str(host_runner.install_status or "").strip().lower() != "installed":
            continue
        if str(host_runner.status or "").strip().lower() not in {"online", "busy"}:
            continue
        if not _runner_heartbeat_is_fresh(host_runner):
            continue
        if assignment.visible_cidrs_json:
            visible = []
            for raw in assignment.visible_cidrs_json:
                try:
                    visible.append(ipaddress.ip_network(str(raw), strict=False))
                except ValueError:
                    continue
            if visible and not any(_networks_overlap(target, network) for network in visible):
                continue
        candidates.append((int(assignment.priority or 100), assignment))
    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], str(item[1].id)))
    return candidates[0][1]


def _networks_overlap(left: ipaddress._BaseNetwork, right: ipaddress._BaseNetwork) -> bool:
    if left.version != right.version:
        return False
    return left.overlaps(right)


def merge_zone_profile_with_defaults(zone: ScannerZone | None, defaults: dict[str, Any] | None = None) -> dict[str, Any]:
    merged = dict(defaults or {})
    if zone is not None and isinstance(zone.default_scan_profile_json, dict):
        merged.update(zone.default_scan_profile_json)
    return merged


def _runner_heartbeat_is_fresh(runner: HostRunner) -> bool:
    last_seen = getattr(runner, "last_seen_at", None)
    if last_seen is None:
        return False
    grace_seconds = max(5, int(getattr(settings, "RUNNER_OFFLINE_GRACE_SECONDS", 45)))
    return datetime.now(timezone.utc) - last_seen <= timedelta(seconds=grace_seconds)
