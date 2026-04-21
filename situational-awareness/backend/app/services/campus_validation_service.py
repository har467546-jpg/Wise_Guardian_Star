from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.db.models.campus_data_source import CampusDataSource
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.discovery_job_execution import DiscoveryJobExecution
from app.db.models.host_runner import HostRunner
from app.db.models.scanner_zone import ScannerZone


def build_campus_preprod_validation_report(db: Session) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(minutes=30)

    zone_count = int(db.scalar(select(func.count(ScannerZone.id))) or 0)
    runner_count = int(db.scalar(select(func.count(HostRunner.id))) or 0)
    source_count = int(db.scalar(select(func.count(CampusDataSource.id))) or 0)
    asset_count = int(db.scalar(select(func.count(Asset.id))) or 0)
    execution_count = int(db.scalar(select(func.count(DiscoveryJobExecution.id))) or 0)

    runner_online_count = int(
        db.scalar(select(func.count(HostRunner.id)).where(HostRunner.last_seen_at.is_not(None), HostRunner.last_seen_at >= stale_cutoff))
        or 0
    )
    source_error_count = int(
        db.scalar(select(func.count(CampusDataSource.id)).where(CampusDataSource.last_error.is_not(None)))
        or 0
    )
    unresolved_execution_count = int(
        db.scalar(
            select(func.count(DiscoveryJobExecution.id)).where(
                DiscoveryJobExecution.status.not_in(["success", "failure", "failed", "canceled"])
            )
        )
        or 0
    )
    stale_open_port_assets = [
        str(asset.id)
        for asset in db.scalars(select(Asset).where(Asset.is_virtual_network_component.is_(False))).all()
        if any(str(port.state or "").strip().lower() == "open" for port in asset.ports or [])
    ]

    report = {
        "generated_at": now.isoformat(),
        "summary": {
            "zone_count": zone_count,
            "runner_count": runner_count,
            "runner_online_count": runner_online_count,
            "data_source_count": source_count,
            "data_source_error_count": source_error_count,
            "asset_count": asset_count,
            "execution_count": execution_count,
            "unresolved_execution_count": unresolved_execution_count,
        },
        "checks": {
            "zone_count_gte_10": zone_count >= 10,
            "runner_count_gte_5": runner_count >= 5,
            "data_source_count_gte_2": source_count >= 2,
            "no_unresolved_executions": unresolved_execution_count == 0,
            "no_data_source_errors": source_error_count == 0,
            "no_runner_self_purged": runner_online_count > 0,
            "stale_open_port_asset_count": len(stale_open_port_assets),
        },
        "artifacts": {
            "stale_open_port_assets": stale_open_port_assets,
            "recent_jobs": [
                {
                    "job_id": item.id,
                    "cidr": str(item.cidr),
                    "status": item.status.value if hasattr(item.status, "value") else str(item.status),
                    "scanner_zone_id": item.scanner_zone_id,
                    "started_at": item.started_at.isoformat() if item.started_at else None,
                    "finished_at": item.finished_at.isoformat() if item.finished_at else None,
                }
                for item in db.scalars(select(DiscoveryJob).order_by(DiscoveryJob.created_at.desc()).limit(10)).all()
            ],
        },
    }
    return report
