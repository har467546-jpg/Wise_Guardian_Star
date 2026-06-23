from __future__ import annotations

from sqlalchemy import case, desc, func, select
from sqlalchemy.orm import Session, joinedload

from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import AssetStatus, DiscoveryJobStatus, FindingStatus, RiskSeverity, TaskExecutionStatus
from app.db.models.risk_finding import RiskFinding
from app.db.models.task_run import TaskRun
from app.schemas.dashboard import (
    DashboardOverviewRead,
    DashboardRiskyAssetRead,
    DashboardSeverityTotalsRead,
)
from app.schemas.mobile import MobileDiscoveryEntryRead
from app.schemas.risk import RiskFindingMobileRead
from app.schemas.task import TaskRunRead
from app.repositories.task_event_repo import list_task_events_for_runs
from app.services.task_observability_service import serialize_task_run
from app.services.task_reconciliation_service import reconcile_stale_active_tasks

ACTIVE_TASK_STATUSES = (
    TaskExecutionStatus.PENDING,
    TaskExecutionStatus.RUNNING,
    TaskExecutionStatus.RETRY,
)
HIGH_RISK_SEVERITIES = (
    RiskSeverity.HIGH,
    RiskSeverity.CRITICAL,
)
SEVERITY_RANK = {
    RiskSeverity.LOW: 1,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.HIGH: 3,
    RiskSeverity.CRITICAL: 4,
}
RANK_TO_SEVERITY = {value: key for key, value in SEVERITY_RANK.items()}


def _count_assets(db: Session, *, status: AssetStatus | None = None) -> int:
    stmt = select(func.count(Asset.id))
    if status is not None:
        stmt = stmt.where(Asset.status == status)
    return int(db.scalar(stmt) or 0)


def _count_open_high_risk_findings(db: Session) -> int:
    stmt = select(func.count(RiskFinding.id)).where(
        RiskFinding.status == FindingStatus.OPEN,
        RiskFinding.severity.in_(HIGH_RISK_SEVERITIES),
    )
    return int(db.scalar(stmt) or 0)


def _count_active_tasks(db: Session) -> int:
    stmt = select(func.count(TaskRun.id)).where(TaskRun.status.in_(ACTIVE_TASK_STATUSES))
    return int(db.scalar(stmt) or 0)


def _count_discovery_jobs(db: Session, *, status: DiscoveryJobStatus) -> int:
    stmt = select(func.count(DiscoveryJob.id)).where(DiscoveryJob.status == status)
    return int(db.scalar(stmt) or 0)


def _list_recent_risks(db: Session, *, limit: int = 5) -> list[RiskFinding]:
    stmt = (
        select(RiskFinding)
        .options(joinedload(RiskFinding.asset), joinedload(RiskFinding.asset_port), joinedload(RiskFinding.rule))
        .where(RiskFinding.status == FindingStatus.OPEN)
        .order_by(RiskFinding.detected_at.desc())
        .limit(max(1, min(limit, 20)))
    )
    return db.scalars(stmt).unique().all()


def _serialize_risk_item(finding: RiskFinding) -> RiskFindingMobileRead:
    asset = finding.asset
    return RiskFindingMobileRead.model_validate(
        {
            "id": finding.id,
            "asset_id": finding.asset_id,
            "asset_ip": str(asset.ip) if asset is not None else "",
            "asset_hostname": asset.hostname if asset is not None else None,
            "asset_port_id": finding.asset_port_id,
            "severity": finding.severity,
            "status": finding.status,
            "title": finding.title,
            "description": finding.description,
            "evidence_json": finding.evidence_json or {},
            "detected_at": finding.detected_at,
            "resolved_at": finding.resolved_at,
        }
    )


def _load_task_health(db: Session, *, limit: int = 8) -> list[TaskRunRead]:
    stmt = select(TaskRun).order_by(TaskRun.updated_at.desc(), TaskRun.created_at.desc()).limit(max(1, min(limit, 20)))
    tasks = db.scalars(stmt).all()
    event_map = list_task_events_for_runs(db, [item.id for item in tasks]) if tasks else {}
    return [
        TaskRunRead.model_validate(serialize_task_run(item, events=event_map.get(item.id, [])))
        for item in tasks
    ]


def _load_severity_totals(db: Session) -> DashboardSeverityTotalsRead:
    stmt = (
        select(RiskFinding.severity, func.count(RiskFinding.id))
        .where(RiskFinding.status == FindingStatus.OPEN)
        .group_by(RiskFinding.severity)
    )
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for severity, count in db.execute(stmt).all():
        key = str(getattr(severity, "value", severity) or "").strip().lower()
        if key in totals:
            totals[key] = int(count or 0)
    return DashboardSeverityTotalsRead(**totals)


def _load_risky_assets(db: Session, *, limit: int = 5) -> list[DashboardRiskyAssetRead]:
    severity_rank_expr = case(
        (RiskFinding.severity == RiskSeverity.CRITICAL, SEVERITY_RANK[RiskSeverity.CRITICAL]),
        (RiskFinding.severity == RiskSeverity.HIGH, SEVERITY_RANK[RiskSeverity.HIGH]),
        (RiskFinding.severity == RiskSeverity.MEDIUM, SEVERITY_RANK[RiskSeverity.MEDIUM]),
        else_=SEVERITY_RANK[RiskSeverity.LOW],
    )
    stmt = (
        select(
            Asset.id,
            Asset.ip,
            Asset.hostname,
            func.count(RiskFinding.id).label("finding_count"),
            func.max(severity_rank_expr).label("highest_rank"),
        )
        .join(RiskFinding, RiskFinding.asset_id == Asset.id)
        .where(RiskFinding.status == FindingStatus.OPEN)
        .group_by(Asset.id, Asset.ip, Asset.hostname, Asset.last_seen_at)
        .order_by(desc("highest_rank"), desc("finding_count"), Asset.last_seen_at.desc())
        .limit(max(1, min(limit, 20)))
    )
    items: list[DashboardRiskyAssetRead] = []
    for asset_id, ip, hostname, finding_count, highest_rank in db.execute(stmt).all():
        severity = RANK_TO_SEVERITY.get(int(highest_rank or 0), RiskSeverity.LOW)
        items.append(
            DashboardRiskyAssetRead(
                id=str(asset_id),
                ip=str(ip),
                hostname=hostname,
                finding_count=int(finding_count or 0),
                highest_severity=severity,
            )
        )
    return items


def build_dashboard_overview(db: Session) -> DashboardOverviewRead:
    reconcile_stale_active_tasks(db)
    return DashboardOverviewRead(
        asset_total=_count_assets(db),
        online_assets=_count_assets(db, status=AssetStatus.ONLINE),
        high_risk_findings=_count_open_high_risk_findings(db),
        active_tasks=_count_active_tasks(db),
        discovery_entry=MobileDiscoveryEntryRead(
            enabled=True,
            pending_jobs=_count_discovery_jobs(db, status=DiscoveryJobStatus.PENDING),
            running_jobs=_count_discovery_jobs(db, status=DiscoveryJobStatus.RUNNING),
        ),
        recent_risks=[_serialize_risk_item(item) for item in _list_recent_risks(db, limit=5)],
        risky_assets=_load_risky_assets(db, limit=5),
        severity_totals=_load_severity_totals(db),
        task_health=_load_task_health(db, limit=8),
    )
