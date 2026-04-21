from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_user, get_db_session
from app.core.security import SecurityError, decode_access_token
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import AssetStatus, DiscoveryJobStatus, FindingStatus, RiskSeverity, TaskExecutionStatus
from app.db.models.risk_finding import RiskFinding
from app.db.models.task_run import TaskRun
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.task_event_repo import list_task_events_for_runs
from app.repositories.task_repo import list_task_runs
from app.schemas.mobile import MobileDiscoveryEntryRead, MobileOverviewRead
from app.schemas.risk import RiskFindingMobileRead
from app.schemas.task import TaskRunRead
from app.services.device_alert_service import device_alert_hub
from app.services.task_observability_service import serialize_task_run

router = APIRouter()

ACTIVE_TASK_STATUSES = (
    TaskExecutionStatus.PENDING,
    TaskExecutionStatus.RUNNING,
    TaskExecutionStatus.RETRY,
)
HIGH_RISK_SEVERITIES = (
    RiskSeverity.HIGH,
    RiskSeverity.CRITICAL,
)


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
            "yaml_rule_id": finding.resolved_yaml_rule_id(),
            "identity_hash": finding.identity_hash,
            "severity": finding.severity,
            "status": finding.status,
            "title": finding.title,
            "description": finding.description,
            "evidence_json": finding.evidence(),
            "detected_at": finding.detected_at,
            "resolved_at": finding.resolved_at,
            "verification_status": finding.resolved_verification_status(),
            "match_source": finding.resolved_match_source(),
        }
    )


@router.get("/overview", response_model=MobileOverviewRead)
def get_mobile_overview(
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> MobileOverviewRead:
    recent_tasks, _ = list_task_runs(db, page=1, page_size=5)
    event_map = list_task_events_for_runs(db, [item.id for item in recent_tasks]) if recent_tasks else {}
    recent_risks = _list_recent_risks(db, limit=5)
    return MobileOverviewRead(
        asset_total=_count_assets(db),
        online_assets=_count_assets(db, status=AssetStatus.ONLINE),
        high_risk_findings=_count_open_high_risk_findings(db),
        active_tasks=_count_active_tasks(db),
        recent_tasks=[
            TaskRunRead.model_validate(serialize_task_run(item, events=event_map.get(item.id, [])))
            for item in recent_tasks
        ],
        recent_risks=[_serialize_risk_item(item) for item in recent_risks],
        discovery_entry=MobileDiscoveryEntryRead(
            enabled=True,
            pending_jobs=_count_discovery_jobs(db, status=DiscoveryJobStatus.PENDING),
            running_jobs=_count_discovery_jobs(db, status=DiscoveryJobStatus.RUNNING),
        ),
    )


@router.websocket("/alerts/stream")
async def stream_mobile_device_alerts(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token") or ""
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return

    with SessionLocal() as db:
        user = _resolve_websocket_user(db, token)
        if user is None:
            await websocket.close(code=1008, reason="unauthorized")
            return
        user_id = user.id

    await device_alert_hub.connect(user_id=user_id, websocket=websocket)
    await websocket.send_json({"type": "ready"})
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        return
    finally:
        await device_alert_hub.disconnect(user_id=user_id, websocket=websocket)


def _resolve_websocket_user(db: Session, token: str) -> User | None:
    try:
        payload = decode_access_token(token)
    except SecurityError:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user
