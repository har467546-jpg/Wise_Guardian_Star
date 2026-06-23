from collections.abc import Generator
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_user, get_db_session
from app.db.base import Base
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import AssetStatus, DiscoveryJobStatus, FindingStatus, RiskSeverity, TaskExecutionStatus, TaskType, UserRole
from app.db.models.risk_finding import RiskFinding
from app.db.models.task_run import TaskRun
from app.main import create_app


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "JSON"


@compiles(INET, "sqlite")
def _compile_inet_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


@compiles(CIDR, "sqlite")
def _compile_cidr_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


def _override_user():
    return SimpleNamespace(id="user-1", role=UserRole.ADMIN, is_active=True)


def _build_client() -> tuple[TestClient, sessionmaker[Session]]:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_local = sessionmaker(
        bind=engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )
    Base.metadata.create_all(bind=engine)

    def _get_test_db() -> Generator[Session, None, None]:
        with session_local() as db:
            yield db

    app = create_app()
    app.dependency_overrides[get_db_session] = _get_test_db
    app.dependency_overrides[get_current_user] = _override_user
    client = TestClient(app)
    return client, session_local


def _task(
    *,
    task_id: str,
    task_type: TaskType,
    status: TaskExecutionStatus,
    updated_at: datetime,
    message: str,
) -> TaskRun:
    return TaskRun(
        id=task_id,
        task_type=task_type,
        status=status,
        scope_type="asset",
        scope_id=str(uuid4()),
        progress=55,
        message=message,
        retry_count=0,
        result_json={},
        error_json={},
        created_at=updated_at,
        started_at=updated_at,
        finished_at=None,
        updated_at=updated_at,
    )


def test_dashboard_overview_endpoint_returns_aggregated_payload() -> None:
    client, session_local = _build_client()
    now = datetime.now(timezone.utc)

    with session_local() as db:
        assets = [
            Asset(id="asset-critical", ip="10.0.0.1", hostname="critical-node", status=AssetStatus.ONLINE, last_seen_at=now),
            Asset(id="asset-high-3", ip="10.0.0.2", hostname="high-node-3", status=AssetStatus.ONLINE, last_seen_at=now),
            Asset(id="asset-high-2", ip="10.0.0.3", hostname="high-node-2", status=AssetStatus.OFFLINE, last_seen_at=now),
            Asset(id="asset-medium", ip="10.0.0.4", hostname="medium-node", status=AssetStatus.ONLINE, last_seen_at=now),
            Asset(id="asset-low", ip="10.0.0.5", hostname="low-node", status=AssetStatus.OFFLINE, last_seen_at=now),
            Asset(id="asset-high-1", ip="10.0.0.6", hostname="high-node-1", status=AssetStatus.UNKNOWN, last_seen_at=now),
        ]
        db.add_all(assets)
        db.add_all(
            [
                RiskFinding(
                    id="risk-critical-1",
                    asset_id="asset-critical",
                    severity=RiskSeverity.CRITICAL,
                    status=FindingStatus.OPEN,
                    title="critical-1",
                    description="critical",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 6, 0, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-high-1",
                    asset_id="asset-high-3",
                    severity=RiskSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    title="high-1",
                    description="high",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 59, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-high-2",
                    asset_id="asset-high-3",
                    severity=RiskSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    title="high-2",
                    description="high",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 58, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-high-3",
                    asset_id="asset-high-3",
                    severity=RiskSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    title="high-3",
                    description="high",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 57, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-high-4",
                    asset_id="asset-high-2",
                    severity=RiskSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    title="high-4",
                    description="high",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 56, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-high-5",
                    asset_id="asset-high-2",
                    severity=RiskSeverity.HIGH,
                    status=FindingStatus.OPEN,
                    title="high-5",
                    description="high",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 55, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-medium-1",
                    asset_id="asset-medium",
                    severity=RiskSeverity.MEDIUM,
                    status=FindingStatus.OPEN,
                    title="medium-1",
                    description="medium",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 54, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-low-1",
                    asset_id="asset-low",
                    severity=RiskSeverity.LOW,
                    status=FindingStatus.OPEN,
                    title="low-1",
                    description="low",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 53, tzinfo=timezone.utc),
                ),
                RiskFinding(
                    id="risk-fixed-1",
                    asset_id="asset-high-1",
                    severity=RiskSeverity.CRITICAL,
                    status=FindingStatus.FIXED,
                    title="fixed-1",
                    description="fixed",
                    evidence_json={},
                    detected_at=datetime(2026, 3, 25, 5, 52, tzinfo=timezone.utc),
                ),
            ]
        )
        db.add_all(
            [
                DiscoveryJob(
                    id="job-pending",
                    cidr="10.0.0.0/24",
                    status=DiscoveryJobStatus.PENDING,
                    label="pending",
                    created_at=now,
                    summary_json={},
                ),
                DiscoveryJob(
                    id="job-running",
                    cidr="10.0.1.0/24",
                    status=DiscoveryJobStatus.RUNNING,
                    label="running",
                    created_at=now,
                    summary_json={},
                ),
                DiscoveryJob(
                    id="job-completed",
                    cidr="10.0.2.0/24",
                    status=DiscoveryJobStatus.COMPLETED,
                    label="completed",
                    created_at=now,
                    summary_json={},
                ),
            ]
        )
        db.add_all(
            [
                _task(
                    task_id="task-newest",
                    task_type=TaskType.ASSET_SCAN,
                    status=TaskExecutionStatus.RUNNING,
                    updated_at=now,
                    message="newest",
                ),
                _task(
                    task_id="task-middle",
                    task_type=TaskType.RISK_VERIFY,
                    status=TaskExecutionStatus.PENDING,
                    updated_at=now - timedelta(minutes=1),
                    message="middle",
                ),
                _task(
                    task_id="task-oldest",
                    task_type=TaskType.REPORT_GENERATE,
                    status=TaskExecutionStatus.SUCCESS,
                    updated_at=now - timedelta(minutes=2),
                    message="oldest",
                ),
                _task(
                    task_id="task-stale-pending",
                    task_type=TaskType.REPORT_GENERATE,
                    status=TaskExecutionStatus.PENDING,
                    updated_at=now - timedelta(hours=48),
                    message="stale",
                ),
            ]
        )
        db.commit()

    response = client.get("/api/v1/dashboard/overview")

    assert response.status_code == 200
    payload = response.json()
    assert payload["asset_total"] == 6
    assert payload["online_assets"] == 3
    assert payload["high_risk_findings"] == 6
    assert payload["active_tasks"] == 2
    assert payload["discovery_entry"] == {
        "enabled": True,
        "pending_jobs": 1,
        "running_jobs": 1,
    }
    assert payload["severity_totals"] == {
        "critical": 1,
        "high": 5,
        "medium": 1,
        "low": 1,
    }
    assert [item["id"] for item in payload["risky_assets"]] == [
        "asset-critical",
        "asset-high-3",
        "asset-high-2",
        "asset-medium",
        "asset-low",
    ]
    assert payload["risky_assets"][0]["highest_severity"] == "critical"
    assert payload["risky_assets"][1]["finding_count"] == 3
    task_health_by_id = {item["id"]: item for item in payload["task_health"]}
    assert set(task_health_by_id) == {
        "task-newest",
        "task-middle",
        "task-oldest",
        "task-stale-pending",
    }
    assert task_health_by_id["task-stale-pending"]["status"] == "failure"
    assert payload["recent_risks"][0]["id"] == "risk-critical-1"

    with session_local() as db:
        stale_task = db.get(TaskRun, "task-stale-pending")
        assert stale_task is not None
        assert stale_task.status == TaskExecutionStatus.FAILURE
        assert stale_task.error_json["reason"] == "stale_active_task"

    client.close()
