from collections.abc import Generator
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api.deps import get_current_user, get_db_session
from app.db.models.enums import DiscoveryJobStatus, FindingStatus, RiskSeverity, TaskExecutionStatus, TaskType, UserRole
from app.db.models.task_run import TaskRun
from app.main import create_app


class _DummyDB:
    pass


def _override_user():
    return SimpleNamespace(id="user-1", role=UserRole.ADMIN, is_active=True)


def _build_client(monkeypatch, db: _DummyDB) -> TestClient:  # type: ignore[no-untyped-def]
    def _noop_create_all(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        return None

    def _get_test_db() -> Generator[_DummyDB, None, None]:
        yield db

    monkeypatch.setattr("app.main.Base.metadata.create_all", _noop_create_all)
    app = create_app()
    app.dependency_overrides[get_db_session] = _get_test_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app)


def test_mobile_overview_endpoint_returns_aggregates(monkeypatch) -> None:
    from app.api.v1.endpoints import mobile as mobile_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.RUNNING,
        scope_type="discovery_job",
        scope_id="job-1",
        progress=35,
        message="正在扫描",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=datetime(2026, 3, 19, 2, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 19, 2, 0, 5, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 19, 2, 0, 20, tzinfo=timezone.utc),
    )
    risk = SimpleNamespace(
        id="risk-1",
        asset_id="asset-1",
        asset_port_id="port-1",
        severity=RiskSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="弱口令风险",
        description="检测到默认口令",
        evidence_json={"service_name": "ssh"},
        detected_at=datetime(2026, 3, 19, 1, 59, tzinfo=timezone.utc),
        resolved_at=None,
        asset=SimpleNamespace(ip="10.10.0.8", hostname="srv-01"),
    )

    monkeypatch.setattr(
        mobile_endpoint,
        "_count_assets",
        lambda _db, status=None: 9 if status is None else 4,
    )
    monkeypatch.setattr(mobile_endpoint, "_count_open_high_risk_findings", lambda _db: 3)
    monkeypatch.setattr(mobile_endpoint, "_count_active_tasks", lambda _db: 2)
    monkeypatch.setattr(
        mobile_endpoint,
        "_count_discovery_jobs",
        lambda _db, status: 1 if status == DiscoveryJobStatus.PENDING else 2,
    )
    monkeypatch.setattr(mobile_endpoint, "list_task_runs", lambda *args, **kwargs: ([task], 1))
    monkeypatch.setattr(mobile_endpoint, "list_task_events_for_runs", lambda *args, **kwargs: {})
    monkeypatch.setattr(mobile_endpoint, "_list_recent_risks", lambda *args, **kwargs: [risk])

    response = client.get("/api/v1/mobile/overview")

    assert response.status_code == 200
    payload = response.json()
    assert payload["asset_total"] == 9
    assert payload["online_assets"] == 4
    assert payload["high_risk_findings"] == 3
    assert payload["active_tasks"] == 2
    assert payload["recent_tasks"][0]["id"] == "task-1"
    assert payload["recent_risks"][0]["asset_ip"] == "10.10.0.8"
    assert payload["discovery_entry"] == {
        "enabled": True,
        "pending_jobs": 1,
        "running_jobs": 2,
    }


def test_risk_list_endpoint_returns_mobile_payload(monkeypatch) -> None:
    from app.api.v1.endpoints import risks as risks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    risk = SimpleNamespace(
        id="risk-1",
        asset_id="asset-1",
        asset_port_id="port-1",
        severity=RiskSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        title="公开暴露",
        description="高危端口暴露",
        evidence_json={"port": 6379},
        detected_at=datetime(2026, 3, 19, 3, 0, tzinfo=timezone.utc),
        resolved_at=None,
        asset=SimpleNamespace(ip="10.10.0.9", hostname="redis-01"),
    )
    monkeypatch.setattr(risks_endpoint, "list_findings_page", lambda *args, **kwargs: ([risk], 1))

    response = client.get("/api/v1/risks", params={"severity": "critical"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"] == {"total": 1, "page": 1, "page_size": 20}
    assert payload["items"][0]["id"] == "risk-1"
    assert payload["items"][0]["asset_hostname"] == "redis-01"
    assert payload["items"][0]["severity"] == "critical"


def test_discovery_job_list_endpoint_returns_paginated_rows(monkeypatch) -> None:
    from app.api.v1.endpoints import discovery as discovery_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    job = SimpleNamespace(
        id="job-1",
        cidr="10.10.0.0/24",
        status=DiscoveryJobStatus.RUNNING,
        label="lab",
        started_at=datetime(2026, 3, 19, 4, 0, tzinfo=timezone.utc),
        finished_at=None,
        created_at=datetime(2026, 3, 19, 3, 59, tzinfo=timezone.utc),
        summary_json={"alive_hosts": 12},
    )
    monkeypatch.setattr(discovery_endpoint, "list_jobs", lambda *args, **kwargs: ([job], 1))

    response = client.get("/api/v1/discovery/jobs", params={"status": "running"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"] == {"total": 1, "page": 1, "page_size": 20}
    assert payload["items"][0]["id"] == "job-1"
    assert payload["items"][0]["status"] == "running"
    assert payload["items"][0]["summary_json"] == {"alive_hosts": 12}
