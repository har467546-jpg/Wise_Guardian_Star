from datetime import datetime, timezone
from ipaddress import ip_network
from types import SimpleNamespace

from fastapi import Response

from app.api.v1.endpoints import discovery as discovery_endpoint
from app.db.models.enums import DiscoveryJobStatus
from app.schemas.discovery import DiscoveryJobCreate


class DummyDB:
    def rollback(self) -> None:
        return None

    def add(self, item) -> None:  # noqa: ARG002 - no-op fake
        return None

    def commit(self) -> None:
        return None

    def refresh(self, item) -> None:  # noqa: ARG002 - no-op fake
        return None


def _job(job_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=job_id,
        cidr=ip_network("10.10.0.0/24"),
        status=DiscoveryJobStatus.PENDING,
        label="test",
        started_at=None,
        finished_at=None,
        created_at=datetime.now(timezone.utc),
        summary_json={},
    )


def test_create_discovery_job_reuses_active_job(monkeypatch) -> None:
    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "find_matching_scanner_zones", lambda db, cidr: [])
    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", lambda db, cidr: _job("job-active"))
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: SimpleNamespace(id="task-active"))
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-created"))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: SimpleNamespace(id="celery-task")),
    )
    monkeypatch.setattr(discovery_endpoint, "update_task_run", lambda db, task, **kwargs: task)

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=DiscoveryJobCreate(cidr="10.10.0.0/24", label="reuse"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 200
    assert result.reused is True
    assert result.status == "reused"
    assert result.task_id == "task-active"
    assert str(result.job.cidr) == "10.10.0.0/24"


def test_create_discovery_job_creates_new_job(monkeypatch) -> None:
    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "find_matching_scanner_zones", lambda db, cidr: [])
    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", lambda db, cidr: None)
    monkeypatch.setattr(discovery_endpoint, "create_job", lambda **kwargs: _job("job-new"))
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-new"))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: SimpleNamespace(id="celery-new")),
    )
    monkeypatch.setattr(discovery_endpoint, "update_task_run", lambda db, task, **kwargs: task)

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=DiscoveryJobCreate(cidr="10.10.0.0/24", label="create"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 201
    assert result.reused is False
    assert result.status == "pending"
    assert result.task_id == "task-new"
    assert str(result.job.cidr) == "10.10.0.0/24"


def test_create_discovery_job_with_runner_dispatch_skips_local_celery(monkeypatch) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", lambda db, cidr: None)
    monkeypatch.setattr(discovery_endpoint, "create_job", lambda **kwargs: _job("job-runner"))
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        discovery_endpoint,
        "resolve_runner_by_asset_for_read",
        lambda db, asset_id: SimpleNamespace(asset_id=asset_id, install_status="installed", status="online"),
    )
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-runner", result_json={}))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not dispatch celery for runner jobs"))),
    )

    def _update_task_run(db, task, **kwargs):  # type: ignore[no-untyped-def]
        observed["message"] = kwargs.get("message")
        observed["result_json"] = kwargs.get("result_json")
        return task

    monkeypatch.setattr(discovery_endpoint, "update_task_run", _update_task_run)

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=DiscoveryJobCreate(cidr="10.10.0.0/24", label="runner", runner_asset_id="asset-runner-1"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 201
    assert result.task_id == "task-runner"
    assert observed["message"] == "等待扫描节点接单"
    assert observed["result_json"]["context"]["runner_asset_id"] == "asset-runner-1"


def test_create_discovery_job_with_scanner_zone_schedules_campus_dispatch(monkeypatch) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", lambda db, cidr: None)
    monkeypatch.setattr(discovery_endpoint, "get_scanner_zone", lambda db, zone_id: SimpleNamespace(id=zone_id, enabled=True))
    monkeypatch.setattr(discovery_endpoint, "create_job", lambda **kwargs: _job("job-zone"))
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-zone", result_json={}))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not dispatch celery for zone jobs"))),
    )
    monkeypatch.setattr(
        discovery_endpoint,
        "schedule_campus_discovery_job",
        lambda db, job, parent_task_id, scanner_zone_id: observed.update(
            {
                "scheduled_job_id": job.id,
                "scheduled_parent_task_id": parent_task_id,
                "scheduled_zone_id": scanner_zone_id,
            }
        ),
    )
    monkeypatch.setattr(
        discovery_endpoint,
        "update_task_run",
        lambda db, task, **kwargs: observed.update({"result_json": kwargs.get("result_json"), "message": kwargs.get("message")}) or task,
    )

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=DiscoveryJobCreate(cidr="10.10.0.0/24", label="zone", scanner_zone_id="zone-1"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 201
    assert result.task_id == "task-zone"
    assert observed["scheduled_job_id"] == "job-zone"
    assert observed["scheduled_parent_task_id"] == "task-zone"
    assert observed["scheduled_zone_id"] == "zone-1"
    assert observed["result_json"]["context"]["scanner_zone_id"] == "zone-1"


def test_create_discovery_job_auto_matched_zone_uses_runner_dispatch(monkeypatch) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", lambda db, cidr: None)
    monkeypatch.setattr(discovery_endpoint, "find_matching_scanner_zones", lambda db, cidr: [SimpleNamespace(id="zone-auto", enabled=True)])
    monkeypatch.setattr(discovery_endpoint, "create_job", lambda **kwargs: _job("job-auto-zone"))
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-auto-zone", result_json={}))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not dispatch celery when auto-matched zones exist"))),
    )
    monkeypatch.setattr(
        discovery_endpoint,
        "schedule_campus_discovery_job",
        lambda db, job, parent_task_id, scanner_zone_id: observed.update(
            {
                "scheduled_job_id": job.id,
                "scheduled_parent_task_id": parent_task_id,
                "scheduled_zone_id": scanner_zone_id,
            }
        ),
    )
    monkeypatch.setattr(
        discovery_endpoint,
        "update_task_run",
        lambda db, task, **kwargs: observed.update({"message": kwargs.get("message"), "result_json": kwargs.get("result_json")}) or task,
    )

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=DiscoveryJobCreate(cidr="10.10.0.0/24", label="auto-zone"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 201
    assert result.task_id == "task-auto-zone"
    assert observed["message"] == "等待扫描节点接单"
    assert observed["result_json"]["context"]["execution_boundary"] == "runner_dispatch"
    assert observed["scheduled_job_id"] == "job-auto-zone"


def test_create_discovery_job_normalizes_host_bits_before_lookup_and_create(monkeypatch) -> None:
    observed: dict[str, str] = {}

    def _get_active_job_by_cidr(db, cidr):  # type: ignore[no-untyped-def]
        observed["lookup_cidr"] = cidr
        return None

    def _create_job(**kwargs):  # type: ignore[no-untyped-def]
        observed["create_cidr"] = kwargs["cidr"]
        return _job("job-normalized")

    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", _get_active_job_by_cidr)
    monkeypatch.setattr(discovery_endpoint, "ensure_campus_auto_bootstrap", lambda db: {})
    monkeypatch.setattr(discovery_endpoint, "find_matching_scanner_zones", lambda db, cidr: [])
    monkeypatch.setattr(discovery_endpoint, "create_job", _create_job)
    monkeypatch.setattr(discovery_endpoint, "get_latest_task_run_for_scope", lambda *args, **kwargs: None)
    monkeypatch.setattr(discovery_endpoint, "create_task_run", lambda *args, **kwargs: SimpleNamespace(id="task-normalized"))
    monkeypatch.setattr(
        discovery_endpoint,
        "run_asset_scan_task",
        SimpleNamespace(delay=lambda *args, **kwargs: SimpleNamespace(id="celery-normalized")),
    )
    monkeypatch.setattr(discovery_endpoint, "update_task_run", lambda db, task, **kwargs: task)

    response = Response()
    result = discovery_endpoint.create_discovery_job(
        payload=SimpleNamespace(cidr="10.10.0.9/24", label="normalize"),
        response=response,
        db=DummyDB(),
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.status_code == 201
    assert observed["lookup_cidr"] == "10.10.0.0/24"
    assert observed["create_cidr"] == "10.10.0.0/24"
    assert str(result.job.cidr) == "10.10.0.0/24"
