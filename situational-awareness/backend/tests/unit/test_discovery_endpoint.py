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


def test_create_discovery_job_normalizes_host_bits_before_lookup_and_create(monkeypatch) -> None:
    observed: dict[str, str] = {}

    def _get_active_job_by_cidr(db, cidr):  # type: ignore[no-untyped-def]
        observed["lookup_cidr"] = cidr
        return None

    def _create_job(**kwargs):  # type: ignore[no-untyped-def]
        observed["create_cidr"] = kwargs["cidr"]
        return _job("job-normalized")

    monkeypatch.setattr(discovery_endpoint, "get_active_job_by_cidr", _get_active_job_by_cidr)
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
