from __future__ import annotations

from types import SimpleNamespace

from app.db.models.enums import DiscoveryJobStatus, TaskExecutionStatus
from app.services import campus_discovery_service


class _FakeDB:
    def __init__(self) -> None:
        self.added: list[object] = []
        self.committed = False

    def add(self, item: object) -> None:
        self.added.append(item)

    def flush(self) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def refresh(self, item: object) -> None:  # noqa: ARG002 - no-op for fake session
        return None


def test_schedule_campus_discovery_job_marks_parent_failed_when_no_runner_available(monkeypatch) -> None:
    db = _FakeDB()
    zone = SimpleNamespace(id="zone-1", name="Auto Zone")
    job = SimpleNamespace(
        id="job-1",
        cidr="192.168.130.0/24",
        status=DiscoveryJobStatus.PENDING,
        started_at=None,
        finished_at=None,
        summary_json={},
    )
    parent_task = SimpleNamespace(id="task-parent", result_json={"context": {"job_id": "job-1"}})
    observed: dict[str, object] = {}

    monkeypatch.setattr(campus_discovery_service, "_resolve_target_zones", lambda db, cidr, scanner_zone_id: [zone])
    monkeypatch.setattr(campus_discovery_service, "choose_scanner_node_for_zone", lambda db, zone, target_cidr: None)
    monkeypatch.setattr(campus_discovery_service, "get_task_run", lambda db, task_id: parent_task if task_id == "task-parent" else None)

    def _update_task_run(db, task, **kwargs):  # type: ignore[no-untyped-def]
        observed.update(kwargs)
        task.status = kwargs.get("status")
        task.message = kwargs.get("message")
        task.error_json = kwargs.get("error_json")
        task.result_json = kwargs.get("result_json")
        return task

    monkeypatch.setattr(campus_discovery_service, "update_task_run", _update_task_run)

    executions = campus_discovery_service.schedule_campus_discovery_job(
        db,
        job=job,
        parent_task_id="task-parent",
        scanner_zone_id=None,
    )

    assert db.committed is True
    assert len(executions) == 1
    assert executions[0].status == "failure"
    assert executions[0].error_json == {"message": "未找到可用的扫描节点"}
    assert job.status == DiscoveryJobStatus.FAILED
    assert job.started_at is not None
    assert job.finished_at is not None
    assert observed["status"] == TaskExecutionStatus.FAILURE
    assert observed["progress"] == 100
    assert observed["message"] == "未找到可用的扫描节点"
    assert observed["error_json"] == {"message": "未找到可用的扫描节点"}
    assert job.summary_json["campus_dispatch"]["failed_execution_count"] == 1
    assert job.summary_json["campus_dispatch"]["errors"] == [
        {"scanner_zone_id": "zone-1", "zone_name": "Auto Zone", "message": "未找到可用的扫描节点"}
    ]
