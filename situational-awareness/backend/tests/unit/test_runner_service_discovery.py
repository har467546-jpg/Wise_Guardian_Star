from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from app.db.models.enums import DiscoveryJobStatus, TaskExecutionStatus, TaskType
from app.schemas.remediation import RunnerTaskCompleteRequest
from app.services import runner_service
from app.tasks import discovery_tasks


class _FakeScalars:
    def __init__(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)


class _FakeExecuteResult:
    def __init__(self, items):
        self._items = list(items)

    def scalars(self):
        return _FakeScalars(self._items)


class _FakeDB:
    def __init__(self, *, tasks=None, jobs=None):
        self.tasks = list(tasks or [])
        self.jobs = dict(jobs or {})
        self.added = []
        self.committed = False

    def execute(self, stmt):  # noqa: ARG002 - SQL is not evaluated in unit fake
        return _FakeExecuteResult(self.tasks)

    def get(self, model, object_id):
        if getattr(model, "__name__", "") == "DiscoveryJob":
            return self.jobs.get(object_id)
        return None

    def add(self, item):
        self.added.append(item)

    def commit(self):
        self.committed = True

    def refresh(self, item):  # noqa: ARG002 - no-op for fake session
        return None


def test_poll_runner_assignments_includes_asset_scan_tasks(monkeypatch) -> None:
    task = SimpleNamespace(
        id="task-scan-1",
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_job",
        scope_id="job-1",
        status=TaskExecutionStatus.PENDING,
        progress=0,
        message=None,
        result_json={"context": {"runner_asset_id": "asset-runner-1"}},
        created_at=datetime.now(timezone.utc),
    )
    job = SimpleNamespace(
        id="job-1",
        cidr="10.10.0.0/24",
        status=DiscoveryJobStatus.PENDING,
        started_at=None,
    )
    runner = SimpleNamespace(
        id="runner-1",
        asset_id="asset-runner-1",
        status="online",
        install_status="installed",
        capabilities_json={},
        last_seen_at=None,
        last_error=None,
        version="2.0.0",
        platform_url="http://platform",
    )
    db = _FakeDB(tasks=[task], jobs={"job-1": job})

    monkeypatch.setattr(runner_service, "update_task_run", lambda db, task, **kwargs: task)
    monkeypatch.setattr(runner_service, "create_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner_service, "update_discovery_execution_from_task", lambda *args, **kwargs: None)
    monkeypatch.setattr(runner_service, "_build_discovery_assignment_execution_script", lambda **kwargs: "echo discovery")

    response = runner_service.poll_runner_assignments(db, runner, max_tasks=1)

    assert response.next_task_id == "task-scan-1"
    assert response.next_execution_script_b64 is not None
    assert len(response.assignments) == 1
    assert response.assignments[0].task_type == "asset_scan"
    assert response.assignments[0].plan["cidr"] == "10.10.0.0/24"


def test_complete_runner_task_routes_asset_scan_results(monkeypatch) -> None:
    task = SimpleNamespace(
        id="task-scan-2",
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_job",
        scope_id="job-2",
        status=TaskExecutionStatus.RUNNING,
        progress=50,
        message=None,
        result_json={"context": {"runner_asset_id": "asset-runner-2"}},
    )
    runner = SimpleNamespace(
        id="runner-2",
        asset_id="asset-runner-2",
        status="busy",
        install_status="installed",
        last_seen_at=None,
        last_error=None,
    )
    db = _FakeDB()

    monkeypatch.setattr(runner_service, "get_task_run", lambda db, task_id: task if task_id == "task-scan-2" else None)
    monkeypatch.setattr(
        discovery_tasks,
        "apply_runner_discovery_scan_result",
        lambda job_id, scan_result: {"host_count": 2, "open_port_count": 4, "source_stats": {"nmap_host_discovery": 2}},
    )
    monkeypatch.setattr(
        runner_service,
        "update_task_run",
        lambda db, task, **kwargs: setattr(task, "status", kwargs.get("status")) or task,
    )
    monkeypatch.setattr(runner_service, "create_task_event", lambda *args, **kwargs: None)

    result = runner_service.complete_runner_task(
        db,
        runner,
        "task-scan-2",
        RunnerTaskCompleteRequest(
            status="success",
            execution={"scan_result": {"hosts": [{"ip": "10.10.0.5"}]}},
            message="runner scan ok",
        ),
    )

    assert task.status == TaskExecutionStatus.SUCCESS
    assert result["scan_summary"]["host_count"] == 2
    assert result["context"]["runner_id"] == "runner-2"
    assert db.committed is True


def test_complete_runner_task_prefers_context_job_id_for_discovery_execution(monkeypatch) -> None:
    task = SimpleNamespace(
        id="task-scan-3",
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_execution",
        scope_id="execution-1",
        status=TaskExecutionStatus.RUNNING,
        progress=50,
        message=None,
        result_json={"context": {"job_id": "job-real", "runner_asset_id": "asset-runner-3", "parent_task_id": "parent-task"}},
    )
    runner = SimpleNamespace(
        id="runner-3",
        asset_id="asset-runner-3",
        status="busy",
        install_status="installed",
        last_seen_at=None,
        last_error=None,
    )
    db = _FakeDB()

    monkeypatch.setattr(runner_service, "get_task_run", lambda db, task_id: task if task_id == "task-scan-3" else None)
    observed: dict[str, object] = {}
    monkeypatch.setattr(
        runner_service,
        "update_discovery_execution_from_task",
        lambda db, **kwargs: observed.update({"execution_status": kwargs.get("status")}) or None,
    )
    monkeypatch.setattr(
        runner_service,
        "aggregate_campus_discovery_job",
        lambda db, job_id: observed.update({"job_id": job_id}) or {"host_count": 1, "port_scan_stats": {"open_port_count": 0}, "discovery_source_stats": {}},
    )
    monkeypatch.setattr(
        runner_service,
        "update_task_run",
        lambda db, task, **kwargs: setattr(task, "status", kwargs.get("status")) or task,
    )
    monkeypatch.setattr(runner_service, "create_task_event", lambda *args, **kwargs: None)

    runner_service.complete_runner_task(
        db,
        runner,
        "task-scan-3",
        RunnerTaskCompleteRequest(
            status="success",
            execution={"scan_result": {"hosts": [{"ip": "10.10.0.5"}]}},
            message="runner scan ok",
        ),
    )

    assert observed["job_id"] == "job-real"


def test_complete_runner_task_baseline_queues_followup_for_discovery_job(monkeypatch) -> None:
    task = SimpleNamespace(
        id="task-scan-4",
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_job",
        scope_id="job-4",
        status=TaskExecutionStatus.RUNNING,
        progress=35,
        message=None,
        result_json={"context": {"job_id": "job-4", "runner_asset_id": "asset-runner-4", "scan_phase": "baseline"}},
    )
    runner = SimpleNamespace(
        id="runner-4",
        asset_id="asset-runner-4",
        status="busy",
        install_status="installed",
        last_seen_at=None,
        last_error=None,
    )
    db = _FakeDB()
    observed: dict[str, object] = {}

    monkeypatch.setattr(runner_service, "get_task_run", lambda db, task_id: task if task_id == "task-scan-4" else None)

    def _apply_runner(job_id, scan_result, *, finalize=True, enqueue_risk_verification=True):  # type: ignore[no-untyped-def]
        observed["job_id"] = job_id
        observed["finalize"] = finalize
        observed["enqueue_risk_verification"] = enqueue_risk_verification
        return {"host_count": 3, "excluded_local_ip_count": 1}

    monkeypatch.setattr(discovery_tasks, "apply_runner_discovery_scan_result", _apply_runner)
    monkeypatch.setattr(runner_service, "_queue_runner_asset_scan_followup_task", lambda db, task, context: "task-followup-4")
    monkeypatch.setattr(
        runner_service,
        "update_task_run",
        lambda db, task, **kwargs: setattr(task, "status", kwargs.get("status")) or setattr(task, "result_json", kwargs.get("result_json")) or task,
    )
    monkeypatch.setattr(runner_service, "create_task_event", lambda *args, **kwargs: None)

    result = runner_service.complete_runner_task(
        db,
        runner,
        "task-scan-4",
        RunnerTaskCompleteRequest(
            status="success",
            execution={"scan_result": {"hosts": [{"ip": "10.10.0.10"}]}, "scan_phase": "baseline"},
            message="runner baseline ok",
        ),
    )

    assert observed == {
        "job_id": "job-4",
        "finalize": False,
        "enqueue_risk_verification": False,
    }
    assert task.status == TaskExecutionStatus.SUCCESS
    assert result["scan_summary"]["host_count"] == 3
    assert result["scan_summary"]["followup_task_id"] == "task-followup-4"
    assert result["followup_task_id"] == "task-followup-4"
    assert result["scan_phase"] == "baseline"


def test_complete_runner_task_baseline_updates_execution_and_partial_aggregate(monkeypatch) -> None:
    task = SimpleNamespace(
        id="task-scan-5",
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_execution",
        scope_id="execution-5",
        status=TaskExecutionStatus.RUNNING,
        progress=35,
        message=None,
        result_json={
            "context": {
                "job_id": "job-5",
                "runner_asset_id": "asset-runner-5",
                "parent_task_id": "parent-task-5",
                "scan_phase": "baseline",
            }
        },
    )
    runner = SimpleNamespace(
        id="runner-5",
        asset_id="asset-runner-5",
        status="busy",
        install_status="installed",
        last_seen_at=None,
        last_error=None,
    )
    db = _FakeDB()
    observed: dict[str, object] = {}

    monkeypatch.setattr(runner_service, "get_task_run", lambda db, task_id: task if task_id == "task-scan-5" else None)
    monkeypatch.setattr(
        runner_service,
        "update_discovery_execution_from_task",
        lambda db, **kwargs: observed.update({"execution_status": kwargs.get("status"), "execution_summary": kwargs.get("summary_json")}) or None,
    )
    monkeypatch.setattr(
        runner_service,
        "aggregate_campus_discovery_job",
        lambda db, **kwargs: observed.update({"aggregate_kwargs": kwargs}) or {"host_count": 2},
    )
    monkeypatch.setattr(runner_service, "_queue_runner_asset_scan_followup_task", lambda db, task, context: "task-followup-5")
    monkeypatch.setattr(
        runner_service,
        "update_task_run",
        lambda db, task, **kwargs: setattr(task, "status", kwargs.get("status")) or setattr(task, "result_json", kwargs.get("result_json")) or task,
    )
    monkeypatch.setattr(runner_service, "create_task_event", lambda *args, **kwargs: None)

    result = runner_service.complete_runner_task(
        db,
        runner,
        "task-scan-5",
        RunnerTaskCompleteRequest(
            status="success",
            execution={"scan_result": {"hosts": [{"ip": "10.10.0.11"}]}, "scan_phase": "baseline"},
            message="runner baseline ok",
        ),
    )

    assert observed["execution_status"] == "running"
    assert observed["execution_summary"]["last_completed_phase"] == "baseline"
    assert observed["aggregate_kwargs"] == {
        "job_id": "job-5",
        "result_key": "baseline_scan_result",
        "allow_partial": True,
        "finalize": False,
    }
    assert result["followup_task_id"] == "task-followup-5"
