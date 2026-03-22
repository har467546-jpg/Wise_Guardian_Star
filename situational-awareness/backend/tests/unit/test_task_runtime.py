from datetime import datetime, timezone

import pytest

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_run import TaskRun
from app.tasks import task_runtime


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def _build_task(status: TaskExecutionStatus) -> TaskRun:
    now = datetime(2026, 3, 14, 12, 30, tzinfo=timezone.utc)
    return TaskRun(
        id="task-1",
        task_type=TaskType.ASSET_SCAN,
        status=status,
        progress=40,
        message="测试任务",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=now,
        started_at=now,
        finished_at=now if status == TaskExecutionStatus.CANCELED else None,
        updated_at=now,
    )


def test_tracked_task_raises_for_canceled_task(monkeypatch) -> None:
    task = _build_task(TaskExecutionStatus.CANCELED)
    monkeypatch.setattr(task_runtime, "SessionLocal", _FakeSessionLocal(object()))
    monkeypatch.setattr(task_runtime, "get_task_run", lambda db, task_run_id: task)

    with pytest.raises(task_runtime.TaskCanceledError):
        with task_runtime.tracked_task("task-1"):
            pass


def test_set_task_progress_skips_canceled_task(monkeypatch) -> None:
    task = _build_task(TaskExecutionStatus.CANCELED)
    calls: list[str] = []

    monkeypatch.setattr(task_runtime, "SessionLocal", _FakeSessionLocal(object()))
    monkeypatch.setattr(task_runtime, "get_task_run", lambda db, task_run_id: task)
    monkeypatch.setattr(task_runtime, "update_task_run", lambda *args, **kwargs: calls.append("update"))
    monkeypatch.setattr(task_runtime, "create_task_event", lambda *args, **kwargs: calls.append("event"))

    with pytest.raises(task_runtime.TaskCanceledError):
        task_runtime.set_task_progress("task-1", 50, "继续执行", {"job_id": "job-1"})

    assert calls == []


def test_set_task_success_raises_for_canceled_task(monkeypatch) -> None:
    task = _build_task(TaskExecutionStatus.CANCELED)
    calls: list[str] = []

    monkeypatch.setattr(task_runtime, "SessionLocal", _FakeSessionLocal(object()))
    monkeypatch.setattr(task_runtime, "get_task_run", lambda db, task_run_id: task)
    monkeypatch.setattr(task_runtime, "update_task_run", lambda *args, **kwargs: calls.append("update"))
    monkeypatch.setattr(task_runtime, "create_task_event", lambda *args, **kwargs: calls.append("event"))

    with pytest.raises(task_runtime.TaskCanceledError):
        task_runtime.set_task_success("task-1", "任务完成", {"job_id": "job-1"})

    assert calls == []
