from types import SimpleNamespace

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_event import TaskEvent
from app.db.models.task_run import TaskRun
from app.repositories.task_repo import cancel_task_run, create_task_run, update_task_run


class _FakeDB:
    def __init__(self) -> None:
        self.items: list[object] = []
        self.commit_count = 0
        self.bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
        self.rollback_count = 0

    def add(self, item: object) -> None:
        if isinstance(item, TaskRun) and not item.id:
            item.id = "task-queued-1"
        if isinstance(item, TaskEvent) and not item.id:
            item.id = f"event-{len([row for row in self.items if isinstance(row, TaskEvent)]) + 1}"
        self.items.append(item)

    def flush(self) -> None:
        for item in self.items:
            if isinstance(item, TaskRun) and not item.id:
                item.id = "task-queued-1"

    def commit(self) -> None:
        self.commit_count += 1

    def rollback(self) -> None:
        self.rollback_count += 1

    def refresh(self, item: object) -> None:
        return None


class _FakePgConnection:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def execution_options(self, **kwargs):
        self.calls.append(f"execution_options:{kwargs.get('isolation_level')}")
        return self

    def execute(self, _stmt) -> None:
        self.calls.append("execute")

    def __enter__(self):
        self.calls.append("__enter__")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.calls.append("__exit__")
        return False


class _FakePgBind:
    def __init__(self, calls: list[str]) -> None:
        self.dialect = SimpleNamespace(name="postgresql")
        self.calls = calls

    def connect(self):
        self.calls.append("connect")
        return _FakePgConnection(self.calls)


def test_create_task_run_records_queued_event() -> None:
    db = _FakeDB()

    task = create_task_run(
        db,
        task_type=TaskType.INFO_COLLECT,
        scope_type="asset",
        scope_id="asset-1",
        message="资产采集任务已入队",
    )

    events = [item for item in db.items if isinstance(item, TaskEvent)]

    assert task.id == "task-queued-1"
    assert len(events) == 1
    assert events[0].task_run_id == "task-queued-1"
    assert events[0].event_type == "queued"
    assert events[0].message == "资产采集任务已入队"
    assert db.commit_count == 1


def test_cancel_task_run_marks_task_canceled_and_records_event() -> None:
    db = _FakeDB()
    task = create_task_run(
        db,
        task_type=TaskType.RISK_VERIFY,
        scope_type="asset",
        scope_id="asset-1",
        message="风险验证任务已入队",
    )

    canceled = cancel_task_run(db, task, payload_json={"source": "api"})
    events = [item for item in db.items if isinstance(item, TaskEvent)]

    assert canceled.status == TaskExecutionStatus.CANCELED
    assert canceled.finished_at is not None
    assert events[-1].event_type == "canceled"
    assert events[-1].level == "warning"
    assert events[-1].payload_json == {"source": "api"}
    assert db.commit_count == 2


def test_update_task_run_truncates_message_and_sanitizes_json() -> None:
    db = _FakeDB()
    task = TaskRun(id="task-1", task_type=TaskType.ASSET_SCAN, status=TaskExecutionStatus.RUNNING)

    update_task_run(
        db,
        task,
        status=TaskExecutionStatus.RETRY,
        message=("错误" * 200) + "\x00尾巴",
        error_json={"error": "mysql\x00banner"},
    )

    assert len(task.message or "") == 255
    assert task.message and task.message.endswith("...")
    assert task.error_json == {"error": "mysqlbanner"}


def test_update_task_run_ensures_postgres_enum_before_cancel(monkeypatch) -> None:
    db = _FakeDB()
    pg_calls: list[str] = []
    db.bind = _FakePgBind(pg_calls)
    task = TaskRun(id="task-1", task_type=TaskType.ASSET_SCAN, status=TaskExecutionStatus.RUNNING)

    monkeypatch.setattr("app.repositories.task_repo.get_task_run", lambda _db, task_id: task)

    canceled = update_task_run(
        db,
        task,
        status=TaskExecutionStatus.CANCELED,
        message="任务已中断",
    )

    assert canceled.status == TaskExecutionStatus.CANCELED
    assert db.rollback_count == 1
    assert pg_calls == ["connect", "__enter__", "execution_options:AUTOCOMMIT", "execute", "__exit__"]
