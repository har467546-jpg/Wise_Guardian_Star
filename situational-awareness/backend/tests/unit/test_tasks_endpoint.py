from collections.abc import Generator
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.api.deps import get_current_user, get_db_session
from app.db.models.enums import TaskExecutionStatus, TaskType, UserRole
from app.db.models.task_event import TaskEvent
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
    monkeypatch.setattr("app.api.v1.endpoints.tasks.reconcile_stale_active_tasks", lambda _db: 0)
    app.dependency_overrides[get_db_session] = _get_test_db
    app.dependency_overrides[get_current_user] = _override_user
    return TestClient(app)


def test_task_list_returns_timing_summary(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.RUNNING,
        scope_type="discovery_job",
        scope_id="job-1",
        progress=60,
        message="开放端口探测完成",
        retry_count=0,
        result_json={"job_id": "job-1"},
        error_json={},
        created_at=datetime(2026, 3, 14, 10, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 14, 10, 0, 5, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 10, 0, 40, tzinfo=timezone.utc),
    )
    event = TaskEvent(
        id="event-1",
        task_run_id=task.id,
        event_type="stage",
        level="info",
        stage_code="probe_open_services",
        stage_name="开放端口探测",
        message="开放端口探测完成",
        progress=60,
        payload_json={"job_id": "job-1"},
        created_at=datetime(2026, 3, 14, 10, 0, 30, tzinfo=timezone.utc),
    )
    event.task_run = task

    monkeypatch.setattr(tasks_endpoint, "list_task_runs", lambda *args, **kwargs: ([task], 1))
    monkeypatch.setattr(tasks_endpoint, "list_task_events_for_runs", lambda *args, **kwargs: {task.id: [event]})

    response = client.get("/api/v1/tasks")

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["total"] == 1
    assert payload["items"][0]["timing"]["has_event_logs"] is True
    assert payload["items"][0]["timing"]["current_stage_code"] == "probe_open_services"
    assert payload["items"][0]["timing"]["current_stage_name"] == "开放端口探测"


def test_task_detail_returns_stage_timings(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-detail-1",
        task_type=TaskType.RISK_VERIFY,
        status=TaskExecutionStatus.SUCCESS,
        scope_type="asset",
        scope_id="asset-1",
        progress=100,
        message="风险验证任务完成",
        retry_count=0,
        result_json={"asset_id": "asset-1"},
        error_json={},
        created_at=datetime(2026, 3, 14, 11, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 14, 11, 0, 2, tzinfo=timezone.utc),
        finished_at=datetime(2026, 3, 14, 11, 0, 15, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 11, 0, 15, tzinfo=timezone.utc),
    )
    events = [
        TaskEvent(
            id="event-ctx",
            task_run_id=task.id,
            event_type="stage",
            level="info",
            stage_code="load_context",
            stage_name="载入上下文",
            message="已载入资产与规则上下文",
            progress=10,
            payload_json={},
            created_at=datetime(2026, 3, 14, 11, 0, 4, tzinfo=timezone.utc),
        ),
        TaskEvent(
            id="event-persist",
            task_run_id=task.id,
            event_type="stage",
            level="info",
            stage_code="persist_result",
            stage_name="结果落盘",
            message="风险结果写入完成",
            progress=90,
            payload_json={},
            created_at=datetime(2026, 3, 14, 11, 0, 10, tzinfo=timezone.utc),
        ),
    ]
    for event in events:
        event.task_run = task

    monkeypatch.setattr(tasks_endpoint, "get_task_run", lambda *args, **kwargs: task)
    monkeypatch.setattr(tasks_endpoint, "list_task_events_for_runs", lambda *args, **kwargs: {task.id: events})

    response = client.get(f"/api/v1/tasks/{task.id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["event_count"] == 2
    assert len(payload["stage_timings"]) == 2
    assert payload["stage_timings"][0]["stage_code"] == "load_context"
    assert payload["timing"]["run_duration_ms"] == 13000


def test_global_task_events_endpoint_returns_event_rows(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-log-1",
        task_type=TaskType.INFO_COLLECT,
        status=TaskExecutionStatus.RETRY,
        scope_type="asset",
        scope_id="asset-9",
        progress=60,
        message="等待重试",
        retry_count=1,
        result_json={},
        error_json={"error": "timeout"},
        created_at=datetime(2026, 3, 14, 12, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 12, 0, 30, tzinfo=timezone.utc),
    )
    event = TaskEvent(
        id="event-retry-1",
        task_run_id=task.id,
        event_type="retry",
        level="warning",
        stage_code="ssh_collect",
        stage_name="SSH 采集",
        message="执行超时，等待重试",
        progress=60,
        payload_json={"error": "timeout"},
        created_at=datetime(2026, 3, 14, 12, 0, 20, tzinfo=timezone.utc),
    )
    event.task_run = task

    monkeypatch.setattr(tasks_endpoint, "list_task_events", lambda *args, **kwargs: ([event], 1))

    response = client.get("/api/v1/tasks/events", params={"level": "warning", "task_type": "info_collect"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["meta"]["total"] == 1
    assert payload["items"][0]["task_type"] == "info_collect"
    assert payload["items"][0]["status"] == "retry"
    assert payload["items"][0]["stage_name"] == "SSH 采集"


def test_cancel_task_endpoint_revokes_and_marks_task_canceled(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-cancel-1",
        task_type=TaskType.INFO_COLLECT,
        status=TaskExecutionStatus.RUNNING,
        scope_type="asset",
        scope_id="asset-1",
        celery_task_id="celery-task-1",
        progress=55,
        message="SSH 采集中",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=datetime(2026, 3, 14, 13, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 14, 13, 0, 3, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 13, 0, 10, tzinfo=timezone.utc),
    )
    revoke_calls: list[dict[str, object]] = []

    monkeypatch.setattr(tasks_endpoint, "get_task_run", lambda *args, **kwargs: task)
    monkeypatch.setattr(
        tasks_endpoint.celery_app.control,
        "revoke",
        lambda task_id, terminate, signal: revoke_calls.append(
            {"task_id": task_id, "terminate": terminate, "signal": signal}
        ),
    )

    def _cancel_task_run(_db, row, **kwargs):
        row.status = TaskExecutionStatus.CANCELED
        row.message = kwargs["message"]
        return row

    monkeypatch.setattr(tasks_endpoint, "cancel_task_run", _cancel_task_run)

    response = client.post(f"/api/v1/tasks/{task.id}/cancel")

    assert response.status_code == 200
    assert response.json() == {"task_id": task.id, "status": "canceled"}
    assert revoke_calls == [{"task_id": "celery-task-1", "terminate": True, "signal": "SIGTERM"}]


def test_cancel_task_endpoint_rejects_terminal_task(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-terminal-1",
        task_type=TaskType.RISK_VERIFY,
        status=TaskExecutionStatus.SUCCESS,
        scope_type="asset",
        scope_id="asset-1",
        progress=100,
        message="风险验证任务完成",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=datetime(2026, 3, 14, 13, 30, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 14, 13, 30, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 3, 14, 13, 30, 8, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 13, 30, 8, tzinfo=timezone.utc),
    )

    monkeypatch.setattr(tasks_endpoint, "get_task_run", lambda *args, **kwargs: task)

    response = client.post(f"/api/v1/tasks/{task.id}/cancel")

    assert response.status_code == 409
    assert response.json()["detail"] == "任务当前状态不支持中断"


def test_clear_tasks_endpoint_cancels_active_tasks_before_delete(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_endpoint

    db = _DummyDB()
    client = _build_client(monkeypatch, db)
    task = TaskRun(
        id="task-running-1",
        task_type=TaskType.ASSET_SCAN,
        status=TaskExecutionStatus.RUNNING,
        scope_type="discovery_job",
        scope_id="job-1",
        celery_task_id="celery-running-1",
        progress=60,
        message="开放端口探测中",
        retry_count=0,
        result_json={},
        error_json={},
        created_at=datetime(2026, 3, 14, 14, 0, tzinfo=timezone.utc),
        started_at=datetime(2026, 3, 14, 14, 0, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 14, 14, 0, 20, tzinfo=timezone.utc),
    )
    revoke_calls: list[dict[str, object]] = []
    canceled_calls: list[dict[str, object]] = []
    deleted_ids: list[str] = []

    monkeypatch.setattr(tasks_endpoint, "find_task_runs_for_clear", lambda *args, **kwargs: [task])
    monkeypatch.setattr(
        tasks_endpoint.celery_app.control,
        "revoke",
        lambda task_id, terminate, signal: revoke_calls.append(
            {"task_id": task_id, "terminate": terminate, "signal": signal}
        ),
    )

    def _cancel_task_run(_db, row, **kwargs):
        canceled_calls.append({"task_id": row.id, "message": kwargs["message"]})
        row.status = TaskExecutionStatus.CANCELED
        return row

    monkeypatch.setattr(tasks_endpoint, "cancel_task_run", _cancel_task_run)
    monkeypatch.setattr(
        tasks_endpoint,
        "delete_task_runs_by_ids",
        lambda _db, task_ids: deleted_ids.extend(task_ids) or len(task_ids),
    )

    response = client.delete("/api/v1/tasks", params={"include_active": "true", "status": "running"})

    assert response.status_code == 200
    assert response.json() == {"deleted": 1}
    assert revoke_calls == [{"task_id": "celery-running-1", "terminate": True, "signal": "SIGTERM"}]
    assert canceled_calls == [{"task_id": "task-running-1", "message": "任务已中断并清理"}]
    assert deleted_ids == ["task-running-1"]
