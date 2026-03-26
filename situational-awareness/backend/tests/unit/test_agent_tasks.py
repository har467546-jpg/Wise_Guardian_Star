from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import ProgrammingError

from app.db.models.enums import TaskExecutionStatus
from app.tasks import agent_tasks


class _FakeDB:
    def __init__(self, session, task_run=None):
        self._session = session
        self._task_run = task_run
        self.committed = False
        self.added: list[object] = []

    def get(self, model, value):
        if value == getattr(self._session, "id", None):
            return self._session
        if value == getattr(self._task_run, "id", None):
            return self._task_run
        return None

    def add(self, obj) -> None:
        self.added.append(obj)

    def commit(self) -> None:
        self.committed = True


def _make_task_run(*, result_json: dict | None = None, status: TaskExecutionStatus = TaskExecutionStatus.PENDING):
    return SimpleNamespace(
        id="task-orchestrate-1",
        status=status,
        progress=0,
        message="haor 编排任务已入队",
        result_json=deepcopy(result_json) if isinstance(result_json, dict) else {},
        error_json={},
    )


class _SessionLocalContext:
    def __init__(self, db):
        self._db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self._db

    def __exit__(self, exc_type, exc, tb):
        return False


@contextmanager
def _tracked_task_context(*_args, **_kwargs):
    yield SimpleNamespace(id="task-orchestrate-1")


def test_run_agent_auto_followup_task_appends_completion_message(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", current_goal_id="goal-1", messages=[])
    db = _FakeDB(session)
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "扫描任务完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        captured["db"] = db_obj
        captured["session_id"] = session_id
        captured["content"] = content
        captured["payload_json"] = payload_json
        captured["message_type"] = message_type

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-child-1",
        {"action_type": "create_discovery_job", "params": {"cidr": "192.168.10.0/24"}},
    )

    assert result == "task-child-1"
    assert db.committed is True
    assert captured["db"] is db
    assert captured["session_id"] == "session-1"
    assert captured["message_type"] == "task_update"
    assert "192.168.10.0/24 的扫描任务已完成" in str(captured["content"])
    payload_json = captured["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["auto_followup"] is True
    assert payload_json["task_id"] == "task-child-1"
    assert payload_json["resume_hint"]["kind"] == "post_scan_analysis"
    assert payload_json["resume_hint"]["goal_id"] == "goal-1"
    assert payload_json["resume_hint"]["preferred_read_tools"][0]["tool_name"] == "list_assets"


def test_run_agent_auto_followup_task_skips_duplicate_followup_messages(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(
        id="session-1",
        messages=[
            SimpleNamespace(
                payload_json={
                    "task_id": "task-child-1",
                    "terminal_status": "success",
                    "auto_followup": True,
                    "action": {"action_type": "create_discovery_job"},
                }
            )
        ],
    )
    db = _FakeDB(session)

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "扫描任务完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not append duplicate follow-up")),
    )

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-child-1",
        {"action_type": "create_discovery_job", "params": {"cidr": "192.168.10.0/24"}},
    )

    assert result == "task-child-1"
    assert db.committed is False


def test_run_agent_auto_followup_task_formats_remediation_completion(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", messages=[])
    db = _FakeDB(session)
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": "success",
            "message": "Runner 已完成整机修复",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        captured["db"] = db_obj
        captured["session_id"] = session_id
        captured["content"] = content
        captured["payload_json"] = payload_json
        captured["message_type"] = message_type

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)

    result = agent_tasks.run_agent_auto_followup_task.run(
        "session-1",
        "task-remediation-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-9", "submit_if_ready": True},
            "payload": {"session_id": "session-9"},
        },
    )

    assert result == "task-remediation-1"
    assert db.committed is True
    assert captured["message_type"] == "task_update"
    assert "资产 asset-9 的自动修复任务已完成" in str(captured["content"])
    assert "修复会话 session-9" in str(captured["content"])
    payload_json = captured["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["resume_hint"]["kind"] == "post_remediation_review"
    preferred_read_tools = payload_json["resume_hint"]["preferred_read_tools"]
    assert any(item["tool_name"] == "get_remediation_session" for item in preferred_read_tools)


def test_run_agent_orchestrate_task_preserves_plan_during_progress_updates(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    initial_result_json = {
        "context": {"session_id": "session-1", "platform_url": "http://localhost:3000"},
        "plan": {
            "proposed_write_actions": [
                {
                    "action_type": "create_or_resume_remediation_session",
                    "title": "自动修复资产",
                    "params": {"asset_id": "asset-1", "submit_if_ready": True},
                }
            ]
        },
        "execution": {"approved_by": "user-1", "results": []},
    }
    task_run = _make_task_run(result_json=initial_result_json)
    session = SimpleNamespace(
        id="session-1",
        user_id="user-1",
        status="running",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        last_task_id=None,
    )
    db = _FakeDB(session, task_run=task_run)
    progress_payloads: list[dict] = []
    appended_messages: list[dict[str, object]] = []

    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)

    def _update_task_run(_db, current_task_run, **kwargs):  # type: ignore[no-untyped-def]
        for key, value in kwargs.items():
            setattr(current_task_run, key, value)
        return current_task_run

    monkeypatch.setattr(agent_tasks, "update_task_run", _update_task_run)

    def _set_task_progress(_task_run_id, _progress, _message, result_json=None, **_kwargs):  # type: ignore[no-untyped-def]
        if isinstance(result_json, dict):
            progress_payloads.append(deepcopy(result_json))
            task_run.result_json = deepcopy(result_json)

    monkeypatch.setattr(agent_tasks, "set_task_progress", _set_task_progress)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_success", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="queued",
            summary="已提交自动修复任务 remediation-task-1",
            payload={"session_id": "remediation-session-1"},
            child_task_id=None,
        ),
    )

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        appended_messages.append(
            {
                "db": db_obj,
                "session_id": session_id,
                "content": content,
                "payload_json": payload_json,
                "message_type": message_type,
            }
        )

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)
    orchestrate_fn = agent_tasks.run_agent_orchestrate_task.__wrapped__.__func__
    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-1", retries=0),
        max_retries=1,
        retry=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not retry success path")),
    )

    result = orchestrate_fn(fake_task, "task-orchestrate-1", "session-1")

    assert result == "task-orchestrate-1"
    assert progress_payloads
    assert progress_payloads[0]["plan"]["proposed_write_actions"][0]["action_type"] == "create_or_resume_remediation_session"
    assert task_run.result_json["plan"]["proposed_write_actions"][0]["params"]["asset_id"] == "asset-1"
    assert task_run.result_json["execution"]["results"][0]["status"] == "queued"
    assert appended_messages[0]["message_type"] == "task_update"


def test_run_agent_orchestrate_task_does_not_retry_deterministic_remediation_failure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    initial_result_json = {
        "context": {"session_id": "session-1", "platform_url": "http://localhost:3000"},
        "plan": {
            "proposed_write_actions": [
                {
                    "action_type": "create_or_resume_remediation_session",
                    "title": "自动修复资产",
                    "params": {"asset_id": "asset-1", "submit_if_ready": True},
                }
            ]
        },
        "execution": {"approved_by": "user-1", "results": []},
    }
    task_run = _make_task_run(result_json=initial_result_json)
    session = SimpleNamespace(
        id="session-1",
        user_id="user-1",
        status="running",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        last_task_id=None,
    )
    db = _FakeDB(session, task_run=task_run)
    appended_messages: list[dict[str, object]] = []
    failure_messages: list[str] = []
    retry_calls: list[dict[str, object]] = []

    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)
    monkeypatch.setattr(agent_tasks, "set_task_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "mark_agent_session_interrupted", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_success", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: retry_calls.append({"args": args, "kwargs": kwargs}))
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda _task_run_id, _retries, message: failure_messages.append(message))

    def _fake_append(db_obj, *, session_id, content, payload_json=None, message_type="task_update"):  # type: ignore[no-untyped-def]
        appended_messages.append(
            {
                "db": db_obj,
                "session_id": session_id,
                "content": content,
                "payload_json": payload_json,
                "message_type": message_type,
            }
        )

    monkeypatch.setattr(agent_tasks, "append_agent_task_message", _fake_append)

    sql_error = ProgrammingError(
        "UPDATE remediation_sessions SET approved_by=%s",
        {"approved_by": "haor"},
        Exception('violates foreign key constraint "remediation_sessions_approved_by_fkey" on approved_by'),
    )
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: (_ for _ in ()).throw(sql_error),
    )

    def _retry(*args, **kwargs):  # type: ignore[no-untyped-def]
        retry_calls.append({"args": args, "kwargs": kwargs})
        raise AssertionError("should not retry deterministic remediation approval failures")

    orchestrate_fn = agent_tasks.run_agent_orchestrate_task.__wrapped__.__func__
    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-1", retries=0),
        max_retries=1,
        retry=_retry,
    )

    with pytest.raises(ProgrammingError):
        orchestrate_fn(fake_task, "task-orchestrate-1", "session-1")

    assert not retry_calls
    assert failure_messages == ["审批人信息无效，请刷新页面后重试"]
    assert appended_messages
    assert appended_messages[0]["message_type"] == "error"
    assert "审批人信息无效，请刷新页面后重试" in str(appended_messages[0]["content"])
    assert "UPDATE remediation_sessions" not in str(appended_messages[0]["content"])
    payload_json = appended_messages[0]["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["error"] == "审批人信息无效，请刷新页面后重试"
