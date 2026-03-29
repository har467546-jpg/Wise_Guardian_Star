from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm.exc import DetachedInstanceError

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

    def flush(self) -> None:
        return None

    def refresh(self, _obj) -> None:
        return None

    def commit(self) -> None:
        self.committed = True


class _DetachingAgentSession(SimpleNamespace):
    def __init__(self, *, current_goal_id=None, **kwargs):
        super().__init__(**kwargs)
        self._current_goal_id = current_goal_id
        self._detached = False

    @property
    def current_goal_id(self):
        if self._detached:
            raise DetachedInstanceError(
                "Instance <AgentSession> is not bound to a Session; attribute refresh operation cannot proceed"
            )
        return self._current_goal_id

    @current_goal_id.setter
    def current_goal_id(self, value):
        self._current_goal_id = value

    def detach(self) -> None:
        self._detached = True


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


class _SessionLocalFactory:
    def __init__(self, *, task_run, session_builder):
        self._task_run = task_run
        self._session_builder = session_builder

    def __call__(self):
        db = _FakeDB(self._session_builder(), task_run=self._task_run)

        class _Context:
            def __enter__(self_inner):
                return db

            def __exit__(self_inner, exc_type, exc, tb):
                detach = getattr(db._session, "detach", None)
                if callable(detach):
                    detach()
                return False

        return _Context()


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


def test_run_agent_secure_post_verify_resume_task_reports_collection_refresh_failure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", user_id="user-1", messages=[])
    db = _FakeDB(session)
    blocked_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": TaskExecutionStatus.FAILURE.value,
            "message": "SSH 深度检查失败",
            "result_json": {},
            "error_json": {"error": "timeout"},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(
        agent_tasks,
        "append_blocked_action_result_message",
        lambda *args, **kwargs: blocked_calls.append(kwargs),
    )

    result = agent_tasks.run_agent_secure_post_verify_resume_task.run(
        "session-1",
        "task-collect-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
        "asset-1",
    )

    assert result == "task-collect-1"
    assert db.committed is True
    assert blocked_calls
    assert blocked_calls[0]["task_id"] == "task-collect-1"
    assert "主机事实刷新失败" in str(blocked_calls[0]["content"])
    assert blocked_calls[0]["message_payload_patch"]["post_verify_action"] == "refresh_failed"


def test_run_agent_secure_post_verify_resume_task_continues_remediation_after_refresh(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", user_id="user-1", messages=[])
    db = _FakeDB(session)
    appended_messages: list[dict[str, object]] = []
    followup_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": TaskExecutionStatus.SUCCESS.value,
            "message": "SSH 深度检查完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="queued",
            summary="已提交自动修复任务 remediation-task-1",
            payload={"asset_id": "asset-1", "session_id": "remediation-session-1"},
            child_task_id="remediation-task-1",
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: appended_messages.append(kwargs),
    )
    monkeypatch.setattr(
        agent_tasks,
        "enqueue_auto_action_followup_task",
        lambda **kwargs: followup_calls.append(kwargs),
    )

    result = agent_tasks.run_agent_secure_post_verify_resume_task.run(
        "session-1",
        "task-collect-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
        "asset-1",
    )

    assert result == "remediation-task-1"
    assert db.committed is True
    assert len(appended_messages) == 2
    assert appended_messages[0]["watching"] is False
    assert appended_messages[0]["message_type"] == "action_update"
    assert "主机信息已刷新，正在重新评估修复条件" in str(appended_messages[0]["content"])
    assert "这一步可能比采集更久" in str(appended_messages[0]["content"])
    first_payload_json = appended_messages[0]["payload_json"]
    assert first_payload_json["task_id"] == "task-collect-1"
    assert first_payload_json["post_verify_action"] == "refresh_reassessing"
    assert appended_messages[1]["watching"] is True
    assert appended_messages[1]["message_type"] == "action_update"
    assert "我已重新评估修复条件，并继续自动修复" in str(appended_messages[1]["content"])
    payload_json = appended_messages[1]["payload_json"]
    assert payload_json["task_id"] == "remediation-task-1"
    assert payload_json["post_verify_action"] == "refresh_and_resume"
    assert followup_calls == [
        {
            "session_id": "session-1",
            "child_task_id": "remediation-task-1",
            "action": {
                "action_type": "create_or_resume_remediation_session",
                "params": {"asset_id": "asset-1", "submit_if_ready": True},
                "payload": {"asset_id": "asset-1", "session_id": "remediation-session-1"},
            },
        }
    ]
    assert session.status == "running"
    assert session.agent_state_json["execution"]["step_label"] == "主机事实已刷新，正在重新评估修复条件"
    assert session.agent_state_json["execution"]["waiting_for"] == "等待重新评估自动修复条件"


def test_run_agent_secure_post_verify_resume_task_humanizes_upstream_reassessment_failure(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", user_id="user-1", messages=[])
    db = _FakeDB(session)
    appended_messages: list[dict[str, object]] = []

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": TaskExecutionStatus.SUCCESS.value,
            "message": "SSH 深度检查完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))

    def _raise_upstream_failure(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("AI 模型服务异常：502 Bad Gateway")

    monkeypatch.setattr(agent_tasks, "execute_approved_action", _raise_upstream_failure)
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: appended_messages.append(kwargs),
    )

    result = agent_tasks.run_agent_secure_post_verify_resume_task.run(
        "session-1",
        "task-collect-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
        "asset-1",
    )

    assert result == "task-collect-1"
    assert db.committed is True
    assert len(appended_messages) == 2
    assert appended_messages[0]["payload_json"]["post_verify_action"] == "refresh_reassessing"
    assert appended_messages[1]["message_type"] == "error"
    assert "上游模型暂时不可用" in str(appended_messages[1]["content"])
    assert appended_messages[1]["payload_json"]["post_verify_action"] == "refresh_resume_failed"


def test_run_agent_secure_post_verify_resume_task_recommends_runner_or_interactive_fallback(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    session = SimpleNamespace(id="session-1", user_id="user-1", messages=[])
    db = _FakeDB(session)
    blocked_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": TaskExecutionStatus.SUCCESS.value,
            "message": "SSH 深度检查完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="success",
            summary="当前主机尚未安装 Host Runner",
            payload={
                "asset_id": "asset-1",
                "execution_ready": False,
                "blocked_reasons": [
                    "当前主机尚未安装 Host Runner",
                    "未识别到稳定的软件包管理器或包名",
                ],
                "blocker_categories": ["runner", "render"],
                "blockers": [
                    {
                        "code": "runner_not_installed",
                        "message": "当前主机尚未安装 Host Runner",
                        "blocker_category": "runner",
                    },
                    {
                        "code": "unstable_render",
                        "message": "未识别到稳定的软件包管理器或包名",
                        "blocker_category": "render",
                    },
                ],
            },
            child_task_id=None,
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "append_blocked_action_result_message",
        lambda *args, **kwargs: blocked_calls.append(kwargs),
    )

    result = agent_tasks.run_agent_secure_post_verify_resume_task.run(
        "session-1",
        "task-collect-1",
        {
            "action_type": "create_or_resume_remediation_session",
            "params": {"asset_id": "asset-1", "submit_if_ready": True},
        },
        "asset-1",
    )

    assert result == "task-collect-1"
    assert db.committed is True
    assert blocked_calls
    assert "即使先安装 Runner，也不保证能立即自动修成功" in str(blocked_calls[0]["content"])
    assert blocked_calls[0]["message_payload_patch"]["post_verify_action"] == "interactive_remediation_recommended"


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


def test_run_agent_orchestrate_task_captures_goal_id_before_session_detaches(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    initial_result_json = {
        "context": {"session_id": "session-1", "platform_url": "http://localhost:3000"},
        "plan": {
            "proposed_write_actions": [
                {
                    "action_type": "verify_asset_risks",
                    "title": "验证资产风险",
                    "params": {"finding_id": "finding-1", "asset_id": "asset-1"},
                }
            ]
        },
        "execution": {"approved_by": "user-1", "results": []},
    }
    task_run = _make_task_run(result_json=initial_result_json)
    appended_messages: list[dict[str, object]] = []

    def _build_session():
        return _DetachingAgentSession(
            id="session-1",
            user_id="user-1",
            current_goal_id="goal-1",
            status="running",
            pending_plan_json={},
            dialog_state_json={},
            browser_runtime_json={},
            last_task_id=None,
        )

    monkeypatch.setattr(
        agent_tasks,
        "SessionLocal",
        _SessionLocalFactory(task_run=task_run, session_builder=_build_session),
    )
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_success", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: None)

    def _update_task_run(_db, current_task_run, **kwargs):  # type: ignore[no-untyped-def]
        for key, value in kwargs.items():
            setattr(current_task_run, key, value)
        return current_task_run

    monkeypatch.setattr(agent_tasks, "update_task_run", _update_task_run)

    def _set_task_progress(_task_run_id, _progress, _message, result_json=None, **_kwargs):  # type: ignore[no-untyped-def]
        if isinstance(result_json, dict):
            task_run.result_json = deepcopy(result_json)

    monkeypatch.setattr(agent_tasks, "set_task_progress", _set_task_progress)
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="queued",
            summary="已提交风险验证任务 task-child-1",
            payload={"finding_id": "finding-1", "asset_id": "asset-1"},
            child_task_id="task-child-1",
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "wait_for_child_task",
        lambda task_id, interval_seconds=0.5: {
            "task_id": task_id,
            "status": TaskExecutionStatus.SUCCESS.value,
            "message": "风险验证完成",
            "result_json": {},
            "error_json": {},
        },
    )
    monkeypatch.setattr(
        agent_tasks,
        "build_auto_action_task_followup_content",
        lambda action, child_summary: (
            "task_update",
            "风险验证已完成",
            {"kind": "post_verify_analysis", "suggested_reply_label": "继续分析风险"},
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
    assert appended_messages
    payload_json = appended_messages[0]["payload_json"]
    assert isinstance(payload_json, dict)
    assert payload_json["resume_hint"]["goal_id"] == "goal-1"


def test_run_agent_orchestrate_task_routes_ssh_blocked_remediation_to_secure_input(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    goal = SimpleNamespace(status="active", blocked_reason=None, progress_json={})
    session = SimpleNamespace(
        id="session-1",
        user_id="user-1",
        current_goal=goal,
        current_goal_id="goal-1",
        status="running",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        last_task_id=None,
    )
    db = _FakeDB(session, task_run=task_run)
    secure_input_calls: list[dict[str, object]] = []
    task_success_calls: list[dict[str, object]] = []

    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)
    monkeypatch.setattr(agent_tasks, "set_task_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        agent_tasks,
        "set_task_success",
        lambda task_id, message, result_json: task_success_calls.append(
            {"task_id": task_id, "message": message, "result_json": deepcopy(result_json)}
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="success",
            summary="当前自动修复先被 SSH 凭据阻塞",
            payload={
                "asset_id": "asset-1",
                "session_id": "remediation-session-1",
                "execution_ready": False,
                "blocked_reasons": ["当前自动修复仍缺少 SSH 管理员凭据"],
                "blocker_codes": ["missing_ssh_credential"],
                "blockers": [
                    {
                        "code": "missing_ssh_credential",
                        "message": "当前自动修复仍缺少 SSH 管理员凭据",
                        "scope": "asset",
                        "blocking": "hard",
                    }
                ],
                "submitted_task_id": None,
            },
            child_task_id=None,
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "append_blocked_action_result_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should route SSH blockers to secure input")),
    )

    def _fake_transition(db_obj, *, session_id, task_id, action, result_payload, content=None):  # type: ignore[no-untyped-def]
        secure_input_calls.append(
            {
                "session_id": session_id,
                "task_id": task_id,
                "action": action,
                "result_payload": result_payload,
                "content": content,
            }
        )
        db_obj._session.browser_runtime_json = {
            "phase": "awaiting_secure_input",
            "pending_secure_input": {
                "resume_action": {"action_type": "create_or_resume_remediation_session"},
            },
        }
        db_obj._session.current_goal.status = "blocked"
        db_obj._session.current_goal.blocked_reason = "等待在安全弹层中完成 SSH 凭据配置"

    monkeypatch.setattr(agent_tasks, "transition_session_to_remediation_secure_input", _fake_transition)
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not append generic completion message")),
    )

    orchestrate_fn = agent_tasks.run_agent_orchestrate_task.__wrapped__.__func__
    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-1", retries=0),
        max_retries=1,
        retry=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not retry success path")),
    )

    result = orchestrate_fn(fake_task, "task-orchestrate-1", "session-1")

    assert result == "task-orchestrate-1"
    assert secure_input_calls
    assert secure_input_calls[0]["task_id"] == "task-orchestrate-1"
    assert secure_input_calls[0]["action"]["action_type"] == "create_or_resume_remediation_session"
    assert session.browser_runtime_json["phase"] == "awaiting_secure_input"
    assert session.current_goal.status == "blocked"
    assert task_success_calls[0]["task_id"] == "task-orchestrate-1"


def test_run_agent_orchestrate_task_keeps_non_ssh_remediation_blocked(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
    goal = SimpleNamespace(status="active", blocked_reason=None, progress_json={})
    session = SimpleNamespace(
        id="session-1",
        user_id="user-1",
        current_goal=goal,
        current_goal_id="goal-1",
        status="running",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        last_task_id=None,
    )
    db = _FakeDB(session, task_run=task_run)
    blocked_calls: list[dict[str, object]] = []
    task_success_calls: list[dict[str, object]] = []

    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)
    monkeypatch.setattr(agent_tasks, "set_task_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        agent_tasks,
        "set_task_success",
        lambda task_id, message, result_json: task_success_calls.append(
            {"task_id": task_id, "message": message, "result_json": deepcopy(result_json)}
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="success",
            summary="当前未自动执行：当前主机尚未安装 Host Runner",
            payload={
                "asset_id": "asset-1",
                "session_id": "remediation-session-1",
                "execution_ready": False,
                "blocked_reasons": ["当前主机尚未安装 Host Runner"],
                "blocker_codes": ["runner_not_installed"],
                "blockers": [
                    {
                        "code": "runner_not_installed",
                        "message": "当前主机尚未安装 Host Runner",
                        "scope": "asset",
                        "blocking": "hard",
                    }
                ],
                "submitted_task_id": None,
            },
            child_task_id=None,
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "transition_session_to_remediation_secure_input",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not open secure input for runner blockers")),
    )

    def _fake_append_blocked(db_obj, *, session_id, task_id, action, result_payload, content, blocked_reason=None):  # type: ignore[no-untyped-def]
        blocked_calls.append(
            {
                "session_id": session_id,
                "task_id": task_id,
                "action": action,
                "result_payload": result_payload,
                "content": content,
                "blocked_reason": blocked_reason,
            }
        )
        db_obj._session.current_goal.status = "blocked"
        db_obj._session.current_goal.blocked_reason = blocked_reason or content

    monkeypatch.setattr(agent_tasks, "append_blocked_action_result_message", _fake_append_blocked)
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not append generic completion message")),
    )

    orchestrate_fn = agent_tasks.run_agent_orchestrate_task.__wrapped__.__func__
    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-1", retries=0),
        max_retries=1,
        retry=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not retry success path")),
    )

    result = orchestrate_fn(fake_task, "task-orchestrate-1", "session-1")

    assert result == "task-orchestrate-1"
    assert blocked_calls
    assert blocked_calls[0]["task_id"] == "task-orchestrate-1"
    assert blocked_calls[0]["action"]["action_type"] == "create_or_resume_remediation_session"
    assert session.current_goal.status == "blocked"
    assert "Host Runner" in str(session.current_goal.blocked_reason)
    assert task_success_calls[0]["task_id"] == "task-orchestrate-1"


def test_run_agent_orchestrate_task_keeps_maintenance_window_blocked(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    initial_result_json = {
        "context": {"session_id": "session-1", "platform_url": "http://localhost:3000"},
        "plan": {
            "proposed_write_actions": [
                {
                    "action_type": "approve_remediation_session",
                    "title": "批准修复会话",
                    "params": {"session_id": "remediation-session-1"},
                }
            ]
        },
        "execution": {"approved_by": "user-1", "results": []},
    }
    task_run = _make_task_run(result_json=initial_result_json)
    goal = SimpleNamespace(status="active", blocked_reason=None, progress_json={})
    session = SimpleNamespace(
        id="session-1",
        user_id="user-1",
        current_goal=goal,
        current_goal_id="goal-1",
        status="running",
        pending_plan_json={},
        dialog_state_json={},
        browser_runtime_json={},
        last_task_id=None,
    )
    db = _FakeDB(session, task_run=task_run)
    blocked_calls: list[dict[str, object]] = []
    task_success_calls: list[dict[str, object]] = []

    monkeypatch.setattr(agent_tasks, "SessionLocal", _SessionLocalContext(db))
    monkeypatch.setattr(agent_tasks, "tracked_task", _tracked_task_context)
    monkeypatch.setattr(agent_tasks, "ensure_task_not_canceled", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(agent_tasks, "get_task_run", lambda _db, _task_run_id: task_run)
    monkeypatch.setattr(agent_tasks, "set_task_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "append_current_task_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "sync_agent_task_watch_state", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_failure", lambda *args, **kwargs: None)
    monkeypatch.setattr(agent_tasks, "set_task_retry", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        agent_tasks,
        "set_task_success",
        lambda task_id, message, result_json: task_success_calls.append(
            {"task_id": task_id, "message": message, "result_json": deepcopy(result_json)}
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "execute_approved_action",
        lambda *args, **kwargs: SimpleNamespace(
            status="success",
            summary="修复会话 remediation-session-1 当前仍缺维护窗口。阻塞原因：当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行。请先填写 maintenance_window_id 后再继续自动修复，或进入修复工作台查看详情。",
            payload={
                "asset_id": "asset-1",
                "session_id": "remediation-session-1",
                "execution_ready": False,
                "blocked_reasons": ["当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行"],
                "blocker_codes": ["maintenance_window_required"],
                "blocker_categories": ["policy"],
                "blockers": [
                    {
                        "code": "maintenance_window_required",
                        "message": "当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行",
                        "blocker_category": "policy",
                        "scope": "stage",
                        "blocking": "hard",
                    }
                ],
                "submitted_task_id": None,
            },
            child_task_id=None,
        ),
    )
    monkeypatch.setattr(
        agent_tasks,
        "transition_session_to_remediation_secure_input",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not open secure input for maintenance window blockers")),
    )

    def _fake_append_blocked(db_obj, *, session_id, task_id, action, result_payload, content, blocked_reason=None):  # type: ignore[no-untyped-def]
        blocked_calls.append(
            {
                "session_id": session_id,
                "task_id": task_id,
                "action": action,
                "result_payload": result_payload,
                "content": content,
                "blocked_reason": blocked_reason,
            }
        )
        db_obj._session.current_goal.status = "blocked"
        db_obj._session.current_goal.blocked_reason = blocked_reason or content

    monkeypatch.setattr(agent_tasks, "append_blocked_action_result_message", _fake_append_blocked)
    monkeypatch.setattr(
        agent_tasks,
        "append_agent_task_message",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not append generic failure message")),
    )

    orchestrate_fn = agent_tasks.run_agent_orchestrate_task.__wrapped__.__func__
    fake_task = SimpleNamespace(
        request=SimpleNamespace(id="celery-1", retries=0),
        max_retries=1,
        retry=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("should not retry blocked path")),
    )

    result = orchestrate_fn(fake_task, "task-orchestrate-1", "session-1")

    assert result == "task-orchestrate-1"
    assert blocked_calls
    assert blocked_calls[0]["action"]["action_type"] == "approve_remediation_session"
    assert "maintenance_window_id" in str(blocked_calls[0]["content"])
    assert session.current_goal.status == "blocked"
    assert "maintenance_window_id" in str(session.current_goal.blocked_reason)
    assert task_success_calls[0]["task_id"] == "task-orchestrate-1"


def test_humanize_orchestrate_error_hides_detached_session_details() -> None:
    exc = DetachedInstanceError(
        "Instance <AgentSession> is not bound to a Session; attribute refresh operation cannot proceed"
    )

    assert agent_tasks._humanize_orchestrate_error(exc) == "会话状态已过期，请刷新页面后重试"
