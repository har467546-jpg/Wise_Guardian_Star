from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.db.models.enums import TaskExecutionStatus
from app.services.agent.async_state import AsyncStatePatch, merge_task_async_state, serialize_celery_payload
from app.services.agent.dlp import MASK, redact_sensitive_payload, redact_sensitive_text
from app.services.agent.execution_registry import AgentActionExecutorContext, AgentExecutionResult
from app.services.agent.execution_service import AgentExecutionService
from app.services.agent.session_service import interrupt_agent_session, reconcile_running_session_state
from app.services.agent.tool_rbac import ToolRbacError


def test_dlp_redacts_secret_values_without_hiding_business_targets() -> None:
    payload = {
        "cidr": "10.0.0.0/24",
        "asset_id": "asset-1",
        "password": "secret-password",
        "nested": {"api_key": "sk-test-secret-value-1234567890"},
        "note": "token=abc.def.ghi",
    }

    redacted = redact_sensitive_payload(payload)

    assert redacted["cidr"] == "10.0.0.0/24"
    assert redacted["asset_id"] == "asset-1"
    assert redacted["password"] == MASK
    assert redacted["nested"]["api_key"] == MASK
    assert MASK in redacted["note"]


def test_dlp_redacts_private_key_blocks_in_text() -> None:
    content = "key:\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"

    redacted = redact_sensitive_text(content)

    assert "abc" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_async_state_serializes_json_and_redacts_secrets() -> None:
    payload = serialize_celery_payload(
        {
            "status": TaskExecutionStatus.RUNNING,
            "created_at": datetime(2026, 6, 22, tzinfo=timezone.utc),
            "token": "plain-token",
        }
    )

    assert payload["status"] == "running"
    assert payload["created_at"].startswith("2026-06-22T00:00:00")
    assert payload["token"] == MASK

    result = merge_task_async_state(
        {"execution": {"results": []}},
        AsyncStatePatch(
            stage="await_child_task",
            message="等待子任务",
            suspend_reason="awaiting_task",
            task_id="task-1",
            child_task_id="child-1",
            payload={"password": "secret"},
        ),
    )

    assert result["async_state"]["stage"] == "await_child_task"
    assert result["async_state"]["child_task_id"] == "child-1"
    assert result["async_state"]["payload"]["password"] == MASK


def test_tool_rbac_blocks_analyst_before_executor_runs(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    service = AgentExecutionService(supported_action_types={"create_discovery_job"})
    calls: list[dict] = []
    monkeypatch.setattr(
        "app.services.agent.execution_service.execute_registered_action",
        lambda *args, **kwargs: calls.append(kwargs) or AgentExecutionResult(status="success", summary="ok"),
    )
    context = AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        session_user_role="analyst",
        platform_url="",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    with pytest.raises(ToolRbacError):
        service.execute(context, action={"action_type": "create_discovery_job", "params": {"cidr": "10.0.0.0/24"}})

    assert calls == []


def test_tool_rbac_allows_admin_executor(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    service = AgentExecutionService(supported_action_types={"create_discovery_job"})
    monkeypatch.setattr(
        "app.services.agent.execution_service.execute_registered_action",
        lambda *args, **kwargs: AgentExecutionResult(status="success", summary="ok"),
    )
    context = AgentActionExecutorContext(
        db=SimpleNamespace(),
        session_user_id="user-1",
        session_user_role="admin",
        platform_url="",
        get_manual_credential=lambda *_args, **_kwargs: None,
    )

    result = service.execute(context, action={"action_type": "create_discovery_job", "params": {"cidr": "10.0.0.0/24"}})

    assert result.status == "success"


def test_reconcile_running_session_uses_async_state_orchestrate_task_when_last_task_is_child() -> None:
    session = SimpleNamespace(
        id="session-1",
        status="running",
        last_task_id="child-task-1",
        browser_runtime_json={"async_state": {"task_id": "task-orchestrate-1"}},
        agent_state_json={},
    )
    tasks = {
        "child-task-1": SimpleNamespace(id="child-task-1", status="running"),
        "task-orchestrate-1": SimpleNamespace(id="task-orchestrate-1", status="running"),
    }
    db = SimpleNamespace(add=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should stay running")))

    changed = reconcile_running_session_state(
        db,
        session=session,
        sanitize_line_fn=lambda value, max_length=64: str(value or "")[:max_length],
        get_task_run_fn=lambda _db, task_id: tasks.get(task_id),
        is_session_orchestrate_task_fn=lambda task, session_id: task.id == "task-orchestrate-1" and session_id == "session-1",
        normalize_task_status_fn=lambda status: str(status or ""),
        is_terminal_task_status_fn=lambda _status: False,
        restore_session_from_running_state_fn=lambda _session: (_ for _ in ()).throw(AssertionError("should not restore")),
        append_interrupted_task_message_fn=lambda *_args, **_kwargs: None,
        canceled_task_status="canceled",
    )

    assert changed is False
    assert session.status == "running"


def test_interrupt_session_uses_async_state_orchestrate_task_when_last_task_is_child() -> None:
    session = SimpleNamespace(
        id="session-1",
        status="running",
        last_task_id="child-task-1",
        browser_runtime_json={"async_state": {"task_id": "task-orchestrate-1"}},
        agent_state_json={},
    )
    task = SimpleNamespace(id="task-orchestrate-1", status="running", celery_task_id="celery-1")
    canceled: dict[str, str] = {}
    revoked: list[str] = []

    class _AgentError(Exception):
        def __init__(self, detail: str, **kwargs) -> None:
            super().__init__(detail)
            self.detail = detail
            self.kwargs = kwargs

    response = interrupt_agent_session(
        SimpleNamespace(commit=lambda: None, refresh=lambda _obj: None),
        user=SimpleNamespace(id="user-1"),
        load_recent_session_fn=lambda _db, user_id: session,
        reconcile_running_session_state_fn=lambda _db, *, session, interrupted_source: False,
        restore_session_from_running_state_fn=lambda _session: None,
        sanitize_line_fn=lambda value, max_length=64: str(value or "")[:max_length],
        get_task_run_fn=lambda _db, task_id: task if task_id == "task-orchestrate-1" else None,
        is_session_orchestrate_task_fn=lambda candidate, session_id: candidate.id == "task-orchestrate-1" and session_id == "session-1",
        is_active_task_status_fn=lambda _status: True,
        normalize_task_status_fn=lambda status: str(status or ""),
        celery_app=SimpleNamespace(control=SimpleNamespace(revoke=lambda celery_id, **_kwargs: revoked.append(celery_id))),
        running_task_status="running",
        retry_task_status="retry",
        cancel_task_run_fn=lambda _db, current_task, **_kwargs: canceled.update({"task_id": current_task.id}) or current_task,
        mark_agent_session_interrupted_fn=lambda _db, *, session_id, task_id, source: canceled.update({"interrupted_task_id": task_id}),
        serialize_agent_session_fn=lambda current_session: {"id": current_session.id, "status": current_session.status},
        agent_not_found_error_cls=_AgentError,
        agent_conflict_error_cls=_AgentError,
        agent_upstream_error_cls=_AgentError,
    )

    assert response["id"] == "session-1"
    assert canceled["task_id"] == "task-orchestrate-1"
    assert canceled["interrupted_task_id"] == "task-orchestrate-1"
    assert revoked == ["celery-1"]
