from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from sqlalchemy.orm import Session

from app.db.models.agent_session import AgentSession
from app.db.models.enums import TaskExecutionStatus
from app.db.models.task_run import TaskRun
from app.repositories.task_repo import update_task_run
from app.services.agent.dlp import redact_sensitive_payload, redact_sensitive_text
from app.utils.sanitize import sanitize_json_value, sanitize_text


AsyncSuspendReason = Literal[
    "awaiting_task",
    "awaiting_secure_input",
    "blocked",
    "retrying",
    "interrupted",
    "failed",
]


@dataclass(frozen=True, slots=True)
class AsyncStatePatch:
    stage: str
    message: str
    suspend_reason: AsyncSuspendReason | None = None
    task_id: str | None = None
    child_task_id: str | None = None
    action_type: str | None = None
    action_index: int | None = None
    total_actions: int | None = None
    progress: int | None = None
    payload: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        payload = sanitize_json_value(self.payload if isinstance(self.payload, dict) else {})
        data = {
            "stage": sanitize_text(self.stage, max_length=64, single_line=True) or "unknown",
            "message": redact_sensitive_text(self.message, max_length=280, single_line=True),
            "suspend_reason": self.suspend_reason,
            "task_id": sanitize_text(self.task_id, max_length=64, single_line=True) or None,
            "child_task_id": sanitize_text(self.child_task_id, max_length=64, single_line=True) or None,
            "action_type": sanitize_text(self.action_type, max_length=64, single_line=True) or None,
            "action_index": self.action_index,
            "total_actions": self.total_actions,
            "progress": None if self.progress is None else max(0, min(100, int(self.progress))),
            "payload": redact_sensitive_payload(payload),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        return {key: value for key, value in data.items() if value is not None and value != {}}


def _deep_merge_dict(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def serialize_celery_payload(value: Any) -> Any:
    return redact_sensitive_payload(sanitize_json_value(value))


def normalize_task_result_json(result_json: dict[str, Any] | None) -> dict[str, Any]:
    payload = sanitize_json_value(result_json if isinstance(result_json, dict) else {})
    if not isinstance(payload, dict):
        return {}
    payload.setdefault("async_state", {})
    return payload


def merge_task_async_state(result_json: dict[str, Any] | None, patch: AsyncStatePatch | dict[str, Any]) -> dict[str, Any]:
    current = normalize_task_result_json(result_json)
    patch_json = patch.to_json() if isinstance(patch, AsyncStatePatch) else serialize_celery_payload(patch)
    async_state = current.get("async_state") if isinstance(current.get("async_state"), dict) else {}
    current["async_state"] = _deep_merge_dict(async_state, patch_json if isinstance(patch_json, dict) else {})
    return current


def update_task_async_state(
    db: Session,
    task_run: TaskRun,
    patch: AsyncStatePatch | dict[str, Any],
    *,
    commit: bool = True,
    refresh: bool = True,
) -> TaskRun:
    return update_task_run(
        db,
        task_run,
        result_json=merge_task_async_state(task_run.result_json if isinstance(task_run.result_json, dict) else {}, patch),
        commit=commit,
        refresh=refresh,
    )


def build_orchestrate_progress_result(
    result_json: dict[str, Any] | None,
    *,
    runtime_patch: dict[str, Any],
    async_patch: AsyncStatePatch | dict[str, Any] | None = None,
) -> dict[str, Any]:
    current_result = normalize_task_result_json(result_json)
    execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
    current_result["execution"] = _deep_merge_dict(execution, {"runtime": serialize_celery_payload(runtime_patch)})
    if async_patch is not None:
        current_result = merge_task_async_state(current_result, async_patch)
    return current_result


def suspend_agent_session(
    session: AgentSession,
    *,
    reason: AsyncSuspendReason,
    task_id: str | None,
    message: str,
    child_task_id: str | None = None,
    runtime_phase: str | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    async_state = AsyncStatePatch(
        stage=runtime_phase or reason,
        message=message,
        suspend_reason=reason,
        task_id=task_id,
        child_task_id=child_task_id,
        payload=payload or {},
    ).to_json()
    raw_runtime = getattr(session, "browser_runtime_json", None)
    runtime = raw_runtime if isinstance(raw_runtime, dict) else {}
    next_runtime = dict(runtime)
    next_runtime["phase"] = runtime_phase or reason
    next_runtime["async_state"] = async_state
    session.browser_runtime_json = serialize_celery_payload(next_runtime)
    session.status = "running" if reason == "awaiting_task" else "active"
    if task_id:
        session.last_task_id = child_task_id or task_id
    raw_state = getattr(session, "agent_state_json", None)
    state = raw_state if isinstance(raw_state, dict) else {}
    state["async_state"] = async_state
    session.agent_state_json = serialize_celery_payload(state)
    return async_state
