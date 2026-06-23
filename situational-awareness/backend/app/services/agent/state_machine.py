from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.db.models.agent_session import AgentSession

AgentRuntimeState = Literal[
    "idle",
    "queued",
    "awaiting_agent_reply",
    "awaiting_task",
    "awaiting_secure_input",
    "awaiting_ui_feedback",
    "waiting_input",
    "waiting_approval",
    "running",
    "resuming",
    "suspended",
    "interrupted",
    "completed",
    "failed",
    "canceled",
]

ACTIVE_PUBLIC_SESSION_STATUSES = {"active", "waiting_approval", "running"}


@dataclass(frozen=True, slots=True)
class AgentStateSnapshot:
    public_status: str
    runtime_phase: str
    internal_state: AgentRuntimeState


def _normalize_public_status(session: AgentSession) -> str:
    return str(getattr(session, "status", "") or "").strip().lower() or "active"


def _normalize_runtime_phase(session: AgentSession) -> str:
    runtime = getattr(session, "browser_runtime_json", None)
    if not isinstance(runtime, dict):
        return "idle"
    return str(runtime.get("phase") or "").strip().lower() or "idle"


def get_runtime_state(session: AgentSession) -> AgentStateSnapshot:
    public_status = _normalize_public_status(session)
    runtime_phase = _normalize_runtime_phase(session)

    if public_status == "waiting_approval":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="waiting_approval")
    if public_status == "running":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="running")
    if public_status == "completed":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="completed")
    if public_status == "failed":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="failed")
    if public_status == "canceled":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="canceled")

    if runtime_phase == "queued":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="queued")
    if runtime_phase == "awaiting_agent_reply":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_agent_reply")
    if runtime_phase in {"awaiting_task", "watching_task"}:
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_task")
    if runtime_phase == "awaiting_secure_input":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_secure_input")
    if runtime_phase == "awaiting_ui_feedback":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_ui_feedback")
    if runtime_phase in {"awaiting_user_input", "waiting_user_input"}:
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="waiting_input")
    if runtime_phase == "resuming":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="resuming")
    if runtime_phase == "suspended":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="suspended")
    if runtime_phase == "interrupted":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="interrupted")
    return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="idle")


def is_active_public_session_status(status: str | None) -> bool:
    return str(status or "").strip().lower() in ACTIVE_PUBLIC_SESSION_STATUSES


def set_runtime_state(session: AgentSession, *, public_status: str | None = None, runtime_phase: str | None = None) -> None:
    runtime = session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    next_runtime = dict(runtime)
    if runtime_phase is not None:
        next_runtime["phase"] = runtime_phase
    session.browser_runtime_json = next_runtime
    if public_status is not None:
        session.status = public_status


def set_runtime_state_from_internal(session: AgentSession, state: AgentRuntimeState) -> None:
    if state == "idle":
        set_runtime_state(session, public_status="active", runtime_phase="idle")
    elif state == "queued":
        set_runtime_state(session, public_status="running", runtime_phase="queued")
    elif state == "awaiting_agent_reply":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_agent_reply")
    elif state == "awaiting_task":
        set_runtime_state(session, public_status="running", runtime_phase="awaiting_task")
    elif state == "awaiting_secure_input":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_secure_input")
    elif state == "awaiting_ui_feedback":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_ui_feedback")
    elif state == "waiting_input":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_user_input")
    elif state == "waiting_approval":
        set_runtime_state(session, public_status="waiting_approval", runtime_phase="idle")
    elif state == "running":
        set_runtime_state(session, public_status="running", runtime_phase="idle")
    elif state == "resuming":
        set_runtime_state(session, public_status="running", runtime_phase="resuming")
    elif state == "suspended":
        set_runtime_state(session, public_status="active", runtime_phase="suspended")
    elif state == "interrupted":
        set_runtime_state(session, public_status="active", runtime_phase="interrupted")
    elif state == "completed":
        set_runtime_state(session, public_status="completed", runtime_phase="idle")
    elif state == "failed":
        set_runtime_state(session, public_status="failed", runtime_phase="idle")
    elif state == "canceled":
        set_runtime_state(session, public_status="canceled", runtime_phase="idle")
