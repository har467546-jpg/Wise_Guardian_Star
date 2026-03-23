from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from app.db.models.agent_session import AgentSession

AgentRuntimeState = Literal[
    "idle",
    "awaiting_agent_reply",
    "awaiting_ui_feedback",
    "waiting_approval",
    "running",
    "interrupted",
    "completed",
    "failed",
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

    if runtime_phase == "awaiting_agent_reply":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_agent_reply")
    if runtime_phase == "awaiting_ui_feedback":
        return AgentStateSnapshot(public_status=public_status, runtime_phase=runtime_phase, internal_state="awaiting_ui_feedback")
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
    elif state == "awaiting_agent_reply":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_agent_reply")
    elif state == "awaiting_ui_feedback":
        set_runtime_state(session, public_status="active", runtime_phase="awaiting_ui_feedback")
    elif state == "waiting_approval":
        set_runtime_state(session, public_status="waiting_approval", runtime_phase="idle")
    elif state == "running":
        set_runtime_state(session, public_status="running", runtime_phase="idle")
    elif state == "interrupted":
        set_runtime_state(session, public_status="active", runtime_phase="interrupted")
    elif state == "completed":
        set_runtime_state(session, public_status="completed", runtime_phase="idle")
    elif state == "failed":
        set_runtime_state(session, public_status="failed", runtime_phase="idle")
