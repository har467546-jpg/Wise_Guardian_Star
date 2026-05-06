from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from time import sleep
from typing import Any, Callable, Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.api.v1.endpoints import vuln_library as vuln_library_endpoint
from app.core.celery_app import celery_app
from app.core.config import read_runtime_env_value, settings
from app.db.models.agent_message import AgentMessage
from app.db.models.agent_goal import AgentGoal
from app.db.models.agent_session import AgentSession
from app.db.models.asset import Asset
from app.db.models.enums import (
    AssetStatus,
    FindingStatus,
    RiskSeverity,
    TaskExecutionStatus,
    TaskType,
    UserRole,
)
from app.db.models.remediation_session import RemediationSession
from app.db.models.risk_finding import RiskFinding
from app.db.models.user import User
from app.repositories.asset_repo import get_asset, list_assets
from app.repositories.risk_repo import get_finding, list_findings, list_findings_by_asset
from app.repositories.task_event_repo import list_task_events_for_task
from app.repositories.task_repo import (
    cancel_task_run,
    create_task_run,
    get_latest_task_run_for_scope,
    get_task_run,
    list_task_runs,
    update_task_run,
)
from app.schemas.agent import (
    AgentActionUpdateEvent,
    AgentApprovalRequest,
    AgentApprovalResponse,
    AgentAttentionKind,
    AgentAssistantDeltaEvent,
    AgentAssistantMessageDoneEvent,
    AgentAssistantMessageStartEvent,
    AgentErrorEvent,
    AgentMessageCreateRequest,
    AgentMessageRead,
    AgentPlanPendingEvent,
    AgentProposedActionRead,
    AgentRecoverableErrorRead,
    AgentRuntimeSnapshotRead,
    AgentStateEvent,
    AgentSessionSummaryRead,
    AgentSessionSnapshotEvent,
    AgentSessionRead,
    AgentTaskUpdateEvent,
    AgentTurnDoneEvent,
    AgentTurnStartedEvent,
    AgentUIActionsRequestedEvent,
    AgentUIStepRequest,
)
from app.services.ai.providers import LLMMessage, LLMRequest, build_provider
from app.services.agent.context_service import sanitize_browser_context_summary
from app.services.agent.execution_registry import AgentActionExecutorContext, AgentExecutionResult
from app.services.agent.execution_service import AgentExecutionService
from app.services.agent_goal_service import (
    attach_goal_to_session,
    ensure_goal_for_message,
    get_agent_goal as get_agent_goal_read,
    list_agent_goals as list_agent_goal_reads,
    mark_goal_blocked,
    mark_goal_canceled,
    resume_agent_goal_binding,
    sync_goal_from_session,
)
from app.services.agent_playbook_service import AgentPlaybookDecision, get_skill_title, match_registered_playbook
from app.services.agent.session_service import (
    append_interrupted_task_message,
    ensure_active_session,
    interrupt_agent_session as interrupt_agent_session_via_service,
    load_recent_session,
    mark_agent_session_interrupted as mark_agent_session_interrupted_via_service,
    reconcile_running_session_state,
    reset_agent_session as reset_agent_session_via_service,
    restore_session_from_running_state,
)
from app.services.agent.state_machine import is_active_public_session_status
from app.services.remediation_service import build_plan, get_manual_credential, list_remediation_assets
from app.services.remediation_session_service import (
    build_remediation_asset_detail,
    get_remediation_session_read,
)
from app.services.task_observability_service import serialize_task_detail, serialize_task_event
from app.tasks.collect_tasks import run_asset_collect_task
from app.tasks.scan_tasks import run_asset_scan_task
from app.utils.local_asset import resolve_local_asset
from app.utils.net import normalize_cidr
from app.utils.sanitize import sanitize_json_value, sanitize_text


AGENT_ID = "haor"
ACTIVE_TASK_STATUSES = {
    TaskExecutionStatus.PENDING,
    TaskExecutionStatus.RUNNING,
    TaskExecutionStatus.RETRY,
}
TERMINAL_TASK_STATUSES = {
    TaskExecutionStatus.SUCCESS,
    TaskExecutionStatus.FAILURE,
    TaskExecutionStatus.CANCELED,
}
SUPPORTED_READ_TOOLS = {
    "list_assets",
    "get_asset_detail",
    "list_risks",
    "get_risk_detail",
    "list_asset_risks",
    "list_tasks",
    "get_task_detail",
    "get_task_events",
    "list_remediation_assets",
    "get_remediation_asset",
    "get_remediation_session",
    "get_risk_remediation_template",
    "list_vuln_rules",
    "get_vuln_rule",
}
SUPPORTED_WRITE_ACTIONS = {
    "create_discovery_job",
    "verify_asset_risks",
    "install_runner",
    "create_or_resume_remediation_session",
    "approve_remediation_session",
    "configure_ssh_credential",
}
AGENT_EXECUTION_SERVICE = AgentExecutionService(supported_action_types=SUPPORTED_WRITE_ACTIONS)
AUTO_EXECUTE_ACTIONS = {
    "create_discovery_job",
    "verify_asset_risks",
    "install_runner",
}
SSH_CREDENTIAL_BLOCKER_CODES = {
    "missing_ssh_credential",
    "authorization_unconfirmed",
    "authorization_not_verified",
    "insufficient_privilege",
}
RUNNER_BLOCKER_CODES = {
    "runner_not_installed",
    "runner_installing",
    "runner_offline",
}
RENDER_BLOCKER_CODES = {
    "unstable_render",
    "missing_target",
    "missing_adapter",
}
ACTION_POLICY_REGISTRY: dict[str, dict[str, Any]] = {
    "create_discovery_job": {
        "required_slots": ["cidr"],
        "risk_level": "low",
        "needs_confirmation": False,
        "auto_execute_allowed": True,
        "task_followup_strategy": "watch_task",
    },
    "verify_asset_risks": {
        "required_slots": ["asset_id"],
        "risk_level": "low",
        "needs_confirmation": False,
        "auto_execute_allowed": True,
        "task_followup_strategy": "watch_task",
    },
    "install_runner": {
        "required_slots": ["asset_id"],
        "risk_level": "low",
        "needs_confirmation": False,
        "auto_execute_allowed": True,
        "task_followup_strategy": "watch_task",
    },
    "create_or_resume_remediation_session": {
        "required_slots": ["asset_id"],
        "risk_level": "high",
        "needs_confirmation": True,
        "auto_execute_allowed": False,
        "task_followup_strategy": "session",
    },
    "approve_remediation_session": {
        "required_slots": ["session_id"],
        "risk_level": "high",
        "needs_confirmation": True,
        "auto_execute_allowed": False,
        "task_followup_strategy": "watch_task",
    },
    "configure_ssh_credential": {
        "required_slots": ["asset_id|asset_ids"],
        "risk_level": "sensitive_input",
        "needs_confirmation": False,
        "auto_execute_allowed": False,
        "task_followup_strategy": "secure_input",
    },
}
SUPPORTED_UI_ACTIONS = {
    "navigate",
    "click",
    "input",
    "select",
    "toggle",
    "expand",
    "scroll_into_view",
    "submit",
    "wait_for",
}
MAX_AGENT_LOOP_STEPS = 10
MAX_UI_ACTION_BATCH = 6
MAX_MODEL_DECISION_STEPS = 3
MAX_MODEL_HISTORY_MESSAGES = 6
MAX_MODEL_HISTORY_CHARS = 1800
MAX_MODEL_TOOL_TRACE_ITEMS = 4
MAX_MODEL_SECONDARY_ENTITIES = 6
MAX_MODEL_VISIBLE_SECTIONS = 8
MAX_MODEL_SEMANTIC_ACTIONS = 8
MAX_MODEL_SEMANTIC_FORMS = 4
MAX_MODEL_SELECTED_ROWS = 4
MAX_MODEL_SELECTED_ENTITIES = 4
MAX_MODEL_OPEN_PANELS = 4
MAX_MODEL_FORMS = 2
MAX_MODEL_VISIBLE_ACTIONS = 8
MAX_MODEL_DOM_SNAPSHOT_NODES = 12
MAX_MODEL_UI_RESULTS = 4
MAX_MODEL_PLANNED_STEPS = 6
MAX_ASSISTANT_MESSAGE_CHARS = 20000
MAX_REPLY_REWRITE_CHARS = 3000
MESSAGE_TURN_STALE_SECONDS = 120
UI_FEEDBACK_STALE_SECONDS = 300

logger = logging.getLogger(__name__)

_SHORT_FOLLOWUP_AFFIRM_MARKERS = {
    "继续",
    "好",
    "好的",
    "是",
    "是的",
    "行",
    "可以",
    "继续吧",
    "看",
    "查看",
    "继续看",
}
_SHORT_FOLLOWUP_DENY_MARKERS = {
    "不用了",
    "算了",
    "别看了",
    "不用",
    "不看了",
    "不要了",
    "取消",
    "先不看",
    "别继续了",
}
_MODEL_DECISION_CONVERSATION_STATE_ALIASES = {
    "completed": "answer",
    "done": "answer",
    "finish": "answer",
    "final": "answer",
}


class AgentServiceError(Exception):
    def __init__(
        self,
        detail: str,
        *,
        status_code: int,
        session_id: str | None = None,
        stage: str | None = None,
    ) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status_code = status_code
        self.session_id = session_id
        self.stage = stage


class AgentBadRequestError(AgentServiceError):
    def __init__(self, detail: str, *, session_id: str | None = None, stage: str | None = None) -> None:
        super().__init__(detail, status_code=400, session_id=session_id, stage=stage)


class AgentPermissionDeniedError(AgentServiceError):
    def __init__(self, detail: str, *, session_id: str | None = None, stage: str | None = None) -> None:
        super().__init__(detail, status_code=403, session_id=session_id, stage=stage)


class AgentNotFoundError(AgentServiceError):
    def __init__(self, detail: str, *, session_id: str | None = None, stage: str | None = None) -> None:
        super().__init__(detail, status_code=404, session_id=session_id, stage=stage)


class AgentConflictError(AgentServiceError):
    def __init__(self, detail: str, *, session_id: str | None = None, stage: str | None = None) -> None:
        super().__init__(detail, status_code=409, session_id=session_id, stage=stage)


class AgentUpstreamError(AgentServiceError):
    def __init__(self, detail: str, *, session_id: str | None = None, stage: str | None = None) -> None:
        super().__init__(detail, status_code=502, session_id=session_id, stage=stage)


class _ReadToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class _ProposedWriteAction(BaseModel):
    action_type: Literal[
        "create_discovery_job",
        "verify_asset_risks",
        "install_runner",
        "create_or_resume_remediation_session",
        "approve_remediation_session",
    ]
    title: str
    reason: str
    params: dict[str, Any] = Field(default_factory=dict)


class _UIAction(BaseModel):
    action_id: str = Field(default_factory=lambda: f"ui-{uuid4().hex[:12]}")
    action_type: Literal[
        "navigate",
        "click",
        "input",
        "select",
        "toggle",
        "expand",
        "scroll_into_view",
        "submit",
        "wait_for",
    ]
    semantic_action_id: str | None = None
    target_node_id: str | None = None
    selector: str | None = None
    text_contains: str | None = None
    label_contains: str | None = None
    href: str | None = None
    value: str | None = None
    field_name: str | None = None
    option_label: str | None = None
    wait_ms: int | None = None
    rationale: str | None = None
    expected_outcome: str | None = None
    expected_page_kind: str | None = None
    expected_section: str | None = None
    expected_entity: dict[str, Any] = Field(default_factory=dict)
    retryable: bool | None = True


class _DialogState(BaseModel):
    status: Literal["idle", "awaiting_user_input"] = "idle"
    intent_kind: Literal["read_followup", "analyze", "fill_slot", "prepare_plan"] | None = None
    question_kind: Literal["confirm", "slot_fill", "disambiguate", "followup"] | None = None
    intent_summary: str | None = None
    last_agent_question: str | None = None
    expected_slots: list[str] = Field(default_factory=list)
    candidate_read_tools: list[_ReadToolCall] = Field(default_factory=list)
    candidate_write_context: dict[str, Any] = Field(default_factory=dict)
    targets_snapshot: dict[str, Any] = Field(default_factory=dict)


class _FollowupResolution(BaseModel):
    status: Literal["resolved", "canceled", "reframed", "needs_more_input", "unknown"] = "unknown"
    summary: str | None = None


class _AgentModelDecision(BaseModel):
    reply_markdown: str
    conversation_state: Literal["answer", "clarifying", "plan"] = "answer"
    objective: str | None = None
    clarifying_question: str | None = None
    read_tool_calls: list[_ReadToolCall] = Field(default_factory=list)
    ui_actions: list[_UIAction] = Field(default_factory=list)
    proposed_write_actions: list[_ProposedWriteAction] = Field(default_factory=list)
    auto_execute_actions: list[_ProposedWriteAction] = Field(default_factory=list)
    needs_confirmation: bool = False
    dialog_state_update: _DialogState | None = None
    followup_resolution: _FollowupResolution | None = None
    stop_reason: str | None = None


@dataclass(slots=True)
class AgentExecutionResult:
    status: str
    summary: str
    child_task_id: str | None = None
    payload: dict[str, Any] | None = None


@dataclass(slots=True)
class _AgentStepPlan:
    step_kind: Literal["answer", "clarify", "read", "ui", "auto_execute", "propose_plan", "watch_task"]
    reason: str | None = None
    waiting_for: str | None = None
    next_step: str | None = None
    expected_outcome: str | None = None
    missing_slots: list[str] | None = None
    evidence: list[dict[str, Any]] | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _to_runtime_timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _parse_runtime_timestamp(value: Any) -> datetime | None:
    text = _sanitize_line(str(value or ""), max_length=64)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _sanitize_line(value: str | None, *, max_length: int = 140) -> str:
    return sanitize_text(value, max_length=max_length, single_line=True) or ""


def _normalize_role(value: UserRole | str | None) -> str:
    if hasattr(value, "value"):
        return str(getattr(value, "value"))
    return str(value or "").strip().lower() or "analyst"


def _session_query(user_id: str):
    return (
        select(AgentSession)
        .where(AgentSession.user_id == user_id, AgentSession.agent_id == AGENT_ID)
        .options(joinedload(AgentSession.messages), joinedload(AgentSession.current_goal))
        .order_by(AgentSession.updated_at.desc(), AgentSession.created_at.desc())
    )


def _summary_session_query(user_id: str):
    return (
        select(AgentSession)
        .where(AgentSession.user_id == user_id, AgentSession.agent_id == AGENT_ID)
        .options(joinedload(AgentSession.current_goal))
        .order_by(AgentSession.updated_at.desc(), AgentSession.created_at.desc())
    )


def _load_recent_session(db: Session, *, user_id: str) -> AgentSession | None:
    return load_recent_session(query_builder=_session_query, db=db, user_id=user_id)


def _load_recent_summary_session(db: Session, *, user_id: str) -> AgentSession | None:
    return load_recent_session(query_builder=_summary_session_query, db=db, user_id=user_id)


def _session_goal(session: AgentSession | None) -> AgentGoal | None:
    if session is None:
        return None
    goal = getattr(session, "current_goal", None)
    if isinstance(goal, AgentGoal):
        return goal
    return None


def _sync_current_goal_state(
    db: Session,
    session: AgentSession,
    *,
    status_override: str | None = None,
    blocked_reason: str | None = None,
    latest_summary: str | None = None,
    goal_blockers: list[dict[str, Any]] | None = None,
) -> AgentGoal | None:
    goal = _session_goal(session)
    if goal is None and getattr(session, "current_goal_id", None):
        goal = db.get(AgentGoal, session.current_goal_id)
        if goal is not None:
            session.current_goal = goal
    if goal is None:
        return None
    sync_goal_from_session(
        goal,
        session,
        status_override=status_override,
        blocked_reason=blocked_reason,
        latest_summary=latest_summary,
        goal_blockers=goal_blockers,
    )
    db.add(goal)
    db.add(session)
    return goal


def _normalize_task_status(status: TaskExecutionStatus | str | None) -> str:
    if hasattr(status, "value"):
        return str(getattr(status, "value") or "").strip().lower()
    return str(status or "").strip().lower()


def _is_active_task_status(status: TaskExecutionStatus | str | None) -> bool:
    return _normalize_task_status(status) in {item.value for item in ACTIVE_TASK_STATUSES}


def _is_terminal_task_status(status: TaskExecutionStatus | str | None) -> bool:
    return _normalize_task_status(status) in {item.value for item in TERMINAL_TASK_STATUSES}


def _is_session_orchestrate_task(task: Any, *, session_id: str) -> bool:
    if task is None:
        return False
    return (
        _normalize_task_status(getattr(task, "task_type", None)) == TaskType.AGENT_ORCHESTRATE.value
        and _sanitize_line(str(getattr(task, "scope_type", None) or ""), max_length=32) == "agent_session"
        and _sanitize_line(str(getattr(task, "scope_id", None) or ""), max_length=64) == session_id
    )


def _normalize_page_context(page_context: dict[str, Any] | None) -> dict[str, Any]:
    payload = page_context if isinstance(page_context, dict) else {}
    query = payload.get("query") if isinstance(payload.get("query"), dict) else {}
    normalized: dict[str, Any] = {
        "pathname": sanitize_text(str(payload.get("pathname") or "/"), max_length=255) or "/",
        "query": sanitize_json_value(query) if isinstance(query, dict) else {},
        "asset_id": sanitize_text(str(payload.get("asset_id") or ""), max_length=64) or None,
        "finding_id": sanitize_text(str(payload.get("finding_id") or ""), max_length=64) or None,
        "task_id": sanitize_text(str(payload.get("task_id") or ""), max_length=64) or None,
    }
    return normalized


def _normalize_browser_dom_node(node: dict[str, Any] | None) -> dict[str, Any]:
    payload = node if isinstance(node, dict) else {}
    normalized = {
        "node_id": _sanitize_line(str(payload.get("node_id") or ""), max_length=64),
        "tag_name": _sanitize_line(str(payload.get("tag_name") or "div"), max_length=24) or "div",
        "role": _sanitize_line(str(payload.get("role") or ""), max_length=32) or None,
        "text": sanitize_text(str(payload.get("text") or ""), max_length=220) or None,
        "label": sanitize_text(str(payload.get("label") or ""), max_length=160) or None,
        "href": sanitize_text(str(payload.get("href") or ""), max_length=255, single_line=True) or None,
        "value": sanitize_text(str(payload.get("value") or ""), max_length=160, single_line=True) or None,
        "is_interactive": bool(payload.get("is_interactive")),
        "is_visible": False if payload.get("is_visible") is False else True,
        "attributes": {},
    }
    if not normalized["node_id"]:
        return {}
    attributes = payload.get("attributes") if isinstance(payload.get("attributes"), dict) else {}
    normalized["attributes"] = {
        _sanitize_line(str(key), max_length=32): sanitize_text(str(value), max_length=120, single_line=True)
        for key, value in list(attributes.items())[:8]
        if _sanitize_line(str(key), max_length=32)
    }
    return normalized


def _normalize_browser_visible_action(action: dict[str, Any] | None) -> dict[str, Any]:
    payload = action if isinstance(action, dict) else {}
    action_type = _sanitize_line(str(payload.get("action_type") or "click"), max_length=32).lower() or "click"
    if action_type not in SUPPORTED_UI_ACTIONS:
        action_type = "click"
    normalized = {
        "action_id": _sanitize_line(str(payload.get("action_id") or f"visible-{uuid4().hex[:10]}"), max_length=64),
        "action_type": action_type,
        "node_id": _sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "label": sanitize_text(str(payload.get("label") or ""), max_length=120) or "",
        "description": sanitize_text(str(payload.get("description") or ""), max_length=160) or None,
    }
    if not normalized["action_id"] or not normalized["label"]:
        return {}
    return normalized


def _normalize_semantic_entity(entity: dict[str, Any] | None) -> dict[str, Any]:
    payload = entity if isinstance(entity, dict) else {}
    normalized = {
        "kind": _sanitize_line(str(payload.get("kind") or "entity"), max_length=32) or "entity",
        "id": _sanitize_line(str(payload.get("id") or ""), max_length=96) or None,
        "label": sanitize_text(str(payload.get("label") or ""), max_length=160) or None,
        "status": _sanitize_line(str(payload.get("status") or ""), max_length=48) or None,
        "source": _sanitize_line(str(payload.get("source") or "browser"), max_length=32) or "browser",
        "meta": sanitize_json_value(payload.get("meta") if isinstance(payload.get("meta"), dict) else {}),
    }
    if not normalized["id"] and not normalized["label"]:
        return {}
    return normalized


def _normalize_semantic_section(section: dict[str, Any] | None) -> dict[str, Any]:
    payload = section if isinstance(section, dict) else {}
    section_id = _sanitize_line(str(payload.get("section_id") or ""), max_length=96)
    label = sanitize_text(str(payload.get("label") or ""), max_length=120)
    if not section_id or not label:
        return {}
    return {
        "section_id": section_id,
        "label": label,
        "node_id": _sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "description": sanitize_text(str(payload.get("description") or ""), max_length=180) or None,
    }


def _normalize_semantic_action(action: dict[str, Any] | None) -> dict[str, Any]:
    payload = action if isinstance(action, dict) else {}
    action_type = _sanitize_line(str(payload.get("action_type") or "click"), max_length=32).lower() or "click"
    if action_type not in SUPPORTED_UI_ACTIONS:
        action_type = "click"
    semantic_action_id = _sanitize_line(str(payload.get("semantic_action_id") or ""), max_length=128)
    label = sanitize_text(str(payload.get("label") or ""), max_length=160)
    if not semantic_action_id or not label:
        return {}
    return {
        "semantic_action_id": semantic_action_id,
        "label": label,
        "action_type": action_type,
        "node_id": _sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "description": sanitize_text(str(payload.get("description") or ""), max_length=180) or None,
        "section_id": _sanitize_line(str(payload.get("section_id") or ""), max_length=96) or None,
        "href": sanitize_text(str(payload.get("href") or ""), max_length=255, single_line=True) or None,
        "selector": sanitize_text(str(payload.get("selector") or ""), max_length=180, single_line=True) or None,
        "text_contains": sanitize_text(str(payload.get("text_contains") or ""), max_length=120) or None,
        "target_entity": _normalize_semantic_entity(
            payload.get("target_entity") if isinstance(payload.get("target_entity"), dict) else {}
        ),
        "keywords": [
            sanitize_text(str(item), max_length=48) or ""
            for item in (payload.get("keywords") if isinstance(payload.get("keywords"), list) else [])[:10]
            if sanitize_text(str(item), max_length=48)
        ],
    }


def _normalize_semantic_form(form: dict[str, Any] | None) -> dict[str, Any]:
    payload = form if isinstance(form, dict) else {}
    semantic_form_id = _sanitize_line(str(payload.get("semantic_form_id") or ""), max_length=128)
    label = sanitize_text(str(payload.get("label") or ""), max_length=160)
    if not semantic_form_id or not label:
        return {}
    return {
        "semantic_form_id": semantic_form_id,
        "label": label,
        "node_id": _sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "fields": sanitize_json_value(payload.get("fields") if isinstance(payload.get("fields"), list) else [])[:8],
        "submit_action_id": _sanitize_line(str(payload.get("submit_action_id") or ""), max_length=128) or None,
    }


def _normalize_semantic_page_context(page_context: dict[str, Any] | None) -> dict[str, Any]:
    payload = page_context if isinstance(page_context, dict) else {}
    sections = payload.get("visible_sections") if isinstance(payload.get("visible_sections"), list) else []
    semantic_actions = payload.get("semantic_actions") if isinstance(payload.get("semantic_actions"), list) else []
    semantic_forms = payload.get("semantic_forms") if isinstance(payload.get("semantic_forms"), list) else []
    secondary_entities = payload.get("secondary_entities") if isinstance(payload.get("secondary_entities"), list) else []
    selected_rows = payload.get("selected_rows") if isinstance(payload.get("selected_rows"), list) else []
    normalized = {
        "page_kind": _sanitize_line(str(payload.get("page_kind") or "unknown"), max_length=48) or "unknown",
        "primary_entity": _normalize_semantic_entity(
            payload.get("primary_entity") if isinstance(payload.get("primary_entity"), dict) else {}
        ),
        "secondary_entities": [],
        "visible_sections": [],
        "semantic_actions": [],
        "semantic_forms": [],
        "active_dialog": sanitize_json_value(
            payload.get("active_dialog") if isinstance(payload.get("active_dialog"), dict) else {}
        ),
        "selected_rows": [],
        "summary": sanitize_text(str(payload.get("summary") or ""), max_length=240) or None,
    }
    for item in secondary_entities[:12]:
        normalized_item = _normalize_semantic_entity(item if isinstance(item, dict) else {})
        if normalized_item:
            normalized["secondary_entities"].append(normalized_item)
    for item in sections[:12]:
        normalized_item = _normalize_semantic_section(item if isinstance(item, dict) else {})
        if normalized_item:
            normalized["visible_sections"].append(normalized_item)
    for item in semantic_actions[:32]:
        normalized_item = _normalize_semantic_action(item if isinstance(item, dict) else {})
        if normalized_item:
            normalized["semantic_actions"].append(normalized_item)
    for item in semantic_forms[:12]:
        normalized_item = _normalize_semantic_form(item if isinstance(item, dict) else {})
        if normalized_item:
            normalized["semantic_forms"].append(normalized_item)
    for item in selected_rows[:8]:
        normalized_item = _normalize_semantic_entity(item if isinstance(item, dict) else {})
        if normalized_item:
            normalized["selected_rows"].append(normalized_item)
    return normalized


def _normalize_browser_context_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    return sanitize_browser_context_summary(summary)


def _normalize_browser_context(browser_context: dict[str, Any] | None) -> dict[str, Any]:
    payload = browser_context if isinstance(browser_context, dict) else {}
    query = payload.get("query") if isinstance(payload.get("query"), dict) else {}
    selected_entities = payload.get("selected_entities") if isinstance(payload.get("selected_entities"), list) else []
    open_panels = payload.get("open_panels") if isinstance(payload.get("open_panels"), list) else []
    forms = payload.get("forms") if isinstance(payload.get("forms"), list) else []
    visible_actions = payload.get("visible_actions") if isinstance(payload.get("visible_actions"), list) else []
    semantic_actions = payload.get("semantic_actions") if isinstance(payload.get("semantic_actions"), list) else []
    semantic_forms = payload.get("semantic_forms") if isinstance(payload.get("semantic_forms"), list) else []
    semantic_page_context = payload.get("semantic_page_context") if isinstance(payload.get("semantic_page_context"), dict) else {}
    summary_json = payload.get("summary_json") if isinstance(payload.get("summary_json"), dict) else {}
    dom_snapshot = payload.get("dom_snapshot") if isinstance(payload.get("dom_snapshot"), list) else []
    summary_json = payload.get("summary_json") if isinstance(payload.get("summary_json"), dict) else {}
    normalized = {
        "pathname": sanitize_text(str(payload.get("pathname") or "/"), max_length=255) or "/",
        "origin": sanitize_text(str(payload.get("origin") or ""), max_length=255, single_line=True) or None,
        "title": sanitize_text(str(payload.get("title") or ""), max_length=180) or None,
        "query": {str(key): sanitize_json_value(value) for key, value in list(query.items())[:12]},
        "asset_id": _sanitize_line(str(payload.get("asset_id") or ""), max_length=64) or None,
        "finding_id": _sanitize_line(str(payload.get("finding_id") or ""), max_length=64) or None,
        "task_id": _sanitize_line(str(payload.get("task_id") or ""), max_length=64) or None,
        "selected_entities": [],
        "open_panels": [],
        "forms": [],
        "visible_actions": [],
        "semantic_page_context": {},
        "semantic_actions": [],
        "semantic_forms": [],
        "summary_json": {},
        "dom_snapshot": [],
    }
    for item in selected_entities[:8]:
        if not isinstance(item, dict):
            continue
        normalized["selected_entities"].append(
            {
                "kind": _sanitize_line(str(item.get("kind") or "entity"), max_length=32) or "entity",
                "id": _sanitize_line(str(item.get("id") or ""), max_length=64) or None,
                "label": sanitize_text(str(item.get("label") or ""), max_length=120) or None,
                "source": _sanitize_line(str(item.get("source") or "browser"), max_length=32) or "browser",
            }
        )
    for item in open_panels[:6]:
        if not isinstance(item, dict):
            continue
        normalized["open_panels"].append(
            {
                "kind": _sanitize_line(str(item.get("kind") or "panel"), max_length=32) or "panel",
                "title": sanitize_text(str(item.get("title") or ""), max_length=120) or None,
                "node_id": _sanitize_line(str(item.get("node_id") or ""), max_length=64) or None,
            }
        )
    for item in forms[:6]:
        if not isinstance(item, dict):
            continue
        normalized["forms"].append(
            {
                "node_id": _sanitize_line(str(item.get("node_id") or ""), max_length=64) or None,
                "name": sanitize_text(str(item.get("name") or ""), max_length=120) or None,
                "fields": sanitize_json_value(item.get("fields") if isinstance(item.get("fields"), list) else [])[:8],
            }
        )
    for item in visible_actions[:20]:
        normalized_action = _normalize_browser_visible_action(item if isinstance(item, dict) else {})
        if normalized_action:
            normalized["visible_actions"].append(normalized_action)
    normalized["semantic_page_context"] = _normalize_semantic_page_context(semantic_page_context)
    if semantic_actions:
        for item in semantic_actions[:32]:
            normalized_action = _normalize_semantic_action(item if isinstance(item, dict) else {})
            if normalized_action:
                normalized["semantic_actions"].append(normalized_action)
    else:
        normalized["semantic_actions"] = sanitize_json_value(
            normalized["semantic_page_context"].get("semantic_actions")
            if isinstance(normalized["semantic_page_context"], dict)
            else []
        )
    if semantic_forms:
        for item in semantic_forms[:12]:
            normalized_form = _normalize_semantic_form(item if isinstance(item, dict) else {})
            if normalized_form:
                normalized["semantic_forms"].append(normalized_form)
    else:
        normalized["semantic_forms"] = sanitize_json_value(
            normalized["semantic_page_context"].get("semantic_forms")
            if isinstance(normalized["semantic_page_context"], dict)
            else []
        )
    normalized["summary_json"] = _normalize_browser_context_summary(summary_json)
    for item in dom_snapshot[:80]:
        normalized_node = _normalize_browser_dom_node(item if isinstance(item, dict) else {})
        if normalized_node:
            normalized["dom_snapshot"].append(normalized_node)
    return normalized


def _page_context_from_browser_context(browser_context: dict[str, Any]) -> dict[str, Any]:
    return _normalize_page_context(
        {
            "pathname": browser_context.get("pathname"),
            "query": browser_context.get("query"),
            "asset_id": browser_context.get("asset_id"),
            "finding_id": browser_context.get("finding_id"),
            "task_id": browser_context.get("task_id"),
        }
    )


def _normalize_ui_action(action: dict[str, Any] | None) -> dict[str, Any]:
    payload = action if isinstance(action, dict) else {}
    action_type = _sanitize_line(str(payload.get("action_type") or ""), max_length=32).lower()
    if action_type not in SUPPORTED_UI_ACTIONS:
        return {}
    try:
        normalized = _UIAction.model_validate(
            {
                "action_id": payload.get("action_id") or f"ui-{uuid4().hex[:12]}",
                "action_type": action_type,
                "semantic_action_id": _sanitize_line(str(payload.get("semantic_action_id") or ""), max_length=128) or None,
                "target_node_id": _sanitize_line(str(payload.get("target_node_id") or ""), max_length=64) or None,
                "selector": sanitize_text(str(payload.get("selector") or ""), max_length=180, single_line=True) or None,
                "text_contains": sanitize_text(str(payload.get("text_contains") or ""), max_length=120) or None,
                "label_contains": sanitize_text(str(payload.get("label_contains") or ""), max_length=120) or None,
                "href": sanitize_text(str(payload.get("href") or ""), max_length=255, single_line=True) or None,
                "value": sanitize_text(str(payload.get("value") or ""), max_length=255) or None,
                "field_name": _sanitize_line(str(payload.get("field_name") or ""), max_length=64) or None,
                "option_label": sanitize_text(str(payload.get("option_label") or ""), max_length=120) or None,
                "wait_ms": max(100, min(int(payload.get("wait_ms") or 450), 5_000)),
                "rationale": sanitize_text(str(payload.get("rationale") or ""), max_length=180) or None,
                "expected_outcome": sanitize_text(str(payload.get("expected_outcome") or ""), max_length=180) or None,
                "expected_page_kind": _sanitize_line(str(payload.get("expected_page_kind") or ""), max_length=48) or None,
                "expected_section": _sanitize_line(str(payload.get("expected_section") or ""), max_length=96) or None,
                "expected_entity": _normalize_semantic_entity(
                    payload.get("expected_entity") if isinstance(payload.get("expected_entity"), dict) else {}
                ),
                "retryable": False if payload.get("retryable") is False else True,
            }
        )
    except (ValidationError, ValueError, TypeError):
        return {}
    return normalized.model_dump(mode="json")


def _normalize_ui_action_results(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in results[:12]:
        if not isinstance(item, dict):
            continue
        action_type = _sanitize_line(str(item.get("action_type") or ""), max_length=32).lower()
        if action_type not in SUPPORTED_UI_ACTIONS:
            continue
        normalized.append(
            {
                "action_id": _sanitize_line(str(item.get("action_id") or ""), max_length=64),
                "action_type": action_type,
                "ok": bool(item.get("ok")),
                "semantic_action_id": _sanitize_line(str(item.get("semantic_action_id") or ""), max_length=128) or None,
                "target_node_id": _sanitize_line(str(item.get("target_node_id") or ""), max_length=64) or None,
                "resolved_node_id": _sanitize_line(str(item.get("resolved_node_id") or ""), max_length=64) or None,
                "message": sanitize_text(str(item.get("message") or ""), max_length=220) or None,
                "resolved_target": sanitize_json_value(
                    item.get("resolved_target") if isinstance(item.get("resolved_target"), dict) else {}
                ),
                "attempt_count": max(1, min(int(item.get("attempt_count") or 1), 4)),
                "detail_json": sanitize_json_value(item.get("detail_json") if isinstance(item.get("detail_json"), dict) else {}),
            }
        )
    return normalized


def _normalize_pending_secure_input(payload: dict[str, Any] | None) -> dict[str, Any]:
    raw = payload if isinstance(payload, dict) else {}
    asset_ids: list[str] = []
    seen_asset_ids: set[str] = set()
    if raw.get("asset_id"):
        normalized_asset_id = _sanitize_line(str(raw.get("asset_id") or ""), max_length=64)
        if normalized_asset_id:
            asset_ids.append(normalized_asset_id)
            seen_asset_ids.add(normalized_asset_id)
    raw_asset_ids = raw.get("asset_ids") if isinstance(raw.get("asset_ids"), list) else []
    for item in raw_asset_ids[:20]:
        normalized_asset_id = _sanitize_line(str(item or ""), max_length=64)
        if not normalized_asset_id or normalized_asset_id in seen_asset_ids:
            continue
        seen_asset_ids.add(normalized_asset_id)
        asset_ids.append(normalized_asset_id)

    if not asset_ids:
        return {}

    raw_labels = raw.get("asset_labels") if isinstance(raw.get("asset_labels"), list) else []
    asset_labels: list[str] = []
    for index, asset_id in enumerate(asset_ids):
        label = sanitize_text(str(raw_labels[index] or ""), max_length=160) if index < len(raw_labels) else None
        asset_labels.append(label or f"资产 {asset_id}")

    auth_type = _sanitize_line(str(raw.get("auth_type") or ""), max_length=16)
    if auth_type not in {"password", "key"}:
        auth_type = None
    mode = _sanitize_line(str(raw.get("mode") or ""), max_length=32)
    if mode not in {"single_asset", "batch_choice", "same_credential_batch", "per_asset_guided"}:
        mode = "single_asset" if len(asset_ids) == 1 else "batch_choice"

    resume_action = raw.get("resume_action") if isinstance(raw.get("resume_action"), dict) else {}
    normalized_resume_action = {}
    resume_action_type = _sanitize_line(str(resume_action.get("action_type") or ""), max_length=64)
    if resume_action_type in SUPPORTED_WRITE_ACTIONS and resume_action_type != "configure_ssh_credential":
        normalized_resume_action = {
            "action_type": resume_action_type,
            "title": sanitize_text(str(resume_action.get("title") or resume_action_type), max_length=120) or resume_action_type,
            "reason": sanitize_text(str(resume_action.get("reason") or ""), max_length=240) or "",
            "params": sanitize_json_value(resume_action.get("params") if isinstance(resume_action.get("params"), dict) else {}),
        }

    return {
        "kind": "ssh_credential",
        "mode": mode,
        "asset_ids": asset_ids,
        "asset_labels": asset_labels,
        "auth_type": auth_type,
        "username": sanitize_text(str(raw.get("username") or ""), max_length=128, single_line=True) or None,
        "resume_goal_id": _sanitize_line(str(raw.get("resume_goal_id") or ""), max_length=64) or None,
        "resume_action": normalized_resume_action,
        "auto_verify": False if raw.get("auto_verify") is False else True,
        "auto_resume": False if raw.get("auto_resume") is False else True,
        "blocker_summary": sanitize_text(str(raw.get("blocker_summary") or ""), max_length=240) or None,
    }


def _normalize_browser_runtime(browser_runtime: dict[str, Any] | None) -> dict[str, Any]:
    payload = browser_runtime if isinstance(browser_runtime, dict) else {}
    pending_ui_actions = payload.get("pending_ui_actions") if isinstance(payload.get("pending_ui_actions"), list) else []
    completed_ui_actions = payload.get("completed_ui_actions") if isinstance(payload.get("completed_ui_actions"), list) else []
    auto_executed_actions = payload.get("auto_executed_actions") if isinstance(payload.get("auto_executed_actions"), list) else []
    last_ui_results = payload.get("last_ui_results") if isinstance(payload.get("last_ui_results"), list) else []
    pending_secure_input = _normalize_pending_secure_input(
        payload.get("pending_secure_input") if isinstance(payload.get("pending_secure_input"), dict) else {}
    )
    normalized_pending_actions = []
    for item in pending_ui_actions[:MAX_UI_ACTION_BATCH]:
        normalized_action = _normalize_ui_action(item if isinstance(item, dict) else {})
        if normalized_action:
            normalized_pending_actions.append(normalized_action)
    return {
        "phase": _sanitize_line(str(payload.get("phase") or ""), max_length=48) or "idle",
        "step_count": max(0, min(int(payload.get("step_count") or 0), MAX_AGENT_LOOP_STEPS)),
        "current_objective": sanitize_text(str(payload.get("current_objective") or ""), max_length=240) or None,
        "objective_kind": _sanitize_line(str(payload.get("objective_kind") or ""), max_length=32) or None,
        "planned_steps": sanitize_json_value(payload.get("planned_steps") if isinstance(payload.get("planned_steps"), list) else [])[:12],
        "step_cursor": max(0, min(int(payload.get("step_cursor") or 0), MAX_AGENT_LOOP_STEPS)),
        "pending_ui_actions": normalized_pending_actions,
        "completed_ui_actions": _normalize_ui_action_results(completed_ui_actions),
        "last_ui_results": _normalize_ui_action_results(last_ui_results),
        "pending_secure_input": pending_secure_input,
        "auto_executed_actions": sanitize_json_value(auto_executed_actions) if auto_executed_actions else [],
        "last_browser_context": _normalize_browser_context(
            payload.get("last_browser_context") if isinstance(payload.get("last_browser_context"), dict) else {}
        ),
        "semantic_page_context": _normalize_semantic_page_context(
            payload.get("semantic_page_context") if isinstance(payload.get("semantic_page_context"), dict) else {}
        ),
        "retry_state": sanitize_json_value(payload.get("retry_state") if isinstance(payload.get("retry_state"), dict) else {}),
        "last_user_intent": sanitize_text(str(payload.get("last_user_intent") or ""), max_length=240) or None,
        "last_error": sanitize_text(str(payload.get("last_error") or ""), max_length=240) or None,
        "current_message_request_id": _sanitize_line(str(payload.get("current_message_request_id") or ""), max_length=128) or None,
        "message_pending_since": _to_runtime_timestamp(_parse_runtime_timestamp(payload.get("message_pending_since"))),
        "last_message_request_id": _sanitize_line(str(payload.get("last_message_request_id") or ""), max_length=128) or None,
        "last_message_ack_at": _to_runtime_timestamp(_parse_runtime_timestamp(payload.get("last_message_ack_at"))),
        "ui_pending_since": _to_runtime_timestamp(_parse_runtime_timestamp(payload.get("ui_pending_since"))),
        "last_step_request_id": _sanitize_line(str(payload.get("last_step_request_id") or ""), max_length=128) or None,
        "last_step_ack_at": _to_runtime_timestamp(_parse_runtime_timestamp(payload.get("last_step_ack_at"))),
    }

def _working_context_summary(context: dict[str, Any]) -> str | None:
    finding_id = _sanitize_line(str(context.get("finding_id") or ""), max_length=64)
    asset_id = _sanitize_line(str(context.get("asset_id") or ""), max_length=64)
    task_id = _sanitize_line(str(context.get("task_id") or ""), max_length=64)
    if finding_id and asset_id:
        return f"风险 {finding_id}（资产 {asset_id}）"
    if finding_id:
        return f"风险 {finding_id}"
    if asset_id:
        return f"资产 {asset_id}"
    if task_id:
        return f"任务 {task_id}"
    return None


def _normalize_focus_target(target: dict[str, Any] | None) -> dict[str, Any]:
    payload = target if isinstance(target, dict) else {}
    normalized = {
        "asset_id": sanitize_text(str(payload.get("asset_id") or ""), max_length=64) or None,
        "finding_id": sanitize_text(str(payload.get("finding_id") or ""), max_length=64) or None,
        "task_id": sanitize_text(str(payload.get("task_id") or ""), max_length=64) or None,
        "source": sanitize_text(str(payload.get("source") or ""), max_length=64) or None,
        "summary": sanitize_text(str(payload.get("summary") or ""), max_length=255) or None,
    }
    if not any(normalized.get(key) for key in ("asset_id", "finding_id", "task_id")):
        return {}
    if normalized["finding_id"]:
        normalized["target_type"] = "finding"
    elif normalized["asset_id"]:
        normalized["target_type"] = "asset"
    else:
        normalized["target_type"] = "task"
    if not normalized["summary"]:
        normalized["summary"] = _working_context_summary(normalized)
    if not normalized["source"]:
        normalized["source"] = "session"
    return normalized


def _normalize_recent_targets(targets: Any) -> list[dict[str, Any]]:
    if not isinstance(targets, list):
        return []
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in targets:
        candidate = _normalize_focus_target(item if isinstance(item, dict) else {})
        if not candidate:
            continue
        signature = _context_target_signature(candidate)
        if signature in seen:
            continue
        seen.add(signature)
        normalized.append(candidate)
        if len(normalized) >= 6:
            break
    return normalized


def _normalize_working_context(working_context: dict[str, Any] | None) -> dict[str, Any]:
    payload = working_context if isinstance(working_context, dict) else {}
    primary_target = _normalize_focus_target(payload.get("primary_target") if isinstance(payload.get("primary_target"), dict) else {})
    if not primary_target:
        primary_target = _normalize_focus_target(payload)
    recent_targets = _normalize_recent_targets(payload.get("recent_targets"))
    if not primary_target and recent_targets:
        primary_target = recent_targets[0]
    if primary_target:
        primary_signature = _context_target_signature(primary_target)
        recent_targets = [primary_target] + [
            item for item in recent_targets if _context_target_signature(item) != primary_signature
        ]
    if not primary_target and not recent_targets:
        return {}
    source = sanitize_text(str(payload.get("source") or ""), max_length=64) or (
        primary_target.get("source") if primary_target else None
    )
    summary = sanitize_text(str(payload.get("summary") or ""), max_length=255) or (
        primary_target.get("summary") if primary_target else None
    )
    normalized = {
        "asset_id": primary_target.get("asset_id") if primary_target else None,
        "finding_id": primary_target.get("finding_id") if primary_target else None,
        "task_id": primary_target.get("task_id") if primary_target else None,
        "source": source or "session",
        "summary": summary or _working_context_summary(primary_target or recent_targets[0]),
        "primary_target": primary_target or recent_targets[0],
        "recent_targets": recent_targets[:6],
    }
    return normalized


def _has_object_target(context: dict[str, Any] | None) -> bool:
    payload = context if isinstance(context, dict) else {}
    return any(payload.get(key) for key in ("asset_id", "finding_id", "task_id"))


def _context_target_signature(context: dict[str, Any] | None) -> tuple[str, str, str]:
    payload = context if isinstance(context, dict) else {}
    return (
        str(payload.get("asset_id") or "").strip(),
        str(payload.get("finding_id") or "").strip(),
        str(payload.get("task_id") or "").strip(),
    )


def _working_context_primary_target(context: dict[str, Any] | None) -> dict[str, Any]:
    payload = context if isinstance(context, dict) else {}
    primary_target = payload.get("primary_target") if isinstance(payload.get("primary_target"), dict) else {}
    normalized = _normalize_focus_target(primary_target)
    if normalized:
        return normalized
    return _normalize_focus_target(payload)


def _canonicalize_working_context_asset_targets(
    db: Session,
    working_context: dict[str, Any] | None,
) -> dict[str, Any]:
    normalized = _normalize_working_context(working_context)
    if not normalized:
        return {}

    primary_target = _working_context_primary_target(normalized)
    asset_reference = _sanitize_line(
        str(primary_target.get("asset_id") or normalized.get("asset_id") or ""),
        max_length=96,
    )
    if not asset_reference:
        return normalized

    asset = _resolve_asset_for_read_tool(db, asset_reference)
    if asset is None:
        return normalized

    asset_display = str(getattr(asset, "ip", None) or getattr(asset, "hostname", None) or asset.id)
    canonical_summary = f"资产 {asset_display}"

    def _canonicalize_target(target: dict[str, Any]) -> dict[str, Any]:
        candidate = _normalize_focus_target(target)
        if not candidate:
            return {}
        if str(candidate.get("asset_id") or "").strip() != asset_reference:
            return candidate
        if not candidate.get("summary") or candidate.get("summary") == f"资产 {asset_reference}":
            candidate["summary"] = canonical_summary
        candidate["asset_id"] = asset.id
        candidate["target_type"] = "asset"
        return candidate

    canonical_primary = _canonicalize_target(primary_target) or primary_target
    canonical_recent: list[dict[str, Any]] = []
    for item in _normalize_recent_targets(normalized.get("recent_targets")):
        canonical_item = _canonicalize_target(item) or item
        canonical_recent.append(canonical_item)

    payload = {
        **normalized,
        "asset_id": asset.id,
        "primary_target": canonical_primary,
        "recent_targets": canonical_recent,
    }
    if not payload.get("summary") or payload.get("summary") == f"资产 {asset_reference}":
        payload["summary"] = canonical_summary
    return _normalize_working_context(payload)


def _merge_soft_focus_context(
    current_context: dict[str, Any] | None,
    next_target: dict[str, Any] | None,
) -> dict[str, Any]:
    current = _normalize_working_context(current_context)
    target = _normalize_focus_target(next_target)
    if not target:
        return current
    recent_targets = [target]
    seen = {_context_target_signature(target)}
    for item in current.get("recent_targets", []):
        if not isinstance(item, dict):
            continue
        normalized_item = _normalize_focus_target(item)
        if not normalized_item:
            continue
        signature = _context_target_signature(normalized_item)
        if signature in seen:
            continue
        seen.add(signature)
        recent_targets.append(normalized_item)
        if len(recent_targets) >= 6:
            break
    return _normalize_working_context(
        {
            "asset_id": target.get("asset_id"),
            "finding_id": target.get("finding_id"),
            "task_id": target.get("task_id"),
            "source": target.get("source") or current.get("source") or "session",
            "summary": target.get("summary"),
            "primary_target": target,
            "recent_targets": recent_targets,
        }
    )


def _read_tool_call_signature(tool_name: str, arguments: dict[str, Any]) -> tuple[str, str]:
    return (
        _sanitize_line(tool_name, max_length=64),
        json.dumps(sanitize_json_value(arguments), ensure_ascii=False, sort_keys=True),
    )


def _dedupe_read_tool_payloads(read_tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in read_tool_calls:
        if not isinstance(item, dict):
            continue
        tool_name = _sanitize_line(str(item.get("tool_name") or ""), max_length=64)
        arguments = item.get("arguments") if isinstance(item.get("arguments"), dict) else {}
        if tool_name not in SUPPORTED_READ_TOOLS:
            continue
        signature = _read_tool_call_signature(tool_name, arguments)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(
            {
                "tool_name": tool_name,
                "arguments": sanitize_json_value(arguments),
            }
        )
        if len(deduped) >= 3:
            break
    return deduped


def _default_resume_read_tools(
    *,
    kind: str,
    working_context: dict[str, Any],
) -> list[dict[str, Any]]:
    normalized_context = _normalize_working_context(working_context)
    primary_target = _working_context_primary_target(normalized_context)
    asset_id = _sanitize_line(str(primary_target.get("asset_id") or normalized_context.get("asset_id") or ""), max_length=64)
    finding_id = _sanitize_line(str(primary_target.get("finding_id") or normalized_context.get("finding_id") or ""), max_length=64)
    task_id = _sanitize_line(str(primary_target.get("task_id") or normalized_context.get("task_id") or ""), max_length=64)
    read_tool_calls: list[dict[str, Any]] = []

    if kind == "post_scan_analysis" and task_id:
        read_tool_calls.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
        read_tool_calls.append({"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 12}})
        return _dedupe_read_tool_payloads(read_tool_calls)

    if kind == "post_verify_analysis" and asset_id:
        read_tool_calls.append({"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "limit": 10}})
        if task_id:
            read_tool_calls.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
        return _dedupe_read_tool_payloads(read_tool_calls)

    if kind in {
        "post_remediation_review",
        "post_remediation_status",
        "post_remediation_gap_analysis",
        "post_remediation_failure_analysis",
    } and asset_id:
        read_tool_calls.append({"tool_name": "get_remediation_asset", "arguments": {"asset_id": asset_id}})
        if task_id:
            read_tool_calls.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
        return _dedupe_read_tool_payloads(read_tool_calls)

    if task_id:
        read_tool_calls.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
        read_tool_calls.append({"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 12}})
    elif finding_id:
        read_tool_calls.append({"tool_name": "get_risk_detail", "arguments": {"finding_id": finding_id}})
        if asset_id:
            read_tool_calls.append({"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "limit": 10}})
    elif asset_id:
        read_tool_calls.append({"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "limit": 10}})
        read_tool_calls.append({"tool_name": "get_asset_detail", "arguments": {"asset_id": asset_id}})

    return _dedupe_read_tool_payloads(read_tool_calls)


def _normalize_resume_hint(hint: dict[str, Any] | None) -> dict[str, Any]:
    payload = hint if isinstance(hint, dict) else {}
    kind = _sanitize_line(str(payload.get("kind") or ""), max_length=64)
    goal_id = _sanitize_line(str(payload.get("goal_id") or ""), max_length=64) or None
    working_context = _normalize_working_context(
        payload.get("working_context") if isinstance(payload.get("working_context"), dict) else {}
    )
    preferred_read_tools = _dedupe_read_tool_payloads(
        payload.get("preferred_read_tools") if isinstance(payload.get("preferred_read_tools"), list) else []
    )
    if not preferred_read_tools and (kind or working_context):
        preferred_read_tools = _default_resume_read_tools(kind=kind, working_context=working_context)
    suggested_reply_label = sanitize_text(str(payload.get("suggested_reply_label") or ""), max_length=80, single_line=True) or None

    normalized: dict[str, Any] = {}
    if kind:
        normalized["kind"] = kind
    if goal_id:
        normalized["goal_id"] = goal_id
    if working_context:
        normalized["working_context"] = working_context
    if preferred_read_tools:
        normalized["preferred_read_tools"] = preferred_read_tools
    if suggested_reply_label:
        normalized["suggested_reply_label"] = suggested_reply_label
    return normalized


def _latest_resume_hint(session: AgentSession | Any | None) -> dict[str, Any]:
    if session is None:
        return {}
    messages = list(getattr(session, "messages", []) or [])
    for item in reversed(messages[-16:]):
        payload = getattr(item, "payload_json", None)
        if not isinstance(payload, dict):
            continue
        normalized = _normalize_resume_hint(payload.get("resume_hint") if isinstance(payload.get("resume_hint"), dict) else {})
        if normalized:
            return normalized
    return {}


def _should_skip_preflight_clarification(
    content: str,
    *,
    session: AgentSession | Any | None,
) -> bool:
    return _content_prefers_resume_hint_read(content, recent_resume_hint=_latest_resume_hint(session))


def _build_working_context_from_page_context(page_context: dict[str, Any], *, source: str) -> dict[str, Any]:
    candidate = {
        "asset_id": page_context.get("asset_id"),
        "finding_id": page_context.get("finding_id"),
        "task_id": page_context.get("task_id"),
        "source": source,
    }
    return _normalize_focus_target(candidate)


def _build_working_context_from_semantic_entity(entity: dict[str, Any], *, source: str) -> dict[str, Any]:
    normalized_entity = _normalize_semantic_entity(entity if isinstance(entity, dict) else {})
    if not normalized_entity:
        return {}
    meta = normalized_entity.get("meta") if isinstance(normalized_entity.get("meta"), dict) else {}
    kind = str(normalized_entity.get("kind") or "").strip().lower()
    entity_id = _sanitize_line(str(normalized_entity.get("id") or ""), max_length=96) or None
    asset_id = _sanitize_line(str(meta.get("asset_id") or ""), max_length=64) or None
    finding_id = _sanitize_line(str(meta.get("finding_id") or ""), max_length=64) or None
    task_id = _sanitize_line(str(meta.get("task_id") or ""), max_length=64) or None

    if kind in {"finding", "risk"}:
        finding_id = finding_id or entity_id
    elif kind in {"task", "task_run"}:
        task_id = task_id or entity_id
        if str(meta.get("scope_type") or "").strip().lower() == "asset":
            asset_id = asset_id or (_sanitize_line(str(meta.get("scope_id") or ""), max_length=64) or None)
    elif kind in {"asset", "host", "server", "device"}:
        asset_id = asset_id or entity_id

    return _normalize_focus_target(
        {
            "asset_id": asset_id,
            "finding_id": finding_id,
            "task_id": task_id,
            "source": source,
            "summary": normalized_entity.get("label"),
        }
    )


def _build_working_context_from_browser_context(browser_context: dict[str, Any], *, source: str) -> dict[str, Any]:
    direct_target = _build_working_context_from_page_context(browser_context, source=source)
    if _has_object_target(direct_target):
        return direct_target

    semantic_page_context = _browser_semantic_page_context(browser_context)
    primary_entity = semantic_page_context.get("primary_entity") if isinstance(semantic_page_context, dict) else {}
    semantic_target = _build_working_context_from_semantic_entity(primary_entity, source=source)
    if _has_object_target(semantic_target):
        return semantic_target

    selected_entities = browser_context.get("selected_entities") if isinstance(browser_context.get("selected_entities"), list) else []
    for item in selected_entities[:3]:
        candidate = _build_working_context_from_semantic_entity(item if isinstance(item, dict) else {}, source=source)
        if _has_object_target(candidate):
            return candidate
    return {}


def _extract_target_from_patterns(content: str) -> dict[str, Any]:
    normalized = sanitize_text(content, max_length=500, single_line=True) or ""
    patterns = [
        ("finding_id", r"(?:finding|风险)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})"),
        ("asset_id", r"(?:asset|资产|主机)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})"),
        ("task_id", r"(?:task|任务)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})"),
    ]
    extracted: dict[str, Any] = {}
    for field, pattern in patterns:
        match = re.search(pattern, normalized, re.IGNORECASE)
        if match:
            extracted[field] = match.group(1)
    if not extracted:
        asset_match = re.search(r"/(?:assets|remediation)/([A-Za-z0-9][A-Za-z0-9._-]{1,63})", normalized)
        task_match = re.search(r"/tasks/([A-Za-z0-9][A-Za-z0-9._-]{1,63})", normalized)
        if asset_match:
            extracted["asset_id"] = asset_match.group(1)
        if task_match:
            extracted["task_id"] = task_match.group(1)
    if extracted:
        extracted["source"] = "message_explicit"
    return _normalize_focus_target(extracted)


def _extract_explicit_working_context(content: str, page_context: dict[str, Any]) -> dict[str, Any]:
    explicit = _extract_target_from_patterns(content)
    if explicit:
        return explicit
    for field in ("finding_id", "asset_id", "task_id"):
        candidate = _sanitize_line(str(page_context.get(field) or ""), max_length=64)
        if candidate and candidate in content:
            return _build_working_context_from_page_context(page_context, source="message_page_target")
    return {}


def _agent_target_summary(target: dict[str, Any] | None) -> str | None:
    payload = target if isinstance(target, dict) else {}
    finding_id = _sanitize_line(str(payload.get("finding_id") or ""), max_length=64)
    asset_id = _sanitize_line(str(payload.get("asset_id") or ""), max_length=64)
    task_id = _sanitize_line(str(payload.get("task_id") or ""), max_length=64)
    session_id = _sanitize_line(str(payload.get("session_id") or ""), max_length=64)
    cidr_value = _extract_cidr_target(str(payload.get("cidr") or ""))
    if finding_id and asset_id:
        return f"风险 {finding_id} / 资产 {asset_id}"
    if finding_id:
        return f"风险 {finding_id}"
    if asset_id:
        return f"资产 {asset_id}"
    if task_id:
        return f"任务 {task_id}"
    if session_id:
        return f"修复会话 {session_id}"
    if cidr_value:
        return f"网段 {cidr_value}"
    return None


def _normalize_agent_focus_target(target: dict[str, Any] | None) -> dict[str, Any]:
    payload = target if isinstance(target, dict) else {}
    normalized = {
        "asset_id": _sanitize_line(str(payload.get("asset_id") or ""), max_length=64) or None,
        "finding_id": _sanitize_line(str(payload.get("finding_id") or ""), max_length=64) or None,
        "task_id": _sanitize_line(str(payload.get("task_id") or ""), max_length=64) or None,
        "session_id": _sanitize_line(str(payload.get("session_id") or ""), max_length=64) or None,
        "cidr": _extract_cidr_target(str(payload.get("cidr") or "")),
        "source": _sanitize_line(str(payload.get("source") or ""), max_length=64) or None,
        "summary": sanitize_text(str(payload.get("summary") or ""), max_length=255) or None,
    }
    if not any(normalized.get(key) for key in ("asset_id", "finding_id", "task_id", "session_id", "cidr")):
        return {}
    if normalized["finding_id"]:
        target_type = "finding"
    elif normalized["asset_id"]:
        target_type = "asset"
    elif normalized["task_id"]:
        target_type = "task"
    elif normalized["session_id"]:
        target_type = "session"
    else:
        target_type = "cidr"
    normalized["target_type"] = target_type
    normalized["summary"] = normalized["summary"] or _agent_target_summary(normalized)
    normalized["source"] = normalized["source"] or "session"
    return normalized


def _resolve_agent_focus(
    *,
    page_context: dict[str, Any] | None = None,
    browser_context: dict[str, Any] | None = None,
    working_context: dict[str, Any] | None = None,
    dialog_state: dict[str, Any] | None = None,
    user_content: str | None = None,
    fallback_watch_task_id: str | None = None,
) -> dict[str, Any]:
    candidates: list[tuple[dict[str, Any], str]] = []

    working_primary = _normalize_agent_focus_target(_working_context_primary_target(working_context))
    if working_primary:
        candidates.append((working_primary, "high"))

    browser_target = _normalize_agent_focus_target(_build_working_context_from_browser_context(browser_context or {}, source="browser_context"))
    if browser_target:
        candidates.append((browser_target, "high"))

    page_target = _normalize_agent_focus_target(_build_working_context_from_page_context(page_context or {}, source="page_context"))
    if page_target:
        candidates.append((page_target, "medium"))

    dialog_targets = _dialog_state_working_context(dialog_state)
    dialog_target = _normalize_agent_focus_target(_working_context_primary_target(dialog_targets))
    if dialog_target:
        candidates.append((dialog_target, "medium"))

    explicit_target = _normalize_agent_focus_target(_extract_target_from_patterns(str(user_content or "")))
    if explicit_target:
        candidates.append((explicit_target, "high"))

    cidr_value = _extract_cidr_target(str(user_content or ""))
    if cidr_value:
        candidates.append((_normalize_agent_focus_target({"cidr": cidr_value, "source": "user_text"}), "high"))

    if fallback_watch_task_id:
        candidates.append(
            (
                _normalize_agent_focus_target(
                    {
                        "task_id": fallback_watch_task_id,
                        "source": "task_watch",
                        "summary": f"任务 {fallback_watch_task_id}",
                    }
                ),
                "medium",
            )
        )

    for target, confidence in candidates:
        if not target:
            continue
        return {
            "summary": target.get("summary"),
            "focus_type": target.get("target_type"),
            "resolved": target,
            "confidence": confidence,
            "source": target.get("source"),
        }
    return {
        "summary": "当前会话",
        "focus_type": "session",
        "resolved": {},
        "confidence": "low",
        "source": "session",
    }


def _normalize_agent_state(payload: dict[str, Any] | None, *, last_task_id: str | None = None) -> dict[str, Any]:
    raw = payload if isinstance(payload, dict) else {}
    focus = raw.get("focus") if isinstance(raw.get("focus"), dict) else {}
    execution = raw.get("execution") if isinstance(raw.get("execution"), dict) else {}
    explanation = raw.get("explanation") if isinstance(raw.get("explanation"), dict) else {}
    watch = raw.get("watch") if isinstance(raw.get("watch"), dict) else {}

    normalized_focus = {
        "summary": sanitize_text(str(focus.get("summary") or ""), max_length=255) or None,
        "focus_type": _sanitize_line(str(focus.get("focus_type") or ""), max_length=32) or None,
        "resolved": sanitize_json_value(
            _normalize_agent_focus_target(focus.get("resolved") if isinstance(focus.get("resolved"), dict) else {})
        ),
        "confidence": _sanitize_line(str(focus.get("confidence") or ""), max_length=16) or None,
        "source": _sanitize_line(str(focus.get("source") or ""), max_length=64) or None,
    }
    if not normalized_focus["summary"] and isinstance(normalized_focus["resolved"], dict) and normalized_focus["resolved"]:
        normalized_focus["summary"] = normalized_focus["resolved"].get("summary")
        normalized_focus["focus_type"] = normalized_focus["focus_type"] or normalized_focus["resolved"].get("target_type")
        normalized_focus["source"] = normalized_focus["source"] or normalized_focus["resolved"].get("source")

    pending_ui_actions = execution.get("pending_ui_actions") if isinstance(execution.get("pending_ui_actions"), list) else []
    normalized_execution = {
        "stage": _sanitize_line(str(execution.get("stage") or ""), max_length=32) or "idle",
        "step_kind": _sanitize_line(str(execution.get("step_kind") or ""), max_length=32) or None,
        "step_label": sanitize_text(str(execution.get("step_label") or ""), max_length=160) or None,
        "waiting_for": sanitize_text(str(execution.get("waiting_for") or ""), max_length=200) or None,
        "missing_slots": [
            _sanitize_line(str(item or ""), max_length=64)
            for item in (execution.get("missing_slots") if isinstance(execution.get("missing_slots"), list) else [])
            if _sanitize_line(str(item or ""), max_length=64)
        ][:6],
        "pending_ui_actions": sanitize_json_value(pending_ui_actions[:6]),
    }

    evidence = explanation.get("evidence") if isinstance(explanation.get("evidence"), list) else []
    normalized_explanation = {
        "reason": sanitize_text(str(explanation.get("reason") or ""), max_length=280) or None,
        "decision_summary": sanitize_text(str(explanation.get("decision_summary") or ""), max_length=280) or None,
        "expected_outcome": sanitize_text(str(explanation.get("expected_outcome") or ""), max_length=280) or None,
        "next_step": sanitize_text(str(explanation.get("next_step") or ""), max_length=280) or None,
        "evidence": sanitize_json_value(evidence[:4]),
    }

    primary_task_id = _sanitize_line(str(watch.get("primary_task_id") or last_task_id or ""), max_length=64) or None
    related_task_ids = [
        _sanitize_line(str(item or ""), max_length=64)
        for item in (watch.get("related_task_ids") if isinstance(watch.get("related_task_ids"), list) else [])
        if _sanitize_line(str(item or ""), max_length=64)
    ][:6]
    if primary_task_id and primary_task_id not in related_task_ids:
        related_task_ids = [primary_task_id, *related_task_ids][:6]
    raw_watching = watch.get("watching")
    if isinstance(raw_watching, bool):
        normalized_watching = raw_watching
    else:
        normalized_watching = normalized_execution["stage"] == "watching_task" and bool(primary_task_id)
    normalized_watch = {
        "primary_task_id": primary_task_id,
        "related_task_ids": related_task_ids,
        "status": _sanitize_line(str(watch.get("status") or ""), max_length=32) or None,
        "watching": normalized_watching,
        "last_task_message": sanitize_text(str(watch.get("last_task_message") or ""), max_length=280) or None,
    }

    return {
        "focus": normalized_focus,
        "execution": normalized_execution,
        "explanation": normalized_explanation,
        "watch": normalized_watch,
    }


def _session_agent_state(session: AgentSession) -> dict[str, Any]:
    return _normalize_agent_state(
        session.agent_state_json if isinstance(getattr(session, "agent_state_json", None), dict) else {},
        last_task_id=_session_last_task_id(session),
    )


def _session_last_task_id(session: AgentSession | Any) -> str | None:
    return _sanitize_line(str(getattr(session, "last_task_id", "") or ""), max_length=64) or None


def _build_agent_state_delta(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for key in ("focus", "execution", "explanation", "watch"):
        if sanitize_json_value(previous.get(key)) != sanitize_json_value(current.get(key)):
            delta[key] = sanitize_json_value(current.get(key))
    return delta


def _apply_agent_state_patch(
    session: AgentSession,
    *,
    focus: dict[str, Any] | None = None,
    execution: dict[str, Any] | None = None,
    explanation: dict[str, Any] | None = None,
    watch: dict[str, Any] | None = None,
) -> dict[str, Any]:
    current = _session_agent_state(session)
    next_state = {
        "focus": {**(current.get("focus") if isinstance(current.get("focus"), dict) else {})},
        "execution": {**(current.get("execution") if isinstance(current.get("execution"), dict) else {})},
        "explanation": {**(current.get("explanation") if isinstance(current.get("explanation"), dict) else {})},
        "watch": {**(current.get("watch") if isinstance(current.get("watch"), dict) else {})},
    }
    if focus:
        next_state["focus"].update(sanitize_json_value(focus))
    if execution:
        next_state["execution"].update(sanitize_json_value(execution))
    if explanation:
        next_state["explanation"].update(sanitize_json_value(explanation))
    if watch:
        next_state["watch"].update(sanitize_json_value(watch))
    normalized = _normalize_agent_state(next_state, last_task_id=_session_last_task_id(session))
    session.agent_state_json = normalized
    return _build_agent_state_delta(current, normalized)


def _tool_trace_evidence(tool_traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in tool_traces[-4:]:
        if not isinstance(item, dict):
            continue
        tool_name = _sanitize_line(str(item.get("tool_name") or ""), max_length=64)
        if not tool_name:
            continue
        evidence.append(
            {
                "kind": "read_tool",
                "tool_name": tool_name,
                "ok": bool(item.get("ok")),
                "arguments": sanitize_json_value(item.get("arguments") if isinstance(item.get("arguments"), dict) else {}),
                "summary": sanitize_text(
                    str(item.get("error") or (item.get("result") if item.get("ok") else "")),
                    max_length=200,
                )
                or None,
            }
        )
    return evidence


def _collect_missing_slots(actions: list[dict[str, Any]]) -> list[str]:
    missing: list[str] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_type = _sanitize_line(str(action.get("action_type") or ""), max_length=64)
        params = action.get("params") if isinstance(action.get("params"), dict) else {}
        policy = ACTION_POLICY_REGISTRY.get(action_type) or {}
        for slot in policy.get("required_slots", []):
            normalized_slot = _sanitize_line(str(slot or ""), max_length=64)
            if not normalized_slot:
                continue
            value = params.get(normalized_slot)
            if normalized_slot == "cidr":
                if _extract_cidr_target(str(value or "")):
                    continue
            elif _sanitize_line(str(value or ""), max_length=64):
                continue
            if normalized_slot not in missing:
                missing.append(normalized_slot)
    return missing


def _plan_agent_step(
    *,
    decision: _AgentModelDecision,
    tool_traces: list[dict[str, Any]],
    normalized_ui_actions: list[dict[str, Any]],
    proposed_actions: list[dict[str, Any]],
    auto_execute_actions: list[dict[str, Any]],
    auto_execute_results: list[dict[str, Any]],
) -> _AgentStepPlan:
    evidence = _tool_trace_evidence(tool_traces)
    if decision.conversation_state == "clarifying":
        return _AgentStepPlan(
            step_kind="clarify",
            reason="当前目标缺少继续推进所需信息",
            waiting_for="等待用户补充目标对象或确认执行意图",
            next_step="收到补充后继续推进当前目标",
            expected_outcome="补齐缺失槽位并恢复执行",
            evidence=evidence,
        )
    if normalized_ui_actions:
        return _AgentStepPlan(
            step_kind="ui",
            reason="当前页面已有足够语义动作可直接推进",
            waiting_for="等待页面动作回执",
            next_step="收到 UI 回执后继续判断下一步",
            expected_outcome="完成站内跳转、展开、输入或提交",
            evidence=evidence,
        )
    if auto_execute_results or auto_execute_actions:
        child_task_ids = [
            _sanitize_line(str(item.get("child_task_id") or ""), max_length=64)
            for item in auto_execute_results
            if isinstance(item, dict)
        ]
        child_task_ids = [item for item in child_task_ids if item]
        return _AgentStepPlan(
            step_kind="watch_task" if child_task_ids else "auto_execute",
            reason="已识别到明确的低风险执行意图",
            waiting_for="等待后台任务完成" if child_task_ids else None,
            next_step="任务完成后自动回显结果" if child_task_ids else "已直接完成当前低风险动作",
            expected_outcome="启动并跟踪低风险动作结果",
            evidence=evidence,
        )
    if proposed_actions:
        return _AgentStepPlan(
            step_kind="propose_plan",
            reason="当前动作需要明确计划和人工确认",
            waiting_for="等待管理员确认执行",
            next_step="确认后进入后台编排执行",
            expected_outcome="形成结构化待确认计划",
            missing_slots=_collect_missing_slots(proposed_actions),
            evidence=evidence,
        )
    if tool_traces:
        return _AgentStepPlan(
            step_kind="answer",
            reason="已读取到当前对象或任务的最新平台数据",
            next_step="如需继续可直接追问或要求执行后续动作",
            expected_outcome="基于最新工具结果给出结论",
            evidence=evidence,
        )
    return _AgentStepPlan(
        step_kind="answer",
        reason="已完成当前轮次决策",
        next_step="如需继续可直接提出下一步目标",
        expected_outcome="返回最终答复",
        evidence=evidence,
    )


def _render_planned_step_content(
    plan: _AgentStepPlan,
    *,
    decision: _AgentModelDecision,
    fallback_content: str,
    ui_actions: list[dict[str, Any]],
    proposed_actions: list[dict[str, Any]],
) -> str:
    if plan.step_kind == "clarify":
        return _normalize_assistant_reply_content(decision.clarifying_question or fallback_content) or fallback_content
    if plan.step_kind == "ui":
        return (
            f"我将先在当前页面执行 {len(ui_actions)} 个站内动作：{_summarize_ui_actions(ui_actions)}。"
            if ui_actions
            else fallback_content
        )
    if plan.step_kind == "propose_plan":
        lines = ["我已经整理出待确认计划："]
        for item in proposed_actions[:4]:
            title = sanitize_text(str(item.get("title") or item.get("action_type") or "待执行动作"), max_length=120) or "待执行动作"
            reason = sanitize_text(str(item.get("reason") or ""), max_length=120) or ""
            lines.append(f"- {title}{f'：{reason}' if reason else ''}")
        lines.append("确认后我会开始执行，并持续回显进度。")
        return _normalize_assistant_reply_content("\n".join(lines)) or fallback_content
    return fallback_content


def _build_message_state_metadata(
    *,
    decision_summary: str | None,
    evidence: list[dict[str, Any]] | None,
    state_delta: dict[str, Any] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if decision_summary:
        payload["decision_summary"] = sanitize_text(decision_summary, max_length=280)
    if evidence:
        payload["evidence"] = sanitize_json_value(evidence[:4])
    if state_delta:
        payload["state_delta"] = sanitize_json_value(state_delta)
    return payload


def _normalize_dialog_state(dialog_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = dialog_state if isinstance(dialog_state, dict) else {}
    payload = _normalize_dialog_state_payload(payload)
    status_value = str(payload.get("status") or "").strip().lower() or "idle"
    if status_value != "awaiting_user_input":
        return {}
    try:
        state = _DialogState.model_validate(payload)
    except ValidationError:
        return {}
    normalized = state.model_dump(mode="json")
    normalized["candidate_write_context"] = sanitize_json_value(
        normalized.get("candidate_write_context") if isinstance(normalized.get("candidate_write_context"), dict) else {}
    )
    normalized["targets_snapshot"] = sanitize_json_value(
        normalized.get("targets_snapshot") if isinstance(normalized.get("targets_snapshot"), dict) else {}
    )
    normalized["expected_slots"] = [
        slot for slot in normalized.get("expected_slots", []) if slot in {"cidr", "asset_id", "finding_id", "task_id", "session_id"}
    ]
    read_tools: list[dict[str, Any]] = []
    for candidate in normalized.get("candidate_read_tools", []):
        if not isinstance(candidate, dict):
            continue
        try:
            read_tools.append(_ReadToolCall.model_validate(candidate).model_dump(mode="json"))
        except ValidationError:
            continue
        if len(read_tools) >= 3:
            break
    normalized["candidate_read_tools"] = read_tools
    return normalized


_DIALOG_STATE_INTENT_KIND_ALIASES = {
    "operate_low_risk": "prepare_plan",
    "operate_high_risk": "prepare_plan",
    "navigate": "read_followup",
    "inspect": "read_followup",
    "ask": "analyze",
    "answer": "analyze",
}


def _normalize_dialog_state_payload(dialog_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = sanitize_json_value(dialog_state if isinstance(dialog_state, dict) else {})
    if not isinstance(payload, dict):
        return {}
    normalized = dict(payload)
    intent_kind = str(normalized.get("intent_kind") or "").strip().lower()
    if intent_kind in _DIALOG_STATE_INTENT_KIND_ALIASES:
        normalized["intent_kind"] = _DIALOG_STATE_INTENT_KIND_ALIASES[intent_kind]
    return normalized


def _dialog_state_targets_snapshot(
    *,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
    extra_targets: dict[str, Any] | None = None,
) -> dict[str, Any]:
    snapshot = {
        "working_context": sanitize_json_value(working_context),
        "page_context": sanitize_json_value(_compact_page_context(page_context)),
    }
    extra = sanitize_json_value(extra_targets if isinstance(extra_targets, dict) else {})
    if isinstance(extra, dict) and extra:
        snapshot["extracted_values"] = extra
    return snapshot


def _dialog_state_expected_slots(question: str, user_content: str) -> list[str]:
    combined = f"{question}\n{user_content}".lower()
    slots: list[str] = []
    if "cidr" in combined or "网段" in combined:
        slots.append("cidr")
    if any(token in combined for token in ("资产 id", "asset id", "资产", "主机")) and any(
        token in combined for token in ("哪", "告诉", "处理", "修复", "继续")
    ):
        slots.append("asset_id")
    if any(token in combined for token in ("风险 id", "finding id", "风险", "finding")) and any(
        token in combined for token in ("哪", "告诉", "模板", "修复", "继续")
    ):
        slots.append("finding_id")
    if any(token in combined for token in ("任务 id", "task id", "任务")) and any(
        token in combined for token in ("哪", "告诉", "详情", "日志", "继续")
    ):
        slots.append("task_id")
    if "会话" in combined and any(token in combined for token in ("session", "会话 id", "session_id")):
        slots.append("session_id")
    deduped: list[str] = []
    for slot in slots:
        if slot not in deduped:
            deduped.append(slot)
    return deduped


def _dialog_state_question_kind(question: str) -> str:
    normalized = sanitize_text(question, max_length=500) or ""
    if any(marker in normalized for marker in ("是否", "要不要", "确认", "继续查看", "继续读取", "继续分析")):
        return "confirm"
    if any(marker in normalized for marker in ("哪一个", "哪台", "哪条", "哪个")):
        return "disambiguate"
    if any(marker in normalized for marker in ("请告诉", "缺少", "需要先知道", "请直接告诉", "还不知道")):
        return "slot_fill"
    return "followup"


def _dialog_state_intent_kind(question: str, user_content: str, candidate_read_tools: list[dict[str, Any]]) -> str:
    if candidate_read_tools:
        return "read_followup"
    if _contains_execution_intent(user_content):
        return "prepare_plan"
    expected_slots = _dialog_state_expected_slots(question, user_content)
    if expected_slots:
        return "fill_slot"
    return "analyze"


def _dialog_state_candidate_read_tools(
    question: str,
    *,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
) -> list[dict[str, Any]]:
    normalized = sanitize_text(question, max_length=500) or ""
    task_id = _sanitize_line(
        str(working_context.get("task_id") or page_context.get("task_id") or ""),
        max_length=64,
    )
    finding_id = _sanitize_line(
        str(working_context.get("finding_id") or page_context.get("finding_id") or ""),
        max_length=64,
    )
    asset_id = _sanitize_line(
        str(working_context.get("asset_id") or page_context.get("asset_id") or ""),
        max_length=64,
    )
    if task_id and "任务详情" in normalized:
        return [{"tool_name": "get_task_detail", "arguments": {"task_id": task_id}}]
    if task_id and any(marker in normalized for marker in ("任务事件", "事件日志", "任务日志")):
        return [{"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 10}}]
    if finding_id and "风险详情" in normalized:
        return [{"tool_name": "get_risk_detail", "arguments": {"finding_id": finding_id}}]
    if finding_id and any(marker in normalized for marker in ("修复模板", "模板", "修复方案")):
        return [{"tool_name": "get_risk_remediation_template", "arguments": {"finding_id": finding_id}}]
    if asset_id and any(marker in normalized for marker in ("修复摘要", "Runner", "修复状态")):
        return [{"tool_name": "get_remediation_asset", "arguments": {"asset_id": asset_id}}]
    return []


def _build_dialog_state(
    *,
    question: str,
    user_content: str,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
    candidate_read_tools: list[dict[str, Any]] | None = None,
    candidate_write_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    read_tools = candidate_read_tools or _dialog_state_candidate_read_tools(
        question,
        working_context=working_context,
        page_context=page_context,
    )
    intent_kind = _dialog_state_intent_kind(question, user_content, read_tools)
    expected_slots = _dialog_state_expected_slots(question, user_content)
    state = _DialogState(
        status="awaiting_user_input",
        intent_kind=intent_kind,  # type: ignore[arg-type]
        question_kind=_dialog_state_question_kind(question),  # type: ignore[arg-type]
        intent_summary=sanitize_text(user_content, max_length=300),
        last_agent_question=sanitize_text(question, max_length=500),
        expected_slots=expected_slots,
        candidate_read_tools=[_ReadToolCall.model_validate(item) for item in read_tools if isinstance(item, dict)],
        candidate_write_context=sanitize_json_value(candidate_write_context or {}),
        targets_snapshot=_dialog_state_targets_snapshot(
            working_context=working_context,
            page_context=page_context,
        ),
    )
    return state.model_dump(mode="json")


def _is_direct_agent_query(content: str) -> bool:
    normalized = (sanitize_text(content, max_length=300) or "").strip()
    identity_queries = ("你是谁", "你是干什么的", "你是什么", "介绍一下你自己", "介绍下你自己")
    capability_queries = ("你能做什么", "你可以做什么", "怎么用你", "如何使用你", "你会什么", "你能帮我做什么")
    return any(query in normalized for query in (*identity_queries, *capability_queries))


def _extract_followup_short_values(content: str, expected_slots: list[str]) -> dict[str, Any]:
    normalized = sanitize_text(content, max_length=300, single_line=True) or ""
    extracted: dict[str, Any] = {}
    explicit_target = _extract_target_from_patterns(normalized)
    for field in ("asset_id", "finding_id", "task_id"):
        if field in expected_slots and explicit_target.get(field):
            extracted[field] = explicit_target.get(field)
    if "cidr" in expected_slots:
        cidr = _extract_cidr_target(normalized)
        if cidr:
            extracted["cidr"] = cidr
    if "session_id" in expected_slots:
        session_match = re.search(r"(?:session|会话)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})", normalized, re.IGNORECASE)
        if session_match:
            extracted["session_id"] = session_match.group(1)
        elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", normalized):
            extracted["session_id"] = normalized
    for slot in expected_slots:
        if slot in extracted:
            continue
        if slot in {"asset_id", "finding_id", "task_id"} and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", normalized):
            extracted[slot] = normalized
    return sanitize_json_value(extracted) if extracted else {}


def _build_followup_hint(content: str, dialog_state: dict[str, Any]) -> dict[str, Any]:
    normalized = sanitize_text(content, max_length=300, single_line=True) or ""
    if not normalized:
        return {}
    if not dialog_state:
        if normalized in _SHORT_FOLLOWUP_AFFIRM_MARKERS:
            return {"reply_kind": "affirm", "raw_user_reply": normalized}
        if normalized in _SHORT_FOLLOWUP_DENY_MARKERS:
            return {"reply_kind": "deny", "raw_user_reply": normalized}
        return {}
    extracted_values = _extract_followup_short_values(
        normalized,
        dialog_state.get("expected_slots") if isinstance(dialog_state.get("expected_slots"), list) else [],
    )
    if normalized in _SHORT_FOLLOWUP_DENY_MARKERS:
        reply_kind = "deny"
    elif normalized in _SHORT_FOLLOWUP_AFFIRM_MARKERS:
        reply_kind = "affirm"
    elif extracted_values:
        reply_kind = "short_value"
    elif _is_direct_agent_query(normalized):
        reply_kind = "new_topic"
    elif (
        len(normalized) >= 8
        and (
            _extract_target_from_patterns(normalized)
            or _extract_cidr_target(normalized)
            or _contains_execution_intent(normalized)
            or any(marker in normalized for marker in ("帮我", "请", "分析", "查看", "扫描", "修复", "验证", "安装", "处理"))
        )
    ):
        reply_kind = "new_topic"
    else:
        reply_kind = "unknown"
    return {
        "reply_kind": reply_kind,
        "raw_user_reply": normalized,
        "pending_dialog_state": sanitize_json_value(dialog_state),
        "extracted_values": extracted_values,
    }


def _apply_followup_values_to_working_context(
    working_context: dict[str, Any],
    followup_hint: dict[str, Any],
    *,
    dialog_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    next_context = _normalize_working_context(working_context)
    reply_kind = str(followup_hint.get("reply_kind") or "").strip().lower()
    if dialog_state and reply_kind in {"affirm", "short_value", "unknown"}:
        targets_snapshot = dialog_state.get("targets_snapshot") if isinstance(dialog_state.get("targets_snapshot"), dict) else {}
        snapshot_context = _normalize_working_context(
            targets_snapshot.get("working_context") if isinstance(targets_snapshot.get("working_context"), dict) else {}
        )
        snapshot_target = _working_context_primary_target(snapshot_context)
        if snapshot_target:
            next_context = _merge_soft_focus_context(next_context, snapshot_target)
    extracted = followup_hint.get("extracted_values") if isinstance(followup_hint.get("extracted_values"), dict) else {}
    target = {
        "asset_id": extracted.get("asset_id"),
        "finding_id": extracted.get("finding_id"),
        "task_id": extracted.get("task_id"),
        "source": "dialog_followup",
    }
    if _has_object_target(target):
        return _merge_soft_focus_context(next_context, target)
    return next_context


def _serialize_proposed_actions(payload_json: dict[str, Any]) -> list[AgentProposedActionRead]:
    raw_items = payload_json.get("proposed_write_actions")
    if not isinstance(raw_items, list):
        return []
    actions: list[AgentProposedActionRead] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        action_type = str(item.get("action_type") or "").strip()
        if action_type not in SUPPORTED_WRITE_ACTIONS:
            continue
        try:
            actions.append(
                AgentProposedActionRead(
                    action_type=action_type,  # type: ignore[arg-type]
                    title=_sanitize_line(str(item.get("title") or action_type), max_length=120) or action_type,
                    reason=sanitize_text(str(item.get("reason") or ""), max_length=500) or "",
                    params=sanitize_json_value(item.get("params") if isinstance(item.get("params"), dict) else {}),
                )
            )
        except ValidationError:
            continue
    return actions


def _serialize_message(message: AgentMessage) -> AgentMessageRead:
    payload_json = message.payload_json if isinstance(message.payload_json, dict) else {}
    return AgentMessageRead(
        id=message.id,
        role=str(message.role or "assistant"),  # type: ignore[arg-type]
        message_type=str(message.message_type or "text"),
        content=message.content,
        payload_json=payload_json,
        created_at=message.created_at,
        proposed_write_actions=_serialize_proposed_actions(payload_json),
    )


def _action_type_to_skill_id(action_type: str | None) -> str | None:
    normalized = _sanitize_line(str(action_type or ""), max_length=64)
    return {
        "create_discovery_job": "scan_and_analyze_cidr",
        "verify_asset_risks": "verify_asset_risks",
        "install_runner": "install_runner",
        "create_or_resume_remediation_session": "start_remediation_session",
        "approve_remediation_session": "start_remediation_session",
        "configure_ssh_credential": "configure_ssh_credential",
    }.get(normalized)


def _derive_active_skill_id(session: AgentSession) -> str | None:
    runtime = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    pending_secure_input = runtime.get("pending_secure_input") if isinstance(runtime.get("pending_secure_input"), dict) else {}
    if pending_secure_input:
        return "configure_ssh_credential"

    current_goal = _session_goal(session)
    if current_goal is not None:
        goal_kind = _sanitize_line(str(current_goal.goal_kind or ""), max_length=128)
        if goal_kind and goal_kind != "general":
            return goal_kind
        progress_json = current_goal.progress_json if isinstance(current_goal.progress_json, dict) else {}
        progress_skill_id = _sanitize_line(str(progress_json.get("active_skill_id") or ""), max_length=128)
        if progress_skill_id:
            return progress_skill_id

    pending_plan = session.pending_plan_json if isinstance(session.pending_plan_json, dict) else {}
    proposed_actions = pending_plan.get("proposed_write_actions") if isinstance(pending_plan.get("proposed_write_actions"), list) else []
    for item in proposed_actions:
        if not isinstance(item, dict):
            continue
        skill_id = _action_type_to_skill_id(item.get("action_type"))
        if skill_id:
            return skill_id

    objective_kind = _sanitize_line(str(runtime.get("objective_kind") or ""), max_length=64)
    if objective_kind in {"navigate", "inspect"} and _sanitize_line(str(session.last_task_id or ""), max_length=64):
        return "resume_task_detail"
    if objective_kind in {"prepare_plan", "operate_high_risk"}:
        return "start_remediation_session"
    if objective_kind in {"operate_low_risk"}:
        auto_actions = runtime.get("auto_executed_actions") if isinstance(runtime.get("auto_executed_actions"), list) else []
        for item in auto_actions:
            if not isinstance(item, dict):
                continue
            skill_id = _action_type_to_skill_id(item.get("action_type"))
            if skill_id:
                return skill_id

    if _sanitize_line(str(session.last_task_id or ""), max_length=64):
        return "resume_task_detail"
    return None


def _runtime_watch_task_id(session: AgentSession) -> str | None:
    agent_state = session.agent_state_json if isinstance(session.agent_state_json, dict) else {}
    watch = agent_state.get("watch") if isinstance(agent_state.get("watch"), dict) else {}
    primary_task_id = _sanitize_line(str(watch.get("primary_task_id") or ""), max_length=64)
    if primary_task_id:
        return primary_task_id
    return _sanitize_line(str(session.last_task_id or ""), max_length=64) or None


def _runtime_blocker_summary(session: AgentSession, *, phase: str, recoverable_error: AgentRecoverableErrorRead | None) -> str | None:
    runtime = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    pending_secure_input = runtime.get("pending_secure_input") if isinstance(runtime.get("pending_secure_input"), dict) else {}
    if phase == "awaiting_secure_input" and pending_secure_input:
        return sanitize_text(
            str(pending_secure_input.get("blocker_summary") or "等待在安全弹层中填写 SSH 敏感信息"),
            max_length=280,
        ) or "等待在安全弹层中填写 SSH 敏感信息"

    current_goal = _session_goal(session)
    if current_goal is not None:
        blocked_reason = sanitize_text(str(current_goal.blocked_reason or ""), max_length=280) or None
        if blocked_reason:
            return blocked_reason
        progress_json = current_goal.progress_json if isinstance(current_goal.progress_json, dict) else {}
        blockers = progress_json.get("blockers") if isinstance(progress_json.get("blockers"), list) else []
        blocker_messages = [
            sanitize_text(str(item.get("blocker_message") if isinstance(item, dict) else item), max_length=180)
            for item in blockers
        ]
        blocker_messages = [item for item in blocker_messages if item]
        if blocker_messages:
            return "；".join(blocker_messages[:2])

    if recoverable_error is not None:
        return recoverable_error.message

    agent_state = session.agent_state_json if isinstance(session.agent_state_json, dict) else {}
    execution = agent_state.get("execution") if isinstance(agent_state.get("execution"), dict) else {}
    explanation = agent_state.get("explanation") if isinstance(agent_state.get("explanation"), dict) else {}
    waiting_for = sanitize_text(str(execution.get("waiting_for") or explanation.get("next_step") or ""), max_length=280) or None
    if waiting_for:
        return waiting_for
    if phase == "waiting_approval":
        return "等待管理员确认当前计划"
    if phase == "awaiting_ui_feedback":
        return "等待页面动作回执"
    if phase == "awaiting_agent_reply":
        return "正在处理上一轮消息"
    return None


def _build_recoverable_error(session: AgentSession) -> AgentRecoverableErrorRead | None:
    runtime = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    raw_message = sanitize_text(str(runtime.get("last_error") or ""), max_length=280) or None
    if raw_message is None:
        return None
    lowered = raw_message.lower()
    if "超时" in raw_message or "timeout" in lowered:
        code = "timeout"
        retryable = True
    elif "鉴权" in raw_message or "401" in lowered or "unauthorized" in lowered:
        code = "auth"
        retryable = False
    elif "请刷新页面后重试" in raw_message or "恢复" in raw_message:
        code = "recoverable_runtime"
        retryable = True
    elif "模型返回" in raw_message or "json" in lowered:
        code = "model_contract"
        retryable = True
    elif "服务异常" in raw_message or "5xx" in lowered or "upstream" in lowered:
        code = "upstream"
        retryable = True
    else:
        code = "runtime_error"
        retryable = True
    return AgentRecoverableErrorRead(code=code, message=raw_message, retryable=retryable)


def _build_runtime_snapshot(session: AgentSession) -> AgentRuntimeSnapshotRead:
    runtime = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    raw_phase = _sanitize_line(str(runtime.get("phase") or ""), max_length=64)
    pending_secure_input = runtime.get("pending_secure_input") if isinstance(runtime.get("pending_secure_input"), dict) else {}
    public_status = _sanitize_line(str(session.status or ""), max_length=32) or "active"
    agent_state = session.agent_state_json if isinstance(session.agent_state_json, dict) else {}
    watch = agent_state.get("watch") if isinstance(agent_state.get("watch"), dict) else {}

    if raw_phase == "recovering":
        phase = "recovering"
    elif public_status == "waiting_approval":
        phase = "waiting_approval"
    elif raw_phase == "awaiting_agent_reply":
        phase = "awaiting_agent_reply"
    elif raw_phase == "awaiting_secure_input" or pending_secure_input:
        phase = "awaiting_secure_input"
    elif raw_phase == "awaiting_ui_feedback":
        phase = "awaiting_ui_feedback"
    elif raw_phase == "resolving_ui_feedback":
        phase = "resolving_ui_feedback"
    elif public_status == "running" or bool(watch.get("watching")):
        phase = "watching_task"
    elif public_status == "failed" or raw_phase == "run_loop_error":
        phase = "failed"
    else:
        phase = "idle"

    input_block_reason = {
        "awaiting_agent_reply": "awaiting_reply",
        "awaiting_secure_input": "pending_sensitive_input",
        "awaiting_ui_feedback": "pending_ui",
        "resolving_ui_feedback": "pending_ui",
        "waiting_approval": "waiting_approval",
        "recovering": "recovering",
    }.get(phase, "none")
    input_state = "locked" if input_block_reason != "none" else "enabled"
    recoverable_error = _build_recoverable_error(session)
    active_skill_id = _derive_active_skill_id(session)
    blocker_summary = _runtime_blocker_summary(session, phase=phase, recoverable_error=recoverable_error)
    current_turn_id = (
        _normalize_client_message_id(runtime.get("current_message_request_id"))
        or _normalize_step_request_id(runtime.get("last_step_request_id"))
        or None
    )
    watch_task_id = _runtime_watch_task_id(session)
    can_resume = bool(recoverable_error is not None and recoverable_error.retryable)
    can_interrupt = public_status == "running" and bool(watch_task_id)
    return AgentRuntimeSnapshotRead(
        phase=phase,
        input_state=input_state,
        input_block_reason=input_block_reason,
        current_turn_id=current_turn_id,
        watch_task_id=watch_task_id,
        active_skill_id=active_skill_id,
        active_skill_title=get_skill_title(active_skill_id),
        blocker_summary=blocker_summary,
        recoverable_error=recoverable_error,
        can_interrupt=can_interrupt,
        can_resume=can_resume,
    )


def serialize_agent_session(session: AgentSession) -> AgentSessionRead:
    route_context_json = _normalize_page_context(session.route_context_json if isinstance(session.route_context_json, dict) else {})
    working_context_json = _normalize_working_context(
        session.working_context_json if isinstance(session.working_context_json, dict) else {}
    )
    dialog_state_json = _normalize_dialog_state(
        session.dialog_state_json if isinstance(session.dialog_state_json, dict) else {}
    )
    pending_plan_json = session.pending_plan_json if isinstance(session.pending_plan_json, dict) else {}
    browser_runtime_json = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    agent_state_json = _session_agent_state(session)
    messages = [_serialize_message(item) for item in session.messages]
    current_goal = _session_goal(session)
    runtime_snapshot = _build_runtime_snapshot(session)
    return AgentSessionRead(
        session_id=session.id,
        agent_id=session.agent_id,
        status=session.status,
        route_context_json=route_context_json,
        working_context_json=working_context_json,
        dialog_state_json=dialog_state_json,
        pending_plan_json=pending_plan_json,
        browser_runtime_json=browser_runtime_json,
        agent_state_json=agent_state_json,
        runtime_snapshot=runtime_snapshot,
        current_goal_id=current_goal.id if current_goal is not None else None,
        current_goal_title=current_goal.title if current_goal is not None else None,
        last_task_id=session.last_task_id,
        messages=messages,
        created_at=session.created_at,
        updated_at=session.updated_at,
    )


def _session_attention_kind(session: AgentSession | None) -> AgentAttentionKind:
    if session is None:
        return "none"
    status = str(session.status or "").strip().lower()
    browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    pending_secure_input = browser_runtime.get("pending_secure_input")
    pending_ui_actions = browser_runtime.get("pending_ui_actions")
    if status == "waiting_approval":
        return "waiting_approval"
    if isinstance(pending_secure_input, dict) and pending_secure_input:
        return "pending_ui_action"
    if isinstance(pending_ui_actions, list) and pending_ui_actions:
        return "pending_ui_action"
    if status == "running" and _runtime_watch_task_id(session):
        return "running_task"
    return "none"


def serialize_agent_session_summary(session: AgentSession | None) -> AgentSessionSummaryRead:
    attention_kind = _session_attention_kind(session)
    if session is None:
        return AgentSessionSummaryRead(
            has_attention=False,
            attention_kind=attention_kind,
            session_status=None,
            runtime_phase="idle",
            input_state="enabled",
            input_block_reason="none",
            current_goal_id=None,
            current_goal_title=None,
            active_skill_title=None,
            last_task_id=None,
            updated_at=None,
        )
    current_goal = _session_goal(session)
    runtime_snapshot = _build_runtime_snapshot(session)
    return AgentSessionSummaryRead(
        has_attention=attention_kind != "none",
        attention_kind=attention_kind,
        session_status=session.status,
        runtime_phase=runtime_snapshot.phase,
        input_state=runtime_snapshot.input_state,
        input_block_reason=runtime_snapshot.input_block_reason,
        current_goal_id=current_goal.id if current_goal is not None else None,
        current_goal_title=current_goal.title if current_goal is not None else None,
        active_skill_title=runtime_snapshot.active_skill_title,
        last_task_id=runtime_snapshot.watch_task_id or session.last_task_id,
        updated_at=session.updated_at,
    )


_AgentStreamEmitter = Callable[[dict[str, Any]], None]


def _emit_stream_event(stream_emitter: _AgentStreamEmitter | None, payload: dict[str, Any]) -> None:
    if stream_emitter is None:
        return
    stream_emitter(sanitize_json_value(payload))


def _emit_session_snapshot(stream_emitter: _AgentStreamEmitter | None, session: AgentSession) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentSessionSnapshotEvent(session=serialize_agent_session(session)).model_dump(mode="json"),
    )
    _emit_stream_event(
        stream_emitter,
        AgentStateEvent(agent_state_json=_session_agent_state(session)).model_dump(mode="json"),
    )


def _emit_agent_state(
    stream_emitter: _AgentStreamEmitter | None,
    session: AgentSession,
    *,
    turn_id: str | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentStateEvent(agent_state_json=_session_agent_state(session), turn_id=turn_id).model_dump(mode="json"),
    )


def _iter_stream_text_chunks(text: str, *, chunk_size: int = 24) -> list[str]:
    normalized = str(text or "")
    if not normalized:
        return []
    chunks: list[str] = []
    lines = normalized.splitlines(keepends=True)
    for line in lines:
        if not line:
            continue
        start = 0
        while start < len(line):
            chunks.append(line[start : start + chunk_size])
            start += chunk_size
    return chunks or [normalized]


def _emit_turn_started(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    phase: str,
    client_message_id: str | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentTurnStartedEvent(turn_id=turn_id, phase=phase, client_message_id=client_message_id).model_dump(mode="json"),
    )


def _emit_turn_done(stream_emitter: _AgentStreamEmitter | None, *, turn_id: str, status: str = "ok") -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(stream_emitter, AgentTurnDoneEvent(turn_id=turn_id, status=status).model_dump(mode="json"))


def _emit_action_update(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    content: str,
    trace: dict[str, Any] | None = None,
    message: AgentMessage | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentActionUpdateEvent(
            turn_id=turn_id,
            content=sanitize_text(content, max_length=4000) or "",
            trace=sanitize_json_value(trace or {}),
            message=_serialize_message(message) if message is not None else None,
        ).model_dump(mode="json"),
    )


def _emit_error_event(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    detail: str,
    turn_id: str | None = None,
    status_code: int | None = None,
    message: AgentMessage | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentErrorEvent(
            detail=sanitize_text(detail, max_length=4000) or "",
            turn_id=turn_id,
            status_code=status_code,
            message=_serialize_message(message) if message is not None else None,
        ).model_dump(mode="json"),
    )


def _emit_streamed_assistant_message(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    message: AgentMessage,
) -> None:
    if stream_emitter is None:
        return
    message_type = str(message.message_type or "text")
    _emit_stream_event(
        stream_emitter,
        AgentAssistantMessageStartEvent(turn_id=turn_id, message_type=message_type).model_dump(mode="json"),
    )
    for chunk in _iter_stream_text_chunks(message.content):
        _emit_stream_event(stream_emitter, AgentAssistantDeltaEvent(turn_id=turn_id, delta=chunk).model_dump(mode="json"))
    _emit_stream_event(
        stream_emitter,
        AgentAssistantMessageDoneEvent(turn_id=turn_id, message=_serialize_message(message)).model_dump(mode="json"),
    )


def _emit_ui_actions_requested(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    ui_actions: list[dict[str, Any]],
    content: str | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentUIActionsRequestedEvent(ui_actions=ui_actions, turn_id=turn_id, content=content).model_dump(mode="json"),
    )


def _emit_plan_pending(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    message: AgentMessage,
    pending_plan_json: dict[str, Any],
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentPlanPendingEvent(
            turn_id=turn_id,
            message=_serialize_message(message),
            pending_plan_json=sanitize_json_value(pending_plan_json),
        ).model_dump(mode="json"),
    )


def _emit_task_update(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    task_id: str,
    status: TaskExecutionStatus | str,
    progress: int | None = None,
    message: str | None = None,
) -> None:
    if stream_emitter is None:
        return
    _emit_stream_event(
        stream_emitter,
        AgentTaskUpdateEvent(
            task_id=task_id,
            status=status,
            progress=progress,
            message=sanitize_text(message, max_length=500),
        ).model_dump(mode="json"),
    )


def _compact_reply_tool_traces(tool_traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compact: list[dict[str, Any]] = []
    for item in tool_traces[-4:]:
        if not isinstance(item, dict):
            continue
        compact_item: dict[str, Any] = {
            "tool_name": _sanitize_line(str(item.get("tool_name") or ""), max_length=64),
            "ok": bool(item.get("ok")),
        }
        if compact_item["ok"]:
            result = item.get("result")
            compact_item["result"] = sanitize_json_value(result if isinstance(result, (dict, list)) else {"value": result})
        else:
            compact_item["error"] = sanitize_text(str(item.get("error") or ""), max_length=240)
        compact.append(compact_item)
    return compact


def _normalize_reply_signature(value: str) -> str:
    return re.sub(r"\s+", " ", sanitize_text(value, max_length=MAX_ASSISTANT_MESSAGE_CHARS) or "").strip()


_THINK_BLOCK_PATTERN = re.compile(r"(?is)<think\b[^>]*>.*?</think>")
_THINK_TAG_PATTERN = re.compile(r"(?i)</?think\b[^>]*>")
_INTERNAL_REPLY_LEAK_KEYS = (
    "confirmed_reply_draft",
    "working_context",
    "tool_trace_summary",
    "pending_dialog_state",
    "followup_hint",
)
_INTERNAL_REPLY_LEAK_META_HINTS = (
    "输出给用户",
    "整理输出",
    "准备好了回复",
    "直接整理",
    "说明没有需要",
    "调用工具",
    "都是空的",
    "当前用户问题",
    "只输出最终中文正文",
    "不要泄露 json 结构",
    "我需要把",
)


def _looks_like_internal_reply_leak_block(block: str) -> bool:
    normalized = sanitize_text(block, max_length=MAX_ASSISTANT_MESSAGE_CHARS) or ""
    if not normalized:
        return False
    lower_block = normalized.lower()
    if not any(key in lower_block for key in _INTERNAL_REPLY_LEAK_KEYS):
        return False
    if any(hint in normalized for hint in _INTERNAL_REPLY_LEAK_META_HINTS):
        return True
    if re.search(
        r'(?i)["\']?(?:confirmed_reply_draft|working_context|tool_trace_summary|pending_dialog_state|followup_hint)["\']?\s*:',
        normalized,
    ):
        return True
    return "{" in normalized or "[" in normalized


def _scrub_assistant_reply_leaks(content: str) -> str:
    normalized = sanitize_text(content, max_length=MAX_ASSISTANT_MESSAGE_CHARS) or ""
    if not normalized:
        return ""
    without_think = _THINK_BLOCK_PATTERN.sub("\n\n", normalized)
    without_think = _THINK_TAG_PATTERN.sub("", without_think).strip()
    blocks = [block.strip() for block in re.split(r"\n{2,}", without_think) if block.strip()]
    if not blocks:
        return without_think
    kept_blocks = [block for block in blocks if not _looks_like_internal_reply_leak_block(block)]
    if kept_blocks:
        return "\n\n".join(kept_blocks).strip()
    if without_think != normalized or len(blocks) != len(kept_blocks):
        return ""
    return without_think


def _is_list_like_reply_block(block: str) -> bool:
    lines = [line.strip() for line in block.splitlines() if line.strip()]
    if len(lines) < 2:
        return False
    return all(re.match(r"(?:[-*•]\s+|\d+\.\s+)", line) for line in lines)


def _split_reply_sentences(block: str) -> list[str]:
    parts = re.findall(r".+?(?:[。！？!?]+|$)", block, flags=re.S)
    return [part.strip() for part in parts if part and part.strip()]


def _dedupe_consecutive_reply_sentences(block: str) -> str:
    sentences = _split_reply_sentences(block)
    if len(sentences) < 2:
        return block.strip()
    signatures = [_normalize_reply_signature(sentence) for sentence in sentences]
    deduped: list[str] = []
    index = 0
    while index < len(sentences):
        matched_span = 0
        max_span = (len(sentences) - index) // 2
        for span in range(1, max_span + 1):
            current = signatures[index : index + span]
            if not all(current):
                continue
            following = signatures[index + span : index + (span * 2)]
            if current == following:
                matched_span = span
        if matched_span:
            deduped.extend(sentence.strip() for sentence in sentences[index : index + matched_span])
            next_index = index + matched_span
            while next_index + matched_span <= len(sentences):
                if signatures[next_index : next_index + matched_span] != signatures[index : index + matched_span]:
                    break
                next_index += matched_span
            index = next_index
            continue
        deduped.append(sentences[index].strip())
        index += 1
    return "".join(deduped).strip() or block.strip()


def _normalize_assistant_reply_content(content: str) -> str:
    normalized = _scrub_assistant_reply_leaks(content)
    if not normalized:
        return ""
    blocks = [block.strip() for block in re.split(r"\n{2,}", normalized) if block.strip()]
    if not blocks:
        return normalized.strip()
    deduped_blocks: list[str] = []
    previous_signature = ""
    for block in blocks:
        cleaned_block = block if _is_list_like_reply_block(block) else _dedupe_consecutive_reply_sentences(block)
        signature = _normalize_reply_signature(cleaned_block)
        if signature and signature == previous_signature:
            continue
        deduped_blocks.append(cleaned_block)
        previous_signature = signature
    return "\n\n".join(deduped_blocks).strip() or normalized.strip()


def _trim_incomplete_think_suffix(content: str) -> str:
    normalized = str(content or "")
    if not normalized:
        return ""
    last_lt = normalized.rfind("<")
    if last_lt < 0:
        return normalized
    suffix = normalized[last_lt:]
    lower_suffix = suffix.lower()
    if "<think".startswith(lower_suffix) or "</think".startswith(lower_suffix):
        return normalized[:last_lt]
    if lower_suffix.startswith("<think") and ">" not in lower_suffix:
        return normalized[:last_lt]
    if lower_suffix.startswith("</think") and ">" not in lower_suffix:
        return normalized[:last_lt]
    return normalized


def _normalize_streaming_assistant_reply_content(content: str) -> str:
    normalized = sanitize_text(content, max_length=MAX_ASSISTANT_MESSAGE_CHARS) or ""
    if not normalized:
        return ""
    visible_source = _trim_incomplete_think_suffix(normalized)
    if not visible_source:
        return ""

    result: list[str] = []
    lowered = visible_source.lower()
    index = 0
    inside_think = False
    while index < len(visible_source):
        if not inside_think and lowered.startswith("<think", index):
            tag_end = visible_source.find(">", index)
            if tag_end < 0:
                break
            inside_think = True
            index = tag_end + 1
            continue
        if inside_think:
            closing_start = lowered.find("</think", index)
            if closing_start < 0:
                break
            tag_end = visible_source.find(">", closing_start)
            if tag_end < 0:
                break
            inside_think = False
            index = tag_end + 1
            continue
        if lowered.startswith("</think", index):
            tag_end = visible_source.find(">", index)
            if tag_end < 0:
                break
            index = tag_end + 1
            continue
        result.append(visible_source[index])
        index += 1
    return "".join(result).strip()


def _emit_assistant_delta(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    delta: str,
) -> None:
    if stream_emitter is None:
        return
    normalized_delta = str(delta or "")
    if not normalized_delta:
        return
    _emit_stream_event(
        stream_emitter,
        AgentAssistantDeltaEvent(turn_id=turn_id, delta=normalized_delta).model_dump(mode="json"),
    )


def _emit_chunked_assistant_reply(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    content: str,
) -> str:
    emitted = ""
    for chunk in _iter_stream_text_chunks(content):
        _emit_assistant_delta(stream_emitter, turn_id=turn_id, delta=chunk)
        emitted = f"{emitted}{chunk}"
    return emitted


def _stream_upstream_assistant_reply(
    stream_emitter: _AgentStreamEmitter | None,
    *,
    turn_id: str,
    raw_chunks: Any,
) -> str:
    accumulated_raw = ""
    emitted_visible = ""
    for raw_chunk in raw_chunks:
        chunk_text = str(raw_chunk or "")
        if not chunk_text:
            continue
        accumulated_raw = f"{accumulated_raw}{chunk_text}"
        visible_text = _normalize_streaming_assistant_reply_content(accumulated_raw)
        if not visible_text or not visible_text.startswith(emitted_visible):
            continue
        next_delta = visible_text[len(emitted_visible) :]
        if not next_delta:
            continue
        _emit_assistant_delta(stream_emitter, turn_id=turn_id, delta=next_delta)
        emitted_visible = visible_text

    normalized_final = _normalize_assistant_reply_content(accumulated_raw)
    if normalized_final.startswith(emitted_visible):
        trailing_delta = normalized_final[len(emitted_visible) :]
        if trailing_delta:
            _emit_assistant_delta(stream_emitter, turn_id=turn_id, delta=trailing_delta)
            emitted_visible = normalized_final
        return normalized_final
    if normalized_final and not emitted_visible:
        return normalized_final
    return emitted_visible


def _build_reply_stream_request(
    *,
    user_content: str,
    message_type: str,
    reply_markdown: str,
    tool_traces: list[dict[str, Any]],
    working_context: dict[str, Any],
) -> LLMRequest:
    goal = "把已经确定的智能体结论整理成面向用户的最终中文回复"
    if message_type == "clarifying":
        goal = "把已经确定的智能体追问整理成直接、自然的一句中文追问"
    if message_type == "plan":
        goal = "把已经确定的智能体计划摘要整理成简洁、自然的中文说明，不要输出动作 JSON"
    payload = {
        "user_request": sanitize_text(user_content, max_length=1000) or "",
        "confirmed_reply_draft": sanitize_text(reply_markdown, max_length=4000) or "",
        "working_context": sanitize_json_value(working_context),
        "tool_trace_summary": _compact_reply_tool_traces(tool_traces),
    }
    return LLMRequest(
        messages=[
            LLMMessage.from_text(
                "system",
                "你是 haor 的回复整理器。"
                f"你的任务是：{goal}。"
                "不要改变事实，不要新增对象 ID、动作、风险结论或执行结果，不要泄露 JSON 结构，只输出最终中文正文。"
                "不要重复句子、不要整段复述同一结果、不要把动作日志原样再说一遍。",
            ),
            LLMMessage.from_text("user", json.dumps(payload, ensure_ascii=False, indent=2)),
        ]
    )


def _append_message(
    db: Session,
    *,
    session: AgentSession,
    role: str,
    message_type: str,
    content: str,
    payload_json: dict[str, Any] | None = None,
) -> AgentMessage:
    message = AgentMessage(
        session_id=session.id,
        role=_sanitize_line(role, max_length=32) or "assistant",
        message_type=_sanitize_line(message_type, max_length=32) or "text",
        content=sanitize_text(content, max_length=MAX_ASSISTANT_MESSAGE_CHARS) or "",
        payload_json=sanitize_json_value(payload_json or {}),
    )
    session.updated_at = _now()
    db.add(message)
    db.add(session)
    db.flush()
    return message


def _append_or_stream_assistant_message(
    db: Session,
    *,
    session: AgentSession,
    message_type: str,
    content: str,
    payload_json: dict[str, Any],
    user_content: str,
    tool_traces: list[dict[str, Any]],
    working_context: dict[str, Any],
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> AgentMessage:
    fallback_content = _normalize_assistant_reply_content(content)
    skip_reply_rewrite = (
        bool(payload_json.get("skip_reply_rewrite"))
        or len(str(content or "")) > MAX_REPLY_REWRITE_CHARS
        or len(fallback_content) > MAX_REPLY_REWRITE_CHARS
    )
    if stream_emitter is None or not turn_id or message_type not in {"text", "clarifying", "plan"}:
        return _append_message(
            db,
            session=session,
            role="assistant",
            message_type=message_type,
            content=fallback_content,
            payload_json=payload_json,
        )

    _emit_stream_event(
        stream_emitter,
        AgentAssistantMessageStartEvent(turn_id=turn_id, message_type=message_type).model_dump(mode="json"),
    )
    final_content = fallback_content
    emitted_content = ""
    if fallback_content and not skip_reply_rewrite and _runtime_provider_mode() != "mock" and _haor_reply_rewrite_enabled():
        reply_request = _build_reply_stream_request(
            user_content=user_content,
            message_type=message_type,
            reply_markdown=fallback_content,
            tool_traces=tool_traces,
            working_context=working_context,
        )
        provider = _build_runtime_provider().provider
        try:
            resolved_reply = _stream_upstream_assistant_reply(
                stream_emitter,
                turn_id=turn_id,
                raw_chunks=provider.stream_generate(reply_request),
            )
            if resolved_reply:
                final_content = resolved_reply
                emitted_content = resolved_reply
        except Exception as exc:
            logger.warning("haor reply stream failed, falling back to draft reply", exc_info=exc)

    if not emitted_content:
        emitted_content = _emit_chunked_assistant_reply(
            stream_emitter,
            turn_id=turn_id,
            content=final_content,
        )
    elif final_content.startswith(emitted_content):
        trailing_delta = final_content[len(emitted_content) :]
        if trailing_delta:
            _emit_chunked_assistant_reply(
                stream_emitter,
                turn_id=turn_id,
                content=trailing_delta,
            )
    message = _append_message(
        db,
        session=session,
        role="assistant",
        message_type=message_type,
        content=final_content,
        payload_json=payload_json,
    )
    _emit_stream_event(
        stream_emitter,
        AgentAssistantMessageDoneEvent(turn_id=turn_id, message=_serialize_message(message)).model_dump(mode="json"),
    )
    return message


def _restore_session_from_running_state(session: AgentSession) -> None:
    restore_session_from_running_state(session, now_fn=_now)


def _has_interrupted_task_message(session: AgentSession, *, task_id: str) -> bool:
    for item in reversed(list(session.messages or [])[-12:]):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if str(payload.get("task_id") or "").strip() != task_id:
            continue
        if payload.get("interrupted"):
            return True
    return False


def _has_stale_ui_feedback_message(session: AgentSession) -> bool:
    for item in reversed(list(session.messages or [])[-12:]):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if payload.get("stale_ui_feedback"):
            return True
    return False


def _has_stale_message_turn_message(session: AgentSession) -> bool:
    for item in reversed(list(session.messages or [])[-12:]):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if payload.get("stale_message_turn"):
            return True
    return False


def _normalize_client_message_id(value: str | None) -> str | None:
    return _sanitize_line(str(value or ""), max_length=128) or None


def _normalize_step_request_id(value: str | None) -> str | None:
    return _sanitize_line(str(value or ""), max_length=128) or None


def _is_duplicate_message_request(browser_runtime: dict[str, Any], *, client_message_id: str | None) -> bool:
    if not client_message_id:
        return False
    return client_message_id in {
        _normalize_client_message_id(browser_runtime.get("current_message_request_id")),
        _normalize_client_message_id(browser_runtime.get("last_message_request_id")),
    }


def _is_duplicate_step_request(browser_runtime: dict[str, Any], *, step_request_id: str | None) -> bool:
    if not step_request_id:
        return False
    return (
        _normalize_step_request_id(browser_runtime.get("last_step_request_id"))
        == _normalize_step_request_id(step_request_id)
        and _parse_runtime_timestamp(browser_runtime.get("last_step_ack_at")) is not None
    )


def _append_interrupted_task_message(
    db: Session,
    *,
    session: AgentSession,
    task_id: str,
    source: str,
) -> None:
    append_interrupted_task_message(
        db,
        session=session,
        task_id=task_id,
        source=source,
        append_message_fn=_append_message,
    )


def _reconcile_running_session_state(
    db: Session,
    *,
    session: AgentSession,
    interrupted_source: str = "session_reconcile",
) -> bool:
    return reconcile_running_session_state(
        db,
        session=session,
        interrupted_source=interrupted_source,
        sanitize_line_fn=_sanitize_line,
        get_task_run_fn=get_task_run,
        is_session_orchestrate_task_fn=_is_session_orchestrate_task,
        normalize_task_status_fn=_normalize_task_status,
        is_terminal_task_status_fn=_is_terminal_task_status,
        restore_session_from_running_state_fn=_restore_session_from_running_state,
        append_interrupted_task_message_fn=_append_interrupted_task_message,
        canceled_task_status=TaskExecutionStatus.CANCELED.value,
    )


def _reconcile_stale_message_turn_state(
    db: Session,
    *,
    session: AgentSession,
    source: str = "message_turn_reconcile",
) -> bool:
    browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    if str(browser_runtime.get("phase") or "") != "awaiting_agent_reply":
        return False
    client_message_id = _normalize_client_message_id(browser_runtime.get("current_message_request_id"))
    if not client_message_id:
        return False
    pending_since = _parse_runtime_timestamp(browser_runtime.get("message_pending_since")) or (
        session.updated_at.astimezone(timezone.utc) if isinstance(session.updated_at, datetime) else None
    )
    if pending_since is None:
        return False
    if (_now() - pending_since).total_seconds() < MESSAGE_TURN_STALE_SECONDS:
        return False

    browser_context = _normalize_browser_context(
        browser_runtime.get("last_browser_context") if isinstance(browser_runtime.get("last_browser_context"), dict) else {}
    )
    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
        current_objective=str(browser_runtime.get("current_objective") or "") or None,
        objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
        auto_executed_actions=browser_runtime.get("auto_executed_actions")
        if isinstance(browser_runtime.get("auto_executed_actions"), list)
        else [],
        last_message_request_id=client_message_id,
        last_message_ack_at=_now(),
    )
    session.status = "active"
    db.add(session)
    if not _has_stale_message_turn_message(session):
        _append_message(
            db,
            session=session,
            role="assistant",
            message_type="text",
            content="检测到上一轮消息处理已超时，已为你结束等待状态；如需继续，请重新发送或改写问题。",
            payload_json={
                "stale_message_turn": True,
                "client_message_id": client_message_id,
                "source": source,
                "expired_after_seconds": MESSAGE_TURN_STALE_SECONDS,
            },
        )
    logger.info(
        "haor stale message turn reconciled",
        extra={
            "agent_session_id": session.id,
            "agent_client_message_id": client_message_id,
            "agent_phase": "awaiting_agent_reply",
            "agent_result": "stale",
            "agent_source": source,
        },
    )
    return True


def _reconcile_stale_ui_feedback_state(
    db: Session,
    *,
    session: AgentSession,
    source: str = "ui_feedback_reconcile",
) -> bool:
    browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    if str(browser_runtime.get("phase") or "") != "awaiting_ui_feedback":
        return False
    pending_ui_actions = browser_runtime.get("pending_ui_actions")
    if not isinstance(pending_ui_actions, list) or not pending_ui_actions:
        return False
    pending_since = _parse_runtime_timestamp(browser_runtime.get("ui_pending_since")) or (
        session.updated_at.astimezone(timezone.utc) if isinstance(session.updated_at, datetime) else None
    )
    if pending_since is None:
        return False
    if (_now() - pending_since).total_seconds() < UI_FEEDBACK_STALE_SECONDS:
        return False

    browser_context = _normalize_browser_context(
        browser_runtime.get("last_browser_context") if isinstance(browser_runtime.get("last_browser_context"), dict) else {}
    )
    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
        current_objective=str(browser_runtime.get("current_objective") or "") or None,
        objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
        auto_executed_actions=browser_runtime.get("auto_executed_actions")
        if isinstance(browser_runtime.get("auto_executed_actions"), list)
        else [],
    )
    session.status = "active"
    db.add(session)
    if not _has_stale_ui_feedback_message(session):
        _append_message(
            db,
            session=session,
            role="assistant",
            message_type="text",
            content="检测到上一次页面动作已过期，已为你解除等待状态；如需继续，请重新描述目标。",
            payload_json={
                "stale_ui_feedback": True,
                "source": source,
                "expired_after_seconds": UI_FEEDBACK_STALE_SECONDS,
            },
        )
    logger.info(
        "haor stale ui feedback reconciled",
        extra={
            "agent_session_id": session.id,
            "agent_phase": "awaiting_ui_feedback",
            "agent_result": "expired",
            "agent_source": source,
        },
    )
    return True


def _repair_inconsistent_runtime_state(
    db: Session,
    *,
    session: AgentSession,
    source: str = "session_recover",
) -> bool:
    browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    phase = _sanitize_line(str(browser_runtime.get("phase") or ""), max_length=64)
    if not phase or phase == "idle":
        return False

    browser_context = _normalize_browser_context(
        browser_runtime.get("last_browser_context") if isinstance(browser_runtime.get("last_browser_context"), dict) else {}
    )
    last_error = sanitize_text(str(browser_runtime.get("last_error") or ""), max_length=240) or None
    changed = False

    if phase == "awaiting_agent_reply" and not _normalize_client_message_id(browser_runtime.get("current_message_request_id")):
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
            current_objective=str(browser_runtime.get("current_objective") or "") or None,
            objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
            auto_executed_actions=browser_runtime.get("auto_executed_actions")
            if isinstance(browser_runtime.get("auto_executed_actions"), list)
            else [],
            last_error=last_error,
        )
        session.status = "active"
        changed = True
    elif phase in {"awaiting_ui_feedback", "resolving_ui_feedback"}:
        pending_ui_actions = browser_runtime.get("pending_ui_actions") if isinstance(browser_runtime.get("pending_ui_actions"), list) else []
        runtime_watch_task_id = _runtime_watch_task_id(session)
        terminal_followup_written = bool(
            runtime_watch_task_id
            and has_agent_task_followup_message(
                session,
                task_id=runtime_watch_task_id,
            )
        )
        if not pending_ui_actions or terminal_followup_written:
            _clear_browser_runtime(
                session,
                browser_context=browser_context,
                last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
                current_objective=str(browser_runtime.get("current_objective") or "") or None,
                objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
                auto_executed_actions=browser_runtime.get("auto_executed_actions")
                if isinstance(browser_runtime.get("auto_executed_actions"), list)
                else [],
                last_error=last_error,
            )
            session.status = "active"
            changed = True
    elif phase == "awaiting_secure_input":
        pending_secure_input = browser_runtime.get("pending_secure_input") if isinstance(browser_runtime.get("pending_secure_input"), dict) else {}
        if not pending_secure_input:
            _clear_browser_runtime(
                session,
                browser_context=browser_context,
                last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
                current_objective=str(browser_runtime.get("current_objective") or "") or None,
                objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
                auto_executed_actions=browser_runtime.get("auto_executed_actions")
                if isinstance(browser_runtime.get("auto_executed_actions"), list)
                else [],
                last_error=last_error,
            )
            session.status = "active"
            changed = True
    elif phase in {
        "cancel_pending_plan",
        "followup_deny",
        "internal_followup",
        "preflight_clarifying",
        "apply_decision",
        "run_loop_error",
    } and str(session.status or "") != "running":
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
            current_objective=str(browser_runtime.get("current_objective") or "") or None,
            objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
            auto_executed_actions=browser_runtime.get("auto_executed_actions")
            if isinstance(browser_runtime.get("auto_executed_actions"), list)
            else [],
            last_error=last_error,
        )
        session.status = "active"
        changed = True
    elif str(session.status or "") == "waiting_approval" and phase not in {"idle", "waiting_approval"}:
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(browser_runtime.get("last_user_intent") or "") or None,
            current_objective=str(browser_runtime.get("current_objective") or "") or None,
            objective_kind=str(browser_runtime.get("objective_kind") or "") or None,
            auto_executed_actions=browser_runtime.get("auto_executed_actions")
            if isinstance(browser_runtime.get("auto_executed_actions"), list)
            else [],
            last_error=last_error,
        )
        changed = True

    if changed:
        db.add(session)
        logger.info(
            "haor session recovered",
            extra={
                "agent_session_id": session.id,
                "agent_phase": phase,
                "agent_result": "session_recovered",
                "agent_source": source,
            },
        )
    return changed


def _reconcile_session_runtime_state(
    db: Session,
    *,
    session: AgentSession,
    interrupted_source: str = "session_reconcile",
    message_stale_source: str = "message_turn_reconcile",
    stale_source: str = "ui_feedback_reconcile",
    repair_source: str = "session_recover",
) -> bool:
    changed = False
    if _reconcile_running_session_state(db, session=session, interrupted_source=interrupted_source):
        changed = True
    if _reconcile_stale_message_turn_state(db, session=session, source=message_stale_source):
        changed = True
    if _reconcile_stale_ui_feedback_state(db, session=session, source=stale_source):
        changed = True
    if _repair_inconsistent_runtime_state(db, session=session, source=repair_source):
        changed = True
    if changed:
        _sync_current_goal_state(db, session)
    return changed


def _refresh_message_turn_if_active(
    db: Session,
    *,
    session: AgentSession,
    client_message_id: str | None,
    turn_id: str | None,
    phase: str,
) -> bool:
    normalized_client_message_id = _normalize_client_message_id(client_message_id)
    if not normalized_client_message_id:
        return True
    db.refresh(session)
    browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    current_message_request_id = _normalize_client_message_id(browser_runtime.get("current_message_request_id"))
    if str(browser_runtime.get("phase") or "") == "awaiting_agent_reply" and current_message_request_id == normalized_client_message_id:
        return True
    logger.info(
        "haor message turn abandoned",
        extra={
            "agent_session_id": session.id,
            "agent_turn_id": turn_id,
            "agent_client_message_id": normalized_client_message_id,
            "agent_phase": phase,
            "agent_result": "abandoned",
        },
    )
    return False


def _log_message_turn_event(
    *,
    session_id: str,
    turn_id: str | None,
    client_message_id: str | None,
    phase: str,
    result: str,
) -> None:
    logger.info(
        "haor message turn event",
        extra={
            "agent_session_id": session_id,
            "agent_turn_id": turn_id,
            "agent_client_message_id": client_message_id,
            "agent_phase": phase,
            "agent_result": result,
        },
    )


def _raise_if_session_running(session: AgentSession | None, *, stage: str) -> None:
    if session is None or str(session.status or "") != "running":
        return
    raise AgentConflictError("当前 haor 正在执行编排任务，请先中断当前任务", session_id=session.id, stage=stage)


def mark_agent_session_interrupted(
    db: Session,
    *,
    session_id: str,
    task_id: str,
    source: str,
) -> None:
    mark_agent_session_interrupted_via_service(
        db,
        session_id=session_id,
        task_id=task_id,
        source=source,
        restore_session_from_running_state_fn=_restore_session_from_running_state,
        append_interrupted_task_message_fn=_append_interrupted_task_message,
    )
    session = db.get(AgentSession, session_id)
    if session is not None:
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason="当前目标已被用户中断，可稍后恢复继续",
        )


def _create_session(db: Session, *, user: User) -> AgentSession:
    session = AgentSession(
        agent_id=AGENT_ID,
        user_id=user.id,
        status="active",
        route_context_json=_normalize_page_context({}),
        working_context_json={},
        dialog_state_json={},
        pending_plan_json={},
        browser_runtime_json={},
        agent_state_json={},
    )
    db.add(session)
    db.flush()
    return session


def get_or_create_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    session = ensure_active_session(
        load_recent_session_fn=_load_recent_session,
        reconcile_session_runtime_state_fn=_reconcile_session_runtime_state,
        create_session_fn=_create_session,
        db=db,
        user=user,
    )
    return serialize_agent_session(session)


def get_agent_session_summary(db: Session, *, user: User) -> AgentSessionSummaryRead:
    session = _load_recent_summary_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(db, session=session):
        db.commit()
        db.refresh(session)
    return serialize_agent_session_summary(session)


def recover_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(
        db,
        session=session,
        interrupted_source="recover_running_state",
        message_stale_source="recover_message_state",
        stale_source="recover_ui_state",
        repair_source="recover_session_state",
    ):
        db.commit()
        db.refresh(session)
    if session is None or not is_active_public_session_status(str(session.status or "")):
        session = ensure_active_session(
            load_recent_session_fn=_load_recent_session,
            reconcile_session_runtime_state_fn=_reconcile_session_runtime_state,
            create_session_fn=_create_session,
            db=db,
            user=user,
        )
        db.commit()
        db.refresh(session)
    return serialize_agent_session(session)


def list_agent_goals(db: Session, *, user: User, limit: int = 12) -> list[Any]:
    return list_agent_goal_reads(db, user=user, limit=limit)


def get_agent_goal(db: Session, *, user: User, goal_id: str) -> Any:
    return get_agent_goal_read(db, user=user, goal_id=goal_id)


def resume_agent_goal(db: Session, *, user: User, goal_id: str) -> AgentSessionRead:
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(db, session=session):
        db.flush()
    if session is None or not is_active_public_session_status(str(session.status or "")):
        session = _create_session(db, user=user)
        db.flush()
    _raise_if_session_running(session, stage="resume_goal")
    goal = resume_agent_goal_binding(db, user=user, session=session, goal_id=goal_id)
    goal_context = goal.context_json if isinstance(goal.context_json, dict) else {}
    browser_context = goal_context.get("browser_summary") if isinstance(goal_context.get("browser_summary"), dict) else {}
    current_objective = sanitize_text(
        str(goal_context.get("current_objective") or goal.title or ""),
        max_length=240,
    ) or goal.title
    objective_kind = _sanitize_line(str(goal_context.get("objective_kind") or goal.goal_kind or ""), max_length=64) or goal.goal_kind
    session.status = "active"
    _set_browser_runtime(
        session,
        phase="idle",
        browser_context=browser_context,
        last_user_intent=current_objective,
        current_objective=current_objective,
        objective_kind=objective_kind,
        planned_steps=[],
        step_cursor=0,
        pending_ui_actions=[],
        completed_ui_actions=[],
        last_ui_results=[],
        auto_executed_actions=[],
        step_count=0,
        retry_state={},
        last_error=None,
    )
    _sync_current_goal_state(
        db,
        session,
        status_override="active",
        latest_summary=f"已恢复目标：{goal.title}",
    )
    db.commit()
    db.refresh(session)
    return serialize_agent_session(session)


def cancel_agent_goal(db: Session, *, user: User, goal_id: str) -> Any:
    goal = db.get(AgentGoal, goal_id)
    if goal is None or goal.user_id != user.id or goal.agent_id != AGENT_ID:
        raise AgentNotFoundError("当前目标不存在", stage="cancel_goal")
    mark_goal_canceled(goal)
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and session.current_goal_id == goal.id:
        attach_goal_to_session(session, None)
        db.add(session)
    db.add(goal)
    db.commit()
    db.refresh(goal)
    return get_agent_goal_read(db, user=user, goal_id=goal.id)


def reset_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    current_session = _load_recent_session(db, user_id=user.id)
    current_goal = _session_goal(current_session)
    if current_session is not None and current_goal is not None and str(current_goal.status or "") not in {"completed", "failed", "canceled"}:
        mark_goal_blocked(current_goal, reason="用户已新建会话，当前目标已暂停")
        db.add(current_goal)
    return reset_agent_session_via_service(
        db,
        user=user,
        load_recent_session_fn=_load_recent_session,
        reconcile_session_runtime_state_fn=_reconcile_session_runtime_state,
        interrupt_agent_session_fn=interrupt_agent_session,
        agent_conflict_error_cls=AgentConflictError,
        query_builder=_session_query,
        normalize_page_context_fn=_normalize_page_context,
        now_fn=_now,
        create_session_fn=_create_session,
        serialize_agent_session_fn=serialize_agent_session,
    )


def append_agent_task_message(
    db: Session,
    *,
    session_id: str,
    content: str,
    payload_json: dict[str, Any] | None = None,
    message_type: str = "task_update",
    watching: bool | None = False,
) -> None:
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    normalized_payload = payload_json if isinstance(payload_json, dict) else {}
    session_browser_runtime = getattr(session, "browser_runtime_json", {})
    session_route_context = getattr(session, "route_context_json", {})
    current_browser_runtime = _normalize_browser_runtime(
        session_browser_runtime if isinstance(session_browser_runtime, dict) else {}
    )
    current_phase = _sanitize_line(str(current_browser_runtime.get("phase") or ""), max_length=64)
    if current_phase in {"awaiting_ui_feedback", "resolving_ui_feedback", "recovering"}:
        browser_context = _normalize_browser_context(
            current_browser_runtime.get("last_browser_context")
            if isinstance(current_browser_runtime.get("last_browser_context"), dict)
            else session_route_context if isinstance(session_route_context, dict) else {}
        )
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=sanitize_text(str(current_browser_runtime.get("last_user_intent") or ""), max_length=240) or None,
            current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or None,
            objective_kind=_sanitize_line(str(current_browser_runtime.get("objective_kind") or ""), max_length=32) or None,
            auto_executed_actions=current_browser_runtime.get("auto_executed_actions")
            if isinstance(current_browser_runtime.get("auto_executed_actions"), list)
            else [],
            last_error=sanitize_text(str(current_browser_runtime.get("last_error") or ""), max_length=240) or None,
            last_message_request_id=_normalize_client_message_id(current_browser_runtime.get("last_message_request_id")),
            last_message_ack_at=_parse_runtime_timestamp(current_browser_runtime.get("last_message_ack_at")),
            last_step_request_id=_normalize_step_request_id(current_browser_runtime.get("last_step_request_id")),
            last_step_ack_at=_parse_runtime_timestamp(current_browser_runtime.get("last_step_ack_at")),
        )
    child_task = normalized_payload.get("child_task") if isinstance(normalized_payload.get("child_task"), dict) else {}
    task_id = _sanitize_line(
        str(normalized_payload.get("task_id") or child_task.get("task_id") or getattr(session, "last_task_id", "") or ""),
        max_length=64,
    ) or None
    if task_id:
        session.last_task_id = task_id
    session_status = str(getattr(session, "status", "") or "").strip().lower()
    if watching is True:
        session.status = "running"
    elif session_status == "running":
        session.status = "active"
    state_delta = sync_agent_task_watch_state(
        session,
        task_id=task_id,
        status=child_task.get("status") or ("failure" if message_type == "error" else "success"),
        message=content,
        action=normalized_payload.get("action") if isinstance(normalized_payload.get("action"), dict) else {},
        watching=watching,
    )
    _append_message(
        db,
        session=session,
        role="assistant",
        message_type=message_type,
        content=content,
        payload_json={
            **normalized_payload,
            **_build_message_state_metadata(
                decision_summary=content,
                evidence=[],
                state_delta=state_delta,
            ),
        },
    )
    _sync_current_goal_state(db, session, latest_summary=content)


def has_agent_task_followup_message(
    session: AgentSession,
    *,
    task_id: str,
    action_type: str | None = None,
    terminal_status: str | None = None,
) -> bool:
    normalized_task_id = _sanitize_line(str(task_id or ""), max_length=64)
    if not normalized_task_id:
        return False
    normalized_action_type = _sanitize_line(str(action_type or ""), max_length=64)
    normalized_terminal_status = _sanitize_line(str(terminal_status or ""), max_length=32)
    for item in reversed(list(session.messages or [])[-16:]):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if _sanitize_line(str(payload.get("task_id") or ""), max_length=64) != normalized_task_id:
            continue
        if payload.get("auto_followup"):
            if normalized_action_type:
                action_payload = payload.get("action") if isinstance(payload.get("action"), dict) else {}
                payload_action_type = _sanitize_line(str(action_payload.get("action_type") or ""), max_length=64)
                if payload_action_type != normalized_action_type:
                    continue
            if normalized_terminal_status:
                payload_terminal_status = _sanitize_line(
                    str(
                        payload.get("terminal_status")
                        or (
                            payload.get("child_task", {}).get("status")
                            if isinstance(payload.get("child_task"), dict)
                            else ""
                        )
                        or ""
                    ),
                    max_length=32,
                )
                if payload_terminal_status != normalized_terminal_status:
                    continue
            return True
    return False


def _content_mentions_current_object(content: str) -> bool:
    markers = ("当前", "这个", "这台", "这条", "这里", "该资产", "该主机", "它", "本页")
    return any(marker in content for marker in markers)


def _contains_execution_intent(content: str) -> bool:
    markers = ("修复", "执行", "开始", "安装", "验证", "扫描", "处理", "部署", "跑一下")
    return any(marker in content for marker in markers)


def _contains_navigation_intent(content: str) -> bool:
    markers = ("打开", "展开", "切到", "切换", "进入", "跳到", "定位", "滚动", "点击")
    return any(marker in content for marker in markers)


def _contains_inspect_intent(content: str) -> bool:
    markers = ("查看", "看看", "详情", "日志", "事件", "分析", "筛选", "搜索", "失败原因", "状态")
    return any(marker in content for marker in markers)


def _classify_objective_kind(
    content: str,
    *,
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
) -> str:
    normalized = sanitize_text(content, max_length=400) or ""
    if not normalized:
        return "ask"
    if any(marker in normalized for marker in ("扫描", "风险验证", "验证风险", "安装 runner", "安装runner", "重装 runner", "重装runner")):
        return "operate_low_risk"
    if any(marker in normalized for marker in ("修复", "批准修复", "整机修复", "批量修复", "恢复修复会话", "创建修复会话")):
        return "operate_high_risk"
    if _contains_navigation_intent(normalized):
        return "navigate"
    if _contains_inspect_intent(normalized):
        return "inspect"
    reply_kind = str(followup_hint.get("reply_kind") or "")
    intent_kind = str(dialog_state.get("intent_kind") or "")
    if reply_kind in {"affirm", "short_value"} and intent_kind == "read_followup":
        return "inspect"
    if reply_kind in {"affirm", "short_value"} and intent_kind in {"prepare_plan", "fill_slot"}:
        return "operate_low_risk"
    return "ask"


def _build_current_objective(
    content: str,
    *,
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
) -> dict[str, Any]:
    return {
        "summary": sanitize_text(content, max_length=240) or None,
        "objective_kind": _classify_objective_kind(content, dialog_state=dialog_state, followup_hint=followup_hint),
    }


def _browser_semantic_page_context(browser_context: dict[str, Any]) -> dict[str, Any]:
    payload = browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
    return _normalize_semantic_page_context(payload)


def _browser_semantic_actions(browser_context: dict[str, Any]) -> list[dict[str, Any]]:
    actions = browser_context.get("semantic_actions") if isinstance(browser_context.get("semantic_actions"), list) else []
    if actions:
        return [_normalize_semantic_action(item if isinstance(item, dict) else {}) for item in actions][:32]
    semantic_page_context = _browser_semantic_page_context(browser_context)
    return sanitize_json_value(
        semantic_page_context.get("semantic_actions") if isinstance(semantic_page_context.get("semantic_actions"), list) else []
    )[:32]


def _semantic_action_matches(action: dict[str, Any], tokens: list[str]) -> bool:
    haystack_parts = [
        str(action.get("semantic_action_id") or ""),
        str(action.get("label") or ""),
        str(action.get("description") or ""),
        " ".join(str(item or "") for item in action.get("keywords", []) if isinstance(item, str)),
    ]
    haystack = " ".join(haystack_parts).lower()
    return any(token and token in haystack for token in tokens)


def _candidate_semantic_ui_actions(
    content: str,
    *,
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
) -> list[dict[str, Any]]:
    normalized = (sanitize_text(content, max_length=400) or "").lower()
    semantic_page_context = _browser_semantic_page_context(browser_context)
    page_kind = str(semantic_page_context.get("page_kind") or "generic")
    semantic_actions = [item for item in _browser_semantic_actions(browser_context) if item]
    tokens: list[str] = []
    if any(marker in normalized for marker in ("事件", "日志")):
        tokens.extend(["事件", "日志", "event"])
    if "详情" in normalized:
        tokens.extend(["详情", "detail"])
    if any(marker in normalized for marker in ("展开", "打开", "切到", "定位", "滚动")):
        tokens.extend(["展开", "打开", "定位", "scroll"])
    if "风险" in normalized:
        tokens.extend(["风险", "risk"])
    if "runner" in normalized or "runner" in normalized.lower():
        tokens.extend(["runner"])
    if "修复" in normalized:
        tokens.extend(["修复", "remediation"])
    if "搜索" in normalized or "筛选" in normalized:
        tokens.extend(["搜索", "筛选", "search"])

    prioritized: list[dict[str, Any]] = []
    for action in semantic_actions:
        if _semantic_action_matches(action, tokens):
            prioritized.append(action)

    if not prioritized and page_kind == "task_detail" and any(marker in normalized for marker in ("事件", "日志", "失败原因")):
        prioritized = [item for item in semantic_actions if "scroll" in str(item.get("semantic_action_id") or "") and "事件" in str(item.get("label") or "")]
    if not prioritized and page_kind == "asset_detail" and "风险" in normalized:
        prioritized = [item for item in semantic_actions if "scroll" in str(item.get("semantic_action_id") or "") and "风险" in str(item.get("label") or "")]
    if not prioritized and page_kind == "remediation_asset_detail" and ("runner" in normalized or "修复" in normalized):
        prioritized = [item for item in semantic_actions if _semantic_action_matches(item, ["runner", "修复"])]
    if not prioritized:
        return []

    results: list[dict[str, Any]] = []
    for item in prioritized[:MAX_UI_ACTION_BATCH]:
        target_entity = item.get("target_entity") if isinstance(item.get("target_entity"), dict) else {}
        results.append(
            _normalize_ui_action(
                {
                    "action_type": item.get("action_type") or "click",
                    "semantic_action_id": item.get("semantic_action_id"),
                    "target_node_id": item.get("node_id"),
                    "selector": item.get("selector"),
                    "href": item.get("href"),
                    "text_contains": item.get("text_contains") or item.get("label"),
                    "label_contains": item.get("label"),
                    "expected_page_kind": page_kind,
                    "expected_section": item.get("section_id"),
                    "expected_entity": target_entity or _working_context_primary_target(working_context),
                    "rationale": f"根据当前页面语义动作直接推进：{item.get('label')}",
                    "retryable": True,
                }
            )
        )
    return [item for item in results if item]


def _heuristic_read_tool_calls(
    content: str,
    *,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
) -> list[dict[str, Any]]:
    normalized = sanitize_text(content, max_length=400) or ""
    semantic_page_context = _browser_semantic_page_context(browser_context)
    page_kind = str(semantic_page_context.get("page_kind") or "")
    task_id = _sanitize_line(str(working_context.get("task_id") or page_context.get("task_id") or ""), max_length=64)
    asset_id = _sanitize_line(str(working_context.get("asset_id") or page_context.get("asset_id") or ""), max_length=64)
    finding_id = _sanitize_line(str(working_context.get("finding_id") or page_context.get("finding_id") or ""), max_length=64)
    read_tools: list[dict[str, Any]] = []

    if task_id and any(marker in normalized for marker in ("失败原因", "事件", "日志")):
        read_tools.append({"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 12}})
        read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
    elif task_id and any(marker in normalized for marker in ("详情", "状态", "阶段")):
        read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})

    if asset_id and any(marker in normalized for marker in ("风险", "risk")):
        read_tools.append({"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "limit": 10}})
    elif asset_id and any(marker in normalized for marker in ("runner", "修复状态", "修复摘要")):
        read_tools.append({"tool_name": "get_remediation_asset", "arguments": {"asset_id": asset_id}})
    elif asset_id and page_kind == "asset_detail" and any(marker in normalized for marker in ("详情", "资产")):
        read_tools.append({"tool_name": "get_asset_detail", "arguments": {"asset_id": asset_id}})

    if finding_id and any(marker in normalized for marker in ("修复模板", "模板", "修复方案")):
        read_tools.append({"tool_name": "get_risk_remediation_template", "arguments": {"finding_id": finding_id}})
    elif finding_id and "风险" in normalized:
        read_tools.append({"tool_name": "get_risk_detail", "arguments": {"finding_id": finding_id}})

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in read_tools:
        signature = (
            str(item.get("tool_name") or ""),
            json.dumps(item.get("arguments") if isinstance(item.get("arguments"), dict) else {}, ensure_ascii=False, sort_keys=True),
        )
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(item)
        if len(deduped) >= 3:
            break
    return deduped


def _heuristic_low_risk_actions(
    content: str,
    *,
    user: User,
    page_context: dict[str, Any],
    working_context: dict[str, Any],
) -> list[dict[str, Any]]:
    if _normalize_role(user.role) != "admin":
        return []
    normalized = sanitize_text(content, max_length=400, single_line=True) or ""
    actions: list[dict[str, Any]] = []
    cidr = _extract_cidr_target(normalized)
    asset_id = _sanitize_line(str(working_context.get("asset_id") or page_context.get("asset_id") or ""), max_length=64)
    if "扫描" in normalized and cidr:
        actions.append(
            {
                "action_type": "create_discovery_job",
                "title": f"扫描网段 {cidr}",
                "reason": "用户明确要求扫描指定网段",
                "params": {"cidr": cidr},
            }
        )
    if asset_id and any(marker in normalized for marker in ("风险验证", "验证风险")):
        actions.append(
            {
                "action_type": "verify_asset_risks",
                "title": f"验证资产 {asset_id} 风险",
                "reason": "用户明确要求执行风险验证",
                "params": {"asset_id": asset_id},
            }
        )
    if asset_id and any(marker in normalized.lower() for marker in ("安装 runner", "安装runner", "重装 runner", "重装runner")):
        actions.append(
            {
                "action_type": "install_runner",
                "title": f"为资产 {asset_id} 安装 Runner",
                "reason": "用户明确要求安装 Host Runner",
                "params": {"asset_id": asset_id},
            }
        )
    return sanitize_json_value(actions)[:3]


def _build_internal_scan_clarifying_decision(
    *,
    user_content: str,
    page_context: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    tool_traces: list[dict[str, Any]],
) -> _AgentModelDecision | None:
    if dialog_state:
        return None
    normalized = sanitize_text(user_content, max_length=400) or ""
    if _contains_execution_intent(normalized):
        return None
    if not _extract_cidr_target(normalized):
        return None
    if not any(marker in normalized for marker in ("分析", "漏洞", "风险", "资产")):
        return None
    cidr = _find_empty_asset_lookup_cidr(normalized, tool_traces)
    if not cidr:
        return None
    question = _build_internal_discovery_followup_question(cidr)
    return _AgentModelDecision(
        reply_markdown=question,
        conversation_state="clarifying",
        objective=f"先扫描网段 {cidr} 再继续分析漏洞",
        clarifying_question=question,
        dialog_state_update=_build_internal_discovery_followup_state(
            cidr=cidr,
            user_content=user_content,
            working_context=working_context,
            page_context=page_context,
        ),
        stop_reason="internal_discovery_followup",
    )


def _decision_has_agent_progress(decision: _AgentModelDecision, *, tool_traces: list[dict[str, Any]]) -> bool:
    return bool(
        tool_traces
        or decision.read_tool_calls
        or decision.ui_actions
        or decision.auto_execute_actions
        or decision.proposed_write_actions
        or decision.conversation_state == "clarifying"
        or decision.stop_reason
    )


def _single_result_item(result: dict[str, Any]) -> dict[str, Any]:
    items = result.get("items") if isinstance(result.get("items"), list) else []
    if len(items) != 1:
        return {}
    item = items[0]
    return item if isinstance(item, dict) else {}


def _focus_target_from_tool_trace(trace: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(trace, dict) or not trace.get("ok"):
        return {}
    tool_name = str(trace.get("tool_name") or "").strip()
    arguments = trace.get("arguments") if isinstance(trace.get("arguments"), dict) else {}
    result = trace.get("result") if isinstance(trace.get("result"), dict) else {}
    source = f"tool:{tool_name}"

    if tool_name == "get_asset_detail":
        return _normalize_focus_target(
            {
                "asset_id": result.get("asset_id") or result.get("id") or arguments.get("asset_id"),
                "source": source,
            }
        )

    if tool_name in {"list_asset_risks", "get_remediation_asset"}:
        return _normalize_focus_target(
            {
                "asset_id": result.get("asset_id") or result.get("id") or arguments.get("asset_id"),
                "source": source,
            }
        )

    if tool_name in {"get_risk_detail", "get_risk_remediation_template"}:
        asset = result.get("asset") if isinstance(result.get("asset"), dict) else {}
        return _normalize_focus_target(
            {
                "finding_id": result.get("finding_id") or result.get("id") or arguments.get("finding_id"),
                "asset_id": result.get("asset_id") or asset.get("id"),
                "source": source,
            }
        )

    if tool_name in {"get_task_detail", "get_task_events"}:
        asset_id = None
        if str(result.get("scope_type") or "").strip().lower() == "asset":
            asset_id = result.get("scope_id")
        return _normalize_focus_target(
            {
                "task_id": result.get("task_id") or result.get("id") or arguments.get("task_id"),
                "asset_id": asset_id,
                "source": source,
            }
        )

    if tool_name == "list_risks":
        argument_asset_id = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=64) or None
        if argument_asset_id:
            return _normalize_focus_target({"asset_id": argument_asset_id, "source": source})
        single_item = _single_result_item(result)
        return _normalize_focus_target(
            {
                "finding_id": single_item.get("finding_id") or single_item.get("id"),
                "asset_id": single_item.get("asset_id"),
                "source": source,
            }
        )

    if tool_name == "list_assets":
        single_item = _single_result_item(result)
        return _normalize_focus_target(
            {
                "asset_id": single_item.get("asset_id") or single_item.get("id"),
                "source": source,
            }
        )

    if tool_name == "list_tasks":
        single_item = _single_result_item(result)
        asset_id = None
        if str(single_item.get("scope_type") or "").strip().lower() == "asset":
            asset_id = single_item.get("scope_id")
        return _normalize_focus_target(
            {
                "task_id": single_item.get("task_id") or single_item.get("id"),
                "asset_id": asset_id,
                "source": source,
            }
        )

    if tool_name == "list_remediation_assets":
        single_item = _single_result_item(result)
        return _normalize_focus_target(
            {
                "asset_id": single_item.get("asset_id") or single_item.get("id"),
                "source": source,
            }
        )

    return {}


def _promote_resolved_targets_from_tool_traces(
    tool_traces: list[dict[str, Any]],
    working_context: dict[str, Any],
) -> dict[str, Any]:
    promoted_context = _normalize_working_context(working_context)
    for trace in tool_traces:
        target = _focus_target_from_tool_trace(trace if isinstance(trace, dict) else {})
        if target:
            promoted_context = _merge_soft_focus_context(promoted_context, target)
    return promoted_context


def _build_contract_error_clarifying_decision() -> _AgentModelDecision:
    question = "我没能稳定承接上一轮，请直接告诉我要继续看什么，例如：资产结果、风险结果或任务详情。"
    return _AgentModelDecision(
        reply_markdown=question,
        conversation_state="clarifying",
        clarifying_question="你想继续看资产结果、风险结果，还是任务详情？",
        stop_reason="contract_error_clarify",
    )


def _build_running_task_conflict_decision(*, task_id: str | None) -> _AgentModelDecision:
    normalized_task_id = _sanitize_line(str(task_id or ""), max_length=64)
    task_label = f"任务 {normalized_task_id}" if normalized_task_id else "当前任务"
    question = f"{task_label} 仍在执行。你是想继续查看任务进度，还是先中断当前任务后再切换到新的高风险操作？"
    return _AgentModelDecision(
        reply_markdown=question,
        conversation_state="clarifying",
        clarifying_question=question,
        dialog_state_update=_DialogState(
            status="awaiting_user_input",
            intent_kind="read_followup",
            question_kind="confirm",
            intent_summary=f"处理 {task_label} 与新高风险目标的冲突",
            last_agent_question=question,
            candidate_read_tools=[
                _ReadToolCall(tool_name="get_task_detail", arguments={"task_id": normalized_task_id})
            ]
            if normalized_task_id
            else [],
            targets_snapshot={
                "working_context": {
                    "task_id": normalized_task_id or None,
                    "source": "running_task_conflict",
                    "summary": task_label,
                }
            },
        ),
        followup_resolution=_FollowupResolution(status="needs_more_input", summary="当前存在运行中的任务，需要先确认是否继续跟踪"),
        stop_reason="running_task_conflict",
    )


def _content_prefers_resume_hint_read(
    content: str,
    *,
    recent_resume_hint: dict[str, Any],
) -> bool:
    normalized = sanitize_text(content, max_length=160, single_line=True) or ""
    if not normalized or not recent_resume_hint:
        return False
    if normalized in _SHORT_FOLLOWUP_AFFIRM_MARKERS:
        return True

    suggested_reply_label = sanitize_text(
        str(recent_resume_hint.get("suggested_reply_label") or ""),
        max_length=80,
        single_line=True,
    ) or ""
    normalized_compact = re.sub(r"\s+", "", normalized)
    suggested_compact = re.sub(r"\s+", "", suggested_reply_label)
    if suggested_compact and suggested_compact in normalized_compact:
        return True

    if "maintenance_window_id" in normalized.lower() or "维护窗口" in normalized:
        return False

    review_markers = ("复盘", "结果", "状态", "详情", "进度")
    resume_verbs = ("继续", "接着", "看看", "查看", "分析", "告诉我", "复盘", "看")
    return any(marker in normalized for marker in review_markers) and any(marker in normalized for marker in resume_verbs)


def _build_resume_hint_read_decision(
    *,
    content: str,
    session: AgentSession | Any | None,
    working_context: dict[str, Any],
    tool_traces: list[dict[str, Any]],
    allow_extended_resume: bool = False,
) -> _AgentModelDecision | None:
    normalized = sanitize_text(content, max_length=160, single_line=True) or ""
    recent_resume_hint = _latest_resume_hint(session)
    if not recent_resume_hint:
        return None
    if normalized not in _SHORT_FOLLOWUP_AFFIRM_MARKERS:
        if not allow_extended_resume or not _content_prefers_resume_hint_read(normalized, recent_resume_hint=recent_resume_hint):
            return None

    resume_context = _normalize_working_context(
        recent_resume_hint.get("working_context") if isinstance(recent_resume_hint.get("working_context"), dict) else {}
    )
    effective_context = _normalize_working_context(working_context)
    resume_target = _working_context_primary_target(resume_context)
    if resume_target:
        effective_context = _merge_soft_focus_context(effective_context, resume_target)

    preferred_read_tools = _dedupe_read_tool_payloads(
        recent_resume_hint.get("preferred_read_tools") if isinstance(recent_resume_hint.get("preferred_read_tools"), list) else []
    )
    if not preferred_read_tools and effective_context:
        preferred_read_tools = _default_resume_read_tools(
            kind=_sanitize_line(str(recent_resume_hint.get("kind") or ""), max_length=64),
            working_context=effective_context,
        )

    executed_signatures = {
        _read_tool_call_signature(
            str(item.get("tool_name") or ""),
            item.get("arguments") if isinstance(item.get("arguments"), dict) else {},
        )
        for item in tool_traces
        if isinstance(item, dict)
    }
    pending_read_tools = [
        item
        for item in preferred_read_tools
        if _read_tool_call_signature(
            str(item.get("tool_name") or ""),
            item.get("arguments") if isinstance(item.get("arguments"), dict) else {},
        )
        not in executed_signatures
    ]
    if not pending_read_tools:
        return None

    suggested_reply_label = sanitize_text(
        str(recent_resume_hint.get("suggested_reply_label") or ""),
        max_length=80,
        single_line=True,
    ) or "上一轮结果"
    return _AgentModelDecision(
        reply_markdown=f"我先承接上一轮结果，继续{suggested_reply_label}。",
        conversation_state="answer",
        objective=sanitize_text(content, max_length=240) or None,
        read_tool_calls=[_ReadToolCall.model_validate(item) for item in pending_read_tools],
        stop_reason="resume_hint_read",
    )


def _latest_successful_tool_result(tool_traces: list[dict[str, Any]], *, tool_name: str) -> dict[str, Any]:
    for item in reversed(tool_traces):
        if not isinstance(item, dict):
            continue
        if str(item.get("tool_name") or "").strip() != tool_name or not item.get("ok"):
            continue
        result = item.get("result") if isinstance(item.get("result"), dict) else {}
        if result:
            return result
    return {}


def _scan_asset_brief(item: dict[str, Any]) -> str:
    asset_id = _sanitize_line(str(item.get("asset_id") or item.get("id") or ""), max_length=64)
    ip = sanitize_text(str(item.get("ip") or ""), max_length=64, single_line=True) or ""
    hostname = sanitize_text(str(item.get("hostname") or ""), max_length=120, single_line=True) or ""
    os_name = sanitize_text(str(item.get("os_name") or ""), max_length=80, single_line=True) or ""
    label = ip or hostname or asset_id or "未命名资产"
    parts = [label]
    if hostname and hostname != label:
        parts.append(hostname)
    if os_name:
        parts.append(os_name)
    return " / ".join(parts)


def _format_resume_hint_brief_list(items: list[str], *, limit: int = 3) -> str:
    cleaned = [
        sanitize_text(item, max_length=120, single_line=True) or ""
        for item in items
        if sanitize_text(item, max_length=120, single_line=True)
    ]
    if not cleaned:
        return ""
    preview = "；".join(cleaned[:limit])
    remainder = len(cleaned) - min(len(cleaned), limit)
    if remainder > 0:
        return f"{preview}；另有 {remainder} 项未展开" if preview else f"另有 {remainder} 项未展开"
    return preview


def _remediation_outcome_brief(item: dict[str, Any]) -> str:
    title = sanitize_text(
        str(item.get("title") or item.get("current_title") or item.get("rule_id") or "未命名风险"),
        max_length=120,
        single_line=True,
    ) or "未命名风险"
    service_name = sanitize_text(str(item.get("service_name") or ""), max_length=64, single_line=True) or ""
    if service_name:
        return f"{title}（{service_name}）"
    return title


def _build_scan_resume_hint_summary_decision(tool_traces: list[dict[str, Any]]) -> _AgentModelDecision | None:
    assets_result = _latest_successful_tool_result(tool_traces, tool_name="list_assets")
    task_result = _latest_successful_tool_result(tool_traces, tool_name="get_task_detail")
    items = assets_result.get("items") if isinstance(assets_result.get("items"), list) else []
    if not items and not task_result:
        return None

    total = int(assets_result.get("total") or len(items))
    task_message = sanitize_text(str(task_result.get("message") or ""), max_length=180) or ""
    task_prefix = "我已接上这次扫描结果。"
    if task_message:
        task_prefix = f"{task_prefix}{task_message}。"

    if total <= 0:
        reply = (
            f"{task_prefix}\n\n当前还没有查询到该网段下的新资产。"
            "\n\n如果你愿意，我可以继续查看任务事件，或换一个更精确的网段重新分析。"
        )
        return _AgentModelDecision(
            reply_markdown=reply,
            conversation_state="answer",
            objective="分析扫描结果",
            stop_reason="resume_hint_scan_summary",
        )

    asset_lines = "；".join(_scan_asset_brief(item) for item in items[:3] if isinstance(item, dict))
    remainder = total - len([item for item in items[:3] if isinstance(item, dict)])
    if remainder > 0:
        asset_lines = f"{asset_lines}；另有 {remainder} 台未展开" if asset_lines else f"另有 {remainder} 台未展开"

    if total == 1:
        recommendation = "如果你要继续，我可以直接分析这台资产的风险和修复建议。"
    else:
        recommendation = "如果你要继续，我可以先分析其中一台资产的风险，或继续帮你查看本次扫描任务详情。"

    reply = (
        f"{task_prefix}\n\n本次扫描共关联到 {total} 台资产。"
        f"{(' 当前可见：' + asset_lines + '。') if asset_lines else ''}\n\n{recommendation}"
    )
    return _AgentModelDecision(
        reply_markdown=reply,
        conversation_state="answer",
        objective="分析扫描结果",
        stop_reason="resume_hint_scan_summary",
    )


def _build_remediation_resume_hint_summary_decision(tool_traces: list[dict[str, Any]]) -> _AgentModelDecision | None:
    task_result = _latest_successful_tool_result(tool_traces, tool_name="get_task_detail")
    remediation_session = _latest_successful_tool_result(tool_traces, tool_name="get_remediation_session")
    remediation_asset = _latest_successful_tool_result(tool_traces, tool_name="get_remediation_asset")
    if not task_result and not remediation_session:
        return None

    result_json = task_result.get("result_json") if isinstance(task_result.get("result_json"), dict) else {}
    execution = result_json.get("execution") if isinstance(result_json.get("execution"), dict) else {}
    reverify_summary = result_json.get("reverify_summary") if isinstance(result_json.get("reverify_summary"), dict) else {}
    plan = result_json.get("plan") if isinstance(result_json.get("plan"), dict) else {}
    if not plan and isinstance(remediation_session.get("plan"), dict):
        plan = remediation_session.get("plan")

    plan_steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
    step_titles = {
        _sanitize_line(str(item.get("step_id") or ""), max_length=128): sanitize_text(
            str(item.get("title") or item.get("step_id") or ""),
            max_length=120,
            single_line=True,
        )
        or ""
        for item in plan_steps
        if isinstance(item, dict) and _sanitize_line(str(item.get("step_id") or ""), max_length=128)
    }

    step_results = execution.get("step_results") if isinstance(execution.get("step_results"), list) else []
    submitted_steps = execution.get("submitted_steps") if isinstance(execution.get("submitted_steps"), list) else []
    submitted_labels: list[str] = []
    for item in submitted_steps:
        if not isinstance(item, dict):
            continue
        step_id = _sanitize_line(str(item.get("step_id") or ""), max_length=128)
        if not step_id:
            continue
        title = step_titles.get(step_id) or sanitize_text(str(item.get("title") or step_id), max_length=120, single_line=True) or step_id
        if title not in submitted_labels:
            submitted_labels.append(title)
    if not submitted_labels:
        for item in step_results:
            if not isinstance(item, dict):
                continue
            title = sanitize_text(str(item.get("title") or item.get("step_id") or ""), max_length=120, single_line=True) or ""
            if title and title not in submitted_labels:
                submitted_labels.append(title)

    success_labels = [
        sanitize_text(str(item.get("title") or item.get("step_id") or ""), max_length=120, single_line=True) or ""
        for item in step_results
        if isinstance(item, dict) and str(item.get("status") or "").strip().lower() == "success"
    ]
    success_labels = [item for item in success_labels if item]
    failed_labels = [
        sanitize_text(str(item.get("title") or item.get("step_id") or ""), max_length=120, single_line=True) or ""
        for item in step_results
        if isinstance(item, dict) and str(item.get("status") or "").strip().lower() in {"failed", "blocked"}
    ]
    failed_labels = [item for item in failed_labels if item]

    targeted_outcomes = result_json.get("targeted_finding_outcomes") if isinstance(result_json.get("targeted_finding_outcomes"), list) else []
    closed_outcomes = [
        _remediation_outcome_brief(item)
        for item in targeted_outcomes
        if isinstance(item, dict) and str(item.get("status") or "").strip().lower() == "closed"
    ]
    open_outcomes = [
        _remediation_outcome_brief(item)
        for item in targeted_outcomes
        if isinstance(item, dict) and str(item.get("status") or "").strip().lower() == "open"
    ]
    asset_findings = remediation_asset.get("findings") if isinstance(remediation_asset.get("findings"), list) else []
    open_asset_findings = [
        _remediation_outcome_brief(item)
        for item in asset_findings
        if isinstance(item, dict) and str(item.get("status") or "").strip().lower() == "open"
    ]

    targeted_total = int(reverify_summary.get("targeted_target_count") or len(targeted_outcomes))
    closed_total = int(reverify_summary.get("closed_target_count") or len(closed_outcomes))
    open_total = int(reverify_summary.get("open_target_count") or len(open_outcomes))
    other_open_total_raw = reverify_summary.get("other_open_finding_count")
    other_open_total = int(other_open_total_raw) if isinstance(other_open_total_raw, int) else None
    business_blockers = [
        sanitize_text(str(item), max_length=160, single_line=True) or ""
        for item in (reverify_summary.get("business_blockers") or [])
        if sanitize_text(str(item), max_length=160, single_line=True)
    ]
    business_status = _sanitize_line(
        str(result_json.get("business_status") or execution.get("business_status") or ""),
        max_length=64,
    ).lower()
    execution_status = _sanitize_line(
        str(result_json.get("execution_status") or execution.get("execution_status") or ""),
        max_length=64,
    ).lower()
    task_timing = task_result.get("timing") if isinstance(task_result.get("timing"), dict) else {}
    stage_name = sanitize_text(
        str(execution.get("stage_name") or task_timing.get("current_stage_name") or ""),
        max_length=120,
        single_line=True,
    ) or ""
    task_message = sanitize_text(str(task_result.get("message") or ""), max_length=180) or ""
    task_status = _sanitize_line(str(task_result.get("status") or ""), max_length=64).lower()
    success_count = int(execution.get("success_count") or len(success_labels))
    failed_count = int(execution.get("failed_count") or 0)
    blocked_count = int(execution.get("blocked_count") or 0)
    skipped_count = int(execution.get("skipped_count") or 0)
    preview_only = execution_status == "preview_only" or _sanitize_line(
        str(execution.get("execution_mode") or ""),
        max_length=32,
    ).lower() == "dry_run"
    plan_blocked_reasons = [
        sanitize_text(str(item), max_length=160, single_line=True) or ""
        for item in (plan.get("blocked_reasons") or [])
        if sanitize_text(str(item), max_length=160, single_line=True)
    ]

    section_one = []
    if stage_name:
        section_one.append(f"- 阶段：{stage_name}")
    if submitted_labels:
        section_one.append(f"- 步骤：{_format_resume_hint_brief_list(submitted_labels, limit=4)}")
    elif task_message:
        section_one.append(f"- 执行摘要：{task_message}")
    else:
        section_one.append("- 执行摘要：当前只拿到修复状态，未拿到更细的步骤明细。")

    section_two = []
    if preview_only:
        section_two.append("- 本轮为预演，未执行任何主机变更。")
    else:
        counts_line = f"- 成功 {success_count} 步，失败 {failed_count} 步，阻塞 {blocked_count} 步，跳过 {skipped_count} 步。"
        section_two.append(counts_line)
    if success_labels:
        section_two.append(f"- 已成功：{_format_resume_hint_brief_list(success_labels, limit=4)}")
    elif task_status == TaskExecutionStatus.SUCCESS.value and task_message:
        section_two.append(f"- 任务结果：{task_message}")
    if failed_labels:
        section_two.append(f"- 异常步骤：{_format_resume_hint_brief_list(failed_labels, limit=3)}")

    section_three = []
    if targeted_total > 0:
        section_three.append(f"- 本轮目标风险 {targeted_total} 条，已闭环 {closed_total} 条。")
    if closed_outcomes:
        section_three.append(f"- 已闭环项：{_format_resume_hint_brief_list(closed_outcomes, limit=3)}")
    elif targeted_total > 0 and closed_total <= 0:
        section_three.append("- 当前还没有确认闭环的目标风险。")
    else:
        section_three.append("- 当前没有拿到可确认闭环的目标风险明细。")

    section_four = []
    if open_total > 0:
        section_four.append(f"- 目标风险仍未闭环 {open_total} 条。")
    else:
        section_four.append("- 当前未看到仍未闭环的目标风险。")
    if open_outcomes:
        section_four.append(f"- 未闭环项：{_format_resume_hint_brief_list(open_outcomes, limit=3)}")
    elif open_total > 0 and open_asset_findings:
        section_four.append(f"- 当前开放风险示例：{_format_resume_hint_brief_list(open_asset_findings, limit=3)}")
    if other_open_total is not None and other_open_total > 0:
        section_four.append(f"- 未纳入本轮的其余开放风险 {other_open_total} 条。")
    if business_blockers:
        section_four.append(f"- 业务阻塞：{_format_resume_hint_brief_list(business_blockers, limit=2)}")

    next_steps: list[str] = []
    if preview_only:
        next_steps.append("先确认维护窗口、变更单和执行边界，再发起正式修复。")
    elif business_status == "pending_reverify":
        next_steps.append("等待自动复验完成后再看最终闭环结果。")
    elif business_status == "verified_closed":
        next_steps.append("可以进入归档或抽样确认，不必继续扩大修复范围。")
    elif business_status == "verified_partial":
        next_steps.append("优先处理仍开放的目标风险，再补一次复验。")
    elif business_status == "verified_failed" or failed_count > 0 or task_status == TaskExecutionStatus.FAILURE.value:
        next_steps.append("先定位失败步骤或复验异常，再决定重试、回滚或切换成人工处置。")
    else:
        next_steps.append("建议继续核对当前修复会话与任务明细，确认是否还有未收敛项。")
    if plan_blocked_reasons:
        next_steps.append(f"需要先补齐阻塞条件：{_format_resume_hint_brief_list(plan_blocked_reasons, limit=2)}。")

    suggest_reverify = False
    reverify_reason = "当前结果已经稳定，不需要再发起复验。"
    if preview_only:
        reverify_reason = "当前仅完成预演，需先正式执行后再复验。"
    elif business_status in {"pending_reverify", "verified_partial", "verified_failed"}:
        suggest_reverify = True
        if business_status == "pending_reverify":
            reverify_reason = "系统已进入复验阶段，建议等待复验完成并再次确认。"
        elif business_status == "verified_partial":
            reverify_reason = "仍有目标风险未闭环，补修后应再次复验。"
        else:
            reverify_reason = "本轮执行或复验失败，修正后需要重新复验。"

    suggest_manual = False
    manual_reason = "当前自动链路可以继续收敛，不需要额外人工介入。"
    if preview_only:
        suggest_manual = True
        manual_reason = "正式执行前需要人工确认维护窗口、变更单或审批条件。"
    elif business_status == "verified_partial" and business_blockers:
        suggest_manual = True
        manual_reason = "存在业务阻塞，建议人工确认外部条件后再继续。"
    elif business_status == "verified_failed" or failed_count > 0 or task_status == TaskExecutionStatus.FAILURE.value:
        suggest_manual = True
        manual_reason = "已出现执行失败，建议人工定位失败点并决定是否回滚。"

    if business_status == "verified_closed":
        report_intro = "我已把这次自动修复整理成最终复盘报告。"
        conclusion = "最终结论：本轮目标风险已经修复完毕，可以直接输出最终修复报告。"
        objective = "输出最终修复报告"
        stop_reason = "resume_hint_remediation_report"
    else:
        report_intro = "我已整理这次自动修复的执行结果，但当前还不能输出最终修复报告。"
        if business_status == "pending_reverify":
            conclusion = "当前结论：系统仍在复验目标风险，尚未达到“修复完毕”的状态。"
        elif business_status == "verified_partial":
            conclusion = "当前结论：仍有目标风险未闭环，尚未达到“修复完毕”的状态。"
        elif business_status == "verified_failed":
            conclusion = "当前结论：本轮执行或复验失败，尚未达到“修复完毕”的状态。"
        else:
            conclusion = "当前结论：还没有拿到明确的闭环证据，暂时不能认定为“修复完毕”。"
        objective = "分析修复结果"
        stop_reason = "resume_hint_remediation_gap_report"
    if task_message:
        report_intro = f"{report_intro}{task_message}。"
    reply = "\n\n".join(
        [
            report_intro,
            conclusion,
            "1. 本轮执行了哪些步骤\n" + "\n".join(section_one),
            "2. 哪些成功\n" + "\n".join(section_two),
            "3. 哪些风险已闭环\n" + "\n".join(section_three),
            "4. 哪些仍未闭环\n" + "\n".join(section_four),
            "5. 下一步建议\n" + "\n".join(f"- {item}" for item in next_steps),
            "6. 是否建议再复验 / 人工介入\n"
            + f"- 建议再复验：{'是' if suggest_reverify else '否'}。{reverify_reason}\n"
            + f"- 建议人工介入：{'是' if suggest_manual else '否'}。{manual_reason}",
        ]
    )
    return _AgentModelDecision(
        reply_markdown=reply,
        conversation_state="answer",
        objective=objective,
        stop_reason=stop_reason,
    )


def _build_asset_risk_summary_decision(
    *,
    decision: _AgentModelDecision,
    tool_traces: list[dict[str, Any]],
) -> _AgentModelDecision | None:
    if _sanitize_line(str(decision.stop_reason or ""), max_length=64) != "playbook_analyze_asset_risks":
        return None

    asset_result = _latest_successful_tool_result(tool_traces, tool_name="get_asset_detail")
    risks_result = _latest_successful_tool_result(tool_traces, tool_name="list_asset_risks")
    risk_items = risks_result.get("items") if isinstance(risks_result.get("items"), list) else []
    if not asset_result and not risks_result:
        return None

    asset_id = _sanitize_line(str(asset_result.get("asset_id") or risks_result.get("asset_id") or ""), max_length=64) or "当前资产"
    ip = sanitize_text(str(asset_result.get("ip") or ""), max_length=64, single_line=True) or ""
    hostname = sanitize_text(str(asset_result.get("hostname") or ""), max_length=120, single_line=True) or ""
    os_name = sanitize_text(str(asset_result.get("os_name") or ""), max_length=80, single_line=True) or ""
    status = sanitize_text(str(asset_result.get("status") or ""), max_length=32, single_line=True) or ""
    ports = asset_result.get("ports") if isinstance(asset_result.get("ports"), list) else []
    open_ports = [
        item
        for item in ports
        if isinstance(item, dict) and str(item.get("state") or "").strip().lower() == "open"
    ]

    risk_total = int(risks_result.get("total") or len(risk_items))
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in risk_items:
        if not isinstance(item, dict):
            continue
        severity = _sanitize_line(str(item.get("severity") or ""), max_length=16).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    top_risks = []
    for severity in ("critical", "high", "medium", "low"):
        for item in risk_items:
            if not isinstance(item, dict):
                continue
            if _sanitize_line(str(item.get("severity") or ""), max_length=16).lower() != severity:
                continue
            title = sanitize_text(str(item.get("title") or ""), max_length=120, single_line=True) or "未命名风险"
            rule_id = sanitize_text(str(item.get("rule_id") or ""), max_length=64, single_line=True) or ""
            service_name = sanitize_text(str(item.get("service_name") or ""), max_length=64, single_line=True) or ""
            detail = title
            if rule_id:
                detail = f"{detail}（{rule_id}）"
            if service_name:
                detail = f"{detail} / {service_name}"
            top_risks.append(detail)
            if len(top_risks) >= 3:
                break
        if len(top_risks) >= 3:
            break

    section_one = [f"- 资产标识：{asset_id}"]
    if ip:
        section_one.append(f"- IP：{ip}")
    if hostname:
        section_one.append(f"- 主机名：{hostname}")
    if os_name:
        section_one.append(f"- 系统：{os_name}")
    if status:
        section_one.append(f"- 当前状态：{status}")
    if open_ports:
        port_preview = "、".join(str(item.get("port")) for item in open_ports[:5] if item.get("port") is not None)
        remainder = len(open_ports) - len(open_ports[:5])
        if remainder > 0 and port_preview:
            port_preview = f"{port_preview} 等 {len(open_ports)} 个开放端口"
        elif port_preview:
            port_preview = f"{port_preview}（共 {len(open_ports)} 个开放端口）"
        if port_preview:
            section_one.append(f"- 开放端口：{port_preview}")

    section_two = [f"- 当前开放风险共 {risk_total} 条。"]
    severity_line = " / ".join(
        [
            f"严重 {severity_counts['critical']}",
            f"高危 {severity_counts['high']}",
            f"中危 {severity_counts['medium']}",
            f"低危 {severity_counts['low']}",
        ]
    )
    section_two.append(f"- 风险分布：{severity_line}")
    if top_risks:
        section_two.append(f"- 优先关注：{_format_resume_hint_brief_list(top_risks, limit=3)}")
    elif risk_total <= 0:
        section_two.append("- 当前没有查询到开放风险。")

    section_three: list[str] = []
    if severity_counts["critical"] > 0 or severity_counts["high"] > 0:
        section_three.append("- 建议先处理严重和高危风险，再看中低危项。")
    elif risk_total > 0:
        section_three.append("- 当前以中低危风险为主，可以按服务暴露面和修复成本排序处理。")
    else:
        section_three.append("- 当前没有开放风险，可以转去查看最近验证结果或补充更细的审计范围。")
    if risk_total > len(risk_items):
        section_three.append(f"- 当前界面只展开了前 {len(risk_items)} 条风险，若需要我可以继续逐条展开。")
    else:
        section_three.append("- 如果你要继续，我可以直接挑出最值得优先处理的几条风险。")

    reply = "\n\n".join(
        [
            f"我已读完资产 {asset_id} 的详情和风险列表，给你一个确定性结论。",
            "1. 资产概况\n" + "\n".join(section_one),
            "2. 风险概览\n" + "\n".join(section_two),
            "3. 下一步建议\n" + "\n".join(section_three),
        ]
    )
    return _AgentModelDecision(
        reply_markdown=reply,
        conversation_state="answer",
        objective="分析资产风险",
        stop_reason="playbook_asset_risk_summary",
    )


def _build_resume_hint_summary_decision(
    *,
    session: AgentSession | Any | None,
    tool_traces: list[dict[str, Any]],
) -> _AgentModelDecision | None:
    recent_resume_hint = _latest_resume_hint(session)
    resume_kind = _sanitize_line(str(recent_resume_hint.get("kind") or ""), max_length=64)
    if resume_kind == "post_scan_analysis":
        return _build_scan_resume_hint_summary_decision(tool_traces)
    if resume_kind in {
        "post_remediation_review",
        "post_remediation_status",
        "post_remediation_gap_analysis",
        "post_remediation_failure_analysis",
    }:
        return _build_remediation_resume_hint_summary_decision(tool_traces)
    return None


def _build_short_resume_fallback_decision(
    *,
    content: str,
    session: AgentSession | Any | None,
    working_context: dict[str, Any],
    tool_traces: list[dict[str, Any]],
) -> _AgentModelDecision | None:
    normalized = sanitize_text(content, max_length=80, single_line=True) or ""
    if normalized not in _SHORT_FOLLOWUP_AFFIRM_MARKERS:
        return None

    resume_decision = _build_resume_hint_read_decision(
        content=content,
        session=session,
        working_context=working_context,
        tool_traces=tool_traces,
    )
    if resume_decision is not None:
        return resume_decision

    return _build_contract_error_clarifying_decision()


def _build_action_first_fallback_decision(
    *,
    content: str,
    user: User,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
    session: AgentSession | Any | None = None,
    tool_traces: list[dict[str, Any]] | None = None,
) -> _AgentModelDecision | None:
    resume_fallback = _build_short_resume_fallback_decision(
        content=content,
        session=session,
        working_context=working_context,
        tool_traces=tool_traces or [],
    )
    if resume_fallback is not None:
        return resume_fallback
    objective = _build_current_objective(content, dialog_state=dialog_state, followup_hint=followup_hint)
    objective_kind = str(objective.get("objective_kind") or "ask")
    if objective_kind == "ask":
        return None
    if objective_kind in {"navigate", "inspect"}:
        ui_actions = _candidate_semantic_ui_actions(content, browser_context=browser_context, working_context=working_context)
        if ui_actions:
            return _AgentModelDecision(
                reply_markdown="我先根据当前页面语义执行站内动作，再继续推进当前目标。",
                conversation_state="answer",
                objective=objective.get("summary"),
                ui_actions=[_UIAction.model_validate(item) for item in ui_actions],
                stop_reason="action_first_ui",
            )
        read_tool_calls = _heuristic_read_tool_calls(
            content,
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
        )
        if read_tool_calls:
            return _AgentModelDecision(
                reply_markdown="我先读取相关平台详情，再继续回答。",
                conversation_state="answer",
                objective=objective.get("summary"),
                read_tool_calls=[_ReadToolCall.model_validate(item) for item in read_tool_calls],
                stop_reason="action_first_read",
            )
    if objective_kind == "operate_low_risk" and allow_auto_execute_actions:
        actions = _heuristic_low_risk_actions(content, user=user, page_context=page_context, working_context=working_context)
        if actions:
            return _AgentModelDecision(
                reply_markdown="我已识别到明确的低风险执行意图，先按平台能力直接推进。",
                conversation_state="answer",
                objective=objective.get("summary"),
                auto_execute_actions=[_ProposedWriteAction.model_validate(item) for item in actions],
                stop_reason="action_first_auto_execute",
            )
    if objective_kind == "operate_high_risk" and allow_write_plans:
        read_tool_calls = _heuristic_read_tool_calls(
            content,
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
        )
        if read_tool_calls:
            return _AgentModelDecision(
                reply_markdown="我先补齐当前对象和平台状态，再为高风险动作形成待确认计划。",
                conversation_state="answer",
                objective=objective.get("summary"),
                read_tool_calls=[_ReadToolCall.model_validate(item) for item in read_tool_calls],
                stop_reason="prepare_high_risk_plan",
            )
    return None


def _build_preflight_clarification(
    content: str,
    *,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
) -> str | None:
    normalized_content = sanitize_text(content, max_length=500) or ""
    asset_id = str(working_context.get("asset_id") or "").strip()
    finding_id = str(working_context.get("finding_id") or "").strip()
    task_id = str(working_context.get("task_id") or "").strip()

    if _content_mentions_current_object(normalized_content) and not any((asset_id, finding_id, task_id)):
        return "我还无法确认你指的是哪一个对象。请告诉我是某台资产、某条风险，还是某个任务。"

    if _contains_execution_intent(normalized_content) and "扫描" in normalized_content and not any(token in normalized_content for token in ("/", "cidr", "网段", "10.", "172.", "192.")) and not asset_id:
        return "你想让我执行扫描，但我还不知道目标范围。请直接告诉我要扫描的网段 CIDR，或先打开目标资产页面。"

    if _contains_execution_intent(normalized_content) and "修复" in normalized_content and not asset_id and not finding_id:
        return "你想让我推进修复，但当前没有明确资产或风险上下文。请告诉我要处理的资产，或先打开对应资产/修复页面。"

    if ("风险" in normalized_content or "模板" in normalized_content) and not asset_id and not finding_id and not task_id and _content_mentions_current_object(normalized_content):
        return "我需要先知道你指的是哪条风险或哪台资产，才能继续分析模板和修复方案。"

    return None


def _dialog_state_working_context(dialog_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = dialog_state if isinstance(dialog_state, dict) else {}
    targets_snapshot = payload.get("targets_snapshot") if isinstance(payload.get("targets_snapshot"), dict) else {}
    working_context = targets_snapshot.get("working_context") if isinstance(targets_snapshot.get("working_context"), dict) else {}
    return _normalize_working_context(working_context)


def _resolve_effective_working_context(
    *,
    db: Session,
    session: AgentSession,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
) -> dict[str, Any]:
    current_context = _normalize_working_context(
        session.working_context_json if isinstance(session.working_context_json, dict) else {}
    )
    recent_resume_hint = _latest_resume_hint(session)
    explicit_context = _extract_explicit_working_context(content, page_context)
    if _has_object_target(explicit_context):
        normalized_context = _canonicalize_working_context_asset_targets(
            db,
            _merge_soft_focus_context(current_context, explicit_context),
        )
        session.working_context_json = normalized_context
        return normalized_context

    effective_context = current_context
    reply_kind = str(followup_hint.get("reply_kind") or "").strip().lower()
    if dialog_state and reply_kind in {"affirm", "short_value", "unknown"}:
        snapshot_target = _working_context_primary_target(_dialog_state_working_context(dialog_state))
        if snapshot_target:
            effective_context = _merge_soft_focus_context(effective_context, snapshot_target)

    effective_context = _apply_followup_values_to_working_context(
        effective_context,
        followup_hint,
        dialog_state=dialog_state,
    )

    should_apply_resume_context = sanitize_text(content, max_length=80, single_line=True) in _SHORT_FOLLOWUP_AFFIRM_MARKERS
    if not should_apply_resume_context and recent_resume_hint:
        should_apply_resume_context = _content_prefers_resume_hint_read(content, recent_resume_hint=recent_resume_hint)

    if not _has_object_target(effective_context) and should_apply_resume_context:
        resume_context = _normalize_working_context(
            recent_resume_hint.get("working_context") if isinstance(recent_resume_hint.get("working_context"), dict) else {}
        )
        resume_target = _working_context_primary_target(resume_context)
        if resume_target:
            effective_context = _merge_soft_focus_context(effective_context, resume_target)

    if _content_mentions_current_object(content):
        page_target = _build_working_context_from_page_context(page_context, source="page_reference")
        if not _has_object_target(page_target):
            page_target = _build_working_context_from_browser_context(browser_context, source="browser_reference")
        if _has_object_target(page_target):
            normalized_context = _canonicalize_working_context_asset_targets(
                db,
                _merge_soft_focus_context(effective_context, page_target),
            )
            session.working_context_json = normalized_context
            return normalized_context

    if _has_object_target(effective_context):
        normalized_context = _canonicalize_working_context_asset_targets(db, effective_context)
        session.working_context_json = normalized_context
        return normalized_context

    return {}


def _resolve_working_context_for_message(
    *,
    db: Session,
    session: AgentSession,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any] | None = None,
    dialog_state: dict[str, Any] | None = None,
    followup_hint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _resolve_effective_working_context(
        db=db,
        session=session,
        content=content,
        page_context=page_context,
        browser_context=browser_context or {},
        dialog_state=dialog_state or {},
        followup_hint=followup_hint or {},
    )


def _extract_cidr_target(content: str) -> str | None:
    normalized = sanitize_text(content, max_length=300, single_line=True) or ""
    match = re.search(r"((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})", normalized)
    if not match:
        return None
    try:
        return normalize_cidr(match.group(0))
    except ValueError:
        return None


def _has_pending_plan(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    proposed_actions = payload.get("proposed_write_actions")
    return isinstance(proposed_actions, list) and bool(proposed_actions)


def _should_cancel_pending_plan(content: str) -> bool:
    normalized = sanitize_text(content, max_length=300, single_line=True) or ""
    markers = ("取消计划", "放弃计划", "清空计划", "不用执行", "不要执行", "取消当前计划", "先别执行")
    return any(marker in normalized for marker in markers)


def _preserve_or_reset_pending_plan(
    session: AgentSession,
    *,
    existing_pending_plan: dict[str, Any],
    preserve_existing: bool,
) -> None:
    if preserve_existing and _has_pending_plan(existing_pending_plan):
        session.status = "waiting_approval"
        session.pending_plan_json = existing_pending_plan
    else:
        session.status = "active"
        session.pending_plan_json = {}


def _clear_dialog_state(session: AgentSession) -> None:
    session.dialog_state_json = {}


def _build_preflight_dialog_state(
    *,
    question: str,
    user_content: str,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
) -> dict[str, Any]:
    candidate_write_context: dict[str, Any] = {}
    if "扫描" in user_content:
        candidate_write_context["action_type"] = "create_discovery_job"
    elif "修复" in user_content:
        candidate_write_context["intent"] = "remediation"
    return _build_dialog_state(
        question=question,
        user_content=user_content,
        working_context=working_context,
        page_context=page_context,
        candidate_write_context=candidate_write_context,
    )


def _extract_discovery_label_followup(content: str) -> tuple[bool, str | None]:
    normalized = sanitize_text(content, max_length=255, single_line=True) or ""
    if not normalized:
        return False, None
    lowered = normalized.lower()
    default_markers = ("默认标签", "沿用默认", "用默认", "默认", "不填标签", "不用标签", "空标签")
    if any(marker in normalized for marker in default_markers) or any(marker in lowered for marker in ("default label", "use default")):
        return True, None
    match = re.search(r"(?:标签|tag|label|备注)\s*(?:写成|写|填成|填|为|是|用)?\s*[:：=]?\s*[\"“]?([^\"”]+?)[\"”]?\s*$", normalized, re.IGNORECASE)
    if not match:
        return False, None
    label = sanitize_text(match.group(1).strip(" '\"“”"), max_length=255, single_line=True) or None
    return True, label


def _build_internal_discovery_followup_question(cidr: str) -> str:
    return f"未查询到 {cidr} 的现有资产。是否立即发起扫描？未指定标签时将使用默认标签。"


def _build_internal_discovery_followup_state(
    *,
    cidr: str,
    user_content: str,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
) -> _DialogState:
    question = _build_internal_discovery_followup_question(cidr)
    return _DialogState(
        status="awaiting_user_input",
        intent_kind="prepare_plan",
        question_kind="confirm",
        intent_summary=sanitize_text(user_content, max_length=300),
        last_agent_question=question,
        expected_slots=[],
        candidate_read_tools=[],
        candidate_write_context={
            "action_type": "create_discovery_job",
            "params": {"cidr": cidr},
            "optional_defaults": {"label": None},
            "allow_affirm_execute": True,
            "reason": "当前网段尚无已采集资产，需要先发起扫描任务",
        },
        targets_snapshot=_dialog_state_targets_snapshot(
            working_context=working_context,
            page_context=page_context,
            extra_targets={"cidr": cidr},
        ),
    )


def _find_empty_asset_lookup_cidr(user_content: str, tool_traces: list[dict[str, Any]]) -> str | None:
    requested_cidr = _extract_cidr_target(user_content)
    if not requested_cidr:
        return None
    for trace in tool_traces:
        if not isinstance(trace, dict) or str(trace.get("tool_name") or "") != "list_assets" or not trace.get("ok"):
            continue
        result = trace.get("result") if isinstance(trace.get("result"), dict) else {}
        total = int(result.get("total") or 0)
        items = result.get("items") if isinstance(result.get("items"), list) else []
        if total or items:
            continue
        arguments = trace.get("arguments") if isinstance(trace.get("arguments"), dict) else {}
        keyword_cidr = _extract_cidr_target(str(arguments.get("keyword") or ""))
        return keyword_cidr or requested_cidr
    return None


def _build_internal_followup_decision(
    *,
    user: User,
    user_content: str,
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
) -> _AgentModelDecision | None:
    candidate_write_context = (
        dialog_state.get("candidate_write_context") if isinstance(dialog_state.get("candidate_write_context"), dict) else {}
    )
    action_type = _sanitize_line(str(candidate_write_context.get("action_type") or ""), max_length=64)
    allow_affirm_execute = bool(candidate_write_context.get("allow_affirm_execute"))
    if action_type != "create_discovery_job" or not allow_affirm_execute:
        return None

    reply_kind = str(followup_hint.get("reply_kind") or "").strip().lower()
    extracted_values = followup_hint.get("extracted_values") if isinstance(followup_hint.get("extracted_values"), dict) else {}
    params = sanitize_json_value(candidate_write_context.get("params") if isinstance(candidate_write_context.get("params"), dict) else {})
    cidr = sanitize_text(str(extracted_values.get("cidr") or params.get("cidr") or ""), max_length=64, single_line=True) or ""
    if not cidr:
        return None

    explicit_label, label = _extract_discovery_label_followup(user_content)
    should_execute = reply_kind == "affirm" or explicit_label or bool(extracted_values.get("cidr"))
    if not should_execute:
        return None

    if not _user_can_auto_execute(user):
        return _AgentModelDecision(
            reply_markdown="当前账号不是管理员，不能自动执行扫描任务；如需继续请由管理员在相同上下文下操作。",
            conversation_state="answer",
            objective=f"扫描网段 {cidr}",
            stop_reason="internal_discovery_followup_no_permission",
        )

    action_params: dict[str, Any] = {"cidr": cidr}
    if explicit_label and label:
        action_params["label"] = label
    return _AgentModelDecision(
        reply_markdown=f"已收到确认，我会先为 {cidr} 发起扫描，并在任务启动后继续给出下一步建议。",
        conversation_state="answer",
        objective=f"扫描网段 {cidr}",
        auto_execute_actions=[
            _ProposedWriteAction(
                action_type="create_discovery_job",
                title=f"扫描网段 {cidr}",
                reason="用户已确认先扫描该网段，再继续分析漏洞。",
                params=action_params,
            )
        ],
        stop_reason="internal_discovery_followup_execute",
    )


def _build_dialog_state_from_model_decision(
    *,
    decision: _AgentModelDecision,
    user_content: str,
    working_context: dict[str, Any],
    page_context: dict[str, Any],
) -> dict[str, Any]:
    if decision.dialog_state_update is not None:
        normalized = _normalize_dialog_state(decision.dialog_state_update.model_dump(mode="json"))
        if normalized:
            return normalized
    question = decision.clarifying_question or decision.reply_markdown
    if not question:
        return {}
    return _build_dialog_state(
        question=question,
        user_content=user_content,
        working_context=working_context,
        page_context=page_context,
        candidate_read_tools=[item.model_dump(mode="json") for item in decision.read_tool_calls],
    )


def _runtime_provider_mode() -> str:
    return read_runtime_env_value("LLM_PROVIDER", str(settings.LLM_PROVIDER or "mock")).strip().lower() or "mock"


def _haor_reply_rewrite_enabled() -> bool:
    raw = read_runtime_env_value(
        "HAOR_REPLY_REWRITE_ENABLED",
        "true" if getattr(settings, "HAOR_REPLY_REWRITE_ENABLED", False) else "false",
    )
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _build_runtime_provider(
    *,
    wire_api_override: str | None = None,
    chat_json_mode: bool = False,
):
    model = read_runtime_env_value("LLM_MODEL", str(settings.LLM_MODEL or "gpt-4o-mini"))
    base_url = read_runtime_env_value("LLM_BASE_URL", str(settings.LLM_BASE_URL or ""))
    wire_api = read_runtime_env_value("LLM_WIRE_API", str(settings.LLM_WIRE_API or "responses"))
    timeout_seconds = int(read_runtime_env_value("LLM_TIMEOUT_SECONDS", str(settings.LLM_TIMEOUT_SECONDS or 60)) or 60)
    api_key = read_runtime_env_value("LLM_API_KEY", str(settings.LLM_API_KEY or ""))
    return build_provider(
        provider_name=_runtime_provider_mode(),
        model=model,
        base_url=base_url,
        wire_api=wire_api_override or wire_api,
        timeout_seconds=timeout_seconds,
        api_key=api_key,
        chat_json_mode=chat_json_mode,
        fallback_to_mock=False,
    )


def _extract_upstream_error_detail(response: httpx.Response) -> str:
    raw_text = response.text.strip()
    normalized_text = re.sub(r"\s+", " ", raw_text)
    if "<html" in raw_text.lower() or "<!doctype html" in raw_text.lower():
        title_match = re.search(r"<title>\s*([^<]+)\s*</title>", raw_text, re.IGNORECASE)
        title = re.sub(r"\s+", " ", str(title_match.group(1) if title_match else "")).strip()
        if "cloudflare" in raw_text.lower() and "bad gateway" in raw_text.lower():
            return f"上游返回 Cloudflare 错误页（{title or '502 Bad gateway'}），说明目标模型网关当前不可用"
        return f"上游返回 HTML 错误页（{title or '未知页面'}），请检查 Base URL 或网关状态"
    try:
        payload = response.json()
    except Exception:
        return normalized_text[:300]
    if isinstance(payload, dict):
        for key in ("error", "detail", "message"):
            value = payload.get(key)
            if isinstance(value, dict):
                nested = value.get("message")
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
            if isinstance(value, str) and value.strip():
                return value.strip()
    return normalized_text[:300]


def _humanize_ai_error(exc: Exception) -> str:
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, httpx.TimeoutException):
        return "AI 模型请求超时，请检查模型地址、网络连通性或超时设置"
    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        detail = _extract_upstream_error_detail(exc.response)
        if status_code in {401, 403}:
            return f"AI 模型鉴权失败：{detail}" if detail else "AI 模型鉴权失败，请检查当前设置中的 API Key"
        if status_code == 404:
            return f"AI 模型接口地址不可用：{detail}" if detail else "AI 模型接口地址不可用，请检查 Base URL 或协议类型"
        if status_code >= 500:
            return f"AI 模型服务异常：{detail}" if detail else "AI 模型服务异常，请稍后重试"
        return f"AI 模型拒绝了请求：{detail or status_code}"
    if isinstance(exc, httpx.RequestError):
        return "无法连接到当前 AI 模型服务，请检查 Base URL 和网络连通性"
    return sanitize_text(str(exc), max_length=300) or "AI 模型调用失败"


def _classify_agent_service_error(
    exc: Exception,
    *,
    session_id: str | None,
    stage: str,
) -> AgentServiceError:
    if isinstance(exc, AgentServiceError):
        return exc
    if _is_model_decision_contract_error(exc):
        return AgentBadRequestError(
            "我没能稳定承接上一轮，请直接告诉我要继续看什么",
            session_id=session_id,
            stage=stage,
        )
    if isinstance(exc, httpx.HTTPError):
        return AgentUpstreamError(_humanize_ai_error(exc), session_id=session_id, stage=stage)
    if isinstance(exc, LookupError):
        return AgentNotFoundError(
            sanitize_text(str(exc), max_length=300) or "请求的智能体对象不存在",
            session_id=session_id,
            stage=stage,
        )
    detail = sanitize_text(str(exc), max_length=300) or "haor 请求失败"
    if isinstance(exc, PermissionError):
        return AgentPermissionDeniedError(detail, session_id=session_id, stage=stage)
    if isinstance(exc, ValueError):
        return AgentBadRequestError(detail, session_id=session_id, stage=stage)
    if isinstance(exc, RuntimeError):
        lowered = detail.lower()
        if any(marker in detail for marker in ("资产不存在", "风险不存在", "任务不存在", "规则不存在", "子任务不存在")):
            return AgentNotFoundError(detail, session_id=session_id, stage=stage)
        if "not found" in lowered:
            return AgentNotFoundError(detail, session_id=session_id, stage=stage)
        if any(
            marker in detail
            for marker in (
                "当前没有可继续的 haor 会话",
                "当前没有待批准的智能体动作计划",
                "当前待批准计划为空或不受支持",
                "当前待确认计划不存在",
                "当前待确认计划已失效",
                "已达到站内代理动作上限",
            )
        ):
            return AgentConflictError(detail, session_id=session_id, stage=stage)
        if "权限" in detail and "管理员" in detail:
            return AgentPermissionDeniedError(detail, session_id=session_id, stage=stage)
        return AgentBadRequestError(detail, session_id=session_id, stage=stage)
    return AgentBadRequestError(detail, session_id=session_id, stage=stage)


def translate_agent_service_exception(
    exc: Exception,
    *,
    session_id: str | None = None,
    stage: str = "unknown",
) -> AgentServiceError:
    return _classify_agent_service_error(exc, session_id=session_id, stage=stage)


def _extract_json_block(raw: str) -> str:
    text = str(raw or "").strip()
    if not text:
        raise ValueError("模型未返回内容")
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    raise ValueError("模型未返回合法 JSON")


def _normalize_model_decision_boolean(value: Any) -> bool | Any:
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "y"}:
            return True
        if lowered in {"false", "0", "no", "n", ""}:
            return False
    return value


def _normalize_model_decision_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("模型返回的 JSON 顶层结构必须是对象")

    normalized = dict(payload)
    conversation_state = _sanitize_line(str(normalized.get("conversation_state") or ""), max_length=32).lower()
    normalized["conversation_state"] = _MODEL_DECISION_CONVERSATION_STATE_ALIASES.get(
        conversation_state,
        conversation_state or "answer",
    )

    for field_name in ("read_tool_calls", "ui_actions", "proposed_write_actions", "auto_execute_actions"):
        field_value = normalized.get(field_name)
        if field_value == "" or field_value is None:
            normalized[field_name] = []

    for field_name in ("objective", "clarifying_question", "stop_reason"):
        if normalized.get(field_name) == "":
            normalized[field_name] = None

    needs_confirmation = _normalize_model_decision_boolean(normalized.get("needs_confirmation"))
    normalized["needs_confirmation"] = bool(needs_confirmation) if needs_confirmation is not None else False

    if normalized.get("dialog_state_update") == "" or normalized.get("dialog_state_update") is None:
        normalized["dialog_state_update"] = None
    elif isinstance(normalized.get("dialog_state_update"), dict):
        normalized["dialog_state_update"] = _normalize_dialog_state_payload(normalized.get("dialog_state_update"))

    followup_resolution = normalized.get("followup_resolution")
    if followup_resolution == "" or followup_resolution is None:
        normalized["followup_resolution"] = None
    elif isinstance(followup_resolution, str):
        summary = sanitize_text(followup_resolution, max_length=240) or None
        normalized["followup_resolution"] = {"status": "unknown", "summary": summary}

    return normalized


def _parse_model_decision(raw: str) -> _AgentModelDecision:
    try:
        payload = json.loads(_extract_json_block(raw))
    except json.JSONDecodeError as exc:
        raise ValueError("模型返回的 JSON 结构无法解析") from exc
    payload = _normalize_model_decision_payload(payload)
    return _AgentModelDecision.model_validate(payload)


def _is_model_decision_contract_error(exc: Exception) -> bool:
    if isinstance(exc, ValidationError):
        return True
    if not isinstance(exc, ValueError):
        return False
    detail = sanitize_text(str(exc), max_length=240) or ""
    return detail in {
        "模型未返回内容",
        "模型未返回合法 JSON",
        "模型返回的 JSON 结构无法解析",
        "模型返回的 JSON 顶层结构必须是对象",
    }


def _compact_page_context(page_context: dict[str, Any]) -> dict[str, Any]:
    query = page_context.get("query") if isinstance(page_context.get("query"), dict) else {}
    compact_query = {str(key): sanitize_json_value(value) for key, value in list(query.items())[:12]}
    return {
        "pathname": page_context.get("pathname"),
        "asset_id": page_context.get("asset_id"),
        "finding_id": page_context.get("finding_id"),
        "task_id": page_context.get("task_id"),
        "query": compact_query,
    }


def _compact_browser_context(browser_context: dict[str, Any]) -> dict[str, Any]:
    return {
        "pathname": browser_context.get("pathname"),
        "origin": browser_context.get("origin"),
        "title": browser_context.get("title"),
        "asset_id": browser_context.get("asset_id"),
        "finding_id": browser_context.get("finding_id"),
        "task_id": browser_context.get("task_id"),
        "query": sanitize_json_value(browser_context.get("query") if isinstance(browser_context.get("query"), dict) else {}),
        "selected_entities": sanitize_json_value(
            browser_context.get("selected_entities") if isinstance(browser_context.get("selected_entities"), list) else []
        )[:MAX_MODEL_SELECTED_ENTITIES],
        "open_panels": sanitize_json_value(
            browser_context.get("open_panels") if isinstance(browser_context.get("open_panels"), list) else []
        )[:MAX_MODEL_OPEN_PANELS],
        "forms": sanitize_json_value(browser_context.get("forms") if isinstance(browser_context.get("forms"), list) else [])[
            :MAX_MODEL_FORMS
        ],
        "visible_actions": sanitize_json_value(
            browser_context.get("visible_actions") if isinstance(browser_context.get("visible_actions"), list) else []
        )[:MAX_MODEL_VISIBLE_ACTIONS],
        "semantic_actions": sanitize_json_value(
            browser_context.get("semantic_actions") if isinstance(browser_context.get("semantic_actions"), list) else []
        )[:MAX_MODEL_SEMANTIC_ACTIONS],
        "semantic_forms": sanitize_json_value(
            browser_context.get("semantic_forms") if isinstance(browser_context.get("semantic_forms"), list) else []
        )[:MAX_MODEL_SEMANTIC_FORMS],
        "dom_snapshot": sanitize_json_value(
            browser_context.get("dom_snapshot") if isinstance(browser_context.get("dom_snapshot"), list) else []
        )[:MAX_MODEL_DOM_SNAPSHOT_NODES],
    }


def _build_model_context_payload(
    *,
    user: User,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
) -> dict[str, Any]:
    current_objective = browser_runtime.get("current_objective") if isinstance(browser_runtime, dict) else None
    objective_kind = browser_runtime.get("objective_kind") if isinstance(browser_runtime, dict) else None
    primary_target = _working_context_primary_target(working_context)
    recent_targets = working_context.get("recent_targets") if isinstance(working_context.get("recent_targets"), list) else []
    semantic_page_context = _compact_semantic_page_context_for_model(_browser_semantic_page_context(browser_context))
    available_tools = [
        {
            "tool_name": "list_assets",
            "description": "读取资产列表，可按 keyword 搜索，limit 最大 10",
            "arguments": {"keyword": "可选字符串", "status": "可选 online/offline/collecting/unknown", "limit": "可选整数"},
        },
        {
            "tool_name": "get_asset_detail",
            "description": "按 asset_id 读取资产详情",
            "arguments": {"asset_id": "必填字符串"},
        },
        {
            "tool_name": "list_risks",
            "description": "读取全局风险列表，可按 asset_id、status、severity、keyword 过滤",
            "arguments": {
                "asset_id": "可选字符串",
                "status": "可选 open/fixed/ignored",
                "severity": "可选 critical/high/medium/low",
                "keyword": "可选字符串",
                "limit": "可选整数",
            },
        },
        {
            "tool_name": "get_risk_detail",
            "description": "按 finding_id 读取单条风险详情",
            "arguments": {"finding_id": "必填字符串"},
        },
        {
            "tool_name": "list_asset_risks",
            "description": "按 asset_id 读取风险列表",
            "arguments": {"asset_id": "必填字符串", "status": "可选 open/fixed/ignored", "limit": "可选整数"},
        },
        {
            "tool_name": "list_tasks",
            "description": "读取平台任务列表",
            "arguments": {"task_type": "可选", "status": "可选", "limit": "可选整数"},
        },
        {
            "tool_name": "get_task_detail",
            "description": "读取单个任务详情",
            "arguments": {"task_id": "必填字符串"},
        },
        {
            "tool_name": "get_task_events",
            "description": "读取单个任务事件日志",
            "arguments": {"task_id": "必填字符串", "limit": "可选整数"},
        },
        {
            "tool_name": "list_remediation_assets",
            "description": "读取可自动修复资产概览，包含 Runner 状态、风险数量与活动修复会话",
            "arguments": {"keyword": "可选字符串", "limit": "可选整数"},
        },
        {
            "tool_name": "get_remediation_asset",
            "description": "读取资产修复摘要、Runner 状态与修复条件",
            "arguments": {"asset_id": "必填字符串"},
        },
        {
            "tool_name": "get_risk_remediation_template",
            "description": "读取单条风险的修复模板/执行计划摘要",
            "arguments": {"finding_id": "必填字符串"},
        },
        {
            "tool_name": "get_remediation_session",
            "description": "读取修复会话摘要，可传 session_id 或 asset_id",
            "arguments": {"session_id": "可选字符串", "asset_id": "可选字符串"},
        },
        {
            "tool_name": "list_vuln_rules",
            "description": "读取漏洞库规则列表",
            "arguments": {"keyword": "可选字符串", "service": "可选字符串", "severity": "可选字符串", "limit": "可选整数"},
        },
        {
            "tool_name": "get_vuln_rule",
            "description": "读取单条漏洞库规则详情",
            "arguments": {"rule_id": "必填字符串"},
        },
    ]
    write_action_whitelist = [
        {
            "action_type": "create_discovery_job",
            "description": "创建扫描任务",
            "required_params": {"cidr": "CIDR 字符串", "label": "可选标签"},
        },
        {
            "action_type": "verify_asset_risks",
            "description": "触发资产风险验证",
            "required_params": {"asset_id": "资产 ID"},
        },
        {
            "action_type": "install_runner",
            "description": "安装 Host Runner",
            "required_params": {"asset_id": "资产 ID"},
        },
        {
            "action_type": "create_or_resume_remediation_session",
            "description": "创建或恢复主机修复会话",
            "required_params": {
                "asset_id": "资产 ID",
                "note": "可选备注",
                "submit_if_ready": "可选布尔值；为 true 时在修复条件满足后直接提交自动修复",
            },
        },
        {
            "action_type": "approve_remediation_session",
            "description": "批准修复会话并触发 Host Runner 修复任务",
            "required_params": {"session_id": "修复会话 ID"},
        },
        {
            "action_type": "configure_ssh_credential",
            "description": "打开 SSH 凭据安全输入引导，不直接在聊天中收集密码或私钥",
            "required_params": {"asset_id": "单资产 ID，或与 asset_ids 二选一", "asset_ids": "批量资产 ID 列表"},
        },
    ]
    browser_action_whitelist = [
        {"action_type": "navigate", "description": "站内路由跳转到已知 href 或 pathname"},
        {"action_type": "click", "description": "点击可见可交互节点"},
        {"action_type": "input", "description": "向输入框填值"},
        {"action_type": "select", "description": "选择下拉项"},
        {"action_type": "toggle", "description": "切换开关、复选框或 Tab"},
        {"action_type": "expand", "description": "展开详情、折叠面板、行内容"},
        {"action_type": "scroll_into_view", "description": "滚动定位到目标节点"},
        {"action_type": "submit", "description": "提交表单或确认当前 UI 操作"},
        {"action_type": "wait_for", "description": "等待弹窗、详情、列表或其他节点出现"},
    ]
    return {
        "agent_id": AGENT_ID,
        "user_role": _normalize_role(user.role),
        "allow_write_plans": allow_write_plans,
        "allow_auto_execute_actions": allow_auto_execute_actions,
        "current_objective": sanitize_text(str(current_objective or ""), max_length=240) or None,
        "objective_kind": _sanitize_line(str(objective_kind or ""), max_length=32) or None,
        "conversation_focus": sanitize_json_value(primary_target),
        "recent_targets": sanitize_json_value(recent_targets[:6]),
        "shared_working_context": sanitize_json_value(working_context),
        "current_page_context": _compact_page_context(page_context),
        "semantic_page_context": sanitize_json_value(semantic_page_context),
        "current_browser_context": _compact_browser_context(browser_context),
        "browser_runtime": _compact_browser_runtime_for_model(browser_runtime),
        "pending_dialog_state": sanitize_json_value(dialog_state),
        "followup_hint": sanitize_json_value(followup_hint),
        "available_read_tools": available_tools,
        "allowed_write_actions": write_action_whitelist,
        "auto_execute_write_actions": [item for item in write_action_whitelist if item["action_type"] in AUTO_EXECUTE_ACTIONS],
        "allowed_browser_actions": browser_action_whitelist,
    }


def _build_model_response_contract() -> dict[str, Any]:
    return {
        "response_rules": [
            "只返回一个 JSON 对象，不要输出代码块、解释前缀或多余文字",
            "reply_markdown 必须是自然中文",
            "如果用户表达的是操作意图，优先推进动作，不要先输出长解释",
            "inspect 或 navigate 意图优先通过 ui_actions 或 read_tool_calls 推进，而不是只给纯文字答复",
            "operate_low_risk 意图在目标明确时优先填写 auto_execute_actions",
            "operate_high_risk 意图先补齐信息，再形成 proposed_write_actions 并等待确认",
            "如果信息不足以继续分析，请将 conversation_state 设为 clarifying，并把自然语言追问写入 clarifying_question",
            "如果需要更多上下文，优先填写 read_tool_calls",
            "如果需要在网站界面中切换、展开、筛选、填写或提交当前页面内容，请使用 ui_actions",
            "不能编造资产 ID、任务 ID、风险 ID、会话 ID 或规则 ID，必须来自工具结果或当前页面上下文",
            "当前消息里显式提到的新对象优先级最高，可以在同一会话里切换目标",
            "如果用户说“这个”“它”“当前页”等指代，可结合 current_page_context 解析；否则优先参考 conversation_focus 和 recent_targets",
            "conversation_focus 和 recent_targets 是软焦点快照，只用于跟进理解，不构成硬锁定",
            "如果 pending_dialog_state 存在，必须先把当前用户回复视为对上一轮追问的承接，再决定是否改成新话题",
            "如果 followup_hint.reply_kind 是 affirm、deny 或 short_value，不能原样重复上一轮问题",
            "若仍然需要继续追问，clarifying_question 必须比上一轮更具体，并同步填写 dialog_state_update",
            "semantic_page_context 是页面理解主输入，优先使用 semantic_actions 里的 semantic_action_id，不要依赖脆弱的裸文本匹配",
            "current_browser_context 会提供当前页面可见 DOM 节点与动作，只有在 semantic_page_context 不足时才回退到 dom_snapshot",
            "如果当前回合目标还未完成，不要把中间状态误当成最终答复",
            "auto_execute_actions 仅允许 create_discovery_job、verify_asset_risks、install_runner，且只能用于明确的执行意图",
            "configure_ssh_credential 只能用于触发安全输入引导，敏感字段绝不能出现在 reply_markdown、dialog_state、ui_actions 或 payload 里",
            "只有在明确形成计划时才填写 proposed_write_actions",
            "允许在一条消息里形成跨多个对象的聚合计划，但每个动作都必须带清晰参数",
            "如果 allow_auto_execute_actions=false，则 auto_execute_actions 必须为空",
            "如果 allow_write_plans=false，则 proposed_write_actions 必须为空，needs_confirmation 必须为 false",
            "严禁输出任何自由 shell、SSH、任意 HTTP、平台设置修改或漏洞库写操作",
        ],
        "output_schema": {
            "reply_markdown": "string",
            "conversation_state": "answer|clarifying|plan",
            "objective": "string|null",
            "clarifying_question": "string|null",
            "read_tool_calls": [{"tool_name": "string", "arguments": {}}],
            "ui_actions": [{
                "action_id": "string",
                "action_type": "string",
                "semantic_action_id": "string|null",
                "target_node_id": "string|null",
                "selector": "string|null",
                "expected_page_kind": "string|null",
                "expected_section": "string|null",
                "retryable": "boolean"
            }],
            "proposed_write_actions": [{"action_type": "string", "title": "string", "reason": "string", "params": {}}],
            "auto_execute_actions": [{"action_type": "string", "title": "string", "reason": "string", "params": {}}],
            "needs_confirmation": "boolean",
            "dialog_state_update": {
                "status": "idle|awaiting_user_input",
                "intent_kind": "read_followup|analyze|fill_slot|prepare_plan|null",
                "question_kind": "confirm|slot_fill|disambiguate|followup|null",
                "intent_summary": "string|null",
                "last_agent_question": "string|null",
                "expected_slots": ["string"],
                "candidate_read_tools": [{"tool_name": "string", "arguments": {}}],
                "candidate_write_context": {},
                "targets_snapshot": {},
            },
            "followup_resolution": {"status": "resolved|canceled|reframed|needs_more_input|unknown", "summary": "string|null"},
            "stop_reason": "string|null",
        },
    }


def _render_history_line(message: AgentMessage | Any, *, max_length: int = 4000) -> str | None:
    role = "assistant" if str(message.role or "").strip().lower() == "assistant" else "user"
    content = sanitize_text(message.content, max_length=max_length) or ""
    if not content:
        return None
    message_type = str(message.message_type or "text").strip().lower() or "text"
    label = role if message_type == "text" else f"{role}/{message_type}"
    return f"{label}: {content}"


def _select_model_history_lines(messages: list[AgentMessage | Any]) -> list[str]:
    selected: list[str] = []
    total_chars = 0
    assistant_types = {"text", "clarifying", "plan", "error"}
    fallback_line: str | None = None

    for item in reversed(messages):
        role = str(getattr(item, "role", "") or "").strip().lower()
        message_type = str(getattr(item, "message_type", "") or "text").strip().lower() or "text"
        rendered = _render_history_line(item, max_length=280)
        if rendered and fallback_line is None:
            fallback_line = rendered
        if role == "assistant" and message_type not in assistant_types:
            continue
        if not rendered:
            continue
        next_total = total_chars + len(rendered)
        if selected and (len(selected) >= MAX_MODEL_HISTORY_MESSAGES or next_total > MAX_MODEL_HISTORY_CHARS):
            break
        selected.append(rendered)
        total_chars = next_total
        if len(selected) >= MAX_MODEL_HISTORY_MESSAGES or total_chars >= MAX_MODEL_HISTORY_CHARS:
            break

    if not selected and fallback_line:
        return [fallback_line]
    return list(reversed(selected))


def _compact_semantic_page_context_for_model(page_context: dict[str, Any] | None) -> dict[str, Any]:
    normalized = _normalize_semantic_page_context(page_context if isinstance(page_context, dict) else {})
    return {
        "page_kind": _sanitize_line(str(normalized.get("page_kind") or "unknown"), max_length=48) or "unknown",
        "primary_entity": sanitize_json_value(
            normalized.get("primary_entity") if isinstance(normalized.get("primary_entity"), dict) else {}
        ),
        "secondary_entities": sanitize_json_value(
            normalized.get("secondary_entities") if isinstance(normalized.get("secondary_entities"), list) else []
        )[:MAX_MODEL_SECONDARY_ENTITIES],
        "visible_sections": sanitize_json_value(
            normalized.get("visible_sections") if isinstance(normalized.get("visible_sections"), list) else []
        )[:MAX_MODEL_VISIBLE_SECTIONS],
        "semantic_actions": sanitize_json_value(
            normalized.get("semantic_actions") if isinstance(normalized.get("semantic_actions"), list) else []
        )[:MAX_MODEL_SEMANTIC_ACTIONS],
        "semantic_forms": sanitize_json_value(
            normalized.get("semantic_forms") if isinstance(normalized.get("semantic_forms"), list) else []
        )[:MAX_MODEL_SEMANTIC_FORMS],
        "active_dialog": sanitize_json_value(
            normalized.get("active_dialog") if isinstance(normalized.get("active_dialog"), dict) else {}
        ),
        "selected_rows": sanitize_json_value(
            normalized.get("selected_rows") if isinstance(normalized.get("selected_rows"), list) else []
        )[:MAX_MODEL_SELECTED_ROWS],
        "summary": sanitize_text(str(normalized.get("summary") or ""), max_length=240) or None,
    }


def _compact_model_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 2:
        return sanitize_json_value(value)
    if isinstance(value, list):
        return [_compact_model_value(item, depth=depth + 1) for item in value[:3]]
    if not isinstance(value, dict):
        return sanitize_json_value(value)

    prioritized_keys = (
        "task_id",
        "asset_id",
        "finding_id",
        "session_id",
        "rule_id",
        "status",
        "task_type",
        "business_status",
        "message",
        "summary",
        "title",
        "label",
        "count",
        "total",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
    )
    compacted: dict[str, Any] = {}
    for key in prioritized_keys:
        if key not in value:
            continue
        compacted[key] = _compact_model_value(value.get(key), depth=depth + 1)

    for list_key in ("items", "events", "rows", "assets", "findings", "sessions"):
        list_value = value.get(list_key)
        if isinstance(list_value, list) and list_value:
            compacted[f"{list_key}_preview"] = [_compact_model_value(item, depth=depth + 1) for item in list_value[:2]]
            if "total" not in compacted:
                compacted["total"] = len(list_value)
            break

    for nested_key in ("timing", "result", "meta"):
        nested_value = value.get(nested_key)
        if isinstance(nested_value, dict) and nested_value:
            compacted[nested_key] = _compact_model_value(nested_value, depth=depth + 1)

    if not compacted:
        for key, item in list(value.items())[:6]:
            compacted[_sanitize_line(str(key), max_length=64) or str(key)] = _compact_model_value(item, depth=depth + 1)
    return sanitize_json_value(compacted)


def _compact_tool_traces_for_model(tool_traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for trace in tool_traces[-MAX_MODEL_TOOL_TRACE_ITEMS:]:
        if not isinstance(trace, dict):
            continue
        item = {
            "tool_name": _sanitize_line(str(trace.get("tool_name") or ""), max_length=64),
            "arguments": sanitize_json_value(trace.get("arguments") if isinstance(trace.get("arguments"), dict) else {}),
            "ok": False if trace.get("ok") is False else True,
        }
        if item["ok"]:
            item["result"] = _compact_model_value(trace.get("result"))
        else:
            item["error"] = sanitize_text(str(trace.get("error") or ""), max_length=240) or None
        compacted.append(item)
    return compacted


def _compact_ui_action_results_for_model(results: Any) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for item in _normalize_ui_action_results(results)[:MAX_MODEL_UI_RESULTS]:
        compacted_item = {
            "action_id": _sanitize_line(str(item.get("action_id") or ""), max_length=64) or None,
            "action_type": _sanitize_line(str(item.get("action_type") or ""), max_length=32) or None,
            "ok": bool(item.get("ok")),
            "semantic_action_id": _sanitize_line(str(item.get("semantic_action_id") or ""), max_length=128) or None,
            "target_node_id": _sanitize_line(str(item.get("target_node_id") or ""), max_length=64) or None,
            "resolved_node_id": _sanitize_line(str(item.get("resolved_node_id") or ""), max_length=64) or None,
            "message": sanitize_text(str(item.get("message") or ""), max_length=180) or None,
            "resolved_target": sanitize_json_value(
                item.get("resolved_target") if isinstance(item.get("resolved_target"), dict) else {}
            ),
            "attempt_count": max(1, min(int(item.get("attempt_count") or 1), 4)),
        }
        compacted.append(compacted_item)
    return compacted


def _compact_auto_executed_actions_for_model(actions: Any) -> list[dict[str, Any]]:
    if not isinstance(actions, list):
        return []
    compacted: list[dict[str, Any]] = []
    for item in actions[:MAX_MODEL_TOOL_TRACE_ITEMS]:
        if not isinstance(item, dict):
            continue
        params = item.get("params") if isinstance(item.get("params"), dict) else {}
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        compacted.append(
            {
                "action_type": _sanitize_line(str(item.get("action_type") or ""), max_length=64) or None,
                "title": sanitize_text(str(item.get("title") or ""), max_length=120) or None,
                "summary": sanitize_text(str(item.get("summary") or ""), max_length=180) or None,
                "child_task_id": _sanitize_line(str(item.get("child_task_id") or ""), max_length=64) or None,
                "status": _sanitize_line(str(item.get("status") or payload.get("status") or ""), max_length=32) or None,
                "asset_id": _sanitize_line(str(params.get("asset_id") or payload.get("asset_id") or ""), max_length=64) or None,
                "session_id": _sanitize_line(str(payload.get("session_id") or ""), max_length=64) or None,
            }
        )
    return compacted


def _compact_browser_runtime_for_model(browser_runtime: dict[str, Any] | None) -> dict[str, Any]:
    runtime = _normalize_browser_runtime(browser_runtime if isinstance(browser_runtime, dict) else {})
    pending_secure_input = (
        runtime.get("pending_secure_input") if isinstance(runtime.get("pending_secure_input"), dict) else {}
    )
    return {
        "phase": _sanitize_line(str(runtime.get("phase") or ""), max_length=48) or "idle",
        "step_count": max(0, min(int(runtime.get("step_count") or 0), MAX_AGENT_LOOP_STEPS)),
        "current_objective": sanitize_text(str(runtime.get("current_objective") or ""), max_length=240) or None,
        "objective_kind": _sanitize_line(str(runtime.get("objective_kind") or ""), max_length=32) or None,
        "planned_steps": sanitize_json_value(
            runtime.get("planned_steps") if isinstance(runtime.get("planned_steps"), list) else []
        )[:MAX_MODEL_PLANNED_STEPS],
        "step_cursor": max(0, min(int(runtime.get("step_cursor") or 0), MAX_AGENT_LOOP_STEPS)),
        "pending_ui_actions": sanitize_json_value(
            runtime.get("pending_ui_actions") if isinstance(runtime.get("pending_ui_actions"), list) else []
        )[:MAX_UI_ACTION_BATCH],
        "completed_ui_actions": _compact_ui_action_results_for_model(runtime.get("completed_ui_actions")),
        "last_ui_results": _compact_ui_action_results_for_model(runtime.get("last_ui_results")),
        "pending_secure_input": {
            "kind": _sanitize_line(str(pending_secure_input.get("kind") or ""), max_length=64) or None,
            "mode": _sanitize_line(str(pending_secure_input.get("mode") or ""), max_length=32) or None,
            "asset_ids": sanitize_json_value(
                pending_secure_input.get("asset_ids") if isinstance(pending_secure_input.get("asset_ids"), list) else []
            )[:4],
            "resume_goal_id": _sanitize_line(str(pending_secure_input.get("resume_goal_id") or ""), max_length=64) or None,
            "blocker_summary": sanitize_text(str(pending_secure_input.get("blocker_summary") or ""), max_length=240) or None,
        }
        if pending_secure_input
        else {},
        "auto_executed_actions": _compact_auto_executed_actions_for_model(runtime.get("auto_executed_actions")),
        "last_user_intent": sanitize_text(str(runtime.get("last_user_intent") or ""), max_length=240) or None,
        "last_error": sanitize_text(str(runtime.get("last_error") or ""), max_length=240) or None,
    }


def _build_model_request(
    *,
    session: AgentSession,
    user: User,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    tool_traces: list[dict[str, Any]],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
) -> LLMRequest:
    recent_messages = list(session.messages[-12:])
    latest_user_content = ""
    if recent_messages:
        last_message = recent_messages[-1]
        last_role = str(getattr(last_message, "role", "") or "").strip().lower()
        if last_role == "user":
            latest_user_content = sanitize_text(getattr(last_message, "content", ""), max_length=4000) or ""
            recent_messages = recent_messages[:-1]
    history_lines = _select_model_history_lines(recent_messages)

    messages: list[LLMMessage] = [
        LLMMessage.from_text(
            "system",
            "你是 haor，负责在资产态势感知平台内充当站内自治助手。"
            "同一会话可以连续处理不同资产、风险、任务和修复对象；页面地址只是提示，不是硬性上下文绑定。"
            "你必须优先推进当前目标，能做动作时不要退化成纯说明，并严格遵守平台白名单工具与动作边界。",
        ),
        LLMMessage.from_text(
            "system",
            json.dumps(_build_model_response_contract(), ensure_ascii=False, indent=2),
        ),
        LLMMessage.from_text(
            "user",
            "平台当前上下文如下：\n"
            + json.dumps(
                _build_model_context_payload(
                    user=user,
                    page_context=page_context,
                    browser_context=browser_context,
                    browser_runtime=browser_runtime,
                    working_context=working_context,
                    dialog_state=dialog_state,
                    followup_hint=followup_hint,
                    allow_write_plans=allow_write_plans,
                    allow_auto_execute_actions=allow_auto_execute_actions,
                ),
                ensure_ascii=False,
                indent=2,
            ),
        ),
    ]
    if history_lines:
        messages.append(
            LLMMessage.from_text(
                "user",
                "最近会话记录如下，请仅将其作为历史参考，不要覆盖当前用户问题：\n" + "\n".join(history_lines),
            )
        )
    if latest_user_content:
        messages.append(LLMMessage.from_text("user", f"当前用户问题：\n{latest_user_content}"))
    if dialog_state:
        messages.append(
            LLMMessage.from_text(
                "user",
                "上一轮仍未完成的对话状态如下，请把当前用户输入优先解释为对该追问的回复：\n"
                + json.dumps(
                    {
                        "pending_dialog_state": dialog_state,
                        "followup_hint": followup_hint,
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
            )
        )
    if tool_traces:
        messages.append(
            LLMMessage.from_text(
                "user",
                "已执行的只读工具结果如下，请基于这些结果继续回答当前用户问题：\n"
                + json.dumps(
                    sanitize_json_value({"executed_read_tools": _compact_tool_traces_for_model(tool_traces)}),
                    ensure_ascii=False,
                    indent=2,
                ),
            )
        )
    return LLMRequest(messages=messages)


def _log_model_decision_contract_issue(
    *,
    provider_name: str,
    wire_api: str,
    resolved_base_url: str,
    objective_kind: str,
    followup_reply_kind: str,
    raw_preview: str,
    error_reason: str,
    phase: str,
) -> None:
    logger.warning(
        "haor model decision contract error",
        extra={
            "agent_provider": provider_name,
            "agent_wire_api": wire_api,
            "agent_base_url": resolved_base_url,
            "agent_objective_kind": objective_kind,
            "agent_followup_reply_kind": followup_reply_kind,
            "agent_model_preview": raw_preview,
            "agent_contract_error": error_reason,
            "agent_contract_phase": phase,
        },
    )


def _run_model_once(
    *,
    session: AgentSession,
    user: User,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    tool_traces: list[dict[str, Any]],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
) -> _AgentModelDecision:
    current_content = sanitize_text(
        str(session.messages[-1].content if session.messages else ""),
        max_length=400,
    ) or ""
    if _runtime_provider_mode() == "mock":
        return _build_mock_model_decision(
            user=user,
            current_content=current_content,
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            dialog_state=dialog_state,
            followup_hint=followup_hint,
            tool_traces=tool_traces,
        )
    provider_result = _build_runtime_provider()
    request = _build_model_request(
        session=session,
        user=user,
        page_context=page_context,
        browser_context=browser_context,
        browser_runtime=browser_runtime,
        working_context=working_context,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
        tool_traces=tool_traces,
        allow_write_plans=allow_write_plans,
        allow_auto_execute_actions=allow_auto_execute_actions,
    )
    objective_kind = _sanitize_line(str(browser_runtime.get("objective_kind") or ""), max_length=32) or _classify_objective_kind(
        current_content,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    )
    followup_reply_kind = _sanitize_line(str(followup_hint.get("reply_kind") or ""), max_length=32)
    content = provider_result.provider.generate(request)
    try:
        return _parse_model_decision(content)
    except Exception as exc:
        if not _is_model_decision_contract_error(exc):
            raise
        _log_model_decision_contract_issue(
            provider_name=_sanitize_line(str(getattr(provider_result, "provider_name", "") or _runtime_provider_mode()), max_length=64)
            or _runtime_provider_mode(),
            wire_api=_sanitize_line(str(getattr(provider_result.provider, "wire_api", "") or ""), max_length=32)
            or _sanitize_line(str(read_runtime_env_value("LLM_WIRE_API", str(settings.LLM_WIRE_API or "responses")) or ""), max_length=32),
            resolved_base_url=_sanitize_line(str(getattr(provider_result, "resolved_base_url", "") or ""), max_length=255),
            objective_kind=objective_kind,
            followup_reply_kind=followup_reply_kind,
            raw_preview=sanitize_text(content, max_length=800) or "",
            error_reason=sanitize_text(str(exc), max_length=400) or "unknown_contract_error",
            phase="primary_parse",
        )
        if _sanitize_line(str(getattr(provider_result, "provider_name", "") or _runtime_provider_mode()), max_length=64) != "custom_proxy":
            raise
        retry_provider_result = _build_runtime_provider(
            wire_api_override="chat_completions",
            chat_json_mode=True,
        )
        retry_content = retry_provider_result.provider.generate(request)
        try:
            return _parse_model_decision(retry_content)
        except Exception as retry_exc:
            if _is_model_decision_contract_error(retry_exc):
                _log_model_decision_contract_issue(
                    provider_name=_sanitize_line(
                        str(getattr(retry_provider_result, "provider_name", "") or _runtime_provider_mode()),
                        max_length=64,
                    )
                    or _runtime_provider_mode(),
                    wire_api=_sanitize_line(str(getattr(retry_provider_result.provider, "wire_api", "") or ""), max_length=32)
                    or "chat_completions",
                    resolved_base_url=_sanitize_line(str(getattr(retry_provider_result, "resolved_base_url", "") or ""), max_length=255),
                    objective_kind=objective_kind,
                    followup_reply_kind=followup_reply_kind,
                    raw_preview=sanitize_text(retry_content, max_length=800) or "",
                    error_reason=sanitize_text(str(retry_exc), max_length=400) or "unknown_contract_error",
                    phase="chat_completions_retry",
                )
            raise


def _build_mock_model_decision(
    *,
    user: User,
    current_content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    tool_traces: list[dict[str, Any]],
) -> _AgentModelDecision:
    objective = _build_current_objective(
        current_content or str(page_context.get("pathname") or "当前会话"),
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    )
    page_summary = _browser_semantic_page_context(browser_context)
    target_summary = _working_context_summary(working_context) or page_context.get("pathname") or "未识别"
    role_label = "管理员" if _normalize_role(user.role) == "admin" else "分析员"
    lines = [
        "当前 haor 处于模拟模式（mock），未接入真实模型推理。",
        f"当前身份：{role_label}",
        f"当前页面：{page_summary.get('page_kind') or page_context.get('pathname') or 'unknown'}",
        f"当前焦点：{target_summary}",
    ]
    if tool_traces:
        lines.append(f"最近已累计 {len(tool_traces)} 条工具结果，可继续用来验证统一代理链路。")
    if _classify_objective_kind(
        current_content,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    ) in {"operate_low_risk", "operate_high_risk"}:
        lines.append("mock 模式下不会执行写动作，也不会生成可执行高风险计划。")
    else:
        lines.append("当前响应仍然经过统一 agent 决策链返回，用于验证会话、上下文和界面动作链路。")
    return _AgentModelDecision(
        reply_markdown="\n".join(lines),
        conversation_state="answer",
        objective=objective.get("summary"),
        stop_reason="mock_mode",
    )


def _risk_rule_id(finding: RiskFinding) -> str | None:
    return finding.resolved_yaml_rule_id()


def _serialize_asset(asset: Asset) -> dict[str, Any]:
    is_local, local_hint = resolve_local_asset(str(asset.ip), asset.hostname)
    return {
        "id": asset.id,
        "ip": str(asset.ip),
        "hostname": asset.hostname,
        "os_name": asset.os_name,
        "status": asset.status.value if hasattr(asset.status, "value") else str(asset.status),
        "is_local": is_local,
        "local_hint": local_hint,
        "first_seen_at": asset.first_seen_at.isoformat() if asset.first_seen_at else None,
        "last_seen_at": asset.last_seen_at.isoformat() if asset.last_seen_at else None,
        "ports": [
            {
                "id": port.id,
                "port": port.port,
                "protocol": port.protocol,
                "service_name": port.service_name,
                "service_version": port.service_version,
                "state": port.state,
            }
            for port in asset.ports[:20]
        ],
    }


def _serialize_finding_summary(finding: RiskFinding) -> dict[str, Any]:
    asset = finding.asset
    return {
        "finding_id": finding.id,
        "asset_id": finding.asset_id,
        "asset_ip": str(asset.ip) if asset is not None else None,
        "asset_hostname": asset.hostname if asset is not None else None,
        "title": finding.title,
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        "rule_id": _risk_rule_id(finding) or finding.rule_id,
        "service_name": finding.asset_port.service_name if finding.asset_port else None,
        "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
    }


def _serialize_finding_detail(finding: RiskFinding) -> dict[str, Any]:
    payload = _serialize_finding_summary(finding)
    payload.update(
        {
            "description": finding.description,
            "evidence_json": sanitize_json_value(finding.evidence_json if isinstance(finding.evidence_json, dict) else {}),
            "asset": _serialize_asset(finding.asset) if finding.asset is not None else None,
            "rule": (
                {
                    "id": finding.rule.id,
                    "title": finding.rule.title,
                    "service_name": finding.rule.service_name,
                    "severity": finding.rule.severity.value
                    if hasattr(finding.rule.severity, "value")
                    else str(finding.rule.severity),
                }
                if finding.rule is not None
                else None
            ),
        }
    )
    return payload


def _resolve_asset_for_read_tool(db: Session, asset_reference: str) -> Asset | None:
    normalized_reference = _sanitize_line(str(asset_reference or ""), max_length=96)
    if not normalized_reference:
        return None

    asset = get_asset(db, normalized_reference)
    if asset is not None:
        return asset

    ip_reference: str | None = None
    try:
        normalized_cidr = normalize_cidr(normalized_reference)
    except ValueError:
        normalized_cidr = None
    if normalized_cidr and normalized_cidr.endswith("/32"):
        ip_reference = normalized_cidr.split("/", 1)[0]
    elif re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", normalized_reference):
        ip_reference = normalized_reference

    if ip_reference:
        items, total = list_assets(db=db, page=1, page_size=2, ip=ip_reference)
        if total == 1 and items:
            return items[0]

    items, total = list_assets(db=db, page=1, page_size=2, keyword=normalized_reference)
    if total != 1 or not items:
        return None
    candidate = items[0]
    candidate_ip = str(getattr(candidate, "ip", "") or "").strip()
    candidate_hostname = str(getattr(candidate, "hostname", "") or "").strip().lower()
    if candidate_ip == normalized_reference or candidate_hostname == normalized_reference.lower():
        return candidate
    return None


def _execute_read_tool(db: Session, *, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    limit = max(1, min(int(arguments.get("limit") or 6), 20))
    if tool_name == "list_assets":
        status_value = str(arguments.get("status") or "").strip().lower() or None
        asset_status = AssetStatus(status_value) if status_value in {item.value for item in AssetStatus} else None
        items, total = list_assets(
            db=db,
            page=1,
            page_size=min(limit, 10),
            keyword=str(arguments.get("keyword") or "").strip() or None,
            asset_status=asset_status,
        )
        return {
            "items": [
                {
                    "asset_id": item.id,
                    "ip": str(item.ip),
                    "hostname": item.hostname,
                    "os_name": item.os_name,
                    "status": item.status.value if hasattr(item.status, "value") else str(item.status),
                }
                for item in items
            ],
            "total": total,
        }
    if tool_name == "get_asset_detail":
        asset_reference = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=96)
        if not asset_reference:
            raise RuntimeError("get_asset_detail 缺少 asset_id")
        asset = _resolve_asset_for_read_tool(db, asset_reference)
        if asset is None:
            raise RuntimeError("资产不存在")
        return _serialize_asset(asset)
    if tool_name == "list_risks":
        status_value = str(arguments.get("status") or "").strip().lower() or None
        severity_value = str(arguments.get("severity") or "").strip().lower() or None
        findings = list_findings(
            db,
            asset_id=_sanitize_line(str(arguments.get("asset_id") or ""), max_length=64) or None,
            status=FindingStatus(status_value) if status_value in {item.value for item in FindingStatus} else None,
            severity=RiskSeverity(severity_value) if severity_value in {item.value for item in RiskSeverity} else None,
            keyword=sanitize_text(str(arguments.get("keyword") or ""), max_length=120) or None,
            limit=min(limit, 10),
        )
        return {
            "items": [_serialize_finding_summary(item) for item in findings],
            "total": len(findings),
        }
    if tool_name == "get_risk_detail":
        finding_id = _sanitize_line(str(arguments.get("finding_id") or ""), max_length=64)
        if not finding_id:
            raise RuntimeError("get_risk_detail 缺少 finding_id")
        finding = get_finding(db, finding_id)
        if finding is None:
            raise RuntimeError("风险不存在")
        return _serialize_finding_detail(finding)
    if tool_name == "list_asset_risks":
        asset_reference = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=96)
        if not asset_reference:
            raise RuntimeError("list_asset_risks 缺少 asset_id")
        asset = _resolve_asset_for_read_tool(db, asset_reference)
        if asset is None:
            raise RuntimeError("资产不存在")
        expected_status = str(arguments.get("status") or "").strip().lower() or None
        findings = list_findings_by_asset(db, asset.id)
        filtered: list[RiskFinding] = []
        for item in findings:
            if expected_status and str(item.status.value if hasattr(item.status, "value") else item.status).lower() != expected_status:
                continue
            filtered.append(item)
        return {
            "asset_id": asset.id,
            "items": [_serialize_finding_summary(item) for item in filtered[:limit]],
            "total": len(filtered),
        }
    if tool_name == "list_tasks":
        task_type_value = str(arguments.get("task_type") or "").strip().lower() or None
        task_status_value = str(arguments.get("status") or "").strip().lower() or None
        task_type = TaskType(task_type_value) if task_type_value in {item.value for item in TaskType} else None
        task_status = (
            TaskExecutionStatus(task_status_value)
            if task_status_value in {item.value for item in TaskExecutionStatus}
            else None
        )
        items, total = list_task_runs(db, page=1, page_size=min(limit, 10), task_type=task_type, status=task_status)
        return {
            "items": [
                {
                    "task_id": item.id,
                    "task_type": item.task_type.value if hasattr(item.task_type, "value") else str(item.task_type),
                    "status": item.status.value if hasattr(item.status, "value") else str(item.status),
                    "scope_type": item.scope_type,
                    "scope_id": item.scope_id,
                    "progress": item.progress,
                    "message": item.message,
                    "created_at": item.created_at.isoformat() if item.created_at else None,
                }
                for item in items
            ],
            "total": total,
        }
    if tool_name == "get_task_detail":
        task_id = _sanitize_line(str(arguments.get("task_id") or ""), max_length=64)
        if not task_id:
            raise RuntimeError("get_task_detail 缺少 task_id")
        task = get_task_run(db, task_id)
        if task is None:
            raise RuntimeError("任务不存在")
        events = list_task_events_for_task(db, task_run_id=task_id, page=1, page_size=100, level=None)[0]
        return serialize_task_detail(task, events=events)
    if tool_name == "get_task_events":
        task_id = _sanitize_line(str(arguments.get("task_id") or ""), max_length=64)
        if not task_id:
            raise RuntimeError("get_task_events 缺少 task_id")
        task = get_task_run(db, task_id)
        if task is None:
            raise RuntimeError("任务不存在")
        events = list_task_events_for_task(db, task_run_id=task_id, page=1, page_size=limit, level=None)[0]
        return {
            "task_id": task_id,
            "items": [serialize_task_event(item, task=task) for item in events],
        }
    if tool_name == "list_remediation_assets":
        result = list_remediation_assets(
            db,
            page=1,
            page_size=min(limit, 10),
            keyword=sanitize_text(str(arguments.get("keyword") or ""), max_length=120) or None,
        )
        return result.model_dump(mode="json")
    if tool_name == "get_remediation_asset":
        asset_reference = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=96)
        if not asset_reference:
            raise RuntimeError("get_remediation_asset 缺少 asset_id")
        asset = _resolve_asset_for_read_tool(db, asset_reference)
        if asset is None:
            raise RuntimeError("资产不存在")
        return build_remediation_asset_detail(db, asset.id).model_dump(mode="json")
    if tool_name == "get_remediation_session":
        session_id = _sanitize_line(str(arguments.get("session_id") or ""), max_length=64)
        asset_reference = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=96)
        asset_id = None
        if asset_reference:
            asset = _resolve_asset_for_read_tool(db, asset_reference)
            if asset is None:
                raise RuntimeError("资产不存在")
            asset_id = asset.id
        if not session_id and asset_id:
            session_id = db.scalar(
                select(RemediationSession.id)
                .where(RemediationSession.asset_id == asset_id)
                .order_by(RemediationSession.updated_at.desc(), RemediationSession.created_at.desc())
            ) or ""
        if not session_id:
            raise RuntimeError("get_remediation_session 缺少 session_id 或 asset_id")
        return get_remediation_session_read(db, session_id).model_dump(mode="json")
    if tool_name == "get_risk_remediation_template":
        finding_id = _sanitize_line(str(arguments.get("finding_id") or ""), max_length=64)
        if not finding_id:
            raise RuntimeError("get_risk_remediation_template 缺少 finding_id")
        return build_plan(db, finding_id).model_dump(mode="json")
    if tool_name == "list_vuln_rules":
        items, total = vuln_library_endpoint.RULE_SERVICE.list_rules(
            page=1,
            page_size=min(limit, 10),
            keyword=str(arguments.get("keyword") or "").strip() or None,
            service=str(arguments.get("service") or "").strip() or None,
            severity=str(arguments.get("severity") or "").strip() or None,
            enabled=None,
            catalog_view="default",
        )
        return {
            "items": [
                {
                    "rule_id": item.rule_id,
                    "name": item.name,
                    "service": item.service,
                    "severity": item.severity,
                    "enabled": item.enabled,
                }
                for item in items
            ],
            "total": total,
        }
    if tool_name == "get_vuln_rule":
        rule_id = _sanitize_line(str(arguments.get("rule_id") or ""), max_length=128)
        if not rule_id:
            raise RuntimeError("get_vuln_rule 缺少 rule_id")
        rule = vuln_library_endpoint.RULE_SERVICE.get_rule(rule_id)
        if rule is None:
            raise RuntimeError("规则不存在")
        return vuln_library_endpoint._to_read_model(rule).model_dump(mode="json")
    raise RuntimeError(f"不支持的只读工具: {tool_name}")


def _run_agent_loop(
    db: Session,
    *,
    session: AgentSession,
    user: User,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> tuple[_AgentModelDecision, list[dict[str, Any]]]:
    tool_traces: list[dict[str, Any]] = []
    working_context = _normalize_working_context(working_context)
    loop_allow_write_plans = allow_write_plans
    loop_allow_auto_execute_actions = allow_auto_execute_actions
    session_last_task_id = _session_last_task_id(session)
    latest_user_content = ""
    for item in reversed(getattr(session, "messages", []) or []):
        if str(getattr(item, "role", "") or "").strip().lower() != "user":
            continue
        latest_user_content = sanitize_text(str(getattr(item, "content", "") or ""), max_length=400) or ""
        if latest_user_content:
            break
    current_content = latest_user_content or str(browser_runtime.get("last_user_intent") or "") or str(session.messages[-1].content if session.messages else "")
    resume_priority_decision = _build_resume_hint_read_decision(
        content=current_content,
        session=session,
        working_context=working_context,
        tool_traces=tool_traces,
        allow_extended_resume=True,
    )
    playbook_match = None
    if resume_priority_decision is None:
        playbook_match = match_registered_playbook(
            content=current_content,
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            current_goal=_session_goal(session),
        )
    objective = _build_current_objective(
        str(browser_runtime.get("current_objective") or "") or current_content,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    )
    decision = _AgentModelDecision(
        reply_markdown="当前未得到有效结论。",
        objective=objective.get("summary"),
        read_tool_calls=[],
        proposed_write_actions=[],
        needs_confirmation=False,
    )
    _apply_agent_state_patch(
        session,
        focus=_resolve_agent_focus(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            dialog_state=dialog_state,
            user_content=current_content,
            fallback_watch_task_id=session_last_task_id,
        ),
        execution={
            "stage": "planning",
            "step_kind": "answer",
            "step_label": "解析当前目标",
            "waiting_for": None,
            "missing_slots": [],
        },
        explanation={
            "reason": "正在解析当前用户目标并决定下一步动作",
            "decision_summary": sanitize_text(str(objective.get("summary") or ""), max_length=280),
            "expected_outcome": "确定是回答、追问、页面动作还是后台执行",
            "next_step": "完成解析后进入单一步骤执行",
            "evidence": [],
        },
        watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
    )
    _emit_agent_state(stream_emitter, session, turn_id=turn_id)
    for _ in range(MAX_MODEL_DECISION_STEPS):
        if resume_priority_decision is not None:
            decision = resume_priority_decision
            resume_priority_decision = None
        elif playbook_match is not None:
            decision = _build_model_decision_from_playbook(playbook_match)
            playbook_match = None
        else:
            try:
                decision = _run_model_once(
                    session=session,
                    user=user,
                    page_context=page_context,
                    browser_context=browser_context,
                    browser_runtime=browser_runtime,
                    working_context=working_context,
                    dialog_state=dialog_state,
                    followup_hint=followup_hint,
                    tool_traces=tool_traces,
                    allow_write_plans=loop_allow_write_plans,
                    allow_auto_execute_actions=loop_allow_auto_execute_actions,
                )
            except Exception as exc:
                if not _is_model_decision_contract_error(exc):
                    raise
                fallback_decision = _build_action_first_fallback_decision(
                    content=current_content,
                    session=session,
                    user=user,
                    page_context=page_context,
                    browser_context=browser_context,
                    working_context=working_context,
                    dialog_state=dialog_state,
                    followup_hint=followup_hint,
                    allow_write_plans=loop_allow_write_plans,
                    allow_auto_execute_actions=loop_allow_auto_execute_actions,
                    tool_traces=tool_traces,
                )
                if fallback_decision is None:
                    fallback_decision = _build_contract_error_clarifying_decision()
                decision = fallback_decision
        if not _decision_has_agent_progress(decision, tool_traces=tool_traces):
            fallback_decision = _build_action_first_fallback_decision(
                content=current_content,
                session=session,
                user=user,
                page_context=page_context,
                browser_context=browser_context,
                working_context=working_context,
                dialog_state=dialog_state,
                followup_hint=followup_hint,
                allow_write_plans=loop_allow_write_plans,
                allow_auto_execute_actions=loop_allow_auto_execute_actions,
                tool_traces=tool_traces,
            )
            if fallback_decision is not None:
                decision = fallback_decision
        if decision.stop_reason == "resume_hint_read":
            loop_allow_write_plans = False
            loop_allow_auto_execute_actions = False
        if decision.conversation_state == "clarifying":
            decision.ui_actions = []
            decision.auto_execute_actions = []
            decision.proposed_write_actions = []
            decision.needs_confirmation = False
            return decision, tool_traces
        read_calls = [item for item in decision.read_tool_calls if item.tool_name in SUPPORTED_READ_TOOLS][:3]
        if not read_calls:
            return decision, tool_traces
        executed_any = False
        for call in read_calls:
            executed_any = True
            _apply_agent_state_patch(
                session,
                execution={
                    "stage": "reading",
                    "step_kind": "read",
                    "step_label": f"读取 {call.tool_name}",
                    "waiting_for": None,
                },
                explanation={
                    "reason": f"需要先读取 {call.tool_name} 的平台数据",
                    "decision_summary": f"执行只读工具 {call.tool_name}",
                    "expected_outcome": "补齐回答或动作所需上下文",
                    "next_step": "读取结果后继续决策",
                    "evidence": _tool_trace_evidence(tool_traces),
                },
            )
            _emit_agent_state(stream_emitter, session, turn_id=turn_id)
            try:
                result = _execute_read_tool(db, tool_name=call.tool_name, arguments=call.arguments)
                trace = {
                    "tool_name": call.tool_name,
                    "arguments": sanitize_json_value(call.arguments),
                    "ok": True,
                    "result": sanitize_json_value(result),
                }
                tool_traces.append(trace)
                if stream_emitter is not None and turn_id:
                    _emit_action_update(
                        stream_emitter,
                        turn_id=turn_id,
                        content=f"已读取 {call.tool_name} 结果，继续推进当前目标。",
                        trace=trace,
                    )
                working_context = _promote_resolved_targets_from_tool_traces([trace], working_context)
                if _has_object_target(working_context):
                    session.working_context_json = working_context
                _apply_agent_state_patch(
                    session,
                    focus=_resolve_agent_focus(
                        page_context=page_context,
                        browser_context=browser_context,
                        working_context=working_context,
                        dialog_state=dialog_state,
                        user_content=current_content,
                        fallback_watch_task_id=session_last_task_id,
                    ),
                    explanation={
                        "reason": f"已完成 {call.tool_name} 读取",
                        "decision_summary": f"{call.tool_name} 已返回结果",
                        "evidence": _tool_trace_evidence(tool_traces),
                    },
                )
                _emit_agent_state(stream_emitter, session, turn_id=turn_id)
            except Exception as exc:
                trace = {
                    "tool_name": call.tool_name,
                    "arguments": sanitize_json_value(call.arguments),
                    "ok": False,
                    "error": sanitize_text(str(exc), max_length=300),
                }
                tool_traces.append(trace)
                if stream_emitter is not None and turn_id:
                    _emit_action_update(
                        stream_emitter,
                        turn_id=turn_id,
                        content=f"{call.tool_name} 执行失败：{sanitize_text(str(exc), max_length=120) or '未知错误'}",
                        trace=trace,
                    )
                _apply_agent_state_patch(
                    session,
                    execution={"stage": "reading", "step_kind": "read", "step_label": f"{call.tool_name} 失败"},
                    explanation={
                        "reason": f"{call.tool_name} 读取失败",
                        "decision_summary": sanitize_text(str(exc), max_length=240),
                        "evidence": _tool_trace_evidence(tool_traces),
                    },
                )
                _emit_agent_state(stream_emitter, session, turn_id=turn_id)
        if not executed_any:
            return decision, tool_traces
        post_read_summary_decision = _build_asset_risk_summary_decision(
            decision=decision,
            tool_traces=tool_traces,
        )
        if post_read_summary_decision is not None:
            return post_read_summary_decision, tool_traces
        if decision.stop_reason == "resume_hint_read":
            resume_summary_decision = _build_resume_hint_summary_decision(session=session, tool_traces=tool_traces)
            if resume_summary_decision is not None:
                return resume_summary_decision, tool_traces
    if decision.read_tool_calls:
        decision.reply_markdown = f"{decision.reply_markdown}\n\n已达到只读工具调用上限，请缩小问题范围后重试。".strip()
        decision.read_tool_calls = []
    return decision, tool_traces


def _normalize_model_write_actions(
    actions: list[_ProposedWriteAction],
    *,
    allowed_types: set[str],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in actions:
        raw = item.model_dump(mode="json")
        action_type = _sanitize_line(str(raw.get("action_type") or ""), max_length=64)
        if action_type not in allowed_types:
            continue
        normalized.append(
            {
                "action_type": action_type,
                "title": sanitize_text(str(raw.get("title") or action_type), max_length=120) or action_type,
                "reason": sanitize_text(str(raw.get("reason") or ""), max_length=240) or "",
                "params": sanitize_json_value(raw.get("params") if isinstance(raw.get("params"), dict) else {}),
            }
        )
    return normalized


def _normalize_model_ui_actions(actions: list[_UIAction]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in actions[:MAX_UI_ACTION_BATCH]:
        normalized_action = _normalize_ui_action(item.model_dump(mode="json"))
        if normalized_action:
            normalized.append(normalized_action)
    return normalized


def _build_model_decision_from_playbook(playbook: AgentPlaybookDecision) -> _AgentModelDecision:
    read_tool_calls: list[_ReadToolCall] = []
    for item in playbook.read_tool_calls[:3]:
        try:
            call = _ReadToolCall.model_validate(item)
        except ValidationError:
            continue
        if call.tool_name in SUPPORTED_READ_TOOLS:
            read_tool_calls.append(call)

    ui_actions: list[_UIAction] = []
    for item in playbook.ui_actions[:MAX_UI_ACTION_BATCH]:
        try:
            ui_actions.append(_UIAction.model_validate(item))
        except ValidationError:
            continue

    proposed_write_actions: list[_ProposedWriteAction] = []
    for item in playbook.proposed_write_actions:
        try:
            proposed_write_actions.append(_ProposedWriteAction.model_validate(item))
        except ValidationError:
            continue

    auto_execute_actions: list[_ProposedWriteAction] = []
    for item in playbook.auto_execute_actions:
        try:
            auto_execute_actions.append(_ProposedWriteAction.model_validate(item))
        except ValidationError:
            continue

    conversation_state = "plan" if playbook.needs_confirmation or proposed_write_actions else playbook.conversation_state
    return _AgentModelDecision(
        reply_markdown=_normalize_assistant_reply_content(playbook.reply_markdown) or playbook.reply_markdown,
        conversation_state=conversation_state,
        objective=playbook.objective,
        read_tool_calls=read_tool_calls,
        ui_actions=ui_actions,
        proposed_write_actions=proposed_write_actions,
        auto_execute_actions=auto_execute_actions,
        needs_confirmation=playbook.needs_confirmation,
        stop_reason=playbook.stop_reason or f"playbook:{playbook.playbook_id}",
    )


def _user_can_auto_execute(user: User) -> bool:
    return _normalize_role(user.role) == "admin"


def _message_allows_auto_execution(
    content: str,
    *,
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
) -> bool:
    if _contains_execution_intent(content):
        return True
    reply_kind = str(followup_hint.get("reply_kind") or "")
    intent_kind = str(dialog_state.get("intent_kind") or "")
    if reply_kind in {"affirm", "short_value"} and intent_kind in {"prepare_plan", "fill_slot"}:
        return True
    candidate_write_context = (
        dialog_state.get("candidate_write_context") if isinstance(dialog_state.get("candidate_write_context"), dict) else {}
    )
    if not candidate_write_context or not candidate_write_context.get("allow_affirm_execute"):
        return False
    action_type = _sanitize_line(str(candidate_write_context.get("action_type") or ""), max_length=64)
    if action_type != "create_discovery_job":
        return False
    explicit_label, _ = _extract_discovery_label_followup(content)
    extracted_values = followup_hint.get("extracted_values") if isinstance(followup_hint.get("extracted_values"), dict) else {}
    return reply_kind == "affirm" or explicit_label or bool(extracted_values.get("cidr"))


def _resolve_platform_url_for_runtime(platform_url: str, browser_context: dict[str, Any]) -> str:
    browser_origin = sanitize_text(str(browser_context.get("origin") or ""), max_length=255, single_line=True) or ""
    if browser_origin.startswith("http://") or browser_origin.startswith("https://"):
        return browser_origin.rstrip("/")
    return str(platform_url or "").rstrip("/")


def _set_browser_runtime(
    session: AgentSession,
    *,
    phase: str,
    browser_context: dict[str, Any],
    last_user_intent: str | None,
    current_objective: str | None = None,
    objective_kind: str | None = None,
    planned_steps: list[dict[str, Any]] | None = None,
    step_cursor: int | None = None,
    pending_ui_actions: list[dict[str, Any]] | None = None,
    pending_secure_input: dict[str, Any] | None = None,
    completed_ui_actions: list[dict[str, Any]] | None = None,
    last_ui_results: list[dict[str, Any]] | None = None,
    auto_executed_actions: list[dict[str, Any]] | None = None,
    step_count: int | None = None,
    retry_state: dict[str, Any] | None = None,
    last_error: str | None = None,
    clear_message_pending: bool = False,
    current_message_request_id: str | None = None,
    message_pending_since: datetime | None = None,
    last_message_request_id: str | None = None,
    last_message_ack_at: datetime | None = None,
    ui_pending_since: datetime | None = None,
    last_step_request_id: str | None = None,
    last_step_ack_at: datetime | None = None,
) -> None:
    current = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    session.browser_runtime_json = _normalize_browser_runtime(
        {
            "phase": phase,
            "step_count": current.get("step_count") if step_count is None else step_count,
            "current_objective": current_objective if current_objective is not None else current.get("current_objective"),
            "objective_kind": objective_kind if objective_kind is not None else current.get("objective_kind"),
            "planned_steps": planned_steps if planned_steps is not None else current.get("planned_steps"),
            "step_cursor": current.get("step_cursor") if step_cursor is None else step_cursor,
            "pending_ui_actions": pending_ui_actions if pending_ui_actions is not None else current.get("pending_ui_actions"),
            "pending_secure_input": pending_secure_input if pending_secure_input is not None else current.get("pending_secure_input"),
            "completed_ui_actions": completed_ui_actions if completed_ui_actions is not None else current.get("completed_ui_actions"),
            "last_ui_results": last_ui_results if last_ui_results is not None else current.get("last_ui_results"),
            "auto_executed_actions": auto_executed_actions if auto_executed_actions is not None else current.get("auto_executed_actions"),
            "last_browser_context": browser_context or current.get("last_browser_context"),
            "semantic_page_context": _browser_semantic_page_context(browser_context) or current.get("semantic_page_context"),
            "retry_state": retry_state if retry_state is not None else current.get("retry_state"),
            "last_user_intent": last_user_intent if last_user_intent is not None else current.get("last_user_intent"),
            "last_error": last_error,
            "current_message_request_id": None
            if clear_message_pending
            else (
                current_message_request_id
                if current_message_request_id is not None
                else current.get("current_message_request_id")
            ),
            "message_pending_since": None
            if clear_message_pending
            else (
                _to_runtime_timestamp(message_pending_since)
                if message_pending_since is not None
                else current.get("message_pending_since")
            ),
            "last_message_request_id": last_message_request_id
            if last_message_request_id is not None
            else current.get("last_message_request_id"),
            "last_message_ack_at": _to_runtime_timestamp(last_message_ack_at)
            if last_message_ack_at is not None
            else current.get("last_message_ack_at"),
            "ui_pending_since": _to_runtime_timestamp(ui_pending_since) if ui_pending_since is not None else current.get("ui_pending_since"),
            "last_step_request_id": last_step_request_id if last_step_request_id is not None else current.get("last_step_request_id"),
            "last_step_ack_at": _to_runtime_timestamp(last_step_ack_at) if last_step_ack_at is not None else current.get("last_step_ack_at"),
        }
    )


def _clear_browser_runtime(
    session: AgentSession,
    *,
    browser_context: dict[str, Any],
    last_user_intent: str | None = None,
    current_objective: str | None = None,
    objective_kind: str | None = None,
    auto_executed_actions: list[dict[str, Any]] | None = None,
    last_error: str | None = None,
    last_message_request_id: str | None = None,
    last_message_ack_at: datetime | None = None,
    last_step_request_id: str | None = None,
    last_step_ack_at: datetime | None = None,
) -> None:
    current = _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {})
    session.browser_runtime_json = _normalize_browser_runtime(
        {
            "phase": "idle",
            "step_count": 0,
            "current_objective": current_objective,
            "objective_kind": objective_kind,
            "planned_steps": [],
            "step_cursor": 0,
            "pending_ui_actions": [],
            "pending_secure_input": {},
            "completed_ui_actions": [],
            "last_ui_results": [],
            "auto_executed_actions": auto_executed_actions or [],
            "last_browser_context": browser_context,
            "semantic_page_context": _browser_semantic_page_context(browser_context),
            "retry_state": {},
            "last_user_intent": last_user_intent,
            "last_error": last_error,
            "current_message_request_id": None,
            "message_pending_since": None,
            "last_message_request_id": last_message_request_id
            if last_message_request_id is not None
            else current.get("last_message_request_id"),
            "last_message_ack_at": _to_runtime_timestamp(last_message_ack_at)
            if last_message_ack_at is not None
            else current.get("last_message_ack_at"),
            "ui_pending_since": None,
            "last_step_request_id": last_step_request_id if last_step_request_id is not None else current.get("last_step_request_id"),
            "last_step_ack_at": _to_runtime_timestamp(last_step_ack_at) if last_step_ack_at is not None else current.get("last_step_ack_at"),
        }
    )


def _summarize_ui_actions(ui_actions: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for item in ui_actions[:4]:
        label = item.get("label_contains") or item.get("text_contains") or item.get("target_node_id") or item.get("href") or ""
        action_type = str(item.get("action_type") or "click")
        parts.append(f"{action_type}{f'({label})' if label else ''}")
    return "，".join(parts)


def _summarize_ui_results(results: list[dict[str, Any]]) -> str:
    if not results:
        return "未收到页面动作回执"
    success = sum(1 for item in results if item.get("ok"))
    total = len(results)
    last_message = next(
        (
            str(item.get("message") or "")
            for item in reversed(results)
            if sanitize_text(str(item.get("message") or ""), max_length=120)
        ),
        "",
    )
    summary = f"已回传 {total} 个页面动作结果，成功 {success} 个"
    if last_message:
        summary = f"{summary}；最近结果：{last_message}"
    return summary


def _execute_auto_actions(
    db: Session,
    *,
    session: AgentSession,
    user: User,
    actions: list[dict[str, Any]],
    browser_context: dict[str, Any],
    platform_url: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    resolved_platform_url = _resolve_platform_url_for_runtime(platform_url, browser_context)
    for item in actions:
        result = execute_approved_action(
            db,
            action=item,
            session_user_id=user.id,
            platform_url=resolved_platform_url,
        )
        payload = {
            "action_type": item.get("action_type"),
            "title": item.get("title"),
            "status": result.status,
            "summary": result.summary,
            "params": sanitize_json_value(item.get("params") if isinstance(item.get("params"), dict) else {}),
            "payload": result.payload or {},
            "child_task_id": result.child_task_id,
        }
        if result.child_task_id and get_task_run(db, result.child_task_id) is not None:
            session.last_task_id = result.child_task_id
            sync_agent_task_watch_state(
                session,
                task_id=result.child_task_id,
                status=result.status,
                message=result.summary,
                action=payload,
                watching=True,
            )
            enqueue_auto_action_followup_task(
                session_id=session.id,
                child_task_id=result.child_task_id,
                action=payload,
            )
        results.append(payload)
    return results


def _append_auto_action_message(
    db: Session,
    *,
    session: AgentSession,
    results: list[dict[str, Any]],
) -> AgentMessage | None:
    if not results:
        return None
    lines = [f"已自动执行 {len(results)} 个低风险动作。"]
    for item in results[:4]:
        lines.append(f"- [{item.get('action_type')}] {item.get('summary')}")
    return _append_message(
        db,
        session=session,
        role="assistant",
        message_type="action_update",
        content="\n".join(lines),
        payload_json={"auto_executed_actions": results},
    )


def _build_auto_execute_reply(action: dict[str, Any], *, user_content: str) -> str:
    action_type = str(action.get("action_type") or "").strip()
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
    if action_type == "create_discovery_job":
        cidr = sanitize_text(str(params.get("cidr") or ""), max_length=64, single_line=True) or "目标网段"
        reused = bool(payload.get("reused"))
        label = sanitize_text(str(params.get("label") or ""), max_length=255, single_line=True) or ""
        if reused:
            base = f"已继续跟踪 {cidr} 的现有扫描任务。"
        elif label:
            base = f"已开始扫描 {cidr}，当前标签为“{label}”。"
        else:
            base = f"已开始扫描 {cidr}，当前使用默认标签。"
        followup = (
            "扫描完成后我可以继续帮你分析该网段资产的漏洞。"
            if any(marker in user_content for marker in ("分析", "漏洞", "风险"))
            else "扫描完成后我可以继续帮你查看该网段的资产结果。"
        )
        return f"{base}{followup}"
    if action_type == "verify_asset_risks":
        asset_id = _sanitize_line(str(params.get("asset_id") or payload.get("asset_id") or ""), max_length=64) or "目标资产"
        return f"已开始验证资产 {asset_id} 的风险。验证完成后我可以继续帮你分析验证结果。"
    if action_type == "install_runner":
        asset_id = _sanitize_line(str(params.get("asset_id") or payload.get("asset_id") or ""), max_length=64) or "目标资产"
        return f"已开始为资产 {asset_id} 安装 Runner。安装完成后我可以继续帮你检查运行状态和后续问题。"
    return sanitize_text(str(action.get("summary") or ""), max_length=4000) or ""


def _build_auto_execute_reply_markdown(
    auto_execute_results: list[dict[str, Any]],
    *,
    user_content: str,
    fallback: str,
) -> str:
    replies = [
        _build_auto_execute_reply(item, user_content=user_content)
        for item in auto_execute_results
        if isinstance(item, dict)
    ]
    replies = [item for item in replies if item]
    if not replies:
        return fallback
    return _normalize_assistant_reply_content("\n\n".join(replies)) or fallback


def _remediation_resume_hint_kind_and_label(
    *,
    status: str,
    business_status: str,
) -> tuple[str, str]:
    if status != TaskExecutionStatus.SUCCESS.value:
        return "task_detail", "查看修复任务详情"
    if business_status == "verified_closed":
        return "post_remediation_review", "输出最终修复报告"
    if business_status == "verified_partial":
        return "post_remediation_gap_analysis", "分析未闭环原因"
    if business_status == "verified_failed":
        return "post_remediation_failure_analysis", "分析修复失败原因"
    if business_status == "pending_reverify":
        return "post_remediation_status", "查看复验状态"
    return "post_remediation_status", "查看修复状态"


def _build_task_followup_resume_hint(action: dict[str, Any], child_summary: dict[str, Any]) -> dict[str, Any]:
    action_type = _sanitize_line(str(action.get("action_type") or ""), max_length=64)
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
    status = _normalize_task_status(child_summary.get("status"))
    result_json = child_summary.get("result_json") if isinstance(child_summary.get("result_json"), dict) else {}
    remediation_business_status = _sanitize_line(
        str(result_json.get("business_status") or ""),
        max_length=64,
    ).lower()
    task_id = _sanitize_line(str(child_summary.get("task_id") or payload.get("submitted_task_id") or ""), max_length=64)
    asset_id = (
        _sanitize_line(str(params.get("asset_id") or payload.get("asset_id") or ""), max_length=64)
        or None
    )
    session_id = _sanitize_line(str(payload.get("session_id") or ""), max_length=64) or None
    cidr = sanitize_text(str(params.get("cidr") or ""), max_length=64, single_line=True) or None

    primary_target: dict[str, Any] = {}
    recent_targets: list[dict[str, Any]] = []
    if action_type == "create_discovery_job" and task_id:
        primary_target = {"task_id": task_id, "source": "task_followup"}
    elif asset_id:
        primary_target = {"asset_id": asset_id, "source": "task_followup"}
        if task_id:
            recent_targets.append({"task_id": task_id, "source": "task_followup"})
    elif task_id:
        primary_target = {"task_id": task_id, "source": "task_followup"}

    working_context = _normalize_working_context(
        {
            "primary_target": primary_target,
            "recent_targets": [primary_target, *recent_targets] if primary_target else recent_targets,
            "source": "task_followup",
        }
    )

    preferred_read_tools: list[dict[str, Any]] = []
    kind = "task_detail"
    suggested_reply_label = "查看任务详情"

    if action_type == "create_discovery_job":
        kind = "post_scan_analysis" if status == TaskExecutionStatus.SUCCESS.value else "task_detail"
        suggested_reply_label = "分析扫描结果"
        if cidr and status == TaskExecutionStatus.SUCCESS.value:
            preferred_read_tools.append({"tool_name": "list_assets", "arguments": {"keyword": cidr, "limit": 5}})
        if task_id:
            preferred_read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
            preferred_read_tools.append({"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 12}})
    elif action_type == "verify_asset_risks":
        kind = "post_verify_analysis" if status == TaskExecutionStatus.SUCCESS.value else "task_detail"
        suggested_reply_label = "分析验证结果"
        if asset_id:
            preferred_read_tools.append({"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "limit": 10}})
        if task_id:
            preferred_read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
    elif action_type == "create_or_resume_remediation_session":
        kind, suggested_reply_label = _remediation_resume_hint_kind_and_label(
            status=status,
            business_status=remediation_business_status,
        )
        if asset_id:
            preferred_read_tools.append({"tool_name": "get_remediation_asset", "arguments": {"asset_id": asset_id}})
        if session_id:
            preferred_read_tools.append({"tool_name": "get_remediation_session", "arguments": {"session_id": session_id}})
        if task_id:
            preferred_read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
    elif action_type == "install_runner":
        suggested_reply_label = "查看 Runner 状态"
        if asset_id:
            preferred_read_tools.append({"tool_name": "get_remediation_asset", "arguments": {"asset_id": asset_id}})
        if task_id:
            preferred_read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
    elif task_id:
        preferred_read_tools.append({"tool_name": "get_task_detail", "arguments": {"task_id": task_id}})
        preferred_read_tools.append({"tool_name": "get_task_events", "arguments": {"task_id": task_id, "limit": 12}})

    return _normalize_resume_hint(
        {
            "kind": kind,
            "working_context": working_context,
            "preferred_read_tools": preferred_read_tools,
            "suggested_reply_label": suggested_reply_label,
        }
    )


def build_auto_action_task_followup_content(action: dict[str, Any], child_summary: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    action_type = _sanitize_line(str(action.get("action_type") or ""), max_length=64)
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    payload = action.get("payload") if isinstance(action.get("payload"), dict) else {}
    status = _normalize_task_status(child_summary.get("status"))
    task_message = sanitize_text(str(child_summary.get("message") or ""), max_length=300) or ""
    result_json = child_summary.get("result_json") if isinstance(child_summary.get("result_json"), dict) else {}
    remediation_business_status = _sanitize_line(
        str(result_json.get("business_status") or ""),
        max_length=64,
    ).lower()
    reverify_summary = result_json.get("reverify_summary") if isinstance(result_json.get("reverify_summary"), dict) else {}
    resume_hint = _build_task_followup_resume_hint(action, child_summary)

    if action_type == "create_discovery_job":
        cidr = sanitize_text(str(params.get("cidr") or ""), max_length=64, single_line=True) or "目标网段"
        if status == TaskExecutionStatus.SUCCESS.value:
            message = f"{cidr} 的扫描任务已完成。"
            if task_message:
                message = f"{message}{task_message}。"
            return "task_update", f"{message} 如需继续，我可以帮你分析该网段的资产和漏洞。", resume_hint
        detail = task_message or "请查看任务详情或事件日志"
        return "error", f"{cidr} 的扫描任务未成功完成：{detail}", resume_hint

    if action_type == "verify_asset_risks":
        asset_id = _sanitize_line(str(params.get("asset_id") or ""), max_length=64) or "目标资产"
        if status == TaskExecutionStatus.SUCCESS.value:
            message = f"资产 {asset_id} 的风险验证任务已完成。"
            if task_message:
                message = f"{message}{task_message}。"
            return "task_update", f"{message} 如需继续，我可以帮你分析最新验证结果。", resume_hint
        detail = task_message or "请查看验证任务详情"
        return "error", f"资产 {asset_id} 的风险验证任务未成功完成：{detail}", resume_hint

    if action_type == "install_runner":
        asset_id = _sanitize_line(str(params.get("asset_id") or ""), max_length=64) or "目标资产"
        if status == TaskExecutionStatus.SUCCESS.value:
            message = f"资产 {asset_id} 的 Runner 安装任务已完成。"
            if task_message:
                message = f"{message}{task_message}。"
            return "task_update", f"{message} 如需继续，我可以帮你检查 Runner 状态和后续问题。", resume_hint
        detail = task_message or "请查看安装任务详情"
        return "error", f"资产 {asset_id} 的 Runner 安装任务未成功完成：{detail}", resume_hint

    if action_type == "create_or_resume_remediation_session":
        asset_id = (
            _sanitize_line(str(params.get("asset_id") or ""), max_length=64)
            or _sanitize_line(str(payload.get("asset_id") or ""), max_length=64)
            or "目标资产"
        )
        session_id = _sanitize_line(str(payload.get("session_id") or ""), max_length=64)
        session_label = f"修复会话 {session_id}" if session_id else "修复会话"
        if status == TaskExecutionStatus.SUCCESS.value:
            target_total = int(reverify_summary.get("targeted_target_count") or 0)
            closed_total = int(reverify_summary.get("closed_target_count") or 0)
            open_total = int(reverify_summary.get("open_target_count") or 0)
            other_total = int(reverify_summary.get("other_open_finding_count") or 0)
            if remediation_business_status == "pending_reverify":
                message = f"资产 {asset_id} 的阶段执行已完成，正在复验目标风险。"
            elif remediation_business_status == "verified_closed":
                message = f"资产 {asset_id} 的目标风险已复验关闭。"
            elif remediation_business_status == "verified_partial":
                message = f"资产 {asset_id} 的阶段执行已完成，但目标风险仍未关闭。"
            elif remediation_business_status == "verified_failed":
                message = f"资产 {asset_id} 的阶段执行后复验失败。"
            else:
                message = f"资产 {asset_id} 的自动修复任务已完成。"
            if target_total:
                message = f"{message}本阶段目标 {target_total} 条，已关闭 {closed_total} 条，仍开放 {open_total} 条，未纳入本阶段的其余风险 {other_total} 条。"
            if task_message:
                message = f"{message}{task_message}。"
            if remediation_business_status == "verified_closed":
                followup = f"{message} 如需继续，我可以直接输出最终修复报告，或带你进入 {session_label} 查看详情。"
            elif remediation_business_status == "verified_partial":
                followup = f"{message} 如需继续，我可以帮你分析未闭环原因，或带你进入 {session_label} 查看详情。"
            elif remediation_business_status == "verified_failed":
                followup = f"{message} 如需继续，我可以帮你分析修复失败原因，或带你进入 {session_label} 查看详情。"
            elif remediation_business_status == "pending_reverify":
                followup = f"{message} 如需继续，我可以帮你查看复验状态，或带你进入 {session_label} 查看详情。"
            else:
                followup = f"{message} 如需继续，我可以帮你查看当前修复状态，或带你进入 {session_label} 查看详情。"
            return "task_update", followup, resume_hint
        detail = task_message or "请查看修复任务详情"
        return "error", f"资产 {asset_id} 的自动修复任务未成功完成：{detail}", resume_hint

    detail = task_message or (status if status else "请查看任务详情")
    if status == TaskExecutionStatus.SUCCESS.value:
        return "task_update", f"关联任务已完成：{detail}", resume_hint
    return "error", f"关联任务未成功完成：{detail}", resume_hint


def sync_agent_task_watch_state(
    session: AgentSession,
    *,
    task_id: str | None,
    status: str | None,
    message: str | None,
    action: dict[str, Any] | None = None,
    watching: bool | None = None,
) -> dict[str, Any]:
    normalized_task_id = _sanitize_line(str(task_id or ""), max_length=64) or None
    normalized_status = _normalize_task_status(status)
    normalized_action = action if isinstance(action, dict) else {}
    action_params = normalized_action.get("params") if isinstance(normalized_action.get("params"), dict) else {}
    action_target = _normalize_agent_focus_target(
        {
            "asset_id": action_params.get("asset_id"),
            "finding_id": action_params.get("finding_id"),
            "task_id": normalized_task_id,
            "session_id": action_params.get("session_id"),
            "cidr": action_params.get("cidr"),
            "source": "task_watch",
        }
    )
    session_working_context = getattr(session, "working_context_json", {})
    current_context = session_working_context if isinstance(session_working_context, dict) else {}
    focus = _resolve_agent_focus(
        working_context=current_context,
        user_content=str(action_params.get("cidr") or ""),
        fallback_watch_task_id=normalized_task_id,
    )
    if action_target:
        focus["resolved"] = action_target
        focus["summary"] = action_target.get("summary")
        focus["focus_type"] = action_target.get("target_type")
        focus["source"] = action_target.get("source")
        focus["confidence"] = "high"
    effective_watching = bool(normalized_task_id) if watching is None else bool(watching)
    stage = "watching_task" if effective_watching else ("failed" if normalized_status in {"failure", "canceled"} else "completed")
    return _apply_agent_state_patch(
        session,
        focus=focus,
        execution={
            "stage": stage,
            "step_kind": "watch_task",
            "step_label": "跟踪后台任务进度" if effective_watching else "后台任务已结束",
            "waiting_for": "等待后台任务完成" if effective_watching else None,
            "missing_slots": [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": sanitize_text(str(normalized_action.get("reason") or normalized_action.get("title") or "跟踪后台任务"), max_length=280)
            or "跟踪后台任务",
            "decision_summary": sanitize_text(str(message or normalized_status or normalized_task_id or ""), max_length=280),
            "expected_outcome": "持续同步后台任务状态并在结束后回显",
            "next_step": "任务结束后追加结果消息" if effective_watching else "等待新的目标",
            "evidence": [],
        },
        watch={
            "primary_task_id": normalized_task_id,
            "related_task_ids": [normalized_task_id] if normalized_task_id else [],
            "status": normalized_status or None,
            "watching": effective_watching,
            "last_task_message": sanitize_text(str(message or ""), max_length=280) or None,
        },
    )


def enqueue_auto_action_followup_task(*, session_id: str, child_task_id: str, action: dict[str, Any]) -> None:
    normalized_session_id = _sanitize_line(str(session_id or ""), max_length=64)
    normalized_task_id = _sanitize_line(str(child_task_id or ""), max_length=64)
    if not normalized_session_id or not normalized_task_id:
        return
    try:
        celery_app.send_task(
            "app.tasks.agent_tasks.run_agent_auto_followup_task",
            args=[normalized_session_id, normalized_task_id, sanitize_json_value(action if isinstance(action, dict) else {})],
        )
    except Exception as exc:
        logger.warning(
            "Failed to enqueue agent auto follow-up task for session=%s child_task=%s: %s",
            normalized_session_id,
            normalized_task_id,
            exc,
        )


def _extract_secure_input_action(actions: list[dict[str, Any]]) -> dict[str, Any]:
    for item in actions:
        if isinstance(item, dict) and _sanitize_line(str(item.get("action_type") or ""), max_length=64) == "configure_ssh_credential":
            return item
    return {}


def _build_pending_secure_input_from_action(
    action: dict[str, Any],
    *,
    current_browser_runtime: dict[str, Any],
) -> dict[str, Any]:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    current_pending = (
        current_browser_runtime.get("pending_secure_input")
        if isinstance(current_browser_runtime.get("pending_secure_input"), dict)
        else {}
    )
    return _normalize_pending_secure_input(
        {
            "kind": "ssh_credential",
            "mode": params.get("mode") or current_pending.get("mode"),
            "asset_id": params.get("asset_id"),
            "asset_ids": params.get("asset_ids"),
            "asset_labels": params.get("asset_labels"),
            "auth_type": params.get("auth_type") or current_pending.get("auth_type"),
            "username": params.get("username") or current_pending.get("username"),
            "resume_goal_id": params.get("resume_goal_id") or current_pending.get("resume_goal_id"),
            "resume_action": params.get("resume_action") if isinstance(params.get("resume_action"), dict) else current_pending.get("resume_action"),
            "auto_verify": params.get("auto_verify") if params.get("auto_verify") is not None else current_pending.get("auto_verify"),
            "auto_resume": params.get("auto_resume") if params.get("auto_resume") is not None else current_pending.get("auto_resume"),
            "blocker_summary": params.get("blocker_summary") or current_pending.get("blocker_summary"),
        }
    )


def _apply_agent_decision(
    db: Session,
    *,
    session: AgentSession,
    user: User,
    decision: _AgentModelDecision,
    tool_traces: list[dict[str, Any]],
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    current_browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    user_content: str,
    existing_pending_plan: dict[str, Any],
    has_pending_plan: bool,
    platform_url: str,
    message_request_id: str | None = None,
    message_request_ack_at: datetime | None = None,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> None:
    current_objective = _build_current_objective(user_content, dialog_state=dialog_state, followup_hint=followup_hint)
    session_last_task_id = _session_last_task_id(session)
    final_working_context = _promote_resolved_targets_from_tool_traces(tool_traces, working_context)
    if _has_object_target(final_working_context):
        session.working_context_json = final_working_context
    normalized_ui_actions = _normalize_model_ui_actions(decision.ui_actions)
    proposed_actions = _normalize_model_write_actions(
        decision.proposed_write_actions,
        allowed_types=SUPPORTED_WRITE_ACTIONS,
    )
    auto_execute_actions = _normalize_model_write_actions(
        decision.auto_execute_actions,
        allowed_types=AUTO_EXECUTE_ACTIONS,
    )
    auto_execute_results: list[dict[str, Any]] = []
    secure_input_action = _extract_secure_input_action(proposed_actions)
    allow_auto_execute = _user_can_auto_execute(user) and _message_allows_auto_execution(
        user_content,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    )
    needs_confirmation = bool(decision.needs_confirmation and proposed_actions and not secure_input_action)

    if auto_execute_actions:
        if allow_auto_execute:
            auto_execute_results = _execute_auto_actions(
                db,
                session=session,
                user=user,
                actions=auto_execute_actions,
                browser_context=browser_context,
                platform_url=platform_url,
            )
            auto_action_message = _append_auto_action_message(db, session=session, results=auto_execute_results)
            if auto_action_message is not None and stream_emitter is not None and turn_id:
                _emit_action_update(
                    stream_emitter,
                    turn_id=turn_id,
                    content=auto_action_message.content,
                    message=auto_action_message,
                )
            decision.reply_markdown = _build_auto_execute_reply_markdown(
                auto_execute_results,
                user_content=sanitize_text(str(dialog_state.get("intent_summary") or user_content), max_length=300) or user_content,
                fallback=decision.reply_markdown,
            )
        elif _user_can_auto_execute(user):
            decision.reply_markdown = (
                f"{decision.reply_markdown}\n\n已识别到可自动执行的低风险动作，但当前意图还不够明确；我已改为待确认计划。"
            ).strip()
            proposed_actions = [*auto_execute_actions, *proposed_actions]
            secure_input_action = _extract_secure_input_action(proposed_actions)
            auto_execute_actions = []
            needs_confirmation = bool(proposed_actions and not secure_input_action)
        else:
            decision.reply_markdown = (
                f"{decision.reply_markdown}\n\n当前账号不是管理员，不能自动执行低风险平台动作。"
            ).strip()
            auto_execute_actions = []

    if not _normalize_role(user.role) == "admin" and proposed_actions and not secure_input_action:
        decision.reply_markdown = (
            f"{decision.reply_markdown}\n\n当前账号为分析员，不能提交执行计划；如需落地请由管理员在相同上下文下确认。"
        ).strip()
        proposed_actions = []
        needs_confirmation = False

    resolved_focus = _resolve_agent_focus(
        page_context=page_context,
        browser_context=browser_context,
        working_context=final_working_context,
        dialog_state=dialog_state,
        user_content=user_content,
        fallback_watch_task_id=session_last_task_id,
    )
    planned_step = _plan_agent_step(
        decision=decision,
        tool_traces=tool_traces,
        normalized_ui_actions=normalized_ui_actions,
        proposed_actions=proposed_actions,
        auto_execute_actions=auto_execute_actions,
        auto_execute_results=auto_execute_results,
    )
    decision_summary = planned_step.reason or sanitize_text(str(decision.stop_reason or decision.objective or ""), max_length=280) or None
    skip_reply_rewrite = decision.stop_reason == "playbook_quick_smalltalk"
    base_assistant_payload = {
        "tool_traces": tool_traces,
        "ui_actions": normalized_ui_actions,
        "proposed_write_actions": proposed_actions,
        "auto_execute_actions": auto_execute_actions,
        "auto_executed_actions": auto_execute_results,
        "mock_mode": _runtime_provider_mode() == "mock",
        "needs_confirmation": needs_confirmation,
        "page_context": page_context,
        "browser_context": browser_context,
        "working_context": final_working_context,
        "followup_hint": followup_hint,
        "stop_reason": decision.stop_reason,
        "skip_reply_rewrite": skip_reply_rewrite,
    }
    rendered_content = _render_planned_step_content(
        planned_step,
        decision=decision,
        fallback_content=_normalize_assistant_reply_content(decision.reply_markdown) or decision.reply_markdown,
        ui_actions=normalized_ui_actions,
        proposed_actions=proposed_actions,
    )

    if decision.conversation_state == "clarifying":
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=has_pending_plan,
        )
        session.dialog_state_json = _build_dialog_state_from_model_decision(
            decision=decision,
            user_content=user_content,
            working_context=final_working_context,
            page_context=page_context,
        )
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=user_content,
            current_objective=decision.objective or current_objective.get("summary"),
            objective_kind=str(current_objective.get("objective_kind") or ""),
            auto_executed_actions=auto_execute_results,
            last_message_request_id=message_request_id,
            last_message_ack_at=message_request_ack_at,
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=resolved_focus,
            execution={
                "stage": "waiting_user_input",
                "step_kind": "clarify",
                "step_label": "等待用户补充信息",
                "waiting_for": planned_step.waiting_for,
                "missing_slots": session.dialog_state_json.get("expected_slots")
                if isinstance(session.dialog_state_json.get("expected_slots"), list)
                else [],
                "pending_ui_actions": [],
            },
            explanation={
                "reason": planned_step.reason,
                "decision_summary": decision_summary,
                "expected_outcome": planned_step.expected_outcome,
                "next_step": planned_step.next_step,
                "evidence": planned_step.evidence,
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        assistant_payload = {
            **base_assistant_payload,
            "dialog_state": sanitize_json_value(session.dialog_state_json),
            **_build_message_state_metadata(
                decision_summary=decision_summary,
                evidence=planned_step.evidence,
                state_delta=state_delta,
            ),
        }
        message = _append_or_stream_assistant_message(
            db,
            session=session,
            message_type="clarifying",
            content=rendered_content,
            payload_json=assistant_payload,
            user_content=user_content,
            tool_traces=tool_traces,
            working_context=final_working_context,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        if isinstance(session.dialog_state_json, dict):
            session.dialog_state_json["last_agent_question"] = message.content
            db.add(session)
        _sync_current_goal_state(db, session, latest_summary=message.content)
        _emit_agent_state(stream_emitter, session, turn_id=turn_id)
        return

    if secure_input_action:
        pending_secure_input = _build_pending_secure_input_from_action(
            secure_input_action,
            current_browser_runtime=current_browser_runtime,
        )
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=False,
        )
        _clear_dialog_state(session)
        _set_browser_runtime(
            session,
            phase="awaiting_secure_input",
            browser_context=browser_context,
            last_user_intent=user_content,
            current_objective=decision.objective or current_objective.get("summary"),
            objective_kind="configure_ssh_credential",
            planned_steps=[
                {
                    "kind": "secure_input",
                    "label": secure_input_action.get("title"),
                    "asset_ids": pending_secure_input.get("asset_ids"),
                }
            ],
            step_cursor=max(0, int(current_browser_runtime.get("step_cursor") or 0)),
            pending_ui_actions=[],
            pending_secure_input=pending_secure_input,
            completed_ui_actions=[],
            last_ui_results=[],
            auto_executed_actions=auto_execute_results,
            step_count=max(1, int(current_browser_runtime.get("step_count") or 0)),
            clear_message_pending=message_request_id is not None,
            last_message_request_id=message_request_id,
            last_message_ack_at=message_request_ack_at,
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=resolved_focus,
            execution={
                "stage": "awaiting_secure_input",
                "step_kind": "secure_input",
                "step_label": "等待安全弹层提交 SSH 凭据",
                "waiting_for": "请在专用弹层中填写密码、私钥或 sudo 密码",
                "missing_slots": [],
                "pending_ui_actions": [],
            },
            explanation={
                "reason": planned_step.reason,
                "decision_summary": decision_summary,
                "expected_outcome": "通过安全弹层保存并验证 SSH 管理员凭据",
                "next_step": "等待用户在安全弹层提交敏感信息",
                "evidence": planned_step.evidence,
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        assistant_payload = {
            **base_assistant_payload,
            "pending_secure_input": pending_secure_input,
            **_build_message_state_metadata(
                decision_summary=decision_summary,
                evidence=planned_step.evidence,
                state_delta=state_delta,
            ),
        }
        message = _append_or_stream_assistant_message(
            db,
            session=session,
            message_type="action_update",
            content=rendered_content,
            payload_json=assistant_payload,
            user_content=user_content,
            tool_traces=tool_traces,
            working_context=final_working_context,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        _sync_current_goal_state(db, session, status_override="blocked", blocked_reason="等待在安全弹层中完成 SSH 凭据配置", latest_summary=message.content)
        _emit_agent_state(stream_emitter, session, turn_id=turn_id)
        return

    if normalized_ui_actions:
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=has_pending_plan,
        )
        _clear_dialog_state(session)
        next_step_count = max(1, int(current_browser_runtime.get("step_count") or 0) + 1)
        if next_step_count > MAX_AGENT_LOOP_STEPS:
            _clear_browser_runtime(
                session,
                browser_context=browser_context,
                last_user_intent=user_content,
                auto_executed_actions=auto_execute_results,
                last_error="已达到站内代理动作上限，请重新描述更具体的目标。",
                last_message_request_id=message_request_id,
                last_message_ack_at=message_request_ack_at,
            )
            state_delta = _apply_agent_state_patch(
                session,
                focus=resolved_focus,
                execution={
                    "stage": "failed",
                    "step_kind": "ui",
                    "step_label": "页面动作已达到上限",
                    "waiting_for": None,
                    "missing_slots": [],
                    "pending_ui_actions": [],
                },
                explanation={
                    "reason": "当前页面动作链路超过最大步数，已中止本轮自动推进",
                    "decision_summary": "站内代理动作达到上限",
                    "expected_outcome": "要求用户提供更具体的下一步目标",
                    "next_step": "等待用户重新描述更精确的操作目标",
                    "evidence": planned_step.evidence,
                },
                watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
            )
            message = _append_message(
                db,
                session=session,
                role="assistant",
                message_type="error",
                content="站内代理动作已达到上限，请直接给我更具体的下一步目标。",
                payload_json={
                    **base_assistant_payload,
                    **_build_message_state_metadata(
                        decision_summary="站内代理动作达到上限",
                        evidence=planned_step.evidence,
                        state_delta=state_delta,
                    ),
                },
            )
            if turn_id:
                _emit_error_event(
                    stream_emitter,
                    detail=message.content,
                    turn_id=turn_id,
                    message=message,
                )
            _sync_current_goal_state(
                db,
                session,
                status_override="blocked",
                blocked_reason="站内动作链路达到上限，请缩小目标范围后继续",
                latest_summary=message.content,
            )
            _emit_agent_state(stream_emitter, session, turn_id=turn_id)
            return
        _set_browser_runtime(
            session,
            phase="awaiting_ui_feedback",
            browser_context=browser_context,
            last_user_intent=user_content,
            current_objective=decision.objective or current_objective.get("summary"),
            objective_kind=str(current_objective.get("objective_kind") or ""),
            planned_steps=[
                {
                    "kind": "ui_action",
                    "action_id": item.get("action_id"),
                    "semantic_action_id": item.get("semantic_action_id"),
                    "label": item.get("label_contains") or item.get("text_contains") or item.get("semantic_action_id"),
                }
                for item in normalized_ui_actions
            ],
            step_cursor=max(0, int(current_browser_runtime.get("step_cursor") or 0)),
            pending_ui_actions=normalized_ui_actions,
            completed_ui_actions=[],
            last_ui_results=[],
            auto_executed_actions=auto_execute_results,
            step_count=next_step_count,
            clear_message_pending=message_request_id is not None,
            last_message_request_id=message_request_id,
            last_message_ack_at=message_request_ack_at,
            ui_pending_since=_now(),
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=resolved_focus,
            execution={
                "stage": "awaiting_ui_feedback",
                "step_kind": "ui",
                "step_label": f"待执行 {len(normalized_ui_actions)} 个页面动作",
                "waiting_for": planned_step.waiting_for,
                "missing_slots": [],
                "pending_ui_actions": normalized_ui_actions,
            },
            explanation={
                "reason": planned_step.reason,
                "decision_summary": decision_summary,
                "expected_outcome": planned_step.expected_outcome,
                "next_step": planned_step.next_step,
                "evidence": planned_step.evidence,
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        assistant_payload = {
            **base_assistant_payload,
            "browser_runtime": sanitize_json_value(session.browser_runtime_json),
            **_build_message_state_metadata(
                decision_summary=decision_summary,
                evidence=planned_step.evidence,
                state_delta=state_delta,
            ),
        }
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="action_update",
            content=rendered_content,
            payload_json=assistant_payload,
        )
        if turn_id:
            _emit_action_update(
                stream_emitter,
                turn_id=turn_id,
                content=rendered_content,
                message=message,
            )
            _emit_ui_actions_requested(
                stream_emitter,
                turn_id=turn_id,
                ui_actions=normalized_ui_actions,
                content=rendered_content,
            )
        _sync_current_goal_state(db, session, latest_summary=message.content)
        _emit_agent_state(stream_emitter, session, turn_id=turn_id)
        return

    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=user_content,
        current_objective=decision.objective or current_objective.get("summary"),
        objective_kind=str(current_objective.get("objective_kind") or ""),
        auto_executed_actions=auto_execute_results,
        last_message_request_id=message_request_id,
        last_message_ack_at=message_request_ack_at,
    )

    if needs_confirmation:
        session.status = "waiting_approval"
        session.pending_plan_json = {
            "reply_markdown": decision.reply_markdown,
            "proposed_write_actions": proposed_actions,
            "auto_executed_actions": auto_execute_results,
            "page_context": page_context,
            "browser_context": browser_context,
            "working_context": final_working_context,
            "resolved_targets": sanitize_json_value(
                final_working_context.get("recent_targets")
                if isinstance(final_working_context.get("recent_targets"), list)
                else []
            ),
        }
        _clear_dialog_state(session)
        state_delta = _apply_agent_state_patch(
            session,
            focus=resolved_focus,
            execution={
                "stage": "waiting_approval",
                "step_kind": "propose_plan",
                "step_label": f"待确认 {len(proposed_actions)} 个执行动作",
                "waiting_for": planned_step.waiting_for,
                "missing_slots": planned_step.missing_slots or [],
                "pending_ui_actions": [],
            },
            explanation={
                "reason": planned_step.reason,
                "decision_summary": decision_summary,
                "expected_outcome": planned_step.expected_outcome,
                "next_step": planned_step.next_step,
                "evidence": planned_step.evidence,
            },
            watch={"primary_task_id": _session_last_task_id(session), "watching": bool(_session_last_task_id(session))},
        )
        assistant_payload = {
            **base_assistant_payload,
            **_build_message_state_metadata(
                decision_summary=decision_summary,
                evidence=planned_step.evidence,
                state_delta=state_delta,
            ),
        }
        message = _append_or_stream_assistant_message(
            db,
            session=session,
            message_type="plan",
            content=rendered_content,
            payload_json=assistant_payload,
            user_content=user_content,
            tool_traces=tool_traces,
            working_context=final_working_context,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        session.pending_plan_json["reply_markdown"] = message.content
        db.add(session)
        if turn_id:
            _emit_plan_pending(
                stream_emitter,
                turn_id=turn_id,
                message=message,
                pending_plan_json=session.pending_plan_json,
            )
        _sync_current_goal_state(db, session, latest_summary=message.content)
        _emit_agent_state(stream_emitter, session, turn_id=turn_id)
        return

    _preserve_or_reset_pending_plan(
        session,
        existing_pending_plan=existing_pending_plan,
        preserve_existing=has_pending_plan,
    )
    _clear_dialog_state(session)
    child_task_ids = [
        _sanitize_line(str(item.get("child_task_id") or ""), max_length=64)
        for item in auto_execute_results
        if isinstance(item, dict)
    ]
    child_task_ids = [item for item in child_task_ids if item]
    state_delta = _apply_agent_state_patch(
        session,
        focus=resolved_focus,
        execution={
            "stage": "watching_task" if child_task_ids else "completed",
            "step_kind": planned_step.step_kind,
            "step_label": "等待后台任务完成" if child_task_ids else "已完成当前回复",
            "waiting_for": planned_step.waiting_for if child_task_ids else None,
            "missing_slots": planned_step.missing_slots or [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": planned_step.reason,
            "decision_summary": decision_summary,
            "expected_outcome": planned_step.expected_outcome,
            "next_step": planned_step.next_step,
            "evidence": planned_step.evidence,
        },
        watch={
            "primary_task_id": child_task_ids[0] if child_task_ids else _session_last_task_id(session),
            "related_task_ids": child_task_ids,
            "status": "running" if child_task_ids else None,
            "watching": bool(child_task_ids),
        },
    )
    assistant_payload = {
        **base_assistant_payload,
        **_build_message_state_metadata(
            decision_summary=decision_summary,
            evidence=planned_step.evidence,
            state_delta=state_delta,
        ),
    }
    final_message = _append_or_stream_assistant_message(
        db,
        session=session,
        message_type="text",
        content=rendered_content,
        payload_json=assistant_payload,
        user_content=user_content,
        tool_traces=tool_traces,
        working_context=final_working_context,
        stream_emitter=stream_emitter,
        turn_id=turn_id,
    )
    _sync_current_goal_state(
        db,
        session,
        latest_summary=final_message.content if final_message is not None else rendered_content,
    )
    _emit_agent_state(stream_emitter, session, turn_id=turn_id)


def post_agent_message(
    db: Session,
    *,
    user: User,
    payload: AgentMessageCreateRequest,
    platform_url: str,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> AgentSessionRead:
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(db, session=session):
        db.flush()
    if session is None or not is_active_public_session_status(str(session.status or "")):
        session = _create_session(db, user=user)
        db.flush()
    session_last_task_id = _session_last_task_id(session)
    session_is_running = str(session.status or "") == "running"
    client_message_id = _normalize_client_message_id(payload.client_message_id) or f"haor-msg-{uuid4().hex[:12]}"

    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    current_phase = str(current_browser_runtime.get("phase") or "")
    current_message_request_id = _normalize_client_message_id(current_browser_runtime.get("current_message_request_id"))
    if _is_duplicate_message_request(current_browser_runtime, client_message_id=client_message_id):
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=current_phase or "idle",
            result="duplicate",
        )
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)
    if current_phase == "awaiting_agent_reply" and current_message_request_id and current_message_request_id != client_message_id:
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=current_phase,
            result="conflict",
        )
        raise AgentConflictError("当前 haor 正在处理上一轮消息，请稍候或重试", session_id=session.id, stage="message")

    page_context = _normalize_page_context(payload.page_context.model_dump(mode="json"))
    browser_context = _normalize_browser_context(payload.browser_context.model_dump(mode="json"))
    browser_context["pathname"] = browser_context.get("pathname") or page_context.get("pathname")
    browser_context["query"] = browser_context.get("query") or page_context.get("query")
    browser_context["asset_id"] = browser_context.get("asset_id") or page_context.get("asset_id")
    browser_context["finding_id"] = browser_context.get("finding_id") or page_context.get("finding_id")
    browser_context["task_id"] = browser_context.get("task_id") or page_context.get("task_id")
    session.route_context_json = page_context
    session.updated_at = _now()
    if session.status in {"completed", "failed"}:
        session.status = "active"
    current_browser_runtime["last_browser_context"] = browser_context
    current_browser_runtime["last_user_intent"] = payload.content
    current_browser_runtime["semantic_page_context"] = _browser_semantic_page_context(browser_context)
    current_dialog_state = _normalize_dialog_state(
        session.dialog_state_json if isinstance(session.dialog_state_json, dict) else {}
    )
    followup_hint = _build_followup_hint(payload.content, current_dialog_state)
    current_objective = _build_current_objective(
        payload.content,
        dialog_state=current_dialog_state,
        followup_hint=followup_hint,
    )
    current_browser_runtime["current_objective"] = current_objective.get("summary")
    current_browser_runtime["objective_kind"] = current_objective.get("objective_kind")
    if followup_hint.get("reply_kind") == "new_topic":
        current_dialog_state = {}
        _clear_dialog_state(session)
        followup_hint = {}
        current_objective = _build_current_objective(payload.content, dialog_state={}, followup_hint={})
        current_browser_runtime["current_objective"] = current_objective.get("summary")
        current_browser_runtime["objective_kind"] = current_objective.get("objective_kind")
    existing_pending_plan = (
        sanitize_json_value(session.pending_plan_json) if isinstance(session.pending_plan_json, dict) else {}
    )
    has_pending_plan = _has_pending_plan(existing_pending_plan)
    db.add(session)
    working_context = _resolve_working_context_for_message(
        db=db,
        session=session,
        content=payload.content,
        page_context=page_context,
        browser_context=browser_context,
        dialog_state=current_dialog_state,
        followup_hint=followup_hint,
    )
    _append_message(
        db,
        session=session,
        role="user",
        message_type="text",
        content=payload.content,
        payload_json={
            "client_message_id": client_message_id,
            "page_context": page_context,
            "browser_context": browser_context,
            "working_context": working_context,
            "dialog_state": current_dialog_state,
            "followup_hint": followup_hint,
        },
    )
    accepted_at = _now()
    _set_browser_runtime(
        session,
        phase="awaiting_agent_reply",
        browser_context=browser_context,
        last_user_intent=payload.content,
        current_objective=current_objective.get("summary"),
        objective_kind=str(current_objective.get("objective_kind") or ""),
        planned_steps=current_browser_runtime.get("planned_steps")
        if isinstance(current_browser_runtime.get("planned_steps"), list)
        else [],
        step_cursor=int(current_browser_runtime.get("step_cursor") or 0),
        pending_ui_actions=current_browser_runtime.get("pending_ui_actions")
        if isinstance(current_browser_runtime.get("pending_ui_actions"), list)
        else [],
        completed_ui_actions=current_browser_runtime.get("completed_ui_actions")
        if isinstance(current_browser_runtime.get("completed_ui_actions"), list)
        else [],
        last_ui_results=current_browser_runtime.get("last_ui_results")
        if isinstance(current_browser_runtime.get("last_ui_results"), list)
        else [],
        auto_executed_actions=current_browser_runtime.get("auto_executed_actions")
        if isinstance(current_browser_runtime.get("auto_executed_actions"), list)
        else [],
        step_count=int(current_browser_runtime.get("step_count") or 0),
        retry_state=current_browser_runtime.get("retry_state")
        if isinstance(current_browser_runtime.get("retry_state"), dict)
        else {},
        last_error=None,
        current_message_request_id=client_message_id,
        message_pending_since=accepted_at,
        last_message_request_id=client_message_id,
        last_message_ack_at=accepted_at,
    )
    _apply_agent_state_patch(
        session,
        focus=_resolve_agent_focus(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            dialog_state=current_dialog_state,
            user_content=payload.content,
            fallback_watch_task_id=session_last_task_id,
        ),
        execution={
            "stage": "awaiting_agent_reply",
            "step_kind": "answer",
            "step_label": "正在解析用户请求",
            "waiting_for": None,
            "missing_slots": [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": "已接收新消息，正在解析目标与下一步动作",
            "decision_summary": sanitize_text(str(current_objective.get("summary") or payload.content), max_length=280),
            "expected_outcome": "确定当前轮次的单一步骤",
            "next_step": "完成解析后进入追问、回答、页面动作或执行",
            "evidence": [],
        },
        watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
    )
    goal = ensure_goal_for_message(
        db,
        user=user,
        session=session,
        content=payload.content,
        page_context=page_context,
        browser_context=browser_context,
        working_context=working_context,
        followup_hint=followup_hint,
        current_objective=current_objective.get("summary"),
        objective_kind=str(current_objective.get("objective_kind") or ""),
    )
    _sync_current_goal_state(
        db,
        session,
        status_override="active",
        latest_summary=sanitize_text(payload.content, max_length=280) or goal.title,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    _log_message_turn_event(
        session_id=session.id,
        turn_id=turn_id,
        client_message_id=client_message_id,
        phase="awaiting_agent_reply",
        result="accepted",
    )
    _emit_session_snapshot(stream_emitter, session)

    if has_pending_plan and _should_cancel_pending_plan(payload.content):
        if not _refresh_message_turn_if_active(
            db,
            session=session,
            client_message_id=client_message_id,
            turn_id=turn_id,
            phase="cancel_pending_plan",
        ):
            return serialize_agent_session(session)
        _preserve_or_reset_pending_plan(session, existing_pending_plan=existing_pending_plan, preserve_existing=False)
        _clear_dialog_state(session)
        _append_message(
            db,
            session=session,
            role="assistant",
            message_type="text",
            content="已取消当前待确认计划。你可以继续在同一会话里分析别的对象，或提出新的执行意图。",
            payload_json={
                "page_context": page_context,
                "browser_context": browser_context,
                "working_context": working_context,
                "pending_plan_cleared": True,
                **_build_message_state_metadata(
                    decision_summary="已取消待确认计划",
                    evidence=[],
                    state_delta={
                        "execution": {
                            "stage": "completed",
                            "step_label": "已取消待确认计划",
                        }
                    },
                ),
            },
        )
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=payload.content,
            last_message_request_id=client_message_id,
            last_message_ack_at=accepted_at,
        )
        _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=working_context,
                user_content=payload.content,
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "completed", "step_kind": "answer", "step_label": "已取消待确认计划", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "用户明确取消当前待确认计划",
                "decision_summary": "已取消待确认计划",
                "expected_outcome": "回到普通会话态，等待新的目标",
                "next_step": "等待用户继续提问或发起新的执行意图",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason="用户已取消当前待确认计划",
            latest_summary="已取消待确认计划",
        )
        db.commit()
        db.refresh(session)
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or "idle"
            ),
            result="completed",
        )
        _emit_streamed_assistant_message(stream_emitter, turn_id=turn_id or str(uuid4()), message=session.messages[-1])
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if current_dialog_state and followup_hint.get("reply_kind") == "deny":
        if not _refresh_message_turn_if_active(
            db,
            session=session,
            client_message_id=client_message_id,
            turn_id=turn_id,
            phase="followup_deny",
        ):
            return serialize_agent_session(session)
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=has_pending_plan,
        )
        _clear_dialog_state(session)
        _append_message(
            db,
            session=session,
            role="assistant",
            message_type="text",
            content="已取消上一轮补问。你可以直接换一个问题，或继续告诉我新的分析/执行目标。",
            payload_json={
                "page_context": page_context,
                "browser_context": browser_context,
                "working_context": working_context,
                "followup_resolution": {"status": "canceled"},
                **_build_message_state_metadata(
                    decision_summary="已取消上一轮补问",
                    evidence=[],
                    state_delta={
                        "execution": {
                            "stage": "completed",
                            "step_label": "已取消上一轮补问",
                        }
                    },
                ),
            },
        )
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=payload.content,
            last_message_request_id=client_message_id,
            last_message_ack_at=accepted_at,
        )
        _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=working_context,
                user_content=payload.content,
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "completed", "step_kind": "answer", "step_label": "已取消上一轮追问", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "用户否定了上一轮追问的继续路径",
                "decision_summary": "已取消上一轮补问",
                "expected_outcome": "解除追问阻塞，返回普通会话态",
                "next_step": "等待用户给出新的目标或对象",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason="用户已取消上一轮补问，等待新的目标",
            latest_summary="已取消上一轮补问",
        )
        db.commit()
        db.refresh(session)
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or "idle"
            ),
            result="completed",
        )
        _emit_streamed_assistant_message(stream_emitter, turn_id=turn_id or str(uuid4()), message=session.messages[-1])
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    internal_followup_decision = _build_internal_followup_decision(
        user=user,
        user_content=payload.content,
        dialog_state=current_dialog_state,
        followup_hint=followup_hint,
    )
    if internal_followup_decision is not None:
        if not _refresh_message_turn_if_active(
            db,
            session=session,
            client_message_id=client_message_id,
            turn_id=turn_id,
            phase="internal_followup",
        ):
            return serialize_agent_session(session)
        _apply_agent_decision(
            db,
            session=session,
            user=user,
            decision=internal_followup_decision,
            tool_traces=[],
            page_context=page_context,
            browser_context=browser_context,
            current_browser_runtime=current_browser_runtime,
            working_context=working_context,
            dialog_state=current_dialog_state,
            followup_hint=followup_hint,
            user_content=payload.content,
            existing_pending_plan=existing_pending_plan,
            has_pending_plan=has_pending_plan,
            platform_url=platform_url,
            message_request_id=client_message_id,
            message_request_ack_at=accepted_at,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        db.commit()
        db.refresh(session)
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or "idle"
            ),
            result="completed",
        )
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if session_is_running and str(current_objective.get("objective_kind") or "") == "operate_high_risk":
        if not _refresh_message_turn_if_active(
            db,
            session=session,
            client_message_id=client_message_id,
            turn_id=turn_id,
            phase="running_task_conflict",
        ):
            return serialize_agent_session(session)
        _apply_agent_decision(
            db,
            session=session,
            user=user,
            decision=_build_running_task_conflict_decision(task_id=session_last_task_id),
            tool_traces=[],
            page_context=page_context,
            browser_context=browser_context,
            current_browser_runtime=current_browser_runtime,
            working_context=working_context,
            dialog_state=current_dialog_state,
            followup_hint=followup_hint,
            user_content=payload.content,
            existing_pending_plan=existing_pending_plan,
            has_pending_plan=has_pending_plan,
            platform_url=platform_url,
            message_request_id=client_message_id,
            message_request_ack_at=accepted_at,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        db.commit()
        db.refresh(session)
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or "idle"
            ),
            result="completed",
        )
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if not current_dialog_state and not _should_skip_preflight_clarification(payload.content, session=session):
        preflight_clarification = _build_preflight_clarification(
            payload.content,
            working_context=working_context,
            page_context=page_context,
        )
        if preflight_clarification:
            if not _refresh_message_turn_if_active(
                db,
                session=session,
                client_message_id=client_message_id,
                turn_id=turn_id,
                phase="preflight_clarifying",
            ):
                return serialize_agent_session(session)
            _preserve_or_reset_pending_plan(
                session,
                existing_pending_plan=existing_pending_plan,
                preserve_existing=has_pending_plan,
            )
            session.dialog_state_json = _build_preflight_dialog_state(
                question=preflight_clarification,
                user_content=payload.content,
                working_context=working_context,
                page_context=page_context,
            )
            _append_message(
                db,
                session=session,
                role="assistant",
                message_type="clarifying",
                content=preflight_clarification,
                payload_json={
                    "page_context": page_context,
                    "browser_context": browser_context,
                    "working_context": working_context,
                    "dialog_state": sanitize_json_value(session.dialog_state_json),
                    **_build_message_state_metadata(
                        decision_summary="进入预检追问",
                        evidence=[],
                        state_delta={
                            "execution": {
                                "stage": "waiting_user_input",
                                "step_kind": "clarify",
                                "step_label": "预检追问",
                            }
                        },
                    ),
                },
            )
            _clear_browser_runtime(
                session,
                browser_context=browser_context,
                last_user_intent=payload.content,
                last_message_request_id=client_message_id,
                last_message_ack_at=accepted_at,
            )
            _apply_agent_state_patch(
                session,
                focus=_resolve_agent_focus(
                    page_context=page_context,
                    browser_context=browser_context,
                    working_context=working_context,
                    dialog_state=session.dialog_state_json,
                    user_content=payload.content,
                    fallback_watch_task_id=session_last_task_id,
                ),
                execution={
                    "stage": "waiting_user_input",
                    "step_kind": "clarify",
                    "step_label": "预检追问",
                    "waiting_for": "等待用户补充目标对象或范围",
                    "missing_slots": session.dialog_state_json.get("expected_slots")
                    if isinstance(session.dialog_state_json.get("expected_slots"), list)
                    else [],
                    "pending_ui_actions": [],
                },
                explanation={
                    "reason": "预检阶段发现当前目标对象或执行范围不明确",
                    "decision_summary": "进入预检追问",
                    "expected_outcome": "补齐目标对象或执行范围后继续推进",
                    "next_step": "等待用户补充后继续解析",
                    "evidence": [],
                },
                watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
            )
            _sync_current_goal_state(db, session, latest_summary=preflight_clarification)
            db.commit()
            db.refresh(session)
            _log_message_turn_event(
                session_id=session.id,
                turn_id=turn_id,
                client_message_id=client_message_id,
                phase=str(
                    _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                        "phase"
                    )
                    or "idle"
                ),
                result="completed",
            )
            _emit_streamed_assistant_message(stream_emitter, turn_id=turn_id or str(uuid4()), message=session.messages[-1])
            _emit_session_snapshot(stream_emitter, session)
            return serialize_agent_session(session)

    allow_write_plans = _normalize_role(user.role) == "admin" and not session_is_running
    allow_auto_execute_actions = _user_can_auto_execute(user) and not session_is_running
    try:
        decision, tool_traces = _run_agent_loop(
            db,
            session=session,
            user=user,
            page_context=page_context,
            browser_context=browser_context,
            browser_runtime=current_browser_runtime,
            working_context=working_context,
            dialog_state=current_dialog_state,
            followup_hint=followup_hint,
            allow_write_plans=allow_write_plans,
            allow_auto_execute_actions=allow_auto_execute_actions,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
    except Exception as exc:
        if not _refresh_message_turn_if_active(
            db,
            session=session,
            client_message_id=client_message_id,
            turn_id=turn_id,
            phase="run_loop_error",
        ):
            return serialize_agent_session(session)
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=has_pending_plan,
        )
        session.dialog_state_json = current_dialog_state if current_dialog_state else {}
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=payload.content,
            last_error=_humanize_ai_error(exc),
            last_message_request_id=client_message_id,
            last_message_ack_at=accepted_at,
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                dialog_state=current_dialog_state,
                user_content=payload.content,
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "failed", "step_kind": "answer", "step_label": "模型调用失败", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "当前轮次在模型推理或决策解析阶段失败",
                "decision_summary": _humanize_ai_error(exc),
                "expected_outcome": "向用户暴露明确错误，等待重试或调整目标",
                "next_step": "等待用户重试或切换目标",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="error",
            content=f"当前 AI 调用失败：{_humanize_ai_error(exc)}",
            payload_json={
                "error": _humanize_ai_error(exc),
                "browser_context": browser_context,
                "working_context": sanitize_json_value(
                    session.working_context_json if isinstance(session.working_context_json, dict) else {}
                ),
                **_build_message_state_metadata(
                    decision_summary=_humanize_ai_error(exc),
                    evidence=[],
                    state_delta=state_delta,
                ),
            },
        )
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason=_humanize_ai_error(exc),
            latest_summary=message.content,
        )
        db.commit()
        db.refresh(session)
        _log_message_turn_event(
            session_id=session.id,
            turn_id=turn_id,
            client_message_id=client_message_id,
            phase=str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or "idle"
            ),
            result="error",
        )
        _emit_error_event(
            stream_emitter,
            detail=message.content,
            turn_id=turn_id,
            message=message,
        )
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    internal_scan_decision = _build_internal_scan_clarifying_decision(
        user_content=payload.content,
        page_context=page_context,
        working_context=working_context,
        dialog_state=current_dialog_state,
        tool_traces=tool_traces,
    )
    if internal_scan_decision is not None:
        decision = internal_scan_decision

    if not _refresh_message_turn_if_active(
        db,
        session=session,
        client_message_id=client_message_id,
        turn_id=turn_id,
        phase="apply_decision",
    ):
        return serialize_agent_session(session)
    _apply_agent_decision(
        db,
        session=session,
        user=user,
        decision=decision,
        tool_traces=tool_traces,
        page_context=page_context,
        browser_context=browser_context,
        current_browser_runtime=current_browser_runtime,
        working_context=working_context,
        dialog_state=current_dialog_state,
        followup_hint=followup_hint,
        user_content=payload.content,
        existing_pending_plan=existing_pending_plan,
        has_pending_plan=has_pending_plan,
        platform_url=platform_url,
        message_request_id=client_message_id,
        message_request_ack_at=accepted_at,
        stream_emitter=stream_emitter,
        turn_id=turn_id,
    )
    db.commit()
    db.refresh(session)
    _log_message_turn_event(
        session_id=session.id,
        turn_id=turn_id,
        client_message_id=client_message_id,
        phase=str(
            _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                "phase"
            )
            or "idle"
        ),
        result="completed",
    )
    _emit_session_snapshot(stream_emitter, session)
    return serialize_agent_session(session)


def _normalize_result_payload_blockers(result_payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    payload = result_payload if isinstance(result_payload, dict) else {}
    blockers: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()

    def _infer_blocker_code_from_message(message: str) -> str:
        lowered_message = message.lower()
        if "maintenance_window_id" in lowered_message or "维护窗口" in message:
            return "maintenance_window_required"
        if ("ssh" in lowered_message and any(marker in message for marker in ("凭据", "私钥", "密码", "授权"))) or "未配置 ssh" in lowered_message:
            return "missing_ssh_credential"
        if "管理员授权" in message:
            return "authorization_unconfirmed"
        if "管理员权限验证" in message:
            return "authorization_not_verified"
        if "未验证到管理员权限" in message or "root/sudo" in lowered_message or "sudo 凭据" in message:
            return "insufficient_privilege"
        if "尚未安装" in message:
            return "runner_not_installed"
        if "正在安装中" in message:
            return "runner_installing"
        if "当前离线" in message:
            return "runner_offline"
        if "未识别到稳定的软件包管理器或包名" in message:
            return "unstable_render"
        if "未识别稳定的软件包管理器" in message or "未识别稳定的软件包名" in message:
            return "unstable_render"
        if "无法生成安全步骤" in message or "无法稳定渲染" in message:
            return "unstable_render"
        if "缺少自动修复适配器" in message:
            return "missing_adapter"
        if "未解析到" in message:
            return "missing_target"
        if "白名单" in message:
            return "action_not_allowed"
        if "snapshot" in lowered_message or "深度检查结果" in message:
            return "missing_snapshot"
        return "unknown_blocker"

    def _blocker_category(code: str, message: str) -> str:
        normalized_code = _sanitize_line(code, max_length=64)
        lowered_message = message.lower()
        if normalized_code == "maintenance_window_required":
            return "policy"
        if normalized_code in SSH_CREDENTIAL_BLOCKER_CODES:
            return "ssh"
        if normalized_code in RUNNER_BLOCKER_CODES:
            return "runner"
        if normalized_code in RENDER_BLOCKER_CODES:
            return "render"
        if "runner" in lowered_message:
            return "runner"
        if "未识别到稳定的软件包管理器或包名" in message:
            return "render"
        if "未识别稳定的软件包管理器" in message or "未识别稳定的软件包名" in message:
            return "render"
        if "无法生成安全步骤" in message or "无法稳定渲染" in message:
            return "render"
        if "ssh" in lowered_message or "sudo" in lowered_message:
            return "ssh"
        return "other"

    raw_blockers = payload.get("blockers") if isinstance(payload.get("blockers"), list) else []
    for item in raw_blockers:
        if not isinstance(item, dict):
            continue
        raw_message = sanitize_text(str(item.get("message") or item.get("blocker_message") or ""), max_length=280) or ""
        raw_code = _sanitize_line(str(item.get("code") or item.get("blocker_code") or ""), max_length=64) or ""
        normalized_code = raw_code
        if not normalized_code or normalized_code == "unknown_blocker":
            normalized_code = _infer_blocker_code_from_message(raw_message)
        blocker = {
            "code": normalized_code,
            "message": raw_message,
            "blocker_category": _blocker_category(normalized_code, raw_message),
            "scope": _sanitize_line(str(item.get("scope") or ""), max_length=64) or None,
            "blocking": _sanitize_line(str(item.get("blocking") or ""), max_length=32) or None,
            "stage_code": _sanitize_line(str(item.get("stage_code") or ""), max_length=64) or None,
            "step_id": _sanitize_line(str(item.get("step_id") or ""), max_length=64) or None,
        }
        if not blocker["message"]:
            continue
        signature = (
            blocker["code"] or "",
            blocker["message"] or "",
            blocker["scope"] or "",
            blocker["blocking"] or "",
            blocker["stage_code"] or "",
            blocker["step_id"] or "",
        )
        if signature in seen:
            continue
        seen.add(signature)
        blockers.append(blocker)
    if blockers:
        return blockers

    blocked_reasons = payload.get("blocked_reasons") if isinstance(payload.get("blocked_reasons"), list) else []
    for raw_reason in blocked_reasons:
        message = sanitize_text(str(raw_reason or ""), max_length=280) or ""
        if not message:
            continue
        code = _infer_blocker_code_from_message(message)
        signature = (code, message, "", "", "", "")
        if signature in seen:
            continue
        seen.add(signature)
        blockers.append(
            {
                "code": code,
                "message": message,
                "blocker_category": _blocker_category(code, message),
                "scope": None,
                "blocking": None,
                "stage_code": None,
                "step_id": None,
            }
        )
    return blockers


def _has_ssh_credential_blockers(blockers: list[dict[str, Any]]) -> bool:
    for item in blockers:
        if not isinstance(item, dict):
            continue
        code = _sanitize_line(str(item.get("code") or item.get("blocker_code") or ""), max_length=64)
        if code in SSH_CREDENTIAL_BLOCKER_CODES:
            return True
    return False


def _format_blocker_summary(blockers: list[dict[str, Any]], *, max_items: int = 3) -> str:
    messages: list[str] = []
    for item in blockers:
        if not isinstance(item, dict):
            continue
        message = sanitize_text(str(item.get("message") or item.get("blocker_message") or ""), max_length=280) or ""
        if message and message not in messages:
            messages.append(message)
        if len(messages) >= max_items:
            break
    return "；".join(messages)


def _collect_blocker_categories(blockers: list[dict[str, Any]]) -> list[str]:
    categories: list[str] = []
    for item in blockers:
        if not isinstance(item, dict):
            continue
        category = _sanitize_line(str(item.get("blocker_category") or ""), max_length=32)
        if not category:
            code = _sanitize_line(str(item.get("code") or item.get("blocker_code") or ""), max_length=64)
            if code in SSH_CREDENTIAL_BLOCKER_CODES:
                category = "ssh"
            elif code in RUNNER_BLOCKER_CODES:
                category = "runner"
            elif code == "maintenance_window_required":
                category = "policy"
            elif code in RENDER_BLOCKER_CODES:
                category = "render"
            else:
                message = sanitize_text(str(item.get("message") or item.get("blocker_message") or ""), max_length=280) or ""
                lowered_message = message.lower()
                if "runner" in lowered_message:
                    category = "runner"
                elif "未识别到稳定的软件包管理器或包名" in message or "无法稳定渲染" in message:
                    category = "render"
                elif "ssh" in lowered_message or "sudo" in lowered_message:
                    category = "ssh"
        if category and category not in categories:
            categories.append(category)
    return categories


def _build_message_action_payload(
    *,
    kind: str,
    label: str,
    message_text: str | None = None,
    pathname: str | None = None,
    asset_id: str | None = None,
) -> dict[str, Any]:
    payload = {
        "kind": _sanitize_line(kind, max_length=32) or "navigate",
        "label": sanitize_text(label, max_length=80) or "继续",
    }
    if message_text:
        payload["message_text"] = sanitize_text(message_text, max_length=240) or ""
    if pathname:
        payload["pathname"] = sanitize_text(pathname, max_length=255, single_line=True) or ""
    if asset_id:
        payload["asset_id"] = _sanitize_line(asset_id, max_length=64) or ""
    return payload


def _build_remediation_guidance_payload(
    *,
    asset_id: str,
    blockers: list[dict[str, Any]],
) -> dict[str, Any]:
    blocker_categories = _collect_blocker_categories(blockers)
    guidance: dict[str, Any] = {"blocker_categories": blocker_categories}
    if "policy" in blocker_categories:
        guidance["recommended_action"] = _build_message_action_payload(
            kind="open_maintenance_window_input",
            label="填写维护窗口并继续自动修复",
        )
        guidance["alternative_action"] = _build_message_action_payload(
            kind="navigate",
            label="查看修复工作台详情",
            pathname=f"/remediation/{asset_id}",
        )
        guidance["post_verify_action"] = "maintenance_window_required"
        return guidance
    if "runner" in blocker_categories:
        guidance["recommended_action"] = _build_message_action_payload(
            kind="install_runner_and_resume",
            label="继续安装 Runner 后走自动修复",
            message_text=f"继续为资产 {asset_id} 安装 Runner，然后继续自动修复",
            asset_id=asset_id,
        )
        guidance["post_verify_action"] = "runner_required"
        if "render" in blocker_categories:
            guidance["alternative_action"] = _build_message_action_payload(
                kind="navigate",
                label="改走交互式修复预演",
                pathname=f"/remediation-workspace/{asset_id}",
            )
        else:
            guidance["alternative_action"] = _build_message_action_payload(
                kind="navigate",
                label="查看修复工作台详情",
                pathname=f"/remediation/{asset_id}",
            )
        return guidance
    if "render" in blocker_categories:
        guidance["recommended_action"] = _build_message_action_payload(
            kind="navigate",
            label="改走交互式修复预演",
            pathname=f"/remediation-workspace/{asset_id}",
        )
        guidance["alternative_action"] = _build_message_action_payload(
            kind="navigate",
            label="查看修复工作台详情",
            pathname=f"/remediation/{asset_id}",
        )
        guidance["post_verify_action"] = "interactive_remediation_recommended"
        return guidance
    guidance["recommended_action"] = _build_message_action_payload(
        kind="navigate",
        label="查看修复工作台详情",
        pathname=f"/remediation/{asset_id}",
    )
    guidance["post_verify_action"] = "review_remediation_workspace"
    return guidance


def _queue_asset_collection_refresh(db: Session, *, asset_id: str) -> str:
    task_run = create_task_run(
        db,
        task_type=TaskType.INFO_COLLECT,
        scope_type="asset",
        scope_id=asset_id,
        message="SSH 凭据已验证，正在刷新主机事实",
    )
    task = run_asset_collect_task.delay(task_run.id, asset_id)
    update_task_run(db, task_run, celery_task_id=task.id)
    return task_run.id


def _enqueue_secure_refresh_resume_followup(
    *,
    session_id: str,
    refresh_task_id: str,
    action: dict[str, Any],
    asset_id: str,
) -> None:
    normalized_session_id = _sanitize_line(str(session_id or ""), max_length=64)
    normalized_refresh_task_id = _sanitize_line(str(refresh_task_id or ""), max_length=64)
    normalized_asset_id = _sanitize_line(str(asset_id or ""), max_length=64)
    if not normalized_session_id or not normalized_refresh_task_id or not normalized_asset_id:
        return
    try:
        celery_app.send_task(
            "app.tasks.agent_tasks.run_agent_secure_post_verify_resume_task",
            args=[
                normalized_session_id,
                normalized_refresh_task_id,
                sanitize_json_value(action if isinstance(action, dict) else {}),
                normalized_asset_id,
            ],
        )
    except Exception as exc:
        logger.warning(
            "Failed to enqueue secure post-verify remediation resume for session=%s task=%s asset=%s: %s",
            normalized_session_id,
            normalized_refresh_task_id,
            normalized_asset_id,
            exc,
        )


def _remediation_resume_action_from_payload(result_payload: dict[str, Any], *, asset_id: str) -> dict[str, Any]:
    session_id = _sanitize_line(str(result_payload.get("session_id") or ""), max_length=64) or None
    title = f"为资产 {asset_id} 继续准备修复会话"
    if session_id:
        title = f"继续修复会话 {session_id}"
    return {
        "action_type": "create_or_resume_remediation_session",
        "title": title,
        "reason": "SSH 凭据验证成功后，继续原自动修复目标。",
        "params": {"asset_id": asset_id, "submit_if_ready": True},
    }


def transition_session_to_remediation_secure_input(
    db: Session,
    *,
    session_id: str,
    task_id: str,
    action: dict[str, Any],
    result_payload: dict[str, Any],
    content: str | None = None,
) -> None:
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    blocker_items = _normalize_result_payload_blockers(result_payload)
    blocker_summary = _format_blocker_summary(blocker_items, max_items=4)
    remaining_blockers = [
        item
        for item in blocker_items
        if _sanitize_line(str(item.get("code") or ""), max_length=64) not in SSH_CREDENTIAL_BLOCKER_CODES
    ]
    asset_id = _sanitize_line(
        str(
            result_payload.get("asset_id")
            or (action.get("params") if isinstance(action.get("params"), dict) else {}).get("asset_id")
            or ""
        ),
        max_length=64,
    ) or ""
    if not asset_id:
        return
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    browser_context = _normalize_browser_context(
        current_browser_runtime.get("last_browser_context")
        if isinstance(current_browser_runtime.get("last_browser_context"), dict)
        else session.route_context_json if isinstance(session.route_context_json, dict) else {}
    )
    browser_context["asset_id"] = browser_context.get("asset_id") or asset_id
    page_context = _page_context_from_browser_context(browser_context)
    browser_target = _build_working_context_from_page_context(page_context, source="secure_input_resume")
    if _has_object_target(browser_target):
        session.working_context_json = _merge_soft_focus_context(
            session.working_context_json if isinstance(session.working_context_json, dict) else {},
            browser_target,
        )
    resume_action = _remediation_resume_action_from_payload(result_payload, asset_id=asset_id)
    pending_secure_input = _normalize_pending_secure_input(
        {
            "kind": "ssh_credential",
            "mode": "single_asset",
            "asset_id": asset_id,
            "asset_ids": [asset_id],
            "asset_labels": [f"资产 {asset_id}"],
            "resume_goal_id": _sanitize_line(str(getattr(session, "current_goal_id", None) or ""), max_length=64) or None,
            "resume_action": resume_action,
            "auto_verify": True,
            "auto_resume": True,
            "blocker_summary": blocker_summary or "当前自动修复仍缺少 SSH 管理员凭据",
        }
    )
    content_text = sanitize_text(content, max_length=4000) or (
        f"当前自动修复先被 SSH 凭据阻塞，我已为资产 {asset_id} 打开 SSH 凭据安全配置弹层。"
        "保存并验证 SSH 后，我会自动续接当前修复目标。"
    )
    if remaining_blockers:
        extra_summary = _format_blocker_summary(remaining_blockers, max_items=3)
        if extra_summary:
            content_text = (
                f"{content_text}\n\n"
                f"即使 SSH 已补齐，后续仍可能继续受这些条件影响：{extra_summary}。"
            )
    session.status = "active"
    session.pending_plan_json = {}
    _clear_dialog_state(session)
    _set_browser_runtime(
        session,
        phase="awaiting_secure_input",
        browser_context=browser_context,
        last_user_intent=sanitize_text(str(current_browser_runtime.get("last_user_intent") or ""), max_length=240) or "自动修复",
        current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or f"为资产 {asset_id} 配置 SSH 凭据",
        objective_kind="configure_ssh_credential",
        planned_steps=[
            {
                "kind": "secure_input",
                "label": "配置 SSH 管理员凭据",
                "asset_ids": pending_secure_input.get("asset_ids"),
            }
        ],
        step_cursor=0,
        pending_ui_actions=[],
        pending_secure_input=pending_secure_input,
        completed_ui_actions=[],
        last_ui_results=[],
        auto_executed_actions=[],
        step_count=1,
        last_message_request_id=_normalize_client_message_id(current_browser_runtime.get("last_message_request_id")),
        last_message_ack_at=_parse_runtime_timestamp(current_browser_runtime.get("last_message_ack_at")),
    )
    session.last_task_id = task_id
    state_delta = _apply_agent_state_patch(
        session,
        focus=_resolve_agent_focus(
            page_context=page_context,
            browser_context=browser_context,
            working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
            fallback_watch_task_id=task_id,
        ),
        execution={
            "stage": "awaiting_secure_input",
            "step_kind": "secure_input",
            "step_label": "等待 SSH 凭据安全输入",
            "waiting_for": "请先在安全弹层中填写 SSH 密码、私钥或 sudo 密码",
            "missing_slots": [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": "当前自动修复先被 SSH 凭据阻塞，需先完成安全输入与管理员权限验证",
            "decision_summary": content_text,
            "expected_outcome": "通过安全弹层保存并验证 SSH 管理员凭据",
            "next_step": "保存并验证 SSH 后自动续接修复；若仍缺 Runner 或其他条件，会继续明确提示",
            "evidence": blocker_items[:4],
        },
        watch={
            "primary_task_id": task_id,
            "related_task_ids": [task_id] if task_id else [],
            "status": TaskExecutionStatus.SUCCESS.value,
            "watching": False,
            "last_task_message": content_text,
        },
    )
    message = _append_message(
        db,
        session=session,
        role="assistant",
        message_type="action_update",
        content=content_text,
        payload_json={
            "task_id": task_id,
            "action": sanitize_json_value(action),
            "result_payload": sanitize_json_value(result_payload),
            "pending_secure_input": pending_secure_input,
            **_build_message_state_metadata(
                decision_summary=content_text,
                evidence=blocker_items[:4],
                state_delta=state_delta,
            ),
        },
    )
    _sync_current_goal_state(
        db,
        session,
        status_override="blocked",
        blocked_reason="等待在安全弹层中完成 SSH 凭据配置",
        latest_summary=message.content,
        goal_blockers=blocker_items,
    )


def append_blocked_action_result_message(
    db: Session,
    *,
    session_id: str,
    task_id: str,
    action: dict[str, Any],
    result_payload: dict[str, Any],
    content: str,
    blocked_reason: str | None = None,
    message_payload_patch: dict[str, Any] | None = None,
) -> None:
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    blocker_items = _normalize_result_payload_blockers(result_payload)
    asset_id = _sanitize_line(
        str(
            result_payload.get("asset_id")
            or (action.get("params") if isinstance(action.get("params"), dict) else {}).get("asset_id")
            or ""
        ),
        max_length=64,
    ) or ""
    guidance_payload = _build_remediation_guidance_payload(asset_id=asset_id, blockers=blocker_items) if asset_id else {}
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    browser_context = _normalize_browser_context(
        current_browser_runtime.get("last_browser_context")
        if isinstance(current_browser_runtime.get("last_browser_context"), dict)
        else session.route_context_json if isinstance(session.route_context_json, dict) else {}
    )
    session.status = "active"
    session.pending_plan_json = {}
    _clear_dialog_state(session)
    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=sanitize_text(str(current_browser_runtime.get("last_user_intent") or ""), max_length=240) or None,
        current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or None,
        objective_kind=sanitize_text(str(current_browser_runtime.get("objective_kind") or ""), max_length=64, single_line=True) or None,
        auto_executed_actions=[],
        last_message_request_id=_normalize_client_message_id(current_browser_runtime.get("last_message_request_id")),
        last_message_ack_at=_parse_runtime_timestamp(current_browser_runtime.get("last_message_ack_at")),
        last_step_request_id=_normalize_step_request_id(current_browser_runtime.get("last_step_request_id")),
        last_step_ack_at=_parse_runtime_timestamp(current_browser_runtime.get("last_step_ack_at")),
    )
    session.last_task_id = task_id
    blocked_summary = sanitize_text(blocked_reason, max_length=500) or _format_blocker_summary(blocker_items, max_items=4) or sanitize_text(content, max_length=500) or "当前目标存在阻塞"
    state_delta = _apply_agent_state_patch(
        session,
        focus=_resolve_agent_focus(
            browser_context=browser_context,
            working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
            fallback_watch_task_id=task_id,
        ),
        execution={
            "stage": "blocked",
            "step_kind": _sanitize_line(str(action.get("action_type") or "action"), max_length=64) or "action",
            "step_label": "当前目标受阻，等待补齐前置条件",
            "waiting_for": "请先补齐阻塞条件后继续",
            "missing_slots": [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": "当前动作已执行到阻塞判断，但前置条件尚未闭合",
            "decision_summary": sanitize_text(content, max_length=280) or blocked_summary,
            "expected_outcome": "明确当前阻塞并等待补齐条件",
            "next_step": "补齐阻塞条件后再继续自动修复，或进入修复工作台查看详情",
            "evidence": blocker_items[:4],
        },
        watch={
            "primary_task_id": task_id,
            "related_task_ids": [task_id] if task_id else [],
            "status": TaskExecutionStatus.SUCCESS.value,
            "watching": False,
            "last_task_message": sanitize_text(content, max_length=280) or blocked_summary,
        },
    )
    message = _append_message(
        db,
        session=session,
        role="assistant",
        message_type="action_update",
        content=sanitize_text(content, max_length=4000) or blocked_summary,
        payload_json={
            "task_id": task_id,
            "action": sanitize_json_value(action),
            "result_payload": sanitize_json_value(result_payload),
            **sanitize_json_value(guidance_payload),
            **sanitize_json_value(message_payload_patch if isinstance(message_payload_patch, dict) else {}),
            **_build_message_state_metadata(
                decision_summary=sanitize_text(content, max_length=280) or blocked_summary,
                evidence=blocker_items[:4],
                state_delta=state_delta,
            ),
        },
    )
    _sync_current_goal_state(
        db,
        session,
        status_override="blocked",
        blocked_reason=blocked_summary,
        latest_summary=message.content,
        goal_blockers=blocker_items,
    )


def _secure_input_result_details(ui_action_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for item in ui_action_results:
        if not isinstance(item, dict):
            continue
        detail_json = item.get("detail_json") if isinstance(item.get("detail_json"), dict) else {}
        kind = _sanitize_line(str(detail_json.get("kind") or ""), max_length=64)
        if kind in {"ssh_credential_single", "ssh_credential_batch", "ssh_credential_cancel"}:
            details.append(sanitize_json_value(detail_json))
    return details


def _expand_secure_resume_actions(pending_secure_input: dict[str, Any], *, success_asset_ids: list[str]) -> list[dict[str, Any]]:
    resume_action = pending_secure_input.get("resume_action") if isinstance(pending_secure_input.get("resume_action"), dict) else {}
    action_type = _sanitize_line(str(resume_action.get("action_type") or ""), max_length=64)
    if action_type not in SUPPORTED_WRITE_ACTIONS or action_type == "configure_ssh_credential":
        return []
    params = resume_action.get("params") if isinstance(resume_action.get("params"), dict) else {}
    if not success_asset_ids:
        return []
    if action_type not in {"verify_asset_risks", "install_runner", "create_or_resume_remediation_session"}:
        return [
            {
                "action_type": action_type,
                "title": sanitize_text(str(resume_action.get("title") or action_type), max_length=120) or action_type,
                "reason": sanitize_text(str(resume_action.get("reason") or ""), max_length=240) or "",
                "params": sanitize_json_value(params),
            }
        ]

    actions: list[dict[str, Any]] = []
    for asset_id in success_asset_ids:
        cloned_params = sanitize_json_value({**params, "asset_id": asset_id})
        actions.append(
            {
                "action_type": action_type,
                "title": sanitize_text(str(resume_action.get("title") or action_type), max_length=120) or action_type,
                "reason": sanitize_text(str(resume_action.get("reason") or ""), max_length=240) or "",
                "params": cloned_params,
            }
        )
    return actions


def _build_secure_input_resume_hint(
    pending_secure_input: dict[str, Any],
    *,
    success_asset_ids: list[str],
    child_task_ids: list[str],
) -> dict[str, Any]:
    if child_task_ids:
        return _normalize_resume_hint(
            {
                "kind": "task_detail",
                "working_context": {
                    "task_id": child_task_ids[0],
                    "source": "secure_input_resume",
                },
                "preferred_read_tools": [{"tool_name": "get_task_detail", "arguments": {"task_id": child_task_ids[0]}}],
                "suggested_reply_label": "查看任务详情",
            }
        )

    if success_asset_ids:
        return _normalize_resume_hint(
            {
                "kind": "post_verify_analysis",
                "working_context": {
                    "asset_id": success_asset_ids[0],
                    "source": "secure_input_resume",
                },
                "suggested_reply_label": "继续当前目标",
            }
        )
    return {}


def _collect_blocked_resume_results(
    resume_results: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str | None]:
    blocked_results: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seen_blockers: set[tuple[str, str, str, str, str, str]] = set()

    for item in resume_results:
        if not isinstance(item, dict):
            continue
        if _sanitize_line(str(item.get("action_type") or ""), max_length=64) != "create_or_resume_remediation_session":
            continue
        if _sanitize_line(str(item.get("child_task_id") or ""), max_length=64):
            continue
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        if payload.get("execution_ready") is not False:
            continue
        normalized_blockers = _normalize_result_payload_blockers(payload)
        blocked_results.append(
            {
                "asset_id": _sanitize_line(
                    str(
                        payload.get("asset_id")
                        or (item.get("params") if isinstance(item.get("params"), dict) else {}).get("asset_id")
                        or ""
                    ),
                    max_length=64,
                )
                or None,
                "summary": sanitize_text(str(item.get("summary") or ""), max_length=280) or None,
                "blockers": normalized_blockers,
            }
        )
        for blocker in normalized_blockers:
            signature = (
                _sanitize_line(str(blocker.get("code") or ""), max_length=64) or "",
                sanitize_text(str(blocker.get("message") or ""), max_length=280) or "",
                _sanitize_line(str(blocker.get("scope") or ""), max_length=64) or "",
                _sanitize_line(str(blocker.get("blocking") or ""), max_length=32) or "",
                _sanitize_line(str(blocker.get("stage_code") or ""), max_length=64) or "",
                _sanitize_line(str(blocker.get("step_id") or ""), max_length=64) or "",
            )
            if signature in seen_blockers:
                continue
            seen_blockers.add(signature)
            blockers.append(blocker)

    blocker_summary = _format_blocker_summary(blockers, max_items=4) or None
    return blocked_results, blockers, blocker_summary


def _handle_secure_input_step(
    db: Session,
    *,
    session: AgentSession,
    user: User,
    browser_context: dict[str, Any],
    current_browser_runtime: dict[str, Any],
    ui_action_results: list[dict[str, Any]],
    platform_url: str,
    step_request_id: str | None = None,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> AgentSessionRead | None:
    pending_secure_input = (
        current_browser_runtime.get("pending_secure_input")
        if isinstance(current_browser_runtime.get("pending_secure_input"), dict)
        else {}
    )
    if not pending_secure_input:
        return None

    detail_items = _secure_input_result_details(ui_action_results)
    if not detail_items:
        return None

    accepted_at = _now()
    details = detail_items[0]
    kind = _sanitize_line(str(details.get("kind") or ""), max_length=64)
    last_user_intent = sanitize_text(str(current_browser_runtime.get("last_user_intent") or ""), max_length=240) or "配置 SSH 凭据"
    browser_target = _build_working_context_from_page_context(_page_context_from_browser_context(browser_context), source="secure_input")
    if _has_object_target(browser_target):
        session.working_context_json = _merge_soft_focus_context(
            session.working_context_json if isinstance(session.working_context_json, dict) else {},
            browser_target,
        )

    if kind == "ssh_credential_cancel":
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=last_user_intent,
            current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or None,
            objective_kind=sanitize_text(str(current_browser_runtime.get("objective_kind") or ""), max_length=64, single_line=True) or None,
            auto_executed_actions=current_browser_runtime.get("auto_executed_actions")
            if isinstance(current_browser_runtime.get("auto_executed_actions"), list)
            else [],
            last_step_request_id=step_request_id,
            last_step_ack_at=accepted_at,
        )
        session.status = "active"
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=_session_last_task_id(session),
            ),
            execution={"stage": "completed", "step_kind": "secure_input", "step_label": "已取消 SSH 凭据配置", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "用户取消了 SSH 凭据安全输入流程",
                "decision_summary": "已取消 SSH 凭据配置",
                "expected_outcome": "解除输入锁定并返回聊天上下文",
                "next_step": "等待新的输入",
                "evidence": [],
            },
            watch={"primary_task_id": _session_last_task_id(session), "watching": bool(_session_last_task_id(session))},
        )
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="action_update",
            content="已取消 SSH 凭据配置。你可以稍后重新发起，或继续处理别的目标。",
            payload_json={
                "secure_input_result": {"kind": kind, "canceled": True},
                **_build_message_state_metadata(
                    decision_summary="已取消 SSH 凭据配置",
                    evidence=[],
                    state_delta=state_delta,
                ),
            },
        )
        _sync_current_goal_state(db, session, status_override="blocked", blocked_reason="用户已取消 SSH 凭据配置", latest_summary=message.content)
        db.commit()
        db.refresh(session)
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    result_items: list[dict[str, Any]] = []
    if kind == "ssh_credential_single":
        result_items = [
            {
                "asset_id": _sanitize_line(str(details.get("asset_id") or ""), max_length=64) or None,
                "saved": bool(details.get("saved")),
                "verified": bool(details.get("verified")),
                "effective_privilege": _sanitize_line(str(details.get("effective_privilege") or ""), max_length=32) or None,
                "error_summary": sanitize_text(str(details.get("error_summary") or ""), max_length=220) or None,
                "auth_type": _sanitize_line(str(details.get("auth_type") or ""), max_length=16) or None,
                "username": sanitize_text(str(details.get("username") or ""), max_length=128, single_line=True) or None,
            }
        ]
    elif kind == "ssh_credential_batch":
        raw_results = details.get("results") if isinstance(details.get("results"), list) else []
        for item in raw_results[:32]:
            if not isinstance(item, dict):
                continue
            result_items.append(
                {
                    "asset_id": _sanitize_line(str(item.get("asset_id") or ""), max_length=64) or None,
                    "saved": bool(item.get("saved")),
                    "verified": bool(item.get("verified")),
                    "effective_privilege": _sanitize_line(str(item.get("effective_privilege") or ""), max_length=32) or None,
                    "error_summary": sanitize_text(str(item.get("error_summary") or ""), max_length=220) or None,
                }
            )

    success_asset_ids = [
        str(item.get("asset_id"))
        for item in result_items
        if item.get("asset_id") and item.get("verified") is True
    ]
    failed_items = [item for item in result_items if item.get("verified") is not True]
    child_task_ids: list[str] = []
    resume_results: list[dict[str, Any]] = []
    refresh_task_id: str | None = None
    post_verify_action: str | None = None
    if success_asset_ids and pending_secure_input.get("auto_resume") is not False:
        resume_goal_id = _sanitize_line(str(pending_secure_input.get("resume_goal_id") or ""), max_length=64)
        if resume_goal_id:
            try:
                resume_agent_goal_binding(db, user=user, session=session, goal_id=resume_goal_id)
            except Exception:
                pass
        resume_actions = _expand_secure_resume_actions(pending_secure_input, success_asset_ids=success_asset_ids)
        if (
            len(success_asset_ids) == 1
            and len(resume_actions) == 1
            and _sanitize_line(str(resume_actions[0].get("action_type") or ""), max_length=64)
            == "create_or_resume_remediation_session"
        ):
            refresh_task_id = _queue_asset_collection_refresh(db, asset_id=success_asset_ids[0])
            child_task_ids = [refresh_task_id]
            post_verify_action = "refresh_and_resume"
            _enqueue_secure_refresh_resume_followup(
                session_id=session.id,
                refresh_task_id=refresh_task_id,
                action=resume_actions[0],
                asset_id=success_asset_ids[0],
            )
        elif resume_actions:
            resume_results = _execute_auto_actions(
                db,
                session=session,
                user=user,
                actions=resume_actions,
                browser_context=browser_context,
                platform_url=platform_url,
            )
            child_task_ids = [
                _sanitize_line(str(item.get("child_task_id") or ""), max_length=64)
                for item in resume_results
                if isinstance(item, dict)
            ]
            child_task_ids = [item for item in child_task_ids if item]

    blocked_resume_results, blocked_resume_blockers, blocked_resume_summary = _collect_blocked_resume_results(resume_results)
    blocked_resume_count = len(blocked_resume_results)
    auto_resumed_count = 0 if refresh_task_id else len(child_task_ids)

    failure_lines = [
        f"{item.get('asset_id') or '目标资产'}：{item.get('error_summary') or '未通过管理员权限验证'}"
        for item in failed_items[:6]
    ]
    if kind == "ssh_credential_batch":
        content_lines = [
            f"SSH 凭据批量处理完成：共 {len(result_items)} 台，成功 {len(success_asset_ids)} 台，失败 {len(failed_items)} 台。",
        ]
        if auto_resumed_count:
            content_lines.append(f"已自动续接 {auto_resumed_count} 台资产的原目标。")
        if blocked_resume_count:
            blocked_intro = f"另有 {blocked_resume_count} 台资产在补齐 SSH 后，原修复目标仍未继续执行"
            if blocked_resume_summary:
                content_lines.append(f"{blocked_intro}：{blocked_resume_summary}。")
            else:
                content_lines.append(f"{blocked_intro}。")
        if failure_lines:
            content_lines.append("失败资产：")
            content_lines.extend(f"- {line}" for line in failure_lines)
        content = "\n".join(content_lines)
    else:
        asset_id = success_asset_ids[0] if success_asset_ids else _sanitize_line(str(details.get("asset_id") or ""), max_length=64) or "目标资产"
        if success_asset_ids:
            if refresh_task_id:
                content = f"资产 {asset_id} 的 SSH 凭据已保存并验证成功。正在通过 SSH 刷新主机信息；刷新完成后会重新评估修复条件。"
            elif blocked_resume_count:
                content = f"资产 {asset_id} 的 SSH 凭据已保存并验证成功，但修复暂未继续执行。"
                if blocked_resume_summary:
                    content = f"{content} 剩余阻塞：{blocked_resume_summary}。"
                else:
                    content = f"{content} 仍有其他前置条件未满足。"
            elif auto_resumed_count:
                content = f"资产 {asset_id} 的 SSH 凭据已保存并验证成功。 我已自动续接原目标。"
            else:
                content = f"资产 {asset_id} 的 SSH 凭据已保存并验证成功。你现在可以继续执行需要管理员 SSH 的操作。"
        else:
            failure_summary = failure_lines[0] if failure_lines else (sanitize_text(str(details.get("error_summary") or ""), max_length=220) or "未通过管理员权限验证")
            content = f"资产 {asset_id} 的 SSH 凭据已保存，但未验证成功：{failure_summary}"

    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=last_user_intent,
        current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or None,
        objective_kind=sanitize_text(str(current_browser_runtime.get("objective_kind") or ""), max_length=64, single_line=True) or None,
        auto_executed_actions=resume_results,
        last_step_request_id=step_request_id,
        last_step_ack_at=accepted_at,
    )
    if child_task_ids:
        session.status = "running"
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=child_task_ids[0],
            ),
            execution={
                "stage": "watching_task",
                "step_kind": "secure_input",
                "step_label": "SSH 已验证，正在刷新主机信息" if refresh_task_id else "凭据验证成功，已续接原目标",
                "waiting_for": "等待主机事实刷新完成" if refresh_task_id else "等待后台任务完成",
                "missing_slots": [],
                "pending_ui_actions": [],
            },
            explanation={
                "reason": "SSH 凭据验证成功后，正在刷新主机事实并恢复原修复目标" if refresh_task_id else "SSH 凭据验证成功后，已恢复原阻塞目标",
                "decision_summary": content,
                "expected_outcome": "主机事实刷新完成后自动重新评估修复条件" if refresh_task_id else "等待恢复后的任务完成并自动回传结果",
                "next_step": "采集完成后自动进入修复条件重评估，并给出继续自动修或替代建议" if refresh_task_id else "任务完成后自动追加结论消息",
                "evidence": [],
            },
            watch={"primary_task_id": child_task_ids[0], "related_task_ids": child_task_ids, "status": "running", "watching": True},
        )
        goal_status_override = "active"
        blocked_reason = None
        goal_blockers = None
    elif blocked_resume_count:
        session.status = "active"
        blocked_reason = blocked_resume_summary or "SSH 凭据已验证，但修复暂未继续执行"
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=_session_last_task_id(session),
            ),
            execution={
                "stage": "blocked",
                "step_kind": "secure_input",
                "step_label": "SSH 已验证，等待补齐剩余修复条件",
                "waiting_for": "请先补齐 Runner、包管理器识别或其他修复前置条件",
                "missing_slots": [],
                "pending_ui_actions": [],
            },
            explanation={
                "reason": "SSH 凭据验证成功，但恢复原修复目标时仍存在剩余阻塞",
                "decision_summary": content,
                "expected_outcome": "明确剩余阻塞并等待补齐条件后继续修复",
                "next_step": "补齐剩余阻塞条件后继续修复，或进入修复工作台查看详情",
                "evidence": blocked_resume_blockers[:4],
            },
            watch={"primary_task_id": _session_last_task_id(session), "watching": False},
        )
        goal_status_override = "blocked"
        goal_blockers = blocked_resume_blockers
    else:
        session.status = "active"
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=_session_last_task_id(session),
            ),
            execution={"stage": "completed", "step_kind": "secure_input", "step_label": "SSH 凭据流程已完成", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "SSH 凭据流程已完成",
                "decision_summary": content,
                "expected_outcome": "返回普通聊天或等待新的目标",
                "next_step": "继续追问或发起新的操作",
                "evidence": [],
            },
            watch={"primary_task_id": _session_last_task_id(session), "watching": False},
        )
        goal_status_override = "active" if success_asset_ids else "blocked"
        blocked_reason = None if success_asset_ids else "SSH 凭据尚未验证成功"
        goal_blockers = None

    resume_hint = _build_secure_input_resume_hint(
        pending_secure_input,
        success_asset_ids=success_asset_ids,
        child_task_ids=child_task_ids,
    )
    message = _append_message(
        db,
        session=session,
        role="assistant",
        message_type="action_update",
        content=content,
        payload_json={
            "secure_input_result": {
                "kind": kind,
                "results": result_items,
                "success_asset_ids": success_asset_ids,
                "failure_count": len(failed_items),
                "auto_resumed_count": auto_resumed_count,
                "blocked_resume_count": blocked_resume_count,
                "post_verify_action": post_verify_action,
                "refresh_task_id": refresh_task_id,
            },
            "auto_executed_actions": resume_results,
            "resume_hint": resume_hint,
            **_build_message_state_metadata(
                decision_summary=content,
                evidence=[],
                state_delta=state_delta,
            ),
        },
    )
    _sync_current_goal_state(
        db,
        session,
        status_override=goal_status_override,
        blocked_reason=blocked_reason,
        latest_summary=message.content,
        goal_blockers=goal_blockers,
    )
    db.commit()
    db.refresh(session)
    _emit_session_snapshot(stream_emitter, session)
    return serialize_agent_session(session)


def post_agent_step(
    db: Session,
    *,
    user: User,
    payload: AgentUIStepRequest,
    platform_url: str,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> AgentSessionRead:
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(db, session=session):
        db.flush()
    if session is None or not is_active_public_session_status(str(session.status or "")):
        raise AgentConflictError("当前没有可继续的 haor 会话", stage="step")
    _raise_if_session_running(session, stage="step")
    session_last_task_id = _session_last_task_id(session)

    browser_context = _normalize_browser_context(payload.browser_context.model_dump(mode="json"))
    page_context = _page_context_from_browser_context(browser_context)
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    step_request_id = _normalize_step_request_id(payload.step_request_id)
    if _is_duplicate_step_request(current_browser_runtime, step_request_id=step_request_id):
        logger.info(
            "haor ui_step duplicate ignored",
            extra={
                "agent_session_id": session.id,
                "agent_turn_id": turn_id,
                "agent_step_request_id": step_request_id,
                "agent_phase": str(current_browser_runtime.get("phase") or ""),
                "agent_result": "duplicate",
            },
        )
        return serialize_agent_session(session)

    session.route_context_json = page_context
    session.updated_at = _now()
    pending_ui_actions = (
        current_browser_runtime.get("pending_ui_actions")
        if isinstance(current_browser_runtime.get("pending_ui_actions"), list)
        else []
    )
    ui_action_results = _normalize_ui_action_results(
        [item.model_dump(mode="json") for item in payload.ui_action_results]
    )

    secure_step_result = _handle_secure_input_step(
        db,
        session=session,
        user=user,
        browser_context=browser_context,
        current_browser_runtime=current_browser_runtime,
        ui_action_results=ui_action_results,
        platform_url=platform_url,
        step_request_id=step_request_id,
        stream_emitter=stream_emitter,
        turn_id=turn_id,
    )
    if secure_step_result is not None:
        return secure_step_result
    if isinstance(current_browser_runtime.get("pending_secure_input"), dict) and current_browser_runtime.get("pending_secure_input"):
        return serialize_agent_session(session)

    if not pending_ui_actions:
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(current_browser_runtime.get("last_user_intent") or "") or None,
        )
        _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "idle", "step_kind": "answer", "step_label": "没有待继续的页面动作", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "当前没有挂起的 UI 动作需要继续处理",
                "decision_summary": "忽略空的页面动作回执",
                "expected_outcome": "保持会话空闲态",
                "next_step": "等待新的消息或页面动作请求",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        _sync_current_goal_state(db, session, latest_summary="没有待继续的页面动作")
        db.commit()
        db.refresh(session)
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if int(current_browser_runtime.get("step_count") or 0) >= MAX_AGENT_LOOP_STEPS:
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(current_browser_runtime.get("last_user_intent") or "") or None,
            last_error="已达到站内代理动作上限，请重新描述更具体的目标。",
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "failed", "step_kind": "ui", "step_label": "页面动作达到上限", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "页面动作链路超过最大步数",
                "decision_summary": "已达到站内代理动作上限",
                "expected_outcome": "要求用户缩小目标范围",
                "next_step": "等待用户给出更具体的操作目标",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="error",
            content="站内代理动作已达到上限，请直接给我更具体的下一步目标。",
            payload_json={
                "browser_context": browser_context,
                **_build_message_state_metadata(
                    decision_summary="已达到站内代理动作上限",
                    evidence=[],
                    state_delta=state_delta,
                ),
            },
        )
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason="站内动作链路达到上限，请缩小目标范围后继续",
            latest_summary=message.content,
        )
        db.commit()
        db.refresh(session)
        _emit_error_event(stream_emitter, detail=message.content, turn_id=turn_id, message=message)
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if ui_action_results:
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="action_update",
            content=_summarize_ui_results(ui_action_results),
            payload_json={"ui_action_results": ui_action_results, "browser_context": browser_context},
        )
        _emit_action_update(
            stream_emitter,
            turn_id=turn_id or str(uuid4()),
            content=message.content,
            message=message,
        )

    existing_pending_plan = (
        sanitize_json_value(session.pending_plan_json) if isinstance(session.pending_plan_json, dict) else {}
    )
    has_pending_plan = _has_pending_plan(existing_pending_plan)
    current_dialog_state = _normalize_dialog_state(
        session.dialog_state_json if isinstance(session.dialog_state_json, dict) else {}
    )
    working_context = _normalize_working_context(
        session.working_context_json if isinstance(session.working_context_json, dict) else {}
    )
    browser_target = _build_working_context_from_page_context(page_context, source="browser_action")
    if _has_object_target(browser_target):
        working_context = _merge_soft_focus_context(working_context, browser_target)
        session.working_context_json = working_context

    accepted_at = _now()
    last_user_intent = sanitize_text(str(current_browser_runtime.get("last_user_intent") or ""), max_length=240) or "继续当前站内动作"
    _set_browser_runtime(
        session,
        phase="resolving_ui_feedback",
        browser_context=browser_context,
        last_user_intent=last_user_intent,
        current_objective=sanitize_text(str(current_browser_runtime.get("current_objective") or ""), max_length=240) or None,
        objective_kind=_sanitize_line(str(current_browser_runtime.get("objective_kind") or ""), max_length=32) or None,
        planned_steps=current_browser_runtime.get("planned_steps")
        if isinstance(current_browser_runtime.get("planned_steps"), list)
        else [],
        step_cursor=int(current_browser_runtime.get("step_cursor") or 0),
        pending_ui_actions=[],
        completed_ui_actions=ui_action_results,
        last_ui_results=ui_action_results,
        auto_executed_actions=current_browser_runtime.get("auto_executed_actions")
        if isinstance(current_browser_runtime.get("auto_executed_actions"), list)
        else [],
        step_count=int(current_browser_runtime.get("step_count") or 0),
        retry_state=current_browser_runtime.get("retry_state")
        if isinstance(current_browser_runtime.get("retry_state"), dict)
        else {},
        last_error=None,
        ui_pending_since=None,
        last_step_request_id=step_request_id,
        last_step_ack_at=accepted_at,
    )
    _apply_agent_state_patch(
        session,
        focus=_resolve_agent_focus(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            dialog_state=current_dialog_state,
            user_content=last_user_intent,
            fallback_watch_task_id=session_last_task_id,
        ),
        execution={
            "stage": "resolving_ui_feedback",
            "step_kind": "ui",
            "step_label": "处理页面动作回执",
            "waiting_for": None,
            "missing_slots": [],
            "pending_ui_actions": [],
        },
        explanation={
            "reason": "已收到页面动作结果，正在决定下一步",
            "decision_summary": _summarize_ui_results(ui_action_results),
            "expected_outcome": "结合页面反馈继续推进当前目标",
            "next_step": "重新进入代理决策",
            "evidence": [],
        },
        watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
    )
    _sync_current_goal_state(db, session, status_override="active", latest_summary=_summarize_ui_results(ui_action_results))
    db.add(session)
    db.commit()
    db.refresh(session)
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
    logger.info(
        "haor ui_step accepted",
        extra={
            "agent_session_id": session.id,
            "agent_turn_id": turn_id,
            "agent_step_request_id": step_request_id,
            "agent_phase": "resolving_ui_feedback",
            "agent_result": "accepted",
        },
    )
    _emit_session_snapshot(stream_emitter, session)

    allow_write_plans = _normalize_role(user.role) == "admin"
    allow_auto_execute_actions = _user_can_auto_execute(user)
    try:
        decision, tool_traces = _run_agent_loop(
            db,
            session=session,
            user=user,
            page_context=page_context,
            browser_context=browser_context,
            browser_runtime=current_browser_runtime,
            working_context=working_context,
            dialog_state=current_dialog_state,
            followup_hint={},
            allow_write_plans=allow_write_plans,
            allow_auto_execute_actions=allow_auto_execute_actions,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
    except Exception as exc:
        _preserve_or_reset_pending_plan(
            session,
            existing_pending_plan=existing_pending_plan,
            preserve_existing=has_pending_plan,
        )
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=last_user_intent,
            last_error=_humanize_ai_error(exc),
        )
        state_delta = _apply_agent_state_patch(
            session,
            focus=_resolve_agent_focus(
                page_context=page_context,
                browser_context=browser_context,
                working_context=working_context,
                dialog_state=current_dialog_state,
                user_content=last_user_intent,
                fallback_watch_task_id=session_last_task_id,
            ),
            execution={"stage": "failed", "step_kind": "ui", "step_label": "页面动作续处理失败", "waiting_for": None, "missing_slots": [], "pending_ui_actions": []},
            explanation={
                "reason": "页面动作回执后的模型决策失败",
                "decision_summary": _humanize_ai_error(exc),
                "expected_outcome": "向用户暴露错误并等待下一步指令",
                "next_step": "等待用户重试、继续或新开目标",
                "evidence": [],
            },
            watch={"primary_task_id": session_last_task_id, "watching": bool(session_last_task_id)},
        )
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="error",
            content=f"当前 AI 调用失败：{_humanize_ai_error(exc)}",
            payload_json={
                "error": _humanize_ai_error(exc),
                "browser_context": browser_context,
                **_build_message_state_metadata(
                    decision_summary=_humanize_ai_error(exc),
                    evidence=[],
                    state_delta=state_delta,
                ),
            },
        )
        _sync_current_goal_state(
            db,
            session,
            status_override="blocked",
            blocked_reason=_humanize_ai_error(exc),
            latest_summary=message.content,
        )
        db.commit()
        db.refresh(session)
        logger.info(
            "haor ui_step failed",
            extra={
                "agent_session_id": session.id,
                "agent_turn_id": turn_id,
                "agent_step_request_id": step_request_id,
                "agent_phase": "resolving_ui_feedback",
                "agent_result": "error",
            },
        )
        _emit_error_event(stream_emitter, detail=message.content, turn_id=turn_id, message=message)
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    _apply_agent_decision(
        db,
        session=session,
        user=user,
        decision=decision,
        tool_traces=tool_traces,
        page_context=page_context,
        browser_context=browser_context,
        current_browser_runtime=current_browser_runtime,
        working_context=working_context,
        dialog_state=current_dialog_state,
        followup_hint={},
        user_content=last_user_intent,
        existing_pending_plan=existing_pending_plan,
        has_pending_plan=has_pending_plan,
        platform_url=platform_url,
        stream_emitter=stream_emitter,
        turn_id=turn_id,
    )
    db.commit()
    db.refresh(session)
    logger.info(
        "haor ui_step completed",
        extra={
            "agent_session_id": session.id,
            "agent_turn_id": turn_id,
            "agent_step_request_id": step_request_id,
            "agent_phase": str(
                _normalize_browser_runtime(session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}).get(
                    "phase"
                )
                or ""
            ),
            "agent_result": "completed",
        },
    )
    _emit_session_snapshot(stream_emitter, session)
    return serialize_agent_session(session)


def stream_agent_message_turn(
    db: Session,
    *,
    user: User,
    payload: AgentMessageCreateRequest,
    platform_url: str,
    turn_id: str,
    client_message_id: str | None = None,
    stream_emitter: _AgentStreamEmitter | None = None,
) -> AgentSessionRead:
    _emit_turn_started(stream_emitter, turn_id=turn_id, phase="message", client_message_id=client_message_id)
    try:
        response = post_agent_message(
            db,
            user=user,
            payload=payload,
            platform_url=platform_url,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
    except Exception:
        _emit_turn_done(stream_emitter, turn_id=turn_id, status="error")
        raise
    _emit_turn_done(stream_emitter, turn_id=turn_id, status="ok")
    return response


def stream_agent_step_turn(
    db: Session,
    *,
    user: User,
    payload: AgentUIStepRequest,
    platform_url: str,
    turn_id: str,
    stream_emitter: _AgentStreamEmitter | None = None,
) -> AgentSessionRead:
    _emit_turn_started(stream_emitter, turn_id=turn_id, phase="ui_step")
    try:
        response = post_agent_step(
            db,
            user=user,
            payload=payload,
            platform_url=platform_url,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
    except Exception:
        _emit_turn_done(stream_emitter, turn_id=turn_id, status="error")
        raise
    _emit_turn_done(stream_emitter, turn_id=turn_id, status="ok")
    return response


def stream_agent_approve_turn(
    db: Session,
    *,
    user: User,
    request: AgentApprovalRequest,
    platform_url: str,
    turn_id: str,
    stream_emitter: _AgentStreamEmitter | None = None,
) -> AgentApprovalResponse:
    _emit_turn_started(stream_emitter, turn_id=turn_id, phase="approve")
    try:
        response = approve_agent_session(
            db,
            user=user,
            request=request,
            platform_url=platform_url,
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
    except Exception:
        _emit_turn_done(stream_emitter, turn_id=turn_id, status="error")
        raise
    _emit_turn_done(stream_emitter, turn_id=turn_id, status="ok")
    return response


def execute_approved_action(
    db: Session,
    *,
    action: dict[str, Any],
    session_user_id: str,
    platform_url: str,
) -> AgentExecutionResult:
    return AGENT_EXECUTION_SERVICE.execute(
        AgentActionExecutorContext(
            db=db,
            session_user_id=session_user_id,
            platform_url=platform_url,
            get_manual_credential=get_manual_credential,
        ),
        action=action,
    )


def wait_for_child_task(task_id: str, *, timeout_seconds: int = 7200, interval_seconds: int = 2) -> dict[str, Any]:
    started_at = _now()
    while (_now() - started_at).total_seconds() <= timeout_seconds:
        with_db = None
        try:
            # Lazy import of SessionLocal would create a circular import here.
            from app.db.session import SessionLocal

            with SessionLocal() as db:
                with_db = db
                task = get_task_run(db, task_id)
                if task is None:
                    raise RuntimeError("子任务不存在")
                if task.status in TERMINAL_TASK_STATUSES:
                    return {
                        "task_id": task.id,
                        "status": task.status.value if hasattr(task.status, "value") else str(task.status),
                        "message": task.message,
                        "result_json": task.result_json if isinstance(task.result_json, dict) else {},
                        "error_json": task.error_json if isinstance(task.error_json, dict) else {},
                    }
        finally:
            with_db = None
        sleep(interval_seconds)
    raise RuntimeError(f"等待子任务 {task_id} 完成超时")


def approve_agent_session(
    db: Session,
    *,
    user: User,
    request: AgentApprovalRequest,
    platform_url: str,
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> AgentApprovalResponse:
    session = _load_recent_session(db, user_id=user.id)
    if session is None:
        raise AgentNotFoundError("当前没有可批准的 haor 会话", stage="approve")
    if _reconcile_session_runtime_state(db, session=session):
        db.flush()
    _raise_if_session_running(session, stage="approve")
    pending_plan = session.pending_plan_json if isinstance(session.pending_plan_json, dict) else {}
    proposed_actions = pending_plan.get("proposed_write_actions")
    if str(session.status or "") != "waiting_approval" or not isinstance(proposed_actions, list) or not proposed_actions:
        raise AgentConflictError("当前没有待批准的智能体动作计划", session_id=session.id, stage="approve")
    sanitized_actions = [item for item in proposed_actions if isinstance(item, dict) and str(item.get("action_type") or "") in SUPPORTED_WRITE_ACTIONS]
    if not sanitized_actions:
        raise AgentConflictError("当前待批准计划为空或不受支持", session_id=session.id, stage="approve")

    task_run = create_task_run(
        db,
        task_type=TaskType.AGENT_ORCHESTRATE,
        scope_type="agent_session",
        scope_id=session.id,
        message="haor 编排任务已入队",
    )
    result_json = {
        "context": {
            "agent_id": AGENT_ID,
            "session_id": session.id,
            "user_id": user.id,
            "platform_url": platform_url,
        },
        "plan": {
            "reply_markdown": pending_plan.get("reply_markdown"),
            "proposed_write_actions": sanitize_json_value(sanitized_actions),
            "browser_context": sanitize_json_value(
                pending_plan.get("browser_context") if isinstance(pending_plan.get("browser_context"), dict) else {}
            ),
            "page_context": sanitize_json_value(
                pending_plan.get("page_context") if isinstance(pending_plan.get("page_context"), dict) else {}
            ),
            "working_context": sanitize_json_value(
                pending_plan.get("working_context") if isinstance(pending_plan.get("working_context"), dict) else {}
            ),
            "resolved_targets": sanitize_json_value(
                pending_plan.get("resolved_targets") if isinstance(pending_plan.get("resolved_targets"), list) else []
            ),
        },
        "execution": {
            "approved_by": user.id,
            "approved_note": request.note,
            "results": [],
        },
    }
    update_task_run(db, task_run, result_json=result_json)
    session.status = "running"
    session.pending_plan_json = {}
    session.dialog_state_json = {}
    session.browser_runtime_json = {}
    session.last_task_id = task_run.id
    sync_agent_task_watch_state(
        session,
        task_id=task_run.id,
        status=task_run.status.value if hasattr(task_run.status, "value") else str(task_run.status),
        message=task_run.message,
        action=sanitized_actions[0] if sanitized_actions else {},
        watching=True,
    )
    session.updated_at = _now()
    db.add(session)
    _append_message(
        db,
        session=session,
        role="user",
        message_type="text",
        content=request.note or "已批准当前智能体动作计划",
        payload_json={"approval": True, "task_id": task_run.id},
    )
    _sync_current_goal_state(
        db,
        session,
        status_override="active",
        latest_summary=request.note or "已批准当前智能体动作计划",
    )
    db.commit()
    db.refresh(session)
    _emit_task_update(
        stream_emitter,
        task_id=task_run.id,
        status=task_run.status,
        progress=task_run.progress,
        message=task_run.message,
    )
    _emit_session_snapshot(stream_emitter, session)
    return AgentApprovalResponse(session_id=session.id, task_id=task_run.id, status=task_run.status)


def interrupt_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    return interrupt_agent_session_via_service(
        db,
        user=user,
        load_recent_session_fn=_load_recent_session,
        reconcile_running_session_state_fn=_reconcile_running_session_state,
        restore_session_from_running_state_fn=_restore_session_from_running_state,
        sanitize_line_fn=_sanitize_line,
        get_task_run_fn=get_task_run,
        is_session_orchestrate_task_fn=_is_session_orchestrate_task,
        is_active_task_status_fn=_is_active_task_status,
        normalize_task_status_fn=_normalize_task_status,
        celery_app=celery_app,
        running_task_status=TaskExecutionStatus.RUNNING.value,
        retry_task_status=TaskExecutionStatus.RETRY.value,
        cancel_task_run_fn=cancel_task_run,
        mark_agent_session_interrupted_fn=mark_agent_session_interrupted,
        serialize_agent_session_fn=serialize_agent_session,
        agent_not_found_error_cls=AgentNotFoundError,
        agent_conflict_error_cls=AgentConflictError,
        agent_upstream_error_cls=AgentUpstreamError,
    )
