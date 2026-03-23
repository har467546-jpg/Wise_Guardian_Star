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
from app.core.config import settings
from app.db.models.agent_message import AgentMessage
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
from app.repositories.discovery_repo import create_job, get_active_job_by_cidr
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
    AgentAssistantDeltaEvent,
    AgentAssistantMessageDoneEvent,
    AgentAssistantMessageStartEvent,
    AgentErrorEvent,
    AgentMessageCreateRequest,
    AgentMessageRead,
    AgentPlanPendingEvent,
    AgentProposedActionRead,
    AgentSessionSnapshotEvent,
    AgentSessionRead,
    AgentTaskUpdateEvent,
    AgentTurnDoneEvent,
    AgentTurnStartedEvent,
    AgentUIActionsRequestedEvent,
    AgentUIStepRequest,
)
from app.services.ai.providers import LLMMessage, LLMRequest, build_provider
from app.services.remediation_service import build_plan, get_manual_credential, list_remediation_assets
from app.services.remediation_session_service import (
    approve_remediation_session,
    build_remediation_asset_detail,
    create_or_resume_remediation_session,
    get_remediation_session_read,
)
from app.services.runner_service import queue_runner_install
from app.services.task_observability_service import serialize_task_detail, serialize_task_event
from app.tasks.runner_tasks import run_runner_install_task
from app.tasks.scan_tasks import run_asset_scan_task
from app.tasks.verify_tasks import run_risk_verify_task
from app.utils.local_asset import resolve_local_asset
from app.utils.sanitize import sanitize_json_value, sanitize_text


AGENT_ID = "haor"
ACTIVE_SESSION_STATUSES = {"active", "waiting_approval", "running"}
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
}
AUTO_EXECUTE_ACTIONS = {
    "create_discovery_job",
    "verify_asset_risks",
    "install_runner",
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
UI_FEEDBACK_STALE_SECONDS = 300

logger = logging.getLogger(__name__)


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
        .options(joinedload(AgentSession.messages))
        .order_by(AgentSession.updated_at.desc(), AgentSession.created_at.desc())
    )


def _load_recent_session(db: Session, *, user_id: str) -> AgentSession | None:
    sessions = db.scalars(_session_query(user_id)).unique().all()
    for session in sessions:
        if str(session.status or "") in ACTIVE_SESSION_STATUSES:
            return session
    return sessions[0] if sessions else None


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
    dom_snapshot = payload.get("dom_snapshot") if isinstance(payload.get("dom_snapshot"), list) else []
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


def _normalize_browser_runtime(browser_runtime: dict[str, Any] | None) -> dict[str, Any]:
    payload = browser_runtime if isinstance(browser_runtime, dict) else {}
    pending_ui_actions = payload.get("pending_ui_actions") if isinstance(payload.get("pending_ui_actions"), list) else []
    completed_ui_actions = payload.get("completed_ui_actions") if isinstance(payload.get("completed_ui_actions"), list) else []
    auto_executed_actions = payload.get("auto_executed_actions") if isinstance(payload.get("auto_executed_actions"), list) else []
    last_ui_results = payload.get("last_ui_results") if isinstance(payload.get("last_ui_results"), list) else []
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
    else:
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


def _normalize_dialog_state(dialog_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = dialog_state if isinstance(dialog_state, dict) else {}
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
    if not dialog_state:
        return {}
    normalized = sanitize_text(content, max_length=300, single_line=True) or ""
    if not normalized:
        return {}
    affirm_markers = {"继续", "好", "好的", "是", "是的", "行", "可以", "继续吧", "看", "查看", "继续看", "继续吧"}
    deny_markers = {"不用了", "算了", "别看了", "不用", "不看了", "不要了", "取消", "先不看", "别继续了"}
    extracted_values = _extract_followup_short_values(
        normalized,
        dialog_state.get("expected_slots") if isinstance(dialog_state.get("expected_slots"), list) else [],
    )
    if normalized in deny_markers:
        reply_kind = "deny"
    elif normalized in affirm_markers:
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
    messages = [_serialize_message(item) for item in session.messages]
    return AgentSessionRead(
        session_id=session.id,
        agent_id=session.agent_id,
        status=session.status,
        route_context_json=route_context_json,
        working_context_json=working_context_json,
        dialog_state_json=dialog_state_json,
        pending_plan_json=pending_plan_json,
        browser_runtime_json=browser_runtime_json,
        last_task_id=session.last_task_id,
        messages=messages,
        created_at=session.created_at,
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
    return re.sub(r"\s+", " ", sanitize_text(value, max_length=4000) or "").strip()


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
    normalized = sanitize_text(content, max_length=4000) or ""
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
        content=sanitize_text(content, max_length=4000) or "",
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
    emitted_chunks: list[str] = []
    if fallback_content and _runtime_provider_mode() != "mock":
        reply_request = _build_reply_stream_request(
            user_content=user_content,
            message_type=message_type,
            reply_markdown=fallback_content,
            tool_traces=tool_traces,
            working_context=working_context,
        )
        provider = _build_runtime_provider().provider
        try:
            for chunk in provider.stream_generate(reply_request):
                normalized_chunk = str(chunk or "")
                if not normalized_chunk:
                    continue
                emitted_chunks.append(normalized_chunk)
                _emit_stream_event(
                    stream_emitter,
                    AgentAssistantDeltaEvent(turn_id=turn_id, delta=normalized_chunk).model_dump(mode="json"),
                )
        except Exception as exc:
            logger.warning("haor reply stream failed, falling back to draft reply", exc_info=exc)
            if emitted_chunks:
                try:
                    resolved_reply = _normalize_assistant_reply_content(provider.generate(reply_request))
                except Exception:
                    resolved_reply = ""
                current_text = "".join(emitted_chunks)
                if resolved_reply.startswith(current_text):
                    suffix = resolved_reply[len(current_text) :]
                    for chunk in _iter_stream_text_chunks(suffix):
                        emitted_chunks.append(chunk)
                        _emit_stream_event(
                            stream_emitter,
                            AgentAssistantDeltaEvent(turn_id=turn_id, delta=chunk).model_dump(mode="json"),
                        )
                else:
                    logger.warning("haor reply stream fallback could not reconcile partial stream")

    if not emitted_chunks:
        for chunk in _iter_stream_text_chunks(fallback_content):
            emitted_chunks.append(chunk)
            _emit_stream_event(
                stream_emitter,
                AgentAssistantDeltaEvent(turn_id=turn_id, delta=chunk).model_dump(mode="json"),
            )

    final_content = _normalize_assistant_reply_content("".join(emitted_chunks).strip()) or fallback_content
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
    session.status = "active"
    session.pending_plan_json = {}
    session.dialog_state_json = {}
    session.browser_runtime_json = {}
    session.updated_at = _now()


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


def _normalize_step_request_id(value: str | None) -> str | None:
    return _sanitize_line(str(value or ""), max_length=128) or None


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
    if _has_interrupted_task_message(session, task_id=task_id):
        return
    _append_message(
        db,
        session=session,
        role="assistant",
        message_type="task_update",
        content="当前编排已中断，可以继续输入新的问题或执行意图。",
        payload_json={
            "task_id": task_id,
            "interrupted": True,
            "source": source,
        },
    )


def _reconcile_running_session_state(
    db: Session,
    *,
    session: AgentSession,
    interrupted_source: str = "session_reconcile",
) -> bool:
    if str(session.status or "") != "running":
        return False

    task_id = _sanitize_line(str(session.last_task_id or ""), max_length=64)
    if not task_id:
        _restore_session_from_running_state(session)
        db.add(session)
        return True

    task = get_task_run(db, task_id)
    if task is None or not _is_session_orchestrate_task(task, session_id=session.id):
        _restore_session_from_running_state(session)
        db.add(session)
        return True

    task_status = _normalize_task_status(task.status)
    if task_status == TaskExecutionStatus.CANCELED.value:
        _restore_session_from_running_state(session)
        session.last_task_id = task_id
        db.add(session)
        _append_interrupted_task_message(db, session=session, task_id=task_id, source=interrupted_source)
        return True

    if _is_terminal_task_status(task.status):
        _restore_session_from_running_state(session)
        session.last_task_id = task_id
        db.add(session)
        return True

    return False


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


def _reconcile_session_runtime_state(
    db: Session,
    *,
    session: AgentSession,
    interrupted_source: str = "session_reconcile",
    stale_source: str = "ui_feedback_reconcile",
) -> bool:
    changed = False
    if _reconcile_running_session_state(db, session=session, interrupted_source=interrupted_source):
        changed = True
    if _reconcile_stale_ui_feedback_state(db, session=session, source=stale_source):
        changed = True
    return changed


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
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    _restore_session_from_running_state(session)
    session.last_task_id = task_id
    db.add(session)
    _append_interrupted_task_message(db, session=session, task_id=task_id, source=source)


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
    )
    db.add(session)
    db.flush()
    return session


def get_or_create_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    session = _load_recent_session(db, user_id=user.id)
    if session is not None and _reconcile_session_runtime_state(db, session=session):
        db.commit()
        db.refresh(session)
    if session is None or str(session.status or "") not in ACTIVE_SESSION_STATUSES:
        session = _create_session(db, user=user)
        db.commit()
        db.refresh(session)
    return serialize_agent_session(session)


def reset_agent_session(db: Session, *, user: User) -> AgentSessionRead:
    current_session = _load_recent_session(db, user_id=user.id)
    if current_session is not None and _reconcile_session_runtime_state(db, session=current_session):
        db.flush()
    if current_session is not None and str(current_session.status or "") == "running":
        try:
            interrupt_agent_session(db, user=user)
        except AgentConflictError:
            db.flush()

    sessions = db.scalars(_session_query(user.id)).unique().all()
    for session in sessions:
        if str(session.status or "") in ACTIVE_SESSION_STATUSES:
            session.status = "completed"
            session.pending_plan_json = {}
            session.working_context_json = {}
            session.dialog_state_json = {}
            session.browser_runtime_json = {}
            session.route_context_json = _normalize_page_context({})
            session.updated_at = _now()
            db.add(session)
    session = _create_session(db, user=user)
    db.commit()
    db.refresh(session)
    return serialize_agent_session(session)


def append_agent_task_message(
    db: Session,
    *,
    session_id: str,
    content: str,
    payload_json: dict[str, Any] | None = None,
    message_type: str = "task_update",
) -> None:
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    _append_message(
        db,
        session=session,
        role="assistant",
        message_type=message_type,
        content=content,
        payload_json=payload_json,
    )


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
) -> _AgentModelDecision | None:
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
    explicit_context = _extract_explicit_working_context(content, page_context)
    if _has_object_target(explicit_context):
        normalized_context = _merge_soft_focus_context(current_context, explicit_context)
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

    if _content_mentions_current_object(content):
        page_target = _build_working_context_from_page_context(page_context, source="page_reference")
        if not _has_object_target(page_target):
            page_target = _build_working_context_from_browser_context(browser_context, source="browser_reference")
        if _has_object_target(page_target):
            normalized_context = _merge_soft_focus_context(effective_context, page_target)
            session.working_context_json = normalized_context
            return normalized_context

    if _has_object_target(effective_context):
        session.working_context_json = effective_context
        return effective_context

    return {}


def _resolve_working_context_for_message(
    *,
    session: AgentSession,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any] | None = None,
    dialog_state: dict[str, Any] | None = None,
    followup_hint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _resolve_effective_working_context(
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
    return match.group(0)


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
    return str(settings.LLM_PROVIDER or "mock").strip().lower() or "mock"


def _build_runtime_provider():
    return build_provider(
        provider_name=_runtime_provider_mode(),
        model=str(settings.LLM_MODEL or "gpt-4o-mini"),
        base_url=str(settings.LLM_BASE_URL or ""),
        wire_api=str(settings.LLM_WIRE_API or "responses"),
        timeout_seconds=int(settings.LLM_TIMEOUT_SECONDS or 60),
        api_key=str(settings.LLM_API_KEY or ""),
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


def _parse_model_decision(raw: str) -> _AgentModelDecision:
    try:
        payload = json.loads(_extract_json_block(raw))
    except json.JSONDecodeError as exc:
        raise ValueError("模型返回的 JSON 结构无法解析") from exc
    return _AgentModelDecision.model_validate(payload)


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
        )[:8],
        "open_panels": sanitize_json_value(
            browser_context.get("open_panels") if isinstance(browser_context.get("open_panels"), list) else []
        )[:6],
        "forms": sanitize_json_value(browser_context.get("forms") if isinstance(browser_context.get("forms"), list) else [])[:4],
        "visible_actions": sanitize_json_value(
            browser_context.get("visible_actions") if isinstance(browser_context.get("visible_actions"), list) else []
        )[:16],
        "semantic_page_context": sanitize_json_value(
            browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
        ),
        "semantic_actions": sanitize_json_value(
            browser_context.get("semantic_actions") if isinstance(browser_context.get("semantic_actions"), list) else []
        )[:20],
        "semantic_forms": sanitize_json_value(
            browser_context.get("semantic_forms") if isinstance(browser_context.get("semantic_forms"), list) else []
        )[:8],
        "dom_snapshot": sanitize_json_value(
            browser_context.get("dom_snapshot") if isinstance(browser_context.get("dom_snapshot"), list) else []
        )[:40],
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
    semantic_page_context = _browser_semantic_page_context(browser_context)
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
            "required_params": {"asset_id": "资产 ID", "note": "可选备注"},
        },
        {
            "action_type": "approve_remediation_session",
            "description": "批准修复会话并触发 Host Runner 修复任务",
            "required_params": {"session_id": "修复会话 ID"},
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
        "browser_runtime": sanitize_json_value(browser_runtime),
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


def _render_history_line(message: AgentMessage | Any) -> str | None:
    role = "assistant" if str(message.role or "").strip().lower() == "assistant" else "user"
    content = sanitize_text(message.content, max_length=4000) or ""
    if not content:
        return None
    message_type = str(message.message_type or "text").strip().lower() or "text"
    label = role if message_type == "text" else f"{role}/{message_type}"
    return f"{label}: {content}"


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
    history_lines: list[str] = []
    if recent_messages:
        last_message = recent_messages[-1]
        last_role = str(getattr(last_message, "role", "") or "").strip().lower()
        if last_role == "user":
            latest_user_content = sanitize_text(getattr(last_message, "content", ""), max_length=4000) or ""
            recent_messages = recent_messages[:-1]
    for item in recent_messages:
        rendered = _render_history_line(item)
        if rendered:
            history_lines.append(rendered)

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
                + json.dumps({"executed_read_tools": tool_traces[-8:]}, ensure_ascii=False, indent=2),
            )
        )
    return LLMRequest(messages=messages)


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
    content = provider_result.provider.generate(
        _build_model_request(
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
    )
    return _parse_model_decision(content)


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
    evidence = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
    rule_id = str(evidence.get("yaml_rule_id") or "").strip()
    return rule_id or None


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
        "rule_id": finding.rule_id or _risk_rule_id(finding),
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
        asset_id = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=64)
        if not asset_id:
            raise RuntimeError("get_asset_detail 缺少 asset_id")
        asset = get_asset(db, asset_id)
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
        asset_id = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=64)
        if not asset_id:
            raise RuntimeError("list_asset_risks 缺少 asset_id")
        expected_status = str(arguments.get("status") or "").strip().lower() or None
        findings = list_findings_by_asset(db, asset_id)
        filtered: list[RiskFinding] = []
        for item in findings:
            if expected_status and str(item.status.value if hasattr(item.status, "value") else item.status).lower() != expected_status:
                continue
            filtered.append(item)
        return {
            "asset_id": asset_id,
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
        asset_id = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=64)
        if not asset_id:
            raise RuntimeError("get_remediation_asset 缺少 asset_id")
        return build_remediation_asset_detail(db, asset_id).model_dump(mode="json")
    if tool_name == "get_remediation_session":
        session_id = _sanitize_line(str(arguments.get("session_id") or ""), max_length=64)
        asset_id = _sanitize_line(str(arguments.get("asset_id") or ""), max_length=64)
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
    current_content = str(browser_runtime.get("last_user_intent") or "") or str(session.messages[-1].content if session.messages else "")
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
    for _ in range(MAX_AGENT_LOOP_STEPS):
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
            allow_write_plans=allow_write_plans,
            allow_auto_execute_actions=allow_auto_execute_actions,
        )
        if not _decision_has_agent_progress(decision, tool_traces=tool_traces):
            fallback_decision = _build_action_first_fallback_decision(
                content=current_content,
                user=user,
                page_context=page_context,
                browser_context=browser_context,
                working_context=working_context,
                dialog_state=dialog_state,
                followup_hint=followup_hint,
                allow_write_plans=allow_write_plans,
                allow_auto_execute_actions=allow_auto_execute_actions,
            )
            if fallback_decision is not None:
                decision = fallback_decision
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
        if not executed_any:
            return decision, tool_traces
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
    completed_ui_actions: list[dict[str, Any]] | None = None,
    last_ui_results: list[dict[str, Any]] | None = None,
    auto_executed_actions: list[dict[str, Any]] | None = None,
    step_count: int | None = None,
    retry_state: dict[str, Any] | None = None,
    last_error: str | None = None,
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
            "completed_ui_actions": completed_ui_actions if completed_ui_actions is not None else current.get("completed_ui_actions"),
            "last_ui_results": last_ui_results if last_ui_results is not None else current.get("last_ui_results"),
            "auto_executed_actions": auto_executed_actions if auto_executed_actions is not None else current.get("auto_executed_actions"),
            "last_browser_context": browser_context or current.get("last_browser_context"),
            "semantic_page_context": _browser_semantic_page_context(browser_context) or current.get("semantic_page_context"),
            "retry_state": retry_state if retry_state is not None else current.get("retry_state"),
            "last_user_intent": last_user_intent if last_user_intent is not None else current.get("last_user_intent"),
            "last_error": last_error,
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
            "completed_ui_actions": [],
            "last_ui_results": [],
            "auto_executed_actions": auto_executed_actions or [],
            "last_browser_context": browser_context,
            "semantic_page_context": _browser_semantic_page_context(browser_context),
            "retry_state": {},
            "last_user_intent": last_user_intent,
            "last_error": last_error,
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
    stream_emitter: _AgentStreamEmitter | None = None,
    turn_id: str | None = None,
) -> None:
    current_objective = _build_current_objective(user_content, dialog_state=dialog_state, followup_hint=followup_hint)
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
    allow_auto_execute = _user_can_auto_execute(user) and _message_allows_auto_execution(
        user_content,
        dialog_state=dialog_state,
        followup_hint=followup_hint,
    )
    needs_confirmation = bool(decision.needs_confirmation and proposed_actions)

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
            auto_execute_actions = []
            needs_confirmation = bool(proposed_actions)
        else:
            decision.reply_markdown = (
                f"{decision.reply_markdown}\n\n当前账号不是管理员，不能自动执行低风险平台动作。"
            ).strip()
            auto_execute_actions = []

    if not _normalize_role(user.role) == "admin" and proposed_actions:
        decision.reply_markdown = (
            f"{decision.reply_markdown}\n\n当前账号为分析员，不能提交执行计划；如需落地请由管理员在相同上下文下确认。"
        ).strip()
        proposed_actions = []
        needs_confirmation = False

    assistant_payload = {
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
    }

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
        assistant_payload["dialog_state"] = sanitize_json_value(session.dialog_state_json)
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=user_content,
            current_objective=decision.objective or current_objective.get("summary"),
            objective_kind=str(current_objective.get("objective_kind") or ""),
            auto_executed_actions=auto_execute_results,
        )
        message = _append_or_stream_assistant_message(
            db,
            session=session,
            message_type="clarifying",
            content=decision.clarifying_question or decision.reply_markdown,
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
            )
            message = _append_message(
                db,
                session=session,
                role="assistant",
                message_type="error",
                content="站内代理动作已达到上限，请直接给我更具体的下一步目标。",
                payload_json=assistant_payload,
            )
            if turn_id:
                _emit_error_event(
                    stream_emitter,
                    detail=message.content,
                    turn_id=turn_id,
                    message=message,
                )
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
            ui_pending_since=_now(),
        )
        content = decision.reply_markdown.strip() or (
            f"我将先在当前页面执行 {len(normalized_ui_actions)} 个站内动作：{_summarize_ui_actions(normalized_ui_actions)}。"
        )
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="action_update",
            content=content,
            payload_json={
                **assistant_payload,
                "browser_runtime": sanitize_json_value(session.browser_runtime_json),
            },
        )
        if turn_id:
            _emit_action_update(
                stream_emitter,
                turn_id=turn_id,
                content=content,
                message=message,
            )
            _emit_ui_actions_requested(stream_emitter, turn_id=turn_id, ui_actions=normalized_ui_actions, content=content)
        return

    _clear_browser_runtime(
        session,
        browser_context=browser_context,
        last_user_intent=user_content,
        current_objective=decision.objective or current_objective.get("summary"),
        objective_kind=str(current_objective.get("objective_kind") or ""),
        auto_executed_actions=auto_execute_results,
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
        message = _append_or_stream_assistant_message(
            db,
            session=session,
            message_type="plan",
            content=decision.reply_markdown,
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
        return

    _preserve_or_reset_pending_plan(
        session,
        existing_pending_plan=existing_pending_plan,
        preserve_existing=has_pending_plan,
    )
    _clear_dialog_state(session)
    _append_or_stream_assistant_message(
        db,
        session=session,
        message_type="text",
        content=decision.reply_markdown,
        payload_json=assistant_payload,
        user_content=user_content,
        tool_traces=tool_traces,
        working_context=final_working_context,
        stream_emitter=stream_emitter,
        turn_id=turn_id,
    )


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
    if session is None or str(session.status or "") not in ACTIVE_SESSION_STATUSES:
        session = _create_session(db, user=user)
        db.flush()
    _raise_if_session_running(session, stage="message")

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
    current_browser_runtime = _normalize_browser_runtime(
        session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    )
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
            **({"client_message_id": payload.client_message_id} if payload.client_message_id else {}),
            "page_context": page_context,
            "browser_context": browser_context,
            "working_context": working_context,
            "dialog_state": current_dialog_state,
            "followup_hint": followup_hint,
        },
    )
    _emit_session_snapshot(stream_emitter, session)

    if has_pending_plan and _should_cancel_pending_plan(payload.content):
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
            },
        )
        _clear_browser_runtime(session, browser_context=browser_context, last_user_intent=payload.content)
        db.commit()
        db.refresh(session)
        _emit_streamed_assistant_message(stream_emitter, turn_id=turn_id or str(uuid4()), message=session.messages[-1])
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if current_dialog_state and followup_hint.get("reply_kind") == "deny":
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
            },
        )
        _clear_browser_runtime(session, browser_context=browser_context, last_user_intent=payload.content)
        db.commit()
        db.refresh(session)
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
            stream_emitter=stream_emitter,
            turn_id=turn_id,
        )
        db.commit()
        db.refresh(session)
        _emit_session_snapshot(stream_emitter, session)
        return serialize_agent_session(session)

    if not current_dialog_state:
        preflight_clarification = _build_preflight_clarification(
            payload.content,
            working_context=working_context,
            page_context=page_context,
        )
        if preflight_clarification:
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
                },
            )
            _clear_browser_runtime(session, browser_context=browser_context, last_user_intent=payload.content)
            db.commit()
            db.refresh(session)
            _emit_streamed_assistant_message(stream_emitter, turn_id=turn_id or str(uuid4()), message=session.messages[-1])
            _emit_session_snapshot(stream_emitter, session)
            return serialize_agent_session(session)

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
            followup_hint=followup_hint,
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
        session.dialog_state_json = current_dialog_state if current_dialog_state else {}
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=payload.content,
            last_error=_humanize_ai_error(exc),
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
            },
        )
        db.commit()
        db.refresh(session)
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
        stream_emitter=stream_emitter,
        turn_id=turn_id,
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
    if session is None or str(session.status or "") not in ACTIVE_SESSION_STATUSES:
        raise AgentConflictError("当前没有可继续的 haor 会话", stage="step")
    _raise_if_session_running(session, stage="step")

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

    if not pending_ui_actions:
        _clear_browser_runtime(
            session,
            browser_context=browser_context,
            last_user_intent=str(current_browser_runtime.get("last_user_intent") or "") or None,
        )
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
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="error",
            content="站内代理动作已达到上限，请直接给我更具体的下一步目标。",
            payload_json={"browser_context": browser_context},
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
        message = _append_message(
            db,
            session=session,
            role="assistant",
            message_type="error",
            content=f"当前 AI 调用失败：{_humanize_ai_error(exc)}",
            payload_json={"error": _humanize_ai_error(exc), "browser_context": browser_context},
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


def _queue_discovery_job_from_action(db: Session, *, action: dict[str, Any], user_id: str) -> AgentExecutionResult:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    cidr = sanitize_text(str(params.get("cidr") or ""), max_length=64, single_line=True) or ""
    label = sanitize_text(str(params.get("label") or ""), max_length=255)
    if not cidr:
        raise RuntimeError("扫描计划缺少 CIDR")
    active_job = get_active_job_by_cidr(db, cidr)
    if active_job is None:
        job = create_job(db=db, cidr=cidr, label=label, created_by=user_id)
    else:
        job = active_job
    existing_task = get_latest_task_run_for_scope(
        db,
        scope_type="discovery_job",
        scope_id=job.id,
        task_type=TaskType.ASSET_SCAN,
        statuses=[TaskExecutionStatus.PENDING, TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY],
    )
    if existing_task is not None:
        return AgentExecutionResult(
            status="queued",
            summary=f"已复用扫描任务 {existing_task.id}",
            child_task_id=existing_task.id,
            payload={"job_id": job.id, "task_id": existing_task.id, "reused": True},
        )
    task_run = create_task_run(
        db,
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_job",
        scope_id=job.id,
        message="扫描任务已入队",
    )
    celery_task = run_asset_scan_task.delay(task_run.id, job.id)
    update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已创建扫描任务 {task_run.id}",
        child_task_id=task_run.id,
        payload={"job_id": job.id, "task_id": task_run.id, "reused": False},
    )


def _queue_risk_verify_from_action(db: Session, *, action: dict[str, Any]) -> AgentExecutionResult:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = _sanitize_line(str(params.get("asset_id") or ""), max_length=64)
    if not asset_id:
        raise RuntimeError("风险验证计划缺少 asset_id")
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    task_run = create_task_run(
        db,
        task_type=TaskType.RISK_VERIFY,
        scope_type="asset",
        scope_id=asset_id,
        message="风险验证任务已入队",
    )
    celery_task = run_risk_verify_task.delay(task_run.id, asset_id)
    update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已触发资产 {asset_id} 的风险验证",
        child_task_id=task_run.id,
        payload={"asset_id": asset_id, "task_id": task_run.id},
    )


def _queue_runner_install_from_action(
    db: Session,
    *,
    action: dict[str, Any],
    platform_url: str,
) -> AgentExecutionResult:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = _sanitize_line(str(params.get("asset_id") or ""), max_length=64)
    if not asset_id:
        raise RuntimeError("Runner 安装计划缺少 asset_id")
    if not str(platform_url or "").strip():
        raise RuntimeError("Runner 安装计划缺少平台地址")
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    credential = get_manual_credential(db, asset_id)
    host_runner, task_id, registration_token = queue_runner_install(
        db,
        asset=asset,
        credential=credential,
        platform_url=platform_url,
    )
    celery_task = run_runner_install_task.delay(task_id, asset_id, platform_url, registration_token)
    task_run = get_task_run(db, task_id)
    if task_run is not None:
        update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已提交 Host Runner 安装任务 {task_id}",
        child_task_id=task_id,
        payload={"asset_id": asset_id, "task_id": task_id, "runner_id": host_runner.id},
    )


def _create_or_resume_remediation_from_action(db: Session, *, action: dict[str, Any]) -> AgentExecutionResult:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = _sanitize_line(str(params.get("asset_id") or ""), max_length=64)
    if not asset_id:
        raise RuntimeError("修复会话计划缺少 asset_id")
    session = create_or_resume_remediation_session(db, asset_id=asset_id)
    return AgentExecutionResult(
        status="success",
        summary=f"已准备主机修复会话 {session.session_id}",
        payload={"asset_id": asset_id, "session_id": session.session_id},
    )


def _approve_remediation_from_action(db: Session, *, action: dict[str, Any]) -> AgentExecutionResult:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    session_id = _sanitize_line(str(params.get("session_id") or ""), max_length=64)
    if not session_id:
        raise RuntimeError("修复批准计划缺少 session_id")
    response = approve_remediation_session(db, session_id=session_id, approved_by="haor")
    return AgentExecutionResult(
        status="queued",
        summary=f"已批准修复会话 {session_id}",
        child_task_id=response.task_id,
        payload={"session_id": session_id, "task_id": response.task_id},
    )


def execute_approved_action(
    db: Session,
    *,
    action: dict[str, Any],
    session_user_id: str,
    platform_url: str,
) -> AgentExecutionResult:
    action_type = str(action.get("action_type") or "").strip()
    if action_type not in SUPPORTED_WRITE_ACTIONS:
        raise RuntimeError("计划中存在不受支持的动作类型")
    if action_type == "create_discovery_job":
        return _queue_discovery_job_from_action(db, action=action, user_id=session_user_id)
    if action_type == "verify_asset_risks":
        return _queue_risk_verify_from_action(db, action=action)
    if action_type == "install_runner":
        return _queue_runner_install_from_action(db, action=action, platform_url=platform_url)
    if action_type == "create_or_resume_remediation_session":
        return _create_or_resume_remediation_from_action(db, action=action)
    if action_type == "approve_remediation_session":
        return _approve_remediation_from_action(db, action=action)
    raise RuntimeError("不支持的动作类型")


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
    session = _load_recent_session(db, user_id=user.id)
    if session is None:
        raise AgentNotFoundError("当前 haor 会话不存在", stage="interrupt")

    if _reconcile_running_session_state(db, session=session, interrupted_source="session_interrupt_reconcile"):
        db.commit()
        db.refresh(session)

    if str(session.status or "") != "running":
        raise AgentConflictError("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    task_id = _sanitize_line(str(session.last_task_id or ""), max_length=64)
    if not task_id:
        _restore_session_from_running_state(session)
        db.commit()
        db.refresh(session)
        raise AgentConflictError("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    task = get_task_run(db, task_id)
    if task is None:
        _restore_session_from_running_state(session)
        db.commit()
        db.refresh(session)
        raise AgentConflictError("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    if not _is_session_orchestrate_task(task, session_id=session.id):
        _restore_session_from_running_state(session)
        db.commit()
        db.refresh(session)
        raise AgentConflictError("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    if not _is_active_task_status(task.status):
        _restore_session_from_running_state(session)
        db.commit()
        db.refresh(session)
        raise AgentConflictError("当前任务已结束，无需中断", session_id=session.id, stage="interrupt")

    if task.celery_task_id:
        try:
            celery_app.control.revoke(
                task.celery_task_id,
                terminate=_normalize_task_status(task.status) in {
                    TaskExecutionStatus.RUNNING.value,
                    TaskExecutionStatus.RETRY.value,
                },
                signal="SIGTERM",
            )
        except Exception as exc:
            raise AgentUpstreamError(
                f"haor 编排中断请求下发失败：{exc}",
                session_id=session.id,
                stage="interrupt",
            ) from exc

    cancel_task_run(
        db,
        task,
        message="haor 编排任务已中断",
        payload_json={
            "source": "agent_session_interrupt",
            "celery_task_id": task.celery_task_id,
            "session_id": session.id,
        },
    )
    mark_agent_session_interrupted(db, session_id=session.id, task_id=task.id, source="interrupt_api")
    db.commit()
    db.refresh(session)
    return serialize_agent_session(session)
