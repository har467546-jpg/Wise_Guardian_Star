from __future__ import annotations

import json
import re
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field, ValidationError, field_validator

from app.services.haor.action_policy import SUPPORTED_WRITE_ACTIONS
from app.utils.sanitize import sanitize_json_value, sanitize_text


MODEL_DECISION_CONVERSATION_STATE_ALIASES = {
    "completed": "answer",
    "done": "answer",
    "finish": "answer",
    "final": "answer",
}

DIALOG_STATE_INTENT_KIND_ALIASES = {
    "operate_low_risk": "prepare_plan",
    "operate_high_risk": "prepare_plan",
    "navigate": "read_followup",
    "inspect": "read_followup",
    "ask": "analyze",
    "answer": "analyze",
}


def sanitize_line(value: str | None, *, max_length: int = 140) -> str:
    return sanitize_text(value, max_length=max_length, single_line=True) or ""


class ReadToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProposedWriteAction(BaseModel):
    action_type: str
    title: str
    reason: str
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("action_type")
    @classmethod
    def _validate_action_type(cls, value: str) -> str:
        action_type = sanitize_line(str(value or ""), max_length=64)
        if action_type not in SUPPORTED_WRITE_ACTIONS:
            raise ValueError(f"unsupported write action: {action_type or '<empty>'}")
        return action_type


class UIAction(BaseModel):
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


class DialogState(BaseModel):
    status: Literal["idle", "awaiting_user_input"] = "idle"
    intent_kind: Literal["read_followup", "analyze", "fill_slot", "prepare_plan"] | None = None
    question_kind: Literal["confirm", "slot_fill", "disambiguate", "followup"] | None = None
    intent_summary: str | None = None
    last_agent_question: str | None = None
    expected_slots: list[str] = Field(default_factory=list)
    candidate_read_tools: list[ReadToolCall] = Field(default_factory=list)
    candidate_write_context: dict[str, Any] = Field(default_factory=dict)
    targets_snapshot: dict[str, Any] = Field(default_factory=dict)


class FollowupResolution(BaseModel):
    status: Literal["resolved", "canceled", "reframed", "needs_more_input", "unknown"] = "unknown"
    summary: str | None = None


class AgentModelDecision(BaseModel):
    reply_markdown: str
    conversation_state: Literal["answer", "clarifying", "plan"] = "answer"
    objective: str | None = None
    clarifying_question: str | None = None
    read_tool_calls: list[ReadToolCall] = Field(default_factory=list)
    ui_actions: list[UIAction] = Field(default_factory=list)
    proposed_write_actions: list[ProposedWriteAction] = Field(default_factory=list)
    auto_execute_actions: list[ProposedWriteAction] = Field(default_factory=list)
    needs_confirmation: bool = False
    dialog_state_update: DialogState | None = None
    followup_resolution: FollowupResolution | None = None
    stop_reason: str | None = None


def normalize_dialog_state_payload(dialog_state: dict[str, Any] | None) -> dict[str, Any]:
    payload = sanitize_json_value(dialog_state if isinstance(dialog_state, dict) else {})
    if not isinstance(payload, dict):
        return {}
    normalized = dict(payload)
    intent_kind = str(normalized.get("intent_kind") or "").strip().lower()
    if intent_kind in DIALOG_STATE_INTENT_KIND_ALIASES:
        normalized["intent_kind"] = DIALOG_STATE_INTENT_KIND_ALIASES[intent_kind]
    return normalized


def extract_json_block(raw: str) -> str:
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


def normalize_model_decision_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("模型返回的 JSON 顶层结构必须是对象")

    normalized = dict(payload)
    conversation_state = sanitize_line(str(normalized.get("conversation_state") or ""), max_length=32).lower()
    normalized["conversation_state"] = MODEL_DECISION_CONVERSATION_STATE_ALIASES.get(
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
        normalized["dialog_state_update"] = normalize_dialog_state_payload(normalized.get("dialog_state_update"))

    followup_resolution = normalized.get("followup_resolution")
    if followup_resolution == "" or followup_resolution is None:
        normalized["followup_resolution"] = None
    elif isinstance(followup_resolution, str):
        summary = sanitize_text(followup_resolution, max_length=240) or None
        normalized["followup_resolution"] = {"status": "unknown", "summary": summary}

    return normalized


def parse_model_decision(raw: str) -> AgentModelDecision:
    try:
        payload = json.loads(extract_json_block(raw))
    except json.JSONDecodeError as exc:
        raise ValueError("模型返回的 JSON 结构无法解析") from exc
    payload = normalize_model_decision_payload(payload)
    return AgentModelDecision.model_validate(payload)


def is_model_decision_contract_error(exc: Exception) -> bool:
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
