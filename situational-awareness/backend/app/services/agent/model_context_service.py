from __future__ import annotations

import json
from typing import Any

from app.services.ai.providers import LLMMessage, LLMRequest
from app.services.agent.identity import AGENT_ID
from app.services.agent.reflection_service import build_reflection_instruction
from app.services.haor.action_policy import AUTO_EXECUTE_ACTIONS
from app.utils.sanitize import sanitize_json_value, sanitize_text


MAX_AGENT_LOOP_STEPS = 10
MAX_UI_ACTION_BATCH = 6
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


def sanitize_line(value: str | None, *, max_length: int = 140) -> str:
    return sanitize_text(value, max_length=max_length, single_line=True) or ""


def normalize_role(value: Any) -> str:
    if hasattr(value, "value"):
        return str(getattr(value, "value"))
    return str(value or "").strip().lower() or "analyst"


def working_context_summary(context: dict[str, Any]) -> str | None:
    finding_id = sanitize_line(str(context.get("finding_id") or ""), max_length=64)
    asset_id = sanitize_line(str(context.get("asset_id") or ""), max_length=64)
    task_id = sanitize_line(str(context.get("task_id") or ""), max_length=64)
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
        normalized["summary"] = working_context_summary(normalized)
    if not normalized["source"]:
        normalized["source"] = "session"
    return normalized


def working_context_primary_target(context: dict[str, Any] | None) -> dict[str, Any]:
    payload = context if isinstance(context, dict) else {}
    primary_target = payload.get("primary_target") if isinstance(payload.get("primary_target"), dict) else {}
    normalized = _normalize_focus_target(primary_target)
    if normalized:
        return normalized
    return _normalize_focus_target(payload)


def _normalize_semantic_entity(entity: dict[str, Any] | None) -> dict[str, Any]:
    payload = entity if isinstance(entity, dict) else {}
    normalized = {
        "kind": sanitize_line(str(payload.get("kind") or "entity"), max_length=32) or "entity",
        "id": sanitize_line(str(payload.get("id") or ""), max_length=96) or None,
        "label": sanitize_text(str(payload.get("label") or ""), max_length=160) or None,
        "status": sanitize_line(str(payload.get("status") or ""), max_length=48) or None,
        "source": sanitize_line(str(payload.get("source") or "browser"), max_length=32) or "browser",
        "meta": sanitize_json_value(payload.get("meta") if isinstance(payload.get("meta"), dict) else {}),
    }
    if not normalized["id"] and not normalized["label"]:
        return {}
    return normalized


def _normalize_semantic_section(section: dict[str, Any] | None) -> dict[str, Any]:
    payload = section if isinstance(section, dict) else {}
    section_id = sanitize_line(str(payload.get("section_id") or ""), max_length=96)
    label = sanitize_text(str(payload.get("label") or ""), max_length=120)
    if not section_id or not label:
        return {}
    return {
        "section_id": section_id,
        "label": label,
        "node_id": sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "description": sanitize_text(str(payload.get("description") or ""), max_length=180) or None,
    }


def _normalize_semantic_action(action: dict[str, Any] | None) -> dict[str, Any]:
    payload = action if isinstance(action, dict) else {}
    action_type = sanitize_line(str(payload.get("action_type") or "click"), max_length=32).lower() or "click"
    if action_type not in SUPPORTED_UI_ACTIONS:
        action_type = "click"
    semantic_action_id = sanitize_line(str(payload.get("semantic_action_id") or ""), max_length=128)
    label = sanitize_text(str(payload.get("label") or ""), max_length=160)
    if not semantic_action_id or not label:
        return {}
    return {
        "semantic_action_id": semantic_action_id,
        "label": label,
        "action_type": action_type,
        "node_id": sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "description": sanitize_text(str(payload.get("description") or ""), max_length=180) or None,
        "section_id": sanitize_line(str(payload.get("section_id") or ""), max_length=96) or None,
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
    semantic_form_id = sanitize_line(str(payload.get("semantic_form_id") or ""), max_length=128)
    label = sanitize_text(str(payload.get("label") or ""), max_length=160)
    if not semantic_form_id or not label:
        return {}
    return {
        "semantic_form_id": semantic_form_id,
        "label": label,
        "node_id": sanitize_line(str(payload.get("node_id") or ""), max_length=64) or None,
        "fields": sanitize_json_value(payload.get("fields") if isinstance(payload.get("fields"), list) else [])[:8],
        "submit_action_id": sanitize_line(str(payload.get("submit_action_id") or ""), max_length=128) or None,
    }


def normalize_semantic_page_context(page_context: dict[str, Any] | None) -> dict[str, Any]:
    payload = page_context if isinstance(page_context, dict) else {}
    sections = payload.get("visible_sections") if isinstance(payload.get("visible_sections"), list) else []
    semantic_actions = payload.get("semantic_actions") if isinstance(payload.get("semantic_actions"), list) else []
    semantic_forms = payload.get("semantic_forms") if isinstance(payload.get("semantic_forms"), list) else []
    secondary_entities = payload.get("secondary_entities") if isinstance(payload.get("secondary_entities"), list) else []
    selected_rows = payload.get("selected_rows") if isinstance(payload.get("selected_rows"), list) else []
    normalized = {
        "page_kind": sanitize_line(str(payload.get("page_kind") or "unknown"), max_length=48) or "unknown",
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


def browser_semantic_page_context(browser_context: dict[str, Any]) -> dict[str, Any]:
    payload = browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
    return normalize_semantic_page_context(payload)


def compact_page_context(page_context: dict[str, Any]) -> dict[str, Any]:
    query = page_context.get("query") if isinstance(page_context.get("query"), dict) else {}
    compact_query = {str(key): sanitize_json_value(value) for key, value in list(query.items())[:12]}
    return {
        "pathname": page_context.get("pathname"),
        "asset_id": page_context.get("asset_id"),
        "finding_id": page_context.get("finding_id"),
        "task_id": page_context.get("task_id"),
        "query": compact_query,
    }


def compact_browser_context(browser_context: dict[str, Any]) -> dict[str, Any]:
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


def resolve_model_context_tier(
    *,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    objective_kind: str | None,
) -> int:
    phase = sanitize_line(str(browser_runtime.get("phase") or ""), max_length=48)
    objective = sanitize_line(str(objective_kind or browser_runtime.get("objective_kind") or ""), max_length=48)
    if phase in {"awaiting_ui_feedback", "awaiting_secure_input", "waiting_approval", "watching_task"}:
        return 3
    if objective in {"inspect", "operate_low_risk", "operate_high_risk"}:
        return 3
    if page_context.get("finding_id") or browser_context.get("finding_id") or objective in {"analyze", "prepare_plan"}:
        return 2
    return 1


def compact_browser_context_for_tier(browser_context: dict[str, Any], *, tier: int) -> dict[str, Any]:
    compacted = compact_browser_context(browser_context)
    if tier >= 3:
        return compacted
    compacted["dom_snapshot"] = []
    compacted["forms"] = []
    if tier < 2:
        compacted["visible_actions"] = []
        compacted["semantic_actions"] = []
        compacted["semantic_forms"] = []
        compacted["selected_entities"] = []
        compacted["open_panels"] = []
    return compacted


def compact_working_context_for_tier(working_context: dict[str, Any], *, tier: int) -> dict[str, Any]:
    if tier >= 2:
        return sanitize_json_value(working_context)
    primary_target = working_context_primary_target(working_context)
    recent_targets = working_context.get("recent_targets") if isinstance(working_context.get("recent_targets"), list) else []
    return sanitize_json_value(
        {
            "primary_target": primary_target,
            "recent_targets": recent_targets[:3],
            "summary": working_context_summary(working_context),
        }
    )


def compact_semantic_page_context_for_model(page_context: dict[str, Any] | None) -> dict[str, Any]:
    normalized = normalize_semantic_page_context(page_context if isinstance(page_context, dict) else {})
    return {
        "page_kind": sanitize_line(str(normalized.get("page_kind") or "unknown"), max_length=48) or "unknown",
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


def compact_model_value(value: Any, *, depth: int = 0) -> Any:
    if depth >= 2:
        return sanitize_json_value(value)
    if isinstance(value, list):
        return [compact_model_value(item, depth=depth + 1) for item in value[:3]]
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
        compacted[key] = compact_model_value(value.get(key), depth=depth + 1)

    for list_key in ("items", "events", "rows", "assets", "findings", "sessions"):
        list_value = value.get(list_key)
        if isinstance(list_value, list) and list_value:
            compacted[f"{list_key}_preview"] = [compact_model_value(item, depth=depth + 1) for item in list_value[:2]]
            if "total" not in compacted:
                compacted["total"] = len(list_value)
            break

    for nested_key in ("timing", "result", "meta"):
        nested_value = value.get(nested_key)
        if isinstance(nested_value, dict) and nested_value:
            compacted[nested_key] = compact_model_value(nested_value, depth=depth + 1)

    if not compacted:
        for key, item in list(value.items())[:6]:
            compacted[sanitize_line(str(key), max_length=64) or str(key)] = compact_model_value(item, depth=depth + 1)
    return sanitize_json_value(compacted)


def compact_tool_traces_for_model(tool_traces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for trace in tool_traces[-MAX_MODEL_TOOL_TRACE_ITEMS:]:
        if not isinstance(trace, dict):
            continue
        item = {
            "tool_name": sanitize_line(str(trace.get("tool_name") or ""), max_length=64),
            "arguments": sanitize_json_value(trace.get("arguments") if isinstance(trace.get("arguments"), dict) else {}),
            "ok": False if trace.get("ok") is False else True,
        }
        if item["ok"]:
            item["result"] = compact_model_value(trace.get("result"))
        else:
            item["error"] = sanitize_text(str(trace.get("error") or ""), max_length=240) or None
        compacted.append(item)
    return compacted


def normalize_ui_action_results(results: Any) -> list[dict[str, Any]]:
    if not isinstance(results, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in results[:12]:
        if not isinstance(item, dict):
            continue
        action_type = sanitize_line(str(item.get("action_type") or ""), max_length=32).lower()
        if action_type not in SUPPORTED_UI_ACTIONS:
            continue
        normalized.append(
            {
                "action_id": sanitize_line(str(item.get("action_id") or ""), max_length=64),
                "action_type": action_type,
                "ok": bool(item.get("ok")),
                "semantic_action_id": sanitize_line(str(item.get("semantic_action_id") or ""), max_length=128) or None,
                "target_node_id": sanitize_line(str(item.get("target_node_id") or ""), max_length=64) or None,
                "resolved_node_id": sanitize_line(str(item.get("resolved_node_id") or ""), max_length=64) or None,
                "message": sanitize_text(str(item.get("message") or ""), max_length=220) or None,
                "resolved_target": sanitize_json_value(
                    item.get("resolved_target") if isinstance(item.get("resolved_target"), dict) else {}
                ),
                "attempt_count": max(1, min(int(item.get("attempt_count") or 1), 4)),
                "detail_json": sanitize_json_value(item.get("detail_json") if isinstance(item.get("detail_json"), dict) else {}),
            }
        )
    return normalized


def compact_ui_action_results_for_model(results: Any) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for item in normalize_ui_action_results(results)[:MAX_MODEL_UI_RESULTS]:
        compacted_item = {
            "action_id": sanitize_line(str(item.get("action_id") or ""), max_length=64) or None,
            "action_type": sanitize_line(str(item.get("action_type") or ""), max_length=32) or None,
            "ok": bool(item.get("ok")),
            "semantic_action_id": sanitize_line(str(item.get("semantic_action_id") or ""), max_length=128) or None,
            "target_node_id": sanitize_line(str(item.get("target_node_id") or ""), max_length=64) or None,
            "resolved_node_id": sanitize_line(str(item.get("resolved_node_id") or ""), max_length=64) or None,
            "message": sanitize_text(str(item.get("message") or ""), max_length=180) or None,
            "resolved_target": sanitize_json_value(
                item.get("resolved_target") if isinstance(item.get("resolved_target"), dict) else {}
            ),
            "attempt_count": max(1, min(int(item.get("attempt_count") or 1), 4)),
        }
        compacted.append(compacted_item)
    return compacted


def compact_auto_executed_actions_for_model(actions: Any) -> list[dict[str, Any]]:
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
                "action_type": sanitize_line(str(item.get("action_type") or ""), max_length=64) or None,
                "title": sanitize_text(str(item.get("title") or ""), max_length=120) or None,
                "summary": sanitize_text(str(item.get("summary") or ""), max_length=180) or None,
                "child_task_id": sanitize_line(str(item.get("child_task_id") or ""), max_length=64) or None,
                "status": sanitize_line(str(item.get("status") or payload.get("status") or ""), max_length=32) or None,
                "asset_id": sanitize_line(str(params.get("asset_id") or payload.get("asset_id") or ""), max_length=64) or None,
                "session_id": sanitize_line(str(payload.get("session_id") or ""), max_length=64) or None,
            }
        )
    return compacted


def normalize_browser_runtime_for_model(browser_runtime: dict[str, Any] | None) -> dict[str, Any]:
    payload = browser_runtime if isinstance(browser_runtime, dict) else {}
    pending_secure_input = (
        payload.get("pending_secure_input") if isinstance(payload.get("pending_secure_input"), dict) else {}
    )
    return {
        "phase": sanitize_line(str(payload.get("phase") or ""), max_length=48) or "idle",
        "step_count": max(0, min(int(payload.get("step_count") or 0), MAX_AGENT_LOOP_STEPS)),
        "current_objective": sanitize_text(str(payload.get("current_objective") or ""), max_length=240) or None,
        "objective_kind": sanitize_line(str(payload.get("objective_kind") or ""), max_length=32) or None,
        "planned_steps": sanitize_json_value(payload.get("planned_steps") if isinstance(payload.get("planned_steps"), list) else [])[
            :MAX_MODEL_PLANNED_STEPS
        ],
        "step_cursor": max(0, min(int(payload.get("step_cursor") or 0), MAX_AGENT_LOOP_STEPS)),
        "pending_ui_actions": sanitize_json_value(
            payload.get("pending_ui_actions") if isinstance(payload.get("pending_ui_actions"), list) else []
        )[:MAX_UI_ACTION_BATCH],
        "completed_ui_actions": compact_ui_action_results_for_model(payload.get("completed_ui_actions")),
        "last_ui_results": compact_ui_action_results_for_model(payload.get("last_ui_results")),
        "pending_secure_input": {
            "kind": sanitize_line(str(pending_secure_input.get("kind") or ""), max_length=64) or None,
            "mode": sanitize_line(str(pending_secure_input.get("mode") or ""), max_length=32) or None,
            "asset_ids": sanitize_json_value(
                pending_secure_input.get("asset_ids") if isinstance(pending_secure_input.get("asset_ids"), list) else []
            )[:4],
            "resume_goal_id": sanitize_line(str(pending_secure_input.get("resume_goal_id") or ""), max_length=64) or None,
            "blocker_summary": sanitize_text(str(pending_secure_input.get("blocker_summary") or ""), max_length=240) or None,
        }
        if pending_secure_input
        else {},
        "auto_executed_actions": compact_auto_executed_actions_for_model(payload.get("auto_executed_actions")),
        "last_user_intent": sanitize_text(str(payload.get("last_user_intent") or ""), max_length=240) or None,
        "last_error": sanitize_text(str(payload.get("last_error") or ""), max_length=240) or None,
    }


def render_history_line(message: Any, *, max_length: int = 4000) -> str | None:
    role = "assistant" if str(message.role or "").strip().lower() == "assistant" else "user"
    content = sanitize_text(message.content, max_length=max_length) or ""
    if not content:
        return None
    message_type = str(message.message_type or "text").strip().lower() or "text"
    label = role if message_type == "text" else f"{role}/{message_type}"
    return f"{label}: {content}"


def select_model_history_lines(messages: list[Any]) -> list[str]:
    selected: list[str] = []
    total_chars = 0
    assistant_types = {"text", "clarifying", "plan", "error"}
    fallback_line: str | None = None

    for item in reversed(messages):
        role = str(getattr(item, "role", "") or "").strip().lower()
        message_type = str(getattr(item, "message_type", "") or "text").strip().lower() or "text"
        rendered = render_history_line(item, max_length=280)
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


def build_model_response_contract() -> dict[str, Any]:
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
            "ui_actions": [
                {
                    "action_id": "string",
                    "action_type": "string",
                    "semantic_action_id": "string|null",
                    "target_node_id": "string|null",
                    "selector": "string|null",
                    "expected_page_kind": "string|null",
                    "expected_section": "string|null",
                    "retryable": "boolean",
                }
            ],
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


def build_model_context_payload(
    *,
    user: Any,
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
    primary_target = working_context_primary_target(working_context)
    recent_targets = working_context.get("recent_targets") if isinstance(working_context.get("recent_targets"), list) else []
    semantic_page_context = compact_semantic_page_context_for_model(browser_semantic_page_context(browser_context))
    context_tier = resolve_model_context_tier(
        page_context=page_context,
        browser_context=browser_context,
        browser_runtime=browser_runtime,
        objective_kind=str(objective_kind or ""),
    )
    available_tools = [
        {
            "tool_name": "list_assets",
            "description": "读取资产列表，可按 keyword 搜索，limit 最大 10",
            "arguments": {"keyword": "可选字符串", "status": "可选 online/offline/collecting/unknown", "limit": "可选整数"},
        },
        {"tool_name": "get_asset_detail", "description": "按 asset_id 读取资产详情", "arguments": {"asset_id": "必填字符串"}},
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
        {"tool_name": "get_risk_detail", "description": "按 finding_id 读取单条风险详情", "arguments": {"finding_id": "必填字符串"}},
        {
            "tool_name": "list_asset_risks",
            "description": "按 asset_id 读取风险列表",
            "arguments": {"asset_id": "必填字符串", "status": "可选 open/fixed/ignored", "limit": "可选整数"},
        },
        {"tool_name": "list_tasks", "description": "读取平台任务列表", "arguments": {"task_type": "可选", "status": "可选", "limit": "可选整数"}},
        {"tool_name": "get_task_detail", "description": "读取单个任务详情", "arguments": {"task_id": "必填字符串"}},
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
        {"tool_name": "get_vuln_rule", "description": "读取单条漏洞库规则详情", "arguments": {"rule_id": "必填字符串"}},
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
        {"action_type": "install_runner", "description": "安装 Host Runner", "required_params": {"asset_id": "资产 ID"}},
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
        "user_role": normalize_role(getattr(user, "role", None)),
        "allow_write_plans": allow_write_plans,
        "allow_auto_execute_actions": allow_auto_execute_actions,
        "current_objective": sanitize_text(str(current_objective or ""), max_length=240) or None,
        "objective_kind": sanitize_line(str(objective_kind or ""), max_length=32) or None,
        "context_triage": {
            "tier": context_tier,
            "loaded_levels": ["session_state", "asset_summary"]
            + (["risk_detail", "environment"] if context_tier >= 2 else [])
            + (["ssh_metadata", "topology_runtime"] if context_tier >= 3 else []),
        },
        "conversation_focus": sanitize_json_value(primary_target),
        "recent_targets": sanitize_json_value(recent_targets[:6]),
        "shared_working_context": compact_working_context_for_tier(working_context, tier=context_tier),
        "current_page_context": compact_page_context(page_context),
        "semantic_page_context": sanitize_json_value(semantic_page_context),
        "current_browser_context": compact_browser_context_for_tier(browser_context, tier=context_tier),
        "browser_runtime": normalize_browser_runtime_for_model(browser_runtime),
        "pending_dialog_state": sanitize_json_value(dialog_state),
        "followup_hint": sanitize_json_value(followup_hint),
        "available_read_tools": available_tools,
        "allowed_write_actions": write_action_whitelist,
        "auto_execute_write_actions": [item for item in write_action_whitelist if item["action_type"] in AUTO_EXECUTE_ACTIONS],
        "allowed_browser_actions": browser_action_whitelist,
    }


def build_agent_model_request(
    *,
    agent_display_name: str,
    session: Any,
    user: Any,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    browser_runtime: dict[str, Any],
    working_context: dict[str, Any],
    dialog_state: dict[str, Any],
    followup_hint: dict[str, Any],
    tool_traces: list[dict[str, Any]],
    allow_write_plans: bool,
    allow_auto_execute_actions: bool,
    reflection_errors: list[dict[str, Any]] | None = None,
) -> LLMRequest:
    recent_messages = list(getattr(session, "messages", [])[-12:])
    latest_user_content = ""
    if recent_messages:
        last_message = recent_messages[-1]
        last_role = str(getattr(last_message, "role", "") or "").strip().lower()
        if last_role == "user":
            latest_user_content = sanitize_text(getattr(last_message, "content", ""), max_length=4000) or ""
            recent_messages = recent_messages[:-1]
    history_lines = select_model_history_lines(recent_messages)

    messages: list[LLMMessage] = [
        LLMMessage.from_text(
            "system",
            f"你是 {agent_display_name}，负责在资产态势感知平台内充当站内自治助手。"
            "同一会话可以连续处理不同资产、风险、任务和修复对象；页面地址只是提示，不是硬性上下文绑定。"
            "你必须优先推进当前目标，能做动作时不要退化成纯说明，并严格遵守平台白名单工具与动作边界。",
        ),
        LLMMessage.from_text(
            "system",
            json.dumps(build_model_response_contract(), ensure_ascii=False, indent=2),
        ),
        LLMMessage.from_text(
            "user",
            "平台当前上下文如下：\n"
            + json.dumps(
                build_model_context_payload(
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
    if reflection_errors:
        messages.append(
            LLMMessage.from_text(
                "system",
                build_reflection_instruction(reflection_errors),
            )
        )
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
                    sanitize_json_value({"executed_read_tools": compact_tool_traces_for_model(tool_traces)}),
                    ensure_ascii=False,
                    indent=2,
                ),
            )
        )
    return LLMRequest(messages=messages)
