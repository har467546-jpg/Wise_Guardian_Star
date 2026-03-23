from __future__ import annotations

from typing import Any

from app.utils.sanitize import sanitize_json_value, sanitize_text


def sanitize_browser_context_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    payload = summary if isinstance(summary, dict) else {}
    return {
        "page_kind": sanitize_text(str(payload.get("page_kind") or "unknown"), max_length=64, single_line=True) or "unknown",
        "primary_entity": sanitize_json_value(payload.get("primary_entity") if isinstance(payload.get("primary_entity"), dict) else {}),
        "secondary_entities": sanitize_json_value(payload.get("secondary_entities") if isinstance(payload.get("secondary_entities"), list) else [])[:6],
        "visible_sections": sanitize_json_value(payload.get("visible_sections") if isinstance(payload.get("visible_sections"), list) else [])[:6],
        "top_semantic_actions": sanitize_json_value(payload.get("top_semantic_actions") if isinstance(payload.get("top_semantic_actions"), list) else [])[:8],
        "selected_rows": sanitize_json_value(payload.get("selected_rows") if isinstance(payload.get("selected_rows"), list) else [])[:6],
        "active_dialog": sanitize_json_value(payload.get("active_dialog") if isinstance(payload.get("active_dialog"), dict) else {}),
        "has_modal_or_drawer": bool(payload.get("has_modal_or_drawer")),
        "summary": sanitize_text(str(payload.get("summary") or ""), max_length=240) or None,
    }
