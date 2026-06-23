from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from redis import Redis

from app.core.config import settings
from app.utils.sanitize import sanitize_json_value, sanitize_text

DEFAULT_CHECKPOINT_TTL_SECONDS = 24 * 60 * 60


def save_agent_session_checkpoint(session: Any, *, stage: str) -> bool:
    session_id = sanitize_text(str(getattr(session, "id", "") or ""), max_length=64, single_line=True)
    if not session_id:
        return False
    payload = _build_checkpoint_payload(session, stage=stage)
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.setex(
            _checkpoint_key(session_id),
            _checkpoint_ttl_seconds(),
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str),
        )
        return True
    except Exception:
        return False
    finally:
        client.close()


def restore_agent_session_checkpoint(session: Any) -> bool:
    session_id = sanitize_text(str(getattr(session, "id", "") or ""), max_length=64, single_line=True)
    if not session_id:
        return False
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = client.get(_checkpoint_key(session_id))
    except Exception:
        return False
    finally:
        client.close()
    if not raw:
        return False
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(payload, dict):
        return False
    if not _checkpoint_is_newer(payload, getattr(session, "updated_at", None)):
        return False
    _apply_checkpoint_payload(session, payload)
    return True


def delete_agent_session_checkpoint(session_id: str) -> None:
    normalized = sanitize_text(str(session_id or ""), max_length=64, single_line=True)
    if not normalized:
        return
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.delete(_checkpoint_key(normalized))
    finally:
        client.close()


def _build_checkpoint_payload(session: Any, *, stage: str) -> dict[str, Any]:
    return sanitize_json_value(
        {
            "version": 1,
            "stage": sanitize_text(stage, max_length=64, single_line=True) or "unknown",
            "session_id": getattr(session, "id", None),
            "status": getattr(session, "status", None),
            "route_context_json": getattr(session, "route_context_json", {}) if isinstance(getattr(session, "route_context_json", None), dict) else {},
            "working_context_json": getattr(session, "working_context_json", {}) if isinstance(getattr(session, "working_context_json", None), dict) else {},
            "dialog_state_json": getattr(session, "dialog_state_json", {}) if isinstance(getattr(session, "dialog_state_json", None), dict) else {},
            "pending_plan_json": getattr(session, "pending_plan_json", {}) if isinstance(getattr(session, "pending_plan_json", None), dict) else {},
            "browser_runtime_json": getattr(session, "browser_runtime_json", {}) if isinstance(getattr(session, "browser_runtime_json", None), dict) else {},
            "agent_state_json": getattr(session, "agent_state_json", {}) if isinstance(getattr(session, "agent_state_json", None), dict) else {},
            "last_task_id": getattr(session, "last_task_id", None),
            "current_goal_id": getattr(session, "current_goal_id", None),
            "updated_at": _serialize_datetime(getattr(session, "updated_at", None)),
            "checkpointed_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def _apply_checkpoint_payload(session: Any, payload: dict[str, Any]) -> None:
    for attr in (
        "route_context_json",
        "working_context_json",
        "dialog_state_json",
        "pending_plan_json",
        "browser_runtime_json",
        "agent_state_json",
    ):
        value = payload.get(attr)
        if isinstance(value, dict):
            setattr(session, attr, value)
    for attr in ("status", "last_task_id", "current_goal_id"):
        value = payload.get(attr)
        if value is not None:
            setattr(session, attr, value)


def _checkpoint_is_newer(payload: dict[str, Any], updated_at: Any) -> bool:
    checkpoint_time = _parse_datetime(payload.get("checkpointed_at")) or _parse_datetime(payload.get("updated_at"))
    session_time = _parse_datetime(updated_at)
    if checkpoint_time is None:
        return False
    if session_time is None:
        return True
    return checkpoint_time >= session_time


def _serialize_datetime(value: Any) -> str | None:
    if isinstance(value, datetime):
        current = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return current.astimezone(timezone.utc).isoformat()
    text = sanitize_text(str(value or ""), max_length=80, single_line=True)
    return text or None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    text = sanitize_text(str(value or ""), max_length=80, single_line=True)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _checkpoint_key(session_id: str) -> str:
    prefix = str(getattr(settings, "AGENT_CHECKPOINT_REDIS_PREFIX", "sa:agent_checkpoint") or "sa:agent_checkpoint").strip()
    return f"{prefix}:{session_id}"


def _checkpoint_ttl_seconds() -> int:
    value = getattr(settings, "AGENT_CHECKPOINT_TTL_SECONDS", DEFAULT_CHECKPOINT_TTL_SECONDS)
    try:
        return max(60, int(value))
    except (TypeError, ValueError):
        return DEFAULT_CHECKPOINT_TTL_SECONDS
