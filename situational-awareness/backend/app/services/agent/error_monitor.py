from __future__ import annotations

import logging
from typing import Any

from app.services.platform_log_service import redact_sensitive_json_value
from app.utils.sanitize import sanitize_json_value, sanitize_text

logger = logging.getLogger("app.agent.monitor")


def record_agent_error(
    *,
    error_type: str,
    stage: str,
    session_id: str | None = None,
    task_id: str | None = None,
    model: str | None = None,
    prompt_version: str | None = None,
    details: dict[str, Any] | None = None,
    exc: Exception | None = None,
) -> None:
    payload = redact_sensitive_json_value(
        sanitize_json_value(
            {
                "error_type": sanitize_text(error_type, max_length=80, single_line=True) or "agent_error",
                "stage": sanitize_text(stage, max_length=80, single_line=True) or "unknown",
                "session_id": sanitize_text(session_id, max_length=64, single_line=True) or None,
                "task_id": sanitize_text(task_id, max_length=64, single_line=True) or None,
                "model": sanitize_text(model, max_length=128, single_line=True) or None,
                "prompt_version": sanitize_text(prompt_version, max_length=64, single_line=True) or None,
                "details": details or {},
                "exception": sanitize_text(str(exc), max_length=500, single_line=True) if exc else None,
            }
        )
    )
    logger.warning(
        "agent runtime error",
        extra={
            "agent_error_type": payload.get("error_type"),
            "agent_stage": payload.get("stage"),
            "agent_session_id": payload.get("session_id"),
            "agent_task_id": payload.get("task_id"),
            "agent_error_payload": payload,
        },
    )
