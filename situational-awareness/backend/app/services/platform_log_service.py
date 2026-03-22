from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
import time
import traceback
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

import redis as redis_sync
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.platform_log_entry import PlatformLogEntry
from app.db.models.task_run import TaskRun
from app.db.session import SessionLocal, engine
from app.repositories.platform_log_repo import delete_platform_log_entries_older_than

PLATFORM_LOG_CHANNEL = "platform_log_entries"
SYSTEM_LOG_SOURCE = "system"
TASK_RAW_LOG_SOURCE = "task_raw"
DEFAULT_LOG_RETENTION_DAYS = 7
DEFAULT_LOG_CLEANUP_INTERVAL_SECONDS = 900
DEFAULT_LOG_HEARTBEAT_SECONDS = 20

_CAPTURED_LOGGER_PREFIXES = ("app.", "uvicorn.error", "celery")
_SKIPPED_LOGGER_PREFIXES = (
    "uvicorn.access",
    "sqlalchemy",
    "watchfiles",
    "asyncio",
    "httpx",
    "redis",
)
_TASK_RAW_EVENT_TYPES = {"command", "stream", "failure", "retry"}
_REDACTED = "[REDACTED]"
_SENSITIVE_NAME_TOKENS = (
    "authorization",
    "password",
    "sudo_password",
    "runner_token",
    "registration_token",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "access_token",
    "private_key",
    "llm_api_key",
)
_TEXT_REDACTION_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)([^\s,;]+)"),
    re.compile(
        r"(?i)(\b(?:password|sudo_password|runner_token|registration_token|llm_api_key|api_key|access_token|secret|token|private_key)\b\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
    ),
]
_cleanup_lock = threading.Lock()
_last_cleanup_monotonic = 0.0
_emit_guard = threading.local()
_capture_enabled = False


def infer_platform_log_service_name(force_service_name: str | None = None) -> str:
    if force_service_name in {"backend", "worker"}:
        return force_service_name
    argv = " ".join(sys.argv).lower()
    return "worker" if "celery" in argv else "backend"


def ensure_platform_log_storage() -> None:
    try:
        PlatformLogEntry.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        return
    maybe_cleanup_expired_platform_logs(force=True)


def maybe_cleanup_expired_platform_logs(*, force: bool = False) -> None:
    global _last_cleanup_monotonic
    current = time.monotonic()
    if not force and current - _last_cleanup_monotonic < DEFAULT_LOG_CLEANUP_INTERVAL_SECONDS:
        return
    with _cleanup_lock:
        current = time.monotonic()
        if not force and current - _last_cleanup_monotonic < DEFAULT_LOG_CLEANUP_INTERVAL_SECONDS:
            return
        cutoff = datetime.now(timezone.utc) - timedelta(days=DEFAULT_LOG_RETENTION_DAYS)
        with SessionLocal() as db:
            try:
                delete_platform_log_entries_older_than(db, cutoff=cutoff)
            except Exception:
                db.rollback()
        _last_cleanup_monotonic = current


def serialize_platform_log_entry(entry: PlatformLogEntry | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(entry, Mapping):
        created_at = entry.get("created_at")
        return {
            "id": str(entry.get("id") or ""),
            "source_kind": str(entry.get("source_kind") or SYSTEM_LOG_SOURCE),
            "service_name": str(entry.get("service_name") or infer_platform_log_service_name()),
            "logger_name": str(entry.get("logger_name") or "log"),
            "task_run_id": str(entry.get("task_run_id") or "").strip() or None,
            "task_type": _enum_value(entry.get("task_type")),
            "event_type": str(entry.get("event_type") or "log"),
            "level": normalize_log_level(entry.get("level")),
            "stage_code": _strip_text(entry.get("stage_code")),
            "stage_name": _strip_text(entry.get("stage_name")),
            "message": _coerce_message(entry.get("message")),
            "payload_json": _json_safe_value(
                entry.get("payload_json") if isinstance(entry.get("payload_json"), Mapping) else {}
            ),
            "created_at": _serialize_datetime(created_at),
        }
    return {
        "id": entry.id,
        "source_kind": entry.source_kind,
        "service_name": entry.service_name,
        "logger_name": entry.logger_name,
        "task_run_id": entry.task_run_id,
        "task_type": entry.task_type,
        "event_type": entry.event_type,
        "level": normalize_log_level(entry.level),
        "stage_code": entry.stage_code,
        "stage_name": entry.stage_name,
        "message": entry.message,
        "payload_json": _json_safe_value(entry.payload_json if isinstance(entry.payload_json, Mapping) else {}),
        "created_at": _serialize_datetime(entry.created_at),
    }


def create_platform_log_entry(
    db: Session,
    *,
    source_kind: str,
    service_name: str,
    logger_name: str,
    task_run_id: str | None = None,
    task_type: str | None = None,
    event_type: str = "log",
    level: str = "info",
    stage_code: str | None = None,
    stage_name: str | None = None,
    message: str | None = None,
    payload_json: dict[str, Any] | None = None,
    created_at: datetime | None = None,
    publish: bool = True,
) -> PlatformLogEntry:
    maybe_cleanup_expired_platform_logs()
    entry = PlatformLogEntry(
        source_kind=source_kind,
        service_name=service_name,
        logger_name=_strip_text(logger_name) or "log",
        task_run_id=_strip_text(task_run_id),
        task_type=_strip_text(task_type),
        event_type=_strip_text(event_type) or "log",
        level=normalize_log_level(level),
        stage_code=_strip_text(stage_code),
        stage_name=_strip_text(stage_name),
        message=redact_sensitive_text(_coerce_message(message)),
        payload_json=redact_sensitive_json_value(payload_json or {}),
        created_at=_ensure_datetime(created_at) or datetime.now(timezone.utc),
    )
    db.add(entry)
    db.flush()
    if publish:
        _publish_platform_log_entry(serialize_platform_log_entry(entry))
    return entry


def mirror_task_event_to_platform_logs(
    db: Session,
    *,
    task_run_id: str,
    event_type: str,
    level: str,
    stage_code: str | None,
    stage_name: str | None,
    message: str | None,
    payload_json: dict[str, Any] | None,
    created_at: datetime | None,
) -> PlatformLogEntry | None:
    payload = payload_json if isinstance(payload_json, Mapping) else {}
    if event_type not in _TASK_RAW_EVENT_TYPES or not _task_event_has_raw_context(payload):
        return None
    task = db.get(TaskRun, task_run_id)
    task_type = task.task_type.value if task is not None and getattr(task, "task_type", None) is not None else None
    return create_platform_log_entry(
        db,
        source_kind=TASK_RAW_LOG_SOURCE,
        service_name=infer_platform_log_service_name(),
        logger_name="task_event",
        task_run_id=task_run_id,
        task_type=task_type,
        event_type=event_type,
        level=level,
        stage_code=stage_code,
        stage_name=stage_name,
        message=_resolve_task_raw_message(message, payload),
        payload_json=dict(payload),
        created_at=created_at,
        publish=True,
    )


def log_entry_matches_filters(
    entry: PlatformLogEntry | Mapping[str, Any],
    *,
    source_kind: str | None = None,
    service_name: str | None = None,
    task_id: str | None = None,
    task_type: str | None = None,
    level: str | None = None,
    keyword: str | None = None,
) -> bool:
    payload = serialize_platform_log_entry(entry)
    if source_kind and payload["source_kind"] != source_kind:
        return False
    if service_name and payload["service_name"] != service_name:
        return False
    if task_id and payload["task_run_id"] != task_id:
        return False
    if task_type and payload["task_type"] != task_type:
        return False
    if level and payload["level"] != normalize_log_level(level):
        return False
    if keyword:
        normalized = keyword.strip().lower()
        if normalized:
            haystacks = [
                str(payload.get("message") or ""),
                str(payload.get("logger_name") or ""),
                str(payload.get("task_run_id") or ""),
                str(payload.get("stage_code") or ""),
                str(payload.get("stage_name") or ""),
                str(payload.get("event_type") or ""),
            ]
            if not any(normalized in item.lower() for item in haystacks):
                return False
    return True


def install_platform_log_capture(*, service_name: str | None = None, root_logger: logging.Logger | None = None) -> None:
    resolved_service_name = infer_platform_log_service_name(service_name)
    target_logger = root_logger or logging.getLogger()
    current_pid = os.getpid()
    for handler in target_logger.handlers:
        if (
            isinstance(handler, PlatformLogCaptureHandler)
            and handler.service_name == resolved_service_name
            and handler.pid == current_pid
        ):
            return
    target_logger.addHandler(PlatformLogCaptureHandler(service_name=resolved_service_name))


def enable_platform_log_capture() -> None:
    global _capture_enabled
    ensure_platform_log_storage()
    _capture_enabled = True


def disable_platform_log_capture() -> None:
    global _capture_enabled
    _capture_enabled = False


class PlatformLogCaptureHandler(logging.Handler):
    def __init__(self, *, service_name: str) -> None:
        super().__init__(level=logging.INFO)
        self.service_name = service_name
        self.pid = os.getpid()

    def emit(self, record: logging.LogRecord) -> None:
        if not _capture_enabled:
            return
        logger_name = str(record.name or "")
        if not _should_capture_logger(logger_name):
            return
        if getattr(_emit_guard, "active", False):
            return

        message = self.format(record) if record.msg else record.getMessage()
        payload = {
            "pathname": record.pathname,
            "lineno": record.lineno,
            "funcName": record.funcName,
            "process": record.process,
            "thread": record.thread,
        }
        if record.exc_info:
            payload["traceback"] = "".join(traceback.format_exception(*record.exc_info))

        try:
            _emit_guard.active = True
            with SessionLocal() as db:
                try:
                    create_platform_log_entry(
                        db,
                        source_kind=SYSTEM_LOG_SOURCE,
                        service_name=self.service_name,
                        logger_name=logger_name,
                        event_type="log",
                        level=record.levelname,
                        message=message,
                        payload_json=payload,
                        publish=True,
                    )
                    db.commit()
                except Exception:
                    db.rollback()
        finally:
            _emit_guard.active = False


def _should_capture_logger(logger_name: str) -> bool:
    if not logger_name:
        return False
    if any(logger_name.startswith(prefix) for prefix in _SKIPPED_LOGGER_PREFIXES):
        return False
    return any(logger_name.startswith(prefix) for prefix in _CAPTURED_LOGGER_PREFIXES)


def _task_event_has_raw_context(payload: Mapping[str, Any]) -> bool:
    command = payload.get("command")
    stdout = payload.get("stdout_tail") or payload.get("stdout")
    stderr = payload.get("stderr_tail") or payload.get("stderr")
    return bool(command or stdout or stderr)


def _resolve_task_raw_message(message: str | None, payload: Mapping[str, Any]) -> str | None:
    if message:
        return message
    command = _strip_text(payload.get("command"))
    if command:
        return command
    return "task raw event"


def _publish_platform_log_entry(payload: Mapping[str, Any]) -> None:
    try:
        client = redis_sync.Redis.from_url(settings.REDIS_URL, decode_responses=True)
        client.publish(PLATFORM_LOG_CHANNEL, json.dumps(dict(payload), ensure_ascii=False, default=str))
        client.close()
    except Exception:
        return


def redact_sensitive_text(value: str | None) -> str | None:
    text = _coerce_message(value)
    if text is None:
        return None
    for pattern in _TEXT_REDACTION_PATTERNS:
        text = pattern.sub(r"\1" + _REDACTED, text)
    return text


def redact_sensitive_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = str(key or "").strip().lower()
            if any(token in normalized_key for token in _SENSITIVE_NAME_TOKENS):
                redacted[str(key)] = _REDACTED
            else:
                redacted[str(key)] = redact_sensitive_json_value(item)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_sensitive_json_value(item) for item in value]
    if isinstance(value, str):
        return redact_sensitive_text(value) or ""
    return value


def normalize_log_level(value: object) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"warn", "warning"}:
        return "warning"
    if normalized in {"critical", "fatal", "exception"}:
        return "error"
    if normalized == "error":
        return "error"
    return "info"


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _serialize_datetime(value)
    return value


def _serialize_datetime(value: object) -> str | None:
    normalized = _ensure_datetime(value)
    return normalized.isoformat() if normalized is not None else None


def _ensure_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None


def _enum_value(value: object) -> str | None:
    if isinstance(value, Enum):
        return str(value.value)
    text = _strip_text(value)
    return text or None


def _strip_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _coerce_message(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
