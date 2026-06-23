from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from app.db.models.enums import TaskExecutionStatus
from app.db.models.task_event import TaskEvent
from app.db.models.task_run import TaskRun


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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _duration_ms(start: datetime | None, end: datetime | None) -> int | None:
    start_at = _ensure_datetime(start)
    end_at = _ensure_datetime(end)
    if start_at is None or end_at is None:
        return None
    return max(0, int((end_at - start_at).total_seconds() * 1000))


def _latest_stage_event(events: list[TaskEvent | dict[str, Any]]) -> TaskEvent | dict[str, Any] | None:
    stage_events = [event for event in events if _event_field(event, "event_type") == "stage"]
    if not stage_events:
        return None
    return stage_events[-1]


def _event_field(event: TaskEvent | dict[str, Any], key: str) -> Any:
    if isinstance(event, dict):
        return event.get(key)
    return getattr(event, key)


def _event_created_at(event: TaskEvent | dict[str, Any]) -> datetime | None:
    return _ensure_datetime(_event_field(event, "created_at"))


def _json_safe_value(value: Any) -> Any:
    if isinstance(value, datetime):
        current = _ensure_datetime(value)
        return current.isoformat() if current is not None else None
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _json_safe_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return [_json_safe_value(item) for item in value]
    if isinstance(value, set):
        return [_json_safe_value(item) for item in sorted(value, key=str)]
    return value


def build_fallback_events(task: TaskRun) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = [
        {
            "id": f"{task.id}-queued",
            "task_run_id": task.id,
            "task_type": task.task_type.value,
            "status": task.status.value,
            "event_type": "queued",
            "level": "info",
            "stage_code": None,
            "stage_name": None,
            "message": "任务已入队",
            "progress": 0,
            "payload_json": {},
            "created_at": task.created_at,
        }
    ]

    if task.started_at is not None:
        events.append(
            {
                "id": f"{task.id}-started",
                "task_run_id": task.id,
                "task_type": task.task_type.value,
                "status": task.status.value,
                "event_type": "started",
                "level": "info",
                "stage_code": None,
                "stage_name": None,
                "message": "任务开始执行",
                "progress": task.progress,
                "payload_json": {},
                "created_at": task.started_at,
            }
        )

    if task.status in TERMINAL_TASK_STATUSES and task.finished_at is not None:
        terminal_message = "任务完成"
        terminal_level = "info"
        terminal_payload = task.result_json
        if task.status == TaskExecutionStatus.FAILURE:
            terminal_message = "任务失败"
            terminal_level = "error"
            terminal_payload = task.error_json
        elif task.status == TaskExecutionStatus.CANCELED:
            terminal_message = "任务已中断"
            terminal_level = "warning"
        events.append(
            {
                "id": f"{task.id}-{task.status.value}",
                "task_run_id": task.id,
                "task_type": task.task_type.value,
                "status": task.status.value,
                "event_type": task.status.value,
                "level": terminal_level,
                "stage_code": None,
                "stage_name": None,
                "message": task.message or terminal_message,
                "progress": task.progress,
                "payload_json": terminal_payload,
                "created_at": task.finished_at,
            }
        )
    elif task.message:
        events.append(
            {
                "id": f"{task.id}-current",
                "task_run_id": task.id,
                "task_type": task.task_type.value,
                "status": task.status.value,
                "event_type": "retry" if task.status == TaskExecutionStatus.RETRY else ("started" if task.started_at is not None else "queued"),
                "level": "warning" if task.status == TaskExecutionStatus.RETRY else "info",
                "stage_code": None,
                "stage_name": task.message,
                "message": task.message,
                "progress": task.progress,
                "payload_json": task.result_json or {},
                "created_at": task.updated_at or task.created_at,
            }
        )
    return events


def serialize_task_event(event: TaskEvent | dict[str, Any], task: TaskRun | None = None) -> dict[str, Any]:
    event_task = task if task is not None else (None if isinstance(event, dict) else event.task_run)
    return {
        "id": _event_field(event, "id"),
        "task_run_id": _event_field(event, "task_run_id"),
        "task_type": _json_safe_value(
            _event_field(event, "task_type")
            if isinstance(event, dict)
            else (event_task.task_type.value if event_task is not None else None)
        ),
        "status": _json_safe_value(
            _event_field(event, "status")
            if isinstance(event, dict)
            else (event_task.status.value if event_task is not None else None)
        ),
        "event_type": _event_field(event, "event_type"),
        "level": _event_field(event, "level"),
        "stage_code": _event_field(event, "stage_code"),
        "stage_name": _event_field(event, "stage_name"),
        "message": _event_field(event, "message"),
        "progress": _event_field(event, "progress"),
        "payload_json": _json_safe_value(_event_field(event, "payload_json") or {}),
        "created_at": _json_safe_value(_event_created_at(event)),
    }


def build_task_timing(
    task: TaskRun,
    events: list[TaskEvent | dict[str, Any]] | None = None,
    *,
    now: datetime | None = None,
    has_event_logs: bool | None = None,
) -> dict[str, Any]:
    current = _ensure_datetime(now) or _now()
    terminal_end = _ensure_datetime(task.finished_at) or (
        current if task.status in ACTIVE_TASK_STATUSES else _ensure_datetime(task.updated_at)
    )
    effective_run_end = terminal_end if task.started_at is not None else None
    queue_end = _ensure_datetime(task.started_at) or terminal_end

    latest_stage = _latest_stage_event(events or [])
    current_stage_name = None
    current_stage_code = None
    current_stage_duration_ms = None
    if latest_stage is not None:
        current_stage_code = _event_field(latest_stage, "stage_code")
        current_stage_name = _event_field(latest_stage, "stage_name")
        current_stage_duration_ms = _duration_ms(_event_created_at(latest_stage), terminal_end)
    elif task.status in ACTIVE_TASK_STATUSES and task.message:
        current_stage_name = task.message
        current_stage_duration_ms = _duration_ms(_ensure_datetime(task.started_at), terminal_end)

    return {
        "queue_duration_ms": _duration_ms(_ensure_datetime(task.created_at), queue_end),
        "run_duration_ms": _duration_ms(_ensure_datetime(task.started_at), effective_run_end),
        "total_duration_ms": _duration_ms(_ensure_datetime(task.created_at), terminal_end),
        "current_stage_code": current_stage_code,
        "current_stage_name": current_stage_name,
        "current_stage_duration_ms": current_stage_duration_ms,
        "has_event_logs": bool(events) if has_event_logs is None else has_event_logs,
    }


def build_stage_timings(
    task: TaskRun,
    events: list[TaskEvent | dict[str, Any]] | None,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if not events:
        return []
    current = _ensure_datetime(now) or _now()
    stage_events = [event for event in events if _event_field(event, "event_type") == "stage"]
    if not stage_events:
        return []

    stages: list[dict[str, Any]] = []
    for index, event in enumerate(stage_events):
        started_at = _event_created_at(event)
        next_started_at = _event_created_at(stage_events[index + 1]) if index + 1 < len(stage_events) else None
        if next_started_at is not None:
            finished_at = next_started_at
        elif task.status in TERMINAL_TASK_STATUSES and task.finished_at is not None:
            finished_at = _ensure_datetime(task.finished_at)
        elif task.status in ACTIVE_TASK_STATUSES:
            finished_at = current
        else:
            finished_at = _ensure_datetime(task.updated_at)
        stages.append(
            {
                "stage_code": _event_field(event, "stage_code"),
                "stage_name": _event_field(event, "stage_name") or _event_field(event, "message"),
                "started_at": _json_safe_value(started_at),
                "finished_at": _json_safe_value(finished_at),
                "duration_ms": _duration_ms(started_at, finished_at),
            }
        )
    return stages


def serialize_task_run(
    task: TaskRun,
    *,
    events: list[TaskEvent] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    active_events: list[TaskEvent | dict[str, Any]] = list(events or [])
    timing_events = active_events
    if not timing_events:
        timing_events = build_fallback_events(task)
    return {
        "id": task.id,
        "task_type": _json_safe_value(task.task_type),
        "status": _json_safe_value(task.status),
        "scope_type": task.scope_type,
        "scope_id": task.scope_id,
        "celery_task_id": task.celery_task_id,
        "execution_boundary": task.execution_boundary,
        "runner_asset_id": task.runner_asset_id,
        "scanner_zone_id": task.scanner_zone_id,
        "progress": task.progress,
        "message": task.message,
        "retry_count": task.retry_count,
        "result_json": _json_safe_value(task.result_json or {}),
        "error_json": _json_safe_value(task.error_json or {}),
        "created_at": _json_safe_value(task.created_at),
        "started_at": _json_safe_value(task.started_at),
        "finished_at": _json_safe_value(task.finished_at),
        "updated_at": _json_safe_value(task.updated_at),
        "timing": build_task_timing(task, timing_events, now=now, has_event_logs=bool(active_events)),
    }


def serialize_task_detail(
    task: TaskRun,
    *,
    events: list[TaskEvent] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    stored_events: list[TaskEvent | dict[str, Any]] = list(events or [])
    detail_events = stored_events or build_fallback_events(task)
    detail = serialize_task_run(task, events=events, now=now)
    detail["stage_timings"] = build_stage_timings(task, detail_events, now=now)
    detail["event_count"] = len(detail_events)
    last_event = detail_events[-1] if detail_events else None
    detail["last_event_at"] = _json_safe_value(_event_created_at(last_event)) if last_event is not None else None
    return detail
