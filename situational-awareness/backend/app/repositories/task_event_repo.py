from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import logging

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_event import TaskEvent
from app.db.models.task_run import TaskRun
from app.services.platform_log_service import mirror_task_event_to_platform_logs
from app.utils.sanitize import sanitize_json_value, sanitize_text

logger = logging.getLogger(__name__)


def create_task_event(
    db: Session,
    *,
    task_run_id: str,
    event_type: str,
    level: str = "info",
    stage_code: str | None = None,
    stage_name: str | None = None,
    message: str | None = None,
    progress: int | None = None,
    payload_json: dict | None = None,
    created_at: datetime | None = None,
) -> TaskEvent:
    event = TaskEvent(
        task_run_id=task_run_id,
        event_type=event_type,
        level=level,
        stage_code=sanitize_text(stage_code, max_length=64, single_line=True),
        stage_name=sanitize_text(stage_name, max_length=128, single_line=True),
        message=sanitize_text(message, max_length=255, single_line=True),
        progress=progress,
        payload_json=sanitize_json_value(payload_json or {}),
        created_at=created_at or datetime.now(timezone.utc),
    )
    db.add(event)
    try:
        mirror_task_event_to_platform_logs(
            db,
            task_run_id=task_run_id,
            event_type=event_type,
            level=level,
            stage_code=event.stage_code,
            stage_name=event.stage_name,
            message=event.message,
            payload_json=event.payload_json,
            created_at=event.created_at,
        )
    except Exception as exc:  # pragma: no cover - log mirroring must never block task events
        logger.warning("Failed to mirror task event %s to platform logs: %s", event_type, exc)
    return event


def list_task_events_for_task(
    db: Session,
    *,
    task_run_id: str,
    page: int,
    page_size: int,
    level: str | None = None,
) -> tuple[list[TaskEvent], int]:
    stmt: Select[tuple[TaskEvent]] = (
        select(TaskEvent)
        .options(joinedload(TaskEvent.task_run))
        .where(TaskEvent.task_run_id == task_run_id)
    )
    count_stmt = select(func.count(TaskEvent.id)).where(TaskEvent.task_run_id == task_run_id)

    if level is not None:
        stmt = stmt.where(TaskEvent.level == level)
        count_stmt = count_stmt.where(TaskEvent.level == level)

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(TaskEvent.created_at.asc(), TaskEvent.id.asc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return items, total


def list_task_events(
    db: Session,
    *,
    page: int,
    page_size: int,
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    level: str | None = None,
    task_id: str | None = None,
    keyword: str | None = None,
) -> tuple[list[TaskEvent], int]:
    if task_type is not None:
        from app.repositories.task_repo import _ensure_task_type_enum_value

        _ensure_task_type_enum_value(db, task_type)
    stmt: Select[tuple[TaskEvent]] = select(TaskEvent).join(TaskRun).options(joinedload(TaskEvent.task_run))
    count_stmt = select(func.count(TaskEvent.id)).select_from(TaskEvent).join(TaskRun)

    filters = []
    if task_type is not None:
        filters.append(TaskRun.task_type == task_type)
    if status is not None:
        filters.append(TaskRun.status == status)
    if level is not None:
        filters.append(TaskEvent.level == level)
    if task_id:
        filters.append(TaskEvent.task_run_id == task_id)
    if keyword:
        like_value = f"%{keyword.strip()}%"
        filters.append(
            or_(
                TaskEvent.message.ilike(like_value),
                TaskEvent.stage_name.ilike(like_value),
                TaskEvent.stage_code.ilike(like_value),
                TaskEvent.task_run_id.ilike(like_value),
            )
        )
    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(TaskEvent.created_at.desc(), TaskEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return items, total


def list_task_events_for_runs(db: Session, task_run_ids: list[str]) -> dict[str, list[TaskEvent]]:
    if not task_run_ids:
        return {}
    rows = db.scalars(
        select(TaskEvent)
        .options(joinedload(TaskEvent.task_run))
        .where(TaskEvent.task_run_id.in_(task_run_ids))
        .order_by(TaskEvent.created_at.asc(), TaskEvent.id.asc())
    ).all()
    grouped: dict[str, list[TaskEvent]] = defaultdict(list)
    for row in rows:
        grouped[row.task_run_id].append(row)
    return grouped
