from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import Select, and_, delete, func, or_, select
from sqlalchemy.orm import Session

from app.db.models.platform_log_entry import PlatformLogEntry


def list_platform_log_entries(
    db: Session,
    *,
    page: int,
    page_size: int,
    source_kind: str | None = None,
    service_name: str | None = None,
    task_id: str | None = None,
    task_type: str | None = None,
    level: str | None = None,
    keyword: str | None = None,
) -> tuple[list[PlatformLogEntry], int]:
    stmt: Select[tuple[PlatformLogEntry]] = select(PlatformLogEntry)
    count_stmt = select(func.count(PlatformLogEntry.id))

    filters = []
    if source_kind:
        filters.append(PlatformLogEntry.source_kind == source_kind)
    if service_name:
        filters.append(PlatformLogEntry.service_name == service_name)
    if task_id:
        filters.append(PlatformLogEntry.task_run_id == task_id.strip())
    if task_type:
        filters.append(PlatformLogEntry.task_type == task_type)
    if level:
        filters.append(PlatformLogEntry.level == level)
    if keyword:
        like_value = f"%{keyword.strip()}%"
        filters.append(
            or_(
                PlatformLogEntry.message.ilike(like_value),
                PlatformLogEntry.logger_name.ilike(like_value),
                PlatformLogEntry.task_run_id.ilike(like_value),
                PlatformLogEntry.stage_code.ilike(like_value),
                PlatformLogEntry.stage_name.ilike(like_value),
                PlatformLogEntry.event_type.ilike(like_value),
            )
        )
    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(PlatformLogEntry.created_at.desc(), PlatformLogEntry.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return items, total


def delete_platform_log_entries_older_than(db: Session, *, cutoff: datetime) -> int:
    result = db.execute(delete(PlatformLogEntry).where(PlatformLogEntry.created_at < cutoff))
    db.commit()
    return int(result.rowcount or 0)


def list_platform_log_entries_by_ids(db: Session, entry_ids: Sequence[str]) -> list[PlatformLogEntry]:
    normalized_ids = [str(item).strip() for item in entry_ids if str(item).strip()]
    if not normalized_ids:
        return []
    return db.scalars(
        select(PlatformLogEntry)
        .where(PlatformLogEntry.id.in_(normalized_ids))
        .order_by(PlatformLogEntry.created_at.desc(), PlatformLogEntry.id.desc())
    ).all()
