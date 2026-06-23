from __future__ import annotations

from datetime import datetime

from sqlalchemy import Select, and_, func, or_, select
from sqlalchemy.orm import Session

from app.db.models.audit_log_entry import AuditLogEntry


def list_audit_log_entries(
    db: Session,
    *,
    page: int,
    page_size: int,
    actor_user_id: str | None = None,
    method: str | None = None,
    path: str | None = None,
    action: str | None = None,
    resource_type: str | None = None,
    outcome: str | None = None,
    status_code: int | None = None,
    keyword: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> tuple[list[AuditLogEntry], int]:
    stmt: Select[tuple[AuditLogEntry]] = select(AuditLogEntry)
    count_stmt = select(func.count(AuditLogEntry.id))
    filters = []

    if actor_user_id:
        filters.append(AuditLogEntry.actor_user_id == actor_user_id.strip())
    if method:
        filters.append(AuditLogEntry.method == method.strip().upper())
    if path:
        filters.append(AuditLogEntry.path.ilike(f"%{path.strip()}%"))
    if action:
        filters.append(AuditLogEntry.action == action.strip())
    if resource_type:
        filters.append(AuditLogEntry.resource_type == resource_type.strip())
    if outcome:
        filters.append(AuditLogEntry.outcome == outcome.strip())
    if status_code is not None:
        filters.append(AuditLogEntry.status_code == status_code)
    if created_from is not None:
        filters.append(AuditLogEntry.created_at >= created_from)
    if created_to is not None:
        filters.append(AuditLogEntry.created_at <= created_to)
    if keyword:
        like_value = f"%{keyword.strip()}%"
        filters.append(
            or_(
                AuditLogEntry.request_id.ilike(like_value),
                AuditLogEntry.actor_user_id.ilike(like_value),
                AuditLogEntry.client_ip.ilike(like_value),
                AuditLogEntry.path.ilike(like_value),
                AuditLogEntry.action.ilike(like_value),
                AuditLogEntry.resource_type.ilike(like_value),
                AuditLogEntry.resource_id.ilike(like_value),
                AuditLogEntry.error_message.ilike(like_value),
            )
        )

    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return items, total

