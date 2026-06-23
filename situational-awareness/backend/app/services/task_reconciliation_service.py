from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.config import settings
from app.repositories.task_repo import mark_stale_active_task_runs


def reconcile_stale_active_tasks(db: Session) -> int:
    return mark_stale_active_task_runs(
        db,
        stale_after_hours=settings.TASK_ACTIVE_STALE_AFTER_HOURS,
    )
