from datetime import datetime, timedelta, timezone

from sqlalchemy import Select, and_, delete, func, select, text
from sqlalchemy.orm import Session

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_run import TaskRun
from app.repositories.task_event_repo import create_task_event
from app.utils.sanitize import sanitize_json_value, sanitize_text


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


def _ensure_task_status_enum_value(
    db: Session,
    status: TaskExecutionStatus,
    *,
    task_id: str | None = None,
) -> TaskRun | None:
    bind = getattr(db, "bind", None)
    if bind is None or bind.dialect.name != "postgresql":
        return None
    with bind.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text(f"ALTER TYPE taskexecutionstatus ADD VALUE IF NOT EXISTS '{status.name}'"))
    rollback = getattr(db, "rollback", None)
    if callable(rollback):
        rollback()
    if task_id:
        return get_task_run(db, task_id)
    return None


def _ensure_task_type_enum_value(
    db: Session,
    task_type: TaskType,
) -> None:
    bind = getattr(db, "bind", None)
    if bind is None or bind.dialect.name != "postgresql":
        return
    with bind.connect() as conn:
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text(f"ALTER TYPE tasktype ADD VALUE IF NOT EXISTS '{task_type.name}'"))
    rollback = getattr(db, "rollback", None)
    if callable(rollback):
        rollback()


def create_task_run(
    db: Session,
    task_type: TaskType,
    scope_type: str | None = None,
    scope_id: str | None = None,
    message: str | None = None,
) -> TaskRun:
    normalized_message = sanitize_text(message, max_length=255, single_line=True)
    _ensure_task_type_enum_value(db, task_type)
    task = TaskRun(
        task_type=task_type,
        scope_type=scope_type,
        scope_id=scope_id,
        message=normalized_message,
    )
    db.add(task)
    db.flush()
    create_task_event(
        db,
        task_run_id=task.id,
        event_type="queued",
        level="info",
        message=normalized_message or "任务已入队",
        progress=task.progress,
    )
    db.commit()
    db.refresh(task)
    return task


def get_task_run(db: Session, task_id: str) -> TaskRun | None:
    return db.get(TaskRun, task_id)


def get_latest_task_run_for_scope(
    db: Session,
    *,
    scope_type: str,
    scope_id: str,
    task_type: TaskType | None = None,
    statuses: list[TaskExecutionStatus] | None = None,
) -> TaskRun | None:
    if task_type is not None:
        _ensure_task_type_enum_value(db, task_type)
    stmt = select(TaskRun).where(TaskRun.scope_type == scope_type, TaskRun.scope_id == scope_id)
    if task_type is not None:
        stmt = stmt.where(TaskRun.task_type == task_type)
    if statuses:
        stmt = stmt.where(TaskRun.status.in_(statuses))
    stmt = stmt.order_by(TaskRun.created_at.desc())
    return db.scalar(stmt)


def list_task_runs(
    db: Session,
    page: int,
    page_size: int,
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
) -> tuple[list[TaskRun], int]:
    if task_type is not None:
        _ensure_task_type_enum_value(db, task_type)
    stmt: Select[tuple[TaskRun]] = select(TaskRun)
    count_stmt = select(func.count(TaskRun.id))

    filters = []
    if task_type is not None:
        filters.append(TaskRun.task_type == task_type)
    if status is not None:
        filters.append(TaskRun.status == status)
    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = db.scalar(count_stmt) or 0
    items = db.scalars(
        stmt.order_by(TaskRun.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return items, total


def mark_stale_active_task_runs(
    db: Session,
    *,
    stale_after_hours: int,
    message: str = "任务执行状态已过期，已自动标记失败",
) -> int:
    stale_hours = max(1, int(stale_after_hours or 1))
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=stale_hours)
    stmt = (
        select(TaskRun)
        .where(
            TaskRun.status.in_(list(ACTIVE_TASK_STATUSES)),
            TaskRun.updated_at < cutoff,
        )
        .order_by(TaskRun.updated_at.asc(), TaskRun.created_at.asc())
    )
    tasks = db.scalars(stmt).all()
    if not tasks:
        return 0

    for task in tasks:
        original_status = getattr(task.status, "value", task.status)
        original_updated_at = task.updated_at
        update_task_run(
            db,
            task,
            status=TaskExecutionStatus.FAILURE,
            message=message,
            error_json={
                "reason": "stale_active_task",
                "stale_after_hours": stale_hours,
                "previous_status": str(original_status),
                "stale_cutoff": cutoff.isoformat(),
            },
            commit=False,
            refresh=False,
        )
        create_task_event(
            db,
            task_run_id=task.id,
            event_type="failure",
            level="error",
            message=message,
            progress=task.progress,
            payload_json={
                "reason": "stale_active_task",
                "stale_after_hours": stale_hours,
                "previous_status": str(original_status),
                "last_updated_at": original_updated_at.isoformat() if original_updated_at else None,
            },
        )
    db.commit()
    return len(tasks)


def clear_task_runs(
    db: Session,
    *,
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    include_active: bool = False,
) -> int:
    if task_type is not None:
        _ensure_task_type_enum_value(db, task_type)
    filters = []
    if task_type is not None:
        filters.append(TaskRun.task_type == task_type)

    if status is not None:
        filters.append(TaskRun.status == status)
    elif not include_active:
        filters.append(TaskRun.status.in_(list(TERMINAL_TASK_STATUSES)))

    stmt = delete(TaskRun)
    if filters:
        stmt = stmt.where(and_(*filters))

    result = db.execute(stmt)
    db.commit()
    return int(result.rowcount or 0)


def find_task_runs_for_clear(
    db: Session,
    *,
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    include_active: bool = False,
) -> list[TaskRun]:
    if task_type is not None:
        _ensure_task_type_enum_value(db, task_type)
    stmt: Select[tuple[TaskRun]] = select(TaskRun)
    filters = []
    if task_type is not None:
        filters.append(TaskRun.task_type == task_type)
    if status is not None:
        filters.append(TaskRun.status == status)
    elif not include_active:
        filters.append(TaskRun.status.in_(list(TERMINAL_TASK_STATUSES)))
    if filters:
        stmt = stmt.where(and_(*filters))
    return db.scalars(stmt).all()


def delete_task_runs_by_ids(db: Session, task_ids: list[str]) -> int:
    ids = [str(task_id).strip() for task_id in task_ids if str(task_id).strip()]
    if not ids:
        return 0
    result = db.execute(delete(TaskRun).where(TaskRun.id.in_(ids)))
    db.commit()
    return int(result.rowcount or 0)


def update_task_run(
    db: Session,
    task: TaskRun,
    *,
    status: TaskExecutionStatus | None = None,
    progress: int | None = None,
    message: str | None = None,
    retry_count: int | None = None,
    celery_task_id: str | None = None,
    execution_boundary: str | None = None,
    runner_asset_id: str | None = None,
    scanner_zone_id: str | None = None,
    result_json: dict | None = None,
    error_json: dict | None = None,
    commit: bool = True,
    refresh: bool = True,
) -> TaskRun:
    now = datetime.now(timezone.utc)
    if status is not None:
        if status == TaskExecutionStatus.CANCELED:
            refreshed_task = _ensure_task_status_enum_value(db, status, task_id=task.id)
            if refreshed_task is not None:
                task = refreshed_task
        task.status = status
        if status == TaskExecutionStatus.RUNNING and task.started_at is None:
            task.started_at = now
        if status in TERMINAL_TASK_STATUSES:
            task.finished_at = now
    if progress is not None:
        task.progress = max(0, min(100, progress))
    if message is not None:
        task.message = sanitize_text(message, max_length=255, single_line=True)
    if retry_count is not None:
        task.retry_count = retry_count
    if celery_task_id is not None:
        task.celery_task_id = celery_task_id
    if execution_boundary is not None:
        task.execution_boundary = sanitize_text(execution_boundary, max_length=32, single_line=True)
    if runner_asset_id is not None:
        task.runner_asset_id = sanitize_text(runner_asset_id, max_length=36, single_line=True)
    if scanner_zone_id is not None:
        task.scanner_zone_id = sanitize_text(scanner_zone_id, max_length=36, single_line=True)
    if result_json is not None:
        task.result_json = sanitize_json_value(result_json)
    if error_json is not None:
        task.error_json = sanitize_json_value(error_json)
    task.updated_at = now
    db.add(task)
    if commit:
        db.commit()
    if refresh:
        db.refresh(task)
    return task


def cancel_task_run(
    db: Session,
    task: TaskRun,
    *,
    message: str = "任务已中断",
    payload_json: dict | None = None,
) -> TaskRun:
    update_task_run(
        db,
        task,
        status=TaskExecutionStatus.CANCELED,
        message=message,
        commit=False,
        refresh=False,
    )
    create_task_event(
        db,
        task_run_id=task.id,
        event_type="canceled",
        level="warning",
        message=message,
        progress=task.progress,
        payload_json=payload_json or {},
    )
    db.commit()
    db.refresh(task)
    return task
