from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.core.celery_app import celery_app
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.user import User
from app.repositories.task_event_repo import list_task_events, list_task_events_for_task, list_task_events_for_runs
from app.repositories.task_repo import cancel_task_run, clear_task_runs, get_task_run, list_task_runs
from app.repositories.task_repo import delete_task_runs_by_ids, find_task_runs_for_clear
from app.schemas.common import PageMeta
from app.schemas.task import (
    TaskEventListResponse,
    TaskEventRead,
    TaskRunClearResponse,
    TaskRunDetailRead,
    TaskRunListResponse,
    TaskRunRead,
    TaskRunResponse,
)
from app.services.task_observability_service import serialize_task_detail, serialize_task_event, serialize_task_run
from app.services.task_reconciliation_service import reconcile_stale_active_tasks

router = APIRouter()


@router.get("/events", response_model=TaskEventListResponse)
def get_task_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    level: str | None = Query(default=None),
    task_id: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskEventListResponse:
    reconcile_stale_active_tasks(db)
    items, total = list_task_events(
        db,
        page=page,
        page_size=page_size,
        task_type=task_type,
        status=status,
        level=level,
        task_id=task_id,
        keyword=keyword,
    )
    return TaskEventListResponse(
        items=[TaskEventRead.model_validate(serialize_task_event(item)) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("", response_model=TaskRunListResponse)
def get_task_list(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskRunListResponse:
    reconcile_stale_active_tasks(db)
    items, total = list_task_runs(db, page=page, page_size=page_size, task_type=task_type, status=status)
    event_map = list_task_events_for_runs(db, [item.id for item in items])
    return TaskRunListResponse(
        items=[TaskRunRead.model_validate(serialize_task_run(item, events=event_map.get(item.id, []))) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/{task_id}/events", response_model=TaskEventListResponse)
def get_task_event_list(
    task_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    level: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskEventListResponse:
    reconcile_stale_active_tasks(db)
    task = get_task_run(db, task_id)
    if not task:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="任务不存在")
    items, total = list_task_events_for_task(db, task_run_id=task_id, page=page, page_size=page_size, level=level)
    return TaskEventListResponse(
        items=[TaskEventRead.model_validate(serialize_task_event(item, task=task)) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/{task_id}", response_model=TaskRunDetailRead)
def get_task_status(
    task_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskRunDetailRead:
    reconcile_stale_active_tasks(db)
    task = get_task_run(db, task_id)
    if not task:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="任务不存在")
    events = list_task_events_for_runs(db, [task_id]).get(task_id, [])
    return TaskRunDetailRead.model_validate(serialize_task_detail(task, events=events))


@router.post("/{task_id}/cancel", response_model=TaskRunResponse)
def cancel_task(
    task_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskRunResponse:
    task = get_task_run(db, task_id)
    if not task:
        raise HTTPException(status_code=http_status.HTTP_404_NOT_FOUND, detail="任务不存在")
    if task.status == TaskExecutionStatus.CANCELED:
        return TaskRunResponse(task_id=task.id, status=task.status)
    if task.status not in {
        TaskExecutionStatus.PENDING,
        TaskExecutionStatus.RUNNING,
        TaskExecutionStatus.RETRY,
    }:
        raise HTTPException(status_code=http_status.HTTP_409_CONFLICT, detail="任务当前状态不支持中断")

    if task.celery_task_id:
        try:
            celery_app.control.revoke(
                task.celery_task_id,
                terminate=task.status in {TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY},
                signal="SIGTERM",
            )
        except Exception as exc:
            raise HTTPException(
                status_code=http_status.HTTP_502_BAD_GATEWAY,
                detail=f"任务中断请求下发失败: {exc}",
            ) from exc

    cancel_task_run(
        db,
        task,
        message="任务已中断",
        payload_json={
            "source": "api",
            "celery_task_id": task.celery_task_id,
        },
    )
    return TaskRunResponse(task_id=task.id, status=task.status)


@router.delete("", response_model=TaskRunClearResponse)
def clear_tasks(
    task_type: TaskType | None = None,
    status: TaskExecutionStatus | None = None,
    include_active: bool = Query(default=False),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskRunClearResponse:
    if include_active:
        matched_tasks = find_task_runs_for_clear(db, task_type=task_type, status=status, include_active=True)
        active_tasks = [
            task
            for task in matched_tasks
            if task.status in {TaskExecutionStatus.PENDING, TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY}
        ]
        revoke_errors: list[str] = []
        for task in active_tasks:
            if not task.celery_task_id:
                continue
            try:
                celery_app.control.revoke(
                    task.celery_task_id,
                    terminate=task.status in {TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY},
                    signal="SIGTERM",
                )
            except Exception as exc:
                revoke_errors.append(f"{task.id}: {exc}")
        if revoke_errors:
            raise HTTPException(
                status_code=http_status.HTTP_502_BAD_GATEWAY,
                detail=f"任务清理前中断失败: {'; '.join(revoke_errors[:5])}",
            )
        for task in active_tasks:
            cancel_task_run(
                db,
                task,
                message="任务已中断并清理",
                payload_json={"source": "api-clear", "celery_task_id": task.celery_task_id},
            )
        deleted = delete_task_runs_by_ids(db, [task.id for task in matched_tasks])
    else:
        deleted = clear_task_runs(db, task_type=task_type, status=status, include_active=False)
    return TaskRunClearResponse(deleted=deleted)
