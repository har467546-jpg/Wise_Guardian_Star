from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Generator

from app.db.models.enums import TaskExecutionStatus
from app.db.models.task_run import TaskRun
from app.db.session import SessionLocal
from app.repositories.task_event_repo import create_task_event
from app.repositories.task_repo import get_task_run, update_task_run
from app.services.agent.async_state import serialize_celery_payload

_CURRENT_TASK_RUN_ID: ContextVar[str | None] = ContextVar("current_task_run_id", default=None)
_IMMUTABLE_TASK_STATUSES = {
    TaskExecutionStatus.SUCCESS,
    TaskExecutionStatus.FAILURE,
    TaskExecutionStatus.CANCELED,
}


class TaskCanceledError(Exception):
    pass


def get_current_task_run_id() -> str | None:
    return _CURRENT_TASK_RUN_ID.get()


def _is_task_immutable(task: TaskRun | None) -> bool:
    return bool(task and task.status in _IMMUTABLE_TASK_STATUSES)


def ensure_task_not_canceled(task_run_id: str) -> None:
    with SessionLocal() as db:
        task = get_task_run(db, task_run_id)
        if task and task.status == TaskExecutionStatus.CANCELED:
            raise TaskCanceledError("任务已中断")


@contextmanager
def _task_context(task_run_id: str) -> Generator[None, None, None]:
    token = _CURRENT_TASK_RUN_ID.set(task_run_id)
    try:
        yield
    finally:
        _CURRENT_TASK_RUN_ID.reset(token)


def append_task_event(
    task_run_id: str,
    *,
    event_type: str,
    level: str = "info",
    stage_code: str | None = None,
    stage_name: str | None = None,
    message: str | None = None,
    progress: int | None = None,
    payload_json: dict | None = None,
) -> None:
    serialized_payload = serialize_celery_payload(payload_json or {})
    with SessionLocal() as db:
        task = get_task_run(db, task_run_id)
        if task is None:
            return
        if task.status == TaskExecutionStatus.CANCELED and event_type != "canceled":
            return
        create_task_event(
            db,
            task_run_id=task_run_id,
            event_type=event_type,
            level=level,
            stage_code=stage_code,
            stage_name=stage_name,
            message=message,
            progress=progress,
            payload_json=serialized_payload if isinstance(serialized_payload, dict) else {},
        )
        db.commit()


def append_current_task_event(
    *,
    event_type: str,
    level: str = "info",
    stage_code: str | None = None,
    stage_name: str | None = None,
    message: str | None = None,
    progress: int | None = None,
    payload_json: dict | None = None,
) -> None:
    task_run_id = get_current_task_run_id()
    if not task_run_id:
        return
    append_task_event(
        task_run_id,
        event_type=event_type,
        level=level,
        stage_code=stage_code,
        stage_name=stage_name,
        message=message,
        progress=progress,
        payload_json=payload_json,
    )


def log_task_warning(
    message: str,
    *,
    stage_code: str | None = None,
    stage_name: str | None = None,
    progress: int | None = None,
    payload_json: dict | None = None,
) -> None:
    append_current_task_event(
        event_type="warning",
        level="warning",
        stage_code=stage_code,
        stage_name=stage_name,
        message=message,
        progress=progress,
        payload_json=payload_json,
    )


@contextmanager
def tracked_task(task_run_id: str, celery_task_id: str | None = None, retry_count: int = 0) -> Generator[TaskRun, None, None]:
    with _task_context(task_run_id):
        with SessionLocal() as db:
            task = get_task_run(db, task_run_id)
            if task:
                if task.status == TaskExecutionStatus.CANCELED:
                    raise TaskCanceledError("任务已中断")
                update_task_run(
                    db,
                    task,
                    status=TaskExecutionStatus.RUNNING,
                    retry_count=retry_count,
                    celery_task_id=celery_task_id,
                )
                create_task_event(
                    db,
                    task_run_id=task_run_id,
                    event_type="started",
                    level="info",
                    message="任务开始执行",
                    progress=task.progress,
                )
                db.commit()
        yield TaskRun(id=task_run_id)


def set_task_progress(
    task_run_id: str,
    progress: int,
    message: str,
    result_json: dict | None = None,
    *,
    stage_code: str | None = None,
    stage_name: str | None = None,
) -> None:
    with _task_context(task_run_id):
        with SessionLocal() as db:
            task = get_task_run(db, task_run_id)
            if task and task.status == TaskExecutionStatus.CANCELED:
                raise TaskCanceledError("任务已中断")
            if task and not _is_task_immutable(task):
                serialized_result = serialize_celery_payload(result_json if result_json is not None else task.result_json)
                serialized_result_json = serialized_result if isinstance(serialized_result, dict) else {}
                update_task_run(
                    db,
                    task,
                    status=TaskExecutionStatus.RUNNING,
                    progress=progress,
                    message=message,
                    result_json=serialized_result_json,
                )
                create_task_event(
                    db,
                    task_run_id=task_run_id,
                    event_type="stage",
                    level="info",
                    stage_code=stage_code,
                    stage_name=stage_name or message,
                    message=message,
                    progress=progress,
                    payload_json=serialized_result_json,
                )
                db.commit()


def set_task_success(task_run_id: str, message: str, result_json: dict | None = None) -> None:
    with _task_context(task_run_id):
        with SessionLocal() as db:
            task = get_task_run(db, task_run_id)
            if task and task.status == TaskExecutionStatus.CANCELED:
                raise TaskCanceledError("任务已中断")
            if task and not _is_task_immutable(task):
                serialized_result = serialize_celery_payload(result_json if result_json is not None else task.result_json)
                serialized_result_json = serialized_result if isinstance(serialized_result, dict) else {}
                update_task_run(
                    db,
                    task,
                    status=TaskExecutionStatus.SUCCESS,
                    progress=100,
                    message=message,
                    result_json=serialized_result_json,
                )
                create_task_event(
                    db,
                    task_run_id=task_run_id,
                    event_type="success",
                    level="info",
                    message=message,
                    progress=100,
                    payload_json=serialized_result_json,
                )
                db.commit()


def set_task_retry(task_run_id: str, retry_count: int, message: str) -> None:
    with _task_context(task_run_id):
        with SessionLocal() as db:
            task = get_task_run(db, task_run_id)
            if task and not _is_task_immutable(task):
                error_json = serialize_celery_payload({"error": message})
                error_payload = error_json if isinstance(error_json, dict) else {"error": ""}
                update_task_run(
                    db,
                    task,
                    status=TaskExecutionStatus.RETRY,
                    message=message,
                    retry_count=retry_count,
                    error_json=error_payload,
                )
                create_task_event(
                    db,
                    task_run_id=task_run_id,
                    event_type="retry",
                    level="warning",
                    message=message,
                    progress=task.progress,
                    payload_json=error_payload,
                )
                db.commit()


def set_task_failure(task_run_id: str, retry_count: int, message: str) -> None:
    with _task_context(task_run_id):
        with SessionLocal() as db:
            task = get_task_run(db, task_run_id)
            if task and not _is_task_immutable(task):
                error_json = serialize_celery_payload({"error": message})
                error_payload = error_json if isinstance(error_json, dict) else {"error": ""}
                update_task_run(
                    db,
                    task,
                    status=TaskExecutionStatus.FAILURE,
                    progress=100,
                    message=message,
                    retry_count=retry_count,
                    error_json=error_payload,
                )
                create_task_event(
                    db,
                    task_run_id=task_run_id,
                    event_type="failure",
                    level="error",
                    message=message,
                    progress=100,
                    payload_json=error_payload,
                )
                db.commit()
