from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.tasks.collection_tasks import run_collection_for_asset, run_collection_for_assets_batch
from app.tasks.task_runtime import (
    TaskCanceledError,
    ensure_task_not_canceled,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)


@celery_app.task(
    bind=True,
    name="app.tasks.collect_tasks.run_asset_collect_task",
    max_retries=3,
)
def run_asset_collect_task(
    self: Task,
    task_run_id: str,
    asset_id: str,
    credential_id: str | None = None,
    connect_timeout_seconds: int | None = None,
    command_timeout_seconds: int | None = None,
    asset_timeout_seconds: int | None = None,
) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 10, "开始 SSH 授权深度检查", {"asset_id": asset_id}, stage_code="verify_authorization", stage_name="授权验证")
            result = run_collection_for_asset(
                asset_id=asset_id,
                credential_id=credential_id,
                connect_timeout_seconds=connect_timeout_seconds,
                command_timeout_seconds=command_timeout_seconds,
                asset_timeout_seconds=asset_timeout_seconds,
            )
            ensure_task_not_canceled(task_run_id)
            set_task_success(task_run_id, "SSH 授权深度检查完成", result)
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        set_task_failure(task_run_id, self.request.retries, str(exc))
        raise
    return task_run_id


@celery_app.task(
    bind=True,
    name="app.tasks.collect_tasks.run_batch_collect_task",
    max_retries=3,
)
def run_batch_collect_task(
    self: Task,
    task_run_id: str,
    asset_ids: list[str],
    credential_id: str | None = None,
    concurrency: int = 20,
    connect_timeout_seconds: int | None = None,
    command_timeout_seconds: int | None = None,
    asset_timeout_seconds: int | None = None,
) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 10, "开始批量 SSH 授权深度检查", {"asset_count": len(asset_ids)}, stage_code="verify_authorization", stage_name="授权验证")
            result = run_collection_for_assets_batch(
                asset_ids=asset_ids,
                credential_id=credential_id,
                concurrency=concurrency,
                connect_timeout_seconds=connect_timeout_seconds,
                command_timeout_seconds=command_timeout_seconds,
                asset_timeout_seconds=asset_timeout_seconds,
            )
            ensure_task_not_canceled(task_run_id)
            set_task_success(task_run_id, "批量 SSH 授权深度检查完成", result)
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        set_task_failure(task_run_id, self.request.retries, str(exc))
        raise
    return task_run_id
