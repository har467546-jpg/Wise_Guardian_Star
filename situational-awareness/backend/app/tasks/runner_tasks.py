from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.services.runner_service import record_runner_install_canceled, record_runner_install_failure, run_runner_install
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
    name="app.tasks.runner_tasks.run_runner_install_task",
    max_retries=1,
)
def run_runner_install_task(
    self: Task,
    task_run_id: str,
    asset_id: str,
    platform_url: str,
    registration_token: str,
) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                10,
                "校验 SSH 管理员权限",
                {"asset_id": asset_id},
                stage_code="verify_runner_install_context",
                stage_name="校验上下文",
            )
            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                25,
                "准备 Runner 安装包",
                {"asset_id": asset_id, "platform_url": platform_url},
                stage_code="prepare_runner_bundle",
                stage_name="准备安装包",
            )
            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                45,
                "通过 SSH 上传并安装 Host Runner",
                {"asset_id": asset_id},
                stage_code="upload_and_install_runner",
                stage_name="上传并安装",
            )
            with SessionLocal() as db:
                result = run_runner_install(
                    db,
                    task_run_id=task_run_id,
                    asset_id=asset_id,
                    platform_url=platform_url,
                    registration_token=registration_token,
                )
            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                85,
                "等待 Host Runner 回连平台注册",
                result,
                stage_code="wait_runner_register",
                stage_name="等待注册",
            )
            ensure_task_not_canceled(task_run_id)
            set_task_success(task_run_id, "Host Runner 安装完成", result)
    except TaskCanceledError:
        with SessionLocal() as db:
            record_runner_install_canceled(db, asset_id=asset_id)
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=3)
        set_task_failure(task_run_id, self.request.retries, str(exc))
        with SessionLocal() as db:
            record_runner_install_failure(db, asset_id=asset_id, message=str(exc))
        raise
    return task_run_id
