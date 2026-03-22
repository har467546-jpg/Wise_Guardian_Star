from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.tasks.risk_tasks import execute_risk_evaluation
from app.tasks.task_runtime import (
    TaskCanceledError,
    ensure_task_not_canceled,
    log_task_warning,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)


@celery_app.task(
    bind=True,
    name="app.tasks.verify_tasks.run_risk_verify_task",
    max_retries=3,
)
def run_risk_verify_task(self: Task, task_run_id: str, asset_id: str) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            progress_stages = {
                10: ("load_context", "载入上下文"),
                35: ("passive_match", "被动匹配"),
                70: ("active_check", "主动探测"),
                90: ("persist_result", "结果落盘"),
            }
            summary = execute_risk_evaluation(
                asset_id,
                progress_callback=lambda progress, message, result: set_task_progress(
                    task_run_id,
                    progress,
                    message,
                    result,
                    stage_code=progress_stages.get(progress, (None, None))[0],
                    stage_name=progress_stages.get(progress, (None, None))[1],
                ),
            )
            ensure_task_not_canceled(task_run_id)
            if summary.get("active_error_count", 0) or summary.get("active_inconclusive_count", 0):
                log_task_warning(
                    "主动探测存在异常或待确认结果",
                    stage_code="active_check",
                    stage_name="主动探测",
                    payload_json={
                        "asset_id": asset_id,
                        "active_error_count": summary.get("active_error_count", 0),
                        "active_inconclusive_count": summary.get("active_inconclusive_count", 0),
                        "active_skipped_count": summary.get("active_skipped_count", 0),
                    },
                )
            set_task_success(task_run_id, "风险验证任务完成", summary)
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        set_task_failure(task_run_id, self.request.retries, str(exc))
        raise
    return task_run_id
