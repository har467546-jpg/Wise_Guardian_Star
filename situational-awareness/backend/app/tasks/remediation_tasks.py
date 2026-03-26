from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.repositories.task_repo import get_task_run
from app.services.remediation_executor import run_remediation_execution
from app.services.remediation_session_service import process_remediation_session_ai_generation
from app.tasks.task_runtime import (
    TaskCanceledError,
    ensure_task_not_canceled,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)
from app.db.models.risk_finding import RiskFinding


def _current_task_result(task_run_id: str) -> dict:
    with SessionLocal() as db:
        task = get_task_run(db, task_run_id)
        return dict(task.result_json or {}) if task and isinstance(task.result_json, dict) else {}


@celery_app.task(
    bind=True,
    name="app.tasks.remediation_tasks.run_remediation_execute_task",
    max_retries=1,
)
def run_remediation_execute_task(
    self: Task,
    task_run_id: str,
    finding_id: str,
    plan: dict,
    submitted_steps: list[dict],
    execution_options: dict | None = None,
) -> str:
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 10, "载入修复上下文", _current_task_result(task_run_id), stage_code="load_workspace_context", stage_name="载入上下文")
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 20, "渲染执行计划", _current_task_result(task_run_id), stage_code="render_execution_plan", stage_name="计划渲染")
            set_task_progress(task_run_id, 30, "验证 SSH 管理员授权", _current_task_result(task_run_id), stage_code="verify_ssh_authorization", stage_name="SSH 授权验证")
            set_task_progress(task_run_id, 40, "准备备份与执行环境", _current_task_result(task_run_id), stage_code="prepare_backups", stage_name="备份准备")
            set_task_progress(task_run_id, 55, "开始执行修复步骤", _current_task_result(task_run_id), stage_code="execute_steps", stage_name="执行步骤")
            with SessionLocal() as db:
                finding = db.get(RiskFinding, finding_id)
                if finding is None:
                    raise RuntimeError("风险发现不存在")
                result = run_remediation_execution(
                    db,
                    task_run_id=task_run_id,
                    finding=finding,
                    plan=plan,
                    submitted_steps=submitted_steps,
                    execution_options=execution_options,
                )
            ensure_task_not_canceled(task_run_id)
            set_task_progress(task_run_id, 85, "执行结果校验完成", result, stage_code="post_validate", stage_name="结果校验")
            set_task_progress(task_run_id, 92, "自动风险复测已处理", result, stage_code="auto_reverify", stage_name="自动复测")
            set_task_progress(task_run_id, 97, "修复结果正在落盘", result, stage_code="persist_result", stage_name="结果落盘")
            ensure_task_not_canceled(task_run_id)
            execution = result.get("execution") if isinstance(result, dict) and isinstance(result.get("execution"), dict) else {}
            final_message = str(execution.get("final_message") or "交互式漏洞修复完成").strip()
            if str(execution.get("overall_status") or "").strip() == "apply_failed":
                set_task_failure(task_run_id, self.request.retries, final_message)
                return task_run_id
            set_task_success(task_run_id, final_message, result)
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=3)
        set_task_failure(task_run_id, self.request.retries, str(exc))
        raise
    return task_run_id


@celery_app.task(
    name="app.tasks.remediation_tasks.run_remediation_session_ai_task",
    max_retries=0,
)
def run_remediation_session_ai_task(
    session_id: str,
    reason: str | None = None,
    force: bool = False,
) -> str:
    with SessionLocal() as db:
        process_remediation_session_ai_generation(
            db,
            session_id=session_id,
            reason=reason,
            force=force,
        )
    return session_id
