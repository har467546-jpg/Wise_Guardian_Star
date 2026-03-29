from __future__ import annotations

from celery import Task

from app.core.celery_app import celery_app
from app.db.models.asset import Asset
from app.db.session import SessionLocal
from app.repositories.task_repo import get_task_run
from app.services.remediation_business_service import (
    BUSINESS_STATUS_VERIFIED_FAILED,
    build_business_status_message,
    build_reverify_failure_summary,
    build_reverify_outcome,
    finalize_remediation_business_outcome,
    run_inline_collection,
    run_inline_rescan,
)
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
from app.tasks.risk_tasks import execute_risk_evaluation
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
        failure_message = str(exc).strip() or "交互式漏洞修复失败"
        set_task_failure(task_run_id, self.request.retries, failure_message)
        raise
    return task_run_id


@celery_app.task(
    bind=True,
    name="app.tasks.remediation_tasks.run_remediation_reverify_task",
    max_retries=0,
)
def run_remediation_reverify_task(
    self: Task,
    task_run_id: str,
    remediation_task_id: str,
    asset_id: str,
    followup_payload: dict | None = None,
) -> str:
    payload = followup_payload if isinstance(followup_payload, dict) else {}
    stage_name = str(payload.get("stage_name") or "").strip() or None
    scan_summary: dict | None = None
    collection_summary: dict | None = None
    verification_summary: dict | None = None
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                8,
                "载入修复后业务复验上下文",
                {
                    "asset_id": asset_id,
                    "remediation_task_id": remediation_task_id,
                    "stage_code": payload.get("stage_code"),
                },
                stage_code="load_reverify_context",
                stage_name="载入上下文",
            )
            with SessionLocal() as db:
                asset = db.get(Asset, asset_id)
                if asset is None:
                    raise RuntimeError("资产不存在")
                asset_label = f"{asset.hostname or asset.ip}"

            if bool(payload.get("requires_rescan")):
                ensure_task_not_canceled(task_run_id)
                set_task_progress(
                    task_run_id,
                    28,
                    "执行修复后重扫",
                    {"asset_id": asset_id, "asset_label": asset_label},
                    stage_code="rescan_after_remediation",
                    stage_name="修复后重扫",
                )
                scan_summary = run_inline_rescan(asset)
                if scan_summary.get("status") != "success":
                    raise RuntimeError(str(scan_summary.get("error") or "修复后重扫失败"))

            if bool(payload.get("requires_recollect")):
                ensure_task_not_canceled(task_run_id)
                set_task_progress(
                    task_run_id,
                    56,
                    "执行修复后重采集",
                    {"asset_id": asset_id, "asset_label": asset_label},
                    stage_code="recollect_after_remediation",
                    stage_name="修复后重采集",
                )
                collection_summary = run_inline_collection(asset_id)
                if collection_summary.get("status") not in {"success", "partial"}:
                    raise RuntimeError(str(collection_summary.get("error") or "修复后重采集失败"))

            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                82,
                "重新验证目标风险",
                {"asset_id": asset_id, "asset_label": asset_label},
                stage_code="reverify_targeted_findings",
                stage_name="目标风险复验",
            )
            verification_summary = execute_risk_evaluation(asset_id)
            with SessionLocal() as db:
                business_status, reverify_summary, targeted_finding_outcomes = build_reverify_outcome(
                    db,
                    asset_id=asset_id,
                    followup_payload=payload,
                    scan_summary=scan_summary,
                    collection_summary=collection_summary,
                    verification_summary=verification_summary,
                )
                final_message = build_business_status_message(business_status, stage_name=stage_name)
                finalize_remediation_business_outcome(
                    db,
                    remediation_task_id=remediation_task_id,
                    reverify_task_id=task_run_id,
                    business_status=business_status,
                    reverify_status="success",
                    reverify_summary=reverify_summary,
                    targeted_finding_outcomes=targeted_finding_outcomes,
                    message=final_message,
                )
            set_task_success(
                task_run_id,
                final_message,
                {
                    "asset_id": asset_id,
                    "remediation_task_id": remediation_task_id,
                    "business_status": business_status,
                    "reverify_summary": reverify_summary,
                    "targeted_finding_outcomes": targeted_finding_outcomes,
                },
            )
    except TaskCanceledError:
        return task_run_id
    except Exception as exc:
        failure_message = build_business_status_message(BUSINESS_STATUS_VERIFIED_FAILED, stage_name=stage_name)
        with SessionLocal() as db:
            finalize_remediation_business_outcome(
                db,
                remediation_task_id=remediation_task_id,
                reverify_task_id=task_run_id,
                business_status=BUSINESS_STATUS_VERIFIED_FAILED,
                reverify_status="failure",
                reverify_summary=build_reverify_failure_summary(
                    followup_payload=payload,
                    error_message=str(exc),
                    scan_summary=scan_summary,
                    collection_summary=collection_summary,
                    verification_summary=verification_summary,
                ),
                targeted_finding_outcomes=[],
                message=failure_message,
            )
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
