from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.repositories.discovery_repo import create_job, get_active_job_by_cidr
from app.repositories.task_repo import create_task_run, get_latest_task_run_for_scope, get_task_run, update_task_run
from app.services.remediation_session_service import approve_remediation_session, create_or_resume_remediation_session
from app.services.runner_service import queue_runner_install
from app.tasks.runner_tasks import run_runner_install_task
from app.tasks.scan_tasks import run_asset_scan_task
from app.tasks.verify_tasks import run_risk_verify_task
from app.utils.net import normalize_cidr
from app.utils.sanitize import sanitize_text


@dataclass(frozen=True, slots=True)
class AgentExecutionResult:
    status: str
    summary: str
    child_task_id: str | None = None
    payload: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AgentActionExecutorContext:
    db: Session
    session_user_id: str
    platform_url: str
    get_manual_credential: Callable[[Session, str], Any]


def _queue_discovery_job(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    cidr = sanitize_text(str(params.get("cidr") or ""), max_length=64, single_line=True) or ""
    label = sanitize_text(str(params.get("label") or ""), max_length=255)
    if not cidr:
        raise RuntimeError("扫描计划缺少 CIDR")
    try:
        cidr = normalize_cidr(cidr)
    except ValueError as exc:
        raise RuntimeError(f"扫描计划中的 CIDR 不合法：{cidr}") from exc
    active_job = get_active_job_by_cidr(db, cidr)
    if active_job is None:
        job = create_job(db=db, cidr=cidr, label=label, created_by=context.session_user_id)
    else:
        job = active_job
    existing_task = get_latest_task_run_for_scope(
        db,
        scope_type="discovery_job",
        scope_id=job.id,
        task_type=TaskType.ASSET_SCAN,
        statuses=[TaskExecutionStatus.PENDING, TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY],
    )
    if existing_task is not None:
        return AgentExecutionResult(
            status="queued",
            summary=f"已复用扫描任务 {existing_task.id}",
            child_task_id=existing_task.id,
            payload={"job_id": job.id, "task_id": existing_task.id, "reused": True},
        )
    task_run = create_task_run(
        db,
        task_type=TaskType.ASSET_SCAN,
        scope_type="discovery_job",
        scope_id=job.id,
        message="扫描任务已入队",
    )
    celery_task = run_asset_scan_task.delay(task_run.id, job.id)
    update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已创建扫描任务 {task_run.id}",
        child_task_id=task_run.id,
        payload={"job_id": job.id, "task_id": task_run.id, "reused": False},
    )


def _queue_risk_verify(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = sanitize_text(str(params.get("asset_id") or ""), max_length=64, single_line=True) or ""
    if not asset_id:
        raise RuntimeError("风险验证计划缺少 asset_id")
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    task_run = create_task_run(
        db,
        task_type=TaskType.RISK_VERIFY,
        scope_type="asset",
        scope_id=asset_id,
        message="风险验证任务已入队",
    )
    celery_task = run_risk_verify_task.delay(task_run.id, asset_id)
    update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已触发资产 {asset_id} 的风险验证",
        child_task_id=task_run.id,
        payload={"asset_id": asset_id, "task_id": task_run.id},
    )


def _queue_runner_install(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = sanitize_text(str(params.get("asset_id") or ""), max_length=64, single_line=True) or ""
    if not asset_id:
        raise RuntimeError("Runner 安装计划缺少 asset_id")
    if not str(context.platform_url or "").strip():
        raise RuntimeError("Runner 安装计划缺少平台地址")
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    credential = context.get_manual_credential(db, asset_id)
    host_runner, task_id, registration_token = queue_runner_install(
        db,
        asset=asset,
        credential=credential,
        platform_url=context.platform_url,
    )
    celery_task = run_runner_install_task.delay(task_id, asset_id, context.platform_url, registration_token)
    task_run = get_task_run(db, task_id)
    if task_run is not None:
        update_task_run(db, task_run, celery_task_id=celery_task.id)
    return AgentExecutionResult(
        status="queued",
        summary=f"已提交 Host Runner 安装任务 {task_id}",
        child_task_id=task_id,
        payload={"asset_id": asset_id, "task_id": task_id, "runner_id": host_runner.id},
    )


def _create_or_resume_remediation(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    asset_id = sanitize_text(str(params.get("asset_id") or ""), max_length=64, single_line=True) or ""
    if not asset_id:
        raise RuntimeError("修复会话计划缺少 asset_id")
    session = create_or_resume_remediation_session(db, asset_id=asset_id)
    return AgentExecutionResult(
        status="success",
        summary=f"已准备主机修复会话 {session.session_id}",
        payload={"asset_id": asset_id, "session_id": session.session_id},
    )


def _approve_remediation(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    session_id = sanitize_text(str(params.get("session_id") or ""), max_length=64, single_line=True) or ""
    if not session_id:
        raise RuntimeError("修复批准计划缺少 session_id")
    response = approve_remediation_session(db, session_id=session_id, approved_by="haor")
    return AgentExecutionResult(
        status="queued",
        summary=f"已批准修复会话 {session_id}",
        child_task_id=response.task_id,
        payload={"session_id": session_id, "task_id": response.task_id},
    )


ACTION_EXECUTORS: dict[str, Callable[[AgentActionExecutorContext, dict[str, Any]], AgentExecutionResult]] = {
    "create_discovery_job": lambda context, action: _queue_discovery_job(context, action=action),
    "verify_asset_risks": lambda context, action: _queue_risk_verify(context, action=action),
    "install_runner": lambda context, action: _queue_runner_install(context, action=action),
    "create_or_resume_remediation_session": lambda context, action: _create_or_resume_remediation(context, action=action),
    "approve_remediation_session": lambda context, action: _approve_remediation(context, action=action),
}


def execute_registered_action(
    context: AgentActionExecutorContext,
    *,
    action: dict[str, Any],
    supported_action_types: set[str] | None = None,
) -> AgentExecutionResult:
    action_type = str(action.get("action_type") or "").strip()
    if supported_action_types is not None and action_type not in supported_action_types:
        raise RuntimeError("计划中存在不受支持的动作类型")
    executor = ACTION_EXECUTORS.get(action_type)
    if executor is None:
        raise RuntimeError("不支持的动作类型")
    return executor(context, action)
