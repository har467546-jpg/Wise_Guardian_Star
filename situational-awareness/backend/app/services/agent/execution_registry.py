from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.remediation_session import RemediationSession
from app.db.models.user import User
from app.repositories.discovery_repo import create_job, get_active_job_by_cidr
from app.repositories.task_repo import create_task_run, get_latest_task_run_for_scope, get_task_run, update_task_run
from app.services.remediation_session_service import approve_remediation_session, create_or_resume_remediation_session
from app.services.runner_service import queue_runner_install
from app.tasks.runner_tasks import run_runner_install_task
from app.tasks.scan_tasks import run_asset_scan_task
from app.tasks.verify_tasks import run_risk_verify_task
from app.utils.net import normalize_cidr
from app.utils.sanitize import sanitize_json_value, sanitize_text

_APPROVE_REMEDIATION_BLOCKING_MESSAGES = {
    "当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行",
    "当前整机修复计划不可执行",
    "当前没有可执行阶段",
    "仅允许审批当前最早可执行阶段",
}


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
    session_user_role: str = "admin"


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _resolve_approved_by_user_id(context: AgentActionExecutorContext) -> str:
    approved_by = sanitize_text(str(context.session_user_id or ""), max_length=64, single_line=True) or ""
    if not approved_by:
        raise RuntimeError("审批人信息无效，请刷新页面后重试")
    if context.db.get(User, approved_by) is None:
        raise RuntimeError("审批人信息无效，请刷新页面后重试")
    return approved_by


def _infer_remediation_blocker_code(message: str | None) -> str:
    normalized = sanitize_text(message, max_length=280) or ""
    lowered = normalized.lower()
    if "maintenance_window_id" in lowered or "维护窗口" in normalized:
        return "maintenance_window_required"
    if ("ssh" in lowered and any(marker in normalized for marker in ("凭据", "私钥", "密码", "授权"))) or "未配置 ssh" in lowered:
        return "missing_ssh_credential"
    if "管理员授权" in normalized:
        return "authorization_unconfirmed"
    if "管理员权限验证" in normalized:
        return "authorization_not_verified"
    if "未验证到管理员权限" in normalized or "root/sudo" in lowered or "sudo 凭据" in normalized:
        return "insufficient_privilege"
    if "尚未安装" in normalized:
        return "runner_not_installed"
    if "正在安装中" in normalized:
        return "runner_installing"
    if "当前离线" in normalized:
        return "runner_offline"
    if "未识别到稳定的软件包管理器或包名" in normalized:
        return "unstable_render"
    if "未识别稳定的软件包管理器" in normalized or "未识别稳定的软件包名" in normalized:
        return "unstable_render"
    if "无法生成安全步骤" in normalized or "无法稳定渲染" in normalized:
        return "unstable_render"
    if "缺少自动修复适配器" in normalized:
        return "missing_adapter"
    if "未解析到" in normalized:
        return "missing_target"
    if "白名单" in normalized:
        return "action_not_allowed"
    if "snapshot" in lowered or "深度检查结果" in normalized:
        return "missing_snapshot"
    return "unknown_blocker"


def _categorize_remediation_blocker(*, code: str | None, message: str | None) -> str:
    normalized_code = sanitize_text(code, max_length=64, single_line=True) or ""
    normalized_message = sanitize_text(message, max_length=280) or ""
    lowered = normalized_message.lower()
    if normalized_code == "maintenance_window_required":
        return "policy"
    if normalized_code in {
        "missing_ssh_credential",
        "authorization_unconfirmed",
        "authorization_not_verified",
        "insufficient_privilege",
    }:
        return "ssh"
    if normalized_code in {"runner_not_installed", "runner_installing", "runner_offline"}:
        return "runner"
    if normalized_code in {"unstable_render", "missing_target", "missing_adapter"}:
        return "render"
    if "runner" in lowered:
        return "runner"
    if "未识别到稳定的软件包管理器或包名" in normalized_message:
        return "render"
    if "未识别稳定的软件包管理器" in normalized_message or "未识别稳定的软件包名" in normalized_message:
        return "render"
    if "无法生成安全步骤" in normalized_message or "无法稳定渲染" in normalized_message:
        return "render"
    if "ssh" in lowered or "sudo" in lowered:
        return "ssh"
    return "other"


def _build_blocked_remediation_approval_result(
    *,
    session_id: str,
    asset_id: str | None,
    error_message: str,
    execution_mode: str,
    stage_code: str | None,
    change_ticket: str | None,
    maintenance_window_id: str | None,
) -> AgentExecutionResult:
    blocker_code = _infer_remediation_blocker_code(error_message)
    blocker_category = _categorize_remediation_blocker(code=blocker_code, message=error_message)
    payload = {
        "session_id": session_id,
        "asset_id": asset_id,
        "execution_ready": False,
        "submitted_task_id": None,
        "blocked_reasons": [error_message],
        "blocker_codes": [blocker_code],
        "blocker_categories": [blocker_category],
        "blockers": [
            {
                "code": blocker_code,
                "message": error_message,
                "blocker_category": blocker_category,
                "scope": "stage",
                "blocking": "hard",
                "stage_code": stage_code,
                "step_id": None,
            }
        ],
        "execution_mode": execution_mode,
        "change_ticket": change_ticket,
        "maintenance_window_id": maintenance_window_id,
    }
    if blocker_code == "maintenance_window_required":
        summary = (
            f"修复会话 {session_id} 当前仍缺维护窗口。"
            f"阻塞原因：{error_message}。"
            "请先填写 maintenance_window_id 后再继续自动修复，或进入修复工作台查看详情。"
        )
    else:
        summary = (
            f"修复会话 {session_id} 当前仍缺前置条件。"
            f"阻塞原因：{error_message}。"
            "请先补齐条件后再继续自动修复，或进入修复工作台查看详情。"
        )
    return AgentExecutionResult(status="success", summary=summary, payload=payload)


def _serialize_remediation_blockers(plan: Any) -> tuple[list[str], list[dict[str, Any]], list[str]]:
    blockers: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for field_name in ("global_blockers", "step_blockers"):
        raw_items = getattr(plan, field_name, None)
        if not isinstance(raw_items, list):
            continue
        for item in raw_items:
            payload = item.model_dump(mode="json") if hasattr(item, "model_dump") else item if isinstance(item, dict) else {}
            if not isinstance(payload, dict):
                continue
            message = sanitize_text(
                str(payload.get("message") or payload.get("blocker_message") or ""),
                max_length=280,
            ) or ""
            if not message:
                continue
            code = sanitize_text(
                str(payload.get("code") or payload.get("blocker_code") or ""),
                max_length=64,
                single_line=True,
            ) or _infer_remediation_blocker_code(message)
            if code == "unknown_blocker":
                inferred_code = _infer_remediation_blocker_code(message)
                if inferred_code != "unknown_blocker":
                    code = inferred_code
            blocker = {
                "code": code or "unknown_blocker",
                "message": message,
                "blocker_category": _categorize_remediation_blocker(code=code, message=message),
                "scope": sanitize_text(str(payload.get("scope") or ""), max_length=64, single_line=True) or None,
                "blocking": sanitize_text(str(payload.get("blocking") or ""), max_length=32, single_line=True) or None,
                "stage_code": sanitize_text(str(payload.get("stage_code") or ""), max_length=64, single_line=True) or None,
                "step_id": sanitize_text(str(payload.get("step_id") or ""), max_length=64, single_line=True) or None,
            }
            signature = (
                blocker["code"] or "",
                blocker["message"] or "",
                blocker["scope"] or "",
                blocker["blocking"] or "",
                blocker["stage_code"] or "",
                blocker["step_id"] or "",
            )
            if signature in seen:
                continue
            seen.add(signature)
            blockers.append(blocker)

    if not blockers:
        blocked_reasons = getattr(plan, "blocked_reasons", None)
        if isinstance(blocked_reasons, list):
            for raw_message in blocked_reasons:
                message = sanitize_text(str(raw_message or ""), max_length=280) or ""
                if not message:
                    continue
                code = _infer_remediation_blocker_code(message)
                signature = (code, message, "", "", "", "")
                if signature in seen:
                    continue
                seen.add(signature)
                blockers.append(
                    {
                        "code": code,
                        "message": message,
                        "blocker_category": _categorize_remediation_blocker(code=code, message=message),
                        "scope": None,
                        "blocking": None,
                        "stage_code": None,
                        "step_id": None,
                    }
                )

    blocker_codes: list[str] = []
    blocker_categories: list[str] = []
    for item in blockers:
        code = sanitize_text(str(item.get("code") or ""), max_length=64, single_line=True) or ""
        if code and code not in blocker_codes:
            blocker_codes.append(code)
        category = sanitize_text(str(item.get("blocker_category") or ""), max_length=32, single_line=True) or ""
        if category and category not in blocker_categories:
            blocker_categories.append(category)
    return blocker_codes, sanitize_json_value(blockers), blocker_categories


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
    submit_if_ready = _coerce_bool(params.get("submit_if_ready"))
    stage_code = sanitize_text(str(params.get("stage_code") or ""), max_length=64, single_line=True) or None
    execution_mode = sanitize_text(str(params.get("execution_mode") or "apply"), max_length=32, single_line=True) or "apply"
    change_ticket = sanitize_text(str(params.get("change_ticket") or ""), max_length=128, single_line=True) or None
    maintenance_window_id = sanitize_text(
        str(params.get("maintenance_window_id") or ""),
        max_length=128,
        single_line=True,
    ) or None
    if not asset_id:
        raise RuntimeError("修复会话计划缺少 asset_id")
    session = create_or_resume_remediation_session(db, asset_id=asset_id)
    blocked_reasons = list(session.plan.blocked_reasons or [])
    blocker_codes, blockers, blocker_categories = _serialize_remediation_blockers(session.plan)
    payload = {
        "asset_id": asset_id,
        "session_id": session.session_id,
        "execution_ready": bool(session.plan.execution_ready),
        "blocked_reasons": blocked_reasons,
        "blocker_codes": blocker_codes,
        "blocker_categories": blocker_categories,
        "blockers": blockers,
        "submitted_task_id": None,
    }
    if submit_if_ready and session.plan.execution_ready:
        approved_by = _resolve_approved_by_user_id(context)
        try:
            response = approve_remediation_session(
                db,
                session_id=session.session_id,
                approved_by=approved_by,
                stage_code=stage_code,
                execution_mode=execution_mode,
                change_ticket=change_ticket,
                maintenance_window_id=maintenance_window_id,
            )
        except RuntimeError as exc:
            error_message = sanitize_text(str(exc), max_length=280) or "当前修复审批仍缺前置条件"
            if error_message in _APPROVE_REMEDIATION_BLOCKING_MESSAGES:
                return _build_blocked_remediation_approval_result(
                    session_id=session.session_id,
                    asset_id=asset_id,
                    error_message=error_message,
                    execution_mode=execution_mode,
                    stage_code=stage_code,
                    change_ticket=change_ticket,
                    maintenance_window_id=maintenance_window_id,
                )
            raise
        payload["submitted_task_id"] = response.task_id
        payload["stage_code"] = stage_code
        payload["execution_mode"] = execution_mode
        payload["change_ticket"] = change_ticket
        payload["maintenance_window_id"] = maintenance_window_id
        return AgentExecutionResult(
            status="queued",
            summary=f"已准备修复会话 {session.session_id}，并直接提交自动修复任务 {response.task_id}",
            child_task_id=response.task_id,
            payload=payload,
        )

    if submit_if_ready:
        blocked_summary = "；".join(blocked_reasons) if blocked_reasons else "当前整机修复计划不可执行"
        return AgentExecutionResult(
            status="success",
            summary=(
                f"已准备修复会话 {session.session_id}，但当前未自动执行。"
                f"阻塞原因：{blocked_summary}。"
                "请先补齐前置条件后再继续自动修复，或进入修复工作台查看详情。"
            ),
            payload=payload,
        )

    return AgentExecutionResult(
        status="success",
        summary=f"已准备主机修复会话 {session.session_id}",
        payload=payload,
    )


def _approve_remediation(context: AgentActionExecutorContext, *, action: dict[str, Any]) -> AgentExecutionResult:
    db = context.db
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    session_id = sanitize_text(str(params.get("session_id") or ""), max_length=64, single_line=True) or ""
    if not session_id:
        raise RuntimeError("修复批准计划缺少 session_id")
    remediation_session = db.get(RemediationSession, session_id)
    asset_id = sanitize_text(
        str(getattr(remediation_session, "asset_id", "") or ""),
        max_length=64,
        single_line=True,
    ) or None
    approved_by = _resolve_approved_by_user_id(context)
    stage_code = sanitize_text(str(params.get("stage_code") or ""), max_length=64, single_line=True) or None
    execution_mode = sanitize_text(str(params.get("execution_mode") or "apply"), max_length=32, single_line=True) or "apply"
    change_ticket = sanitize_text(str(params.get("change_ticket") or ""), max_length=128, single_line=True) or None
    maintenance_window_id = sanitize_text(
        str(params.get("maintenance_window_id") or ""),
        max_length=128,
        single_line=True,
    ) or None
    try:
        response = approve_remediation_session(
            db,
            session_id=session_id,
            approved_by=approved_by,
            stage_code=stage_code,
            execution_mode=execution_mode,
            change_ticket=change_ticket,
            maintenance_window_id=maintenance_window_id,
        )
    except RuntimeError as exc:
        error_message = sanitize_text(str(exc), max_length=280) or "当前修复审批仍缺前置条件"
        if error_message in _APPROVE_REMEDIATION_BLOCKING_MESSAGES:
            return _build_blocked_remediation_approval_result(
                session_id=session_id,
                asset_id=asset_id,
                error_message=error_message,
                execution_mode=execution_mode,
                stage_code=stage_code,
                change_ticket=change_ticket,
                maintenance_window_id=maintenance_window_id,
            )
        raise
    return AgentExecutionResult(
        status="queued",
        summary=f"已批准修复会话 {session_id}",
        child_task_id=response.task_id,
        payload={
            "session_id": session_id,
            "asset_id": asset_id,
            "task_id": response.task_id,
            "stage_code": stage_code,
            "execution_mode": execution_mode,
            "change_ticket": change_ticket,
            "maintenance_window_id": maintenance_window_id,
        },
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
