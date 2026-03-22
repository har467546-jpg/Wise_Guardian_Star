from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.host_runner import HostRunner
from app.db.models.remediation_message import RemediationMessage
from app.db.models.remediation_session import RemediationSession
from app.db.models.task_run import TaskRun
from app.repositories.task_event_repo import create_task_event
from app.repositories.task_repo import create_task_run, update_task_run
from app.schemas.remediation import (
    HostRemediationRelatedFindingRead,
    HostRemediationPhaseRead,
    HostRemediationPlanRead,
    HostRemediationPlanStepRead,
    HostRemediationStageRead,
    RemediationAssetDetailRead,
    RemediationBlockerRead,
    RemediationMessageRead,
    RemediationSessionApproveResponse,
    RemediationSessionCreateRequest,
    RemediationSessionFindingRead,
    RemediationSessionMessageActionRead,
    RemediationSessionMessageCreateRequest,
    RemediationSessionRead,
)
from app.services.remediation_service import (
    _compute_blocked_reasons,
    build_asset_plans,
    build_workspace,
    get_latest_collection_snapshot,
    get_manual_credential,
    select_executable_plan_steps,
)
from app.services.remediation_ai_explanation_service import (
    RemediationAIExplanationService,
)
from app.services.runner_service import (
    resolve_runner_by_asset_for_read,
    runner_install_blocked_reasons,
    serialize_host_runner,
)


PHASE_DEFINITIONS = [
    ("precheck_backup", "预检与备份", 1, "执行前自动核对主机上下文，并为配置与权限调整创建备份。"),
    ("remove_exposure", "暴露面收敛", 2, "先收敛危险管理入口、远程暴露面和高危监听来源。"),
    ("config_hardening", "配置加固", 3, "再统一写回配置加固项，避免相同服务重复重载。"),
    ("package_upgrade", "软件升级", 4, "随后处理软件升级类修复，优先升级存在已知暴露的软件包。"),
    ("service_control", "服务控制", 5, "最后执行需要的 reload、restart 或 disable，以应用已落地改动。"),
    ("post_validate", "执行后校验与复测", 6, "执行完成后自动触发现有风险复测链路。"),
]
PHASE_METADATA = {code: {"name": name, "order": order, "summary": summary} for code, name, order, summary in PHASE_DEFINITIONS}
INTENT_LABELS = {
    "refresh_plan": "刷新整机计划",
    "summarize_risks": "重新概览风险",
    "explain_blockers": "解释阻塞原因",
    "refresh_ai": "重新生成 AI 解读",
    "note": "写入审计备注",
}
RUNNING_TASK_STATUSES = {
    TaskExecutionStatus.PENDING,
    TaskExecutionStatus.RUNNING,
    TaskExecutionStatus.RETRY,
}
TERMINAL_TASK_TO_SESSION_STATUS = {
    TaskExecutionStatus.SUCCESS: "completed",
    TaskExecutionStatus.FAILURE: "failed",
    TaskExecutionStatus.CANCELED: "canceled",
}
SESSION_PLAN_SCHEMA_VERSION = "2026-03-18-remediation-host-plan-v3"
AI_MESSAGE_TYPES = {"ai_plan_summary", "ai_blocker_analysis", "ai_task_failure"}
AI_GENERATION_RUNNING_STATUSES = {"queued", "running"}


def build_remediation_asset_detail(db: Session, asset_id: str) -> RemediationAssetDetailRead:
    workspace = build_workspace(db, asset_id)
    credential = get_manual_credential(db, asset_id)
    host_runner = resolve_runner_by_asset_for_read(db, asset_id)
    active_session = _latest_session(db, asset_id)
    latest_task = _latest_asset_task(db, asset_id)
    return RemediationAssetDetailRead(
        asset=workspace.asset,
        authorization=workspace.authorization,
        latest_collection=workspace.latest_collection,
        findings=[
            RemediationSessionFindingRead(
                finding_id=item.finding_id,
                rule_id=item.rule_id,
                title=item.title,
                severity=item.severity,
                status=item.status,
                service_name=item.service_name,
                detected_at=item.detected_at,
                has_template=item.has_template,
            )
            for item in workspace.findings
        ],
        runner=serialize_host_runner(asset_id, host_runner),
        active_session_id=active_session.id if active_session else None,
        active_session_status=active_session.status if active_session else None,
        latest_task_id=latest_task.id if latest_task else workspace.last_task_id,
        can_install_runner=not runner_install_blocked_reasons(credential),
        runner_install_blocked_reasons=runner_install_blocked_reasons(credential),
    )


def create_or_resume_remediation_session(
    db: Session,
    *,
    asset_id: str,
    payload: RemediationSessionCreateRequest | None = None,
) -> RemediationSessionRead:
    asset_detail = build_remediation_asset_detail(db, asset_id)
    runner_id = asset_detail.runner.runner_id
    session = _latest_session(db, asset_id)
    ai_reason: str | None = None
    queue_ai = False
    if session is None or session.status in {"completed", "failed", "canceled"}:
        session = RemediationSession(asset_id=asset_id, runner_id=runner_id, status="draft")
        db.add(session)
        db.flush()
        ai_reason = "initial"
    plan = _resolve_session_plan(db, session, asset_detail)
    _persist_session_snapshot(db, session, asset_detail, plan)
    _synchronize_session_runtime_state(db, session=session, plan=plan)
    if session.status in {"completed", "failed", "canceled"}:
        session = RemediationSession(asset_id=asset_id, runner_id=runner_id, status="draft")
        db.add(session)
        db.flush()
        plan = _resolve_session_plan(db, session, asset_detail)
        _persist_session_snapshot(db, session, asset_detail, plan)
        _synchronize_session_runtime_state(db, session=session, plan=plan)
        ai_reason = ai_reason or "initial"
    queue_ai = _mark_ai_generation_requested(
        db,
        session=session,
        asset_detail=asset_detail,
        plan=plan,
        reason=ai_reason,
        force=False,
    )
    if payload and (payload.note or "").strip():
        _append_conversation_turn(
            db,
            session=session,
            asset_detail=asset_detail,
            plan=plan,
            intent="note",
            note=payload.note,
        )
    db.commit()
    if queue_ai:
        _enqueue_ai_generation(session.id, reason=ai_reason, force=False)
    session = db.get(RemediationSession, session.id) or session
    return _serialize_session(db, session, asset_detail, plan)


def get_remediation_session_read(db: Session, session_id: str, *, queue_ai: bool = True) -> RemediationSessionRead:
    session = db.get(RemediationSession, session_id)
    if session is None:
        raise LookupError("修复会话不存在")
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    _persist_session_snapshot(db, session, asset_detail, plan)
    _synchronize_session_runtime_state(db, session=session, plan=plan)
    should_queue_ai = False
    if queue_ai:
        should_queue_ai = _mark_ai_generation_requested(
            db,
            session=session,
            asset_detail=asset_detail,
            plan=plan,
            reason=None,
            force=False,
        )
    db.commit()
    if should_queue_ai:
        _enqueue_ai_generation(session.id, reason=None, force=False)
    db.refresh(session)
    return _serialize_session(db, session, asset_detail, plan)


def get_remediation_session_snapshot_read(db: Session, session_id: str) -> RemediationSessionRead:
    session = db.get(RemediationSession, session_id)
    if session is None:
        raise LookupError("修复会话不存在")
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    return _serialize_session(db, session, asset_detail, plan)


def append_remediation_session_message(
    db: Session,
    *,
    session_id: str,
    payload: RemediationSessionMessageCreateRequest,
) -> RemediationSessionRead:
    session = db.get(RemediationSession, session_id)
    if session is None:
        raise LookupError("修复会话不存在")
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    _persist_session_snapshot(db, session, asset_detail, plan)
    _synchronize_session_runtime_state(db, session=session, plan=plan)
    intent_key = str(payload.intent or "refresh_plan").strip() or "refresh_plan"
    _append_conversation_turn(
        db,
        session=session,
        asset_detail=asset_detail,
        plan=plan,
        intent=intent_key,
        note=payload.note,
    )
    should_queue_ai = False
    if intent_key != "note":
        should_queue_ai = _mark_ai_generation_requested(
            db,
            session=session,
            asset_detail=asset_detail,
            plan=plan,
            reason=intent_key,
            force=True,
        )
    db.commit()
    if should_queue_ai:
        _enqueue_ai_generation(session.id, reason=intent_key, force=True)
    db.refresh(session)
    return _serialize_session(db, session, asset_detail, plan)


def approve_remediation_session(
    db: Session,
    *,
    session_id: str,
    approved_by: str,
    stage_code: str | None = None,
) -> RemediationSessionApproveResponse:
    session = db.get(RemediationSession, session_id)
    if session is None:
        raise LookupError("修复会话不存在")
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    if not plan.execution_ready:
        raise RuntimeError("；".join(plan.blocked_reasons) or "当前整机修复计划不可执行")
    requested_stage_code = str(stage_code or "").strip() or None
    approvable_stage = next((stage for stage in plan.stages if stage.gate_status == "ready"), None)
    if approvable_stage is None:
        raise RuntimeError("当前没有可执行阶段")
    if requested_stage_code and requested_stage_code != approvable_stage.stage_code:
        raise RuntimeError("仅允许审批当前最早可执行阶段")
    stage = approvable_stage
    ready_steps = [step.model_dump(mode="json") for step in select_executable_plan_steps(stage.steps)]
    task_run = create_task_run(
        db,
        task_type=TaskType.REMEDIATION_EXECUTE,
        scope_type="asset",
        scope_id=session.asset_id,
        message=f"Host Runner 阶段修复任务已入队：{stage.stage_name}",
    )
    summary_state = _summary_state(session)
    summary_state["running_stage_code"] = stage.stage_code
    session.summary_json = summary_state
    result_json = {
        "context": {
            "asset_id": session.asset_id,
            "session_id": session.id,
            "runner_id": session.runner_id,
            "stage_code": stage.stage_code,
            "stage_name": stage.stage_name,
        },
        "plan": plan.model_dump(mode="json"),
        "execution": {
            "submitted_steps": [{"step_id": item["step_id"]} for item in ready_steps],
            "execution_boundary": "runner_dispatch",
            "stage_code": stage.stage_code,
            "stage_name": stage.stage_name,
        },
        "backups": {},
        "reverify": {},
    }
    update_task_run(db, task_run, result_json=result_json)
    create_task_event(
        db,
        task_run_id=task_run.id,
        event_type="stage",
        level="info",
        stage_code=stage.stage_code,
        stage_name=stage.stage_name,
        message=f"阶段“{stage.stage_name}”已排队，等待 Host Runner 拉取执行",
        progress=5,
        payload_json={"session_id": session.id, "stage_code": stage.stage_code},
    )
    session.status = "running"
    session.approved_at = datetime.now(timezone.utc)
    session.approved_by = approved_by
    session.last_task_id = task_run.id
    _persist_session_snapshot(db, session, asset_detail, plan)
    _append_session_audit_message(
        db,
        session=session,
        event_code="task_submitted",
        task_id=task_run.id,
        status="running",
        content=f"已提交阶段“{stage.stage_name}”的修复任务，等待 Host Runner 拉取执行。",
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return RemediationSessionApproveResponse(
        session_id=session.id,
        task_id=task_run.id,
        status=task_run.status,
        stream_url=f"/api/v1/remediation/tasks/{task_run.id}/stream",
    )


def _append_conversation_turn(
    db: Session,
    *,
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
    plan: HostRemediationPlanRead,
    intent: str,
    note: str | None,
) -> None:
    intent_key = str(intent or "refresh_plan").strip() or "refresh_plan"
    label = INTENT_LABELS.get(intent_key, "刷新整机计划")
    normalized_note = str(note or "").strip() or None
    if intent_key == "note":
        if not normalized_note:
            return
        _append_session_message(
            db,
            session=session,
            role="user",
            message_type="note",
            content=normalized_note,
            payload_json={"intent": "note"},
        )
        return

    user_content = label if not normalized_note else f"{label}\n备注：{normalized_note}"
    _append_session_message(
        db,
        session=session,
        role="user",
        message_type="intent",
        content=user_content,
        payload_json={"intent": intent_key, "note": normalized_note},
    )


def _persist_session_snapshot(
    db: Session,
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
    plan: HostRemediationPlanRead,
) -> None:
    existing_summary = dict(session.summary_json or {}) if isinstance(session.summary_json, dict) else {}
    session.runner_id = asset_detail.runner.runner_id
    session.plan_json = plan.model_dump(mode="json")
    session.finding_snapshot_json = {
        "findings": [item.model_dump(mode="json") for item in asset_detail.findings],
        "latest_collection_at": asset_detail.latest_collection.collected_at if asset_detail.latest_collection else None,
        "authorization_admin_authorized": asset_detail.authorization.admin_authorized,
        "authorization_verification_status": asset_detail.authorization.last_verification_status,
        "authorization_effective_privilege": asset_detail.authorization.effective_privilege,
        "runner_status": asset_detail.runner.status,
        "runner_install_status": asset_detail.runner.install_status,
        "runner_install_mode": asset_detail.runner.install_mode,
        "runner_service_mode": asset_detail.runner.service_mode,
        "stage_progress_signature": _stage_progress_signature(session),
        "planner_version": SESSION_PLAN_SCHEMA_VERSION,
    }
    session.summary_json = {
        **existing_summary,
        "summary_text": plan.summary_text,
        "findings_covered_count": plan.findings_covered_count,
        "service_count": plan.service_count,
        "plan_mode": plan.plan_mode,
        "current_stage_code": plan.current_stage_code,
        "ready_stage_count": plan.ready_stage_count,
        "blocked_stage_count": plan.blocked_stage_count,
        "ready_step_count": plan.ready_step_count,
        "blocked_step_count": plan.blocked_step_count,
        "runner_status": asset_detail.runner.status,
        "runner_install_status": asset_detail.runner.install_status,
        "planner_version": SESSION_PLAN_SCHEMA_VERSION,
    }
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)


def _append_session_audit_message(
    db: Session,
    *,
    session: RemediationSession,
    event_code: str,
    content: str,
    task_id: str | None = None,
    status: str | None = None,
) -> None:
    normalized_task_id = str(task_id or "").strip() or None
    normalized_status = str(status or "").strip() or None
    for item in reversed(session.messages):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if str(payload.get("event_code") or "") != event_code:
            continue
        if normalized_task_id and str(payload.get("task_id") or "") != normalized_task_id:
            continue
        if normalized_status and str(payload.get("status") or "") != normalized_status:
            continue
        return
    _append_session_message(
        db,
        session=session,
        role="assistant",
        message_type="audit",
        content=content,
        payload_json={
            "event_code": event_code,
            "task_id": normalized_task_id,
            "status": normalized_status,
        },
    )


def _append_session_message(
    db: Session,
    *,
    session: RemediationSession,
    role: str,
    message_type: str,
    content: str,
    payload_json: dict[str, Any] | None = None,
) -> None:
    message = RemediationMessage(
        session_id=session.id,
        role=role,
        message_type=message_type,
        content=content,
        payload_json=payload_json or {},
    )
    session.messages.append(message)
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
    db.add(message)


def _mark_ai_generation_requested(
    db: Session,
    *,
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
    plan: HostRemediationPlanRead,
    reason: str | None = None,
    force: bool = False,
) -> bool:
    _prune_legacy_summary_messages(db, session=session)
    provider_mode = RemediationAIExplanationService().provider_mode()
    needs = _collect_ai_generation_needs(
        db,
        session=session,
        plan=plan,
        provider_mode=provider_mode,
        reason=reason,
        force=force,
    )
    summary_state = _summary_state(session)
    if not needs:
        summary_state.update(
            ai_generation_status="idle",
            pending_ai_reason=None,
            pending_ai_digest=None,
        )
        session.summary_json = summary_state
        session.updated_at = datetime.now(timezone.utc)
        db.add(session)
        return False

    pending_digest = _hash_payload(
        {
            "provider_mode": provider_mode,
            "reason": reason or "auto",
            "force": force,
            "needs": needs,
        }
    )
    if (
        str(summary_state.get("pending_ai_digest") or "") == pending_digest
        and str(summary_state.get("ai_generation_status") or "") in AI_GENERATION_RUNNING_STATUSES
    ):
        return False
    summary_state.update(
        ai_generation_status="queued",
        pending_ai_reason=reason or "auto",
        pending_ai_digest=pending_digest,
        last_ai_error=None,
    )
    session.summary_json = summary_state
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
    return True


def process_remediation_session_ai_generation(
    db: Session,
    *,
    session_id: str,
    reason: str | None = None,
    force: bool = False,
) -> None:
    session = db.get(RemediationSession, session_id)
    if session is None:
        return
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    _persist_session_snapshot(db, session, asset_detail, plan)
    _synchronize_session_runtime_state(db, session=session, plan=plan)
    _prune_legacy_summary_messages(db, session=session)
    ai_service = RemediationAIExplanationService()
    provider_mode = ai_service.provider_mode()
    needs = _collect_ai_generation_needs(
        db,
        session=session,
        plan=plan,
        provider_mode=provider_mode,
        reason=reason,
        force=force,
    )
    summary_state = _summary_state(session)
    if not needs:
        summary_state.update(
            ai_generation_status="idle",
            pending_ai_reason=None,
            pending_ai_digest=None,
            last_ai_error=None,
            last_ai_provider_mode=provider_mode,
        )
        session.summary_json = summary_state
        session.updated_at = datetime.now(timezone.utc)
        db.add(session)
        db.commit()
        return

    summary_state.update(
        ai_generation_status="running",
        pending_ai_reason=reason or str(summary_state.get("pending_ai_reason") or "auto"),
        last_ai_error=None,
        last_ai_provider_mode=provider_mode,
    )
    session.summary_json = summary_state
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
    db.commit()

    session = db.get(RemediationSession, session_id)
    if session is None:
        return
    asset_detail = build_remediation_asset_detail(db, session.asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    summary_state = _summary_state(session)
    needs = _collect_ai_generation_needs(
        db,
        session=session,
        plan=plan,
        provider_mode=provider_mode,
        reason=reason,
        force=force,
    )
    try:
        if "ai_plan_summary" in needs:
            plan_content = ai_service.build_plan_summary(asset_detail=asset_detail, plan=plan)
            _append_session_message(
                db,
                session=session,
                role="assistant",
                message_type="ai_plan_summary",
                content=plan_content,
                payload_json={
                    "provider_mode": provider_mode,
                    "plan_digest": needs["ai_plan_summary"]["digest"],
                    "reason": reason or "auto",
                },
            )
            summary_state["last_plan_digest"] = needs["ai_plan_summary"]["digest"]
        if "ai_blocker_analysis" in needs:
            blocker_content = ai_service.build_blocker_analysis(asset_detail=asset_detail, plan=plan)
            _append_session_message(
                db,
                session=session,
                role="assistant",
                message_type="ai_blocker_analysis",
                content=blocker_content,
                payload_json={
                    "provider_mode": provider_mode,
                    "blocker_digest": needs["ai_blocker_analysis"]["digest"],
                    "reason": reason or "auto",
                },
            )
            summary_state["last_blocker_digest"] = needs["ai_blocker_analysis"]["digest"]
        if "ai_task_failure" in needs:
            failed_task = db.get(TaskRun, needs["ai_task_failure"]["task_id"])
            if failed_task is not None:
                failure_content = ai_service.build_task_failure(asset_detail=asset_detail, plan=plan, task=failed_task)
                _append_session_message(
                    db,
                    session=session,
                    role="assistant",
                    message_type="ai_task_failure",
                    content=failure_content,
                    payload_json={
                        "provider_mode": provider_mode,
                        "task_id": failed_task.id,
                        "failed_task_digest": needs["ai_task_failure"]["digest"],
                    },
                )
                summary_state["last_failed_task_digest"] = needs["ai_task_failure"]["digest"]
        summary_state.update(
            ai_generation_status="idle",
            pending_ai_reason=None,
            pending_ai_digest=None,
            last_ai_error=None,
            last_ai_provider_mode=provider_mode,
        )
        session.summary_json = summary_state
        session.updated_at = datetime.now(timezone.utc)
        db.add(session)
        db.commit()
    except Exception as exc:
        summary_state.update(
            ai_generation_status="failed",
            pending_ai_reason=None,
            pending_ai_digest=None,
            last_ai_error=str(exc),
            last_ai_provider_mode=provider_mode,
        )
        session.summary_json = summary_state
        session.updated_at = datetime.now(timezone.utc)
        db.add(session)
        db.commit()
        raise


def _collect_ai_generation_needs(
    db: Session,
    *,
    session: RemediationSession,
    plan: HostRemediationPlanRead,
    provider_mode: str,
    reason: str | None = None,
    force: bool = False,
) -> dict[str, dict[str, Any]]:
    summary_state = _summary_state(session)
    provider_changed = str(summary_state.get("last_ai_provider_mode") or "") != provider_mode
    needs: dict[str, dict[str, Any]] = {}

    plan_digest = _hash_payload({"provider_mode": provider_mode, "plan": plan.model_dump(mode="json")})
    force_plan_summary = force and reason in {"refresh_plan", "refresh_ai", "summarize_risks"}
    if (
        force_plan_summary
        or reason == "initial"
        or provider_changed
        or str(summary_state.get("last_plan_digest") or "") != plan_digest
        or not _has_message_type(session, "ai_plan_summary")
    ):
        needs["ai_plan_summary"] = {"digest": plan_digest}

    if plan.blocked_reasons:
        blocker_digest = _hash_payload(
            {
                "provider_mode": provider_mode,
                "global_blockers": [item.model_dump(mode="json") for item in plan.global_blockers],
                "step_blockers": [item.model_dump(mode="json") for item in plan.step_blockers],
            }
        )
        force_blocker_analysis = force and reason in {"explain_blockers", "refresh_ai"}
        if (
            force_blocker_analysis
            or provider_changed
            or str(summary_state.get("last_blocker_digest") or "") != blocker_digest
            or not _has_message_type(session, "ai_blocker_analysis")
        ):
            needs["ai_blocker_analysis"] = {"digest": blocker_digest}

    failed_task = _latest_failed_remediation_task(db, session.asset_id)
    if failed_task is not None:
        failure_digest = _hash_payload(
            {
                "task_id": failed_task.id,
                "status": str(failed_task.status.value if hasattr(failed_task.status, "value") else failed_task.status),
                "message": failed_task.message,
                "result_json": failed_task.result_json,
            }
        )
        if str(summary_state.get("last_failed_task_digest") or "") != failure_digest or not _has_task_failure_message(session, failure_digest):
            needs["ai_task_failure"] = {"digest": failure_digest, "task_id": failed_task.id}
    return needs


def _prune_legacy_summary_messages(db: Session, *, session: RemediationSession) -> None:
    removed = False
    for item in list(session.messages):
        if item.role == "assistant" and item.message_type == "summary":
            session.messages.remove(item)
            db.delete(item)
            removed = True
    if removed:
        db.add(session)


def _has_message_type(session: RemediationSession, message_type: str) -> bool:
    return any(item.message_type == message_type for item in session.messages)


def _has_task_failure_message(session: RemediationSession, failure_digest: str) -> bool:
    for item in session.messages:
        if item.message_type != "ai_task_failure":
            continue
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if str(payload.get("failed_task_digest") or "") == failure_digest:
            return True
    return False


def _summary_state(session: RemediationSession) -> dict[str, Any]:
    return dict(session.summary_json or {}) if isinstance(session.summary_json, dict) else {}


def _latest_failed_remediation_task(db: Session, asset_id: str) -> TaskRun | None:
    task = db.scalar(
        select(TaskRun)
        .where(
            TaskRun.scope_type == "asset",
            TaskRun.scope_id == asset_id,
            TaskRun.task_type == TaskType.REMEDIATION_EXECUTE,
        )
        .order_by(TaskRun.created_at.desc())
    )
    if task is None or task.status != TaskExecutionStatus.FAILURE:
        return None
    return task


def _reconcile_session_task_progress(db: Session, session: RemediationSession) -> None:
    if not session.last_task_id:
        return
    task = db.get(TaskRun, session.last_task_id)
    if task is None:
        return
    if task.task_type != TaskType.REMEDIATION_EXECUTE or task.scope_type != "asset" or task.scope_id != session.asset_id:
        return
    summary_state = _summary_state(session)
    task_context = task.result_json.get("context") if isinstance(task.result_json, dict) and isinstance(task.result_json.get("context"), dict) else {}
    stage_code = str(task_context.get("stage_code") or "").strip()
    running_stage_code = str(summary_state.get("running_stage_code") or "").strip()
    changed = False

    if task.status in RUNNING_TASK_STATUSES and stage_code and running_stage_code != stage_code:
        summary_state["running_stage_code"] = stage_code
        changed = True
    elif task.status == TaskExecutionStatus.SUCCESS:
        completed_stage_codes = _completed_stage_codes(session)
        if stage_code and stage_code not in completed_stage_codes:
            completed_stage_codes.append(stage_code)
            summary_state["completed_stage_codes"] = completed_stage_codes
            changed = True
        if running_stage_code and (not stage_code or running_stage_code == stage_code):
            summary_state["running_stage_code"] = None
            changed = True
    elif task.status in {TaskExecutionStatus.FAILURE, TaskExecutionStatus.CANCELED}:
        if running_stage_code and (not stage_code or running_stage_code == stage_code):
            summary_state["running_stage_code"] = None
            changed = True

    if not changed:
        return
    session.summary_json = summary_state
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)


def _hash_payload(payload: Any) -> str:
    return hashlib.sha256(json_dumps(payload).encode("utf-8")).hexdigest()


def _enqueue_ai_generation(session_id: str, *, reason: str | None, force: bool) -> None:
    from app.db.session import SessionLocal
    from app.tasks.remediation_tasks import run_remediation_session_ai_task

    try:
        run_remediation_session_ai_task.delay(session_id, reason, force)
    except Exception as exc:
        with SessionLocal() as db:
            session = db.get(RemediationSession, session_id)
            if session is None:
                return
            summary_state = _summary_state(session)
            summary_state.update(
                ai_generation_status="failed",
                pending_ai_reason=None,
                pending_ai_digest=None,
                last_ai_error=str(exc),
            )
            session.summary_json = summary_state
            session.updated_at = datetime.now(timezone.utc)
            db.add(session)
            db.commit()


def _completed_stage_codes(session: RemediationSession) -> list[str]:
    summary_state = _summary_state(session)
    return [
        str(item).strip()
        for item in (summary_state.get("completed_stage_codes") or [])
        if str(item).strip()
    ]


def _running_stage_code(session: RemediationSession) -> str | None:
    value = str(_summary_state(session).get("running_stage_code") or "").strip()
    return value or None


def _stage_progress_signature(session: RemediationSession) -> str:
    return _hash_payload(
        {
            "completed_stage_codes": _completed_stage_codes(session),
            "running_stage_code": _running_stage_code(session),
        }
    )


def _synchronize_session_runtime_state(
    db: Session,
    *,
    session: RemediationSession,
    plan: HostRemediationPlanRead,
) -> None:
    _synchronize_session_runtime_state_with_plan(
        db,
        session=session,
        plan=plan,
    )


def synchronize_active_session_runtime_state(db: Session, asset_id: str) -> RemediationSession | None:
    session = _latest_session(db, asset_id)
    if session is None:
        return None
    asset_detail = build_remediation_asset_detail(db, asset_id)
    plan = _resolve_session_plan(db, session, asset_detail)
    _persist_session_snapshot(db, session, asset_detail, plan)
    _synchronize_session_runtime_state_with_plan(
        db,
        session=session,
        plan=plan,
    )
    db.flush()
    return _latest_session(db, asset_id)


def _synchronize_session_runtime_state_with_plan(
    db: Session,
    *,
    session: RemediationSession,
    plan: HostRemediationPlanRead,
) -> None:
    task = None
    if session.last_task_id:
        candidate = db.get(TaskRun, session.last_task_id)
        if (
            candidate is not None
            and candidate.task_type == TaskType.REMEDIATION_EXECUTE
            and candidate.scope_type == "asset"
            and candidate.scope_id == session.asset_id
        ):
            task = candidate
        else:
            session.last_task_id = None

    next_status = "ready" if plan.execution_ready else "draft"
    if task is not None:
        task_context = task.result_json.get("context") if isinstance(task.result_json, dict) and isinstance(task.result_json.get("context"), dict) else {}
        running_stage_name = str(task_context.get("stage_name") or "").strip()
        if task.status in RUNNING_TASK_STATUSES:
            next_status = "running"
            _append_session_audit_message(
                db,
                session=session,
                event_code="task_submitted",
                task_id=task.id,
                status="running",
                content=f"已提交阶段“{running_stage_name}”的修复任务，等待 Host Runner 拉取执行。" if running_stage_name else "已提交整机修复任务，等待 Host Runner 拉取执行。",
            )
        elif task.status == TaskExecutionStatus.SUCCESS:
            if plan.plan_mode == "completed":
                next_status = "completed"
                content = "Host Runner 已完成整机修复计划。"
            else:
                content = f"阶段“{running_stage_name}”执行完成，工作台已更新到下一阶段。" if running_stage_name else "当前阶段执行完成，工作台已更新。"
            _append_session_audit_message(
                db,
                session=session,
                event_code="task_terminal",
                task_id=task.id,
                status=next_status,
                content=content,
            )
        elif task.status in {TaskExecutionStatus.FAILURE, TaskExecutionStatus.CANCELED}:
            next_status = TERMINAL_TASK_TO_SESSION_STATUS[task.status]
            if next_status == "failed":
                detail = str(task.message or "").strip()
                content = f"Host Runner 执行失败：{detail}" if detail else "Host Runner 执行失败，请查看任务输出。"
            else:
                content = "整机修复任务已中断。"
            _append_session_audit_message(
                db,
                session=session,
                event_code="task_terminal",
                task_id=task.id,
                status=next_status,
                content=content,
            )
    if plan.plan_mode == "completed":
        next_status = "completed"
    elif plan.plan_mode == "failed":
        next_status = "failed"
    elif plan.plan_mode == "running":
        next_status = "running"
    session.status = next_status
    db.add(session)


def _serialize_session(
    db: Session,
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
    plan: HostRemediationPlanRead,
) -> RemediationSessionRead:
    messages = [_serialize_session_message(item) for item in session.messages]
    return RemediationSessionRead(
        session_id=session.id,
        asset_id=session.asset_id,
        status=session.status,
        asset=asset_detail.asset,
        authorization=asset_detail.authorization,
        latest_collection=asset_detail.latest_collection,
        runner=asset_detail.runner,
        findings=asset_detail.findings,
        plan=plan,
        messages=messages,
        last_task_id=session.last_task_id,
        approved_at=session.approved_at.isoformat() if session.approved_at else None,
        approved_by=session.approved_by,
    )


def _serialize_session_message(item: RemediationMessage) -> RemediationMessageRead:
    payload_json = dict(item.payload_json or {})
    return RemediationMessageRead(
        id=item.id,
        role=item.role,
        message_type=item.message_type,
        content=item.content,
        payload_json=payload_json,
        created_at=item.created_at,
        actions=[
            RemediationSessionMessageActionRead(
                action_id=str(action.get("action_id") or ""),
                label=str(action.get("label") or ""),
                intent=str(action.get("intent") or ""),
            )
            for action in (payload_json.get("actions") or [])
            if isinstance(action, dict)
        ],
    )


def _build_host_plan(db: Session, asset_detail: RemediationAssetDetailRead, session: RemediationSession | None = None) -> HostRemediationPlanRead:
    findings = list(asset_detail.findings)
    findings.sort(key=lambda item: (_severity_rank(item.severity.value), item.detected_at.isoformat()), reverse=True)
    plans_by_finding_id = build_asset_plans(db, asset_detail.asset.id)
    impacted_services: list[str] = []
    seen_services: set[str] = set()
    impact_summaries: list[str] = []
    precheck_items: list[str] = []
    verify_items: list[str] = []
    rollback_notes: list[str] = []
    step_map: dict[tuple[Any, ...], HostRemediationPlanStepRead] = {}
    global_blockers = _build_global_blockers(db, asset_detail)
    step_blockers: list[RemediationBlockerRead] = []
    completed_stage_codes = set(_completed_stage_codes(session)) if session is not None else set()
    running_stage_code = _running_stage_code(session) if session is not None else None
    findings_covered_count = 0

    for finding in findings:
        plan = plans_by_finding_id.get(finding.finding_id)
        if plan is None:
            continue
        findings_covered_count += 1
        if plan.impact_summary and plan.impact_summary not in impact_summaries:
            impact_summaries.append(plan.impact_summary)
        for item in plan.precheck_items:
            if item not in precheck_items:
                precheck_items.append(item)
        for item in plan.verify_items:
            if item not in verify_items:
                verify_items.append(item)
        for item in plan.rollback_notes:
            if item not in rollback_notes:
                rollback_notes.append(item)
        service_name = plan.service_name or finding.service_name
        if service_name and service_name not in seen_services:
            seen_services.add(service_name)
            impacted_services.append(service_name)
        for step in plan.steps:
            phase_code, phase_name = _phase_for_action(step.action_type)
            blocked_reason = step.blocked_reason or None
            blockers = (
                [_make_blocker(blocked_reason, scope="step", blocking="soft", stage_code=phase_code, step_id=step.step_id)]
                if blocked_reason
                else []
            )
            dedupe_key = (
                phase_code,
                step.action_type,
                step.title,
                step.generated_command or "",
                blocked_reason or "",
                json_dumps(step.backup_plan.model_dump(mode="json") if step.backup_plan else {}),
                json_dumps(step.target_files),
                json_dumps(step.target_services),
                json_dumps(step.target_paths),
            )
            related_finding = HostRemediationRelatedFindingRead(
                finding_id=finding.finding_id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                service_name=finding.service_name,
            )
            if dedupe_key not in step_map:
                step_map[dedupe_key] = HostRemediationPlanStepRead(
                    step_id=step.step_id,
                    finding_id=finding.finding_id,
                    finding_title=finding.title,
                    action_type=step.action_type,
                    title=step.title,
                    phase_code=phase_code,
                    phase_name=phase_name,
                    execution_state=step.execution_state,
                    blocked_reason=blocked_reason,
                    generated_command=step.generated_command,
                    backup_plan=step.backup_plan,
                    render_reason=step.render_reason,
                    service_name=service_name,
                    target_files=list(step.target_files),
                    target_services=list(step.target_services),
                    target_paths=list(step.target_paths),
                    fallback_strategy=step.fallback_strategy,
                    fallback_candidates=list(step.fallback_candidates),
                    verify_items=list(step.verify_items),
                    rollback_hint=step.rollback_hint,
                    blockers=blockers,
                    related_findings=[related_finding],
                    related_rules=[plan.rule_id],
                )
            else:
                merged = step_map[dedupe_key]
                merged.target_files = _merge_unique_strings(merged.target_files, step.target_files)
                merged.target_services = _merge_unique_strings(merged.target_services, step.target_services)
                merged.target_paths = _merge_unique_strings(merged.target_paths, step.target_paths)
                merged.fallback_candidates = _merge_unique_strings(merged.fallback_candidates, step.fallback_candidates)
                merged.verify_items = _merge_unique_strings(merged.verify_items, step.verify_items)
                merged.related_rules = _merge_unique_strings(merged.related_rules, [plan.rule_id])
                if not merged.fallback_strategy and step.fallback_strategy:
                    merged.fallback_strategy = step.fallback_strategy
                if not any(item.finding_id == related_finding.finding_id for item in merged.related_findings):
                    merged.related_findings.append(related_finding)
                for blocker in blockers:
                    if not _has_blocker(merged.blockers, blocker):
                        merged.blockers.append(blocker)
            for blocker in blockers:
                if not _has_blocker(step_blockers, blocker):
                    step_blockers.append(blocker)

    steps = sorted(
        step_map.values(),
        key=lambda item: (PHASE_METADATA[item.phase_code]["order"], item.title, item.step_id),
    )
    step_blockers = _assign_host_plan_step_ids(steps)
    phases: list[HostRemediationPhaseRead] = []
    stages: list[HostRemediationStageRead] = []
    stage_rows: list[dict[str, Any]] = []
    for phase_code, phase_name, order, summary in PHASE_DEFINITIONS:
        phase_steps = [item for item in steps if item.phase_code == phase_code]
        include_stage = bool(phase_steps) or phase_code in completed_stage_codes or phase_code == running_stage_code
        if not include_stage:
            continue
        ready_count = len([item for item in phase_steps if item.execution_state == "ready"])
        blocked_count = len([item for item in phase_steps if item.execution_state == "blocked"])
        phases.append(
            HostRemediationPhaseRead(
                phase_code=phase_code,
                phase_name=phase_name,
                order=order,
                summary=summary,
                ready_count=ready_count,
                blocked_count=blocked_count,
            )
        )
        stage_rows.append(
            {
                "stage_code": phase_code,
                "stage_name": phase_name,
                "order": order,
                "summary": summary,
                "steps": phase_steps,
                "ready_step_count": ready_count,
                "blocked_step_count": blocked_count,
                "related_finding_ids": [item.finding_id for item in phase_steps if item.finding_id],
                "related_rule_ids": list({rule_id for item in phase_steps for rule_id in item.related_rules if rule_id}),
                "related_services": list({item.service_name for item in phase_steps if item.service_name}),
            }
        )
    current_pending_index = next(
        (index for index, row in enumerate(stage_rows) if row["stage_code"] not in completed_stage_codes),
        None,
    )
    current_stage_code: str | None = running_stage_code
    hard_global_blockers = [item for item in global_blockers if item.blocking == "hard"]
    for index, row in enumerate(stage_rows):
        stage_code = row["stage_code"]
        stage_global_blockers = [] if stage_code in completed_stage_codes else list(global_blockers)
        if stage_code in completed_stage_codes:
            gate_status = "completed"
        elif running_stage_code == stage_code and session is not None and session.status == "running":
            gate_status = "running"
        elif current_pending_index is not None and index > current_pending_index:
            gate_status = "locked"
        elif hard_global_blockers:
            gate_status = "blocked"
        elif row["ready_step_count"] > 0:
            gate_status = "ready"
        elif row["blocked_step_count"] > 0:
            gate_status = "blocked"
        else:
            gate_status = "locked"
        if current_stage_code is None and gate_status in {"ready", "blocked"}:
            current_stage_code = stage_code
        stages.append(
            HostRemediationStageRead(
                stage_code=stage_code,
                stage_name=row["stage_name"],
                order=row["order"],
                summary=row["summary"],
                gate_status=gate_status,
                ready_step_count=row["ready_step_count"],
                blocked_step_count=row["blocked_step_count"],
                global_blockers=stage_global_blockers,
                related_finding_ids=_merge_unique_strings([], row["related_finding_ids"]),
                related_rule_ids=_merge_unique_strings([], row["related_rule_ids"]),
                related_services=_merge_unique_strings([], row["related_services"]),
                steps=row["steps"],
            )
        )
    ready_step_count = len([item for item in steps if item.execution_state == "ready"])
    blocked_step_count = len([item for item in steps if item.execution_state == "blocked"])
    ready_stage_count = len([item for item in stages if item.gate_status == "ready"])
    blocked_stage_count = len([item for item in stages if item.gate_status == "blocked"])
    blocked_reasons = [item.message for item in [*global_blockers, *step_blockers]]
    execution_ready = ready_stage_count > 0
    plan_mode = _plan_mode_for_session(session=session, stages=stages, execution_ready=execution_ready)
    summary_text = (
        f"已聚合 {findings_covered_count} 条风险，生成 {len(stages)} 个执行阶段，"
        f"当前可执行阶段 {ready_stage_count} 个，{ready_step_count} 个步骤可执行，{blocked_step_count} 个步骤阻塞。"
    )
    return HostRemediationPlanRead(
        execution_ready=execution_ready,
        plan_mode=plan_mode,
        current_stage_code=current_stage_code,
        blocked_reasons=blocked_reasons,
        global_blockers=global_blockers,
        step_blockers=step_blockers,
        findings_covered_count=findings_covered_count,
        service_count=len(impacted_services),
        impacted_services=impacted_services,
        phase_count=len(stages),
        ready_stage_count=ready_stage_count,
        blocked_stage_count=blocked_stage_count,
        ready_step_count=ready_step_count,
        blocked_step_count=blocked_step_count,
        summary_text=summary_text,
        impact_summary="；".join(impact_summaries) if impact_summaries else None,
        precheck_items=precheck_items,
        verify_items=verify_items,
        rollback_notes=rollback_notes,
        phases=phases,
        steps=steps,
        stages=stages,
    )


def _resolve_session_plan(
    db: Session,
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
) -> HostRemediationPlanRead:
    _reconcile_session_task_progress(db, session)
    cached_plan = _cached_session_plan(session, asset_detail)
    if cached_plan is not None:
        return cached_plan
    return _build_host_plan(db, asset_detail, session=session)


def _cached_session_plan(
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
) -> HostRemediationPlanRead | None:
    if not _session_snapshot_matches_asset_detail(session, asset_detail):
        return None
    plan_json = session.plan_json if isinstance(session.plan_json, dict) else {}
    if not plan_json:
        return None
    try:
        return HostRemediationPlanRead.model_validate(plan_json)
    except Exception:
        return None


def _session_snapshot_matches_asset_detail(
    session: RemediationSession,
    asset_detail: RemediationAssetDetailRead,
) -> bool:
    snapshot = session.finding_snapshot_json if isinstance(session.finding_snapshot_json, dict) else {}
    cached_findings = snapshot.get("findings")
    if not isinstance(cached_findings, list):
        return False
    cached_finding_ids = sorted(
        str(item.get("finding_id") or "").strip()
        for item in cached_findings
        if isinstance(item, dict) and str(item.get("finding_id") or "").strip()
    )
    current_finding_ids = sorted(item.finding_id for item in asset_detail.findings if item.finding_id)
    if cached_finding_ids != current_finding_ids:
        return False
    cached_collection_at = str(snapshot.get("latest_collection_at") or "").strip()
    current_collection_at = str(asset_detail.latest_collection.collected_at if asset_detail.latest_collection else "").strip()
    if cached_collection_at != current_collection_at:
        return False
    if bool(snapshot.get("authorization_admin_authorized")) != bool(asset_detail.authorization.admin_authorized):
        return False
    if str(snapshot.get("authorization_verification_status") or "").strip() != str(asset_detail.authorization.last_verification_status or "").strip():
        return False
    if str(snapshot.get("authorization_effective_privilege") or "").strip() != str(asset_detail.authorization.effective_privilege or "").strip():
        return False
    if str(snapshot.get("runner_status") or "").strip() != str(asset_detail.runner.status or "").strip():
        return False
    if str(snapshot.get("runner_install_status") or "").strip() != str(asset_detail.runner.install_status or "").strip():
        return False
    if str(snapshot.get("runner_install_mode") or "").strip() != str(asset_detail.runner.install_mode or "").strip():
        return False
    if str(snapshot.get("runner_service_mode") or "").strip() != str(asset_detail.runner.service_mode or "").strip():
        return False
    if str(snapshot.get("stage_progress_signature") or "").strip() != _stage_progress_signature(session):
        return False
    return str(snapshot.get("planner_version") or "").strip() == SESSION_PLAN_SCHEMA_VERSION


def _phase_for_action(action_type: str) -> tuple[str, str]:
    normalized = str(action_type or "").strip().lower()
    if normalized in {"restrict_network", "remove_exposure", "set_bind_scope", "set_access_policy", "remove_path", "toggle_feature"}:
        return "remove_exposure", PHASE_METADATA["remove_exposure"]["name"]
    if normalized in {"set_config", "remove_config", "permission_set", "set_path_permission"}:
        return "config_hardening", PHASE_METADATA["config_hardening"]["name"]
    if normalized == "upgrade_package":
        return "package_upgrade", PHASE_METADATA["package_upgrade"]["name"]
    if normalized in {"reload_service", "restart_service", "disable_service"}:
        return "service_control", PHASE_METADATA["service_control"]["name"]
    return "config_hardening", PHASE_METADATA["config_hardening"]["name"]


def _assign_host_plan_step_ids(steps: list[HostRemediationPlanStepRead]) -> list[RemediationBlockerRead]:
    phase_counters: dict[str, int] = {}
    step_blockers: list[RemediationBlockerRead] = []
    for step in steps:
        phase_code = str(step.phase_code or "config_hardening").strip() or "config_hardening"
        phase_counters[phase_code] = phase_counters.get(phase_code, 0) + 1
        step.step_id = f"{phase_code}-step-{phase_counters[phase_code]}"
        for blocker in step.blockers:
            blocker.step_id = step.step_id
            blocker.stage_code = blocker.stage_code or phase_code
            if not _has_blocker(step_blockers, blocker):
                step_blockers.append(blocker)
    return step_blockers


def _make_blocker(
    message: str,
    *,
    scope: str,
    blocking: str,
    stage_code: str | None = None,
    step_id: str | None = None,
) -> RemediationBlockerRead:
    normalized = str(message or "").strip()
    message_lower = normalized.lower()
    code = "unknown_blocker"
    if "未配置 ssh" in normalized:
        code = "missing_ssh_credential"
    elif "管理员授权" in normalized:
        code = "authorization_unconfirmed"
    elif "管理员权限验证" in normalized:
        code = "authorization_not_verified"
    elif "未验证到管理员权限" in normalized:
        code = "insufficient_privilege"
    elif "root/sudo" in normalized or "sudo 凭据" in normalized:
        code = "insufficient_privilege"
    elif "深度检查结果" in normalized or "snapshot" in message_lower:
        code = "missing_snapshot"
    elif "尚未安装" in normalized:
        code = "runner_not_installed"
    elif "正在安装中" in normalized:
        code = "runner_installing"
    elif "当前离线" in normalized:
        code = "runner_offline"
    elif "缺少自动修复适配器" in normalized:
        code = "missing_adapter"
    elif "无法稳定渲染" in normalized:
        code = "unstable_render"
    elif "未解析到" in normalized:
        code = "missing_target"
    elif "白名单" in normalized:
        code = "action_not_allowed"
    return RemediationBlockerRead(
        code=code,
        message=normalized,
        scope=scope,
        blocking=blocking,
        stage_code=stage_code,
        step_id=step_id,
    )


def _has_blocker(items: list[RemediationBlockerRead], blocker: RemediationBlockerRead) -> bool:
    for item in items:
        if (
            item.code == blocker.code
            and item.message == blocker.message
            and item.scope == blocker.scope
            and item.stage_code == blocker.stage_code
            and item.step_id == blocker.step_id
        ):
            return True
    return False


def _merge_unique_strings(base: list[str], extra: list[str] | tuple[str, ...] | set[str]) -> list[str]:
    merged = list(base)
    for item in extra:
        value = str(item or "").strip()
        if value and value not in merged:
            merged.append(value)
    return merged


def _build_global_blockers(db: Session, asset_detail: RemediationAssetDetailRead) -> list[RemediationBlockerRead]:
    credential = get_manual_credential(db, asset_detail.asset.id)
    snapshot = get_latest_collection_snapshot(db, asset_detail.asset.id)
    blockers = [
        _make_blocker(message, scope="global", blocking="hard")
        for message in _compute_blocked_reasons(credential, snapshot)
    ]
    runner_capabilities = asset_detail.runner.capabilities_json if isinstance(asset_detail.runner.capabilities_json, dict) else {}
    probe_payload = runner_capabilities.get("probe") if isinstance(runner_capabilities.get("probe"), dict) else {}
    if (
        asset_detail.runner.install_status == "installed"
        and str(asset_detail.runner.install_mode or "").strip().lower() == "user"
        and probe_payload.get("can_system_install") is False
    ):
        blockers.append(
            _make_blocker(
                "当前目标主机未检测到可用的 root/sudo，需先恢复管理员权限或更新 sudo 凭据后再执行整机修复",
                scope="global",
                blocking="hard",
            )
        )
    if asset_detail.runner.install_status == "not_installed":
        blockers.append(_make_blocker("当前主机尚未安装 Host Runner", scope="global", blocking="hard"))
    elif asset_detail.runner.install_status == "installing":
        blockers.append(_make_blocker("Host Runner 正在安装中，暂不可执行整机修复任务", scope="global", blocking="hard"))
    elif asset_detail.runner.status not in {"online", "busy"}:
        blockers.append(_make_blocker("Host Runner 当前离线，暂不可执行整机修复任务", scope="global", blocking="hard"))
    deduped: list[RemediationBlockerRead] = []
    for item in blockers:
        if not _has_blocker(deduped, item):
            deduped.append(item)
    return deduped


def _plan_mode_for_session(
    *,
    session: RemediationSession | None,
    stages: list[HostRemediationStageRead],
    execution_ready: bool,
) -> str:
    session_status = str(session.status or "").strip().lower() if session is not None else ""
    if session_status == "failed":
        return "failed"
    if session_status == "completed":
        return "completed"
    if any(item.gate_status == "running" for item in stages):
        return "running"
    if session_status == "running" and session is not None and _running_stage_code(session):
        return "running"
    if stages and all(item.gate_status == "completed" for item in stages):
        return "completed"
    if execution_ready and session is not None and _completed_stage_codes(session):
        return "partial"
    if execution_ready:
        return "ready"
    return "blocked"


def _severity_rank(value: str | None) -> int:
    raw = str(value or "").strip().lower()
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(raw, 0)


def _runner_id_for_asset(db: Session, asset_id: str) -> str | None:
    runner = resolve_runner_by_asset_for_read(db, asset_id)
    return runner.id if runner else None


def _stored_execution_ready(session: RemediationSession) -> bool:
    if isinstance(session.plan_json, dict) and isinstance(session.plan_json.get("execution_ready"), bool):
        return bool(session.plan_json["execution_ready"])
    if isinstance(session.summary_json, dict):
        if "ready_stage_count" in session.summary_json:
            return int(session.summary_json.get("ready_stage_count") or 0) > 0
        return int(session.summary_json.get("ready_step_count") or 0) > 0 and int(session.summary_json.get("blocked_step_count") or 0) == 0
    return False


def _latest_session(db: Session, asset_id: str) -> RemediationSession | None:
    return db.scalar(
        select(RemediationSession)
        .where(
            RemediationSession.asset_id == asset_id,
            RemediationSession.status.not_in(["completed", "failed", "canceled"]),
        )
        .order_by(RemediationSession.created_at.desc())
    )


def _latest_asset_task(db: Session, asset_id: str) -> TaskRun | None:
    return db.scalar(
        select(TaskRun)
        .where(
            TaskRun.scope_type == "asset",
            TaskRun.scope_id == asset_id,
            TaskRun.task_type.in_([TaskType.RUNNER_INSTALL, TaskType.REMEDIATION_EXECUTE]),
        )
        .order_by(TaskRun.created_at.desc())
    )


def json_dumps(value: Any) -> str:
    return __import__("json").dumps(value, ensure_ascii=False, sort_keys=True)
