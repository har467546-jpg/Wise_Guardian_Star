from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.core.security import SecurityError, decode_access_token
from app.db.models.asset import Asset
from app.db.models.enums import TaskExecutionStatus, TaskType, UserRole
from app.db.models.remediation_session import RemediationSession
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.task_event_repo import create_task_event, list_task_events_for_runs
from app.repositories.task_repo import create_task_run, get_task_run, update_task_run
from app.schemas.remediation import (
    HostRunnerInstallRead,
    HostRunnerRead,
    RemediationAssetDetailRead,
    RemediationAssetListRead,
    RemediationExecuteRequest,
    RemediationExecuteResponse,
    RemediationPlanRead,
    RemediationSessionApproveRequest,
    RemediationSessionApproveResponse,
    RemediationSessionCreateRequest,
    RemediationSessionMessageCreateRequest,
    RemediationSessionRead,
    RemediationTaskRead,
    RemediationTaskEvidenceRead,
    RemediationWorkspaceRead,
)
from app.services.remediation_business_service import EXECUTION_STATUS_PENDING
from app.services.remediation_executor import build_remediation_preview_result
from app.services.remediation_service import (
    build_plan,
    build_workspace,
    get_manual_credential,
    list_remediation_assets,
    selected_steps_require_maintenance_window,
    select_executable_plan_steps,
)
from app.services.remediation_session_service import (
    append_remediation_session_message,
    approve_remediation_session,
    build_remediation_asset_detail,
    create_or_resume_remediation_session,
    get_remediation_session_read,
    get_remediation_session_snapshot_read,
    synchronize_active_session_runtime_state,
)
from app.services.runner_service import (
    queue_runner_install,
    resolve_runner_by_asset_for_read,
    resolve_runner_public_url,
    serialize_host_runner,
)
from app.services.task_observability_service import serialize_task_event
from app.tasks.remediation_tasks import run_remediation_execute_task
from app.tasks.runner_tasks import run_runner_install_task

router = APIRouter()


@router.get("/assets", response_model=RemediationAssetListRead)
def get_remediation_assets(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=24, ge=1, le=200),
    keyword: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationAssetListRead:
    return list_remediation_assets(db, page=page, page_size=page_size, keyword=keyword)


@router.get("/assets/{asset_id}", response_model=RemediationAssetDetailRead)
def get_remediation_asset(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationAssetDetailRead:
    try:
        detail = build_remediation_asset_detail(db, asset_id)
        if detail.active_session_id:
            session = synchronize_active_session_runtime_state(db, asset_id)
            detail.active_session_id = session.id if session else None
            detail.active_session_status = session.status if session else None
        db.commit()
        return detail
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/assets/{asset_id}/runner", response_model=HostRunnerRead)
def get_asset_runner(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> HostRunnerRead:
    return serialize_host_runner(asset_id, resolve_runner_by_asset_for_read(db, asset_id))


@router.post("/assets/{asset_id}/runner/install", response_model=HostRunnerInstallRead, status_code=status.HTTP_202_ACCEPTED)
def install_asset_runner(
    asset_id: str,
    request: Request,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> HostRunnerInstallRead:
    asset_model = db.get(Asset, asset_id)
    if asset_model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    credential = get_manual_credential(db, asset_id)
    try:
        host_runner, task_id, registration_token = queue_runner_install(
            db,
            asset=asset_model,
            credential=credential,
            platform_url=_resolve_platform_url(request),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    task = run_runner_install_task.delay(task_id, asset_id, _resolve_platform_url(request), registration_token)
    task_run = get_task_run(db, task_id)
    if task_run is not None:
        update_task_run(db, task_run, celery_task_id=task.id)
    return HostRunnerInstallRead(
        task_id=task_id,
        status=TaskExecutionStatus.PENDING,
        runner_id=host_runner.id,
        stream_url=f"/api/v1/remediation/tasks/{task_id}/stream",
    )


@router.get("/assets/{asset_id}/workspace", response_model=RemediationWorkspaceRead)
def get_remediation_workspace(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationWorkspaceRead:
    try:
        return build_workspace(db, asset_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/assets/{asset_id}/sessions", response_model=RemediationSessionRead)
def create_remediation_session(
    asset_id: str,
    payload: RemediationSessionCreateRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationSessionRead:
    try:
        return create_or_resume_remediation_session(db, asset_id=asset_id, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/sessions/{session_id}", response_model=RemediationSessionRead)
def get_remediation_session(
    session_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationSessionRead:
    try:
        return get_remediation_session_read(db, session_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/sessions/{session_id}/messages", response_model=RemediationSessionRead)
def post_remediation_session_message(
    session_id: str,
    payload: RemediationSessionMessageCreateRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationSessionRead:
    try:
        return append_remediation_session_message(db, session_id=session_id, payload=payload)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/sessions/{session_id}/approve", response_model=RemediationSessionApproveResponse, status_code=status.HTTP_202_ACCEPTED)
def approve_host_remediation_session(
    session_id: str,
    payload: RemediationSessionApproveRequest | None = None,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_admin_user),
) -> RemediationSessionApproveResponse:
    try:
        return approve_remediation_session(
            db,
            session_id=session_id,
            approved_by=user.id,
            stage_code=payload.stage_code if payload else None,
            execution_mode=payload.execution_mode if payload else "apply",
            change_ticket=payload.change_ticket if payload else None,
            maintenance_window_id=payload.maintenance_window_id if payload else None,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get("/findings/{finding_id}/plan", response_model=RemediationPlanRead)
def get_remediation_plan(
    finding_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationPlanRead:
    try:
        return build_plan(db, finding_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/findings/{finding_id}/execute", response_model=RemediationExecuteResponse, status_code=status.HTTP_202_ACCEPTED)
def execute_remediation_plan(
    finding_id: str,
    payload: RemediationExecuteRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationExecuteResponse:
    try:
        plan = build_plan(db, finding_id)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not plan.execution_ready:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="；".join(plan.blocked_reasons) or "当前资产不满足修复执行条件",
        )

    try:
        selected_steps = select_executable_plan_steps(
            plan.steps,
            submitted_step_ids=[item.step_id for item in payload.steps] if payload.steps else None,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    execution_mode = str(payload.execution_mode or "dry_run").strip().lower() or "dry_run"
    change_ticket = str(payload.change_ticket or "").strip() or None
    maintenance_window_id = str(payload.maintenance_window_id or "").strip() or None
    if execution_mode == "apply" and selected_steps_require_maintenance_window(selected_steps) and not maintenance_window_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="当前所选步骤需要维护窗口，请先填写 maintenance_window_id 后再正式执行",
        )
    submitted_steps = [{"step_id": step.step_id} for step in selected_steps]
    task_run = create_task_run(
        db,
        task_type=TaskType.REMEDIATION_EXECUTE,
        scope_type="asset",
        scope_id=plan.asset_id,
        message="修复预演任务已生成" if execution_mode == "dry_run" else "交互式漏洞修复任务已入队",
    )
    selected_step_payloads = [
        step.model_dump(mode="json") if hasattr(step, "model_dump") else step
        for step in selected_steps
    ]
    initial_result = {
        "context": {
            "asset_id": plan.asset_id,
            "finding_id": plan.finding_id,
            "rule_id": plan.rule_id,
            "service_name": plan.service_name,
        },
        "plan": plan.model_dump(mode="json"),
        "execution": {
            "submitted_steps": [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in submitted_steps
            ],
            "execution_mode": execution_mode,
            "change_ticket": change_ticket,
            "maintenance_window_id": maintenance_window_id,
            "execution_status": EXECUTION_STATUS_PENDING if execution_mode == "apply" else "preview_only",
        },
        "execution_status": EXECUTION_STATUS_PENDING if execution_mode == "apply" else "preview_only",
        "business_status": None,
        "backups": {},
        "reverify": {},
        "reverify_task_id": None,
        "reverify_summary": {},
        "targeted_finding_outcomes": [],
    }
    if execution_mode == "dry_run":
        preview_result = build_remediation_preview_result(
            task_run_id=task_run.id,
            context=initial_result["context"],
            plan=plan.model_dump(mode="json"),
            selected_steps=selected_step_payloads,
            change_ticket=change_ticket,
            maintenance_window_id=maintenance_window_id,
        )
        update_task_run(
            db,
            task_run,
            status=TaskExecutionStatus.SUCCESS,
            progress=100,
            message="修复预演已生成，尚未执行任何主机变更",
            result_json=preview_result,
        )
        create_task_event(
            db,
            task_run_id=task_run.id,
            event_type="success",
            level="info",
            stage_code="dry_run_preview",
            stage_name="修复预演",
            message="修复预演已生成，尚未执行任何主机变更",
            progress=100,
            payload_json=preview_result,
        )
    else:
        update_task_run(db, task_run, result_json=initial_result)
        task = run_remediation_execute_task.delay(
            task_run.id,
            finding_id,
            plan.model_dump(mode="json"),
            [
                item.model_dump(mode="json") if hasattr(item, "model_dump") else item
                for item in submitted_steps
            ],
            {
                "execution_mode": execution_mode,
                "change_ticket": change_ticket,
                "maintenance_window_id": maintenance_window_id,
            },
        )
        update_task_run(db, task_run, celery_task_id=task.id)
    return RemediationExecuteResponse(
        task_id=task_run.id,
        status=task_run.status,
        stream_url=f"/api/v1/remediation/tasks/{task_run.id}/stream",
        execution_mode=execution_mode,
    )


@router.get("/tasks/{task_id}", response_model=RemediationTaskRead)
def get_remediation_task(
    task_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationTaskRead:
    task = get_task_run(db, task_id)
    if task is None or task.task_type not in {TaskType.REMEDIATION_EXECUTE, TaskType.RUNNER_INSTALL}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="修复任务不存在")
    events = list_task_events_for_runs(db, [task_id]).get(task_id, [])
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
    return RemediationTaskRead(
        task_id=task.id,
        status=task.status,
        progress=task.progress,
        message=task.message,
        asset_id=context.get("asset_id"),
        finding_id=context.get("finding_id"),
        created_at=task.created_at,
        started_at=task.started_at,
        finished_at=task.finished_at,
        event_count=len(events),
        last_event_at=events[-1].created_at if events else None,
        execution_boundary=(result_json.get("execution") or {}).get("execution_boundary"),
        execution_mode=(result_json.get("execution") or {}).get("execution_mode"),
        execution_status=result_json.get("execution_status"),
        business_status=result_json.get("business_status"),
        context=context,
        plan=result_json.get("plan") if isinstance(result_json.get("plan"), dict) else {},
        execution=result_json.get("execution") if isinstance(result_json.get("execution"), dict) else {},
        backups=result_json.get("backups") if isinstance(result_json.get("backups"), dict) else {},
        reverify=result_json.get("reverify") if isinstance(result_json.get("reverify"), dict) else {},
        targeted_finding_outcomes=result_json.get("targeted_finding_outcomes") if isinstance(result_json.get("targeted_finding_outcomes"), list) else [],
        reverify_task_id=str(result_json.get("reverify_task_id") or "").strip() or None,
        reverify_summary=result_json.get("reverify_summary") if isinstance(result_json.get("reverify_summary"), dict) else {},
    )


@router.get("/tasks/{task_id}/evidence", response_model=RemediationTaskEvidenceRead)
def get_remediation_task_evidence(
    task_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> RemediationTaskEvidenceRead:
    task = get_task_run(db, task_id)
    if task is None or task.task_type not in {TaskType.REMEDIATION_EXECUTE, TaskType.RUNNER_INSTALL}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="修复任务不存在")
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    evidence = result_json.get("evidence") if isinstance(result_json.get("evidence"), dict) else {}
    return RemediationTaskEvidenceRead(
        task_id=task.id,
        execution_mode=evidence.get("execution_mode"),
        execution_boundary=evidence.get("execution_boundary"),
        generated_at=evidence.get("generated_at"),
        item_count=int(evidence.get("item_count") or 0),
        items=evidence.get("items") if isinstance(evidence.get("items"), list) else [],
        summary=evidence.get("summary") if isinstance(evidence.get("summary"), dict) else {},
    )


@router.websocket("/tasks/{task_id}/stream")
async def stream_remediation_task(task_id: str, websocket: WebSocket) -> None:
    token = websocket.query_params.get("token") or ""
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return
    with SessionLocal() as db:
        user = _resolve_websocket_admin(db, token)
        if user is None:
            await websocket.close(code=1008, reason="unauthorized")
            return
        task = get_task_run(db, task_id)
        if task is None or task.task_type not in {TaskType.REMEDIATION_EXECUTE, TaskType.RUNNER_INSTALL}:
            await websocket.close(code=1008, reason="task not found")
            return
    await websocket.accept()
    sent_event_ids: set[str] = set()
    try:
        while True:
            with SessionLocal() as db:
                task = get_task_run(db, task_id)
                if task is None:
                    await websocket.send_json({"type": "error", "message": "任务不存在"})
                    break
                events = list_task_events_for_runs(db, [task_id]).get(task_id, [])
                await websocket.send_json(
                    {
                        "type": "task",
                        "task": {
                            "task_id": task.id,
                            "status": task.status.value if hasattr(task.status, "value") else str(task.status),
                            "progress": task.progress,
                            "message": task.message,
                        },
                    }
                )
                for event in events:
                    if event.id in sent_event_ids:
                        continue
                    sent_event_ids.add(event.id)
                    await websocket.send_json({"type": "event", "event": serialize_task_event(event, task=task)})
                if task.status in {
                    TaskExecutionStatus.SUCCESS,
                    TaskExecutionStatus.FAILURE,
                    TaskExecutionStatus.CANCELED,
                }:
                    await websocket.send_json(
                        {
                            "type": "complete",
                            "status": task.status.value if hasattr(task.status, "value") else str(task.status),
                        }
                    )
                    break
            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass


@router.websocket("/sessions/{session_id}/stream")
async def stream_remediation_session(session_id: str, websocket: WebSocket) -> None:
    token = websocket.query_params.get("token") or ""
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return
    with SessionLocal() as db:
        user = _resolve_websocket_admin(db, token)
        if user is None:
            await websocket.close(code=1008, reason="unauthorized")
            return
        session = db.get(RemediationSession, session_id)
        if session is None:
            await websocket.close(code=1008, reason="session not found")
            return
    await websocket.accept()
    initial_snapshot_sent = False
    sent_message_ids: set[str] = set()
    last_state_signature = ""
    last_pending_digest = ""
    last_error = ""
    try:
        while True:
            with SessionLocal() as db:
                session = db.get(RemediationSession, session_id)
                if session is None:
                    await websocket.send_json({"type": "error", "message": "修复会话不存在"})
                    break
                snapshot = get_remediation_session_snapshot_read(db, session_id)
                summary_json = session.summary_json if isinstance(session.summary_json, dict) else {}
                ai_status = str(summary_json.get("ai_generation_status") or "").strip().lower()
                pending_digest = str(summary_json.get("pending_ai_digest") or "").strip()
                pending_reason = str(summary_json.get("pending_ai_reason") or "").strip() or None
                ai_error = str(summary_json.get("last_ai_error") or "").strip()
                state_payload = snapshot.model_dump(mode="json")
                state_signature = json.dumps(state_payload, ensure_ascii=False, sort_keys=True, default=str)

                if not initial_snapshot_sent:
                    await websocket.send_json({"type": "session_snapshot", "session": state_payload})
                    sent_message_ids = {item["id"] for item in state_payload.get("messages", []) if isinstance(item, dict) and item.get("id")}
                    last_state_signature = state_signature
                    initial_snapshot_sent = True
                else:
                    if ai_status in {"queued", "running"} and pending_digest and pending_digest != last_pending_digest:
                        await websocket.send_json({"type": "ai_generation_started", "reason": pending_reason})
                        last_pending_digest = pending_digest
                    elif ai_status not in {"queued", "running"}:
                        last_pending_digest = ""
                    new_messages = [
                        item
                        for item in state_payload.get("messages", [])
                        if isinstance(item, dict) and item.get("id") and item["id"] not in sent_message_ids
                    ]
                    if new_messages:
                        for item in new_messages:
                            sent_message_ids.add(str(item["id"]))
                            await websocket.send_json({"type": "session_message_added", "message": item})
                    if state_signature != last_state_signature:
                        await websocket.send_json({"type": "session_snapshot", "session": state_payload})
                        last_state_signature = state_signature
                    if ai_error and ai_error != last_error:
                        await websocket.send_json({"type": "error", "message": ai_error})
                        last_error = ai_error
            await asyncio.sleep(0.8)
    except WebSocketDisconnect:
        return
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            pass


def _resolve_websocket_admin(db: Session, token: str) -> User | None:
    try:
        payload = decode_access_token(token)
    except SecurityError:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or user.role != UserRole.ADMIN:
        return None
    return user


def _resolve_platform_url(request: Request) -> str:
    try:
        return resolve_runner_public_url(
            request.headers.get("x-platform-origin"),
            request.headers.get("origin"),
            str(request.base_url),
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
