from __future__ import annotations

import asyncio
import logging
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.websocket_auth import authenticate_websocket
from app.api.deps import get_admin_user, get_current_user, get_db_session
from app.core.security import SecurityError, decode_access_token
from app.db.models.enums import UserRole
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.task_repo import get_task_run, update_task_run
from app.schemas.agent import (
    AgentApprovalRequest,
    AgentApprovalResponse,
    AgentErrorEvent,
    AgentGoalRead,
    AgentMessageCreateRequest,
    AgentSessionRead,
    AgentSessionSummaryRead,
    AgentStreamClientEnvelope,
    AgentTaskUpdateEvent,
    AgentUIStepRequest,
)
from app.services.agent.identity import AGENT_DISPLAY_NAME
from app.services.haor_agent_service import (
    AgentServiceError,
    approve_agent_session,
    cancel_agent_goal,
    get_agent_goal,
    get_agent_session_summary,
    get_or_create_agent_session,
    interrupt_agent_session,
    list_agent_goals,
    post_agent_message,
    post_agent_step,
    recover_agent_session,
    reset_agent_session,
    resume_agent_goal,
    stream_agent_approve_turn,
    stream_agent_message_turn,
    stream_agent_step_turn,
    translate_agent_service_exception,
)
from app.services.runner_service import resolve_runner_public_url
from app.tasks.agent_tasks import run_agent_orchestrate_task

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/xuanwu/summary", response_model=AgentSessionSummaryRead)
@router.get("/haor/summary", response_model=AgentSessionSummaryRead, include_in_schema=False)
def get_haor_session_summary(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionSummaryRead:
    try:
        return get_agent_session_summary(db, user=user)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="get_summary", user=user)


@router.get("/xuanwu/session", response_model=AgentSessionRead)
@router.get("/haor/session", response_model=AgentSessionRead, include_in_schema=False)
def get_haor_session(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return get_or_create_agent_session(db, user=user)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="get_session", user=user)


@router.get("/xuanwu/goals", response_model=list[AgentGoalRead])
@router.get("/haor/goals", response_model=list[AgentGoalRead], include_in_schema=False)
def list_haor_goals(
    limit: int = 12,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> list[AgentGoalRead]:
    try:
        return list_agent_goals(db, user=user, limit=limit)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="list_goals", user=user)


@router.get("/xuanwu/goals/{goal_id}", response_model=AgentGoalRead)
@router.get("/haor/goals/{goal_id}", response_model=AgentGoalRead, include_in_schema=False)
def get_haor_goal(
    goal_id: str,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentGoalRead:
    try:
        return get_agent_goal(db, user=user, goal_id=goal_id)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="get_goal", user=user)


@router.post("/xuanwu/goals/{goal_id}/resume", response_model=AgentSessionRead)
@router.post("/haor/goals/{goal_id}/resume", response_model=AgentSessionRead, include_in_schema=False)
def resume_haor_goal(
    goal_id: str,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return resume_agent_goal(db, user=user, goal_id=goal_id)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="resume_goal", user=user)


@router.post("/xuanwu/goals/{goal_id}/cancel", response_model=AgentGoalRead)
@router.post("/haor/goals/{goal_id}/cancel", response_model=AgentGoalRead, include_in_schema=False)
def cancel_haor_goal(
    goal_id: str,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentGoalRead:
    try:
        return cancel_agent_goal(db, user=user, goal_id=goal_id)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="cancel_goal", user=user)


@router.post("/xuanwu/session/reset", response_model=AgentSessionRead)
@router.post("/haor/session/reset", response_model=AgentSessionRead, include_in_schema=False)
def reset_haor_session(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return reset_agent_session(db, user=user)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="reset_session", user=user)


@router.post("/xuanwu/session/recover", response_model=AgentSessionRead)
@router.post("/haor/session/recover", response_model=AgentSessionRead, include_in_schema=False)
def recover_haor_session(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return recover_agent_session(db, user=user)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="recover_session", user=user)


@router.post("/xuanwu/session/messages", response_model=AgentSessionRead)
@router.post("/haor/session/messages", response_model=AgentSessionRead, include_in_schema=False)
def send_haor_message(
    payload: AgentMessageCreateRequest,
    request: Request,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return post_agent_message(db, user=user, payload=payload, platform_url=_resolve_platform_url(request))
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="post_message", user=user)


@router.post("/xuanwu/session/steps", response_model=AgentSessionRead)
@router.post("/haor/session/steps", response_model=AgentSessionRead, include_in_schema=False)
def step_haor_session(
    payload: AgentUIStepRequest,
    request: Request,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return post_agent_step(db, user=user, payload=payload, platform_url=_resolve_platform_url(request))
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="post_step", user=user)


@router.post("/xuanwu/session/approve", response_model=AgentApprovalResponse, status_code=status.HTTP_202_ACCEPTED)
@router.post("/haor/session/approve", response_model=AgentApprovalResponse, status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
def approve_haor_session(
    payload: AgentApprovalRequest,
    request: Request,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_admin_user),
) -> AgentApprovalResponse:
    try:
        response = approve_agent_session(
            db,
            user=user,
            request=payload,
            platform_url=_resolve_platform_url(request),
        )
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="approve_session", user=user)

    celery_task = run_agent_orchestrate_task.delay(response.task_id, response.session_id)
    task_run = get_task_run(db, response.task_id)
    if task_run is not None:
        update_task_run(db, task_run, celery_task_id=celery_task.id)
    return response


@router.post("/xuanwu/session/interrupt", response_model=AgentSessionRead)
@router.post("/haor/session/interrupt", response_model=AgentSessionRead, include_in_schema=False)
def interrupt_haor_session(
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> AgentSessionRead:
    try:
        return interrupt_agent_session(db, user=user)
    except Exception as exc:
        _raise_agent_http_exception(exc, stage="interrupt_session", user=user)


@router.websocket("/xuanwu/session/stream")
@router.websocket("/haor/session/stream")
async def stream_haor_session(websocket: WebSocket) -> None:
    with SessionLocal() as db:
        user = await authenticate_websocket(
            websocket,
            resolve_actor=lambda token: _resolve_websocket_user(db, token),
        )
        if user is None:
            return
        user_id = user.id
        user_role = str(user.role.value if hasattr(user.role, "value") else user.role)
    task_monitor: asyncio.Task[None] | None = None
    monitored_task_id = ""

    async def stop_task_monitor() -> None:
        nonlocal task_monitor, monitored_task_id
        if task_monitor is None:
            return
        task_monitor.cancel()
        try:
            await task_monitor
        except asyncio.CancelledError:
            pass
        task_monitor = None
        monitored_task_id = ""

    async def ensure_task_monitor(task_id: str | None) -> None:
        nonlocal task_monitor, monitored_task_id
        normalized_task_id = str(task_id or "").strip()
        if not normalized_task_id:
            await stop_task_monitor()
            return
        if task_monitor is not None and monitored_task_id == normalized_task_id and not task_monitor.done():
            return
        await stop_task_monitor()
        monitored_task_id = normalized_task_id
        task_monitor = asyncio.create_task(_stream_task_updates(websocket, user_id=user_id, task_id=normalized_task_id))

    initial_session = await asyncio.to_thread(_load_ws_session_snapshot, user_id)
    await websocket.send_json({"type": "session_snapshot", "session": initial_session})
    await websocket.send_json({"type": "agent_state", "agent_state_json": initial_session.get("agent_state_json") or {}})
    await ensure_task_monitor(initial_session.get("last_task_id"))

    try:
        while True:
            try:
                raw_payload = await websocket.receive_json()
                frame = AgentStreamClientEnvelope.model_validate(raw_payload)
            except ValidationError as exc:
                await websocket.send_json(
                    AgentErrorEvent(
                        detail="当前流式请求格式不合法",
                        status_code=status.HTTP_400_BAD_REQUEST,
                    ).model_dump(mode="json")
                )
                logger.debug("Invalid haor stream payload: %s", exc)
                continue

            if frame.type == "ping":
                continue

            if frame.type == "hello":
                snapshot = await asyncio.to_thread(_load_ws_session_snapshot, user_id)
                await websocket.send_json({"type": "session_snapshot", "session": snapshot})
                await websocket.send_json({"type": "agent_state", "agent_state_json": snapshot.get("agent_state_json") or {}})
                await ensure_task_monitor(snapshot.get("last_task_id"))
                continue

            if frame.type == "approve_plan" and user_role != UserRole.ADMIN.value:
                await websocket.send_json(
                    AgentErrorEvent(
                        detail="当前账号不是管理员，不能确认执行",
                        status_code=status.HTTP_403_FORBIDDEN,
                    ).model_dump(mode="json")
                )
                continue

            turn_id = str(uuid4())
            result = await _run_stream_turn(
                websocket,
                user_id=user_id,
                stage=_frame_stage(frame.type),
                handler=_build_ws_turn_handler(
                    frame=frame,
                    turn_id=turn_id,
                    platform_url=_resolve_platform_url_from_websocket(websocket),
                ),
            )
            await ensure_task_monitor(_result_task_id(result))
    except WebSocketDisconnect:
        await stop_task_monitor()
        return
    finally:
        await stop_task_monitor()
        try:
            await websocket.close()
        except RuntimeError:
            pass


def _resolve_platform_url(request: Request) -> str:
    host = str(request.headers.get("x-platform-host") or "").strip()
    host_url = f"{'https' if host.endswith(':443') else request.url.scheme}://{host}".rstrip("/") if host else ""
    try:
        return resolve_runner_public_url(
            request.headers.get("x-platform-origin"),
            request.headers.get("origin"),
            host_url,
            str(request.base_url),
        )
    except RuntimeError:
        return str(request.base_url).rstrip("/")


def _resolve_platform_url_from_websocket(websocket: WebSocket) -> str:
    host = str(websocket.headers.get("x-platform-host") or "").strip()
    host_url = f"{'https' if host.endswith(':443') else websocket.url.scheme}://{host}".rstrip("/") if host else ""
    try:
        return resolve_runner_public_url(
            websocket.headers.get("x-platform-origin"),
            websocket.headers.get("origin"),
            host_url,
            f"{websocket.url.scheme}://{websocket.url.netloc}",
        )
    except RuntimeError:
        return f"{websocket.url.scheme}://{websocket.url.netloc}".rstrip("/")


def _resolve_websocket_user(db: Session, token: str) -> User | None:
    try:
        payload = decode_access_token(token)
    except SecurityError:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        return None
    return user


def _map_agent_exception(exc: Exception, *, stage: str, user: User | None) -> tuple[int, str]:
    if isinstance(exc, AgentServiceError):
        return exc.status_code, exc.detail
    if isinstance(exc, KeyError):
        logger.exception(
            "Unhandled haor endpoint key error",
            extra={
                "agent_stage": stage,
                "agent_user_id": getattr(user, "id", None),
                "agent_session_id": getattr(exc, "session_id", None),
            },
        )
        return status.HTTP_500_INTERNAL_SERVER_ERROR, "后端服务异常，请稍后重试"
    if isinstance(exc, (LookupError, RuntimeError, ValueError, httpx.HTTPError)):
        mapped = translate_agent_service_exception(exc, stage=stage)
        return mapped.status_code, mapped.detail
    logger.exception(
        "Unhandled haor endpoint error",
        extra={
            "agent_stage": stage,
            "agent_user_id": getattr(user, "id", None),
            "agent_session_id": getattr(exc, "session_id", None),
        },
    )
    return status.HTTP_500_INTERNAL_SERVER_ERROR, "后端服务异常，请稍后重试"


def _raise_agent_http_exception(exc: Exception, *, stage: str, user: User | None) -> None:
    status_code, detail = _map_agent_exception(exc, stage=stage, user=user)
    raise HTTPException(status_code=status_code, detail=detail) from exc


def _frame_stage(frame_type: str) -> str:
    if frame_type == "message":
        return "post_message"
    if frame_type == "ui_step":
        return "post_step"
    if frame_type == "approve_plan":
        return "approve_session"
    return "stream"


def _build_ws_turn_handler(
    *,
    frame: AgentStreamClientEnvelope,
    turn_id: str,
    platform_url: str,
):
    def _handler(db: Session, user: User, emit):  # type: ignore[no-untyped-def]
        if frame.type == "message":
            payload = AgentMessageCreateRequest(
                client_message_id=frame.client_message_id,
                content=frame.content or "",
                page_context=frame.page_context,
                browser_context=frame.browser_context,
            )
            return stream_agent_message_turn(
                db,
                user=user,
                payload=payload,
                platform_url=platform_url,
                turn_id=turn_id,
                client_message_id=frame.client_message_id,
                stream_emitter=emit,
            )
        if frame.type == "ui_step":
            payload = AgentUIStepRequest(
                step_request_id=frame.step_request_id,
                browser_context=frame.browser_context,
                ui_action_results=frame.ui_action_results,
            )
            return stream_agent_step_turn(
                db,
                user=user,
                payload=payload,
                platform_url=platform_url,
                turn_id=turn_id,
                stream_emitter=emit,
            )
        if frame.type == "approve_plan":
            response = stream_agent_approve_turn(
                db,
                user=user,
                request=AgentApprovalRequest(note=frame.note),
                platform_url=platform_url,
                turn_id=turn_id,
                stream_emitter=emit,
            )
            celery_task = run_agent_orchestrate_task.delay(response.task_id, response.session_id)
            task_run = get_task_run(db, response.task_id)
            if task_run is not None:
                update_task_run(db, task_run, celery_task_id=celery_task.id)
            return response
        return None

    return _handler


async def _run_stream_turn(websocket: WebSocket, *, user_id: str, stage: str, handler):  # type: ignore[no-untyped-def]
    queue: asyncio.Queue[dict] = asyncio.Queue()
    loop = asyncio.get_running_loop()
    outcome: dict[str, object] = {}
    sentinel = {"type": "__stream_turn_complete__"}

    def emit(payload: dict) -> None:
        loop.call_soon_threadsafe(queue.put_nowait, payload)

    def worker() -> None:
        with SessionLocal() as db:
            user = db.get(User, user_id)
            if user is None or not user.is_active:
                emit(
                    AgentErrorEvent(
                        detail=f"当前 {AGENT_DISPLAY_NAME} 会话用户不可用",
                        status_code=status.HTTP_404_NOT_FOUND,
                    ).model_dump(mode="json")
                )
                return
            try:
                outcome["result"] = handler(db, user, emit)
            except Exception as exc:  # noqa: BLE001
                status_code, detail = _map_agent_exception(exc, stage=stage, user=user)
                emit(AgentErrorEvent(detail=detail, status_code=status_code).model_dump(mode="json"))
            finally:
                emit(sentinel)

    task = asyncio.create_task(asyncio.to_thread(worker))
    while True:
        payload = await queue.get()
        if payload == sentinel:
            break
        await websocket.send_json(payload)
    await task
    return outcome.get("result")


def _load_ws_session_snapshot(user_id: str) -> dict:
    with SessionLocal() as db:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            return {}
        return recover_agent_session(db, user=user).model_dump(mode="json")


def _session_snapshot_has_task_followup(session_snapshot: dict | None, *, task_id: str) -> bool:
    if not isinstance(session_snapshot, dict):
        return False
    messages = session_snapshot.get("messages") if isinstance(session_snapshot.get("messages"), list) else []
    normalized_task_id = str(task_id or "").strip()
    if not normalized_task_id:
        return False
    for item in reversed(messages[-12:]):
        if not isinstance(item, dict):
            continue
        payload = item.get("payload_json") if isinstance(item.get("payload_json"), dict) else {}
        if str(payload.get("task_id") or "").strip() != normalized_task_id:
            continue
        if payload.get("auto_followup"):
            return True
    return False


async def _await_terminal_session_snapshot(user_id: str, task_id: str, initial_snapshot: dict | None) -> dict:
    latest_snapshot = initial_snapshot if isinstance(initial_snapshot, dict) else {}
    if _session_snapshot_has_task_followup(latest_snapshot, task_id=task_id):
        return latest_snapshot
    for _ in range(5):
        await asyncio.sleep(0.3)
        candidate = await asyncio.to_thread(_load_ws_session_snapshot, user_id)
        if isinstance(candidate, dict) and candidate:
            latest_snapshot = candidate
            if _session_snapshot_has_task_followup(candidate, task_id=task_id):
                return candidate
    return latest_snapshot


async def _stream_task_updates(websocket: WebSocket, *, user_id: str, task_id: str) -> None:
    last_signature: tuple[str, int | None, str | None] | None = None
    try:
        while True:
            payload = await asyncio.to_thread(_load_ws_task_payload, user_id, task_id)
            if not payload:
                return
            if payload.get("missing"):
                await websocket.send_json(
                    AgentErrorEvent(
                        detail="当前关联任务不存在",
                        status_code=status.HTTP_404_NOT_FOUND,
                    ).model_dump(mode="json")
                )
                return
            signature = (
                str(payload.get("status") or ""),
                payload.get("progress") if isinstance(payload.get("progress"), int) else None,
                str(payload.get("message") or "") or None,
            )
            if signature != last_signature:
                last_signature = signature
                await websocket.send_json(
                    AgentTaskUpdateEvent(
                        task_id=task_id,
                        status=str(payload.get("status") or ""),
                        progress=payload.get("progress") if isinstance(payload.get("progress"), int) else None,
                        message=str(payload.get("message") or "") or None,
                    ).model_dump(mode="json")
                )
            if payload.get("terminal"):
                session_snapshot = payload.get("session_snapshot")
                if isinstance(session_snapshot, dict) and session_snapshot:
                    session_snapshot = await _await_terminal_session_snapshot(user_id, task_id, session_snapshot)
                    await websocket.send_json({"type": "session_snapshot", "session": session_snapshot})
                    await websocket.send_json(
                        {"type": "agent_state", "agent_state_json": session_snapshot.get("agent_state_json") or {}}
                    )
                return
            await asyncio.sleep(0.8)
    except asyncio.CancelledError:
        return


def _load_ws_task_payload(user_id: str, task_id: str) -> dict:
    with SessionLocal() as db:
        task = get_task_run(db, task_id)
        if task is None:
            return {"missing": True}
        user = db.get(User, user_id)
        session_snapshot: dict | None = None
        if user is not None and user.is_active:
            session_snapshot = get_or_create_agent_session(db, user=user).model_dump(mode="json")
        terminal = str(task.status.value if hasattr(task.status, "value") else task.status) in {
            "success",
            "failure",
            "canceled",
        }
        return {
            "task_id": task.id,
            "status": task.status.value if hasattr(task.status, "value") else str(task.status),
            "progress": task.progress,
            "message": task.message,
            "terminal": terminal,
            "session_snapshot": session_snapshot,
        }


def _result_task_id(result: object) -> str | None:
    if isinstance(result, AgentSessionRead):
        return result.last_task_id
    if isinstance(result, AgentApprovalResponse):
        return result.task_id
    return None
