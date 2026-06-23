from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

import redis.asyncio as redis_async
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.core.config import settings
from app.core.security import SecurityError, decode_access_token
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.audit_log_repo import list_audit_log_entries
from app.repositories.platform_log_repo import list_platform_log_entries
from app.schemas.common import PageMeta
from app.schemas.logs import AuditLogEntryListResponse, AuditLogEntryRead, LogEntryListResponse, LogEntryRead
from app.services.audit_log_service import serialize_audit_log_entry
from app.services.platform_log_service import (
    DEFAULT_LOG_HEARTBEAT_SECONDS,
    PLATFORM_LOG_CHANNEL,
    log_entry_matches_filters,
    normalize_log_level,
    serialize_platform_log_entry,
)

router = APIRouter()


@dataclass(slots=True)
class LogStreamFilters:
    source_kind: str | None
    service_name: str | None
    task_id: str | None
    task_type: str | None
    level: str | None
    keyword: str | None
    page_size: int


def _normalize_source_kind(value: object) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if normalized not in {"system", "task_raw"}:
        raise ValueError("日志来源无效")
    return normalized


def _normalize_service_name(value: object) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if normalized not in {"backend", "worker"}:
        raise ValueError("服务名称无效")
    return normalized


def _normalize_task_type(value: object) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _normalize_level(value: object) -> str | None:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    if normalized not in {"info", "warning", "error", "warn", "critical", "fatal", "exception"}:
        raise ValueError("日志级别无效")
    return normalize_log_level(normalized)


def _build_log_filters(
    *,
    source_kind: object = None,
    service_name: object = None,
    task_id: object = None,
    task_type: object = None,
    level: object = None,
    keyword: object = None,
    page_size: object = None,
) -> LogStreamFilters:
    try:
        normalized_page_size = max(1, min(int(page_size or 100), 200))
    except (TypeError, ValueError):
        normalized_page_size = 100
    return LogStreamFilters(
        source_kind=_normalize_source_kind(source_kind),
        service_name=_normalize_service_name(service_name),
        task_id=str(task_id or "").strip() or None,
        task_type=_normalize_task_type(task_type),
        level=_normalize_level(level),
        keyword=str(keyword or "").strip() or None,
        page_size=normalized_page_size,
    )


def _resolve_websocket_admin(db: Session, token: str) -> User | None:
    try:
        payload = decode_access_token(token)
    except SecurityError:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active or str(user.role.value if hasattr(user.role, "value") else user.role) != "admin":
        return None
    return user


@router.get("", response_model=LogEntryListResponse)
def get_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    source_kind: str | None = Query(default=None),
    service_name: str | None = Query(default=None),
    task_id: str | None = Query(default=None),
    task_type: str | None = Query(default=None),
    level: str | None = Query(default=None),
    keyword: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> LogEntryListResponse:
    try:
        filters = _build_log_filters(
            source_kind=source_kind,
            service_name=service_name,
            task_id=task_id,
            task_type=task_type,
            level=level,
            keyword=keyword,
            page_size=page_size,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    items, total = list_platform_log_entries(
        db,
        page=page,
        page_size=page_size,
        source_kind=filters.source_kind,
        service_name=filters.service_name,
        task_id=filters.task_id,
        task_type=filters.task_type,
        level=filters.level,
        keyword=filters.keyword,
    )
    return LogEntryListResponse(
        items=[LogEntryRead.model_validate(item) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/audit", response_model=AuditLogEntryListResponse)
def get_audit_logs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
    actor_user_id: str | None = Query(default=None),
    method: str | None = Query(default=None),
    path: str | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    status_code: int | None = Query(default=None, ge=100, le=599),
    keyword: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> AuditLogEntryListResponse:
    items, total = list_audit_log_entries(
        db,
        page=page,
        page_size=page_size,
        actor_user_id=actor_user_id,
        method=method.upper() if method else None,
        path=path,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
        status_code=status_code,
        keyword=keyword,
    )
    return AuditLogEntryListResponse(
        items=[AuditLogEntryRead.model_validate(serialize_audit_log_entry(item)) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.websocket("/stream")
async def stream_logs(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token") or ""
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return

    with SessionLocal() as db:
        if _resolve_websocket_admin(db, token) is None:
            await websocket.close(code=1008, reason="unauthorized")
            return

    await websocket.accept()
    try:
        filters = _build_log_filters(
            source_kind=websocket.query_params.get("source_kind"),
            service_name=websocket.query_params.get("service_name"),
            task_id=websocket.query_params.get("task_id"),
            task_type=websocket.query_params.get("task_type"),
            level=websocket.query_params.get("level"),
            keyword=websocket.query_params.get("keyword"),
            page_size=websocket.query_params.get("page_size") or 100,
        )
    except ValueError as exc:
        await websocket.send_json({"type": "error", "detail": str(exc)})
        await websocket.close(code=1008)
        return

    with SessionLocal() as db:
        snapshot_items, total = list_platform_log_entries(
            db,
            page=1,
            page_size=filters.page_size,
            source_kind=filters.source_kind,
            service_name=filters.service_name,
            task_id=filters.task_id,
            task_type=filters.task_type,
            level=filters.level,
            keyword=filters.keyword,
        )
        await websocket.send_json(
            {
                "type": "snapshot",
                "items": [LogEntryRead.model_validate(item).model_dump(mode="json") for item in snapshot_items],
                "meta": {"total": total, "page": 1, "page_size": filters.page_size},
            }
        )

    redis_client = redis_async.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = redis_client.pubsub()
    try:
        await pubsub.subscribe(PLATFORM_LOG_CHANNEL)
        last_heartbeat = time.monotonic()
        while True:
            try:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                await websocket.send_json({"type": "error", "detail": f"日志实时通道异常: {exc}"})
                return

            if message and message.get("type") == "message":
                try:
                    payload = json.loads(str(message.get("data") or "{}"))
                except json.JSONDecodeError:
                    payload = {}
                if payload and log_entry_matches_filters(
                    payload,
                    source_kind=filters.source_kind,
                    service_name=filters.service_name,
                    task_id=filters.task_id,
                    task_type=filters.task_type,
                    level=filters.level,
                    keyword=filters.keyword,
                ):
                    await websocket.send_json(
                        {
                            "type": "log_append",
                            "item": LogEntryRead.model_validate(serialize_platform_log_entry(payload)).model_dump(mode="json"),
                        }
                    )

            if time.monotonic() - last_heartbeat >= DEFAULT_LOG_HEARTBEAT_SECONDS:
                await websocket.send_json(
                    {
                        "type": "heartbeat",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                last_heartbeat = time.monotonic()
    except WebSocketDisconnect:
        return
    finally:
        try:
            await pubsub.unsubscribe(PLATFORM_LOG_CHANNEL)
        except Exception:
            pass
        try:
            await pubsub.aclose()
        except Exception:
            pass
        try:
            await redis_client.aclose()
        except Exception:
            pass
