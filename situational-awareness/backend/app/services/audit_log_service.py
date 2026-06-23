from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from starlette.requests import Request

from app.core.config import settings
from app.core.security import SecurityError, decode_access_token
from app.db.models.audit_log_entry import AuditLogEntry
from app.db.session import SessionLocal, engine
from app.services.client_ip_service import resolve_client_ip as resolve_trusted_client_ip
from app.services.platform_log_service import redact_sensitive_json_value, redact_sensitive_text


@dataclass(frozen=True, slots=True)
class AuditActor:
    user_id: str | None
    role: str | None


@dataclass(frozen=True, slots=True)
class AuditResource:
    action: str
    resource_type: str | None
    resource_id: str | None


class StrictAuditError(RuntimeError):
    pass


def ensure_audit_log_storage() -> None:
    try:
        AuditLogEntry.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        return


def should_audit_request(request: Request) -> bool:
    path = request.url.path
    if path == "/health":
        return False
    if path in {"/docs", "/redoc", "/openapi.json"}:
        return False
    return path.startswith(settings.API_V1_PREFIX)


def should_strict_audit_request(request: Request) -> bool:
    if not should_audit_request(request):
        return False
    method = str(request.method or "").upper()
    path = str(request.url.path or "").rstrip("/")
    prefix = settings.API_V1_PREFIX.rstrip("/")

    if method == "GET" and path.startswith(f"{prefix}/data-exchange/export/"):
        return True
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    if path in {
        f"{prefix}/agent/xuanwu/session/approve",
        f"{prefix}/agent/haor/session/approve",
        f"{prefix}/data-exchange/servers/import",
        f"{prefix}/settings/security/secret-cipher-migration",
    }:
        return True
    if path.startswith(f"{prefix}/auth/users/") and path.endswith("/sessions/revoke"):
        return True
    if path.startswith(f"{prefix}/remediation/findings/") and path.endswith("/execute"):
        return True
    if path.startswith(f"{prefix}/remediation/assets/") and path.endswith("/runner/install"):
        return True
    if path.startswith(f"{prefix}/remediation/assets/") and path.endswith("/terminal/tickets"):
        return True
    if path.startswith(f"{prefix}/collection/") and _path_has_any_segment(path, {"credential", "credentials"}):
        return True
    if path.startswith(f"{prefix}/campus/data-sources"):
        return True
    return False


def new_request_id(request: Request) -> str:
    request_id = str(request.headers.get("x-request-id") or "").strip()
    if request_id:
        return request_id[:64]
    return str(uuid4())


def resolve_audit_actor(request: Request) -> AuditActor:
    token = _extract_bearer_token(request.headers.get("authorization") or "")
    if not token:
        return AuditActor(user_id=None, role=None)
    try:
        payload = decode_access_token(token)
    except SecurityError:
        return AuditActor(user_id=None, role=None)
    return AuditActor(
        user_id=str(payload.get("sub") or "").strip() or None,
        role=str(payload.get("role") or "").strip() or None,
    )


def resolve_client_ip(request: Request) -> str | None:
    client_host = request.client.host if request.client is not None else None
    resolved = resolve_trusted_client_ip(request.headers, client_host)
    return resolved[:64] if resolved else None


def resolve_audit_resource(method: str, path: str) -> AuditResource:
    segments = [part for part in path.split("/") if part]
    api_prefix = [part for part in settings.API_V1_PREFIX.split("/") if part]
    if segments[: len(api_prefix)] == api_prefix:
        segments = segments[len(api_prefix) :]

    resource_type = segments[0] if segments else "system"
    resource_id = _resolve_resource_id(segments)
    action_parts = [method.lower()]
    action_parts.extend(segments[:2] or ["system"])
    return AuditResource(
        action=":".join(action_parts)[:128],
        resource_type=resource_type[:64] if resource_type else None,
        resource_id=resource_id[:128] if resource_id else None,
    )


def build_query_payload(request: Request) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for key, value in request.query_params.multi_items():
        if key in payload:
            existing = payload[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                payload[key] = [existing, value]
        else:
            payload[key] = value
    return redact_sensitive_json_value(payload)


def resolve_outcome(status_code: int, *, rate_limited: bool = False) -> str:
    if rate_limited:
        return "rate_limited"
    if status_code >= 500:
        return "server_error"
    if status_code >= 400:
        return "client_error"
    return "success"


def monotonic_ms(started_at: float) -> int:
    return max(0, int((time.perf_counter() - started_at) * 1000))


def write_audit_log(
    *,
    request: Request,
    request_id: str,
    status_code: int,
    duration_ms: int,
    rate_limited: bool = False,
    error_message: str | None = None,
    payload_json: dict[str, Any] | None = None,
    strict: bool = False,
) -> None:
    if not should_audit_request(request):
        return
    actor = resolve_audit_actor(request)
    resource = resolve_audit_resource(request.method, request.url.path)
    user_agent = str(request.headers.get("user-agent") or "").strip()[:512] or None
    with SessionLocal() as db:
        try:
            db.add(
                AuditLogEntry(
                    request_id=request_id,
                    actor_user_id=actor.user_id,
                    actor_role=actor.role,
                    client_ip=resolve_client_ip(request),
                    user_agent=user_agent,
                    method=request.method.upper()[:8],
                    path=request.url.path[:512],
                    action=resource.action,
                    resource_type=resource.resource_type,
                    resource_id=resource.resource_id,
                    status_code=status_code,
                    outcome=resolve_outcome(status_code, rate_limited=rate_limited),
                    duration_ms=duration_ms,
                    query_json=build_query_payload(request),
                    payload_json=redact_sensitive_json_value(payload_json or {}),
                    error_message=redact_sensitive_text(error_message) if error_message else None,
                    created_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        except Exception:
            db.rollback()
            if strict:
                raise StrictAuditError("审计日志写入失败，已阻断高危操作")


def write_strict_audit_log(
    *,
    request: Request,
    request_id: str,
    status_code: int,
    duration_ms: int,
    error_message: str | None = None,
    payload_json: dict[str, Any] | None = None,
) -> None:
    write_audit_log(
        request=request,
        request_id=request_id,
        status_code=status_code,
        duration_ms=duration_ms,
        error_message=error_message,
        payload_json=payload_json,
        strict=True,
    )


def serialize_audit_log_entry(entry: AuditLogEntry) -> dict[str, Any]:
    return {
        "id": entry.id,
        "request_id": entry.request_id,
        "actor_user_id": entry.actor_user_id,
        "actor_role": entry.actor_role,
        "client_ip": entry.client_ip,
        "user_agent": entry.user_agent,
        "method": entry.method,
        "path": entry.path,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "status_code": entry.status_code,
        "outcome": entry.outcome,
        "duration_ms": entry.duration_ms,
        "query_json": entry.query_json if isinstance(entry.query_json, dict) else {},
        "payload_json": entry.payload_json if isinstance(entry.payload_json, dict) else {},
        "error_message": entry.error_message,
        "created_at": entry.created_at,
    }


def _extract_bearer_token(value: str) -> str:
    prefix = "bearer "
    normalized = str(value or "").strip()
    if normalized.lower().startswith(prefix):
        return normalized[len(prefix) :].strip()
    return ""


def _resolve_resource_id(segments: list[str]) -> str | None:
    if len(segments) < 2:
        return None
    for item in segments[1:]:
        if item in {"status", "summary", "overview", "stream", "logs", "me", "health"}:
            continue
        return item
    return None


def _path_has_any_segment(path: str, candidates: set[str]) -> bool:
    return any(part in candidates for part in path.split("/") if part)
