from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import uuid4

from redis import Redis

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class WebSocketTicketClaims:
    ticket: str
    user_id: str
    role: str
    resource_type: str
    resource_id: str


def issue_websocket_ticket(*, user_id: str, role: str, resource_type: str, resource_id: str) -> WebSocketTicketClaims:
    ticket = uuid4().hex
    claims = WebSocketTicketClaims(
        ticket=ticket,
        user_id=str(user_id),
        role=str(role),
        resource_type=str(resource_type),
        resource_id=str(resource_id),
    )
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.set(_ticket_key(ticket), json.dumps(_claims_to_payload(claims), ensure_ascii=False), ex=websocket_ticket_ttl_seconds())
    finally:
        client.close()
    return claims


def consume_websocket_ticket(*, ticket: str, resource_type: str, resource_id: str) -> WebSocketTicketClaims | None:
    normalized_ticket = str(ticket or "").strip()
    if not normalized_ticket:
        return None
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw_payload = client.getdel(_ticket_key(normalized_ticket))
    finally:
        client.close()
    if not raw_payload:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    claims = WebSocketTicketClaims(
        ticket=normalized_ticket,
        user_id=str(payload.get("user_id") or ""),
        role=str(payload.get("role") or ""),
        resource_type=str(payload.get("resource_type") or ""),
        resource_id=str(payload.get("resource_id") or ""),
    )
    if claims.resource_type != resource_type or claims.resource_id != resource_id:
        return None
    if not claims.user_id or not claims.role:
        return None
    return claims


def websocket_ticket_ttl_seconds() -> int:
    return max(1, int(settings.SECURITY_WS_TICKET_TTL_SECONDS))


def _ticket_key(ticket: str) -> str:
    prefix = str(settings.SECURITY_WS_TICKET_REDIS_PREFIX or "sa:ws_ticket").strip() or "sa:ws_ticket"
    return f"{prefix}:{ticket}"


def _claims_to_payload(claims: WebSocketTicketClaims) -> dict[str, str]:
    return {
        "user_id": claims.user_id,
        "role": claims.role,
        "resource_type": claims.resource_type,
        "resource_id": claims.resource_id,
    }
