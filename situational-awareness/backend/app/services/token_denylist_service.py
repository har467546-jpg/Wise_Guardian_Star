from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from redis import Redis

from app.core.config import settings


def denylist_token_payload(payload: dict[str, Any]) -> bool:
    if not settings.SECURITY_TOKEN_DENYLIST_ENABLED:
        return False
    jti = str(payload.get("jti") or "").strip()
    if not jti:
        return False
    ttl = _seconds_until_expiry(payload.get("exp"))
    if ttl <= 0:
        return False
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        return bool(client.set(_denylist_key(jti), "1", ex=ttl))
    finally:
        client.close()


def is_token_payload_denied(payload: dict[str, Any]) -> bool:
    if not settings.SECURITY_TOKEN_DENYLIST_ENABLED:
        return False
    jti = str(payload.get("jti") or "").strip()
    if not jti:
        return False
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        return bool(client.exists(_denylist_key(jti)))
    except Exception:
        return False
    finally:
        client.close()


def _seconds_until_expiry(value: Any) -> int:
    if isinstance(value, datetime):
        expire_at = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return max(0, int((expire_at.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds()))
    try:
        return max(0, int(float(value) - datetime.now(timezone.utc).timestamp()))
    except (TypeError, ValueError):
        return 0


def _denylist_key(jti: str) -> str:
    prefix = str(settings.SECURITY_TOKEN_DENYLIST_REDIS_PREFIX or "sa:token_denylist").strip() or "sa:token_denylist"
    return f"{prefix}:{jti}"
