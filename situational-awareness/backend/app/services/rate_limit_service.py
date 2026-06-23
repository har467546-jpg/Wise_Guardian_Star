from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from typing import Any

import redis.asyncio as redis_async
from starlette.requests import Request

from app.core.config import settings
from app.core.security import SecurityError, decode_access_token


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_after_seconds: int
    key: str
    identifier: str


_redis_client: redis_async.Redis | None = None
_local_lock = threading.Lock()
_local_windows: dict[str, tuple[int, int]] = {}


def _split_csv(value: str) -> set[str]:
    return {item.strip() for item in str(value or "").split(",") if item.strip()}


def should_skip_rate_limit(request: Request) -> bool:
    if not settings.RATE_LIMIT_ENABLED:
        return True
    if request.method.upper() == "OPTIONS":
        return True
    path = request.url.path
    if path in _split_csv(settings.RATE_LIMIT_EXEMPT_PATHS):
        return True
    return False


async def check_rate_limit(request: Request) -> RateLimitDecision:
    limit = _resolve_limit(request)
    window_seconds = max(1, int(settings.RATE_LIMIT_WINDOW_SECONDS))
    now = int(time.time())
    window_id = now // window_seconds
    reset_at = (window_id + 1) * window_seconds
    identifier = _resolve_identifier(request)
    key = _build_key(identifier, window_id)

    try:
        client = _get_redis_client()
        count = int(await client.incr(key))
        if count == 1:
            await client.expire(key, window_seconds + 5)
    except Exception:
        count = _increment_local_window(key, window_id)

    remaining = max(0, limit - count)
    return RateLimitDecision(
        allowed=count <= limit,
        limit=limit,
        remaining=remaining,
        reset_after_seconds=max(1, reset_at - now),
        key=key,
        identifier=identifier,
    )


async def close_rate_limit_client() -> None:
    global _redis_client
    if _redis_client is None:
        return
    client = _redis_client
    _redis_client = None
    await client.aclose()


def build_rate_limit_headers(decision: RateLimitDecision) -> dict[str, str]:
    headers = {
        "X-RateLimit-Limit": str(decision.limit),
        "X-RateLimit-Remaining": str(decision.remaining),
        "X-RateLimit-Reset": str(decision.reset_after_seconds),
    }
    if not decision.allowed:
        headers["Retry-After"] = str(decision.reset_after_seconds)
    return headers


def _resolve_limit(request: Request) -> int:
    path = request.url.path
    if path.startswith(f"{settings.API_V1_PREFIX}/auth/"):
        return max(1, int(settings.RATE_LIMIT_AUTH_PER_MINUTE))
    return max(1, int(settings.RATE_LIMIT_PER_MINUTE))


def _resolve_identifier(request: Request) -> str:
    token = _extract_bearer_token(request.headers.get("authorization") or "")
    if token:
        try:
            payload = decode_access_token(token)
            subject = str(payload.get("sub") or "").strip()
            if subject:
                return f"user:{subject}"
        except SecurityError:
            pass
    return f"ip:{_resolve_client_ip(request)}"


def _extract_bearer_token(value: str) -> str:
    prefix = "bearer "
    normalized = str(value or "").strip()
    if normalized.lower().startswith(prefix):
        return normalized[len(prefix) :].strip()
    return ""


def _resolve_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        first = forwarded_for.split(",", 1)[0].strip()
        if first:
            return first
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    client = request.client
    return client.host if client is not None else "unknown"


def _build_key(identifier: str, window_id: int) -> str:
    digest = hashlib.sha256(identifier.encode()).hexdigest()[:32]
    prefix = str(settings.RATE_LIMIT_REDIS_PREFIX or "sa:rate_limit").strip() or "sa:rate_limit"
    return f"{prefix}:{digest}:{window_id}"


def _get_redis_client() -> redis_async.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_async.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


def _increment_local_window(key: str, window_id: int) -> int:
    with _local_lock:
        stale_keys = [item_key for item_key, (_, item_window_id) in _local_windows.items() if item_window_id != window_id]
        for stale_key in stale_keys[:1000]:
            _local_windows.pop(stale_key, None)
        current, _ = _local_windows.get(key, (0, window_id))
        current += 1
        _local_windows[key] = (current, window_id)
        return current

