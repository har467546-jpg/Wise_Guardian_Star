from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.user import User


@dataclass(frozen=True)
class UserAuthState:
    user_id: str
    role: str
    is_active: bool
    cached_at: float


def get_user_auth_state(db: Session, user_id: str) -> UserAuthState | None:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    cached = _read_cached_state(normalized_user_id)
    if cached is not None:
        return cached

    user = db.get(User, normalized_user_id)
    if user is None:
        state = UserAuthState(user_id=normalized_user_id, role="", is_active=False, cached_at=time.time())
    else:
        state = UserAuthState(
            user_id=user.id,
            role=str(user.role.value if hasattr(user.role, "value") else user.role),
            is_active=bool(user.is_active),
            cached_at=time.time(),
        )
    _write_cached_state(state)
    return state


def invalidate_user_auth_state(user_id: str) -> None:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.delete(_user_state_key(normalized_user_id))
    finally:
        client.close()


def revoke_user_tokens(user_id: str) -> bool:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return False
    ttl = max(60, int(settings.REFRESH_TOKEN_EXPIRE_DAYS) * 24 * 60 * 60)
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.set(_user_revoked_after_key(normalized_user_id), str(time.time()), ex=ttl)
        client.delete(_user_state_key(normalized_user_id))
        return True
    finally:
        client.close()


def is_user_token_revoked(user_id: str, issued_at: Any) -> bool:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return True
    issued_at_ts = _coerce_timestamp(issued_at)
    if issued_at_ts <= 0:
        return False
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = client.get(_user_revoked_after_key(normalized_user_id))
    except Exception:
        return False
    finally:
        client.close()
    revoked_after = _coerce_timestamp(raw)
    return revoked_after > 0 and issued_at_ts <= revoked_after


def resolve_active_user_from_token_payload(db: Session, payload: dict[str, Any]) -> User | None:
    user_id = str(payload.get("sub") or "").strip()
    if not user_id:
        return None
    if is_user_token_revoked(user_id, payload.get("iat")):
        return None
    state = get_user_auth_state(db, user_id)
    if state is None or not state.is_active:
        return None
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        invalidate_user_auth_state(user_id)
        return None
    return user


def _read_cached_state(user_id: str) -> UserAuthState | None:
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = client.get(_user_state_key(user_id))
    except Exception:
        return None
    finally:
        client.close()
    if not raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return UserAuthState(
        user_id=str(payload.get("user_id") or user_id),
        role=str(payload.get("role") or ""),
        is_active=bool(payload.get("is_active")),
        cached_at=float(payload.get("cached_at") or 0),
    )


def _write_cached_state(state: UserAuthState) -> None:
    ttl = max(1, int(settings.SECURITY_USER_STATE_CACHE_TTL_SECONDS or 60))
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.setex(
            _user_state_key(state.user_id),
            ttl,
            json.dumps(
                {
                    "user_id": state.user_id,
                    "role": state.role,
                    "is_active": state.is_active,
                    "cached_at": state.cached_at,
                },
                separators=(",", ":"),
            ),
        )
    except Exception:
        return
    finally:
        client.close()


def _coerce_timestamp(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _user_state_key(user_id: str) -> str:
    prefix = str(settings.SECURITY_USER_STATE_CACHE_PREFIX or "sa:user_state").strip() or "sa:user_state"
    return f"{prefix}:{user_id}"


def _user_revoked_after_key(user_id: str) -> str:
    prefix = str(settings.SECURITY_USER_REVOKED_AFTER_PREFIX or "sa:user_revoked_after").strip() or "sa:user_revoked_after"
    return f"{prefix}:{user_id}"
