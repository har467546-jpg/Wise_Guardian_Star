from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from redis import Redis
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import SecurityError, create_access_token, create_refresh_token, decode_refresh_token
from app.services.token_denylist_service import _seconds_until_expiry
from app.services.user_state_cache_service import get_user_auth_state, is_user_token_revoked


class RefreshTokenError(Exception):
    pass


class RefreshTokenReplayError(RefreshTokenError):
    pass


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 0
    refresh_expires_in: int = 0


def issue_token_pair(*, user_id: str, role: str) -> TokenPair:
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        raise RefreshTokenError("Invalid user")
    normalized_role = str(role or "").strip()
    refresh_token = create_refresh_token(subject=normalized_user_id, extra={"role": normalized_role})
    refresh_payload = decode_refresh_token(refresh_token, verify_denylist=False)
    access_token = create_access_token(subject=normalized_user_id, extra={"role": normalized_role})
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        _store_active_refresh_token(client, refresh_payload, role=normalized_role)
    finally:
        client.close()
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=max(1, int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60),
        refresh_expires_in=_seconds_until_expiry(refresh_payload.get("exp")),
    )


def rotate_refresh_token(db: Session, refresh_token: str) -> TokenPair:
    try:
        payload = decode_refresh_token(refresh_token, verify_denylist=False)
    except SecurityError as exc:
        raise RefreshTokenError("Refresh token invalid") from exc

    user_id = str(payload.get("sub") or "").strip()
    family_id = str(payload.get("family_id") or "").strip()
    jti = str(payload.get("jti") or "").strip()
    if not user_id or not family_id or not jti:
        raise RefreshTokenError("Refresh token invalid")
    if is_user_token_revoked(user_id, payload.get("iat")):
        raise RefreshTokenError("User session revoked")
    state = get_user_auth_state(db, user_id)
    if state is None or not state.is_active:
        raise RefreshTokenError("User disabled")
    role = state.role or str(payload.get("role") or "")

    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    lock_value = uuid4().hex
    lock_key = _refresh_lock_key(jti)
    grace_seconds = _refresh_grace_seconds()
    try:
        if _family_is_revoked(client, family_id):
            raise RefreshTokenError("Refresh token family revoked")
        if not _acquire_rotation_lock(client, lock_key, lock_value, grace_seconds):
            time.sleep(0.05)
            return _rotate_from_existing_record(
                client,
                user_id=user_id,
                role=role,
                family_id=family_id,
                payload=payload,
                allow_active=False,
            )
        try:
            return _rotate_from_existing_record(
                client,
                user_id=user_id,
                role=role,
                family_id=family_id,
                payload=payload,
                allow_active=True,
            )
        finally:
            _release_rotation_lock(client, lock_key, lock_value)
    finally:
        client.close()


def revoke_refresh_token(refresh_token: str) -> bool:
    try:
        payload = decode_refresh_token(refresh_token, verify_denylist=False)
    except SecurityError:
        return False
    family_id = str(payload.get("family_id") or "").strip()
    jti = str(payload.get("jti") or "").strip()
    ttl = _seconds_until_expiry(payload.get("exp"))
    if not family_id or ttl <= 0:
        return False
    client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        client.set(_family_revoked_key(family_id), "1", ex=ttl)
        if jti:
            client.set(_refresh_token_key(jti), _dump_record({"status": "revoked", "family_id": family_id}), ex=ttl)
        return True
    finally:
        client.close()


def _rotate_from_existing_record(
    client: Redis,
    *,
    user_id: str,
    role: str,
    family_id: str,
    payload: dict[str, Any],
    allow_active: bool,
) -> TokenPair:
    jti = str(payload.get("jti") or "").strip()
    key = _refresh_token_key(jti)
    record = _load_record(client, key)
    if not record:
        _revoke_family(client, family_id, payload)
        raise RefreshTokenReplayError("Refresh token replay detected")

    status = str(record.get("status") or "").strip().lower()
    if status == "active":
        if not allow_active:
            raise RefreshTokenError("Refresh token rotation in progress")
        return _rotate_active_record(
            client,
            old_key=key,
            old_payload=payload,
            user_id=user_id,
            role=role,
            family_id=family_id,
        )

    if status == "rotated":
        grace_until = _coerce_float(record.get("grace_until"))
        replacement_refresh_token = str(record.get("replacement_refresh_token") or "").strip()
        if replacement_refresh_token and time.time() <= grace_until:
            replacement_payload = decode_refresh_token(replacement_refresh_token, verify_denylist=False)
            access_token = create_access_token(subject=user_id, extra={"role": role})
            return TokenPair(
                access_token=access_token,
                refresh_token=replacement_refresh_token,
                expires_in=max(1, int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60),
                refresh_expires_in=_seconds_until_expiry(replacement_payload.get("exp")),
            )
        _revoke_family(client, family_id, payload)
        raise RefreshTokenReplayError("Refresh token replay detected")

    raise RefreshTokenError("Refresh token revoked")


def _rotate_active_record(
    client: Redis,
    *,
    old_key: str,
    old_payload: dict[str, Any],
    user_id: str,
    role: str,
    family_id: str,
) -> TokenPair:
    grace_seconds = _refresh_grace_seconds()
    new_refresh_token = create_refresh_token(subject=user_id, family_id=family_id, extra={"role": role})
    new_payload = decode_refresh_token(new_refresh_token, verify_denylist=False)
    new_jti = str(new_payload.get("jti") or "").strip()
    access_token = create_access_token(subject=user_id, extra={"role": role})
    _store_active_refresh_token(client, new_payload, role=role)
    client.set(
        old_key,
        _dump_record(
            {
                "status": "rotated",
                "user_id": user_id,
                "family_id": family_id,
                "rotated_to": new_jti,
                "replacement_refresh_token": new_refresh_token,
                "grace_until": time.time() + grace_seconds,
            }
        ),
        ex=grace_seconds + 1,
    )
    return TokenPair(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=max(1, int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60),
        refresh_expires_in=_seconds_until_expiry(new_payload.get("exp")),
    )


def _store_active_refresh_token(client: Redis, payload: dict[str, Any], *, role: str) -> None:
    jti = str(payload.get("jti") or "").strip()
    ttl = _seconds_until_expiry(payload.get("exp"))
    if not jti or ttl <= 0:
        raise RefreshTokenError("Refresh token invalid")
    client.set(
        _refresh_token_key(jti),
        _dump_record(
            {
                "status": "active",
                "user_id": str(payload.get("sub") or ""),
                "role": role,
                "family_id": str(payload.get("family_id") or ""),
                "jti": jti,
                "issued_at": payload.get("iat"),
                "expires_at": payload.get("exp"),
            }
        ),
        ex=ttl,
    )


def _load_record(client: Redis, key: str) -> dict[str, Any] | None:
    raw = client.get(key)
    if not raw:
        return None
    try:
        parsed = json.loads(str(raw))
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _family_is_revoked(client: Redis, family_id: str) -> bool:
    return bool(client.exists(_family_revoked_key(family_id)))


def _revoke_family(client: Redis, family_id: str, payload: dict[str, Any]) -> None:
    ttl = max(_seconds_until_expiry(payload.get("exp")), _refresh_grace_seconds())
    client.set(_family_revoked_key(family_id), "1", ex=ttl)


def _acquire_rotation_lock(client: Redis, key: str, value: str, grace_seconds: int) -> bool:
    return bool(client.set(key, value, nx=True, ex=max(2, grace_seconds)))


def _release_rotation_lock(client: Redis, key: str, value: str) -> None:
    try:
        if client.get(key) == value:
            client.delete(key)
    except Exception:
        return


def _dump_record(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def _coerce_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _refresh_grace_seconds() -> int:
    return max(5, min(10, int(settings.SECURITY_REFRESH_TOKEN_GRACE_SECONDS or 10)))


def _refresh_token_key(jti: str) -> str:
    return f"{_refresh_prefix()}:token:{jti}"


def _family_revoked_key(family_id: str) -> str:
    return f"{_refresh_prefix()}:family_revoked:{family_id}"


def _refresh_lock_key(jti: str) -> str:
    return f"{_refresh_prefix()}:lock:{jti}"


def _refresh_prefix() -> str:
    return str(settings.SECURITY_REFRESH_TOKEN_REDIS_PREFIX or "sa:refresh_token").strip() or "sa:refresh_token"
