from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
JWT_SIGNING_ALGORITHM = "HS256"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


class SecurityError(Exception):
    pass


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def validate_jwt_algorithm_settings() -> None:
    if str(settings.JWT_ALGORITHM or "").strip().upper() != JWT_SIGNING_ALGORITHM:
        raise RuntimeError("JWT_ALGORITHM 已被安全策略锁定为 HS256")


def create_access_token(subject: str, expires_minutes: int | None = None, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "jti": uuid4().hex,
        "token_type": ACCESS_TOKEN_TYPE,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_SIGNING_ALGORITHM)


def create_refresh_token(
    subject: str,
    *,
    family_id: str | None = None,
    expires_days: int | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=expires_days or settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire,
        "iat": now,
        "jti": uuid4().hex,
        "family_id": family_id or uuid4().hex,
        "token_type": REFRESH_TOKEN_TYPE,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=JWT_SIGNING_ALGORITHM)


def decode_access_token(token: str, *, verify_denylist: bool = True) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_SIGNING_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise SecurityError("Invalid token") from exc
    token_type = str(payload.get("token_type") or ACCESS_TOKEN_TYPE)
    if token_type != ACCESS_TOKEN_TYPE:
        raise SecurityError("Invalid token type")
    if verify_denylist:
        from app.services.token_denylist_service import is_token_payload_denied

        if is_token_payload_denied(payload):
            raise SecurityError("Token revoked")
    return payload


def decode_refresh_token(token: str, *, verify_denylist: bool = True) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_SIGNING_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise SecurityError("Invalid token") from exc
    if str(payload.get("token_type") or "") != REFRESH_TOKEN_TYPE:
        raise SecurityError("Invalid token type")
    if verify_denylist:
        from app.services.token_denylist_service import is_token_payload_denied

        if is_token_payload_denied(payload):
            raise SecurityError("Token revoked")
    return payload
