from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_current_user, get_db_session
from app.core.security import SecurityError, decode_access_token, get_password_hash, verify_password
from app.db.models.enums import UserRole
from app.db.models.user import User
from app.schemas.auth import (
    BootstrapAdminRequest,
    BootstrapStatusResponse,
    LoginRequest,
    LogoutRequest,
    LogoutResponse,
    RefreshTokenRequest,
    RevokeUserSessionsResponse,
    TokenResponse,
    UserRead,
)
from app.services.refresh_token_service import RefreshTokenError, TokenPair, issue_token_pair, revoke_refresh_token, rotate_refresh_token
from app.services.token_denylist_service import denylist_token_payload
from app.services.user_state_cache_service import invalidate_user_auth_state, revoke_user_tokens

router = APIRouter()


def _count_users(db: Session) -> int:
    return int(db.scalar(select(func.count(User.id))) or 0)


@router.get("/bootstrap-status", response_model=BootstrapStatusResponse)
def bootstrap_status(db: Session = Depends(get_db_session)) -> BootstrapStatusResponse:
    user_count = _count_users(db)
    return BootstrapStatusResponse(
        bootstrapped=user_count > 0,
        can_bootstrap_admin=user_count == 0,
        user_count=user_count,
    )


@router.post("/bootstrap-admin", response_model=TokenResponse)
def bootstrap_admin(payload: BootstrapAdminRequest, db: Session = Depends(get_db_session)) -> TokenResponse:
    user_count = _count_users(db)
    if user_count > 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="系统已完成初始化，请直接登录")

    admin = User(
        username=payload.username,
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=UserRole.ADMIN,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    invalidate_user_auth_state(admin.id)
    return _token_response(issue_token_pair(user_id=admin.id, role=admin.role.value))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db_session)) -> TokenResponse:
    login_identity = payload.username.strip()
    stmt = select(User).where(
        or_(
            func.lower(User.username) == login_identity.lower(),
            func.lower(User.email) == login_identity.lower(),
        )
    )
    user = db.scalar(stmt)
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用户名或密码错误")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="当前账号不存在或已停用")

    return _token_response(issue_token_pair(user_id=user.id, role=user.role.value))


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(payload: RefreshTokenRequest, db: Session = Depends(get_db_session)) -> TokenResponse:
    try:
        return _token_response(rotate_refresh_token(db, payload.refresh_token))
    except RefreshTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="登录状态已失效，请重新登录") from exc


@router.post("/logout", response_model=LogoutResponse)
def logout(payload: LogoutRequest | None = None, authorization: str | None = Header(default=None)) -> LogoutResponse:
    revoked = False
    token = _extract_bearer_token(authorization or "")
    if token:
        try:
            access_payload = decode_access_token(token, verify_denylist=False)
        except SecurityError:
            access_payload = None
        if access_payload is not None:
            revoked = denylist_token_payload(access_payload) or revoked
    if payload and payload.refresh_token:
        revoked = revoke_refresh_token(payload.refresh_token) or revoked
    return LogoutResponse(revoked=revoked)


@router.post("/users/{user_id}/sessions/revoke", response_model=RevokeUserSessionsResponse)
def revoke_user_sessions(user_id: str, _: User = Depends(get_admin_user)) -> RevokeUserSessionsResponse:
    return RevokeUserSessionsResponse(user_id=user_id, revoked=revoke_user_tokens(user_id))


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> UserRead:
    return UserRead.model_validate(current_user)


def _extract_bearer_token(value: str) -> str:
    normalized = str(value or "").strip()
    if normalized.lower().startswith("bearer "):
        return normalized.split(" ", 1)[1].strip()
    return ""


def _token_response(pair: TokenPair) -> TokenResponse:
    return TokenResponse(
        access_token=pair.access_token,
        refresh_token=pair.refresh_token,
        token_type=pair.token_type,
        expires_in=pair.expires_in,
        refresh_expires_in=pair.refresh_expires_in,
    )
