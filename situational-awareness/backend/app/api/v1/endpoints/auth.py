from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.core.security import create_access_token, get_password_hash, verify_password
from app.db.models.enums import UserRole
from app.db.models.user import User
from app.schemas.auth import BootstrapAdminRequest, BootstrapStatusResponse, LoginRequest, TokenResponse, UserRead

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

    token = create_access_token(subject=admin.id, extra={"role": admin.role.value})
    return TokenResponse(access_token=token)


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

    token = create_access_token(subject=user.id, extra={"role": user.role.value})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> UserRead:
    return UserRead.model_validate(current_user)
