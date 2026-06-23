from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.db.models.enums import UserRole
from app.schemas.common import ORMModel


class LoginRequest(BaseModel):
    username: str
    password: str


class BootstrapAdminRequest(BaseModel):
    username: str
    email: EmailStr
    password: str


class BootstrapStatusResponse(BaseModel):
    bootstrapped: bool
    can_bootstrap_admin: bool
    user_count: int


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    refresh_expires_in: int | None = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class LogoutResponse(BaseModel):
    revoked: bool


class RevokeUserSessionsResponse(BaseModel):
    user_id: str
    revoked: bool


class UserRead(ORMModel):
    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime
