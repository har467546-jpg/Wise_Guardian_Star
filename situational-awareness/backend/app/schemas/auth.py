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
    token_type: str = "bearer"


class UserRead(ORMModel):
    id: str
    username: str
    email: EmailStr
    role: UserRole
    is_active: bool
    created_at: datetime
