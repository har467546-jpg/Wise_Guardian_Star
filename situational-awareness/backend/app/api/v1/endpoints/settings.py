from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.db.models.user import User
from app.schemas.settings import (
    PlatformAIModelsRequest,
    PlatformAIModelsResponse,
    PlatformAIValidateRequest,
    PlatformAIValidateResponse,
    PlatformSettingsApplyComplete,
    PlatformSettingsApplyResponse,
    PlatformSettingsRead,
    PlatformSettingsUpdate,
)
from app.services.platform_settings_service import (
    complete_platform_settings_apply,
    get_platform_settings_read,
    list_platform_ai_models,
    queue_platform_settings_apply,
    validate_platform_ai_settings,
    verify_settings_helper_token,
)

router = APIRouter()


@router.get("", response_model=PlatformSettingsRead)
def get_platform_settings(
    _: User = Depends(get_admin_user),
) -> PlatformSettingsRead:
    return get_platform_settings_read()


@router.put("", response_model=PlatformSettingsApplyResponse, status_code=status.HTTP_202_ACCEPTED)
def update_platform_settings(
    payload: PlatformSettingsUpdate,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> PlatformSettingsApplyResponse:
    try:
        return queue_platform_settings_apply(db, payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/ai/validate", response_model=PlatformAIValidateResponse)
def validate_platform_ai(
    payload: PlatformAIValidateRequest,
    _: User = Depends(get_admin_user),
) -> PlatformAIValidateResponse:
    return validate_platform_ai_settings(payload)


@router.post("/ai/models", response_model=PlatformAIModelsResponse)
def list_platform_ai_model_options(
    payload: PlatformAIModelsRequest,
    _: User = Depends(get_admin_user),
) -> PlatformAIModelsResponse:
    return list_platform_ai_models(payload)


@router.post("/internal/tasks/{task_id}/complete")
def complete_platform_settings_task(
    task_id: str,
    payload: PlatformSettingsApplyComplete,
    x_settings_helper_token: str | None = Header(default=None),
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    try:
        verify_settings_helper_token(x_settings_helper_token)
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="内部设置执行器认证失败") from exc
    try:
        complete_platform_settings_apply(db, task_id, payload)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"status": "ok"}
