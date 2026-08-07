from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.db.models.user import User
from app.schemas.gateway import GatewayChannelCreate, GatewayChannelTestResponse, GatewayChannelUpdate
from app.services.ai.model_router_service import (
    create_gateway_channel,
    delete_gateway_channel,
    get_gateway_channels_payload,
    get_gateway_traffic_payload,
    probe_gateway_channel,
    publish_gateway_config_updated,
    refresh_gateway_channel_cache,
    update_gateway_channel,
)

router = APIRouter()


@router.get("/channels")
def list_gateway_channels(
    _: User = Depends(get_admin_user),
) -> dict[str, object]:
    return {"channels": get_gateway_channels_payload()}


@router.post("/channels", status_code=status.HTTP_201_CREATED)
def create_gateway_channel_endpoint(
    payload: GatewayChannelCreate,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> dict[str, object]:
    try:
        channel = create_gateway_channel(db, payload.model_dump(exclude_none=True))
        db.commit()
        db.refresh(channel)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    publish_gateway_config_updated(reason="channel_created")
    refresh_gateway_channel_cache()
    return {"channel": _created_channel_payload(channel.id)}


@router.put("/channels/{channel_id}")
def update_gateway_channel_endpoint(
    channel_id: int,
    payload: GatewayChannelUpdate,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> dict[str, object]:
    try:
        channel = update_gateway_channel(db, channel_id, payload.model_dump(exclude_none=True))
        db.commit()
        db.refresh(channel)
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    publish_gateway_config_updated(reason="channel_updated")
    refresh_gateway_channel_cache()
    return {"channel": _created_channel_payload(channel.id)}


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_gateway_channel_endpoint(
    channel_id: int,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> None:
    try:
        delete_gateway_channel(db, channel_id)
        db.commit()
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    publish_gateway_config_updated(reason="channel_deleted")
    refresh_gateway_channel_cache()


@router.post("/channels/{channel_id}/test", response_model=GatewayChannelTestResponse)
def test_gateway_channel(
    channel_id: int,
    _: User = Depends(get_admin_user),
) -> GatewayChannelTestResponse:
    record = probe_gateway_channel(channel_id, include_disabled=True)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI 通道不存在")
    return GatewayChannelTestResponse(
        channel_id=record.channel_id,
        success=record.success,
        latency_ms=record.latency_ms,
        error=record.error,
        status_code=record.status_code,
        purpose=record.purpose,
    )


@router.get("/metrics/traffic")
def get_gateway_traffic_metrics(
    minutes: int = Query(default=30, ge=1, le=120),
    _: User = Depends(get_admin_user),
) -> dict[str, object]:
    return get_gateway_traffic_payload(minutes=minutes)


def _created_channel_payload(channel_id: int) -> dict[str, object]:
    channels = get_gateway_channels_payload()
    return next((channel for channel in channels if channel.get("id") == channel_id), {"id": channel_id})
