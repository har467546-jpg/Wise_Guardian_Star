from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.db.models.enums import AssetStatus
from app.db.models.asset import Asset
from app.db.models.user import User
from app.repositories.asset_repo import batch_delete_assets, delete_asset, get_asset, list_assets, replace_asset_tags
from app.schemas.asset import AssetBatchDeleteRequest, AssetBatchDeleteResponse, AssetListResponse, AssetRead, AssetUpdate
from app.schemas.common import PageMeta
from app.utils.local_asset import resolve_local_asset

router = APIRouter()


def _build_asset_read(asset: Asset) -> AssetRead:
    payload = AssetRead.model_validate(asset).model_dump()
    is_local, local_hint = resolve_local_asset(str(asset.ip), asset.hostname)
    payload["is_local"] = is_local
    payload["local_hint"] = local_hint
    return AssetRead.model_validate(payload)


@router.get("", response_model=AssetListResponse)
def get_assets(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    ip: str | None = None,
    keyword: str | None = Query(default=None, description="IP/hostname/OS fuzzy search"),
    asset_status: AssetStatus | None = Query(default=None, alias="status"),
    tag_id: str | None = None,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetListResponse:
    items, total = list_assets(
        db=db,
        page=page,
        page_size=page_size,
        ip=ip,
        keyword=keyword,
        asset_status=asset_status,
        tag_id=tag_id,
    )
    return AssetListResponse(
        items=[_build_asset_read(item) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset_detail(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetRead:
    asset = get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    return _build_asset_read(asset)


@router.patch("/{asset_id}", response_model=AssetRead)
def patch_asset(
    asset_id: str,
    payload: AssetUpdate,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetRead:
    asset = get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    if payload.tag_ids is not None:
        replace_asset_tags(db, asset=asset, tag_ids=payload.tag_ids)
        asset = get_asset(db, asset_id)

    return _build_asset_read(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_asset(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> Response:
    asset = get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    delete_asset(db, asset)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/batch/delete", response_model=AssetBatchDeleteResponse)
def remove_assets_batch(
    payload: AssetBatchDeleteRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetBatchDeleteResponse:
    deleted, missing_ids = batch_delete_assets(db, payload.asset_ids)
    return AssetBatchDeleteResponse(
        requested=len(payload.asset_ids),
        deleted=deleted,
        missing_ids=missing_ids,
    )
