from sqlalchemy import Select, String, and_, cast, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.models.asset import Asset, AssetTag
from app.db.models.credential import AssetCredentialBinding, SSHCredential
from app.db.models.enums import AssetStatus
from app.db.models.risk_finding import RiskFinding


def list_assets(
    db: Session,
    page: int,
    page_size: int,
    ip: str | None = None,
    keyword: str | None = None,
    asset_status: AssetStatus | None = None,
    tag_id: str | None = None,
    network_zone: str | None = None,
    asset_category: str | None = None,
) -> tuple[list[Asset], int]:
    stmt: Select[tuple[Asset]] = select(Asset).options(joinedload(Asset.ports))
    count_stmt = select(func.count(Asset.id))

    filters = []
    if ip:
        filters.append(Asset.ip == ip)
    if keyword:
        normalized = keyword.strip()
        if normalized:
            like_value = f"%{normalized}%"
            filters.append(
                or_(
                    cast(Asset.ip, String).ilike(like_value),
                    Asset.hostname.ilike(like_value),
                    Asset.os_name.ilike(like_value),
                )
            )
    if asset_status is not None:
        filters.append(Asset.status == asset_status)
    if network_zone:
        filters.append(Asset.network_zone == network_zone)
    if asset_category:
        filters.append(Asset.asset_category == asset_category)
    if tag_id:
        stmt = stmt.join(AssetTag, AssetTag.asset_id == Asset.id)
        count_stmt = count_stmt.join(AssetTag, AssetTag.asset_id == Asset.id)
        filters.append(AssetTag.tag_id == tag_id)

    if filters:
        stmt = stmt.where(and_(*filters))
        count_stmt = count_stmt.where(and_(*filters))

    total = db.scalar(count_stmt) or 0
    items = db.scalars(stmt.order_by(Asset.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)).unique().all()
    return items, total


def get_asset(db: Session, asset_id: str) -> Asset | None:
    stmt = select(Asset).where(Asset.id == asset_id).options(joinedload(Asset.ports))
    return db.scalar(stmt)


def replace_asset_tags(db: Session, asset: Asset, tag_ids: list[str]) -> None:
    db.query(AssetTag).filter(AssetTag.asset_id == asset.id).delete(synchronize_session=False)
    for tag_id in tag_ids:
        db.add(AssetTag(asset_id=asset.id, tag_id=tag_id))
    db.commit()


def delete_asset(db: Session, asset: Asset) -> None:
    asset_id = asset.id
    db.delete(asset)
    db.flush()
    _delete_unbound_manual_credentials(db, [asset_id])
    db.commit()


def batch_delete_assets(db: Session, asset_ids: list[str]) -> tuple[int, list[str]]:
    if not asset_ids:
        return 0, []

    existing_ids = set(db.scalars(select(Asset.id).where(Asset.id.in_(asset_ids))).all())
    missing_ids = [asset_id for asset_id in asset_ids if asset_id not in existing_ids]
    deleted_count = 0
    if existing_ids:
        asset_ids_to_cleanup = list(existing_ids)
        deleted_count = (
            db.query(Asset)
            .filter(Asset.id.in_(list(existing_ids)))
            .delete(synchronize_session=False)
        )
        _delete_unbound_manual_credentials(db, asset_ids_to_cleanup)
        db.commit()
    return int(deleted_count), missing_ids


def _delete_unbound_manual_credentials(db: Session, asset_ids: list[str]) -> None:
    if not asset_ids:
        return

    credential_names = [f"manual-asset-{asset_id}" for asset_id in asset_ids]
    credentials = db.scalars(select(SSHCredential).where(SSHCredential.name.in_(credential_names))).all()
    for credential in credentials:
        still_bound = db.scalar(
            select(AssetCredentialBinding.id).where(AssetCredentialBinding.credential_id == credential.id).limit(1)
        )
        if still_bound is None:
            db.delete(credential)


def summarize_asset_risk(db: Session, asset_id: str) -> tuple[int, str | None]:
    stmt = select(RiskFinding).where(RiskFinding.asset_id == asset_id)
    findings = db.scalars(stmt).all()
    if not findings:
        return 0, None

    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = max(findings, key=lambda f: order[f.severity.value])
    open_count = sum(1 for item in findings if item.status.value == "open")
    return open_count, highest.severity.value
