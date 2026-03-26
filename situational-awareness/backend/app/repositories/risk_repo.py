from sqlalchemy import Select, String, cast, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.db.models.asset import Asset, AssetTag
from app.db.models.enums import FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding


def _finding_load_options():
    return (
        joinedload(RiskFinding.asset).joinedload(Asset.tags).joinedload(AssetTag.tag),
        joinedload(RiskFinding.asset).joinedload(Asset.owner),
        joinedload(RiskFinding.asset_port),
        joinedload(RiskFinding.rule),
        joinedload(RiskFinding.governance),
        joinedload(RiskFinding.waivers),
    )


def list_findings_by_asset(db: Session, asset_id: str) -> list[RiskFinding]:
    stmt = (
        select(RiskFinding)
        .options(*_finding_load_options())
        .where(RiskFinding.asset_id == asset_id)
        .order_by(RiskFinding.detected_at.desc())
    )
    return db.scalars(stmt).unique().all()


def list_findings(
    db: Session,
    *,
    asset_id: str | None = None,
    status: FindingStatus | None = None,
    severity: RiskSeverity | None = None,
    keyword: str | None = None,
    limit: int = 20,
) -> list[RiskFinding]:
    stmt = (
        select(RiskFinding)
        .options(*_finding_load_options())
        .order_by(RiskFinding.detected_at.desc())
        .limit(max(1, min(limit, 50)))
    )
    if asset_id:
        stmt = stmt.where(RiskFinding.asset_id == asset_id)
    if status is not None:
        stmt = stmt.where(RiskFinding.status == status)
    if severity is not None:
        stmt = stmt.where(RiskFinding.severity == severity)
    if keyword:
        stmt = stmt.where(RiskFinding.title.ilike(f"%{keyword}%"))
    return db.scalars(stmt).unique().all()


def list_findings_page(
    db: Session,
    *,
    page: int,
    page_size: int,
    status: FindingStatus | None = None,
    severity: RiskSeverity | None = None,
    keyword: str | None = None,
) -> tuple[list[RiskFinding], int]:
    stmt: Select[tuple[RiskFinding]] = (
        select(RiskFinding)
        .join(Asset, RiskFinding.asset_id == Asset.id)
        .options(*_finding_load_options())
    )
    count_stmt = select(func.count(RiskFinding.id)).select_from(RiskFinding).join(Asset, RiskFinding.asset_id == Asset.id)

    filters = []
    if status is not None:
        filters.append(RiskFinding.status == status)
    if severity is not None:
        filters.append(RiskFinding.severity == severity)
    if keyword:
        normalized = keyword.strip()
        if normalized:
            like_value = f"%{normalized}%"
            filters.append(
                or_(
                    RiskFinding.title.ilike(like_value),
                    RiskFinding.description.ilike(like_value),
                    cast(Asset.ip, String).ilike(like_value),
                    Asset.hostname.ilike(like_value),
                )
            )
    if filters:
        stmt = stmt.where(*filters)
        count_stmt = count_stmt.where(*filters)

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(RiskFinding.detected_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).unique().all()
    return items, total


def get_finding(db: Session, finding_id: str) -> RiskFinding | None:
    stmt = (
        select(RiskFinding)
        .options(*_finding_load_options())
        .where(RiskFinding.id == finding_id)
    )
    return db.scalars(stmt).unique().first()
