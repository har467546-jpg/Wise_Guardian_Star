from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.utils.local_asset import resolve_local_asset


def purge_local_assets(db: Session) -> list[dict[str, str | None]]:
    removed: list[dict[str, str | None]] = []
    assets = db.scalars(select(Asset)).all()
    for asset in assets:
        ip = str(asset.ip or "").strip()
        hostname = asset.hostname.strip() if isinstance(asset.hostname, str) and asset.hostname.strip() else None
        if not ip:
            continue
        if getattr(asset, "host_runner", None) is not None:
            continue
        is_local, reason = resolve_local_asset(ip, hostname)
        if not is_local:
            continue
        removed.append(
            {
                "id": str(asset.id or ""),
                "ip": ip,
                "hostname": hostname,
                "reason": reason or "匹配平台本机资产排除策略",
            }
        )
        db.delete(asset)
    return removed
