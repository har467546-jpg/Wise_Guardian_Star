from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScannerNodeAssignment(Base):
    __tablename__ = "scanner_node_assignments"
    __table_args__ = (
        UniqueConstraint("scanner_zone_id", "asset_id", name="uq_scanner_zone_asset"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scanner_zone_id: Mapped[str] = mapped_column(String(36), ForeignKey("scanner_zones.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    visible_cidrs_json: Mapped[list] = mapped_column(JSONB, default=list)
    max_concurrent_jobs: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    scanner_zone = relationship("ScannerZone", back_populates="node_assignments")
    asset = relationship("Asset", back_populates="scanner_node_assignments")
