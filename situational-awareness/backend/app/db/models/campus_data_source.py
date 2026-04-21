from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class CampusDataSource(Base):
    __tablename__ = "campus_data_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scanner_zone_id: Mapped[str] = mapped_column(String(36), ForeignKey("scanner_zones.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    source_type: Mapped[str] = mapped_column(String(32), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    collection_interval_seconds: Mapped[int] = mapped_column(Integer, default=1800)
    config_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_summary_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    secret_ciphertext: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    scanner_zone = relationship("ScannerZone", back_populates="data_sources")
    asset = relationship("Asset", back_populates="campus_data_sources")
