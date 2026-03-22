from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class HostRunner(Base):
    __tablename__ = "host_runners"
    __table_args__ = (
        Index("ix_host_runners_status_seen", "status", "last_seen_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="offline", index=True)
    install_status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    registration_token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    capabilities_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    asset = relationship("Asset", back_populates="host_runner")
    sessions = relationship("RemediationSession", back_populates="runner")
