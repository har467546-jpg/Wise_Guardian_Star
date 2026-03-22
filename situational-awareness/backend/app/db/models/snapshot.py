from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class HostSnapshot(Base):
    __tablename__ = "host_snapshots"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_release: Mapped[str | None] = mapped_column(String(255), nullable=True)
    kernel_version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cpu_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    memory_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    software_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    services_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    collection_status: Mapped[str] = mapped_column(String(16), default="failed")
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="snapshots")
