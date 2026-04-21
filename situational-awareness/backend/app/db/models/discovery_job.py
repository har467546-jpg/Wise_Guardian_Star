from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, text
from sqlalchemy.dialects.postgresql import CIDR, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import DiscoveryJobStatus


class DiscoveryJob(Base):
    __tablename__ = "discovery_jobs"
    __table_args__ = (
        Index("ix_discovery_jobs_status_created", "status", "created_at"),
        Index(
            "uq_discovery_jobs_active_cidr",
            "cidr",
            unique=True,
            postgresql_where=text("status IN ('PENDING', 'RUNNING')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    cidr: Mapped[str] = mapped_column(CIDR)
    status: Mapped[DiscoveryJobStatus] = mapped_column(Enum(DiscoveryJobStatus), default=DiscoveryJobStatus.PENDING)
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scanner_zone_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scanner_zones.id", ondelete="SET NULL"), nullable=True, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    summary_json: Mapped[dict] = mapped_column(JSONB, default=dict)

    creator = relationship("User", back_populates="created_discovery_jobs")
    scanner_zone = relationship("ScannerZone", back_populates="discovery_jobs")
    executions = relationship("DiscoveryJobExecution", back_populates="discovery_job", cascade="all, delete-orphan")
