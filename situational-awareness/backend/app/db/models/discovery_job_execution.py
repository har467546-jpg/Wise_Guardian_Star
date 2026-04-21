from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class DiscoveryJobExecution(Base):
    __tablename__ = "discovery_job_executions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    discovery_job_id: Mapped[str] = mapped_column(String(36), ForeignKey("discovery_jobs.id", ondelete="CASCADE"), index=True)
    scanner_zone_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scanner_zones.id", ondelete="SET NULL"), nullable=True, index=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    target_cidr: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)
    task_run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("task_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    summary_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    discovery_job = relationship("DiscoveryJob", back_populates="executions")
    scanner_zone = relationship("ScannerZone", back_populates="executions")
    asset = relationship("Asset")
    task_run = relationship("TaskRun")
