from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class RemediationSession(Base):
    __tablename__ = "remediation_sessions"
    __table_args__ = (
        Index("ix_remediation_sessions_asset_status_created", "asset_id", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    runner_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("host_runners.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    plan_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    finding_snapshot_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    summary_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    last_task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("task_runs.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    asset = relationship("Asset", back_populates="remediation_sessions")
    runner = relationship("HostRunner", back_populates="sessions")
    approver = relationship("User", back_populates="approved_remediation_sessions")
    last_task = relationship("TaskRun")
    messages = relationship(
        "RemediationMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="RemediationMessage.created_at.asc()",
    )
