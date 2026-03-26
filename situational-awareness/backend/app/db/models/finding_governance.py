from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class FindingGovernance(Base):
    __tablename__ = "finding_governance"
    __table_args__ = (
        Index("ix_finding_governance_priority_tier", "priority_tier"),
        Index("ix_finding_governance_owner_status", "owner_id", "status"),
        Index("ix_finding_governance_sla_due_at", "sla_due_at"),
    )

    finding_id: Mapped[str] = mapped_column(String(36), ForeignKey("risk_findings.id", ondelete="CASCADE"), primary_key=True)
    priority_score: Mapped[int] = mapped_column(Integer, default=0)
    priority_tier: Mapped[str] = mapped_column(String(8), default="P4")
    priority_reason_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    owner_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    finding = relationship("RiskFinding", back_populates="governance")
    owner = relationship("User")
