from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import FindingStatus, RiskSeverity


class RiskFinding(Base):
    __tablename__ = "risk_findings"
    __table_args__ = (Index("ix_risk_findings_asset_status", "asset_id", "status"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    asset_port_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("asset_ports.id", ondelete="SET NULL"), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("risk_rules.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity))
    status: Mapped[FindingStatus] = mapped_column(Enum(FindingStatus), default=FindingStatus.OPEN)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String)
    evidence_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset = relationship("Asset", back_populates="findings")
    rule = relationship("RiskRule", back_populates="findings")
    asset_port = relationship("AssetPort")
