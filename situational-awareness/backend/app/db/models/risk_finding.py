from hashlib import md5
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import FindingStatus, RiskSeverity


class RiskFinding(Base):
    __tablename__ = "risk_findings"
    __table_args__ = (
        Index("ix_risk_findings_asset_status", "asset_id", "status"),
        Index("ix_risk_findings_asset_yaml_status", "asset_id", "yaml_rule_id", "status"),
        Index("ix_risk_findings_identity_hash", "identity_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    asset_port_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("asset_ports.id", ondelete="SET NULL"), nullable=True)
    yaml_rule_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    identity_hash: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    governance = relationship("FindingGovernance", back_populates="finding", uselist=False, cascade="all, delete-orphan")
    waivers = relationship("FindingWaiver", back_populates="finding", cascade="all, delete-orphan")

    def evidence(self) -> dict:
        return dict(self.evidence_json) if isinstance(self.evidence_json, dict) else {}

    def resolved_yaml_rule_id(self) -> str | None:
        value = str(self.yaml_rule_id or "").strip()
        if value:
            return value
        value = str(self.evidence().get("yaml_rule_id") or "").strip()
        return value or None

    def resolved_evidence_scope(self) -> str | None:
        value = str(self.evidence().get("evidence_scope") or "").strip()
        return value or None

    def resolved_verification_status(self) -> str | None:
        value = str(self.evidence().get("verification_status") or "").strip()
        return value or None

    def resolved_match_source(self) -> str | None:
        value = str(self.evidence().get("match_source") or "").strip()
        return value or None


def build_finding_identity_hash(
    *,
    asset_id: str | None,
    asset_port_id: str | None,
    yaml_rule_id: str | None,
    evidence_scope: str | None,
) -> str | None:
    normalized_asset_id = str(asset_id or "").strip()
    normalized_yaml_rule_id = str(yaml_rule_id or "").strip()
    normalized_scope = str(evidence_scope or "").strip()
    normalized_asset_port_id = str(asset_port_id or "").strip()
    if not normalized_asset_id or not normalized_yaml_rule_id or not normalized_scope:
        return None
    payload = "|".join([normalized_asset_id, normalized_asset_port_id, normalized_yaml_rule_id, normalized_scope])
    return md5(payload.encode("utf-8"), usedforsecurity=False).hexdigest()
