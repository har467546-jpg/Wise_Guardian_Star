from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.enums import RiskSeverity


class VulnRuleIndex(Base):
    __tablename__ = "vuln_rule_index"
    __table_args__ = (
        Index("ix_vuln_rule_index_service_severity_enabled", "service", "severity", "enabled"),
        Index("ix_vuln_rule_index_updated", "yaml_updated_at"),
        Index("ix_vuln_rule_index_source_hash", "source_hash"),
    )

    rule_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    service: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[RiskSeverity] = mapped_column(Enum(RiskSeverity), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    match_type: Mapped[str] = mapped_column(String(16))
    has_nse_match: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    nse_scripts: Mapped[list[str]] = mapped_column(JSONB, default=list)
    has_active_check: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    active_detector: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    active_trigger: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    yaml_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    yaml_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    source_hash: Mapped[str] = mapped_column(String(64))
    indexed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
