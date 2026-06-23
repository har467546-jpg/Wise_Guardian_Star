from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VulnCveIntel(Base):
    __tablename__ = "vuln_cve_intel"
    __table_args__ = (
        Index("ix_vuln_cve_intel_synced_at", "synced_at"),
        Index("ix_vuln_cve_intel_kev_flag", "kev_flag"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(128), default="cve_project")
    cvss_v3: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    kev_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    exploit_maturity: Mapped[str | None] = mapped_column(String(64), nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    references_json: Mapped[list[str]] = mapped_column(JSONB, default=list)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
