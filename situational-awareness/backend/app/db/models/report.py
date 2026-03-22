from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Enum, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.models.enums import ReportScope


class AIReport(Base):
    __tablename__ = "ai_reports"
    __table_args__ = (Index("ix_ai_reports_scope_scope_id_created", "scope", "scope_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    scope: Mapped[ReportScope] = mapped_column(Enum(ReportScope), index=True)
    scope_id: Mapped[str] = mapped_column(String(36), index=True)
    summary_md: Mapped[str] = mapped_column(String)
    risk_overview_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    analysis_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
