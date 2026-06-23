from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Index, Integer, String, Text, desc
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLogEntry(Base):
    __tablename__ = "audit_log_entries"
    __table_args__ = (
        Index("ix_audit_log_entries_created", desc("created_at")),
        Index("ix_audit_log_entries_actor_created", "actor_user_id", desc("created_at")),
        Index("ix_audit_log_entries_path_created", "path", desc("created_at")),
        Index("ix_audit_log_entries_outcome_created", "outcome", desc("created_at")),
        Index("ix_audit_log_entries_request_id", "request_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    request_id: Mapped[str] = mapped_column(String(64))
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(512))
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer, index=True)
    outcome: Mapped[str] = mapped_column(String(32))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    query_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    payload_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )
