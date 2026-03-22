from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Index, String, Text, desc
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class PlatformLogEntry(Base):
    __tablename__ = "platform_log_entries"
    __table_args__ = (
        Index("ix_platform_log_entries_source_created", "source_kind", desc("created_at")),
        Index("ix_platform_log_entries_service_created", "service_name", desc("created_at")),
        Index("ix_platform_log_entries_task_created", "task_run_id", desc("created_at")),
        Index("ix_platform_log_entries_level_created", "level", desc("created_at")),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source_kind: Mapped[str] = mapped_column(String(32), index=True)
    service_name: Mapped[str] = mapped_column(String(32), index=True)
    logger_name: Mapped[str] = mapped_column(String(255))
    task_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    task_type: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), default="log")
    level: Mapped[str] = mapped_column(String(16), default="info")
    stage_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    stage_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
