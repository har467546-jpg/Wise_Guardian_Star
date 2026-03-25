from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AgentGoal(Base):
    __tablename__ = "agent_goals"
    __table_args__ = (
        Index("ix_agent_goals_user_agent_updated", "user_id", "agent_id", "updated_at"),
        Index("ix_agent_goals_user_status_updated", "user_id", "status", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(String(32), default="haor", index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    title: Mapped[str] = mapped_column(String(255), default="当前目标")
    goal_kind: Mapped[str] = mapped_column(String(64), default="general")
    success_criteria_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    context_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    plan_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    progress_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    blocked_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    last_session_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("agent_sessions.id", ondelete="SET NULL"),
        nullable=True,
    )
    last_task_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("task_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="agent_goals")
    last_session = relationship("AgentSession", foreign_keys=[last_session_id])
    last_task = relationship("TaskRun", foreign_keys=[last_task_id])
    current_sessions = relationship(
        "AgentSession",
        back_populates="current_goal",
        foreign_keys="AgentSession.current_goal_id",
    )
