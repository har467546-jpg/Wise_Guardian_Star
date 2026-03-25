from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class AgentSession(Base):
    __tablename__ = "agent_sessions"
    __table_args__ = (
        Index("ix_agent_sessions_user_agent_updated", "user_id", "agent_id", "updated_at"),
        Index("ix_agent_sessions_user_status_created", "user_id", "status", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    agent_id: Mapped[str] = mapped_column(String(32), default="haor", index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="active", index=True)
    route_context_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    working_context_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    dialog_state_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    pending_plan_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    browser_runtime_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    agent_state_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    current_goal_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("agent_goals.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_task_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("task_runs.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    user = relationship("User", back_populates="agent_sessions")
    current_goal = relationship("AgentGoal", back_populates="current_sessions", foreign_keys=[current_goal_id])
    last_task = relationship("TaskRun")
    messages = relationship(
        "AgentMessage",
        back_populates="session",
        cascade="all, delete-orphan",
        order_by="AgentMessage.created_at.asc()",
    )
