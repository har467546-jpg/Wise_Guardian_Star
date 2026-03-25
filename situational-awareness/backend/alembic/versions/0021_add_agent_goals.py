"""add agent goals and session binding

Revision ID: 0021_agent_goals
Revises: 0020_agent_state
Create Date: 2026-03-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0021_agent_goals"
down_revision: str | None = "0020_agent_state"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    table_names = set(inspector.get_table_names())

    if "agent_goals" not in table_names:
        op.create_table(
            "agent_goals",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("agent_id", sa.String(length=32), nullable=False, server_default="haor"),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("title", sa.String(length=255), nullable=False, server_default="当前目标"),
            sa.Column("goal_kind", sa.String(length=64), nullable=False, server_default="general"),
            sa.Column("success_criteria_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("context_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("plan_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("progress_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("blocked_reason", sa.String(length=500), nullable=True),
            sa.Column("last_session_id", sa.String(length=36), nullable=True),
            sa.Column("last_task_id", sa.String(length=36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["last_session_id"], ["agent_sessions.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["last_task_id"], ["task_runs.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_agent_goals_user_agent_updated", "agent_goals", ["user_id", "agent_id", "updated_at"])
        op.create_index("ix_agent_goals_user_status_updated", "agent_goals", ["user_id", "status", "updated_at"])
        op.create_index(op.f("ix_agent_goals_agent_id"), "agent_goals", ["agent_id"])
        op.create_index(op.f("ix_agent_goals_status"), "agent_goals", ["status"])
        op.create_index(op.f("ix_agent_goals_user_id"), "agent_goals", ["user_id"])
        op.alter_column("agent_goals", "agent_id", server_default=None)
        op.alter_column("agent_goals", "status", server_default=None)
        op.alter_column("agent_goals", "title", server_default=None)
        op.alter_column("agent_goals", "goal_kind", server_default=None)
        op.alter_column("agent_goals", "success_criteria_json", server_default=None)
        op.alter_column("agent_goals", "context_json", server_default=None)
        op.alter_column("agent_goals", "plan_json", server_default=None)
        op.alter_column("agent_goals", "progress_json", server_default=None)

    column_names = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "current_goal_id" not in column_names:
        op.add_column("agent_sessions", sa.Column("current_goal_id", sa.String(length=36), nullable=True))
        op.create_index(op.f("ix_agent_sessions_current_goal_id"), "agent_sessions", ["current_goal_id"])
        op.create_foreign_key(
            "fk_agent_sessions_current_goal_id_agent_goals",
            "agent_sessions",
            "agent_goals",
            ["current_goal_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    column_names = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "current_goal_id" in column_names:
        op.drop_constraint("fk_agent_sessions_current_goal_id_agent_goals", "agent_sessions", type_="foreignkey")
        op.drop_index(op.f("ix_agent_sessions_current_goal_id"), table_name="agent_sessions")
        op.drop_column("agent_sessions", "current_goal_id")

    table_names = set(inspector.get_table_names())
    if "agent_goals" in table_names:
        op.drop_index(op.f("ix_agent_goals_user_id"), table_name="agent_goals")
        op.drop_index(op.f("ix_agent_goals_status"), table_name="agent_goals")
        op.drop_index(op.f("ix_agent_goals_agent_id"), table_name="agent_goals")
        op.drop_index("ix_agent_goals_user_status_updated", table_name="agent_goals")
        op.drop_index("ix_agent_goals_user_agent_updated", table_name="agent_goals")
        op.drop_table("agent_goals")
