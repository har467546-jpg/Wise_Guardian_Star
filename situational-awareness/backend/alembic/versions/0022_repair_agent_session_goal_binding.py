"""repair agent session goal binding

Revision ID: 0022_repair_agent_session_goal_binding
Revises: 0021_agent_goals
Create Date: 2026-03-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0022_repair_agent_session_goal_binding"
down_revision: str | None = "0021_agent_goals"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    table_names = set(inspector.get_table_names())
    if "agent_sessions" not in table_names or "agent_goals" not in table_names:
        return

    session_columns = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "current_goal_id" not in session_columns:
        op.add_column("agent_sessions", sa.Column("current_goal_id", sa.String(length=36), nullable=True))

    inspector = sa.inspect(op.get_bind())
    session_indexes = {item["name"] for item in inspector.get_indexes("agent_sessions")}
    if op.f("ix_agent_sessions_current_goal_id") not in session_indexes:
        op.create_index(op.f("ix_agent_sessions_current_goal_id"), "agent_sessions", ["current_goal_id"])

    inspector = sa.inspect(op.get_bind())
    session_foreign_keys = {item["name"] for item in inspector.get_foreign_keys("agent_sessions")}
    fk_name = "fk_agent_sessions_current_goal_id_agent_goals"
    if fk_name not in session_foreign_keys:
        op.create_foreign_key(
            fk_name,
            "agent_sessions",
            "agent_goals",
            ["current_goal_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    table_names = set(inspector.get_table_names())
    if "agent_sessions" not in table_names:
        return

    fk_name = "fk_agent_sessions_current_goal_id_agent_goals"
    session_foreign_keys = {item["name"] for item in inspector.get_foreign_keys("agent_sessions")}
    if fk_name in session_foreign_keys:
        op.drop_constraint(fk_name, "agent_sessions", type_="foreignkey")

    inspector = sa.inspect(op.get_bind())
    session_indexes = {item["name"] for item in inspector.get_indexes("agent_sessions")}
    if op.f("ix_agent_sessions_current_goal_id") in session_indexes:
        op.drop_index(op.f("ix_agent_sessions_current_goal_id"), table_name="agent_sessions")

    inspector = sa.inspect(op.get_bind())
    session_columns = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "current_goal_id" in session_columns:
        op.drop_column("agent_sessions", "current_goal_id")
