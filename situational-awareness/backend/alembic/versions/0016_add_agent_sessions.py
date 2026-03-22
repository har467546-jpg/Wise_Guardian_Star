"""add haor agent session tables

Revision ID: 0016_agent_sessions
Revises: 0015_host_runner_sessions
Create Date: 2026-03-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0016_agent_sessions"
down_revision: str | None = "0015_host_runner_sessions"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tasktype') THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_enum e
                    JOIN pg_type t ON t.oid = e.enumtypid
                    WHERE t.typname = 'tasktype' AND e.enumlabel = 'AGENT_ORCHESTRATE'
                ) THEN
                    ALTER TYPE tasktype ADD VALUE 'AGENT_ORCHESTRATE';
                END IF;
            END IF;
        END
        $$;
        """
    )

    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("agent_id", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("route_context_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("pending_plan_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("last_task_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["last_task_id"], ["task_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_sessions_agent_id", "agent_sessions", ["agent_id"], unique=False)
    op.create_index("ix_agent_sessions_user_id", "agent_sessions", ["user_id"], unique=False)
    op.create_index("ix_agent_sessions_status", "agent_sessions", ["status"], unique=False)
    op.create_index(
        "ix_agent_sessions_user_agent_updated",
        "agent_sessions",
        ["user_id", "agent_id", "updated_at"],
        unique=False,
    )
    op.create_index(
        "ix_agent_sessions_user_status_created",
        "agent_sessions",
        ["user_id", "status", "created_at"],
        unique=False,
    )

    op.create_table(
        "agent_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("message_type", sa.String(length=32), nullable=False),
        sa.Column("content", sa.String(length=4000), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_messages_session_id", "agent_messages", ["session_id"], unique=False)
    op.create_index(
        "ix_agent_messages_session_created",
        "agent_messages",
        ["session_id", "created_at"],
        unique=False,
    )

    op.alter_column("agent_sessions", "route_context_json", server_default=None)
    op.alter_column("agent_sessions", "pending_plan_json", server_default=None)
    op.alter_column("agent_messages", "payload_json", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_agent_messages_session_created", table_name="agent_messages")
    op.drop_index("ix_agent_messages_session_id", table_name="agent_messages")
    op.drop_table("agent_messages")

    op.drop_index("ix_agent_sessions_user_status_created", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_user_agent_updated", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_status", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_user_id", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_agent_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
    # PostgreSQL enum values cannot be removed safely without type recreation.
