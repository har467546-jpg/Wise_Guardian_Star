"""add host runner and remediation session tables

Revision ID: 0015_host_runner_sessions
Revises: 0014_authorized_ssh_fields
Create Date: 2026-03-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0015_host_runner_sessions"
down_revision: str | None = "0014_authorized_ssh_fields"
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
                    WHERE t.typname = 'tasktype' AND e.enumlabel = 'RUNNER_INSTALL'
                ) THEN
                    ALTER TYPE tasktype ADD VALUE 'RUNNER_INSTALL';
                END IF;
            END IF;
        END
        $$;
        """
    )

    op.create_table(
        "host_runners",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("install_status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("platform_url", sa.String(length=512), nullable=True),
        sa.Column("registration_token_hash", sa.String(length=128), nullable=True),
        sa.Column("token_hash", sa.String(length=128), nullable=True),
        sa.Column("capabilities_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("asset_id"),
    )
    op.create_index("ix_host_runners_asset_id", "host_runners", ["asset_id"], unique=False)
    op.create_index("ix_host_runners_status", "host_runners", ["status"], unique=False)
    op.create_index("ix_host_runners_status_seen", "host_runners", ["status", "last_seen_at"], unique=False)

    op.create_table(
        "remediation_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("asset_id", sa.String(length=36), nullable=False),
        sa.Column("runner_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("finding_snapshot_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("summary_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(length=36), nullable=True),
        sa.Column("last_task_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_task_id"], ["task_runs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["runner_id"], ["host_runners.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_sessions_asset_id", "remediation_sessions", ["asset_id"], unique=False)
    op.create_index("ix_remediation_sessions_runner_id", "remediation_sessions", ["runner_id"], unique=False)
    op.create_index("ix_remediation_sessions_status", "remediation_sessions", ["status"], unique=False)
    op.create_index(
        "ix_remediation_sessions_asset_status_created",
        "remediation_sessions",
        ["asset_id", "status", "created_at"],
        unique=False,
    )

    op.create_table(
        "remediation_messages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("message_type", sa.String(length=32), nullable=False),
        sa.Column("content", sa.String(length=4000), nullable=False),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["remediation_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_messages_session_id", "remediation_messages", ["session_id"], unique=False)
    op.create_index(
        "ix_remediation_messages_session_created",
        "remediation_messages",
        ["session_id", "created_at"],
        unique=False,
    )

    op.alter_column("host_runners", "capabilities_json", server_default=None)
    op.alter_column("remediation_sessions", "plan_json", server_default=None)
    op.alter_column("remediation_sessions", "finding_snapshot_json", server_default=None)
    op.alter_column("remediation_sessions", "summary_json", server_default=None)
    op.alter_column("remediation_messages", "payload_json", server_default=None)


def downgrade() -> None:
    op.drop_index("ix_remediation_messages_session_created", table_name="remediation_messages")
    op.drop_index("ix_remediation_messages_session_id", table_name="remediation_messages")
    op.drop_table("remediation_messages")

    op.drop_index("ix_remediation_sessions_asset_status_created", table_name="remediation_sessions")
    op.drop_index("ix_remediation_sessions_status", table_name="remediation_sessions")
    op.drop_index("ix_remediation_sessions_runner_id", table_name="remediation_sessions")
    op.drop_index("ix_remediation_sessions_asset_id", table_name="remediation_sessions")
    op.drop_table("remediation_sessions")

    op.drop_index("ix_host_runners_status_seen", table_name="host_runners")
    op.drop_index("ix_host_runners_status", table_name="host_runners")
    op.drop_index("ix_host_runners_asset_id", table_name="host_runners")
    op.drop_table("host_runners")
    # PostgreSQL enum values cannot be removed safely without type recreation.
