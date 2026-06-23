"""add security audit logs

Revision ID: 0029_add_security_audit_logs
Revises: 0028_add_task_run_dispatch_columns
Create Date: 2026-06-22 11:05:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0029_add_security_audit_logs"
down_revision = "0028_add_task_run_dispatch_columns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_entries" in set(inspector.get_table_names()):
        return

    op.create_table(
        "audit_log_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("actor_role", sa.String(length=32), nullable=True),
        sa.Column("client_ip", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("method", sa.String(length=8), nullable=False),
        sa.Column("path", sa.String(length=512), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("query_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_entries_created", "audit_log_entries", ["created_at"])
    op.create_index("ix_audit_log_entries_actor_created", "audit_log_entries", ["actor_user_id", "created_at"])
    op.create_index("ix_audit_log_entries_path_created", "audit_log_entries", ["path", "created_at"])
    op.create_index("ix_audit_log_entries_outcome_created", "audit_log_entries", ["outcome", "created_at"])
    op.create_index("ix_audit_log_entries_request_id", "audit_log_entries", ["request_id"])
    op.create_index("ix_audit_log_entries_action", "audit_log_entries", ["action"])
    op.create_index("ix_audit_log_entries_resource_type", "audit_log_entries", ["resource_type"])
    op.create_index("ix_audit_log_entries_status_code", "audit_log_entries", ["status_code"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log_entries" not in set(inspector.get_table_names()):
        return
    for index_name in [
        "ix_audit_log_entries_status_code",
        "ix_audit_log_entries_resource_type",
        "ix_audit_log_entries_action",
        "ix_audit_log_entries_request_id",
        "ix_audit_log_entries_outcome_created",
        "ix_audit_log_entries_path_created",
        "ix_audit_log_entries_actor_created",
        "ix_audit_log_entries_created",
    ]:
        op.drop_index(index_name, table_name="audit_log_entries")
    op.drop_table("audit_log_entries")

