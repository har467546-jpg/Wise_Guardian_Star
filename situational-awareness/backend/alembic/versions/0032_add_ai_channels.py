"""add ai channels

Revision ID: 0032_add_ai_channels
Revises: 0031_add_secret_cipher_migration_task_type
Create Date: 2026-06-25 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "0032_add_ai_channels"
down_revision = "0031_add_secret_cipher_migration_task_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    json_type = postgresql.JSONB(astext_type=sa.Text()) if bind.dialect.name == "postgresql" else sa.JSON()
    op.create_table(
        "ai_channels",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("api_base", sa.String(length=1024), nullable=False, server_default=""),
        sa.Column("api_key_ciphertext", sa.Text(), nullable=True),
        sa.Column("model_name", sa.String(length=128), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("config_json", json_type, nullable=False, server_default=sa.text("'{}'::jsonb") if bind.dialect.name == "postgresql" else sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_channels_provider", "ai_channels", ["provider"])
    op.create_index("ix_ai_channels_status", "ai_channels", ["status"])
    op.create_index("ix_ai_channels_status_priority", "ai_channels", ["status", "priority"])


def downgrade() -> None:
    op.drop_index("ix_ai_channels_status_priority", table_name="ai_channels")
    op.drop_index("ix_ai_channels_status", table_name="ai_channels")
    op.drop_index("ix_ai_channels_provider", table_name="ai_channels")
    op.drop_table("ai_channels")
