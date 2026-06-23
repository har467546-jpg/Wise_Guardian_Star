"""add secret cipher migration task type

Revision ID: 0031_add_secret_cipher_migration_task_type
Revises: 0030_add_vuln_intel_sync_task_type
Create Date: 2026-06-23 00:00:00.000000
"""

from alembic import op


revision = "0031_add_secret_cipher_migration_task_type"
down_revision = "0030_add_vuln_intel_sync_task_type"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE tasktype ADD VALUE IF NOT EXISTS 'SECRET_CIPHER_MIGRATION'")


def downgrade() -> None:
    # PostgreSQL enum values cannot be dropped safely without recreating the type.
    pass
