"""add vuln intel sync task type

Revision ID: 0030_add_vuln_intel_sync_task_type
Revises: 0029_add_security_audit_logs
Create Date: 2026-06-22 18:40:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0030_add_vuln_intel_sync_task_type"
down_revision = "0029_add_security_audit_logs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(sa.text("ALTER TYPE tasktype ADD VALUE IF NOT EXISTS 'VULN_INTEL_SYNC'"))


def downgrade() -> None:
    # PostgreSQL enum values cannot be safely removed without rebuilding the type.
    return
