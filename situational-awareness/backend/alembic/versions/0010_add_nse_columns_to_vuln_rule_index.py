"""add nse columns to vuln_rule_index

Revision ID: 0010_vuln_rule_index_nse
Revises: 0009_vuln_rule_index_active_check
Create Date: 2026-03-13 11:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy import inspect


revision: str = "0010_vuln_rule_index_nse"
down_revision: str | None = "0009_vuln_rule_index_active_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
    if "has_nse_match" not in existing_columns:
        op.add_column(
            "vuln_rule_index",
            sa.Column("has_nse_match", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if "nse_scripts" not in existing_columns:
        op.add_column(
            "vuln_rule_index",
            sa.Column("nse_scripts", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        )

    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_has_nse_match" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_has_nse_match", "vuln_rule_index", ["has_nse_match"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        return

    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_has_nse_match" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_has_nse_match", table_name="vuln_rule_index")

    existing_columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
    if "nse_scripts" in existing_columns:
        op.drop_column("vuln_rule_index", "nse_scripts")
    if "has_nse_match" in existing_columns:
        op.drop_column("vuln_rule_index", "has_nse_match")
