"""add active check columns to vuln rule index

Revision ID: 0009_vuln_rule_index_active_check
Revises: 0008_add_vuln_rule_index
Create Date: 2026-03-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0009_vuln_rule_index_active_check"
down_revision: str | None = "0008_add_vuln_rule_index"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
    if "has_active_check" not in existing_columns:
        op.add_column(
            "vuln_rule_index",
            sa.Column("has_active_check", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
    if "active_detector" not in existing_columns:
        op.add_column(
            "vuln_rule_index",
            sa.Column("active_detector", sa.String(length=64), nullable=True),
        )
    if "active_trigger" not in existing_columns:
        op.add_column(
            "vuln_rule_index",
            sa.Column("active_trigger", sa.String(length=32), nullable=True),
        )

    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_has_active_check" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_has_active_check", "vuln_rule_index", ["has_active_check"], unique=False)
    if "ix_vuln_rule_index_active_detector" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_active_detector", "vuln_rule_index", ["active_detector"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        return

    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_active_detector" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_active_detector", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_has_active_check" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_has_active_check", table_name="vuln_rule_index")

    existing_columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
    if "active_trigger" in existing_columns:
        op.drop_column("vuln_rule_index", "active_trigger")
    if "active_detector" in existing_columns:
        op.drop_column("vuln_rule_index", "active_detector")
    if "has_active_check" in existing_columns:
        op.drop_column("vuln_rule_index", "has_active_check")
