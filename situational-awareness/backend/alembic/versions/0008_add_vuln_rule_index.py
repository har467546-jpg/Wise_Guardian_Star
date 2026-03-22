"""add vuln rule index

Revision ID: 0008_add_vuln_rule_index
Revises: 0007_asset_port_fingerprint
Create Date: 2026-03-12
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0008_add_vuln_rule_index"
down_revision: str | None = "0007_asset_port_fingerprint"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        op.create_table(
            "vuln_rule_index",
            sa.Column("rule_id", sa.String(length=128), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("service", sa.String(length=128), nullable=False),
            sa.Column(
                "severity",
                sa.Enum("LOW", "MEDIUM", "HIGH", "CRITICAL", name="riskseverity", create_type=False),
                nullable=False,
            ),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("match_type", sa.String(length=16), nullable=False),
            sa.Column(
                "cve_ids",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column(
                "tags",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'[]'::jsonb"),
            ),
            sa.Column("yaml_created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("yaml_updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("source_hash", sa.String(length=64), nullable=False),
            sa.Column("indexed_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("rule_id"),
        )
    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_enabled" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_enabled", "vuln_rule_index", ["enabled"], unique=False)
    if "ix_vuln_rule_index_name" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_name", "vuln_rule_index", ["name"], unique=False)
    if "ix_vuln_rule_index_service" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_service", "vuln_rule_index", ["service"], unique=False)
    if "ix_vuln_rule_index_service_severity_enabled" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_service_severity_enabled", "vuln_rule_index", ["service", "severity", "enabled"], unique=False)
    if "ix_vuln_rule_index_severity" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_severity", "vuln_rule_index", ["severity"], unique=False)
    if "ix_vuln_rule_index_source_hash" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_source_hash", "vuln_rule_index", ["source_hash"], unique=False)
    if "ix_vuln_rule_index_updated" not in existing_indexes:
        op.create_index("ix_vuln_rule_index_updated", "vuln_rule_index", ["yaml_updated_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "vuln_rule_index" not in inspector.get_table_names():
        return
    existing_indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_index")}
    if "ix_vuln_rule_index_updated" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_updated", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_source_hash" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_source_hash", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_severity" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_severity", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_service_severity_enabled" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_service_severity_enabled", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_service" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_service", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_name" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_name", table_name="vuln_rule_index")
    if "ix_vuln_rule_index_enabled" in existing_indexes:
        op.drop_index("ix_vuln_rule_index_enabled", table_name="vuln_rule_index")
    op.drop_table("vuln_rule_index")
