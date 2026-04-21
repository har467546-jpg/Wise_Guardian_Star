"""add risk finding identity fields

Revision ID: 0025_add_risk_finding_identity_fields
Revises: 0024_add_campus_discovery_foundation
Create Date: 2026-04-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0025_add_risk_finding_identity_fields"
down_revision: str | None = "0024_add_campus_discovery_foundation"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "risk_findings" not in table_names:
        return

    columns = {item["name"] for item in inspector.get_columns("risk_findings")}
    if "yaml_rule_id" not in columns:
        op.add_column("risk_findings", sa.Column("yaml_rule_id", sa.String(length=128), nullable=True))
    if "identity_hash" not in columns:
        op.add_column("risk_findings", sa.Column("identity_hash", sa.String(length=32), nullable=True))

    op.execute(
        sa.text(
            """
            UPDATE risk_findings
            SET yaml_rule_id = NULLIF(BTRIM(evidence_json ->> 'yaml_rule_id'), '')
            WHERE (yaml_rule_id IS NULL OR yaml_rule_id = '')
              AND evidence_json IS NOT NULL
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE risk_findings
            SET identity_hash = md5(
                COALESCE(asset_id, '')
                || '|'
                || COALESCE(asset_port_id, '')
                || '|'
                || COALESCE(
                    NULLIF(BTRIM(yaml_rule_id), ''),
                    NULLIF(BTRIM(evidence_json ->> 'yaml_rule_id'), ''),
                    ''
                )
                || '|'
                || COALESCE(NULLIF(BTRIM(evidence_json ->> 'evidence_scope'), ''), '')
            )
            WHERE (identity_hash IS NULL OR identity_hash = '')
              AND COALESCE(
                    NULLIF(BTRIM(yaml_rule_id), ''),
                    NULLIF(BTRIM(evidence_json ->> 'yaml_rule_id'), '')
                  ) IS NOT NULL
              AND NULLIF(BTRIM(evidence_json ->> 'evidence_scope'), '') IS NOT NULL
            """
        )
    )

    inspector = sa.inspect(bind)
    indexes = {item["name"] for item in inspector.get_indexes("risk_findings")}
    if "ix_risk_findings_asset_yaml_status" not in indexes:
        op.create_index(
            "ix_risk_findings_asset_yaml_status",
            "risk_findings",
            ["asset_id", "yaml_rule_id", "status"],
            unique=False,
        )
    if "ix_risk_findings_identity_hash" not in indexes:
        op.create_index("ix_risk_findings_identity_hash", "risk_findings", ["identity_hash"], unique=False)
    if "ix_risk_findings_yaml_rule_id" not in indexes:
        op.create_index("ix_risk_findings_yaml_rule_id", "risk_findings", ["yaml_rule_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "risk_findings" not in table_names:
        return

    indexes = {item["name"] for item in inspector.get_indexes("risk_findings")}
    if "ix_risk_findings_identity_hash" in indexes:
        op.drop_index("ix_risk_findings_identity_hash", table_name="risk_findings")
    if "ix_risk_findings_asset_yaml_status" in indexes:
        op.drop_index("ix_risk_findings_asset_yaml_status", table_name="risk_findings")
    if "ix_risk_findings_yaml_rule_id" in indexes:
        op.drop_index("ix_risk_findings_yaml_rule_id", table_name="risk_findings")

    columns = {item["name"] for item in inspector.get_columns("risk_findings")}
    if "identity_hash" in columns:
        op.drop_column("risk_findings", "identity_hash")
    if "yaml_rule_id" in columns:
        op.drop_column("risk_findings", "yaml_rule_id")
