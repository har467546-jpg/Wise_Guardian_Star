"""add vuln intel and governance

Revision ID: 0023_vuln_intel_and_governance
Revises: 0022_repair_agent_session_goal_binding
Create Date: 2026-03-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0023_vuln_intel_and_governance"
down_revision: str | None = "0022_repair_agent_session_goal_binding"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "vuln_cve_intel" not in table_names:
        op.create_table(
            "vuln_cve_intel",
            sa.Column("cve_id", sa.String(length=32), nullable=False),
            sa.Column("source", sa.String(length=128), nullable=False),
            sa.Column("cvss_v3", sa.Float(), nullable=True),
            sa.Column("epss_score", sa.Float(), nullable=True),
            sa.Column("kev_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("exploit_maturity", sa.String(length=64), nullable=True),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("references_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("cve_id"),
        )
        op.create_index("ix_vuln_cve_intel_synced_at", "vuln_cve_intel", ["synced_at"], unique=False)
        op.create_index("ix_vuln_cve_intel_kev_flag", "vuln_cve_intel", ["kev_flag"], unique=False)

    if "finding_governance" not in table_names:
        op.create_table(
            "finding_governance",
            sa.Column("finding_id", sa.String(length=36), nullable=False),
            sa.Column("priority_score", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("priority_tier", sa.String(length=8), nullable=False, server_default="P4"),
            sa.Column("priority_reason_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("owner_id", sa.String(length=36), nullable=True),
            sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["finding_id"], ["risk_findings.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("finding_id"),
        )
        op.create_index("ix_finding_governance_priority_tier", "finding_governance", ["priority_tier"], unique=False)
        op.create_index("ix_finding_governance_owner_status", "finding_governance", ["owner_id", "status"], unique=False)
        op.create_index("ix_finding_governance_sla_due_at", "finding_governance", ["sla_due_at"], unique=False)

    if "finding_waivers" not in table_names:
        op.create_table(
            "finding_waivers",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("finding_id", sa.String(length=36), nullable=False),
            sa.Column("waiver_type", sa.String(length=32), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("approved_by", sa.String(length=36), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"]),
            sa.ForeignKeyConstraint(["finding_id"], ["risk_findings.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("ix_finding_waivers_finding_status", "finding_waivers", ["finding_id", "status"], unique=False)
        op.create_index("ix_finding_waivers_expires_at", "finding_waivers", ["expires_at"], unique=False)

    if "vuln_rule_governance" not in table_names:
        op.create_table(
            "vuln_rule_governance",
            sa.Column("rule_id", sa.String(length=128), nullable=False),
            sa.Column("owner_id", sa.String(length=36), nullable=True),
            sa.Column("review_status", sa.String(length=32), nullable=False, server_default="published"),
            sa.Column("change_ticket", sa.String(length=128), nullable=True),
            sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_preview_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["owner_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("rule_id"),
        )
        op.create_index("ix_vuln_rule_governance_owner_id", "vuln_rule_governance", ["owner_id"], unique=False)
        op.create_index("ix_vuln_rule_governance_review_status", "vuln_rule_governance", ["review_status"], unique=False)

    if "vuln_rule_index" in table_names:
        columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
        if "cve_count" not in columns:
            op.add_column("vuln_rule_index", sa.Column("cve_count", sa.Integer(), nullable=False, server_default="0"))
        if "max_cvss" not in columns:
            op.add_column("vuln_rule_index", sa.Column("max_cvss", sa.Float(), nullable=True))
        if "max_epss" not in columns:
            op.add_column("vuln_rule_index", sa.Column("max_epss", sa.Float(), nullable=True))
        if "kev_flag" not in columns:
            op.add_column("vuln_rule_index", sa.Column("kev_flag", sa.Boolean(), nullable=False, server_default=sa.text("false")))
        if "exploit_maturity" not in columns:
            op.add_column("vuln_rule_index", sa.Column("exploit_maturity", sa.String(length=64), nullable=True))
        if "intel_synced_at" not in columns:
            op.add_column("vuln_rule_index", sa.Column("intel_synced_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())

    if "vuln_rule_index" in table_names:
        columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
        for name in ["intel_synced_at", "exploit_maturity", "kev_flag", "max_epss", "max_cvss", "cve_count"]:
            if name in columns:
                op.drop_column("vuln_rule_index", name)
                inspector = sa.inspect(bind)
                columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}

    if "vuln_rule_governance" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("vuln_rule_governance")}
        if "ix_vuln_rule_governance_review_status" in indexes:
            op.drop_index("ix_vuln_rule_governance_review_status", table_name="vuln_rule_governance")
        if "ix_vuln_rule_governance_owner_id" in indexes:
            op.drop_index("ix_vuln_rule_governance_owner_id", table_name="vuln_rule_governance")
        op.drop_table("vuln_rule_governance")

    if "finding_waivers" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("finding_waivers")}
        if "ix_finding_waivers_expires_at" in indexes:
            op.drop_index("ix_finding_waivers_expires_at", table_name="finding_waivers")
        if "ix_finding_waivers_finding_status" in indexes:
            op.drop_index("ix_finding_waivers_finding_status", table_name="finding_waivers")
        op.drop_table("finding_waivers")

    if "finding_governance" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("finding_governance")}
        if "ix_finding_governance_sla_due_at" in indexes:
            op.drop_index("ix_finding_governance_sla_due_at", table_name="finding_governance")
        if "ix_finding_governance_owner_status" in indexes:
            op.drop_index("ix_finding_governance_owner_status", table_name="finding_governance")
        if "ix_finding_governance_priority_tier" in indexes:
            op.drop_index("ix_finding_governance_priority_tier", table_name="finding_governance")
        op.drop_table("finding_governance")

    if "vuln_cve_intel" in table_names:
        indexes = {item["name"] for item in inspector.get_indexes("vuln_cve_intel")}
        if "ix_vuln_cve_intel_kev_flag" in indexes:
            op.drop_index("ix_vuln_cve_intel_kev_flag", table_name="vuln_cve_intel")
        if "ix_vuln_cve_intel_synced_at" in indexes:
            op.drop_index("ix_vuln_cve_intel_synced_at", table_name="vuln_cve_intel")
        op.drop_table("vuln_cve_intel")
