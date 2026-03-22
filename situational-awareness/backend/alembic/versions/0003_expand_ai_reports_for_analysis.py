"""expand ai reports for structured analysis

Revision ID: 0003_expand_ai_reports
Revises: 0002_expand_host_snapshots
Create Date: 2026-03-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0003_expand_ai_reports"
down_revision: str | None = "0002_expand_host_snapshots"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ai_reports" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("ai_reports")}
    if "analysis_json" not in existing_columns:
        op.add_column(
            "ai_reports",
            sa.Column(
                "analysis_json",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )

    existing_indexes = {item["name"] for item in inspector.get_indexes("ai_reports")}
    if "ix_ai_reports_scope_scope_id_created" not in existing_indexes:
        op.create_index(
            "ix_ai_reports_scope_scope_id_created",
            "ai_reports",
            ["scope", "scope_id", "created_at"],
            unique=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "ai_reports" not in inspector.get_table_names():
        return

    existing_indexes = {item["name"] for item in inspector.get_indexes("ai_reports")}
    if "ix_ai_reports_scope_scope_id_created" in existing_indexes:
        op.drop_index("ix_ai_reports_scope_scope_id_created", table_name="ai_reports")

    existing_columns = {item["name"] for item in inspector.get_columns("ai_reports")}
    if "analysis_json" in existing_columns:
        op.drop_column("ai_reports", "analysis_json")
