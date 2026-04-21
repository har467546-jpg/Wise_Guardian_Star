"""add asset device assessment json

Revision ID: 0026_add_asset_device_assessment_json
Revises: 0025_add_risk_finding_identity_fields
Create Date: 2026-04-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0026_add_asset_device_assessment_json"
down_revision: str | None = "0025_add_risk_finding_identity_fields"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "assets" not in table_names:
        return

    columns = {item["name"] for item in inspector.get_columns("assets")}
    if "device_assessment_json" not in columns:
        op.add_column(
            "assets",
            sa.Column(
                "device_assessment_json",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    table_names = set(inspector.get_table_names())
    if "assets" not in table_names:
        return

    columns = {item["name"] for item in inspector.get_columns("assets")}
    if "device_assessment_json" in columns:
        op.drop_column("assets", "device_assessment_json")
