"""add fingerprint json to asset ports

Revision ID: 0007_asset_port_fingerprint
Revises: 0006_add_asset_collecting_status
Create Date: 2026-03-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0007_asset_port_fingerprint"
down_revision: str | None = "0006_add_asset_collecting_status"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "asset_ports" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("asset_ports")}
    if "fingerprint_json" not in existing_columns:
        op.add_column(
            "asset_ports",
            sa.Column(
                "fingerprint_json",
                postgresql.JSONB(astext_type=sa.Text()),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "asset_ports" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("asset_ports")}
    if "fingerprint_json" in existing_columns:
        op.drop_column("asset_ports", "fingerprint_json")
