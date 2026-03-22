"""expand host snapshots for async ssh collection

Revision ID: 0002_expand_host_snapshots
Revises: 0001_init
Create Date: 2026-03-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0002_expand_host_snapshots"
down_revision: str | None = "0001_init"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "host_snapshots" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("host_snapshots")}
    if "hostname" not in existing_columns:
        op.add_column("host_snapshots", sa.Column("hostname", sa.String(length=255), nullable=True))
    if "cpu_json" not in existing_columns:
        op.add_column(
            "host_snapshots",
            sa.Column("cpu_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        )
    if "memory_json" not in existing_columns:
        op.add_column(
            "host_snapshots",
            sa.Column("memory_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        )
    if "error_json" not in existing_columns:
        op.add_column(
            "host_snapshots",
            sa.Column("error_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        )
    if "collection_status" not in existing_columns:
        op.add_column(
            "host_snapshots",
            sa.Column("collection_status", sa.String(length=16), nullable=False, server_default=sa.text("'failed'")),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "host_snapshots" not in inspector.get_table_names():
        return

    existing_columns = {item["name"] for item in inspector.get_columns("host_snapshots")}
    if "collection_status" in existing_columns:
        op.drop_column("host_snapshots", "collection_status")
    if "error_json" in existing_columns:
        op.drop_column("host_snapshots", "error_json")
    if "memory_json" in existing_columns:
        op.drop_column("host_snapshots", "memory_json")
    if "cpu_json" in existing_columns:
        op.drop_column("host_snapshots", "cpu_json")
    if "hostname" in existing_columns:
        op.drop_column("host_snapshots", "hostname")
