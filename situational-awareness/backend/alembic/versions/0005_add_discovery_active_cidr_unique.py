"""add partial unique index for active discovery cidr

Revision ID: 0005_discovery_active_cidr
Revises: 0004_create_task_runs
Create Date: 2026-03-11
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0005_discovery_active_cidr"
down_revision: str | None = "0004_create_task_runs"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "discovery_jobs" not in inspector.get_table_names():
        return

    existing_indexes = {item["name"] for item in inspector.get_indexes("discovery_jobs")}
    if "uq_discovery_jobs_active_cidr" not in existing_indexes:
        op.create_index(
            "uq_discovery_jobs_active_cidr",
            "discovery_jobs",
            ["cidr"],
            unique=True,
            postgresql_where=sa.text("status IN ('PENDING', 'RUNNING')"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "discovery_jobs" not in inspector.get_table_names():
        return

    existing_indexes = {item["name"] for item in inspector.get_indexes("discovery_jobs")}
    if "uq_discovery_jobs_active_cidr" in existing_indexes:
        op.drop_index("uq_discovery_jobs_active_cidr", table_name="discovery_jobs")
