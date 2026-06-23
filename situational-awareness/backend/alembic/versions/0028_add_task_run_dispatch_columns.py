"""add task run dispatch columns

Revision ID: 0028_add_task_run_dispatch_columns
Revises: 0027_expand_agent_message_content
Create Date: 2026-06-17 12:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0028_add_task_run_dispatch_columns"
down_revision = "0027_expand_agent_message_content"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("task_runs", sa.Column("execution_boundary", sa.String(length=32), nullable=True))
    op.add_column("task_runs", sa.Column("runner_asset_id", sa.String(length=36), nullable=True))
    op.add_column("task_runs", sa.Column("scanner_zone_id", sa.String(length=36), nullable=True))
    op.create_index("ix_task_runs_execution_boundary", "task_runs", ["execution_boundary"])
    op.create_index("ix_task_runs_runner_asset_id", "task_runs", ["runner_asset_id"])
    op.create_index("ix_task_runs_scanner_zone_id", "task_runs", ["scanner_zone_id"])


def downgrade() -> None:
    op.drop_index("ix_task_runs_scanner_zone_id", table_name="task_runs")
    op.drop_index("ix_task_runs_runner_asset_id", table_name="task_runs")
    op.drop_index("ix_task_runs_execution_boundary", table_name="task_runs")
    op.drop_column("task_runs", "scanner_zone_id")
    op.drop_column("task_runs", "runner_asset_id")
    op.drop_column("task_runs", "execution_boundary")
