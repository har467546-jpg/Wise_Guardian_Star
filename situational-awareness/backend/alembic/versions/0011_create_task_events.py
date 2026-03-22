"""create task events table

Revision ID: 0011_create_task_events
Revises: 0010_add_nse_columns_to_vuln_rule_index
Create Date: 2026-03-14
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0011_create_task_events"
down_revision: str | None = "0010_vuln_rule_index_nse"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "task_events" not in inspector.get_table_names():
        op.create_table(
            "task_events",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("task_run_id", sa.String(length=36), nullable=False),
            sa.Column("event_type", sa.String(length=32), nullable=False),
            sa.Column("level", sa.String(length=16), nullable=False, server_default="info"),
            sa.Column("stage_code", sa.String(length=64), nullable=True),
            sa.Column("stage_name", sa.String(length=128), nullable=True),
            sa.Column("message", sa.String(length=255), nullable=True),
            sa.Column("progress", sa.Integer(), nullable=True),
            sa.Column("payload_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["task_run_id"], ["task_runs.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        inspector = sa.inspect(bind)

    existing_indexes = {item["name"] for item in inspector.get_indexes("task_events")}
    if "ix_task_events_task_created" not in existing_indexes:
        op.create_index("ix_task_events_task_created", "task_events", ["task_run_id", "created_at"], unique=False)
    if "ix_task_events_level_created" not in existing_indexes:
        op.create_index("ix_task_events_level_created", "task_events", ["level", "created_at"], unique=False)
    if "ix_task_events_event_type_created" not in existing_indexes:
        op.create_index("ix_task_events_event_type_created", "task_events", ["event_type", "created_at"], unique=False)
    if "ix_task_events_task_run_id" not in existing_indexes:
        op.create_index("ix_task_events_task_run_id", "task_events", ["task_run_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "task_events" in inspector.get_table_names():
        existing_indexes = {item["name"] for item in inspector.get_indexes("task_events")}
        if "ix_task_events_task_run_id" in existing_indexes:
            op.drop_index("ix_task_events_task_run_id", table_name="task_events")
        if "ix_task_events_event_type_created" in existing_indexes:
            op.drop_index("ix_task_events_event_type_created", table_name="task_events")
        if "ix_task_events_level_created" in existing_indexes:
            op.drop_index("ix_task_events_level_created", table_name="task_events")
        if "ix_task_events_task_created" in existing_indexes:
            op.drop_index("ix_task_events_task_created", table_name="task_events")
        op.drop_table("task_events")
