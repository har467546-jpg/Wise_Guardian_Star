"""create task runs table

Revision ID: 0004_create_task_runs
Revises: 0003_expand_ai_reports
Create Date: 2026-03-10
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "0004_create_task_runs"
down_revision: str | None = "0003_expand_ai_reports"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


task_type_enum = sa.Enum("ASSET_SCAN", "INFO_COLLECT", "RISK_VERIFY", "REPORT_GENERATE", name="tasktype")
task_status_enum = sa.Enum("PENDING", "RUNNING", "RETRY", "SUCCESS", "FAILURE", name="taskexecutionstatus")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    task_type_enum.create(bind, checkfirst=True)
    task_status_enum.create(bind, checkfirst=True)

    if "task_runs" not in inspector.get_table_names():
        op.create_table(
            "task_runs",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("task_type", task_type_enum, nullable=False),
            sa.Column("status", task_status_enum, nullable=False, server_default="PENDING"),
            sa.Column("scope_type", sa.String(length=32), nullable=True),
            sa.Column("scope_id", sa.String(length=36), nullable=True),
            sa.Column("celery_task_id", sa.String(length=255), nullable=True),
            sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("message", sa.String(length=255), nullable=True),
            sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("result_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("error_json", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
        inspector = sa.inspect(bind)

    existing_indexes = {item["name"] for item in inspector.get_indexes("task_runs")}
    if "ix_task_runs_celery_task_id" not in existing_indexes:
        op.create_index("ix_task_runs_celery_task_id", "task_runs", ["celery_task_id"], unique=False)
    if "ix_task_runs_scope" not in existing_indexes:
        op.create_index("ix_task_runs_scope", "task_runs", ["scope_type", "scope_id"], unique=False)
    if "ix_task_runs_status" not in existing_indexes:
        op.create_index("ix_task_runs_status", "task_runs", ["status"], unique=False)
    if "ix_task_runs_task_type" not in existing_indexes:
        op.create_index("ix_task_runs_task_type", "task_runs", ["task_type"], unique=False)
    if "ix_task_runs_type_status_created" not in existing_indexes:
        op.create_index("ix_task_runs_type_status_created", "task_runs", ["task_type", "status", "created_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "task_runs" in inspector.get_table_names():
        existing_indexes = {item["name"] for item in inspector.get_indexes("task_runs")}
        if "ix_task_runs_type_status_created" in existing_indexes:
            op.drop_index("ix_task_runs_type_status_created", table_name="task_runs")
        if "ix_task_runs_task_type" in existing_indexes:
            op.drop_index("ix_task_runs_task_type", table_name="task_runs")
        if "ix_task_runs_status" in existing_indexes:
            op.drop_index("ix_task_runs_status", table_name="task_runs")
        if "ix_task_runs_scope" in existing_indexes:
            op.drop_index("ix_task_runs_scope", table_name="task_runs")
        if "ix_task_runs_celery_task_id" in existing_indexes:
            op.drop_index("ix_task_runs_celery_task_id", table_name="task_runs")
        op.drop_table("task_runs")
    task_status_enum.drop(bind, checkfirst=True)
    task_type_enum.drop(bind, checkfirst=True)
