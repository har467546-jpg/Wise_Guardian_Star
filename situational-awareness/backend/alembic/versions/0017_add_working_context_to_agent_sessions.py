"""add working context to haor sessions

Revision ID: 0017_agent_working_context
Revises: 0016_agent_sessions
Create Date: 2026-03-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0017_agent_working_context"
down_revision: str | None = "0016_agent_sessions"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_sessions",
        sa.Column(
            "working_context_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.execute(
        """
        UPDATE agent_sessions
        SET working_context_json = CASE
            WHEN COALESCE(route_context_json->>'finding_id', '') <> '' THEN
                jsonb_strip_nulls(
                    jsonb_build_object(
                        'finding_id', route_context_json->>'finding_id',
                        'source', 'migrated_route_context',
                        'summary', concat('风险 ', route_context_json->>'finding_id')
                    )
                )
            WHEN COALESCE(route_context_json->>'asset_id', '') <> '' THEN
                jsonb_strip_nulls(
                    jsonb_build_object(
                        'asset_id', route_context_json->>'asset_id',
                        'source', 'migrated_route_context',
                        'summary', concat('资产 ', route_context_json->>'asset_id')
                    )
                )
            WHEN COALESCE(route_context_json->>'task_id', '') <> '' THEN
                jsonb_strip_nulls(
                    jsonb_build_object(
                        'task_id', route_context_json->>'task_id',
                        'source', 'migrated_route_context',
                        'summary', concat('任务 ', route_context_json->>'task_id')
                    )
                )
            ELSE '{}'::jsonb
        END
        """
    )
    op.alter_column("agent_sessions", "working_context_json", server_default=None)


def downgrade() -> None:
    op.drop_column("agent_sessions", "working_context_json")
