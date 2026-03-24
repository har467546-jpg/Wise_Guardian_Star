"""add agent state to haor sessions

Revision ID: 0020_agent_state
Revises: 0019_agent_browser_runtime
Create Date: 2026-03-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0020_agent_state"
down_revision: str | None = "0019_agent_browser_runtime"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    column_names = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "agent_state_json" in column_names:
        return
    op.add_column(
        "agent_sessions",
        sa.Column(
            "agent_state_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.alter_column("agent_sessions", "agent_state_json", server_default=None)


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    column_names = {item["name"] for item in inspector.get_columns("agent_sessions")}
    if "agent_state_json" not in column_names:
        return
    op.drop_column("agent_sessions", "agent_state_json")
