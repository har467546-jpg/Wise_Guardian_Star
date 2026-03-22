"""add browser runtime to haor sessions

Revision ID: 0019_agent_browser_runtime
Revises: 0018_agent_dialog_state
Create Date: 2026-03-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "0019_agent_browser_runtime"
down_revision: str | None = "0018_agent_dialog_state"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_sessions",
        sa.Column(
            "browser_runtime_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )
    op.alter_column("agent_sessions", "browser_runtime_json", server_default=None)


def downgrade() -> None:
    op.drop_column("agent_sessions", "browser_runtime_json")
