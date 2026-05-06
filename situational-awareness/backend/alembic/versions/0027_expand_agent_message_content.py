"""expand agent message content

Revision ID: 0027_expand_agent_message_content
Revises: 0026_add_asset_device_assessment_json
Create Date: 2026-05-06 00:45:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "0027_expand_agent_message_content"
down_revision = "0026_add_asset_device_assessment_json"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "agent_messages",
        "content",
        existing_type=sa.String(length=4000),
        type_=sa.Text(),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "agent_messages",
        "content",
        existing_type=sa.Text(),
        type_=sa.String(length=4000),
        existing_nullable=False,
    )
