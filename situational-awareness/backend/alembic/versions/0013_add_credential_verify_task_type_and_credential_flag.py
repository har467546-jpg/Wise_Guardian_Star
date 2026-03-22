"""add credential verify task type and credential risk flag

Revision ID: 0013_credential_verify_task_type
Revises: 0012_task_status_canceled
Create Date: 2026-03-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0013_credential_verify_task_type"
down_revision: str | None = "0012_task_status_canceled"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'tasktype') THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_enum e
                    JOIN pg_type t ON t.oid = e.enumtypid
                    WHERE t.typname = 'tasktype' AND e.enumlabel = 'CREDENTIAL_VERIFY'
                ) THEN
                    ALTER TYPE tasktype ADD VALUE 'CREDENTIAL_VERIFY';
                END IF;
            END IF;
        END
        $$;
        """
    )
    op.add_column(
        "ssh_credentials",
        sa.Column("treat_success_as_risk", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.alter_column("ssh_credentials", "treat_success_as_risk", server_default=None)


def downgrade() -> None:
    op.drop_column("ssh_credentials", "treat_success_as_risk")
    # PostgreSQL enum values cannot be removed safely without type recreation.
    pass
