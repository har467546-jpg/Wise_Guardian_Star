"""add canceled to taskexecutionstatus enum

Revision ID: 0012_task_status_canceled
Revises: 0011_create_task_events
Create Date: 2026-03-14
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0012_task_status_canceled"
down_revision: str | None = "0011_create_task_events"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'taskexecutionstatus') THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_enum e
                    JOIN pg_type t ON t.oid = e.enumtypid
                    WHERE t.typname = 'taskexecutionstatus' AND e.enumlabel = 'CANCELED'
                ) THEN
                    ALTER TYPE taskexecutionstatus ADD VALUE 'CANCELED';
                END IF;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely without type recreation.
    pass
