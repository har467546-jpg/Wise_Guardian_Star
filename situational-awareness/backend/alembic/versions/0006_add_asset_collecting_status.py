"""add collecting status to asset enum

Revision ID: 0006_add_asset_collecting_status
Revises: 0005_discovery_active_cidr
Create Date: 2026-03-11
"""

from collections.abc import Sequence

from alembic import op


revision: str = "0006_add_asset_collecting_status"
down_revision: str | None = "0005_discovery_active_cidr"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'assetstatus') THEN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_enum e
                    JOIN pg_type t ON t.oid = e.enumtypid
                    WHERE t.typname = 'assetstatus' AND e.enumlabel = 'COLLECTING'
                ) THEN
                    ALTER TYPE assetstatus ADD VALUE 'COLLECTING';
                END IF;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    # PostgreSQL enum values cannot be removed safely without type recreation.
    pass
