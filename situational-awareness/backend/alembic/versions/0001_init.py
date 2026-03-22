"""init placeholder

Revision ID: 0001_init
Revises:
Create Date: 2026-03-10
"""

from collections.abc import Sequence

from alembic import op

from app.db.base import Base
from app.db import models as db_models  # noqa: F401


revision: str = "0001_init"
down_revision: str | None = None
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    # Bootstrap the current schema so fresh databases can be upgraded directly.
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    pass
