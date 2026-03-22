"""add authorized ssh credential fields

Revision ID: 0014_authorized_ssh_fields
Revises: 0013_credential_verify_task_type
Create Date: 2026-03-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "0014_authorized_ssh_fields"
down_revision: str | None = "0013_credential_verify_task_type"
branch_labels: Sequence[str] | None = None
depends_on: Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("ssh_credentials", sa.Column("sudo_secret_ciphertext", sa.String(), nullable=True))
    op.add_column(
        "ssh_credentials",
        sa.Column("admin_authorized", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("ssh_credentials", sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("ssh_credentials", sa.Column("last_verification_status", sa.String(length=32), nullable=True))
    op.add_column("ssh_credentials", sa.Column("last_effective_privilege", sa.String(length=32), nullable=True))
    op.alter_column("ssh_credentials", "admin_authorized", server_default=None)


def downgrade() -> None:
    op.drop_column("ssh_credentials", "last_effective_privilege")
    op.drop_column("ssh_credentials", "last_verification_status")
    op.drop_column("ssh_credentials", "last_verified_at")
    op.drop_column("ssh_credentials", "admin_authorized")
    op.drop_column("ssh_credentials", "sudo_secret_ciphertext")
