from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import CredentialAuthType


class SSHCredential(Base):
    __tablename__ = "ssh_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(128))
    auth_type: Mapped[CredentialAuthType] = mapped_column(Enum(CredentialAuthType))
    secret_ciphertext: Mapped[str | None] = mapped_column(String, nullable=True)
    key_ciphertext: Mapped[str | None] = mapped_column(String, nullable=True)
    sudo_secret_ciphertext: Mapped[str | None] = mapped_column(String, nullable=True)
    # Legacy compatibility column kept in the table; authorized SSH flow always writes false.
    treat_success_as_risk: Mapped[bool] = mapped_column(Boolean, default=False)
    admin_authorized: Mapped[bool] = mapped_column(Boolean, default=False)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_verification_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_effective_privilege: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    creator = relationship("User", back_populates="created_credentials")
    asset_bindings = relationship("AssetCredentialBinding", back_populates="credential", cascade="all, delete-orphan")


class AssetCredentialBinding(Base):
    __tablename__ = "asset_credential_bindings"
    __table_args__ = (UniqueConstraint("asset_id", "credential_id", name="uq_asset_credential"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    credential_id: Mapped[str] = mapped_column(String(36), ForeignKey("ssh_credentials.id", ondelete="CASCADE"), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=10)

    asset = relationship("Asset", back_populates="credential_bindings")
    credential = relationship("SSHCredential", back_populates="asset_bindings")
