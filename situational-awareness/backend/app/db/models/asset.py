from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.models.enums import AssetStatus


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    ip: Mapped[str] = mapped_column(INET, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    status: Mapped[AssetStatus] = mapped_column(Enum(AssetStatus), default=AssetStatus.UNKNOWN)

    owner = relationship("User", back_populates="owned_assets")
    ports = relationship(
        "AssetPort",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by=lambda: (AssetPort.port.asc(), AssetPort.protocol.asc()),
    )
    tags = relationship("AssetTag", back_populates="asset", cascade="all, delete-orphan")
    snapshots = relationship("HostSnapshot", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("RiskFinding", back_populates="asset", cascade="all, delete-orphan")
    credential_bindings = relationship("AssetCredentialBinding", back_populates="asset", cascade="all, delete-orphan")
    host_runner = relationship("HostRunner", back_populates="asset", uselist=False, cascade="all, delete-orphan")
    remediation_sessions = relationship("RemediationSession", back_populates="asset", cascade="all, delete-orphan")


class AssetPort(Base):
    __tablename__ = "asset_ports"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_asset_port_protocol"),
        Index("ix_asset_ports_service", "service_name", "service_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fingerprint_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    state: Mapped[str] = mapped_column(String(32), default="open")
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    asset = relationship("Asset", back_populates="ports")


class AssetTag(Base):
    __tablename__ = "asset_tags"
    __table_args__ = (UniqueConstraint("asset_id", "tag_id", name="uq_asset_tag"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    tag_id: Mapped[str] = mapped_column(String(36), ForeignKey("tags.id", ondelete="CASCADE"), index=True)

    asset = relationship("Asset", back_populates="tags")
    tag = relationship("Tag", back_populates="assets")
