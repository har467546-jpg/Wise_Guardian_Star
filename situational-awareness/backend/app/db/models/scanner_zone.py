from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class ScannerZone(Base):
    __tablename__ = "scanner_zones"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    zone_type: Mapped[str] = mapped_column(String(32), index=True, default="office")
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    cidrs_json: Mapped[list] = mapped_column(JSONB, default=list)
    default_scan_profile_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    allowed_data_source_types_json: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    runners = relationship("HostRunner", back_populates="scanner_zone")
    node_assignments = relationship("ScannerNodeAssignment", back_populates="scanner_zone", cascade="all, delete-orphan")
    data_sources = relationship("CampusDataSource", back_populates="scanner_zone", cascade="all, delete-orphan")
    discovery_jobs = relationship("DiscoveryJob", back_populates="scanner_zone")
    executions = relationship("DiscoveryJobExecution", back_populates="scanner_zone")
