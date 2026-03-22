from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.sql import func


class SchemaDesignBase(DeclarativeBase):
    """Standalone metadata for canonical schema design artifacts.

    This keeps the design models isolated from the runtime models already used by
    the platform so the table metadata does not conflict during app startup.
    """


class Asset(SchemaDesignBase):
    __tablename__ = "assets"
    __table_args__ = (
        CheckConstraint("criticality IN ('low', 'medium', 'high', 'critical')", name="ck_assets_criticality"),
        CheckConstraint("status IN ('online', 'offline', 'unknown')", name="ck_assets_status"),
        Index("ix_assets_status_last_seen", "status", "last_seen_at"),
        Index("ix_assets_owner", "owner"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    ip: Mapped[str] = mapped_column(INET, nullable=False, unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'medium'"))
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'unknown'"))
    tags: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"), default=list)
    metadata_json: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset", cascade="all, delete-orphan")
    scan_results = relationship("ScanResult", back_populates="asset")


class Service(SchemaDesignBase):
    __tablename__ = "services"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_services_asset_port_protocol"),
        CheckConstraint("port BETWEEN 1 AND 65535", name="ck_services_port_range"),
        CheckConstraint("protocol IN ('tcp', 'udp')", name="ck_services_protocol"),
        CheckConstraint("state IN ('open', 'closed', 'filtered', 'unknown')", name="ck_services_state"),
        Index("ix_services_asset_state", "asset_id", "state"),
        Index("ix_services_name_version", "service_name", "version"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, server_default=text("'tcp'"))
    service_name: Mapped[str] = mapped_column(String(128), nullable=False)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'open'"))
    detected_by: Mapped[str] = mapped_column(String(64), nullable=False, server_default=text("'scanner'"))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    asset = relationship("Asset", back_populates="services")
    findings = relationship("Finding", back_populates="service")


class Task(SchemaDesignBase):
    __tablename__ = "tasks"
    __table_args__ = (
        CheckConstraint("task_type IN ('discovery', 'port_scan', 'service_scan', 'risk_scan')", name="ck_tasks_type"),
        CheckConstraint("status IN ('pending', 'running', 'completed', 'failed', 'cancelled')", name="ck_tasks_status"),
        Index("ix_tasks_type_status_created", "task_type", "status", "created_at"),
        Index("ix_tasks_status_started", "status", "started_at"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_cidr: Mapped[str | None] = mapped_column(CIDR, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'pending'"))
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parameters: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    summary: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    scan_results = relationship("ScanResult", back_populates="task", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="task")


class ScanResult(SchemaDesignBase):
    __tablename__ = "scan_results"
    __table_args__ = (
        CheckConstraint("duration_ms IS NULL OR duration_ms >= 0", name="ck_scan_results_duration"),
        Index("ix_scan_results_task_scanned", "task_id", "scanned_at"),
        Index("ix_scan_results_asset_scanned", "asset_id", "scanned_at"),
        Index("ix_scan_results_ip", "ip"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    task_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("tasks.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    ip: Mapped[str] = mapped_column(INET, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    icmp_alive: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    tcp_alive: Mapped[bool] = mapped_column(nullable=False, server_default=text("false"))
    open_ports: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"), default=list)
    services: Mapped[list] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"), default=list)
    raw_result: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    task = relationship("Task", back_populates="scan_results")
    asset = relationship("Asset", back_populates="scan_results")


class Finding(SchemaDesignBase):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint("severity IN ('low', 'medium', 'high', 'critical')", name="ck_findings_severity"),
        CheckConstraint("status IN ('open', 'confirmed', 'ignored', 'fixed')", name="ck_findings_status"),
        CheckConstraint("confidence IS NULL OR (confidence >= 0 AND confidence <= 100)", name="ck_findings_confidence"),
        Index("ix_findings_asset_status_severity", "asset_id", "status", "severity"),
        Index("ix_findings_service", "service_id"),
        Index("ix_findings_task", "task_id"),
        Index("ix_findings_rule_key", "rule_key"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    service_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("services.id", ondelete="SET NULL"), nullable=True)
    task_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), ForeignKey("tasks.id", ondelete="SET NULL"), nullable=True)
    rule_key: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'open'"))
    confidence: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"), default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    asset = relationship("Asset", back_populates="findings")
    service = relationship("Service", back_populates="findings")
    task = relationship("Task", back_populates="findings")


__all__ = [
    "SchemaDesignBase",
    "Asset",
    "Service",
    "Finding",
    "Task",
    "ScanResult",
]
