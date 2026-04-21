from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel, PageMeta


ScannerZoneType = Literal["office", "dormitory", "wireless", "server", "iot", "custom"]
CampusDataSourceType = Literal["dhcp_lease", "snmp_switch"]


class ScannerZoneRead(ORMModel):
    id: str
    name: str
    zone_type: ScannerZoneType
    description: str | None = None
    priority: int
    enabled: bool
    cidrs_json: list[str] = Field(default_factory=list)
    default_scan_profile_json: dict[str, Any] = Field(default_factory=dict)
    allowed_data_source_types_json: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class ScannerZoneWrite(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    zone_type: ScannerZoneType = "office"
    description: str | None = Field(default=None, max_length=255)
    priority: int = Field(default=100, ge=1, le=10000)
    enabled: bool = True
    cidrs_json: list[str] = Field(default_factory=list)
    default_scan_profile_json: dict[str, Any] = Field(default_factory=dict)
    allowed_data_source_types_json: list[CampusDataSourceType] = Field(default_factory=list)


class ScannerZoneListResponse(BaseModel):
    items: list[ScannerZoneRead] = Field(default_factory=list)
    meta: PageMeta


class ScannerNodeAssignmentRead(ORMModel):
    id: str
    scanner_zone_id: str
    asset_id: str
    enabled: bool
    priority: int
    visible_cidrs_json: list[str] = Field(default_factory=list)
    max_concurrent_jobs: int
    created_at: datetime
    updated_at: datetime


class ScannerNodeAssignmentWrite(BaseModel):
    asset_id: str
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=10000)
    visible_cidrs_json: list[str] = Field(default_factory=list)
    max_concurrent_jobs: int = Field(default=1, ge=1, le=128)


class CampusDataSourceRead(ORMModel):
    id: str
    scanner_zone_id: str
    asset_id: str | None = None
    name: str
    source_type: CampusDataSourceType
    enabled: bool
    collection_interval_seconds: int
    config_json: dict[str, Any] = Field(default_factory=dict)
    last_summary_json: dict[str, Any] = Field(default_factory=dict)
    last_collected_at: datetime | None = None
    last_error: str | None = None
    created_at: datetime
    updated_at: datetime


class CampusDataSourceWrite(BaseModel):
    scanner_zone_id: str
    asset_id: str | None = None
    name: str = Field(min_length=1, max_length=128)
    source_type: CampusDataSourceType
    enabled: bool = True
    collection_interval_seconds: int = Field(default=1800, ge=60, le=86400)
    config_json: dict[str, Any] = Field(default_factory=dict)
    secret_plaintext: str | None = Field(default=None, max_length=4096)


class CampusDataSourceTestResponse(BaseModel):
    ok: bool
    source_type: CampusDataSourceType
    message: str
    summary_json: dict[str, Any] = Field(default_factory=dict)


class DiscoveryJobExecutionRead(ORMModel):
    id: str
    discovery_job_id: str
    scanner_zone_id: str | None = None
    asset_id: str | None = None
    target_cidr: str
    status: str
    progress: int
    task_run_id: str | None = None
    summary_json: dict[str, Any] = Field(default_factory=dict)
    error_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime


class DiscoveryJobExecutionListResponse(BaseModel):
    items: list[DiscoveryJobExecutionRead] = Field(default_factory=list)
    meta: PageMeta
