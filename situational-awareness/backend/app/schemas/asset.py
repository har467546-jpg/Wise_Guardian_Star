from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, IPvAnyAddress

from app.db.models.enums import AssetStatus, RiskSeverity
from app.schemas.common import ORMModel, PageMeta


class AssetPortRead(ORMModel):
    id: str
    port: int
    protocol: str
    service_name: str | None
    service_version: str | None
    fingerprint_json: dict[str, Any] = {}
    state: str
    last_seen_at: datetime


class AssetRead(ORMModel):
    id: str
    ip: IPvAnyAddress
    mac_address: str | None = None
    vendor: str | None = None
    hostname: str | None
    os_name: str | None
    network_zone: str | None = None
    network_vlan: str | None = None
    building: str | None = None
    department: str | None = None
    asset_category: str | None = None
    device_role: str | None = None
    device_assessment_json: dict[str, Any] = Field(default_factory=dict)
    identity_source: str | None = None
    last_auth_time: datetime | None = None
    is_infrastructure_device: bool = False
    is_iot: bool = False
    is_virtual_network_component: bool = False
    ipv6_addresses_json: list[str] = []
    status: AssetStatus
    is_local: bool = False
    local_hint: str | None = None
    first_seen_at: datetime
    last_seen_at: datetime
    ports: list[AssetPortRead] = []


class AssetListResponse(BaseModel):
    items: list[AssetRead]
    meta: PageMeta


class AssetUpdate(BaseModel):
    tag_ids: list[str] | None = None


class AssetBatchDeleteRequest(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=200)


class AssetBatchDeleteResponse(BaseModel):
    requested: int
    deleted: int
    missing_ids: list[str]


class AssetRiskSummary(BaseModel):
    asset_id: str
    highest_severity: RiskSeverity | None
    open_findings: int
