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
    hostname: str | None
    os_name: str | None
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
