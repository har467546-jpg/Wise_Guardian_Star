from datetime import datetime

from pydantic import BaseModel, IPvAnyNetwork

from app.schemas.campus import ScannerZoneRead
from app.schemas.common import PageMeta
from app.db.models.enums import DiscoveryJobStatus
from app.schemas.common import ORMModel


class DiscoveryJobCreate(BaseModel):
    cidr: IPvAnyNetwork
    label: str | None = None
    runner_asset_id: str | None = None
    scanner_zone_id: str | None = None


class DiscoveryJobRead(ORMModel):
    id: str
    cidr: IPvAnyNetwork
    status: DiscoveryJobStatus
    label: str | None
    scanner_zone_id: str | None = None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    summary_json: dict


class DiscoveryJobCreateResponse(BaseModel):
    job: DiscoveryJobRead
    task_id: str
    status: str
    reused: bool = False


class DiscoveryJobListResponse(BaseModel):
    items: list[DiscoveryJobRead]
    meta: PageMeta


class DiscoveryRunnerOptionRead(BaseModel):
    runner_id: str | None = None
    asset_id: str
    asset_ip: str | None = None
    asset_hostname: str | None = None
    status: str
    install_status: str
    version: str | None = None
    scanner_zone_id: str | None = None
    last_seen_at: str | None = None
    detected_os: str | None = None
    detected_arch: str | None = None
    compatibility_issues: list[str] = []
    capabilities_json: dict = {}


class DiscoverySchedulingOptionRead(BaseModel):
    recommended_zone_ids: list[str] = []
    scanner_zones: list[ScannerZoneRead] = []
    runner_assets: list[DiscoveryRunnerOptionRead] = []
