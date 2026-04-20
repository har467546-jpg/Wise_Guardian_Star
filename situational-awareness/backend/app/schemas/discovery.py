from datetime import datetime

from pydantic import BaseModel, IPvAnyNetwork

from app.schemas.common import PageMeta
from app.db.models.enums import DiscoveryJobStatus
from app.schemas.common import ORMModel


class DiscoveryJobCreate(BaseModel):
    cidr: IPvAnyNetwork
    label: str | None = None
    runner_asset_id: str | None = None


class DiscoveryJobRead(ORMModel):
    id: str
    cidr: IPvAnyNetwork
    status: DiscoveryJobStatus
    label: str | None
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
