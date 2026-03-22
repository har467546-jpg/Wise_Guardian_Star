from pydantic import BaseModel, Field

from app.schemas.risk import RiskFindingMobileRead
from app.schemas.task import TaskRunRead


class MobileDiscoveryEntryRead(BaseModel):
    enabled: bool = True
    pending_jobs: int = 0
    running_jobs: int = 0


class MobileOverviewRead(BaseModel):
    asset_total: int = 0
    online_assets: int = 0
    high_risk_findings: int = 0
    active_tasks: int = 0
    recent_tasks: list[TaskRunRead] = Field(default_factory=list)
    recent_risks: list[RiskFindingMobileRead] = Field(default_factory=list)
    discovery_entry: MobileDiscoveryEntryRead = Field(default_factory=MobileDiscoveryEntryRead)
