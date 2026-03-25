from pydantic import BaseModel, Field

from app.db.models.enums import RiskSeverity
from app.schemas.mobile import MobileDiscoveryEntryRead
from app.schemas.risk import RiskFindingMobileRead
from app.schemas.task import TaskRunRead


class DashboardSeverityTotalsRead(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardRiskyAssetRead(BaseModel):
    id: str
    ip: str
    hostname: str | None = None
    finding_count: int = 0
    highest_severity: RiskSeverity


class DashboardOverviewRead(BaseModel):
    asset_total: int = 0
    online_assets: int = 0
    high_risk_findings: int = 0
    active_tasks: int = 0
    discovery_entry: MobileDiscoveryEntryRead = Field(default_factory=MobileDiscoveryEntryRead)
    recent_risks: list[RiskFindingMobileRead] = Field(default_factory=list)
    risky_assets: list[DashboardRiskyAssetRead] = Field(default_factory=list)
    severity_totals: DashboardSeverityTotalsRead = Field(default_factory=DashboardSeverityTotalsRead)
    task_health: list[TaskRunRead] = Field(default_factory=list)
