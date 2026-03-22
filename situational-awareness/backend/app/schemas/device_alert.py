from datetime import datetime

from pydantic import BaseModel, Field

from app.db.models.enums import RiskSeverity


class DeviceAbnormalAlertEvent(BaseModel):
    type: str = Field(default="device_abnormal_alert", frozen=True)
    finding_id: str
    asset_id: str
    asset_ip: str
    asset_hostname: str | None = None
    severity: RiskSeverity
    title: str
    message: str
    route: str
    navigate_with_go: bool = False
    high_risk_findings: int = 0
    detected_at: datetime
