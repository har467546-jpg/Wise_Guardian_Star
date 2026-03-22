from datetime import datetime

from pydantic import BaseModel

from app.db.models.enums import ReportScope
from app.schemas.common import ORMModel


class GenerateReportResponse(BaseModel):
    task_id: str
    status: str


class ReportRead(ORMModel):
    id: str
    scope: ReportScope
    scope_id: str
    summary_md: str
    risk_overview_json: dict
    analysis_json: dict
    created_at: datetime
