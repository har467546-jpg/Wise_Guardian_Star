from datetime import datetime

from pydantic import BaseModel

from app.db.models.enums import TaskType
from app.schemas.common import ORMModel, PageMeta


class LogEntryRead(ORMModel):
    id: str
    source_kind: str
    service_name: str
    logger_name: str
    task_run_id: str | None
    task_type: TaskType | None
    event_type: str
    level: str
    stage_code: str | None
    stage_name: str | None
    message: str | None
    payload_json: dict
    created_at: datetime


class LogEntryListResponse(BaseModel):
    items: list[LogEntryRead]
    meta: PageMeta
