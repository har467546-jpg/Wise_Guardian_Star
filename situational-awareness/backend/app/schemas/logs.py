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


class AuditLogEntryRead(BaseModel):
    id: str
    request_id: str
    actor_user_id: str | None
    actor_role: str | None
    client_ip: str | None
    user_agent: str | None
    method: str
    path: str
    action: str
    resource_type: str | None
    resource_id: str | None
    status_code: int
    outcome: str
    duration_ms: int
    query_json: dict
    payload_json: dict
    error_message: str | None
    created_at: datetime


class AuditLogEntryListResponse(BaseModel):
    items: list[AuditLogEntryRead]
    meta: PageMeta
