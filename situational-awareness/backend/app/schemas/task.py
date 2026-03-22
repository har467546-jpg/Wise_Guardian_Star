from datetime import datetime

from pydantic import BaseModel

from app.db.models.enums import TaskExecutionStatus, TaskType
from app.schemas.common import ORMModel, PageMeta


class TaskStageTimingRead(BaseModel):
    stage_code: str | None
    stage_name: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None


class TaskTimingRead(BaseModel):
    queue_duration_ms: int | None
    run_duration_ms: int | None
    total_duration_ms: int | None
    current_stage_code: str | None
    current_stage_name: str | None
    current_stage_duration_ms: int | None
    has_event_logs: bool


class TaskRunRead(ORMModel):
    id: str
    task_type: TaskType
    status: TaskExecutionStatus
    scope_type: str | None
    scope_id: str | None
    celery_task_id: str | None
    progress: int
    message: str | None
    retry_count: int
    result_json: dict
    error_json: dict
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime
    timing: TaskTimingRead


class TaskEventRead(BaseModel):
    id: str
    task_run_id: str
    task_type: TaskType | None
    status: TaskExecutionStatus | None
    event_type: str
    level: str
    stage_code: str | None
    stage_name: str | None
    message: str | None
    progress: int | None
    payload_json: dict
    created_at: datetime


class TaskRunDetailRead(TaskRunRead):
    timing: TaskTimingRead
    stage_timings: list[TaskStageTimingRead]
    event_count: int
    last_event_at: datetime | None


class TaskRunResponse(BaseModel):
    task_id: str
    status: TaskExecutionStatus


class TaskRunListResponse(BaseModel):
    items: list[TaskRunRead]
    meta: PageMeta


class TaskEventListResponse(BaseModel):
    items: list[TaskEventRead]
    meta: PageMeta


class TaskRunClearResponse(BaseModel):
    deleted: int
