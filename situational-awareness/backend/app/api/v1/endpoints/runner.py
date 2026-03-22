from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_db_session
from app.db.models.host_runner import HostRunner
from app.schemas.remediation import (
    HostRunnerRead,
    RunnerHeartbeatRequest,
    RunnerPollRequest,
    RunnerPollResponse,
    RunnerRegisterRequest,
    RunnerRegisterResponse,
    RunnerTaskCompleteRequest,
    RunnerTaskEventBatch,
)
from app.services.runner_service import (
    append_runner_task_events,
    authenticate_runner,
    complete_runner_task,
    poll_runner_assignments,
    record_runner_heartbeat,
    register_runner,
)

router = APIRouter()


def _get_runner_from_token(
    x_runner_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db_session),
) -> HostRunner:
    token = (x_runner_token or "").strip()
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="缺少 Runner 认证令牌")
    runner = authenticate_runner(db, token)
    if runner is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Runner 认证失败")
    return runner


@router.post("/register", response_model=RunnerRegisterResponse)
def register_host_runner(
    payload: RunnerRegisterRequest,
    db: Session = Depends(get_db_session),
) -> RunnerRegisterResponse:
    try:
        return register_runner(db, payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/heartbeat", response_model=HostRunnerRead)
def heartbeat_host_runner(
    payload: RunnerHeartbeatRequest,
    runner: HostRunner = Depends(_get_runner_from_token),
    db: Session = Depends(get_db_session),
) -> HostRunnerRead:
    return record_runner_heartbeat(db, runner, payload)


@router.post("/poll", response_model=RunnerPollResponse)
def poll_host_runner_tasks(
    payload: RunnerPollRequest,
    runner: HostRunner = Depends(_get_runner_from_token),
    db: Session = Depends(get_db_session),
) -> RunnerPollResponse:
    return poll_runner_assignments(db, runner, max_tasks=payload.max_tasks)


@router.post("/tasks/{task_id}/events", status_code=status.HTTP_202_ACCEPTED)
def post_host_runner_task_events(
    task_id: str,
    payload: RunnerTaskEventBatch,
    runner: HostRunner = Depends(_get_runner_from_token),
    db: Session = Depends(get_db_session),
) -> dict[str, str]:
    try:
        append_runner_task_events(db, runner, task_id, payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"status": "accepted"}


@router.post("/tasks/{task_id}/complete")
def complete_host_runner_task(
    task_id: str,
    payload: RunnerTaskCompleteRequest,
    runner: HostRunner = Depends(_get_runner_from_token),
    db: Session = Depends(get_db_session),
) -> dict:
    try:
        return complete_runner_task(db, runner, task_id, payload)
    except RuntimeError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
