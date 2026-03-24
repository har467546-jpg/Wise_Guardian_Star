from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy.orm import Session

from app.db.models.agent_session import AgentSession
from app.db.models.task_run import TaskRun
from app.db.models.user import User
from app.services.agent.state_machine import is_active_public_session_status


def load_recent_session(*, query_builder, db: Session, user_id: str) -> AgentSession | None:
    sessions = db.scalars(query_builder(user_id)).unique().all()
    for session in sessions:
        if is_active_public_session_status(str(session.status or "")):
            return session
    return sessions[0] if sessions else None


def ensure_active_session(
    *,
    load_recent_session_fn,
    reconcile_session_runtime_state_fn,
    create_session_fn,
    db: Session,
    user: User,
):
    session = load_recent_session_fn(db, user_id=user.id)
    if session is not None and reconcile_session_runtime_state_fn(db, session=session):
        db.commit()
        db.refresh(session)
    if session is None or not is_active_public_session_status(str(session.status or "")):
        session = create_session_fn(db, user=user)
        db.commit()
        db.refresh(session)
    return session


def restore_session_from_running_state(
    session: AgentSession,
    *,
    now_fn: Callable[[], Any],
) -> None:
    session.status = "active"
    session.pending_plan_json = {}
    session.dialog_state_json = {}
    session.browser_runtime_json = {}
    session.agent_state_json = {}
    session.updated_at = now_fn()


def has_interrupted_task_message(session: AgentSession, *, task_id: str) -> bool:
    for item in reversed(list(session.messages or [])[-12:]):
        payload = item.payload_json if isinstance(item.payload_json, dict) else {}
        if str(payload.get("task_id") or "").strip() != task_id:
            continue
        if payload.get("interrupted"):
            return True
    return False


def append_interrupted_task_message(
    db: Session,
    *,
    session: AgentSession,
    task_id: str,
    source: str,
    append_message_fn,
) -> None:
    if has_interrupted_task_message(session, task_id=task_id):
        return
    append_message_fn(
        db,
        session=session,
        role="assistant",
        message_type="task_update",
        content="当前编排已中断，可以继续输入新的问题或执行意图。",
        payload_json={
            "task_id": task_id,
            "interrupted": True,
            "source": source,
        },
    )


def mark_agent_session_interrupted(
    db: Session,
    *,
    session_id: str,
    task_id: str,
    source: str,
    restore_session_from_running_state_fn,
    append_interrupted_task_message_fn,
) -> None:
    session = db.get(AgentSession, session_id)
    if session is None:
        return
    restore_session_from_running_state_fn(session)
    session.last_task_id = task_id
    db.add(session)
    append_interrupted_task_message_fn(db, session=session, task_id=task_id, source=source)


def reconcile_running_session_state(
    db: Session,
    *,
    session: AgentSession,
    interrupted_source: str = "session_reconcile",
    sanitize_line_fn,
    get_task_run_fn,
    is_session_orchestrate_task_fn,
    normalize_task_status_fn,
    is_terminal_task_status_fn,
    restore_session_from_running_state_fn,
    append_interrupted_task_message_fn,
    canceled_task_status: str,
) -> bool:
    if str(session.status or "") != "running":
        return False

    task_id = sanitize_line_fn(str(session.last_task_id or ""), max_length=64)
    if not task_id:
        restore_session_from_running_state_fn(session)
        db.add(session)
        return True

    task = get_task_run_fn(db, task_id)
    if task is None or not is_session_orchestrate_task_fn(task, session_id=session.id):
        restore_session_from_running_state_fn(session)
        db.add(session)
        return True

    task_status = normalize_task_status_fn(task.status)
    if task_status == canceled_task_status:
        restore_session_from_running_state_fn(session)
        session.last_task_id = task_id
        db.add(session)
        append_interrupted_task_message_fn(db, session=session, task_id=task_id, source=interrupted_source)
        return True

    if is_terminal_task_status_fn(task.status):
        restore_session_from_running_state_fn(session)
        session.last_task_id = task_id
        db.add(session)
        return True

    return False


def interrupt_agent_session(
    db: Session,
    *,
    user: User,
    load_recent_session_fn,
    reconcile_running_session_state_fn,
    restore_session_from_running_state_fn,
    sanitize_line_fn,
    get_task_run_fn,
    is_session_orchestrate_task_fn,
    is_active_task_status_fn,
    normalize_task_status_fn,
    celery_app,
    running_task_status: str,
    retry_task_status: str,
    cancel_task_run_fn,
    mark_agent_session_interrupted_fn,
    serialize_agent_session_fn,
    agent_not_found_error_cls,
    agent_conflict_error_cls,
    agent_upstream_error_cls,
):
    session = load_recent_session_fn(db, user_id=user.id)
    if session is None:
        raise agent_not_found_error_cls("当前 haor 会话不存在", stage="interrupt")

    if reconcile_running_session_state_fn(db, session=session, interrupted_source="session_interrupt_reconcile"):
        db.commit()
        db.refresh(session)

    if str(session.status or "") != "running":
        raise agent_conflict_error_cls("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    task_id = sanitize_line_fn(str(session.last_task_id or ""), max_length=64)
    if not task_id:
        restore_session_from_running_state_fn(session)
        db.commit()
        db.refresh(session)
        raise agent_conflict_error_cls("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    task: TaskRun | None = get_task_run_fn(db, task_id)
    if task is None:
        restore_session_from_running_state_fn(session)
        db.commit()
        db.refresh(session)
        raise agent_conflict_error_cls("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    if not is_session_orchestrate_task_fn(task, session_id=session.id):
        restore_session_from_running_state_fn(session)
        db.commit()
        db.refresh(session)
        raise agent_conflict_error_cls("当前没有运行中的 haor 编排任务", session_id=session.id, stage="interrupt")

    if not is_active_task_status_fn(task.status):
        restore_session_from_running_state_fn(session)
        db.commit()
        db.refresh(session)
        raise agent_conflict_error_cls("当前任务已结束，无需中断", session_id=session.id, stage="interrupt")

    if task.celery_task_id:
        try:
            celery_app.control.revoke(
                task.celery_task_id,
                terminate=normalize_task_status_fn(task.status) in {running_task_status, retry_task_status},
                signal="SIGTERM",
            )
        except Exception as exc:
            raise agent_upstream_error_cls(
                f"haor 编排中断请求下发失败：{exc}",
                session_id=session.id,
                stage="interrupt",
            ) from exc

    cancel_task_run_fn(
        db,
        task,
        message="haor 编排任务已中断",
        payload_json={
            "source": "agent_session_interrupt",
            "celery_task_id": task.celery_task_id,
            "session_id": session.id,
        },
    )
    mark_agent_session_interrupted_fn(db, session_id=session.id, task_id=task.id, source="interrupt_api")
    db.commit()
    db.refresh(session)
    return serialize_agent_session_fn(session)


def reset_agent_session(
    db: Session,
    *,
    user: User,
    load_recent_session_fn,
    reconcile_session_runtime_state_fn,
    interrupt_agent_session_fn,
    agent_conflict_error_cls,
    query_builder,
    normalize_page_context_fn,
    now_fn,
    create_session_fn,
    serialize_agent_session_fn,
):
    current_session = load_recent_session_fn(db, user_id=user.id)
    if current_session is not None and reconcile_session_runtime_state_fn(db, session=current_session):
        db.flush()
    if current_session is not None and str(current_session.status or "") == "running":
        try:
            interrupt_agent_session_fn(db, user=user)
        except agent_conflict_error_cls:
            db.flush()

    sessions = db.scalars(query_builder(user.id)).unique().all()
    for session in sessions:
        if is_active_public_session_status(str(session.status or "")):
            session.status = "completed"
            session.pending_plan_json = {}
            session.working_context_json = {}
            session.dialog_state_json = {}
            session.browser_runtime_json = {}
            session.agent_state_json = {}
            session.route_context_json = normalize_page_context_fn({})
            session.updated_at = now_fn()
            db.add(session)
    session = create_session_fn(db, user=user)
    db.commit()
    db.refresh(session)
    return serialize_agent_session_fn(session)
