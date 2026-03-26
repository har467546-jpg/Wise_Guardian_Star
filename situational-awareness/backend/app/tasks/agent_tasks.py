from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any

from celery import Task
from sqlalchemy.exc import IntegrityError, ProgrammingError

from app.core.celery_app import celery_app
from app.db.models.agent_session import AgentSession
from app.db.models.enums import TaskExecutionStatus
from app.db.session import SessionLocal
from app.repositories.task_repo import get_task_run, update_task_run
from app.services.haor_agent_service import (
    append_agent_task_message,
    build_auto_action_task_followup_content,
    execute_approved_action,
    has_agent_task_followup_message,
    mark_agent_session_interrupted,
    sync_agent_task_watch_state,
    wait_for_child_task,
)
from app.tasks.task_runtime import (
    TaskCanceledError,
    append_current_task_event,
    ensure_task_not_canceled,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)
from app.utils.sanitize import sanitize_text


logger = logging.getLogger(__name__)

_NON_RETRYABLE_REMEDIATION_ERRORS = (
    "审批人信息无效，请刷新页面后重试",
    "当前整机修复计划不可执行",
    "当前没有可执行阶段",
    "仅允许审批当前最早可执行阶段",
    "修复会话不存在",
)


def _deep_merge_dict(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_dict(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def _load_task_result_json(task_run_id: str) -> dict[str, Any]:
    with SessionLocal() as db:
        task_run = get_task_run(db, task_run_id)
        if task_run is None or not isinstance(task_run.result_json, dict):
            return {}
        return deepcopy(task_run.result_json)


def _build_orchestrate_progress_result(
    task_run_id: str,
    *,
    runtime_patch: dict[str, Any],
) -> dict[str, Any]:
    current_result = _load_task_result_json(task_run_id)
    execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
    current_result["execution"] = _deep_merge_dict(execution, {"runtime": runtime_patch})
    return current_result


def _humanize_orchestrate_error(exc: Exception) -> str:
    raw_message = str(exc).strip()
    if not raw_message:
        return "haor 编排执行失败，请稍后重试"
    if isinstance(exc, (IntegrityError, ProgrammingError)):
        lowered = raw_message.lower()
        if "remediation_sessions_approved_by_fkey" in raw_message or (
            "remediation_sessions" in lowered and "approved_by" in lowered
        ):
            return "审批人信息无效，请刷新页面后重试"
        return "haor 编排执行失败，请稍后重试"
    for message in _NON_RETRYABLE_REMEDIATION_ERRORS:
        if message in raw_message:
            return message
    sanitized = sanitize_text(raw_message, max_length=200, single_line=True) or ""
    return sanitized or "haor 编排执行失败，请稍后重试"


def _should_retry_orchestrate_error(
    exc: Exception,
    *,
    entered_action_execution: bool,
    terminal_followup: dict[str, object] | None,
) -> bool:
    if entered_action_execution:
        return False
    if isinstance(terminal_followup, dict) and str(terminal_followup.get("message_type") or "") == "error":
        return False
    if isinstance(exc, (IntegrityError, ProgrammingError)):
        return False
    humanized = _humanize_orchestrate_error(exc)
    if humanized in _NON_RETRYABLE_REMEDIATION_ERRORS:
        return False
    return True


@celery_app.task(
    bind=True,
    name="app.tasks.agent_tasks.run_agent_orchestrate_task",
    max_retries=1,
)
def run_agent_orchestrate_task(
    self: Task,
    task_run_id: str,
    session_id: str,
) -> str:
    actions: list[dict] = []
    terminal_followup: dict[str, object] | None = None
    entered_action_execution = False
    try:
        with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
            ensure_task_not_canceled(task_run_id)
            with SessionLocal() as db:
                task_run = get_task_run(db, task_run_id)
                if task_run is None:
                    raise RuntimeError("编排任务不存在")
                session = db.get(AgentSession, session_id)
                if session is None:
                    raise RuntimeError("haor 会话不存在")
                result_json = task_run.result_json if isinstance(task_run.result_json, dict) else {}
                plan = result_json.get("plan") if isinstance(result_json.get("plan"), dict) else {}
                actions = plan.get("proposed_write_actions") if isinstance(plan.get("proposed_write_actions"), list) else []
                platform_url = (
                    result_json.get("context", {}).get("platform_url")
                    if isinstance(result_json.get("context"), dict)
                    else ""
                )
                if not actions:
                    raise RuntimeError("当前编排任务未找到已批准动作")

            set_task_progress(
                task_run_id,
                8,
                "载入 haor 会话与已批准动作计划",
                _build_orchestrate_progress_result(
                    task_run_id,
                    runtime_patch={
                        "stage": "prepare",
                        "session_id": session_id,
                        "action_count": len(actions),
                    },
                ),
                stage_code="agent_prepare",
                stage_name="载入计划",
            )

            action_results: list[dict] = []
            total_actions = len(actions)
            for index, action in enumerate(actions, start=1):
                ensure_task_not_canceled(task_run_id)
                title = str(action.get("title") or action.get("action_type") or f"动作 {index}")
                stage_progress = min(85, 10 + int((index - 1) * 70 / max(total_actions, 1)))
                set_task_progress(
                    task_run_id,
                    stage_progress,
                    f"执行动作 {index}/{total_actions}: {title}",
                    _build_orchestrate_progress_result(
                        task_run_id,
                        runtime_patch={
                            "stage": "execute_action",
                            "action_index": index,
                            "total_actions": total_actions,
                            "action_type": action.get("action_type"),
                            "title": title,
                        },
                    ),
                    stage_code="agent_execute_action",
                    stage_name="执行动作",
                )
                with SessionLocal() as db:
                    session = db.get(AgentSession, session_id)
                    if session is None:
                        raise RuntimeError("haor 会话不存在")
                    entered_action_execution = True
                    result = execute_approved_action(
                        db,
                        action=action,
                        session_user_id=session.user_id,
                        platform_url=str(platform_url or ""),
                    )
                    action_result = {
                        "index": index,
                        "action_type": action.get("action_type"),
                        "title": title,
                        "status": result.status,
                        "summary": result.summary,
                        "payload": result.payload or {},
                    }
                    action_results.append(action_result)
                    if result.child_task_id:
                        session.last_task_id = result.child_task_id
                        sync_agent_task_watch_state(
                            session,
                            task_id=result.child_task_id,
                            status=result.status,
                            message=result.summary,
                            action=action_result,
                            watching=True,
                        )
                        db.add(session)
                    task_run = get_task_run(db, task_run_id)
                    if task_run is not None:
                        current_result = task_run.result_json if isinstance(task_run.result_json, dict) else {}
                        execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
                        execution["results"] = action_results
                        current_result["execution"] = execution
                        update_task_run(db, task_run, result_json=current_result)
                append_current_task_event(
                    event_type="stage",
                    level="info",
                    stage_code="agent_action_dispatched",
                    stage_name="动作已下发",
                    message=result.summary,
                    progress=stage_progress,
                    payload_json=action_results[-1],
                )
                if result.child_task_id:
                    append_current_task_event(
                        event_type="stage",
                        level="info",
                        stage_code="agent_wait_subtask",
                        stage_name="等待子任务",
                        message=f"等待子任务 {result.child_task_id} 完成",
                        progress=min(90, stage_progress + 5),
                        payload_json={"child_task_id": result.child_task_id},
                    )
                    child_summary = wait_for_child_task(result.child_task_id)
                    action_results[-1]["child_task"] = child_summary
                    followup_action = {**action, "payload": result.payload or {}}
                    followup_message_type, followup_content, followup_resume_hint = build_auto_action_task_followup_content(
                        followup_action,
                        child_summary,
                    )
                    terminal_followup = {
                        "message_type": followup_message_type,
                        "content": followup_content,
                        "payload_json": {
                            "task_id": child_summary.get("task_id") or result.child_task_id,
                            "terminal_status": child_summary.get("status"),
                            "action": followup_action,
                            "child_task": child_summary,
                            "resume_hint": {
                                **followup_resume_hint,
                                "goal_id": getattr(session, "current_goal_id", None),
                            },
                        },
                    }
                    with SessionLocal() as db:
                        task_run = get_task_run(db, task_run_id)
                        if task_run is not None:
                            current_result = task_run.result_json if isinstance(task_run.result_json, dict) else {}
                            execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
                            execution["results"] = action_results
                            current_result["execution"] = execution
                            update_task_run(db, task_run, result_json=current_result)
                    if child_summary.get("status") != TaskExecutionStatus.SUCCESS.value:
                        raise RuntimeError(followup_content)
                elif result.summary:
                    terminal_followup = {
                        "message_type": "task_update",
                        "content": result.summary,
                        "payload_json": {
                            "task_id": task_run_id,
                            "action": {**action, "payload": result.payload or {}},
                            "result_payload": result.payload or {},
                        },
                    }

            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                92,
                "haor 编排计划执行完成，正在写入总结",
                _build_orchestrate_progress_result(
                    task_run_id,
                    runtime_patch={
                        "stage": "finalize",
                        "completed_actions": len(action_results),
                    },
                ),
                stage_code="agent_finalize",
                stage_name="结果收尾",
            )
            with SessionLocal() as db:
                task_run = get_task_run(db, task_run_id)
                if task_run is None:
                    raise RuntimeError("编排任务不存在")
                current_result = task_run.result_json if isinstance(task_run.result_json, dict) else {}
                execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
                execution["results"] = action_results
                current_result["execution"] = execution
                session = db.get(AgentSession, session_id)
                if session is not None:
                    final_message_type = "task_update"
                    final_message_content = f"已完成本轮 haor 编排，共执行 {len(action_results)} 个动作。"
                    final_message_payload = {"results": action_results, "task_id": task_run_id}
                    final_watch_task_id = task_run_id
                    if len(action_results) == 1 and isinstance(terminal_followup, dict):
                        followup_payload = terminal_followup.get("payload_json")
                        final_message_type = str(terminal_followup.get("message_type") or "task_update")
                        final_message_content = str(terminal_followup.get("content") or final_message_content)
                        final_message_payload = {
                            "results": action_results,
                            "task_id": task_run_id,
                            "orchestrate_task_id": task_run_id,
                            **(followup_payload if isinstance(followup_payload, dict) else {}),
                        }
                        final_watch_task_id = str(final_message_payload.get("task_id") or task_run_id)
                    session.status = "active"
                    session.pending_plan_json = {}
                    session.dialog_state_json = {}
                    session.browser_runtime_json = {}
                    session.last_task_id = final_watch_task_id
                    sync_agent_task_watch_state(
                        session,
                        task_id=final_watch_task_id,
                        status=TaskExecutionStatus.SUCCESS.value,
                        message=final_message_content,
                        action=actions[0] if actions else {},
                        watching=False,
                    )
                    db.add(session)
                    append_agent_task_message(
                        db,
                        session_id=session_id,
                        content=final_message_content,
                        payload_json=final_message_payload,
                        message_type=final_message_type,
                    )
                db.commit()
                set_task_success(task_run_id, "haor 编排任务完成", current_result)
    except TaskCanceledError:
        with SessionLocal() as db:
            mark_agent_session_interrupted(
                db,
                session_id=session_id,
                task_id=task_run_id,
                source="agent_task_worker",
            )
            db.commit()
        return task_run_id
    except Exception as exc:
        logger.exception(
            "haor orchestrate task failed",
            extra={
                "task_run_id": task_run_id,
                "session_id": session_id,
                "entered_action_execution": entered_action_execution,
                "action_count": len(actions),
            },
        )
        humanized_error = _humanize_orchestrate_error(exc)
        with SessionLocal() as db:
            session = db.get(AgentSession, session_id)
            if session is not None:
                final_message_type = "error"
                final_message_content = f"本轮 haor 编排失败：{humanized_error}"
                final_message_payload = {"task_id": task_run_id, "error": humanized_error}
                final_watch_task_id = task_run_id
                if isinstance(terminal_followup, dict):
                    followup_payload = terminal_followup.get("payload_json")
                    if str(terminal_followup.get("message_type") or "") == "error":
                        final_message_content = str(terminal_followup.get("content") or final_message_content)
                        final_message_payload = {
                            "task_id": task_run_id,
                            "orchestrate_task_id": task_run_id,
                            "error": humanized_error,
                            **(followup_payload if isinstance(followup_payload, dict) else {}),
                        }
                        final_watch_task_id = str(final_message_payload.get("task_id") or task_run_id)
                session.status = "active"
                session.pending_plan_json = {}
                session.dialog_state_json = {}
                session.browser_runtime_json = {}
                session.last_task_id = final_watch_task_id
                sync_agent_task_watch_state(
                    session,
                    task_id=final_watch_task_id,
                    status=TaskExecutionStatus.FAILURE.value,
                    message=final_message_content,
                    action=actions[0] if actions else {},
                    watching=False,
                )
                db.add(session)
                append_agent_task_message(
                    db,
                    session_id=session_id,
                    content=final_message_content,
                    payload_json=final_message_payload,
                    message_type=final_message_type,
                )
                db.commit()
        should_retry = _should_retry_orchestrate_error(
            exc,
            entered_action_execution=entered_action_execution,
            terminal_followup=terminal_followup,
        )
        if should_retry and self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, humanized_error)
            raise self.retry(exc=exc, countdown=3)
        set_task_failure(task_run_id, self.request.retries, humanized_error)
        raise
    return task_run_id


@celery_app.task(
    bind=True,
    name="app.tasks.agent_tasks.run_agent_auto_followup_task",
    max_retries=0,
)
def run_agent_auto_followup_task(
    self: Task,
    session_id: str,
    child_task_id: str,
    action: dict | None = None,
) -> str:
    normalized_action = action if isinstance(action, dict) else {}
    try:
        child_summary = wait_for_child_task(child_task_id, interval_seconds=0.5)
    except Exception as exc:
        child_summary = {
            "task_id": child_task_id,
            "status": TaskExecutionStatus.FAILURE.value,
            "message": str(exc),
            "error_json": {"error": str(exc)},
        }

    with SessionLocal() as db:
        session = db.get(AgentSession, session_id)
        if session is None:
            return child_task_id
        normalized_action_type = str(normalized_action.get("action_type") or "").strip() or None
        child_terminal_status = str(child_summary.get("status") or "").strip() or None
        if has_agent_task_followup_message(
            session,
            task_id=child_task_id,
            action_type=normalized_action_type,
            terminal_status=child_terminal_status,
        ):
            logger.info(
                "haor auto followup deduped",
                extra={
                    "agent_session_id": session_id,
                    "agent_result": "followup_deduped",
                    "child_task_id": child_task_id,
                    "action_type": normalized_action_type,
                    "terminal_status": child_terminal_status,
                },
            )
            return child_task_id
        message_type, content, resume_hint = build_auto_action_task_followup_content(normalized_action, child_summary)
        append_agent_task_message(
            db,
            session_id=session_id,
            content=content,
            payload_json={
                "task_id": child_task_id,
                "terminal_status": child_terminal_status,
                "auto_followup": True,
                "action": normalized_action,
                "child_task": child_summary,
                "resume_hint": {
                    **resume_hint,
                    "goal_id": getattr(session, "current_goal_id", None),
                },
            },
            message_type=message_type,
        )
        db.commit()
    return child_task_id
