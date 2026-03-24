from __future__ import annotations

from celery import Task

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
                {"session_id": session_id},
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
                    {"action_index": index, "action_type": action.get("action_type"), "title": title},
                    stage_code="agent_execute_action",
                    stage_name="执行动作",
                )
                with SessionLocal() as db:
                    session = db.get(AgentSession, session_id)
                    if session is None:
                        raise RuntimeError("haor 会话不存在")
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
                    if child_summary.get("status") != TaskExecutionStatus.SUCCESS.value:
                        raise RuntimeError(
                            str(child_summary.get("message") or child_summary.get("error_json") or "子任务执行失败")
                        )
                    with SessionLocal() as db:
                        task_run = get_task_run(db, task_run_id)
                        if task_run is not None:
                            current_result = task_run.result_json if isinstance(task_run.result_json, dict) else {}
                            execution = current_result.get("execution") if isinstance(current_result.get("execution"), dict) else {}
                            execution["results"] = action_results
                            current_result["execution"] = execution
                            update_task_run(db, task_run, result_json=current_result)

            ensure_task_not_canceled(task_run_id)
            set_task_progress(
                task_run_id,
                92,
                "haor 编排计划执行完成，正在写入总结",
                {"results": action_results},
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
                    session.status = "active"
                    session.pending_plan_json = {}
                    session.dialog_state_json = {}
                    session.browser_runtime_json = {}
                    session.last_task_id = task_run_id
                    sync_agent_task_watch_state(
                        session,
                        task_id=task_run_id,
                        status=TaskExecutionStatus.SUCCESS.value,
                        message="haor 编排任务完成",
                        action=actions[0] if actions else {},
                        watching=False,
                    )
                    db.add(session)
                    append_agent_task_message(
                        db,
                        session_id=session_id,
                        content=f"已完成本轮 haor 编排，共执行 {len(action_results)} 个动作。",
                        payload_json={"results": action_results, "task_id": task_run_id},
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
        with SessionLocal() as db:
            session = db.get(AgentSession, session_id)
            if session is not None:
                session.status = "active"
                session.pending_plan_json = {}
                session.dialog_state_json = {}
                session.browser_runtime_json = {}
                session.last_task_id = task_run_id
                sync_agent_task_watch_state(
                    session,
                    task_id=task_run_id,
                    status=TaskExecutionStatus.FAILURE.value,
                    message=str(exc),
                    action=actions[0] if actions else {},
                    watching=False,
                )
                db.add(session)
                append_agent_task_message(
                    db,
                    session_id=session_id,
                    content=f"本轮 haor 编排失败：{exc}",
                    payload_json={"task_id": task_run_id, "error": str(exc)},
                    message_type="error",
                )
                db.commit()
        if self.request.retries < self.max_retries:
            set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=3)
        set_task_failure(task_run_id, self.request.retries, str(exc))
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
        if has_agent_task_followup_message(session, task_id=child_task_id):
            return child_task_id
        message_type, content = build_auto_action_task_followup_content(normalized_action, child_summary)
        append_agent_task_message(
            db,
            session_id=session_id,
            content=content,
            payload_json={
                "task_id": child_task_id,
                "auto_followup": True,
                "action": normalized_action,
                "child_task": child_summary,
            },
            message_type=message_type,
        )
        db.commit()
    return child_task_id
