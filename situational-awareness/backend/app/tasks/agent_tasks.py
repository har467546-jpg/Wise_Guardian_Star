from __future__ import annotations

import logging
from copy import deepcopy
from typing import Any

from celery import Task
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm.exc import DetachedInstanceError

from app.core.celery_app import celery_app
from app.db.models.agent_session import AgentSession
from app.db.models.enums import TaskExecutionStatus
from app.db.session import SessionLocal
from app.repositories.task_repo import get_task_run, update_task_run
from app.services.haor_agent_service import (
    append_blocked_action_result_message,
    append_agent_task_message,
    build_auto_action_task_followup_content,
    enqueue_auto_action_followup_task,
    execute_approved_action,
    has_agent_task_followup_message,
    mark_agent_session_interrupted,
    sync_agent_task_watch_state,
    transition_session_to_remediation_secure_input,
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
    "当前阶段包含高风险步骤，请先填写 maintenance_window_id 后再正式执行",
    "修复会话不存在",
)
_NON_RETRYABLE_ORCHESTRATE_ERRORS = _NON_RETRYABLE_REMEDIATION_ERRORS + (
    "会话状态已过期，请刷新页面后重试",
)
_SSH_REMEDIATION_BLOCKER_CODES = {
    "missing_ssh_credential",
    "authorization_unconfirmed",
    "authorization_not_verified",
    "insufficient_privilege",
}
_TERMINAL_FOLLOWUP_SECURE_INPUT = "secure_input_required"
_TERMINAL_FOLLOWUP_BLOCKED = "blocked"


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
    if isinstance(exc, DetachedInstanceError) or (
        "is not bound to a Session" in raw_message and "attribute refresh operation cannot proceed" in raw_message
    ):
        return "会话状态已过期，请刷新页面后重试"
    if isinstance(exc, (IntegrityError, ProgrammingError)):
        lowered = raw_message.lower()
        if "remediation_sessions_approved_by_fkey" in raw_message or (
            "remediation_sessions" in lowered and "approved_by" in lowered
        ):
            return "审批人信息无效，请刷新页面后重试"
        return "haor 编排执行失败，请稍后重试"
    for message in _NON_RETRYABLE_ORCHESTRATE_ERRORS:
        if message in raw_message:
            return message
    sanitized = sanitize_text(raw_message, max_length=200, single_line=True) or ""
    return sanitized or "haor 编排执行失败，请稍后重试"


def _is_post_verify_upstream_failure(exc: Exception) -> bool:
    lowered = str(exc or "").strip().lower()
    if not lowered:
        return False
    markers = (
        "ai 模型服务异常",
        "上游模型",
        "upstream",
        "bad gateway",
        "gateway timeout",
        "cloudflare",
        "502",
        "503",
        "504",
        "/responses",
        "model service",
    )
    return any(marker in lowered for marker in markers)


def _mark_post_verify_reassessment_wait_state(
    session: AgentSession,
    *,
    refresh_task_id: str,
    content: str,
) -> None:
    current_state = getattr(session, "agent_state_json", None)
    current_state = current_state if isinstance(current_state, dict) else {}
    session.status = "running"
    session.last_task_id = refresh_task_id
    session.agent_state_json = _deep_merge_dict(
        current_state,
        {
            "execution": {
                "stage": "watching_task",
                "step_kind": "secure_input",
                "step_label": "主机事实已刷新，正在重新评估修复条件",
                "waiting_for": "等待重新评估自动修复条件",
                "missing_slots": [],
                "pending_ui_actions": [],
            },
            "explanation": {
                "reason": "SSH 凭据验证成功后，主机事实已刷新，正在重新评估自动修复条件",
                "decision_summary": content,
                "expected_outcome": "完成修复条件重评估后，自动继续修复或明确剩余阻塞",
                "next_step": "若上游模型响应较慢，这一步可能比采集更久；完成后会自动回传结论",
                "evidence": [],
            },
            "watch": {
                "primary_task_id": refresh_task_id,
                "related_task_ids": [refresh_task_id],
                "status": TaskExecutionStatus.RUNNING.value,
                "watching": True,
                "last_task_message": content,
            },
        },
    )


def _is_submit_if_ready_remediation_action(action: dict[str, Any]) -> bool:
    if str(action.get("action_type") or "").strip() != "create_or_resume_remediation_session":
        return False
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    raw_submit_if_ready = params.get("submit_if_ready")
    if isinstance(raw_submit_if_ready, bool):
        return raw_submit_if_ready
    if isinstance(raw_submit_if_ready, str):
        return raw_submit_if_ready.strip().lower() in {"true", "1", "yes", "y", "on"}
    return bool(raw_submit_if_ready)


def _result_blocker_codes(result_payload: dict[str, Any] | None) -> list[str]:
    payload = result_payload if isinstance(result_payload, dict) else {}
    blocker_codes = payload.get("blocker_codes") if isinstance(payload.get("blocker_codes"), list) else []
    normalized: list[str] = []
    for item in blocker_codes:
        code = str(item or "").strip()
        if code and code not in normalized:
            normalized.append(code)
    return normalized


def _remediation_blocked_followup_mode(
    action: dict[str, Any],
    *,
    child_task_id: str | None,
    result_payload: dict[str, Any] | None,
) -> str | None:
    if child_task_id:
        return None
    payload = result_payload if isinstance(result_payload, dict) else {}
    action_type = str(action.get("action_type") or "").strip()
    if action_type == "approve_remediation_session":
        if payload.get("execution_ready") is False or _result_blocker_codes(payload):
            return _TERMINAL_FOLLOWUP_BLOCKED
        return None
    if not _is_submit_if_ready_remediation_action(action):
        return None
    if payload.get("execution_ready") is not False:
        return None
    if any(code in _SSH_REMEDIATION_BLOCKER_CODES for code in _result_blocker_codes(payload)):
        return _TERMINAL_FOLLOWUP_SECURE_INPUT
    return _TERMINAL_FOLLOWUP_BLOCKED


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
    if humanized in _NON_RETRYABLE_ORCHESTRATE_ERRORS:
        return False
    return True


def _result_blocker_categories(result_payload: dict[str, Any] | None) -> list[str]:
    payload = result_payload if isinstance(result_payload, dict) else {}
    raw_categories = payload.get("blocker_categories") if isinstance(payload.get("blocker_categories"), list) else []
    normalized: list[str] = []
    for item in raw_categories:
        category = str(item or "").strip()
        if category and category not in normalized:
            normalized.append(category)
    return normalized


def _summarize_post_refresh_blocked_content(
    *,
    asset_id: str,
    result_summary: str,
    result_payload: dict[str, Any] | None,
) -> str:
    payload = result_payload if isinstance(result_payload, dict) else {}
    blocker_categories = _result_blocker_categories(payload)
    blocker_messages = payload.get("blocked_reasons") if isinstance(payload.get("blocked_reasons"), list) else []
    blocker_summary = "；".join(str(item).strip() for item in blocker_messages if str(item).strip())
    normalized_asset_id = str(asset_id or "").strip() or "目标资产"
    if "runner" in blocker_categories and "render" in blocker_categories:
        summary = blocker_summary or result_summary or "仍存在 Host Runner 与步骤渲染前置条件"
        return (
            f"资产 {normalized_asset_id} 的 SSH 凭据已验证成功，主机信息也已刷新，但整机自动修复仍未继续执行。"
            f"当前阻塞：{summary}。即使先安装 Runner，也不保证能立即自动修成功；你也可以改走交互式修复预演。"
        )
    if "runner" in blocker_categories:
        summary = blocker_summary or result_summary or "当前主机尚未安装 Host Runner"
        return (
            f"资产 {normalized_asset_id} 的 SSH 凭据已验证成功，主机信息也已刷新，但整机自动修复仍需要 Host Runner。"
            f" 当前阻塞：{summary}。建议先安装 Runner，再继续自动修复。"
        )
    if "render" in blocker_categories:
        summary = blocker_summary or result_summary or "当前仍无法稳定生成自动修复步骤"
        return (
            f"资产 {normalized_asset_id} 的 SSH 凭据已验证成功，主机信息也已刷新，但当前仍不适合继续整机自动修复。"
            f" 当前阻塞：{summary}。这类情况更适合先走交互式修复预演或人工处理。"
        )
    summary = blocker_summary or result_summary or "仍有其他前置条件未满足"
    return (
        f"资产 {normalized_asset_id} 的 SSH 凭据已验证成功，主机信息也已刷新，但自动修复暂未继续执行。"
        f" 当前阻塞：{summary}。你可以先查看修复工作台详情，再决定下一步。"
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
                    current_goal_id = getattr(session, "current_goal_id", None)
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
                                "goal_id": current_goal_id,
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
                    remediation_followup_mode = _remediation_blocked_followup_mode(
                        action,
                        child_task_id=result.child_task_id,
                        result_payload=result.payload,
                    )
                    terminal_followup = {
                        "message_type": remediation_followup_mode or "task_update",
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
                        followup_message_type = str(terminal_followup.get("message_type") or "task_update")
                        followup_content = str(terminal_followup.get("content") or final_message_content)
                        followup_payload_json = followup_payload if isinstance(followup_payload, dict) else {}
                        if followup_message_type == _TERMINAL_FOLLOWUP_SECURE_INPUT:
                            transition_session_to_remediation_secure_input(
                                db,
                                session_id=session_id,
                                task_id=task_run_id,
                                action=followup_payload_json.get("action")
                                if isinstance(followup_payload_json.get("action"), dict)
                                else (actions[0] if actions else {}),
                                result_payload=followup_payload_json.get("result_payload")
                                if isinstance(followup_payload_json.get("result_payload"), dict)
                                else {},
                                content=followup_content,
                            )
                            db.commit()
                            set_task_success(task_run_id, "haor 编排任务完成", current_result)
                            return task_run_id
                        if followup_message_type == _TERMINAL_FOLLOWUP_BLOCKED:
                            append_blocked_action_result_message(
                                db,
                                session_id=session_id,
                                task_id=task_run_id,
                                action=followup_payload_json.get("action")
                                if isinstance(followup_payload_json.get("action"), dict)
                                else (actions[0] if actions else {}),
                                result_payload=followup_payload_json.get("result_payload")
                                if isinstance(followup_payload_json.get("result_payload"), dict)
                                else {},
                                content=followup_content,
                            )
                            db.commit()
                            set_task_success(task_run_id, "haor 编排任务完成", current_result)
                            return task_run_id
                        final_message_type = followup_message_type
                        final_message_content = followup_content
                        final_message_payload = {
                            "results": action_results,
                            "task_id": task_run_id,
                            "orchestrate_task_id": task_run_id,
                            **followup_payload_json,
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
        action_params = normalized_action.get("params") if isinstance(normalized_action.get("params"), dict) else {}
        resume_action = action_params.get("resume_action") if isinstance(action_params.get("resume_action"), dict) else {}
        if (
            normalized_action_type == "install_runner"
            and child_terminal_status == TaskExecutionStatus.SUCCESS.value
            and resume_action
        ):
            asset_id = str(action_params.get("asset_id") or "").strip() or "目标资产"
            try:
                resume_result = execute_approved_action(
                    db,
                    action=resume_action,
                    session_user_id=getattr(session, "user_id", ""),
                    platform_url="",
                )
            except Exception as exc:
                append_agent_task_message(
                    db,
                    session_id=session_id,
                    content=(
                        f"资产 {asset_id} 的 Runner 安装任务已完成，"
                        f"但自动续接修复失败：{sanitize_text(str(exc), max_length=280) or '未知错误'}"
                    ),
                    payload_json={
                        "task_id": child_task_id,
                        "terminal_status": child_terminal_status,
                        "auto_followup": True,
                        "action": normalized_action,
                        "child_task": child_summary,
                        "resume_action": resume_action,
                    },
                    message_type="error",
                )
                db.commit()
                return child_task_id

            resumed_action = {
                "action_type": resume_action.get("action_type"),
                "title": resume_action.get("title"),
                "status": resume_result.status,
                "summary": resume_result.summary,
                "params": deepcopy(resume_action.get("params") if isinstance(resume_action.get("params"), dict) else {}),
                "payload": resume_result.payload or {},
                "child_task_id": resume_result.child_task_id,
            }
            resume_child_summary = {
                "task_id": resume_result.child_task_id,
                "status": TaskExecutionStatus.SUCCESS.value if resume_result.status == "success" else resume_result.status,
                "message": resume_result.summary,
                "result_json": resume_result.payload or {},
                "error_json": {},
            }
            resume_hint = build_auto_action_task_followup_content(resumed_action, resume_child_summary)[2]
            append_agent_task_message(
                db,
                session_id=session_id,
                content=f"资产 {asset_id} 的 Runner 安装任务已完成。{resume_result.summary}",
                payload_json={
                    "task_id": child_task_id,
                    "terminal_status": child_terminal_status,
                    "auto_followup": True,
                    "action": normalized_action,
                    "child_task": child_summary,
                    "resume_action": resume_action,
                    "resume_action_result": resumed_action,
                    "resume_hint": {
                        **resume_hint,
                        "goal_id": getattr(session, "current_goal_id", None),
                    },
                },
                message_type="task_update",
            )
            if resume_result.child_task_id:
                session.last_task_id = resume_result.child_task_id
                sync_agent_task_watch_state(
                    session,
                    task_id=resume_result.child_task_id,
                    status=resume_result.status,
                    message=resume_result.summary,
                    action=resumed_action,
                    watching=True,
                )
                enqueue_auto_action_followup_task(
                    session_id=session_id,
                    child_task_id=resume_result.child_task_id,
                    action=resumed_action,
                )
            db.commit()
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


@celery_app.task(
    bind=True,
    name="app.tasks.agent_tasks.run_agent_secure_post_verify_resume_task",
    max_retries=0,
)
def run_agent_secure_post_verify_resume_task(
    self: Task,
    session_id: str,
    refresh_task_id: str,
    action: dict | None = None,
    asset_id: str | None = None,
) -> str:
    normalized_action = action if isinstance(action, dict) else {}
    normalized_asset_id = str(asset_id or "").strip() or (
        str((normalized_action.get("params") if isinstance(normalized_action.get("params"), dict) else {}).get("asset_id") or "").strip()
    )
    try:
        refresh_summary = wait_for_child_task(refresh_task_id, interval_seconds=0.5)
    except Exception as exc:
        refresh_summary = {
            "task_id": refresh_task_id,
            "status": TaskExecutionStatus.FAILURE.value,
            "message": str(exc),
            "error_json": {"error": str(exc)},
        }

    refresh_terminal_status = str(refresh_summary.get("status") or "").strip().lower()
    if refresh_terminal_status != TaskExecutionStatus.SUCCESS.value:
        with SessionLocal() as db:
            append_blocked_action_result_message(
                db,
                session_id=session_id,
                task_id=refresh_task_id,
                action=normalized_action,
                result_payload={"asset_id": normalized_asset_id, "refresh_task": refresh_summary},
                content=(
                    f"资产 {normalized_asset_id or '目标资产'} 的 SSH 凭据已验证成功，但主机事实刷新失败，暂无法继续自动修复。"
                    "请查看采集任务详情或稍后重试。"
                ),
                blocked_reason="SSH 已配置成功，但主机事实刷新失败，暂无法继续自动修复",
                message_payload_patch={
                    "refresh_task_id": refresh_task_id,
                    "refresh_task": refresh_summary,
                    "post_verify_action": "refresh_failed",
                },
            )
            db.commit()
        return refresh_task_id

    with SessionLocal() as db:
        session = db.get(AgentSession, session_id)
        if session is None:
            return refresh_task_id
        reassessing_content = (
            f"资产 {normalized_asset_id or '目标资产'} 的主机信息已刷新，正在重新评估修复条件。"
            "若上游模型响应较慢或暂时不可用，这一步可能比采集更久。"
        )
        append_agent_task_message(
            db,
            session_id=session_id,
            content=reassessing_content,
            payload_json={
                "task_id": refresh_task_id,
                "refresh_task_id": refresh_task_id,
                "refresh_task": refresh_summary,
                "action": normalized_action,
                "post_verify_action": "refresh_reassessing",
            },
            message_type="action_update",
            watching=False,
        )
        _mark_post_verify_reassessment_wait_state(
            session,
            refresh_task_id=refresh_task_id,
            content=reassessing_content,
        )
        db.commit()
        try:
            result = execute_approved_action(
                db,
                action=normalized_action,
                session_user_id=session.user_id,
                platform_url="",
            )
        except Exception as exc:
            if _is_post_verify_upstream_failure(exc):
                content = (
                    f"资产 {normalized_asset_id or '目标资产'} 的主机信息已刷新，"
                    "但重新评估修复条件时上游模型暂时不可用，请稍后恢复会话或重试。"
                )
            else:
                content = (
                    f"资产 {normalized_asset_id or '目标资产'} 的 SSH 凭据已验证成功，主机信息也已刷新，"
                    f"但重新评估自动修复时失败：{sanitize_text(str(exc), max_length=200) or '未知错误'}"
                )
            append_agent_task_message(
                db,
                session_id=session_id,
                content=content,
                payload_json={
                    "task_id": refresh_task_id,
                    "refresh_task_id": refresh_task_id,
                    "refresh_task": refresh_summary,
                    "action": normalized_action,
                    "post_verify_action": "refresh_resume_failed",
                },
                message_type="error",
            )
            db.commit()
            return refresh_task_id

        result_payload = result.payload if isinstance(result.payload, dict) else {}
        if result.child_task_id:
            action_payload = {**normalized_action, "payload": result_payload}
            append_agent_task_message(
                db,
                session_id=session_id,
                content=(
                    f"资产 {normalized_asset_id or '目标资产'} 的主机信息已刷新。"
                    "我已重新评估修复条件，并继续自动修复。"
                ),
                payload_json={
                    "task_id": result.child_task_id,
                    "refresh_task_id": refresh_task_id,
                    "refresh_task": refresh_summary,
                    "action": action_payload,
                    "child_task": {
                        "task_id": result.child_task_id,
                        "status": TaskExecutionStatus.RUNNING.value,
                        "message": result.summary,
                    },
                    "result_payload": result_payload,
                    "post_verify_action": "refresh_and_resume",
                },
                message_type="action_update",
                watching=True,
            )
            db.commit()
            enqueue_auto_action_followup_task(
                session_id=session_id,
                child_task_id=result.child_task_id,
                action=action_payload,
            )
            return result.child_task_id

        blocked_content = _summarize_post_refresh_blocked_content(
            asset_id=normalized_asset_id,
            result_summary=result.summary,
            result_payload=result_payload,
        )
        append_blocked_action_result_message(
            db,
            session_id=session_id,
            task_id=refresh_task_id,
            action=normalized_action,
            result_payload=result_payload,
            content=blocked_content,
            blocked_reason=result.summary or blocked_content,
            message_payload_patch={
                "refresh_task_id": refresh_task_id,
                "refresh_task": refresh_summary,
                "post_verify_action": "interactive_remediation_recommended"
                if "render" in _result_blocker_categories(result_payload)
                else "runner_required"
                if "runner" in _result_blocker_categories(result_payload)
                else "review_remediation_workspace",
            },
        )
        db.commit()
    return refresh_task_id
