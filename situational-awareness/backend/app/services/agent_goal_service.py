from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.db.models.agent_goal import AgentGoal
from app.db.models.agent_session import AgentSession
from app.db.models.user import User
from app.schemas.agent import AgentGoalRead
from app.services.agent_playbook_service import get_skill_title, infer_goal_profile
from app.utils.sanitize import sanitize_json_value, sanitize_text

GOAL_ACTIVE_STATUSES = {"active", "blocked"}
GOAL_TERMINAL_STATUSES = {"completed", "failed", "canceled"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_goal_status(value: str | None) -> str:
    return sanitize_text(value, max_length=32, single_line=True) or "active"


def _normalize_goal_kind(value: str | None) -> str:
    return sanitize_text(value, max_length=64, single_line=True) or "general"


def _normalize_goal_title(value: str | None) -> str:
    return sanitize_text(value, max_length=255) or "当前目标"


def _goal_query(user_id: str, *, goal_id: str | None = None):
    stmt = (
        select(AgentGoal)
        .where(AgentGoal.user_id == user_id, AgentGoal.agent_id == "haor")
        .options(joinedload(AgentGoal.last_task), joinedload(AgentGoal.last_session))
        .order_by(AgentGoal.updated_at.desc(), AgentGoal.created_at.desc())
    )
    if goal_id:
        stmt = stmt.where(AgentGoal.id == goal_id)
    return stmt


def _goal_context_payload(
    *,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    current_objective: str | None,
    objective_kind: str | None,
) -> dict[str, Any]:
    return {
        "page_context": sanitize_json_value(page_context if isinstance(page_context, dict) else {}),
        "browser_summary": sanitize_json_value(
            browser_context.get("summary_json") if isinstance(browser_context.get("summary_json"), dict) else {}
        ),
        "semantic_page_context": sanitize_json_value(
            browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
        ),
        "working_context": sanitize_json_value(working_context if isinstance(working_context, dict) else {}),
        "current_objective": sanitize_text(current_objective, max_length=255) or None,
        "objective_kind": _normalize_goal_kind(objective_kind),
    }


def serialize_agent_goal(goal: AgentGoal) -> AgentGoalRead:
    return AgentGoalRead(
        id=goal.id,
        user_id=goal.user_id,
        agent_id=goal.agent_id,
        status=goal.status,
        title=goal.title,
        goal_kind=goal.goal_kind,
        success_criteria_json=sanitize_json_value(goal.success_criteria_json if isinstance(goal.success_criteria_json, dict) else {}),
        context_json=sanitize_json_value(goal.context_json if isinstance(goal.context_json, dict) else {}),
        plan_json=sanitize_json_value(goal.plan_json if isinstance(goal.plan_json, dict) else {}),
        progress_json=sanitize_json_value(goal.progress_json if isinstance(goal.progress_json, dict) else {}),
        blocked_reason=goal.blocked_reason,
        last_session_id=goal.last_session_id,
        last_task_id=goal.last_task_id,
        created_at=goal.created_at,
        updated_at=goal.updated_at,
        completed_at=goal.completed_at,
    )


def list_agent_goals(db: Session, *, user: User, limit: int = 12) -> list[AgentGoalRead]:
    stmt = _goal_query(user.id).limit(max(1, min(limit, 50)))
    return [serialize_agent_goal(item) for item in db.scalars(stmt).all()]


def get_agent_goal(db: Session, *, user: User, goal_id: str) -> AgentGoalRead:
    goal = db.scalar(_goal_query(user.id, goal_id=goal_id))
    if goal is None:
        raise LookupError("目标不存在")
    return serialize_agent_goal(goal)


def get_goal_for_user(db: Session, *, user_id: str, goal_id: str | None) -> AgentGoal | None:
    if not goal_id:
        return None
    return db.scalar(_goal_query(user_id, goal_id=goal_id))


def get_recent_resumable_goal(db: Session, *, user_id: str) -> AgentGoal | None:
    stmt = _goal_query(user_id).where(AgentGoal.status.in_(GOAL_ACTIVE_STATUSES)).limit(1)
    return db.scalar(stmt)


def message_requests_goal_resume(content: str) -> bool:
    normalized = sanitize_text(content, max_length=200) or ""
    return any(marker in normalized for marker in ("继续上次", "继续那个", "恢复目标", "恢复上次", "继续之前"))


def _message_requests_credential_unblock(content: str) -> bool:
    normalized = sanitize_text(content, max_length=240) or ""
    lowered = normalized.lower()
    return (
        "继续" in normalized
        or "恢复" in normalized
        or "凭据" in normalized
        or "私钥" in normalized
        or "sudo 密码" in normalized
        or "管理员授权" in normalized
        or ("ssh" in lowered and any(marker in normalized for marker in ("配置", "设置", "密码", "私钥", "凭据", "授权")))
    )


def _goal_blocked_by_credential(goal: AgentGoal | None) -> bool:
    if goal is None:
        return False
    blocked_reason = sanitize_text(goal.blocked_reason, max_length=240) or ""
    if any(marker in blocked_reason for marker in ("SSH", "管理员授权", "管理员权限验证")):
        return True
    progress_json = goal.progress_json if isinstance(goal.progress_json, dict) else {}
    blockers = progress_json.get("blockers") if isinstance(progress_json.get("blockers"), list) else []
    for item in blockers:
        if not isinstance(item, dict):
            continue
        blocker_code = sanitize_text(str(item.get("blocker_code") or ""), max_length=64, single_line=True) or ""
        blocker_message = sanitize_text(str(item.get("blocker_message") or ""), max_length=240) or ""
        if blocker_code in {"missing_ssh_credential", "authorization_unconfirmed", "authorization_not_verified", "insufficient_privilege"}:
            return True
        if any(marker in blocker_message for marker in ("SSH", "管理员授权", "管理员权限验证")):
            return True
    return False


def create_agent_goal(
    db: Session,
    *,
    user: User,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    current_objective: str | None,
    objective_kind: str | None,
) -> AgentGoal:
    profile = infer_goal_profile(content=content, page_context=page_context, working_context=working_context)
    goal = AgentGoal(
        user_id=user.id,
        agent_id="haor",
        status="active",
        title=_normalize_goal_title(profile.get("title")),
        goal_kind=_normalize_goal_kind(profile.get("goal_kind")),
        success_criteria_json=sanitize_json_value(
            profile.get("success_criteria_json") if isinstance(profile.get("success_criteria_json"), dict) else {}
        ),
        context_json=_goal_context_payload(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            current_objective=current_objective,
            objective_kind=objective_kind,
        ),
        plan_json={},
        progress_json={
            "summary": _normalize_goal_title(profile.get("title")),
            "stage": "active",
        },
    )
    db.add(goal)
    db.flush()
    return goal


def attach_goal_to_session(session: AgentSession, goal: AgentGoal | None) -> None:
    session.current_goal = goal
    session.current_goal_id = goal.id if goal is not None else None


def mark_goal_blocked(goal: AgentGoal, *, reason: str | None) -> None:
    goal.status = "blocked"
    goal.blocked_reason = sanitize_text(reason, max_length=500) or None
    goal.completed_at = None
    goal.updated_at = _now()


def mark_goal_canceled(goal: AgentGoal, *, reason: str | None = None) -> None:
    goal.status = "canceled"
    goal.blocked_reason = sanitize_text(reason, max_length=500) or "用户已取消当前目标"
    goal.completed_at = _now()
    goal.updated_at = goal.completed_at


def resume_agent_goal_binding(
    db: Session,
    *,
    user: User,
    session: AgentSession,
    goal_id: str,
) -> AgentGoal:
    goal = db.scalar(_goal_query(user.id, goal_id=goal_id))
    if goal is None:
        raise LookupError("目标不存在")
    goal.status = "active"
    goal.blocked_reason = None
    goal.completed_at = None
    goal.last_session_id = session.id
    goal.updated_at = _now()
    attach_goal_to_session(session, goal)
    return goal


def ensure_goal_for_message(
    db: Session,
    *,
    user: User,
    session: AgentSession,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    followup_hint: dict[str, Any],
    current_objective: str | None,
    objective_kind: str | None,
) -> AgentGoal:
    existing_goal = session.current_goal
    reply_kind = sanitize_text(str(followup_hint.get("reply_kind") or ""), max_length=32, single_line=True) or ""

    if existing_goal is None and message_requests_goal_resume(content):
        resumable = get_recent_resumable_goal(db, user_id=user.id)
        if resumable is not None:
            existing_goal = resumable
            attach_goal_to_session(session, resumable)

    if (
        existing_goal is not None
        and _normalize_goal_status(existing_goal.status) not in GOAL_TERMINAL_STATUSES
        and _goal_blocked_by_credential(existing_goal)
        and _message_requests_credential_unblock(content)
    ):
        existing_goal.status = "active"
        existing_goal.updated_at = _now()
        existing_goal.last_session_id = session.id
        existing_goal.context_json = _goal_context_payload(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            current_objective=current_objective,
            objective_kind=objective_kind,
        )
        attach_goal_to_session(session, existing_goal)
        return existing_goal

    if existing_goal is not None and reply_kind != "new_topic" and _normalize_goal_status(existing_goal.status) not in GOAL_TERMINAL_STATUSES:
        existing_goal.status = "active"
        existing_goal.blocked_reason = None
        existing_goal.updated_at = _now()
        existing_goal.last_session_id = session.id
        existing_goal.context_json = _goal_context_payload(
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            current_objective=current_objective,
            objective_kind=objective_kind,
        )
        return existing_goal

    if existing_goal is not None and _normalize_goal_status(existing_goal.status) not in GOAL_TERMINAL_STATUSES:
        mark_goal_blocked(existing_goal, reason="用户切换到新的目标")

    goal = create_agent_goal(
        db,
        user=user,
        content=content,
        page_context=page_context,
        browser_context=browser_context,
        working_context=working_context,
        current_objective=current_objective,
        objective_kind=objective_kind,
    )
    goal.last_session_id = session.id
    attach_goal_to_session(session, goal)
    return goal


def derive_goal_status_from_session(
    session: AgentSession,
    *,
    status_override: str | None = None,
    blocked_reason: str | None = None,
) -> tuple[str, str | None]:
    if status_override:
        normalized_override = _normalize_goal_status(status_override)
        if normalized_override in GOAL_TERMINAL_STATUSES | GOAL_ACTIVE_STATUSES:
            return normalized_override, sanitize_text(blocked_reason, max_length=500) or None

    session_status = sanitize_text(str(session.status or ""), max_length=32, single_line=True) or "active"
    agent_state = session.agent_state_json if isinstance(session.agent_state_json, dict) else {}
    execution = agent_state.get("execution") if isinstance(agent_state.get("execution"), dict) else {}
    explanation = agent_state.get("explanation") if isinstance(agent_state.get("explanation"), dict) else {}
    watch = agent_state.get("watch") if isinstance(agent_state.get("watch"), dict) else {}
    stage = sanitize_text(str(execution.get("stage") or ""), max_length=32, single_line=True) or "idle"
    waiting_for = sanitize_text(str(execution.get("waiting_for") or explanation.get("next_step") or ""), max_length=500) or None

    if session_status == "failed" or stage == "failed":
        return "failed", sanitize_text(blocked_reason or explanation.get("decision_summary"), max_length=500) or waiting_for
    if session_status == "completed" or stage == "completed":
        return "completed", None
    if session_status == "waiting_approval" or stage in {"waiting_approval", "waiting_user_input", "awaiting_secure_input", "blocked"}:
        return "blocked", sanitize_text(blocked_reason or waiting_for, max_length=500) or None
    if bool(watch.get("watching")) or session_status == "running" or stage in {
        "planning",
        "reading",
        "watching_task",
        "awaiting_ui_feedback",
        "resolving_ui_feedback",
        "awaiting_agent_reply",
    }:
        return "active", None
    return "active", None


def _normalize_goal_progress_blockers(
    blockers: list[dict[str, Any]] | None,
    *,
    fallback_next_step: str | None,
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str, str]] = set()
    for item in blockers or []:
        if not isinstance(item, dict):
            continue
        blocker_code = sanitize_text(
            str(item.get("blocker_code") or item.get("code") or ""),
            max_length=64,
            single_line=True,
        ) or "goal_blocked"
        blocker_message = sanitize_text(
            str(item.get("blocker_message") or item.get("message") or ""),
            max_length=500,
        ) or ""
        if not blocker_message:
            continue
        normalized_item = {
            "blocker_code": blocker_code,
            "blocker_message": blocker_message,
            "recommended_next_step": sanitize_text(
                str(item.get("recommended_next_step") or fallback_next_step or ""),
                max_length=240,
            ) or None,
            "scope": sanitize_text(str(item.get("scope") or ""), max_length=64, single_line=True) or None,
            "blocking": sanitize_text(str(item.get("blocking") or ""), max_length=32, single_line=True) or None,
            "stage_code": sanitize_text(str(item.get("stage_code") or ""), max_length=64, single_line=True) or None,
            "step_id": sanitize_text(str(item.get("step_id") or ""), max_length=64, single_line=True) or None,
        }
        signature = (
            normalized_item["blocker_code"] or "",
            normalized_item["blocker_message"] or "",
            normalized_item["scope"] or "",
            normalized_item["blocking"] or "",
            normalized_item["stage_code"] or "",
            normalized_item["step_id"] or "",
        )
        if signature in seen:
            continue
        seen.add(signature)
        normalized.append(normalized_item)
    return normalized


def sync_goal_from_session(
    goal: AgentGoal,
    session: AgentSession,
    *,
    status_override: str | None = None,
    blocked_reason: str | None = None,
    latest_summary: str | None = None,
    goal_blockers: list[dict[str, Any]] | None = None,
) -> AgentGoal:
    agent_state = session.agent_state_json if isinstance(session.agent_state_json, dict) else {}
    focus = agent_state.get("focus") if isinstance(agent_state.get("focus"), dict) else {}
    execution = agent_state.get("execution") if isinstance(agent_state.get("execution"), dict) else {}
    explanation = agent_state.get("explanation") if isinstance(agent_state.get("explanation"), dict) else {}
    watch = agent_state.get("watch") if isinstance(agent_state.get("watch"), dict) else {}
    runtime = session.browser_runtime_json if isinstance(session.browser_runtime_json, dict) else {}
    last_browser_context = runtime.get("last_browser_context") if isinstance(runtime.get("last_browser_context"), dict) else {}
    last_browser_summary = (
        last_browser_context.get("summary_json") if isinstance(last_browser_context.get("summary_json"), dict) else {}
    )
    semantic_page_context = (
        runtime.get("semantic_page_context")
        if isinstance(runtime.get("semantic_page_context"), dict)
        else (
            last_browser_context.get("semantic_page_context")
            if isinstance(last_browser_context.get("semantic_page_context"), dict)
            else {}
        )
    )
    derived_status, derived_blocked_reason = derive_goal_status_from_session(
        session,
        status_override=status_override,
        blocked_reason=blocked_reason,
    )
    summary = sanitize_text(
        latest_summary
        or explanation.get("decision_summary")
        or watch.get("last_task_message")
        or focus.get("summary")
        or goal.title,
        max_length=280,
    ) or goal.title
    active_skill_id = (
        sanitize_text(goal.goal_kind, max_length=128, single_line=True)
        if sanitize_text(goal.goal_kind, max_length=128, single_line=True) not in {None, "", "general"}
        else None
    )
    watch_task_id = sanitize_text(
        str(watch.get("primary_task_id") or session.last_task_id or goal.last_task_id or ""),
        max_length=64,
        single_line=True,
    ) or None
    fallback_next_step = sanitize_text(
        str(explanation.get("next_step") or execution.get("waiting_for") or ""),
        max_length=240,
    ) or None
    existing_progress = goal.progress_json if isinstance(goal.progress_json, dict) else {}
    existing_blockers = existing_progress.get("blockers") if isinstance(existing_progress.get("blockers"), list) else []
    blockers = _normalize_goal_progress_blockers(goal_blockers, fallback_next_step=fallback_next_step)
    if not blockers and derived_status == "blocked":
        blockers = _normalize_goal_progress_blockers(existing_blockers, fallback_next_step=fallback_next_step)
    if not blockers and derived_blocked_reason:
        blockers = [
            {
                "blocker_code": "goal_blocked",
                "blocker_message": derived_blocked_reason,
                "recommended_next_step": fallback_next_step,
                "scope": None,
                "blocking": None,
                "stage_code": None,
                "step_id": None,
            }
        ]

    goal.status = derived_status
    goal.blocked_reason = derived_blocked_reason
    goal.last_session_id = session.id
    goal.last_task_id = sanitize_text(str(session.last_task_id or goal.last_task_id or ""), max_length=64, single_line=True) or None
    goal.context_json = _goal_context_payload(
        page_context=session.route_context_json if isinstance(session.route_context_json, dict) else {},
        browser_context={
            "summary_json": last_browser_summary,
            "semantic_page_context": semantic_page_context,
        },
        working_context=session.working_context_json if isinstance(session.working_context_json, dict) else {},
        current_objective=runtime.get("current_objective") if isinstance(runtime, dict) else None,
        objective_kind=runtime.get("objective_kind") if isinstance(runtime, dict) else None,
    )
    goal.plan_json = {
        "pending_plan": sanitize_json_value(session.pending_plan_json if isinstance(session.pending_plan_json, dict) else {}),
        "planned_steps": sanitize_json_value(runtime.get("planned_steps") if isinstance(runtime.get("planned_steps"), list) else []),
        "pending_ui_actions": sanitize_json_value(runtime.get("pending_ui_actions") if isinstance(runtime.get("pending_ui_actions"), list) else []),
        "last_ui_results": sanitize_json_value(runtime.get("last_ui_results") if isinstance(runtime.get("last_ui_results"), list) else []),
    }
    goal.progress_json = {
        "summary": summary,
        "stage": sanitize_text(str(execution.get("stage") or ""), max_length=64, single_line=True) or "active",
        "blockers": blockers,
        "last_result": sanitize_text(
            str(watch.get("last_task_message") or explanation.get("decision_summary") or latest_summary or ""),
            max_length=280,
        ) or None,
        "next_step": sanitize_text(str(explanation.get("next_step") or execution.get("waiting_for") or ""), max_length=280) or None,
        "active_skill_id": active_skill_id,
        "active_skill_title": get_skill_title(active_skill_id),
        "watch_task_id": watch_task_id,
        "updated_at": _now().isoformat(),
    }
    goal.updated_at = _now()
    if derived_status in {"completed", "failed", "canceled"}:
        goal.completed_at = goal.completed_at or goal.updated_at
    else:
        goal.completed_at = None
    return goal
