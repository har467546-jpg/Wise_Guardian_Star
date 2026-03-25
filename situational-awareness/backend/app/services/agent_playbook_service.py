from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.utils.sanitize import sanitize_json_value, sanitize_text

CIDR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

PLAYBOOK_SCAN_AND_ANALYZE_CIDR = "scan_and_analyze_cidr"
PLAYBOOK_ANALYZE_ASSET_RISKS = "analyze_asset_risks"
PLAYBOOK_VERIFY_ASSET_RISKS = "verify_asset_risks"
PLAYBOOK_INSTALL_RUNNER = "install_runner"
PLAYBOOK_START_REMEDIATION_SESSION = "start_remediation_session"
GOAL_KIND_GENERAL = "general"


@dataclass(frozen=True, slots=True)
class AgentPlaybookDecision:
    playbook_id: str
    objective: str
    reply_markdown: str
    conversation_state: str = "answer"
    read_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    ui_actions: list[dict[str, Any]] = field(default_factory=list)
    proposed_write_actions: list[dict[str, Any]] = field(default_factory=list)
    auto_execute_actions: list[dict[str, Any]] = field(default_factory=list)
    needs_confirmation: bool = False
    stop_reason: str | None = None


def _normalize_text(value: str | None, *, max_length: int = 400) -> str:
    return sanitize_text(value, max_length=max_length) or ""


def _normalize_id(value: Any) -> str | None:
    text = sanitize_text(str(value or ""), max_length=64, single_line=True) or ""
    return text or None


def _extract_cidr(value: str) -> str | None:
    match = CIDR_PATTERN.search(value)
    if not match:
        return None
    return sanitize_text(match.group(0), max_length=64, single_line=True) or None


def _contains_any(content: str, markers: tuple[str, ...]) -> bool:
    return any(marker in content for marker in markers)


def _contains_risk_verification_intent(content: str) -> bool:
    return _contains_any(content, ("验证风险", "风险验证", "复核风险", "校验风险")) or (
        "验证" in content and "风险" in content
    )


def _asset_id_from_context(page_context: dict[str, Any], working_context: dict[str, Any]) -> str | None:
    return _normalize_id(working_context.get("asset_id") or page_context.get("asset_id"))


def _goal_success_criteria(goal_kind: str, *, title: str, working_context: dict[str, Any]) -> dict[str, Any]:
    asset_id = _asset_id_from_context({}, working_context)
    if goal_kind == PLAYBOOK_SCAN_AND_ANALYZE_CIDR:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                "扫描任务完成",
                "已返回网段内资产或风险结论",
            ],
        }
    if goal_kind == PLAYBOOK_ANALYZE_ASSET_RISKS:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                f"已读取资产 {asset_id or '当前资产'} 的详情和风险列表",
                "已给出风险分析与下一步建议",
            ],
        }
    if goal_kind == PLAYBOOK_VERIFY_ASSET_RISKS:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                f"已触发资产 {asset_id or '当前资产'} 的风险验证任务",
                "验证结果已自动回传到会话",
            ],
        }
    if goal_kind == PLAYBOOK_INSTALL_RUNNER:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                f"已触发资产 {asset_id or '当前资产'} 的 Runner 安装任务",
                "安装状态已自动回传到会话",
            ],
        }
    if goal_kind == PLAYBOOK_START_REMEDIATION_SESSION:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                f"已为资产 {asset_id or '当前资产'} 准备修复会话",
                "已给出下一步修复执行建议",
            ],
        }
    return {
        "goal_kind": goal_kind or GOAL_KIND_GENERAL,
        "done_when": [
            sanitize_text(title, max_length=160) or "当前目标已完成",
        ],
    }


def infer_goal_profile(
    *,
    content: str,
    page_context: dict[str, Any],
    working_context: dict[str, Any],
) -> dict[str, Any]:
    normalized = _normalize_text(content)
    cidr = _extract_cidr(normalized)
    asset_id = _asset_id_from_context(page_context, working_context)

    if cidr and _contains_any(normalized, ("扫描", "分析", "网段", "漏洞", "风险")):
        title = f"扫描并分析 {cidr}"
        goal_kind = PLAYBOOK_SCAN_AND_ANALYZE_CIDR
    elif asset_id and _contains_any(normalized, ("修复", "整改", "修补", "恢复修复")):
        title = f"为资产 {asset_id} 启动修复会话"
        goal_kind = PLAYBOOK_START_REMEDIATION_SESSION
    elif asset_id and _contains_any(normalized, ("安装 runner", "安装runner", "重装 runner", "重装runner", "runner")):
        title = f"为资产 {asset_id} 安装 Runner"
        goal_kind = PLAYBOOK_INSTALL_RUNNER
    elif asset_id and _contains_risk_verification_intent(normalized):
        title = f"验证资产 {asset_id} 的风险"
        goal_kind = PLAYBOOK_VERIFY_ASSET_RISKS
    elif asset_id and _contains_any(normalized, ("分析", "查看", "看看", "风险", "漏洞", "详情")):
        title = f"分析资产 {asset_id} 的风险"
        goal_kind = PLAYBOOK_ANALYZE_ASSET_RISKS
    else:
        title = sanitize_text(normalized, max_length=180) or "当前目标"
        goal_kind = GOAL_KIND_GENERAL

    return {
        "title": title,
        "goal_kind": goal_kind,
        "success_criteria_json": _goal_success_criteria(goal_kind, title=title, working_context=working_context),
    }


def _playbook_scan_and_analyze_cidr(content: str) -> AgentPlaybookDecision | None:
    cidr = _extract_cidr(content)
    if not cidr or not _contains_any(content, ("扫描", "分析", "网段", "漏洞", "风险")):
        return None
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_SCAN_AND_ANALYZE_CIDR,
        objective=f"扫描并分析 {cidr}",
        reply_markdown=f"我会先发起 {cidr} 的扫描任务，待扫描完成后继续帮你分析资产和漏洞。",
        auto_execute_actions=[
            {
                "action_type": "create_discovery_job",
                "title": f"扫描 {cidr}",
                "reason": f"为完成 {cidr} 的资产和漏洞分析，先发起发现任务。",
                "params": {"cidr": cidr},
            }
        ],
        stop_reason="playbook_scan_and_analyze_cidr",
    )


def _playbook_analyze_asset_risks(content: str, *, page_context: dict[str, Any], working_context: dict[str, Any]) -> AgentPlaybookDecision | None:
    asset_id = _asset_id_from_context(page_context, working_context)
    if not asset_id or not _contains_any(content, ("分析", "查看", "看看", "风险", "漏洞", "详情")):
        return None
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_ANALYZE_ASSET_RISKS,
        objective=f"分析资产 {asset_id} 的风险",
        reply_markdown=f"我先读取资产 {asset_id} 的详情和当前风险，再给你结论。",
        read_tool_calls=[
            {"tool_name": "get_asset_detail", "arguments": {"asset_id": asset_id}},
            {"tool_name": "list_asset_risks", "arguments": {"asset_id": asset_id, "status": "open", "limit": 10}},
        ],
        stop_reason="playbook_analyze_asset_risks",
    )


def _playbook_verify_asset_risks(content: str, *, page_context: dict[str, Any], working_context: dict[str, Any]) -> AgentPlaybookDecision | None:
    asset_id = _asset_id_from_context(page_context, working_context)
    if not asset_id or not _contains_risk_verification_intent(content):
        return None
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_VERIFY_ASSET_RISKS,
        objective=f"验证资产 {asset_id} 的风险",
        reply_markdown=f"我会先触发资产 {asset_id} 的风险验证，并在任务结束后继续回传结果。",
        auto_execute_actions=[
            {
                "action_type": "verify_asset_risks",
                "title": f"验证资产 {asset_id} 的风险",
                "reason": "用户已明确要求验证当前资产风险。",
                "params": {"asset_id": asset_id},
            }
        ],
        stop_reason="playbook_verify_asset_risks",
    )


def _playbook_install_runner(content: str, *, page_context: dict[str, Any], working_context: dict[str, Any]) -> AgentPlaybookDecision | None:
    asset_id = _asset_id_from_context(page_context, working_context)
    if not asset_id or not _contains_any(content, ("安装 runner", "安装runner", "重装 runner", "重装runner", "runner")):
        return None
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_INSTALL_RUNNER,
        objective=f"为资产 {asset_id} 安装 Runner",
        reply_markdown=f"我会先为资产 {asset_id} 启动 Runner 安装任务，并在完成后继续同步状态。",
        auto_execute_actions=[
            {
                "action_type": "install_runner",
                "title": f"为资产 {asset_id} 安装 Runner",
                "reason": "用户已明确要求安装当前资产的 Runner。",
                "params": {"asset_id": asset_id},
            }
        ],
        stop_reason="playbook_install_runner",
    )


def _playbook_start_remediation_session(content: str, *, page_context: dict[str, Any], working_context: dict[str, Any]) -> AgentPlaybookDecision | None:
    asset_id = _asset_id_from_context(page_context, working_context)
    if not asset_id or not _contains_any(content, ("修复", "整改", "修补", "恢复修复")):
        return None
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_START_REMEDIATION_SESSION,
        objective=f"为资产 {asset_id} 准备修复会话",
        reply_markdown=(
            f"我已为资产 {asset_id} 准备修复计划。"
            "确认后，如果当前修复条件已满足，我会直接提交自动修复；"
            "如果条件不足，我会只创建修复会话并明确告诉你阻塞原因。"
        ),
        proposed_write_actions=[
            {
                "action_type": "create_or_resume_remediation_session",
                "title": f"为资产 {asset_id} 准备修复会话",
                "reason": "用户已明确要求推进当前资产修复。",
                "params": {"asset_id": asset_id, "submit_if_ready": True},
            }
        ],
        needs_confirmation=True,
        stop_reason="playbook_start_remediation_session",
    )


def match_registered_playbook(
    *,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
) -> AgentPlaybookDecision | None:
    normalized = _normalize_text(content)
    if not normalized:
        return None

    matchers = (
        lambda: _playbook_scan_and_analyze_cidr(normalized),
        lambda: _playbook_verify_asset_risks(normalized, page_context=page_context, working_context=working_context),
        lambda: _playbook_install_runner(normalized, page_context=page_context, working_context=working_context),
        lambda: _playbook_start_remediation_session(normalized, page_context=page_context, working_context=working_context),
        lambda: _playbook_analyze_asset_risks(normalized, page_context=page_context, working_context=working_context),
    )
    for matcher in matchers:
        matched = matcher()
        if matched is not None:
            return matched

    semantic_page = browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
    if semantic_page.get("page_kind") == "dashboard_overview" and _contains_any(normalized, ("总览", "首页", "态势")):
        return AgentPlaybookDecision(
            playbook_id="dashboard_overview_brief",
            objective="解读桌面态势总览",
            reply_markdown="我先读取首页总览里的资产、任务和风险信息，再帮你归纳当前态势重点。",
            read_tool_calls=[
                {"tool_name": "list_tasks", "arguments": {"limit": 5}},
                {"tool_name": "list_risks", "arguments": {"status": "open", "limit": 5}},
            ],
            stop_reason="playbook_dashboard_overview_brief",
        )
    return None


def serialize_playbook_decision(match: AgentPlaybookDecision) -> dict[str, Any]:
    return {
        "playbook_id": match.playbook_id,
        "objective": match.objective,
        "reply_markdown": match.reply_markdown,
        "conversation_state": match.conversation_state,
        "read_tool_calls": sanitize_json_value(match.read_tool_calls),
        "ui_actions": sanitize_json_value(match.ui_actions),
        "proposed_write_actions": sanitize_json_value(match.proposed_write_actions),
        "auto_execute_actions": sanitize_json_value(match.auto_execute_actions),
        "needs_confirmation": match.needs_confirmation,
        "stop_reason": match.stop_reason,
    }
