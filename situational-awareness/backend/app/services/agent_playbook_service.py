from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services.agent.identity import AGENT_DISPLAY_NAME
from app.utils.sanitize import sanitize_json_value, sanitize_text

CIDR_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
ASSET_ID_PATTERN = re.compile(
    r"(?:asset|资产|主机)\s*(?:id)?\s*[:：#]?\s*([A-Za-z0-9][A-Za-z0-9._-]{2,63})",
    re.IGNORECASE,
)
MAINTENANCE_WINDOW_PATTERN = re.compile(
    r"(?:maintenance_window_id|维护窗口(?:id|编号)?)\s*(?:是|为|=|:|：)\s*([A-Za-z0-9][A-Za-z0-9._-]{1,126})",
    re.IGNORECASE,
)

PLAYBOOK_SCAN_AND_ANALYZE_CIDR = "scan_and_analyze_cidr"
PLAYBOOK_ANALYZE_ASSET_RISKS = "analyze_asset_risks"
PLAYBOOK_VERIFY_ASSET_RISKS = "verify_asset_risks"
PLAYBOOK_INSTALL_RUNNER = "install_runner"
PLAYBOOK_START_REMEDIATION_SESSION = "start_remediation_session"
PLAYBOOK_CONFIGURE_SSH_CREDENTIAL = "configure_ssh_credential"
PLAYBOOK_QUICK_SMALLTALK = "quick_smalltalk"
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


@dataclass(frozen=True, slots=True)
class AgentSkillDefinition:
    skill_id: str
    title: str
    entry_intents: list[str] = field(default_factory=list)
    required_context: list[str] = field(default_factory=list)
    read_chain: list[str] = field(default_factory=list)
    write_chain: list[str] = field(default_factory=list)
    success_criteria: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    resume_strategy: str | None = None
    default_next_step: str | None = None


SKILL_REGISTRY: dict[str, AgentSkillDefinition] = {
    PLAYBOOK_SCAN_AND_ANALYZE_CIDR: AgentSkillDefinition(
        skill_id=PLAYBOOK_SCAN_AND_ANALYZE_CIDR,
        title="扫描并分析网段",
        entry_intents=["扫描", "分析网段", "查看网段漏洞"],
        required_context=["cidr"],
        write_chain=["create_discovery_job"],
        success_criteria=["扫描任务完成", "返回网段资产与风险结论"],
        resume_strategy="resume_hint_or_goal",
        default_next_step="分析扫描结果",
    ),
    PLAYBOOK_ANALYZE_ASSET_RISKS: AgentSkillDefinition(
        skill_id=PLAYBOOK_ANALYZE_ASSET_RISKS,
        title="分析资产风险",
        entry_intents=["分析资产", "查看风险", "资产详情"],
        required_context=["asset_id"],
        read_chain=["get_asset_detail", "list_asset_risks"],
        success_criteria=["读取资产详情", "给出风险分析结论"],
        resume_strategy="goal_context",
        default_next_step="继续查看风险明细或后续动作",
    ),
    PLAYBOOK_VERIFY_ASSET_RISKS: AgentSkillDefinition(
        skill_id=PLAYBOOK_VERIFY_ASSET_RISKS,
        title="验证资产风险",
        entry_intents=["验证风险", "复核风险"],
        required_context=["asset_id"],
        write_chain=["verify_asset_risks"],
        success_criteria=["验证任务完成", "验证结果回传到会话"],
        resume_strategy="watch_task",
        default_next_step="分析验证结果",
    ),
    PLAYBOOK_INSTALL_RUNNER: AgentSkillDefinition(
        skill_id=PLAYBOOK_INSTALL_RUNNER,
        title="安装 Host Runner",
        entry_intents=["安装 runner", "重装 runner"],
        required_context=["asset_id"],
        write_chain=["install_runner"],
        success_criteria=["安装任务完成", "Runner 状态回传到会话"],
        blockers=["缺少平台地址", "缺少管理员凭据", "资产不存在"],
        resume_strategy="watch_task",
        default_next_step="查看 Runner 状态",
    ),
    PLAYBOOK_START_REMEDIATION_SESSION: AgentSkillDefinition(
        skill_id=PLAYBOOK_START_REMEDIATION_SESSION,
        title="准备自动修复",
        entry_intents=["修复", "整改", "修补"],
        required_context=["asset_id"],
        read_chain=["get_remediation_asset", "get_remediation_session"],
        write_chain=["create_or_resume_remediation_session"],
        success_criteria=["修复会话就绪", "满足条件时已提交自动修复"],
        blockers=["缺少 Host Runner", "缺少管理员授权", "当前没有可执行阶段"],
        resume_strategy="resume_hint_or_goal",
        default_next_step="复盘修复结果或补齐阻塞条件",
    ),
    PLAYBOOK_CONFIGURE_SSH_CREDENTIAL: AgentSkillDefinition(
        skill_id=PLAYBOOK_CONFIGURE_SSH_CREDENTIAL,
        title="配置 SSH 凭据",
        entry_intents=["配置 ssh", "ssh 凭据", "管理员凭据", "私钥", "密码", "sudo 密码"],
        required_context=["asset_id|selected_rows"],
        write_chain=["configure_ssh_credential"],
        success_criteria=["敏感字段已通过安全弹层保存", "凭据已验证", "原阻塞目标已自动续接或给出下一步"],
        blockers=["缺少目标资产", "未选择批量资产"],
        resume_strategy="goal_context",
        default_next_step="验证凭据并恢复原目标",
    ),
    "resume_task_detail": AgentSkillDefinition(
        skill_id="resume_task_detail",
        title="继续查看任务详情",
        entry_intents=["继续", "查看任务", "任务详情"],
        required_context=["task_id"],
        read_chain=["get_task_detail", "get_task_events"],
        success_criteria=["定位最近任务", "展示任务详情与事件"],
        resume_strategy="resume_hint",
        default_next_step="查看任务详情",
    ),
}


def get_skill_definition(skill_id: str | None) -> AgentSkillDefinition | None:
    normalized = sanitize_text(skill_id, max_length=128, single_line=True) or ""
    if not normalized:
        return None
    return SKILL_REGISTRY.get(normalized)


def get_skill_title(skill_id: str | None) -> str | None:
    definition = get_skill_definition(skill_id)
    return definition.title if definition is not None else None


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


def _extract_maintenance_window_id(value: str) -> str | None:
    match = MAINTENANCE_WINDOW_PATTERN.search(value)
    if not match:
        return None
    return sanitize_text(match.group(1), max_length=128, single_line=True) or None


def _contains_any(content: str, markers: tuple[str, ...]) -> bool:
    return any(marker in content for marker in markers)


def _contains_risk_verification_intent(content: str) -> bool:
    return _contains_any(content, ("验证风险", "风险验证", "复核风险", "校验风险")) or (
        "验证" in content and "风险" in content
    )


def _contains_ssh_credential_intent(content: str) -> bool:
    lowered = content.lower()
    return _contains_any(
        content,
        ("ssh 凭据", "SSH 凭据", "管理员凭据", "凭据配置", "配置凭据", "配置 ssh", "配置SSH", "私钥", "sudo 密码", "管理员授权"),
    ) or ("ssh" in lowered and any(marker in content for marker in ("配置", "设置", "密码", "私钥", "授权", "凭据")))


_QUICK_SMALLTALK_EXACT = {
    "hi",
    "hello",
    "hey",
    "你好",
    "您好",
    "嗨",
    "哈喽",
    "在吗",
    "在不在",
    "早上好",
    "上午好",
    "中午好",
    "下午好",
    "晚上好",
}
_QUICK_THANKS_EXACT = {"谢谢", "多谢", "谢了", "感谢", "辛苦了", "thanks", "thankyou"}
_QUICK_IDENTITY_MARKERS = ("你是谁", "你是干什么的", "你是什么", "介绍一下你自己", "介绍下你自己")
_QUICK_CAPABILITY_MARKERS = ("你能做什么", "你可以做什么", "怎么用你", "如何使用你", "你会什么", "你能帮我做什么")
_BUSINESS_INTENT_MARKERS = (
    "扫描",
    "分析",
    "网段",
    "漏洞",
    "风险",
    "资产",
    "主机",
    "验证",
    "复核",
    "安装",
    "runner",
    "修复",
    "整改",
    "修补",
    "ssh",
    "凭据",
    "密码",
    "私钥",
    "任务",
    "日志",
    "报告",
    "查看",
    "看看",
    "处理",
    "配置",
    "执行",
    "下发",
    "审批",
    "确认",
    "maintenance_window",
    "cidr",
)


def _asset_id_from_context(page_context: dict[str, Any], working_context: dict[str, Any]) -> str | None:
    return _normalize_id(working_context.get("asset_id") or page_context.get("asset_id"))


def _asset_id_from_request(content: str, page_context: dict[str, Any], working_context: dict[str, Any]) -> str | None:
    match = ASSET_ID_PATTERN.search(content)
    if match is not None:
        explicit = _normalize_id(match.group(1))
        if explicit:
            return explicit
    return _asset_id_from_context(page_context, working_context)


def _selected_asset_targets(browser_context: dict[str, Any]) -> list[dict[str, str]]:
    semantic_page = browser_context.get("semantic_page_context") if isinstance(browser_context.get("semantic_page_context"), dict) else {}
    selected_rows = semantic_page.get("selected_rows") if isinstance(semantic_page.get("selected_rows"), list) else []
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in selected_rows:
        if not isinstance(item, dict):
            continue
        meta = item.get("meta") if isinstance(item.get("meta"), dict) else {}
        asset_id = _normalize_id(item.get("asset_id") or item.get("id") or meta.get("asset_id"))
        if not asset_id or asset_id in seen:
            continue
        seen.add(asset_id)
        label = _normalize_text(str(item.get("label") or meta.get("label") or f"资产 {asset_id}"), max_length=160) or f"资产 {asset_id}"
        targets.append({"asset_id": asset_id, "label": label})
        if len(targets) >= 20:
            break
    return targets


def _current_goal_blockers(current_goal: Any | None) -> tuple[list[str], list[str]]:
    if current_goal is None:
        return [], []
    blocker_messages: list[str] = []
    blocker_codes: list[str] = []
    blocked_reason = _normalize_text(str(getattr(current_goal, "blocked_reason", "") or ""), max_length=200)
    if blocked_reason:
        blocker_messages.append(blocked_reason)
    progress_json = getattr(current_goal, "progress_json", None)
    if isinstance(progress_json, dict):
        blockers = progress_json.get("blockers") if isinstance(progress_json.get("blockers"), list) else []
        for item in blockers:
            if not isinstance(item, dict):
                continue
            code = _normalize_text(str(item.get("blocker_code") or ""), max_length=64)
            message = _normalize_text(str(item.get("blocker_message") or ""), max_length=200)
            if code:
                blocker_codes.append(code)
            if message:
                blocker_messages.append(message)
    return blocker_codes, blocker_messages


def _goal_resume_action(
    current_goal: Any | None,
    *,
    asset_targets: list[dict[str, str]],
) -> dict[str, Any]:
    if current_goal is None or not asset_targets:
        return {}
    goal_kind = _normalize_text(str(getattr(current_goal, "goal_kind", "") or ""), max_length=128)
    asset_id = asset_targets[0]["asset_id"]
    if goal_kind == PLAYBOOK_VERIFY_ASSET_RISKS:
        return {
            "action_type": "verify_asset_risks",
            "title": f"验证资产 {asset_id} 的风险",
            "reason": "SSH 凭据验证成功后，继续原风险验证目标。",
            "params": {"asset_id": asset_id},
        }
    if goal_kind == PLAYBOOK_INSTALL_RUNNER:
        return {
            "action_type": "install_runner",
            "title": f"为资产 {asset_id} 安装 Runner",
            "reason": "SSH 凭据验证成功后，继续原 Runner 安装目标。",
            "params": {"asset_id": asset_id},
        }
    if goal_kind == PLAYBOOK_START_REMEDIATION_SESSION:
        return {
            "action_type": "create_or_resume_remediation_session",
            "title": f"为资产 {asset_id} 准备修复会话",
            "reason": "SSH 凭据验证成功后，继续原自动修复目标。",
            "params": {"asset_id": asset_id, "submit_if_ready": True},
        }
    return {}


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
    if goal_kind == PLAYBOOK_CONFIGURE_SSH_CREDENTIAL:
        return {
            "goal_kind": goal_kind,
            "done_when": [
                f"已为资产 {asset_id or '当前目标'} 打开安全凭据配置流程",
                "敏感字段已在专用弹层提交并验证",
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
    elif _contains_ssh_credential_intent(normalized):
        title = "配置 SSH 凭据"
        goal_kind = PLAYBOOK_CONFIGURE_SSH_CREDENTIAL
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
    asset_id = _asset_id_from_request(content, page_context, working_context)
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
    asset_id = _asset_id_from_request(content, page_context, working_context)
    lowered = content.lower()
    if not asset_id or not (_contains_any(content, ("安装 runner", "安装runner", "重装 runner", "重装runner")) or "runner" in lowered):
        return None
    params: dict[str, Any] = {"asset_id": asset_id}
    if _contains_any(content, ("自动修复", "继续自动修复", "然后继续自动修复", "恢复修复", "整改", "修复")):
        params["resume_action"] = {
            "action_type": "create_or_resume_remediation_session",
            "title": f"为资产 {asset_id} 准备修复会话",
            "reason": "Runner 安装完成后继续原自动修复目标。",
            "params": {"asset_id": asset_id, "submit_if_ready": True},
        }
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_INSTALL_RUNNER,
        objective=f"为资产 {asset_id} 安装 Runner",
        reply_markdown=(
            f"我会先为资产 {asset_id} 启动 Runner 安装任务，并在完成后继续自动修复。"
            if "resume_action" in params
            else f"我会先为资产 {asset_id} 启动 Runner 安装任务，并在完成后继续同步状态。"
        ),
        auto_execute_actions=[
            {
                "action_type": "install_runner",
                "title": f"为资产 {asset_id} 安装 Runner",
                "reason": "用户已明确要求安装当前资产的 Runner。",
                "params": params,
            }
        ],
        stop_reason="playbook_install_runner",
    )


def _playbook_start_remediation_session(content: str, *, page_context: dict[str, Any], working_context: dict[str, Any]) -> AgentPlaybookDecision | None:
    asset_id = _asset_id_from_request(content, page_context, working_context)
    maintenance_window_id = _extract_maintenance_window_id(content)
    if not asset_id or (not _contains_any(content, ("修复", "整改", "修补", "恢复修复")) and not maintenance_window_id):
        return None
    params: dict[str, Any] = {"asset_id": asset_id, "submit_if_ready": True}
    if maintenance_window_id:
        params["maintenance_window_id"] = maintenance_window_id
    reply_markdown = (
        f"我已为资产 {asset_id} 准备修复计划。"
        "确认后，如果当前修复条件已满足，我会直接提交自动修复；"
        "如果条件不足，我会只创建修复会话并明确告诉你阻塞原因。"
    )
    reason = "用户已明确要求推进当前资产修复。"
    if maintenance_window_id:
        reply_markdown = (
            f"我已记录 maintenance_window_id={maintenance_window_id}，并为资产 {asset_id} 准备修复计划。"
            "确认后，我会带着这个维护窗口继续自动修复；如果仍有其他条件不足，我会明确告诉你阻塞原因。"
        )
        reason = f"用户已补充 maintenance_window_id={maintenance_window_id}，要求继续自动修复。"
    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_START_REMEDIATION_SESSION,
        objective=f"为资产 {asset_id} 准备修复会话",
        reply_markdown=reply_markdown,
        proposed_write_actions=[
            {
                "action_type": "create_or_resume_remediation_session",
                "title": f"为资产 {asset_id} 准备修复会话",
                "reason": reason,
                "params": params,
            }
        ],
        needs_confirmation=True,
        stop_reason="playbook_start_remediation_session",
    )


def _normalized_quick_chat_content(content: str) -> str:
    return re.sub(r"[\s,，。.!！?？~～、；;:：]+", "", content).lower()


def _contains_business_intent(content: str) -> bool:
    lowered = content.lower()
    return any(marker in lowered for marker in _BUSINESS_INTENT_MARKERS) or bool(CIDR_PATTERN.search(content))


def _playbook_quick_smalltalk(content: str) -> AgentPlaybookDecision | None:
    compact = _normalized_quick_chat_content(content)
    if not compact or len(compact) > 28:
        return None
    if _contains_business_intent(content):
        return None

    if compact in _QUICK_SMALLTALK_EXACT:
        objective = "快速寒暄"
        reply = f"你好，我是 {AGENT_DISPLAY_NAME}。你可以直接告诉我要查看、分析或处理的资产、风险、任务或网段。"
    elif compact in _QUICK_THANKS_EXACT:
        objective = "回应致谢"
        reply = "不客气。你可以继续告诉我要分析或处理的目标。"
    elif any(marker in compact for marker in _QUICK_IDENTITY_MARKERS):
        objective = f"介绍 {AGENT_DISPLAY_NAME}"
        reply = f"我是 {AGENT_DISPLAY_NAME}，负责在当前平台里帮助你查看态势、分析资产风险，并在确认后推进扫描、验证、Runner 安装和修复流程。"
    elif any(marker in compact for marker in _QUICK_CAPABILITY_MARKERS):
        objective = f"说明 {AGENT_DISPLAY_NAME} 能力"
        reply = "我可以帮你查看态势、分析资产风险、扫描网段、验证风险、安装 Runner，并在满足条件时准备修复流程。"
    elif compact.startswith(("你好", "您好", "hi", "hello")) and any(
        marker in compact for marker in (*_QUICK_IDENTITY_MARKERS, *_QUICK_CAPABILITY_MARKERS)
    ):
        objective = f"介绍 {AGENT_DISPLAY_NAME}"
        reply = f"你好，我是 {AGENT_DISPLAY_NAME}。你可以让我查看态势、分析资产风险、扫描网段、验证风险、安装 Runner，或准备修复流程。"
    else:
        return None

    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_QUICK_SMALLTALK,
        objective=objective,
        reply_markdown=reply,
        stop_reason="playbook_quick_smalltalk",
    )


def _playbook_configure_ssh_credential(
    content: str,
    *,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    current_goal: Any | None,
) -> AgentPlaybookDecision | None:
    asset_targets = _selected_asset_targets(browser_context)
    primary_asset_id = _asset_id_from_context(page_context, working_context)
    if primary_asset_id:
        primary_label = _normalize_text(f"资产 {primary_asset_id}", max_length=160) or f"资产 {primary_asset_id}"
        asset_targets = [{"asset_id": primary_asset_id, "label": primary_label}, *[item for item in asset_targets if item["asset_id"] != primary_asset_id]]

    blocker_codes, blocker_messages = _current_goal_blockers(current_goal)
    blocked_by_credential = any(
        code in {"missing_ssh_credential", "authorization_unconfirmed", "authorization_not_verified", "insufficient_privilege"}
        for code in blocker_codes
    ) or any("SSH" in message or "管理员授权" in message or "管理员权限验证" in message for message in blocker_messages)
    explicit_intent = _contains_ssh_credential_intent(content)
    short_resume = content in {"继续", "好的", "可以", "看", "继续吧", "继续处理"}
    if not explicit_intent and not (blocked_by_credential and short_resume):
        return None

    if not asset_targets:
        return AgentPlaybookDecision(
            playbook_id=PLAYBOOK_CONFIGURE_SSH_CREDENTIAL,
            objective="确认 SSH 凭据配置目标",
            reply_markdown="要继续配置 SSH 凭据，我需要知道目标资产。请打开目标资产详情页，或先在资产列表中勾选要批量处理的资产。",
            conversation_state="clarifying",
            stop_reason="playbook_configure_ssh_credential_missing_target",
        )

    resume_action = _goal_resume_action(current_goal, asset_targets=asset_targets)
    resume_goal_id = _normalize_id(getattr(current_goal, "id", None))
    asset_ids = [item["asset_id"] for item in asset_targets]
    asset_labels = [item["label"] for item in asset_targets]
    blocker_summary = "；".join(blocker_messages[:2]) if blocker_messages else None
    target_summary = asset_labels[0] if len(asset_labels) == 1 else f"已选择 {len(asset_labels)} 台资产"
    reply = (
        f"我会先为 {target_summary} 打开 SSH 凭据安全配置弹层。"
        "聊天里只保留目标资产、认证方式和用户名，密码、私钥与 sudo 密码只在专用弹层中填写。"
        "保存后我会立即验证管理员权限；如果当前目标正被 SSH 凭据阻塞，验证成功后会自动续接原目标。"
    )
    if len(asset_ids) > 1:
        reply = (
            f"我会先为这 {len(asset_ids)} 台资产打开 SSH 凭据安全配置弹层。"
            "你需要先选择“同一套凭据批量应用”或“逐台引导配置”；敏感字段只会在弹层中填写。"
            "保存后我会立即验证，成功资产会自动续接原阻塞目标，失败资产会单独汇总原因。"
        )
    if blocker_summary:
        reply = f"{reply}\n\n当前阻塞：{blocker_summary}"

    return AgentPlaybookDecision(
        playbook_id=PLAYBOOK_CONFIGURE_SSH_CREDENTIAL,
        objective=f"为 {target_summary} 配置 SSH 凭据",
        reply_markdown=reply,
        proposed_write_actions=[
            {
                "action_type": "configure_ssh_credential",
                "title": f"为 {target_summary} 配置 SSH 凭据",
                "reason": "当前目标缺少可用 SSH 管理员凭据，需要进入安全输入流程。",
                "params": {
                    "asset_id": asset_ids[0] if len(asset_ids) == 1 else None,
                    "asset_ids": asset_ids,
                    "asset_labels": asset_labels,
                    "mode": "single_asset" if len(asset_ids) == 1 else "batch_choice",
                    "auth_type": None,
                    "username": None,
                    "resume_goal_id": resume_goal_id,
                    "resume_action": resume_action,
                    "auto_verify": True,
                    "auto_resume": True,
                    "blocker_summary": blocker_summary,
                },
            }
        ],
        stop_reason="playbook_configure_ssh_credential",
    )


def match_registered_playbook(
    *,
    content: str,
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    working_context: dict[str, Any],
    current_goal: Any | None = None,
) -> AgentPlaybookDecision | None:
    normalized = _normalize_text(content)
    if not normalized:
        return None

    matchers = (
        lambda: _playbook_quick_smalltalk(normalized),
        lambda: _playbook_configure_ssh_credential(
            normalized,
            page_context=page_context,
            browser_context=browser_context,
            working_context=working_context,
            current_goal=current_goal,
        ),
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
