from __future__ import annotations

from typing import Any

from app.core.config import settings
from app.db.models.task_run import TaskRun
from app.schemas.remediation import HostRemediationPlanRead, RemediationAssetDetailRead
from app.services.ai.gateway import LLMGateway
from app.services.ai.providers import LLMRequest, MockProvider


AI_EXPLANATION_SYSTEM_PROMPT = (
    "你是资产态势感知平台修复工作台的 AI 解读助手。"
    "你的职责仅是解释当前整机修复计划、阻塞原因和失败现象，帮助管理员理解现状。"
    "你不能生成可直接执行的 shell、不能建议绕过审批、不能伪造执行结果、不能改写当前计划真源。"
    "请只根据输入事实，用简洁中文 Markdown 输出 3-8 条高信息密度要点。"
)


class DeterministicRemediationExplanationProvider:
    def build_plan_summary(self, *, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
        asset_name = asset_detail.asset.hostname or asset_detail.asset.ip
        lines = [
            f"### AI 解读",
            f"- 当前主机 `{asset_name}` 已聚合 {plan.findings_covered_count} 条可自动修复风险，涉及 {plan.service_count} 类服务。",
            f"- 整机计划共 {plan.phase_count} 个阶段，可执行步骤 {plan.ready_step_count} 个，阻塞步骤 {plan.blocked_step_count} 个。",
        ]
        if plan.impacted_services:
            lines.append(f"- 预计影响服务：{'、'.join(plan.impacted_services)}。")
        if plan.impact_summary:
            lines.append(f"- 影响范围：{plan.impact_summary}")
        if plan.verify_items:
            lines.append(f"- 执行后优先关注：{'；'.join(plan.verify_items[:3])}")
        if plan.rollback_notes:
            lines.append(f"- 回滚关注：{'；'.join(plan.rollback_notes[:2])}")
        if plan.blocked_reasons:
            lines.append(f"- 当前仍不可直接执行，主要阻塞：{'；'.join(plan.blocked_reasons[:3])}")
        else:
            lines.append("- 当前整机计划满足执行条件，可在确认窗口期后交由 Host Runner 执行。")
        return "\n".join(lines)

    def build_blocker_analysis(self, *, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
        lines = [
            "### 阻塞诊断",
            f"- 当前共有 {plan.blocked_step_count} 个阻塞步骤，系统级阻塞为：{'；'.join(plan.blocked_reasons[:4]) if plan.blocked_reasons else '暂无系统级阻塞。'}",
        ]
        runner = asset_detail.runner
        if runner.install_status != "installed":
            lines.append(f"- Host Runner 目前状态为 `{runner.install_status}`，需要先完成安装或恢复在线。")
        elif runner.status not in {"online", "busy"}:
            lines.append(f"- Host Runner 当前为 `{runner.status}`，在恢复在线前无法拉取整机执行任务。")
        if asset_detail.authorization.blocked_reasons:
            lines.append(f"- SSH/授权前置条件未闭合：{'；'.join(asset_detail.authorization.blocked_reasons[:3])}")
        blocked_steps = [step for step in plan.steps if step.execution_state == "blocked" and step.blocked_reason]
        if blocked_steps:
            step = blocked_steps[0]
            targets = "、".join([*step.target_files[:2], *step.target_paths[:2]]) or "当前未解析出稳定目标"
            lines.append(f"- 典型阻塞步骤“{step.title}”卡在：{step.blocked_reason}。关联目标：{targets}。")
        lines.append("- 优先补齐 Runner 在线、SSH 授权、配置文件路径或主机快照后，再刷新整机计划。")
        return "\n".join(lines)

    def build_task_failure(
        self,
        *,
        asset_detail: RemediationAssetDetailRead,
        plan: HostRemediationPlanRead,
        task: TaskRun,
    ) -> str:
        execution = task.result_json.get("execution") if isinstance(task.result_json, dict) else {}
        execution = execution if isinstance(execution, dict) else {}
        step_results = execution.get("step_results") if isinstance(execution.get("step_results"), list) else []
        failed_step = next(
            (
                item for item in step_results
                if isinstance(item, dict) and str(item.get("status") or "").strip().lower() == "failed"
            ),
            None,
        )
        lines = [
            "### 失败诊断",
            f"- 最近一次整机修复任务执行失败，任务状态为 `{str(task.status.value if hasattr(task.status, 'value') else task.status)}`。",
            f"- 平台记录的失败信息：{str(task.message or '未返回明确错误，请查看任务输出。').strip()}",
        ]
        if failed_step:
            output_tail = failed_step.get("output_tail") if isinstance(failed_step.get("output_tail"), list) else []
            lines.append(f"- 首个失败步骤是“{str(failed_step.get('title') or failed_step.get('step_id') or '未知步骤')}”。")
            if output_tail:
                lines.append(f"- 任务尾部输出提示：{str(output_tail[-1])}")
        if plan.rollback_notes:
            lines.append(f"- 建议先核对回滚与恢复点：{'；'.join(plan.rollback_notes[:2])}")
        lines.append("- 先结合任务输出和目标主机实际状态定位失败原因，确认后再决定是否重试。")
        return "\n".join(lines)


class RemediationAIExplanationService:
    def __init__(
        self,
        *,
        gateway: LLMGateway | None = None,
        fallback_provider: DeterministicRemediationExplanationProvider | None = None,
    ) -> None:
        self.gateway = gateway or LLMGateway()
        self.fallback_provider = fallback_provider or DeterministicRemediationExplanationProvider()

    def provider_mode(self) -> str:
        provider = getattr(self.gateway, "provider", None)
        if isinstance(provider, MockProvider):
            return "mock"
        return str(settings.LLM_PROVIDER or "mock").strip().lower() or "mock"

    def build_plan_summary(self, *, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
        fallback = self.fallback_provider.build_plan_summary(asset_detail=asset_detail, plan=plan)
        prompt = _build_plan_summary_prompt(asset_detail=asset_detail, plan=plan)
        return self._generate(prompt=prompt, fallback=fallback)

    def build_blocker_analysis(self, *, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
        fallback = self.fallback_provider.build_blocker_analysis(asset_detail=asset_detail, plan=plan)
        prompt = _build_blocker_analysis_prompt(asset_detail=asset_detail, plan=plan)
        return self._generate(prompt=prompt, fallback=fallback)

    def build_task_failure(
        self,
        *,
        asset_detail: RemediationAssetDetailRead,
        plan: HostRemediationPlanRead,
        task: TaskRun,
    ) -> str:
        fallback = self.fallback_provider.build_task_failure(asset_detail=asset_detail, plan=plan, task=task)
        prompt = _build_task_failure_prompt(asset_detail=asset_detail, plan=plan, task=task)
        return self._generate(prompt=prompt, fallback=fallback)

    def _generate(self, *, prompt: str, fallback: str) -> str:
        provider = getattr(self.gateway, "provider", None)
        if isinstance(provider, MockProvider):
            return fallback
        try:
            request = LLMRequest.from_text(prompt, system_prompt=AI_EXPLANATION_SYSTEM_PROMPT)
            content = provider.generate(request)
        except Exception:
            return fallback
        normalized = _normalize_explanation(content)
        return normalized or fallback


def _build_plan_summary_prompt(*, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
    key_steps = [
        {
            "title": step.title,
            "phase": step.phase_name,
            "state": step.execution_state,
            "service": step.service_name,
            "target_files": step.target_files[:2],
            "target_services": step.target_services[:2],
            "target_paths": step.target_paths[:2],
            "verify_items": step.verify_items[:2],
            "rollback_hint": step.rollback_hint,
        }
        for step in plan.steps[:8]
    ]
    payload = {
        "asset": {
            "hostname": asset_detail.asset.hostname,
            "ip": asset_detail.asset.ip,
            "os_name": asset_detail.asset.os_name,
        },
        "runner": {
            "status": asset_detail.runner.status,
            "install_status": asset_detail.runner.install_status,
        },
        "authorization": {
            "effective_privilege": asset_detail.authorization.effective_privilege,
            "blocked_reasons": asset_detail.authorization.blocked_reasons,
        },
        "plan": {
            "execution_ready": plan.execution_ready,
            "summary_text": plan.summary_text,
            "impact_summary": plan.impact_summary,
            "blocked_reasons": plan.blocked_reasons,
            "impacted_services": plan.impacted_services,
            "precheck_items": plan.precheck_items[:4],
            "verify_items": plan.verify_items[:4],
            "rollback_notes": plan.rollback_notes[:3],
            "phases": [
                {
                    "phase_name": item.phase_name,
                    "summary": item.summary,
                    "ready_count": item.ready_count,
                    "blocked_count": item.blocked_count,
                }
                for item in plan.phases
            ],
            "key_steps": key_steps,
        },
    }
    return (
        "请为修复工作台生成一段整机修复计划解读。\n"
        "只解释当前计划将做什么、先后顺序、影响范围、验证重点和回滚关注点。\n"
        "禁止输出 shell、禁止替代审批、禁止假设已执行完成。\n\n"
        f"{_safe_json(payload)}"
    )


def _build_blocker_analysis_prompt(*, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead) -> str:
    blocked_steps = [
        {
            "title": step.title,
            "phase": step.phase_name,
            "blocked_reason": step.blocked_reason,
            "service": step.service_name,
            "target_files": step.target_files[:2],
            "target_paths": step.target_paths[:2],
        }
        for step in plan.steps
        if step.execution_state == "blocked"
    ][:8]
    payload = {
        "asset": {
            "hostname": asset_detail.asset.hostname,
            "ip": asset_detail.asset.ip,
        },
        "runner": {
            "status": asset_detail.runner.status,
            "install_status": asset_detail.runner.install_status,
            "compatibility_issues": asset_detail.runner.compatibility_issues[:4],
        },
        "authorization": {
            "effective_privilege": asset_detail.authorization.effective_privilege,
            "blocked_reasons": asset_detail.authorization.blocked_reasons,
        },
        "plan": {
            "blocked_reasons": plan.blocked_reasons,
            "blocked_step_count": plan.blocked_step_count,
            "blocked_steps": blocked_steps,
        },
    }
    return (
        "请解释当前整机修复计划为什么被阻塞，并指出优先应补齐哪类前置条件。\n"
        "只能基于给定事实判断阻塞属于路径、快照、Runner、凭据、配置文件或在线状态中的哪类。\n"
        "禁止输出新的执行命令，禁止虚构未提供的资产事实。\n\n"
        f"{_safe_json(payload)}"
    )


def _build_task_failure_prompt(*, asset_detail: RemediationAssetDetailRead, plan: HostRemediationPlanRead, task: TaskRun) -> str:
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    execution = result_json.get("execution") if isinstance(result_json.get("execution"), dict) else {}
    step_results = execution.get("step_results") if isinstance(execution.get("step_results"), list) else []
    payload = {
        "asset": {
            "hostname": asset_detail.asset.hostname,
            "ip": asset_detail.asset.ip,
        },
        "task": {
            "task_id": task.id,
            "status": str(task.status.value if hasattr(task.status, "value") else task.status),
            "message": task.message,
            "execution_boundary": execution.get("execution_boundary"),
            "step_results": step_results[:6],
        },
        "plan": {
            "summary_text": plan.summary_text,
            "rollback_notes": plan.rollback_notes[:3],
        },
    }
    return (
        "请对这次整机修复失败做简短诊断，只解释失败位置、常见原因和人工排查方向。\n"
        "禁止输出 shell、禁止下达执行命令、禁止假设未出现的主机状态。\n\n"
        f"{_safe_json(payload)}"
    )


def _normalize_explanation(content: Any) -> str:
    text = str(content or "").strip()
    if not text:
        return ""
    return text[:4000].strip()


def _safe_json(payload: dict[str, Any]) -> str:
    return __import__("json").dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
