from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


ActionRiskLevel = Literal["low", "high", "sensitive_input"]
TaskFollowupStrategy = Literal["watch_task", "session", "secure_input"]


@dataclass(frozen=True, slots=True)
class HaorActionPolicy:
    action_type: str
    required_slots: tuple[str, ...]
    risk_level: ActionRiskLevel
    needs_confirmation: bool
    auto_execute_allowed: bool
    task_followup_strategy: TaskFollowupStrategy

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_slots": list(self.required_slots),
            "risk_level": self.risk_level,
            "needs_confirmation": self.needs_confirmation,
            "auto_execute_allowed": self.auto_execute_allowed,
            "task_followup_strategy": self.task_followup_strategy,
        }


ACTION_POLICIES: dict[str, HaorActionPolicy] = {
    "create_discovery_job": HaorActionPolicy(
        action_type="create_discovery_job",
        required_slots=("cidr",),
        risk_level="low",
        needs_confirmation=False,
        auto_execute_allowed=True,
        task_followup_strategy="watch_task",
    ),
    "verify_asset_risks": HaorActionPolicy(
        action_type="verify_asset_risks",
        required_slots=("asset_id",),
        risk_level="low",
        needs_confirmation=False,
        auto_execute_allowed=True,
        task_followup_strategy="watch_task",
    ),
    "install_runner": HaorActionPolicy(
        action_type="install_runner",
        required_slots=("asset_id",),
        risk_level="low",
        needs_confirmation=False,
        auto_execute_allowed=True,
        task_followup_strategy="watch_task",
    ),
    "create_or_resume_remediation_session": HaorActionPolicy(
        action_type="create_or_resume_remediation_session",
        required_slots=("asset_id",),
        risk_level="high",
        needs_confirmation=True,
        auto_execute_allowed=False,
        task_followup_strategy="session",
    ),
    "approve_remediation_session": HaorActionPolicy(
        action_type="approve_remediation_session",
        required_slots=("session_id",),
        risk_level="high",
        needs_confirmation=True,
        auto_execute_allowed=False,
        task_followup_strategy="watch_task",
    ),
    "configure_ssh_credential": HaorActionPolicy(
        action_type="configure_ssh_credential",
        required_slots=("asset_id|asset_ids",),
        risk_level="sensitive_input",
        needs_confirmation=False,
        auto_execute_allowed=False,
        task_followup_strategy="secure_input",
    ),
}

SUPPORTED_WRITE_ACTIONS = frozenset(ACTION_POLICIES)
AUTO_EXECUTE_ACTIONS = frozenset(
    action_type for action_type, policy in ACTION_POLICIES.items() if policy.auto_execute_allowed
)
ACTION_POLICY_REGISTRY: dict[str, dict[str, Any]] = {
    action_type: policy.to_dict() for action_type, policy in ACTION_POLICIES.items()
}


def get_action_policy(action_type: str) -> HaorActionPolicy | None:
    return ACTION_POLICIES.get(str(action_type or "").strip())


def action_policy_payload(action_type: str) -> dict[str, Any]:
    policy = get_action_policy(action_type)
    return policy.to_dict() if policy is not None else {}


def action_requires_confirmation(action_type: str) -> bool:
    policy = get_action_policy(action_type)
    return bool(policy and policy.needs_confirmation)


def action_allows_auto_execute(action_type: str) -> bool:
    policy = get_action_policy(action_type)
    return bool(policy and policy.auto_execute_allowed)

