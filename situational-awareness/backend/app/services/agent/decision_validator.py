from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from app.utils.sanitize import sanitize_json_value, sanitize_text

LOW_RISK_AUTO_ACTIONS = {"create_discovery_job", "verify_asset_risks", "install_runner"}
HIGH_RISK_ACTIONS = {
    "approve_remediation_session",
    "create_or_resume_remediation_session",
    "configure_ssh_credential",
}
SENSITIVE_PARAM_MARKERS = {
    "password",
    "passwd",
    "private_key",
    "secret",
    "token",
    "credential",
    "sudo",
    "script",
    "command",
    "shell",
    "path",
}


@dataclass(frozen=True, slots=True)
class DecisionValidationIssue:
    code: str
    message: str
    severity: str = "high"
    action_type: str | None = None

    def to_payload(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "action_type": self.action_type,
        }


@dataclass(slots=True)
class DecisionValidationResult:
    auto_actions: list[dict[str, Any]] = field(default_factory=list)
    proposed_actions: list[dict[str, Any]] = field(default_factory=list)
    downgraded_actions: list[dict[str, Any]] = field(default_factory=list)
    issues: list[DecisionValidationIssue] = field(default_factory=list)

    @property
    def downgraded(self) -> bool:
        return bool(self.downgraded_actions)


def validate_agent_write_decisions(
    *,
    auto_actions: list[dict[str, Any]],
    proposed_actions: list[dict[str, Any]],
    working_context: dict[str, Any],
    page_context: dict[str, Any],
    browser_context: dict[str, Any],
    user_role: str,
) -> DecisionValidationResult:
    normalized_proposed_actions = [_normalize_action(item) for item in proposed_actions]
    result = DecisionValidationResult()
    allowed_asset_ids = _collect_allowed_asset_ids(working_context, page_context, browser_context)
    role = str(user_role or "").strip().lower()

    for raw_action in auto_actions:
        action = _normalize_action(raw_action)
        issues = _validate_action(action, allowed_asset_ids=allowed_asset_ids, user_role=role)
        if issues:
            normalized_proposed_actions.append(_with_validation_issues(action, issues))
            result.downgraded_actions.append(action)
            result.issues.extend(issues)
        else:
            result.auto_actions.append(action)

    for raw_action in normalized_proposed_actions:
        action = _normalize_action(raw_action)
        issues = _validate_proposed_action(action, allowed_asset_ids=allowed_asset_ids, user_role=role)
        if issues:
            action = _with_validation_issues(action, issues)
            result.issues.extend(issues)
        result.proposed_actions.append(action)

    return result


def _validate_action(action: dict[str, Any], *, allowed_asset_ids: set[str], user_role: str) -> list[DecisionValidationIssue]:
    action_type = _action_type(action)
    issues: list[DecisionValidationIssue] = []
    if user_role != "admin":
        issues.append(_issue("non_admin_auto_execute", "非管理员账号不能自动执行写动作", action_type))
    if action_type not in LOW_RISK_AUTO_ACTIONS:
        issues.append(_issue("not_low_risk_auto_action", "该动作不属于低风险自动执行白名单", action_type))
    issues.extend(_asset_scope_issues(action, allowed_asset_ids=allowed_asset_ids))
    issues.extend(_sensitive_param_issues(action))
    if _looks_like_bulk_action(action):
        issues.append(_issue("bulk_write_requires_confirmation", "批量写动作必须进入人工确认", action_type))
    return issues


def _validate_proposed_action(action: dict[str, Any], *, allowed_asset_ids: set[str], user_role: str) -> list[DecisionValidationIssue]:
    action_type = _action_type(action)
    issues: list[DecisionValidationIssue] = []
    if user_role != "admin":
        issues.append(_issue("non_admin_write_plan", "非管理员账号不能提交执行计划", action_type, severity="medium"))
    if action_type in HIGH_RISK_ACTIONS:
        issues.append(_issue("high_risk_requires_confirmation", "高风险动作已强制保持人工确认", action_type, severity="medium"))
    issues.extend(_asset_scope_issues(action, allowed_asset_ids=allowed_asset_ids))
    return issues


def _asset_scope_issues(action: dict[str, Any], *, allowed_asset_ids: set[str]) -> list[DecisionValidationIssue]:
    action_type = _action_type(action)
    asset_ids = _collect_action_asset_ids(action)
    if not asset_ids or not allowed_asset_ids:
        return []
    unexpected = sorted(asset_ids - allowed_asset_ids)
    if not unexpected:
        return []
    return [
        _issue(
            "asset_scope_mismatch",
            f"动作包含未在当前上下文授权的资产：{', '.join(unexpected[:4])}",
            action_type,
        )
    ]


def _sensitive_param_issues(action: dict[str, Any]) -> list[DecisionValidationIssue]:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    keys = {str(key).lower() for key in _walk_keys(params)}
    matches = sorted(key for key in keys for marker in SENSITIVE_PARAM_MARKERS if marker in key)
    if not matches:
        return []
    return [_issue("sensitive_params_in_write_action", "写动作包含敏感参数，必须进入人工确认", _action_type(action))]


def _looks_like_bulk_action(action: dict[str, Any]) -> bool:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    for key in ("asset_ids", "finding_ids", "rule_ids", "targets"):
        value = params.get(key)
        if isinstance(value, list) and len(value) > 1:
            return True
    return False


def _collect_allowed_asset_ids(*payloads: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for payload in payloads:
        _collect_ids_from_payload(payload, values)
    return values


def _collect_action_asset_ids(action: dict[str, Any]) -> set[str]:
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    values: set[str] = set()
    _collect_ids_from_payload(params, values)
    return values


def _collect_ids_from_payload(value: Any, values: set[str]) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key or "").strip().lower()
            if key_text == "asset_id" and item:
                values.add(str(item))
            elif key_text == "asset_ids" and isinstance(item, list):
                values.update(str(entry) for entry in item if entry)
            else:
                _collect_ids_from_payload(item, values)
    elif isinstance(value, list):
        for item in value[:20]:
            _collect_ids_from_payload(item, values)


def _walk_keys(value: Any) -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_walk_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_walk_keys(item))
    return keys


def _normalize_action(action: dict[str, Any]) -> dict[str, Any]:
    payload = action if isinstance(action, dict) else {}
    return {
        "action_type": _action_type(payload),
        "title": sanitize_text(str(payload.get("title") or payload.get("action_type") or ""), max_length=120) or _action_type(payload),
        "reason": sanitize_text(str(payload.get("reason") or ""), max_length=240) or "",
        "params": sanitize_json_value(payload.get("params") if isinstance(payload.get("params"), dict) else {}),
        **({"validation": sanitize_json_value(payload.get("validation"))} if isinstance(payload.get("validation"), dict) else {}),
    }


def _with_validation_issues(action: dict[str, Any], issues: list[DecisionValidationIssue]) -> dict[str, Any]:
    payload = _normalize_action(action)
    payload["validation"] = {
        "requires_human_confirmation": True,
        "issues": [issue.to_payload() for issue in issues],
    }
    return payload


def _action_type(action: dict[str, Any]) -> str:
    return sanitize_text(str(action.get("action_type") or ""), max_length=64, single_line=True) or ""


def _issue(code: str, message: str, action_type: str, *, severity: str = "high") -> DecisionValidationIssue:
    return DecisionValidationIssue(code=code, message=message, action_type=action_type, severity=severity)
