from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from app.utils.versioning import compare_debian_package_versions, normalize_version_token

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
SUPPORTED_CONFIG_OPERATORS = {"eq", "ne", "exists", "contains"}
SUPPORTED_PACKAGE_MANAGERS = {"dpkg"}
SUPPORTED_PACKAGE_COMPARES = {"lt_fixed"}
VALID_REMEDIATION_AUTOMATION_LEVELS = {"callable"}
SUPPORTED_REMEDIATION_ACTION_TYPES = {
    "upgrade_package",
    "set_config",
    "remove_config",
    "restart_service",
    "reload_service",
    "disable_service",
    "restrict_network",
    "remove_exposure",
    "permission_set",
    "toggle_feature",
    "set_bind_scope",
    "set_access_policy",
    "remove_path",
    "set_path_permission",
}
SUPPORTED_ACTIVE_CHECK_DETECTORS = {
    "vsftpd_smiley_backdoor",
    "ftp_anonymous_login",
    "tomcat_manager_default_creds",
    "distccd_rce_probe",
    "unrealircd_backdoor_probe",
    "redis_unauth_info_probe",
    "http_risky_methods_probe",
}
SUPPORTED_ACTIVE_CHECK_TRIGGERS = {"on_passive_match", "on_service_present"}


@dataclass(frozen=True, slots=True)
class RuleInput:
    service: str
    version: str | None = None
    config: dict[str, Any] | None = None
    nse: dict[str, Any] | None = None
    package: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RuleMatch:
    severity: str
    rule_id: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "rule_id": self.rule_id,
            "description": self.description,
        }


@dataclass(frozen=True, slots=True)
class ActiveCheckDefinition:
    detector: str
    trigger: str
    timeout_seconds: int = 5
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PackageMatchDefinition:
    manager: str
    name: str
    compare: str
    fixed_versions: dict[str, dict[str, str]]


@dataclass(frozen=True, slots=True)
class RemediationActionDefinition:
    action_type: str
    title: str
    params: dict[str, Any] = field(default_factory=dict)
    requires_confirmation: bool | None = None
    rollback_hint: str | None = None
    target_files: list[str] = field(default_factory=list)
    target_services: list[str] = field(default_factory=list)
    target_paths: list[str] = field(default_factory=list)
    verify_items: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RuleRemediationDefinition:
    summary: str
    automation_level: str
    impact_summary: str | None = None
    precheck_items: list[str] = field(default_factory=list)
    verify_items: list[str] = field(default_factory=list)
    rollback_notes: list[str] = field(default_factory=list)
    actions: list[RemediationActionDefinition] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    rule_id: str
    enabled: bool
    service: str
    severity: str
    description: str
    name: str | None = None
    version_constraint: str | None = None
    config_conditions: dict[str, dict[str, Any]] | None = None
    nse_conditions: dict[str, dict[str, Any]] | None = None
    package_conditions: PackageMatchDefinition | None = None
    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    affected_versions_text: str | None = None
    exploit_module: str | None = None
    preconditions: list[str] = field(default_factory=list)
    verify_playbook: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    remediation: RuleRemediationDefinition | None = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None
    active_check: ActiveCheckDefinition | None = None


class RuleMatcher:
    @staticmethod
    def match(rule_input: RuleInput, rules: list[RuleDefinition]) -> list[RuleMatch]:
        normalized_service = (rule_input.service or "").strip().lower()
        matches: list[RuleMatch] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.service != normalized_service:
                continue
            if not RuleMatcher._matches_version(rule, rule_input.version):
                continue
            if not RuleMatcher._matches_config(rule, rule_input.config or {}):
                continue
            if not RuleMatcher._matches_nse(rule, rule_input.nse or {}):
                continue
            if not RuleMatcher._matches_package(rule, rule_input.package or {}):
                continue
            matches.append(
                RuleMatch(
                    severity=rule.severity,
                    rule_id=rule.rule_id,
                    description=rule.description,
                )
            )
        return matches

    @staticmethod
    def _matches_version(rule: RuleDefinition, version: str | None) -> bool:
        if not rule.version_constraint:
            return True
        normalized = RuleMatcher._normalize_version(version)
        if not normalized:
            return False
        try:
            parsed_version = Version(normalized)
            specifier = SpecifierSet(rule.version_constraint)
        except (InvalidVersion, InvalidSpecifier):
            return False
        return parsed_version in specifier

    @staticmethod
    def _matches_config(rule: RuleDefinition, config: dict[str, Any]) -> bool:
        conditions = rule.config_conditions or {}
        for key, operations in conditions.items():
            if not RuleMatcher._matches_mapping_operations(config, key, operations):
                return False
        return True

    @staticmethod
    def _matches_nse(rule: RuleDefinition, nse: dict[str, Any]) -> bool:
        conditions = rule.nse_conditions or {}
        for key, operations in conditions.items():
            if not RuleMatcher._matches_mapping_operations(nse, key, operations):
                return False
        return True

    @staticmethod
    def _matches_package(rule: RuleDefinition, package: dict[str, Any]) -> bool:
        condition = rule.package_conditions
        if condition is None:
            return True
        if not isinstance(package, dict):
            return False

        manager = str(package.get("manager") or "").strip().lower()
        name = str(package.get("name") or "").strip().lower()
        version = str(package.get("version") or "").strip()
        distro = str(package.get("distro") or "").strip().lower()
        release = str(package.get("release") or "").strip()
        if manager != condition.manager or name != condition.name:
            return False
        if not version or not distro or not release:
            return False

        fixed_version = condition.fixed_versions.get(distro, {}).get(release)
        if not fixed_version:
            return False

        if condition.compare == "lt_fixed" and manager == "dpkg":
            return compare_debian_package_versions(version, fixed_version) < 0
        return False

    @staticmethod
    def _matches_mapping_operations(payload: dict[str, Any], key: str, operations: dict[str, Any]) -> bool:
        present, value = RuleMatcher._resolve_match_path(payload, key)

        for operator, expected in operations.items():
            if operator == "exists":
                if bool(present) != bool(expected):
                    return False
            elif operator == "eq":
                if not present or value != expected:
                    return False
            elif operator == "ne":
                if not present or value == expected:
                    return False
            elif operator == "contains":
                if not present:
                    return False
                if isinstance(value, str):
                    if str(expected) not in value:
                        return False
                elif isinstance(value, (list, tuple, set)):
                    if expected not in value:
                        return False
                else:
                    return False
            else:
                return False
        return True

    @staticmethod
    def _resolve_match_path(payload: dict[str, Any], key: str) -> tuple[bool, Any]:
        if not isinstance(payload, dict):
            return False, None
        if key in payload:
            return True, payload.get(key)

        current: Any = payload
        for segment in key.split("."):
            if not isinstance(current, dict) or segment not in current:
                return False, None
            current = current.get(segment)
        return True, current

    @staticmethod
    def _normalize_version(raw: str | None) -> str | None:
        return normalize_version_token(raw)
