from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from app.rules.rule_matcher import (
    ActiveCheckDefinition,
    PackageMatchDefinition,
    RemediationActionDefinition,
    RuleDefinition,
    RuleRemediationDefinition,
    SUPPORTED_ACTIVE_CHECK_DETECTORS,
    SUPPORTED_ACTIVE_CHECK_TRIGGERS,
    SUPPORTED_CONFIG_OPERATORS,
    SUPPORTED_PACKAGE_COMPARES,
    SUPPORTED_PACKAGE_MANAGERS,
    SUPPORTED_REMEDIATION_ACTION_TYPES,
    VALID_SEVERITIES,
    VALID_REMEDIATION_AUTOMATION_LEVELS,
)

logger = logging.getLogger(__name__)
_UNICODE_ESCAPE_PATTERN = re.compile(r"\\u([0-9a-fA-F]{4})")


class RuleLoadError(ValueError):
    pass


@dataclass(slots=True)
class RuleSet:
    path: str
    source_mtime: float | None
    loaded_at: datetime | None
    rules: list[RuleDefinition] = field(default_factory=list)
    last_error: str | None = None


class RuleLoader:
    def __init__(self, rule_path: str | Path) -> None:
        self.rule_path = Path(rule_path)
        self._rule_set = RuleSet(path=str(self.rule_path), source_mtime=None, loaded_at=None, rules=[], last_error=None)

    def load(self, force: bool = False) -> RuleSet:
        if force:
            return self._reload_from_disk(current_mtime=self._get_mtime())
        return self.maybe_reload()

    def maybe_reload(self) -> RuleSet:
        current_mtime = self._get_mtime()
        if self._rule_set.loaded_at is None:
            return self._reload_from_disk(current_mtime=current_mtime)
        if current_mtime is None:
            return self._rule_set
        if self._rule_set.source_mtime == current_mtime:
            return self._rule_set
        return self._reload_from_disk(current_mtime=current_mtime)

    def _reload_from_disk(self, current_mtime: float | None) -> RuleSet:
        previous_rules = list(self._rule_set.rules)
        try:
            payload = yaml.safe_load(self.rule_path.read_text(encoding="utf-8")) or {}
            rules = self.validate_payload(payload)
        except Exception as exc:
            message = str(exc)
            logger.warning("failed to load risk rules from %s: %s", self.rule_path, message)
            if self._rule_set.loaded_at is None:
                self._rule_set = RuleSet(
                    path=str(self.rule_path),
                    source_mtime=current_mtime,
                    loaded_at=datetime.now(timezone.utc),
                    rules=[],
                    last_error=message,
                )
                return self._rule_set

            self._rule_set = RuleSet(
                path=str(self.rule_path),
                source_mtime=self._rule_set.source_mtime,
                loaded_at=self._rule_set.loaded_at,
                rules=previous_rules,
                last_error=message,
            )
            return self._rule_set

        self._rule_set = RuleSet(
            path=str(self.rule_path),
            source_mtime=current_mtime,
            loaded_at=datetime.now(timezone.utc),
            rules=rules,
            last_error=None,
        )
        return self._rule_set

    def validate_payload(self, payload: Any) -> list[RuleDefinition]:
        return self._parse_payload(payload)

    def _get_mtime(self) -> float | None:
        try:
            return self.rule_path.stat().st_mtime
        except FileNotFoundError:
            return None

    def _parse_payload(self, payload: Any) -> list[RuleDefinition]:
        if not isinstance(payload, dict):
            raise RuleLoadError("规则文件顶层必须是对象结构")

        raw_rules = payload.get("rules", [])
        if not isinstance(raw_rules, list):
            raise RuleLoadError("rules 必须是列表")

        seen_ids: set[str] = set()
        rules: list[RuleDefinition] = []
        for raw_rule in raw_rules:
            rule = self._parse_rule(raw_rule)
            if rule.rule_id in seen_ids:
                raise RuleLoadError(f"规则 ID 重复：{rule.rule_id}")
            seen_ids.add(rule.rule_id)
            rules.append(rule)
        return rules

    def _parse_rule(self, raw_rule: Any) -> RuleDefinition:
        if not isinstance(raw_rule, dict):
            raise RuleLoadError("每条规则都必须是对象结构")

        rule_id = self._expect_string(raw_rule, "id")
        service = self._expect_string(raw_rule, "service").lower()
        severity = self._expect_string(raw_rule, "severity").lower()
        description = self._expect_string(raw_rule, "description", decode_unicode_escapes=True)
        enabled = bool(raw_rule.get("enabled", True))
        if severity not in VALID_SEVERITIES:
            raise RuleLoadError(f"规则严重级别无效：{rule_id} -> {severity}")

        match = raw_rule.get("match", {})
        if not isinstance(match, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 match 必须是对象结构")

        version_constraint = match.get("version")
        if version_constraint is not None and not isinstance(version_constraint, str):
            raise RuleLoadError(f"规则 {rule_id} 的版本匹配必须是字符串")
        if isinstance(version_constraint, str):
            try:
                SpecifierSet(version_constraint)
            except InvalidSpecifier as exc:
                raise RuleLoadError(f"规则 {rule_id} 的版本约束无效：{version_constraint}") from exc

        config_conditions = self._parse_mapping_conditions(
            rule_id=rule_id,
            raw_conditions=match.get("config"),
            field_label="config",
            key_label="配置键",
            mapping_error="配置匹配必须是对象结构",
        )
        nse_conditions = self._parse_mapping_conditions(
            rule_id=rule_id,
            raw_conditions=match.get("nse"),
            field_label="nse",
            key_label="NSE 键",
            mapping_error="NSE 匹配必须是对象结构",
        )
        package_conditions = self._parse_package_conditions(rule_id=rule_id, raw_conditions=match.get("package"))
        if version_constraint is None and config_conditions is None and nse_conditions is None and package_conditions is None:
            raise RuleLoadError(f"规则 {rule_id} 必须定义 match.version、match.config、match.nse 或 match.package")

        active_check = self._parse_active_check(rule_id, raw_rule.get("active_check"))
        remediation = self._parse_remediation(rule_id, raw_rule.get("remediation"))

        return RuleDefinition(
            rule_id=rule_id,
            enabled=enabled,
            service=service,
            severity=severity,
            description=description,
            name=self._optional_string(raw_rule.get("name"), decode_unicode_escapes=True) or rule_id,
            version_constraint=version_constraint,
            config_conditions=config_conditions,
            nse_conditions=nse_conditions,
            package_conditions=package_conditions,
            cve_ids=self._string_list(raw_rule.get("cve_ids")),
            cwe_ids=self._string_list(raw_rule.get("cwe_ids")),
            affected_versions_text=self._optional_string(raw_rule.get("affected_versions_text"), decode_unicode_escapes=True),
            exploit_module=self._optional_string(raw_rule.get("exploit_module")),
            preconditions=self._string_list(raw_rule.get("preconditions"), decode_unicode_escapes=True),
            verify_playbook=self._string_list(raw_rule.get("verify_playbook"), decode_unicode_escapes=True),
            mitigations=self._string_list(raw_rule.get("mitigations"), decode_unicode_escapes=True),
            remediation=remediation,
            references=self._string_list(raw_rule.get("references") or raw_rule.get("reference")),
            tags=self._string_list(raw_rule.get("tags")),
            created_at=self._optional_string(raw_rule.get("created_at")),
            updated_at=self._optional_string(raw_rule.get("updated_at")),
            active_check=active_check,
        )

    def _parse_mapping_conditions(
        self,
        *,
        rule_id: str,
        raw_conditions: Any,
        field_label: str,
        key_label: str,
        mapping_error: str,
    ) -> dict[str, dict[str, Any]] | None:
        if raw_conditions is None:
            return None
        if not isinstance(raw_conditions, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 {mapping_error}")
        for key, operators in raw_conditions.items():
            if not isinstance(key, str):
                raise RuleLoadError(f"规则 {rule_id} 的 {key_label} 必须是字符串")
            if not isinstance(operators, dict):
                raise RuleLoadError(f"规则 {rule_id} 的 {field_label} 操作必须是对象结构")
            unknown = set(operators) - SUPPORTED_CONFIG_OPERATORS
            if unknown:
                unsupported = ", ".join(sorted(unknown))
                raise RuleLoadError(f"规则 {rule_id} 使用了不支持的 {field_label} 操作符：{unsupported}")
        return raw_conditions

    def _parse_package_conditions(self, *, rule_id: str, raw_conditions: Any) -> PackageMatchDefinition | None:
        if raw_conditions is None:
            return None
        if not isinstance(raw_conditions, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 软件包匹配必须是对象结构")

        manager = self._expect_string(raw_conditions, "manager").lower()
        if manager not in SUPPORTED_PACKAGE_MANAGERS:
            raise RuleLoadError(f"规则 {rule_id} 的 match.package.manager 不受支持：{manager}")

        name = self._expect_string(raw_conditions, "name").lower()
        compare = self._expect_string(raw_conditions, "compare").lower()
        if compare not in SUPPORTED_PACKAGE_COMPARES:
            raise RuleLoadError(f"规则 {rule_id} 的 match.package.compare 不受支持：{compare}")

        fixed_versions = raw_conditions.get("fixed_versions")
        if not isinstance(fixed_versions, dict) or not fixed_versions:
            raise RuleLoadError(f"规则 {rule_id} 的 match.package.fixed_versions 必须是非空对象结构")

        normalized_fixed_versions: dict[str, dict[str, str]] = {}
        for distro, releases in fixed_versions.items():
            if not isinstance(distro, str) or not distro.strip():
                raise RuleLoadError(f"规则 {rule_id} 的 match.package.fixed_versions 发行版键必须是非空字符串")
            if not isinstance(releases, dict) or not releases:
                raise RuleLoadError(f"规则 {rule_id} 的 match.package.fixed_versions.{distro} 必须是非空对象结构")
            normalized_releases: dict[str, str] = {}
            for release, version in releases.items():
                if not isinstance(release, str) or not release.strip():
                    raise RuleLoadError(f"规则 {rule_id} 的 match.package.fixed_versions.{distro} 发行版版本键必须是非空字符串")
                if not isinstance(version, str) or not version.strip():
                    raise RuleLoadError(f"规则 {rule_id} 的 match.package.fixed_versions.{distro}.{release} 必须是非空字符串")
                normalized_releases[release.strip()] = version.strip()
            normalized_fixed_versions[distro.strip().lower()] = normalized_releases

        return PackageMatchDefinition(
            manager=manager,
            name=name,
            compare=compare,
            fixed_versions=normalized_fixed_versions,
        )

    def _parse_remediation(self, rule_id: str, raw_remediation: Any) -> RuleRemediationDefinition | None:
        if raw_remediation is None:
            return None
        if not isinstance(raw_remediation, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 remediation 必须是对象结构")

        summary = self._expect_string(raw_remediation, "summary")
        automation_level = self._expect_string(raw_remediation, "automation_level").lower()
        if automation_level not in VALID_REMEDIATION_AUTOMATION_LEVELS:
            raise RuleLoadError(f"规则 {rule_id} 的 remediation.automation_level 不受支持：{automation_level}")

        raw_actions = raw_remediation.get("actions")
        if not isinstance(raw_actions, list) or not raw_actions:
            raise RuleLoadError(f"规则 {rule_id} 的 remediation.actions 必须是非空数组")

        actions: list[RemediationActionDefinition] = []
        for index, raw_action in enumerate(raw_actions, start=1):
            if not isinstance(raw_action, dict):
                raise RuleLoadError(f"规则 {rule_id} 的 remediation.actions[{index}] 必须是对象结构")
            action_type = self._expect_string(raw_action, "action_type")
            if action_type not in SUPPORTED_REMEDIATION_ACTION_TYPES:
                raise RuleLoadError(f"规则 {rule_id} 的 remediation.actions[{index}].action_type 不受支持：{action_type}")
            title = self._expect_string(raw_action, "title")
            params = raw_action.get("params") or {}
            if not isinstance(params, dict):
                raise RuleLoadError(f"规则 {rule_id} 的 remediation.actions[{index}].params 必须是对象结构")

            requires_confirmation = raw_action.get("requires_confirmation")
            if requires_confirmation is not None and not isinstance(requires_confirmation, bool):
                raise RuleLoadError(
                    f"规则 {rule_id} 的 remediation.actions[{index}].requires_confirmation 必须是布尔值"
                )

            rollback_hint = raw_action.get("rollback_hint")
            if rollback_hint is not None and not isinstance(rollback_hint, str):
                raise RuleLoadError(f"规则 {rule_id} 的 remediation.actions[{index}].rollback_hint 必须是字符串或 null")
            normalized_rollback_hint = rollback_hint.strip() or None if isinstance(rollback_hint, str) else None
            target_files = self._string_list(raw_action.get("target_files"), decode_unicode_escapes=True)
            target_services = self._string_list(raw_action.get("target_services"), decode_unicode_escapes=True)
            target_paths = self._string_list(raw_action.get("target_paths"), decode_unicode_escapes=True)
            verify_items = self._string_list(raw_action.get("verify_items"), decode_unicode_escapes=True)

            actions.append(
                RemediationActionDefinition(
                    action_type=action_type,
                    title=title,
                    params=params,
                    requires_confirmation=requires_confirmation,
                    rollback_hint=normalized_rollback_hint,
                    target_files=target_files,
                    target_services=target_services,
                    target_paths=target_paths,
                    verify_items=verify_items,
                )
            )

        return RuleRemediationDefinition(
            summary=summary,
            automation_level=automation_level,
            impact_summary=self._optional_string(raw_remediation.get("impact_summary"), decode_unicode_escapes=True),
            precheck_items=self._string_list(raw_remediation.get("precheck_items"), decode_unicode_escapes=True),
            verify_items=self._string_list(raw_remediation.get("verify_items"), decode_unicode_escapes=True),
            rollback_notes=self._string_list(raw_remediation.get("rollback_notes"), decode_unicode_escapes=True),
            actions=actions,
            references=self._string_list(raw_remediation.get("references")),
        )

    def _parse_active_check(self, rule_id: str, raw_active_check: Any) -> ActiveCheckDefinition | None:
        if raw_active_check is None:
            return None
        if not isinstance(raw_active_check, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 active_check 必须是对象结构")

        detector = self._expect_string(raw_active_check, "detector")
        trigger = self._expect_string(raw_active_check, "trigger")
        if detector not in SUPPORTED_ACTIVE_CHECK_DETECTORS:
            raise RuleLoadError(f"规则 {rule_id} 的 active_check.detector 不受支持：{detector}")
        if trigger not in SUPPORTED_ACTIVE_CHECK_TRIGGERS:
            raise RuleLoadError(f"规则 {rule_id} 的 active_check.trigger 不受支持：{trigger}")

        timeout_seconds = raw_active_check.get("timeout_seconds", 5)
        if not isinstance(timeout_seconds, int) or timeout_seconds < 1 or timeout_seconds > 60:
            raise RuleLoadError(f"规则 {rule_id} 的 active_check.timeout_seconds 必须是 1 到 60 之间的整数")

        params = raw_active_check.get("params") or {}
        if not isinstance(params, dict):
            raise RuleLoadError(f"规则 {rule_id} 的 active_check.params 必须是对象结构")

        return ActiveCheckDefinition(
            detector=detector,
            trigger=trigger,
            timeout_seconds=timeout_seconds,
            params=params,
        )

    @staticmethod
    def _expect_string(raw_rule: dict[str, Any], field: str, *, decode_unicode_escapes: bool = False) -> str:
        value = raw_rule.get(field)
        if not isinstance(value, str) or not value.strip():
            raise RuleLoadError(f"{field} 必须是非空字符串")
        normalized = value.strip()
        if decode_unicode_escapes:
            normalized = RuleLoader._decode_unicode_escapes(normalized)
        return normalized

    @staticmethod
    def _optional_string(value: Any, *, decode_unicode_escapes: bool = False) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise RuleLoadError("optional string fields must be strings")
        normalized = value.strip()
        if decode_unicode_escapes:
            normalized = RuleLoader._decode_unicode_escapes(normalized)
        return normalized or None

    @staticmethod
    def _string_list(value: Any, *, decode_unicode_escapes: bool = False) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            normalized = value.strip()
            if decode_unicode_escapes:
                normalized = RuleLoader._decode_unicode_escapes(normalized)
            return [normalized] if normalized else []
        if not isinstance(value, list):
            raise RuleLoadError("list fields must be arrays of strings")
        result: list[str] = []
        for item in value:
            if not isinstance(item, str):
                raise RuleLoadError("list fields must contain strings")
            normalized = item.strip()
            if decode_unicode_escapes:
                normalized = RuleLoader._decode_unicode_escapes(normalized)
            if normalized:
                result.append(normalized)
        return result

    @staticmethod
    def _decode_unicode_escapes(value: str) -> str:
        if "\\u" not in value:
            return value
        return _UNICODE_ESCAPE_PATTERN.sub(lambda match: chr(int(match.group(1), 16)), value)
