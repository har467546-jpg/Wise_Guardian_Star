from __future__ import annotations

import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

try:
    import fcntl
except ModuleNotFoundError:
    fcntl = None
import yaml

from app.rules.remediation import resolve_rule_remediation, serialize_remediation
from app.rules.rule_loader import RuleLoader
from app.rules.rule_matcher import RuleDefinition


class RuleStoreError(ValueError):
    pass


class RuleNotFoundError(RuleStoreError):
    pass


class RuleConflictError(RuleStoreError):
    pass


@dataclass(frozen=True, slots=True)
class RuleImportWriteResult:
    created_ids: list[str]
    updated_ids: list[str]
    skipped_ids: list[str]


@dataclass(frozen=True, slots=True)
class RuleBatchStatusResult:
    enabled: bool
    updated_ids: list[str]
    unchanged_ids: list[str]
    missing_ids: list[str]


class RuleStore:
    def __init__(self, rule_path: str | Path) -> None:
        self.rule_path = Path(rule_path)
        self.lock_path = self.rule_path.with_suffix(f"{self.rule_path.suffix}.lock")
        self.loader = RuleLoader(rule_path)

    def list_rules(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        keyword: str | None = None,
        service: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
        catalog_view: str = "default",
    ) -> tuple[list[RuleDefinition], int]:
        rules = self.loader.load().rules
        filtered = self._filter_rules(
            rules,
            keyword=keyword,
            service=service,
            severity=severity,
            enabled=enabled,
            catalog_view=catalog_view,
        )
        start = max(0, (page - 1) * page_size)
        end = start + page_size
        return filtered[start:end], len(filtered)

    def search_rules(
        self,
        *,
        keyword: str | None = None,
        service: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
        catalog_view: str = "default",
    ) -> list[RuleDefinition]:
        rules = self.loader.load().rules
        return self._filter_rules(
            rules,
            keyword=keyword,
            service=service,
            severity=severity,
            enabled=enabled,
            catalog_view=catalog_view,
        )

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        rules = self.loader.load().rules
        return next((rule for rule in rules if rule.rule_id == rule_id), None)

    def create_rule(self, payload: dict[str, Any]) -> RuleDefinition:
        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            if any(rule.rule_id == payload["id"] for rule in existing_rules):
                raise RuleConflictError(f"规则已存在：{payload['id']}")

            now = self._now_iso()
            candidate_rules = existing_rules + [self._payload_with_timestamps(payload, created_at=now, updated_at=now)]
            validated_rules = self._validate_rules(candidate_rules)
            self._write_rules(validated_rules)
            return next(rule for rule in validated_rules if rule.rule_id == payload["id"])

    def update_rule(self, rule_id: str, payload: dict[str, Any]) -> RuleDefinition:
        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            target = next((rule for rule in existing_rules if rule.rule_id == rule_id), None)
            if target is None:
                raise RuleNotFoundError(f"规则不存在：{rule_id}")

            updated_rules: list[dict[str, Any]] = []
            for rule in existing_rules:
                serialized = self.serialize_rule(rule)
                if rule.rule_id == rule_id:
                    serialized.update(payload)
                    serialized["id"] = rule_id
                    serialized["created_at"] = rule.created_at or serialized.get("created_at") or self._now_iso()
                    serialized["updated_at"] = self._now_iso()
                updated_rules.append(serialized)

            validated_rules = self._validate_rules(updated_rules)
            self._write_rules(validated_rules)
            return next(rule for rule in validated_rules if rule.rule_id == rule_id)

    def delete_rule(self, rule_id: str) -> None:
        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            remaining_rules = [rule for rule in existing_rules if rule.rule_id != rule_id]
            if len(remaining_rules) == len(existing_rules):
                raise RuleNotFoundError(f"规则不存在：{rule_id}")
            self._write_rules(remaining_rules)

    def bootstrap_rules(self, payload_rules: list[dict[str, Any]]) -> tuple[list[RuleDefinition], list[str]]:
        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            existing_ids = {rule.rule_id for rule in existing_rules}
            skipped_ids: list[str] = []
            created_ids: list[str] = []
            appended_rules = [self.serialize_rule(rule) for rule in existing_rules]

            for payload in payload_rules:
                if payload["id"] in existing_ids:
                    skipped_ids.append(payload["id"])
                    continue
                now = self._now_iso()
                appended_rules.append(self._payload_with_timestamps(payload, created_at=now, updated_at=now))
                existing_ids.add(payload["id"])
                created_ids.append(payload["id"])

            validated_rules = self._validate_rules(appended_rules)
            self._write_rules(validated_rules)
            created_rules = [rule for rule in validated_rules if rule.rule_id in created_ids]
            return created_rules, skipped_ids

    def import_rules(self, payload_rules: list[dict[str, Any]], *, mode: str = "skip_existing") -> RuleImportWriteResult:
        if mode not in {"skip_existing", "upsert"}:
            raise ValueError(f"不支持的导入模式：{mode}")

        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            existing_ids = {rule.rule_id for rule in existing_rules}
            incoming_payloads = [self.serialize_rule(rule) if isinstance(rule, RuleDefinition) else dict(rule) for rule in payload_rules]
            incoming_by_id = {payload["id"]: payload for payload in incoming_payloads}

            created_ids: list[str] = []
            updated_ids: list[str] = []
            skipped_ids: list[str] = []
            merged_payloads: list[dict[str, Any]] = []

            for rule in existing_rules:
                current_payload = self.serialize_rule(rule)
                incoming = incoming_by_id.get(rule.rule_id)
                if incoming is None:
                    merged_payloads.append(current_payload)
                    continue

                if mode == "skip_existing":
                    skipped_ids.append(rule.rule_id)
                    merged_payloads.append(current_payload)
                    continue

                candidate_payload = self._payload_with_timestamps(
                    incoming,
                    created_at=rule.created_at or self._now_iso(),
                    updated_at=self._now_iso(),
                )
                if self._payloads_equal(current_payload, candidate_payload):
                    skipped_ids.append(rule.rule_id)
                    merged_payloads.append(current_payload)
                    continue

                updated_ids.append(rule.rule_id)
                merged_payloads.append(candidate_payload)

            for incoming in incoming_payloads:
                rule_id = incoming["id"]
                if rule_id in existing_ids:
                    continue
                now = self._now_iso()
                created_ids.append(rule_id)
                merged_payloads.append(self._payload_with_timestamps(incoming, created_at=now, updated_at=now))

            validated_rules = self._validate_rules(merged_payloads)
            self._write_rules(validated_rules)
            return RuleImportWriteResult(
                created_ids=created_ids,
                updated_ids=updated_ids,
                skipped_ids=skipped_ids,
            )

    def set_rules_enabled(self, rule_ids: list[str], *, enabled: bool) -> RuleBatchStatusResult:
        unique_rule_ids = list(dict.fromkeys(rule_ids))
        if not unique_rule_ids:
            return RuleBatchStatusResult(enabled=enabled, updated_ids=[], unchanged_ids=[], missing_ids=[])

        with self._write_lock():
            existing_rules = self.loader.load(force=True).rules
            existing_map = {rule.rule_id: rule for rule in existing_rules}
            missing_ids = [rule_id for rule_id in unique_rule_ids if rule_id not in existing_map]

            updated_ids: list[str] = []
            unchanged_ids: list[str] = []
            updated_payloads: list[dict[str, Any]] = []

            for rule in existing_rules:
                payload = self.serialize_rule(rule)
                if rule.rule_id not in unique_rule_ids:
                    updated_payloads.append(payload)
                    continue

                if rule.enabled is enabled:
                    unchanged_ids.append(rule.rule_id)
                    updated_payloads.append(payload)
                    continue

                payload["enabled"] = enabled
                payload["updated_at"] = self._now_iso()
                updated_ids.append(rule.rule_id)
                updated_payloads.append(payload)

            if updated_ids:
                validated_rules = self._validate_rules(updated_payloads)
                self._write_rules(validated_rules)

            return RuleBatchStatusResult(
                enabled=enabled,
                updated_ids=updated_ids,
                unchanged_ids=unchanged_ids,
                missing_ids=missing_ids,
            )

    def _validate_rules(self, raw_rules: list[RuleDefinition | dict[str, Any]]) -> list[RuleDefinition]:
        payload = {"rules": [self.serialize_rule(rule) if isinstance(rule, RuleDefinition) else rule for rule in raw_rules]}
        return self.loader.validate_payload(payload)

    def _write_rules(self, rules: list[RuleDefinition]) -> None:
        payload = {"rules": [self.serialize_rule(rule) for rule in rules]}
        self.rule_path.parent.mkdir(parents=True, exist_ok=True)

        fd, temp_path = tempfile.mkstemp(prefix="risk_rules_", suffix=".yaml", dir=self.rule_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
                yaml.safe_dump(payload, temp_file, sort_keys=False, allow_unicode=True, default_flow_style=False)
            os.replace(temp_path, self.rule_path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        self.loader.load(force=True)

    def _filter_rules(
        self,
        rules: list[RuleDefinition],
        *,
        keyword: str | None,
        service: str | None,
        severity: str | None,
        enabled: bool | None,
        catalog_view: str,
    ) -> list[RuleDefinition]:
        keyword_value = (keyword or "").strip().lower()
        service_value = (service or "").strip().lower()
        severity_value = (severity or "").strip().lower()
        catalog_view_value = (catalog_view or "default").strip().lower() or "default"

        filtered: list[RuleDefinition] = []
        for rule in rules:
            tags = {tag.strip() for tag in rule.tags if isinstance(tag, str)}
            is_legacy_exposure = "legacy-exposure" in tags
            if service_value and rule.service != service_value:
                continue
            if severity_value and rule.severity != severity_value:
                continue
            if enabled is not None and rule.enabled is not enabled:
                continue
            if catalog_view_value == "default" and is_legacy_exposure:
                continue
            if catalog_view_value == "legacy" and not is_legacy_exposure:
                continue
            if keyword_value:
                haystack = " ".join(
                    [
                        rule.rule_id,
                        rule.name or "",
                        rule.service,
                        rule.description,
                        " ".join(rule.cve_ids),
                        " ".join(rule.tags),
                    ]
                ).lower()
                if keyword_value not in haystack:
                    continue
            filtered.append(rule)
        filtered.sort(key=lambda item: (item.service, item.name or item.rule_id))
        filtered.sort(key=lambda item: item.updated_at or "", reverse=True)
        filtered.sort(key=self._catalog_priority, reverse=True)
        return filtered

    @staticmethod
    def _catalog_priority(rule: RuleDefinition) -> int:
        tags = {tag.strip() for tag in rule.tags if isinstance(tag, str)}
        if "high-value" in tags:
            return 2
        if "legacy-exposure" in tags:
            return 0
        return 1

    def _payload_with_timestamps(self, payload: dict[str, Any], *, created_at: str, updated_at: str) -> dict[str, Any]:
        result = dict(payload)
        result["created_at"] = payload.get("created_at") or created_at
        result["updated_at"] = updated_at
        return result

    @staticmethod
    def _payloads_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
        ignored_keys = {"created_at", "updated_at"}
        left_cmp = {key: value for key, value in left.items() if key not in ignored_keys}
        right_cmp = {key: value for key, value in right.items() if key not in ignored_keys}
        return left_cmp == right_cmp

    @staticmethod
    def serialize_rule(rule: RuleDefinition, *, include_resolved_remediation: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": rule.rule_id,
            "name": rule.name or rule.rule_id,
            "enabled": rule.enabled,
            "service": rule.service,
            "severity": rule.severity,
            "description": rule.description,
            "match": {},
        }
        if rule.version_constraint:
            payload["match"]["version"] = rule.version_constraint
        if rule.config_conditions:
            payload["match"]["config"] = rule.config_conditions
        if rule.nse_conditions:
            payload["match"]["nse"] = rule.nse_conditions
        if rule.package_conditions:
            payload["match"]["package"] = {
                "manager": rule.package_conditions.manager,
                "name": rule.package_conditions.name,
                "compare": rule.package_conditions.compare,
                "fixed_versions": rule.package_conditions.fixed_versions,
            }
        if rule.cve_ids:
            payload["cve_ids"] = rule.cve_ids
        if rule.cwe_ids:
            payload["cwe_ids"] = rule.cwe_ids
        if rule.affected_versions_text:
            payload["affected_versions_text"] = rule.affected_versions_text
        if rule.exploit_module:
            payload["exploit_module"] = rule.exploit_module
        if rule.preconditions:
            payload["preconditions"] = rule.preconditions
        if rule.verify_playbook:
            payload["verify_playbook"] = rule.verify_playbook
        if rule.mitigations:
            payload["mitigations"] = rule.mitigations
        remediation = resolve_rule_remediation(rule) if include_resolved_remediation or rule.remediation is None else rule.remediation
        if remediation is not None:
            payload["remediation"] = serialize_remediation(remediation)
        if rule.references:
            payload["references"] = rule.references
        if rule.tags:
            payload["tags"] = rule.tags
        if rule.active_check:
            payload["active_check"] = {
                "detector": rule.active_check.detector,
                "trigger": rule.active_check.trigger,
                "timeout_seconds": rule.active_check.timeout_seconds,
                "params": rule.active_check.params,
            }
        if rule.created_at:
            payload["created_at"] = rule.created_at
        if rule.updated_at:
            payload["updated_at"] = rule.updated_at
        return payload

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock_file:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
