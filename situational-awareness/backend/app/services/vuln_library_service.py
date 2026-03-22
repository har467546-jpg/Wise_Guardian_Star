from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

import yaml
from sqlalchemy import String, case, delete, desc, distinct, func, select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import text

from app.db.models.enums import RiskSeverity
from app.db.models.vuln_rule_index import VulnRuleIndex
from app.db.session import SessionLocal
from app.rules.rule_loader import RuleLoadError, RuleSet
from app.rules.rule_matcher import RuleDefinition
from app.rules.rule_store import RuleBatchStatusResult, RuleImportWriteResult, RuleStore


@dataclass(frozen=True, slots=True)
class VulnLibraryIndexStatus:
    indexed_rule_count: int
    index_synced_at: datetime | None
    index_in_sync: bool
    source_hash: str | None
    index_last_error: str | None = None


@dataclass(frozen=True, slots=True)
class VulnLibraryStatusPayload:
    path: str
    loaded_at: datetime | None
    source_mtime: float | None
    rule_count: int
    last_error: str | None
    indexed_rule_count: int
    index_synced_at: datetime | None
    index_in_sync: bool
    index_last_error: str | None


@dataclass(frozen=True, slots=True)
class VulnRuleImportError:
    rule_id: str | None
    message: str


@dataclass(frozen=True, slots=True)
class VulnRuleImportResult:
    dry_run: bool
    mode: str
    detected_format: str
    total_in_file: int
    created_ids: list[str] = field(default_factory=list)
    updated_ids: list[str] = field(default_factory=list)
    skipped_ids: list[str] = field(default_factory=list)
    errors: list[VulnRuleImportError] = field(default_factory=list)

    @property
    def created(self) -> int:
        return len(self.created_ids)

    @property
    def updated(self) -> int:
        return len(self.updated_ids)

    @property
    def skipped(self) -> int:
        return len(self.skipped_ids)

    @property
    def error_count(self) -> int:
        return len(self.errors)


@dataclass(frozen=True, slots=True)
class VulnRuleExportPayload:
    filename: str
    media_type: str
    content: bytes


@dataclass(frozen=True, slots=True)
class VulnRuleIndexRebuildResult:
    indexed_rule_count: int
    index_synced_at: datetime | None
    index_in_sync: bool
    source_hash: str | None
    index_last_error: str | None


class VulnLibraryService:
    LEGACY_EXPOSURE_TAG = "legacy-exposure"
    HIGH_VALUE_TAG = "high-value"

    def __init__(
        self,
        rule_store: RuleStore,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self.rule_store = rule_store
        self.rule_path = Path(rule_store.rule_path)
        self.session_factory = session_factory
        self._last_index_error: str | None = None

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
        ruleset = self.rule_store.loader.maybe_reload()
        index_status = self._ensure_index_current(ruleset)
        if index_status.index_last_error is None:
            try:
                rule_ids, total = self._list_rule_ids_from_index(
                    page=page,
                    page_size=page_size,
                    keyword=keyword,
                    service=service,
                    severity=severity,
                    enabled=enabled,
                    catalog_view=catalog_view,
                )
                rules_by_id = {rule.rule_id: rule for rule in ruleset.rules}
                return [rules_by_id[rule_id] for rule_id in rule_ids if rule_id in rules_by_id], total
            except Exception as exc:  # pragma: no cover - defensive fallback
                self._last_index_error = str(exc)

        return self.rule_store.list_rules(
            page=page,
            page_size=page_size,
            keyword=keyword,
            service=service,
            severity=severity,
            enabled=enabled,
            catalog_view=catalog_view,
        )

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        self._ensure_index_current(self.rule_store.loader.maybe_reload())
        return self.rule_store.get_rule(rule_id)

    def create_rule(self, payload: dict[str, Any]) -> RuleDefinition:
        rule = self.rule_store.create_rule(payload)
        self._refresh_index_after_write()
        return rule

    def update_rule(self, rule_id: str, payload: dict[str, Any]) -> RuleDefinition:
        rule = self.rule_store.update_rule(rule_id, payload)
        self._refresh_index_after_write()
        return rule

    def delete_rule(self, rule_id: str) -> None:
        self.rule_store.delete_rule(rule_id)
        self._refresh_index_after_write()

    def bootstrap_rules(self, payload_rules: list[dict[str, Any]]) -> tuple[list[RuleDefinition], list[str]]:
        result = self.rule_store.bootstrap_rules(payload_rules)
        self._refresh_index_after_write()
        return result

    def batch_update_status(self, rule_ids: list[str], *, enabled: bool) -> RuleBatchStatusResult:
        result = self.rule_store.set_rules_enabled(rule_ids, enabled=enabled)
        self._refresh_index_after_write()
        return result

    def export_rules(
        self,
        *,
        format_name: str = "yaml",
        rule_ids: list[str] | None = None,
        keyword: str | None = None,
        service: str | None = None,
        severity: str | None = None,
        enabled: bool | None = None,
        catalog_view: str = "default",
    ) -> VulnRuleExportPayload:
        normalized_format = format_name.lower()
        if normalized_format not in {"yaml", "json"}:
            raise ValueError(f"不支持的导出格式：{format_name}")

        ruleset = self.rule_store.loader.maybe_reload()
        self._ensure_index_current(ruleset)
        selected_rules = self._resolve_export_rules(
            ruleset.rules,
            rule_ids=rule_ids or [],
            keyword=keyword,
            service=service,
            severity=severity,
            enabled=enabled,
            catalog_view=catalog_view,
        )
        payload = {"rules": [self.rule_store.serialize_rule(rule) for rule in selected_rules]}
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        if normalized_format == "json":
            content = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
            return VulnRuleExportPayload(
                filename=f"vuln_rules_export_{timestamp}.json",
                media_type="application/json",
                content=content,
            )

        content = yaml.safe_dump(
            payload,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        ).encode("utf-8")
        return VulnRuleExportPayload(
            filename=f"vuln_rules_export_{timestamp}.yaml",
            media_type="application/yaml",
            content=content,
        )

    def import_rules_from_bytes(
        self,
        *,
        content: bytes,
        filename: str | None,
        format_name: str = "auto",
        mode: str = "skip_existing",
        dry_run: bool = False,
    ) -> VulnRuleImportResult:
        normalized_mode = mode.lower()
        if normalized_mode not in {"skip_existing", "upsert"}:
            raise ValueError(f"不支持的导入模式：{mode}")

        detected_format = self._detect_import_format(content, filename, format_name)
        try:
            parsed = self._parse_import_content(content, detected_format)
            normalized_payload, total_in_file = self._normalize_import_payload(parsed)
            validated_rules = self.rule_store.loader.validate_payload(normalized_payload)
            imported_payloads = [self.rule_store.serialize_rule(rule) for rule in validated_rules]
        except Exception as exc:
            return VulnRuleImportResult(
                dry_run=dry_run,
                mode=normalized_mode,
                detected_format=detected_format,
                total_in_file=0,
                errors=[VulnRuleImportError(rule_id=None, message=str(exc))],
            )

        preview = self._preview_import(imported_payloads, mode=normalized_mode)
        if dry_run:
            return VulnRuleImportResult(
                dry_run=True,
                mode=normalized_mode,
                detected_format=detected_format,
                total_in_file=total_in_file,
                created_ids=preview.created_ids,
                updated_ids=preview.updated_ids,
                skipped_ids=preview.skipped_ids,
            )

        if preview.error_count:
            return preview

        write_result = self.rule_store.import_rules(imported_payloads, mode=normalized_mode)
        self._refresh_index_after_write()
        return VulnRuleImportResult(
            dry_run=False,
            mode=normalized_mode,
            detected_format=detected_format,
            total_in_file=total_in_file,
            created_ids=write_result.created_ids,
            updated_ids=write_result.updated_ids,
            skipped_ids=write_result.skipped_ids,
        )

    def upsert_rules(self, payload_rules: list[dict[str, Any]]) -> RuleImportWriteResult:
        write_result = self.rule_store.import_rules(payload_rules, mode="upsert")
        self._refresh_index_after_write()
        return write_result

    def rebuild_index(self) -> VulnRuleIndexRebuildResult:
        ruleset = self.rule_store.loader.maybe_reload()
        index_status = self._ensure_index_current(ruleset, force=True, raise_on_error=True)
        return VulnRuleIndexRebuildResult(
            indexed_rule_count=index_status.indexed_rule_count,
            index_synced_at=index_status.index_synced_at,
            index_in_sync=index_status.index_in_sync,
            source_hash=index_status.source_hash,
            index_last_error=index_status.index_last_error,
        )

    def get_status(self) -> VulnLibraryStatusPayload:
        ruleset = self.rule_store.loader.maybe_reload()
        index_status = self._ensure_index_current(ruleset)
        return VulnLibraryStatusPayload(
            path=ruleset.path,
            loaded_at=ruleset.loaded_at,
            source_mtime=ruleset.source_mtime,
            rule_count=len(ruleset.rules),
            last_error=ruleset.last_error,
            indexed_rule_count=index_status.indexed_rule_count,
            index_synced_at=index_status.index_synced_at,
            index_in_sync=index_status.index_in_sync,
            index_last_error=index_status.index_last_error,
        )

    def _refresh_index_after_write(self) -> None:
        try:
            self._ensure_index_current(self.rule_store.loader.load(force=True), force=True, raise_on_error=True)
        except Exception as exc:  # pragma: no cover - fallback for degraded index sync
            self._last_index_error = str(exc)

    def _ensure_index_current(
        self,
        ruleset: RuleSet,
        *,
        force: bool = False,
        raise_on_error: bool = False,
    ) -> VulnLibraryIndexStatus:
        expected_hash = self._calculate_source_hash(ruleset.rules)
        try:
            with self.session_factory() as db:
                current = self._read_index_status(db, expected_hash=expected_hash, expected_count=len(ruleset.rules))
                if force or not current.index_in_sync:
                    try:
                        current = self._rebuild_index_in_session(db, ruleset.rules, expected_hash)
                    except IntegrityError:
                        db.rollback()
                        recovered = self._read_index_status(db, expected_hash=expected_hash, expected_count=len(ruleset.rules))
                        if recovered.index_in_sync:
                            current = recovered
                        else:
                            raise
                self._last_index_error = None
                return current
        except Exception as exc:
            self._last_index_error = str(exc)
            if raise_on_error:
                raise
            return VulnLibraryIndexStatus(
                indexed_rule_count=0,
                index_synced_at=None,
                index_in_sync=False,
                source_hash=expected_hash,
                index_last_error=str(exc),
            )

    def _list_rule_ids_from_index(
        self,
        *,
        page: int,
        page_size: int,
        keyword: str | None,
        service: str | None,
        severity: str | None,
        enabled: bool | None,
        catalog_view: str,
    ) -> tuple[list[str], int]:
        with self.session_factory() as db:
            conditions = self._build_index_conditions(
                keyword=keyword,
                service=service,
                severity=severity,
                enabled=enabled,
                catalog_view=catalog_view,
            )
            total_stmt = select(func.count()).select_from(VulnRuleIndex)
            ids_stmt = select(VulnRuleIndex.rule_id)
            for condition in conditions:
                total_stmt = total_stmt.where(condition)
                ids_stmt = ids_stmt.where(condition)
            total = int(db.scalar(total_stmt) or 0)
            ordered_ids = db.execute(
                ids_stmt.order_by(
                    desc(self._catalog_priority_expression()),
                    desc(VulnRuleIndex.yaml_updated_at).nullslast(),
                    VulnRuleIndex.service.asc(),
                    VulnRuleIndex.name.asc(),
                    VulnRuleIndex.rule_id.asc(),
                )
                .offset(max(0, (page - 1) * page_size))
                .limit(page_size)
            ).scalars().all()
            return ordered_ids, total

    def _resolve_export_rules(
        self,
        rules: list[RuleDefinition],
        *,
        rule_ids: list[str],
        keyword: str | None,
        service: str | None,
        severity: str | None,
        enabled: bool | None,
        catalog_view: str,
    ) -> list[RuleDefinition]:
        rules_by_id = {rule.rule_id: rule for rule in rules}
        if rule_ids:
            return [rules_by_id[rule_id] for rule_id in rule_ids if rule_id in rules_by_id]

        index_status = self._ensure_index_current(self.rule_store.loader.maybe_reload())
        if index_status.index_last_error is None:
            try:
                with self.session_factory() as db:
                    ids_stmt = select(VulnRuleIndex.rule_id)
                    for condition in self._build_index_conditions(
                        keyword=keyword,
                        service=service,
                        severity=severity,
                        enabled=enabled,
                        catalog_view=catalog_view,
                    ):
                        ids_stmt = ids_stmt.where(condition)
                    ordered_ids = db.execute(
                        ids_stmt.order_by(
                            desc(self._catalog_priority_expression()),
                            desc(VulnRuleIndex.yaml_updated_at).nullslast(),
                            VulnRuleIndex.service.asc(),
                            VulnRuleIndex.name.asc(),
                            VulnRuleIndex.rule_id.asc(),
                        )
                    ).scalars().all()
                return [rules_by_id[rule_id] for rule_id in ordered_ids if rule_id in rules_by_id]
            except Exception as exc:  # pragma: no cover - defensive fallback
                self._last_index_error = str(exc)

        return self.rule_store.search_rules(
            keyword=keyword,
            service=service,
            severity=severity,
            enabled=enabled,
            catalog_view=catalog_view,
        )

    def _preview_import(self, imported_payloads: list[dict[str, Any]], *, mode: str) -> VulnRuleImportResult:
        existing_rules = self.rule_store.loader.load(force=True).rules
        existing_payloads = {rule.rule_id: self.rule_store.serialize_rule(rule) for rule in existing_rules}

        created_ids: list[str] = []
        updated_ids: list[str] = []
        skipped_ids: list[str] = []

        for payload in imported_payloads:
            rule_id = payload["id"]
            current_payload = existing_payloads.get(rule_id)
            if current_payload is None:
                created_ids.append(rule_id)
                continue

            if mode == "skip_existing":
                skipped_ids.append(rule_id)
                continue

            if self.rule_store._payloads_equal(current_payload, payload):
                skipped_ids.append(rule_id)
            else:
                updated_ids.append(rule_id)

        return VulnRuleImportResult(
            dry_run=True,
            mode=mode,
            detected_format="yaml",
            total_in_file=len(imported_payloads),
            created_ids=created_ids,
            updated_ids=updated_ids,
            skipped_ids=skipped_ids,
        )

    def _read_index_status(self, db: Session, *, expected_hash: str, expected_count: int) -> VulnLibraryIndexStatus:
        indexed_rule_count = int(db.scalar(select(func.count()).select_from(VulnRuleIndex)) or 0)
        index_synced_at = db.scalar(select(func.max(VulnRuleIndex.indexed_at)))
        source_hashes = db.execute(select(distinct(VulnRuleIndex.source_hash))).scalars().all()
        source_hash = source_hashes[0] if len(source_hashes) == 1 else None

        if expected_count == 0 and indexed_rule_count == 0:
            return VulnLibraryIndexStatus(
                indexed_rule_count=0,
                index_synced_at=index_synced_at,
                index_in_sync=True,
                source_hash=expected_hash,
                index_last_error=None,
            )

        index_in_sync = indexed_rule_count == expected_count and len(source_hashes) == 1 and source_hash == expected_hash
        return VulnLibraryIndexStatus(
            indexed_rule_count=indexed_rule_count,
            index_synced_at=index_synced_at,
            index_in_sync=index_in_sync,
            source_hash=source_hash,
            index_last_error=None,
        )

    def _rebuild_index_in_session(self, db: Session, rules: list[RuleDefinition], expected_hash: str) -> VulnLibraryIndexStatus:
        indexed_at = datetime.now(timezone.utc)
        # Serialize index rebuild writers to avoid concurrent delete-and-reinsert races.
        db.execute(text("LOCK TABLE vuln_rule_index IN EXCLUSIVE MODE"))
        db.execute(delete(VulnRuleIndex))
        db.flush()
        for rule in rules:
            db.add(
                VulnRuleIndex(
                    rule_id=rule.rule_id,
                    name=rule.name or rule.rule_id,
                    service=rule.service,
                    severity=RiskSeverity(rule.severity),
                    enabled=rule.enabled,
                    match_type=self._resolve_match_type(rule),
                    has_nse_match=rule.nse_conditions is not None,
                    nse_scripts=self._nse_scripts_from_rule(rule),
                    has_active_check=rule.active_check is not None,
                    active_detector=rule.active_check.detector if rule.active_check else None,
                    active_trigger=rule.active_check.trigger if rule.active_check else None,
                    cve_ids=rule.cve_ids,
                    tags=rule.tags,
                    yaml_created_at=self._parse_yaml_datetime(rule.created_at),
                    yaml_updated_at=self._parse_yaml_datetime(rule.updated_at),
                    source_hash=expected_hash,
                    indexed_at=indexed_at,
                )
            )
        db.commit()
        return VulnLibraryIndexStatus(
            indexed_rule_count=len(rules),
            index_synced_at=indexed_at if rules else None,
            index_in_sync=True,
            source_hash=expected_hash,
            index_last_error=None,
        )

    @staticmethod
    def _build_index_conditions(
        *,
        keyword: str | None,
        service: str | None,
        severity: str | None,
        enabled: bool | None,
        catalog_view: str,
    ) -> list[Any]:
        conditions: list[Any] = []
        keyword_value = (keyword or "").strip().lower()
        if keyword_value:
            like_value = f"%{keyword_value}%"
            conditions.append(
                func.lower(
                    func.concat(
                        VulnRuleIndex.rule_id,
                        " ",
                        VulnRuleIndex.name,
                        " ",
                        VulnRuleIndex.service,
                        " ",
                        func.coalesce(func.cast(VulnRuleIndex.cve_ids, String), ""),
                        " ",
                        func.coalesce(func.cast(VulnRuleIndex.tags, String), ""),
                    )
                ).like(like_value)
            )
        service_value = (service or "").strip().lower()
        if service_value:
            conditions.append(VulnRuleIndex.service == service_value)
        severity_value = (severity or "").strip().lower()
        if severity_value:
            conditions.append(VulnRuleIndex.severity == RiskSeverity(severity_value))
        if enabled is not None:
            conditions.append(VulnRuleIndex.enabled.is_(enabled))
        catalog_view_value = (catalog_view or "default").strip().lower() or "default"
        legacy_like = VulnLibraryService._tag_like_expression(VulnLibraryService.LEGACY_EXPOSURE_TAG)
        if catalog_view_value == "default":
            conditions.append(~legacy_like)
        elif catalog_view_value == "legacy":
            conditions.append(legacy_like)
        return conditions

    @staticmethod
    def _tag_like_expression(tag: str) -> Any:
        return func.cast(VulnRuleIndex.tags, String).like(f'%"{tag}"%')

    @classmethod
    def _catalog_priority_expression(cls) -> Any:
        return case((cls._tag_like_expression(cls.HIGH_VALUE_TAG), 1), else_=0)

    @staticmethod
    def _calculate_source_hash(rules: list[RuleDefinition]) -> str:
        payload = {
            "rules": [RuleStore.serialize_rule(rule) for rule in rules],
        }
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return sha256(encoded).hexdigest()

    @staticmethod
    def _resolve_match_type(rule: RuleDefinition) -> str:
        match_components = [
            bool(rule.version_constraint),
            bool(rule.config_conditions),
            bool(rule.nse_conditions),
            bool(rule.package_conditions),
        ]
        if sum(1 for item in match_components if item) > 1:
            return "mixed"
        if rule.nse_conditions:
            return "nse"
        if rule.package_conditions:
            return "package"
        if rule.config_conditions:
            return "config"
        return "version"

    @staticmethod
    def _nse_scripts_from_rule(rule: RuleDefinition) -> list[str]:
        if not rule.nse_conditions:
            return []
        return sorted({key.split(".", 1)[0] for key in rule.nse_conditions if isinstance(key, str) and key.strip()})

    @staticmethod
    def _parse_yaml_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @staticmethod
    def _detect_import_format(content: bytes, filename: str | None, format_name: str) -> str:
        normalized = (format_name or "auto").strip().lower()
        if normalized in {"yaml", "json"}:
            return normalized
        if filename:
            lowered = filename.lower()
            if lowered.endswith(".json"):
                return "json"
            if lowered.endswith(".yaml") or lowered.endswith(".yml"):
                return "yaml"
        stripped = content.lstrip()
        if stripped.startswith(b"{") or stripped.startswith(b"["):
            return "json"
        return "yaml"

    @staticmethod
    def _parse_import_content(content: bytes, detected_format: str) -> Any:
        text = content.decode("utf-8")
        if detected_format == "json":
            return json.loads(text)
        return yaml.safe_load(text)

    @staticmethod
    def _normalize_import_payload(parsed: Any) -> tuple[dict[str, Any], int]:
        if isinstance(parsed, list):
            normalized_rules = [VulnLibraryService._normalize_import_rule_payload(item) for item in parsed]
            return {"rules": normalized_rules}, len(normalized_rules)
        if isinstance(parsed, dict):
            if "rules" not in parsed:
                raise RuleLoadError("导入内容顶层必须包含 rules 列表")
            rules = parsed.get("rules")
            if not isinstance(rules, list):
                raise RuleLoadError("rules 必须是列表")
            normalized = dict(parsed)
            normalized["rules"] = [VulnLibraryService._normalize_import_rule_payload(item) for item in rules]
            return normalized, len(rules)
        raise RuleLoadError("导入内容必须是 YAML/JSON 的对象或列表")

    @staticmethod
    def _normalize_import_rule_payload(raw_rule: Any) -> dict[str, Any]:
        if not isinstance(raw_rule, dict):
            raise RuleLoadError("导入规则必须是对象结构")
        normalized = dict(raw_rule)
        remediation = normalized.get("remediation")
        if not isinstance(remediation, dict):
            return normalized

        automation_level = str(remediation.get("automation_level") or "").strip().lower()
        actions = remediation.get("actions")
        action_types = {
            str(item.get("action_type") or "").strip()
            for item in actions
            if isinstance(item, dict)
        } if isinstance(actions, list) else set()
        if automation_level != "callable" or {"manual_step", "rotate_credential"} & action_types:
            normalized.pop("remediation", None)
        return normalized
