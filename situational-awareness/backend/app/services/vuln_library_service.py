from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable

import yaml
from sqlalchemy import String, case, delete, desc, distinct, func, inspect as sa_inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql import text

from app.db.models.enums import FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding
from app.db.models.vuln_rule_governance import VulnRuleGovernance
from app.db.models.vuln_rule_index import VulnRuleIndex
from app.db.session import SessionLocal
from app.rules.rule_loader import RuleLoadError, RuleSet
from app.rules.rule_matcher import RuleDefinition
from app.rules.rule_store import RuleBatchStatusResult, RuleImportWriteResult, RuleStore
from app.services.finding_governance_service import recalculate_open_finding_priorities
from app.services.vuln_intel_service import (
    RuleIntelSummary,
    VulnIntelSyncResult,
    build_rule_intel_summary_map,
    get_vuln_intel_status,
    sync_vuln_intel,
)


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
    schema_ready: bool
    schema_error: str | None
    indexed_rule_count: int
    index_synced_at: datetime | None
    index_in_sync: bool
    index_last_error: str | None


@dataclass(frozen=True, slots=True)
class VulnLibrarySchemaStatus:
    ready: bool
    error: str | None = None


class VulnLibrarySchemaNotReadyError(RuntimeError):
    """Raised when the vuln intel/governance schema has not been migrated."""


@dataclass(frozen=True, slots=True)
class VulnRuleImportError:
    rule_id: str | None
    message: str


@dataclass(frozen=True, slots=True)
class RuleImportImpactChange:
    rule_id: str
    operation: str
    changed_fields: list[str] = field(default_factory=list)
    high_risk_flags: list[str] = field(default_factory=list)
    affected_open_findings: int = 0


@dataclass(frozen=True, slots=True)
class RuleImportImpactPreview:
    created_rule_ids: list[str] = field(default_factory=list)
    updated_rule_ids: list[str] = field(default_factory=list)
    skipped_rule_ids: list[str] = field(default_factory=list)
    total_affected_open_findings: int = 0
    high_risk_rule_ids: list[str] = field(default_factory=list)
    changes: list[RuleImportImpactChange] = field(default_factory=list)


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
    impact_preview: RuleImportImpactPreview | None = None

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


@dataclass(frozen=True, slots=True)
class RuleCatalogMetadata:
    rule_id: str
    intel_summary: RuleIntelSummary
    owner_id: str | None = None
    review_status: str = "published"
    change_ticket: str | None = None
    last_validated_at: datetime | None = None
    last_preview_at: datetime | None = None
    updated_at: datetime | None = None
    affected_open_finding_count: int = 0


class VulnLibraryService:
    LEGACY_EXPOSURE_TAG = "legacy-exposure"
    HIGH_VALUE_TAG = "high-value"
    _REQUIRED_SCHEMA_TABLES = (
        "vuln_cve_intel",
        "finding_governance",
        "finding_waivers",
        "vuln_rule_governance",
    )
    _REQUIRED_INDEX_COLUMNS = (
        "cve_count",
        "max_cvss",
        "max_epss",
        "kev_flag",
        "exploit_maturity",
        "intel_synced_at",
    )
    _TRACKED_IMPORT_FIELDS = (
        "name",
        "enabled",
        "service",
        "severity",
        "description",
        "match",
        "cve_ids",
        "cwe_ids",
        "affected_versions_text",
        "exploit_module",
        "preconditions",
        "verify_playbook",
        "mitigations",
        "remediation",
        "references",
        "tags",
        "active_check",
    )
    _SEVERITY_RANK = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

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

    def get_rule_catalog_metadata(self, rules: list[RuleDefinition]) -> dict[str, RuleCatalogMetadata]:
        if not rules:
            return {}
        with self.session_factory() as db:
            intel_summaries = build_rule_intel_summary_map(db, rules)
            governance_rows = self._load_rule_governance_map(db, [rule.rule_id for rule in rules])
            open_finding_counts = self._count_open_findings_by_rule(db)

        metadata: dict[str, RuleCatalogMetadata] = {}
        for rule in rules:
            governance = governance_rows.get(rule.rule_id)
            metadata[rule.rule_id] = RuleCatalogMetadata(
                rule_id=rule.rule_id,
                intel_summary=intel_summaries.get(rule.rule_id, RuleIntelSummary(cve_count=len(rule.cve_ids or []))),
                owner_id=governance.owner_id if governance is not None else None,
                review_status=governance.review_status if governance is not None else "published",
                change_ticket=governance.change_ticket if governance is not None else None,
                last_validated_at=governance.last_validated_at if governance is not None else None,
                last_preview_at=governance.last_preview_at if governance is not None else None,
                updated_at=governance.updated_at if governance is not None else None,
                affected_open_finding_count=open_finding_counts.get(rule.rule_id, 0),
            )
        return metadata

    def get_intel_status(self) -> VulnIntelSyncResult:
        rules = self.rule_store.loader.maybe_reload().rules
        with self.session_factory() as db:
            return get_vuln_intel_status(db, rules=rules)

    def sync_intel(self, progress_callback: Callable[[int, str, dict[str, Any]], None] | None = None) -> VulnIntelSyncResult:
        ruleset = self.rule_store.loader.maybe_reload()
        schema_status = self._get_schema_status()
        if not schema_status.ready:
            raise VulnLibrarySchemaNotReadyError(schema_status.error or self._default_schema_error_message())
        expected_hash = self._calculate_source_hash(ruleset.rules)
        with self.session_factory() as db:
            result = sync_vuln_intel(db, rules=ruleset.rules, progress_callback=progress_callback)
            if progress_callback is not None:
                progress_callback(94, "正在刷新漏洞规则索引", {"indexed_rules": len(ruleset.rules)})
            self._rebuild_index_in_session(db, ruleset.rules, expected_hash)
            if progress_callback is not None:
                progress_callback(97, "正在重算开放风险优先级", {"indexed_rules": len(ruleset.rules)})
            recalculate_open_finding_priorities(db, rules=ruleset.rules)
            return result

    def create_rule(self, payload: dict[str, Any]) -> RuleDefinition:
        rule = self.rule_store.create_rule(payload)
        self.touch_rule_governance([rule.rule_id], validated=True)
        self._refresh_index_after_write()
        return rule

    def update_rule(self, rule_id: str, payload: dict[str, Any]) -> RuleDefinition:
        rule = self.rule_store.update_rule(rule_id, payload)
        self.touch_rule_governance([rule.rule_id], validated=True)
        self._refresh_index_after_write()
        return rule

    def delete_rule(self, rule_id: str) -> None:
        self.rule_store.delete_rule(rule_id)
        self._delete_rule_governance([rule_id])
        self._refresh_index_after_write()

    def bootstrap_rules(self, payload_rules: list[dict[str, Any]]) -> tuple[list[RuleDefinition], list[str]]:
        result = self.rule_store.bootstrap_rules(payload_rules)
        self.touch_rule_governance([rule.rule_id for rule in result[0]], validated=True)
        self._refresh_index_after_write()
        return result

    def batch_update_status(self, rule_ids: list[str], *, enabled: bool) -> RuleBatchStatusResult:
        result = self.rule_store.set_rules_enabled(rule_ids, enabled=enabled)
        if result.updated_ids:
            self.touch_rule_governance(result.updated_ids, validated=True)
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
        preview = replace(
            preview,
            dry_run=dry_run,
            mode=normalized_mode,
            detected_format=detected_format,
            total_in_file=total_in_file,
        )
        if dry_run:
            impacted_rule_ids = preview.created_ids + preview.updated_ids
            if impacted_rule_ids:
                self.touch_rule_governance(impacted_rule_ids, previewed=True)
            return preview

        if preview.error_count:
            return preview

        write_result = self.rule_store.import_rules(imported_payloads, mode=normalized_mode)
        changed_rule_ids = write_result.created_ids + write_result.updated_ids
        if changed_rule_ids:
            self.touch_rule_governance(changed_rule_ids, previewed=True, validated=True)
        self._refresh_index_after_write()
        return VulnRuleImportResult(
            dry_run=False,
            mode=normalized_mode,
            detected_format=detected_format,
            total_in_file=total_in_file,
            created_ids=write_result.created_ids,
            updated_ids=write_result.updated_ids,
            skipped_ids=write_result.skipped_ids,
            impact_preview=preview.impact_preview,
        )

    def upsert_rules(self, payload_rules: list[dict[str, Any]]) -> RuleImportWriteResult:
        write_result = self.rule_store.import_rules(payload_rules, mode="upsert")
        changed_rule_ids = write_result.created_ids + write_result.updated_ids
        if changed_rule_ids:
            self.touch_rule_governance(changed_rule_ids, validated=True)
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
        schema_status = self._get_schema_status()
        if schema_status.ready:
            index_status = self._ensure_index_current(ruleset)
        else:
            index_status = VulnLibraryIndexStatus(
                indexed_rule_count=0,
                index_synced_at=None,
                index_in_sync=False,
                source_hash=self._calculate_source_hash(ruleset.rules),
                index_last_error=schema_status.error,
            )
        return VulnLibraryStatusPayload(
            path=ruleset.path,
            loaded_at=ruleset.loaded_at,
            source_mtime=ruleset.source_mtime,
            rule_count=len(ruleset.rules),
            last_error=ruleset.last_error,
            schema_ready=schema_status.ready,
            schema_error=schema_status.error,
            indexed_rule_count=index_status.indexed_rule_count,
            index_synced_at=index_status.index_synced_at,
            index_in_sync=index_status.index_in_sync,
            index_last_error=index_status.index_last_error,
        )

    def touch_rule_governance(
        self,
        rule_ids: list[str],
        *,
        previewed: bool = False,
        validated: bool = False,
    ) -> None:
        normalized_rule_ids = [item for item in dict.fromkeys(rule_ids) if item]
        if not normalized_rule_ids:
            return
        with self.session_factory() as db:
            now = datetime.now(timezone.utc)
            rows = self._ensure_rule_governance_rows(db, normalized_rule_ids)
            for row in rows.values():
                if previewed:
                    row.last_preview_at = now
                if validated:
                    row.last_validated_at = now
                row.updated_at = now
                db.add(row)
            db.commit()

    def _refresh_index_after_write(self) -> None:
        try:
            ruleset = self.rule_store.loader.load(force=True)
            self._ensure_index_current(ruleset, force=True, raise_on_error=True)
            with self.session_factory() as db:
                recalculate_open_finding_priorities(db, rules=ruleset.rules)
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

    def _get_schema_status(self) -> VulnLibrarySchemaStatus:
        try:
            with self.session_factory() as db:
                bind = db.get_bind()
                inspector = sa_inspect(bind)
                table_names = set(inspector.get_table_names())
                missing_tables = [name for name in self._REQUIRED_SCHEMA_TABLES if name not in table_names]
                missing_columns: list[str] = []
                if "vuln_rule_index" not in table_names:
                    missing_tables.append("vuln_rule_index")
                else:
                    columns = {item["name"] for item in inspector.get_columns("vuln_rule_index")}
                    missing_columns = [
                        f"vuln_rule_index.{name}"
                        for name in self._REQUIRED_INDEX_COLUMNS
                        if name not in columns
                    ]
                if missing_tables or missing_columns:
                    return VulnLibrarySchemaStatus(
                        ready=False,
                        error=self._format_schema_error_message(
                            missing_tables=missing_tables,
                            missing_columns=missing_columns,
                        ),
                    )
        except Exception as exc:  # pragma: no cover - defensive health reporting
            return VulnLibrarySchemaStatus(
                ready=False,
                error=f"{self._default_schema_error_message()}（结构检查失败：{exc}）",
            )
        return VulnLibrarySchemaStatus(ready=True, error=None)

    @staticmethod
    def _default_schema_error_message() -> str:
        return "数据库结构未升级，请先执行 alembic upgrade head"

    def _format_schema_error_message(
        self,
        *,
        missing_tables: list[str],
        missing_columns: list[str],
    ) -> str:
        details: list[str] = []
        if missing_tables:
            details.append(f"缺少表：{', '.join(missing_tables)}")
        if missing_columns:
            details.append(f"缺少列：{', '.join(missing_columns)}")
        if not details:
            return self._default_schema_error_message()
        return f"{self._default_schema_error_message()}（{'；'.join(details)}）"

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
                    desc(VulnRuleIndex.kev_flag),
                    desc(VulnRuleIndex.max_epss).nullslast(),
                    desc(VulnRuleIndex.max_cvss).nullslast(),
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
                            desc(VulnRuleIndex.kev_flag),
                            desc(VulnRuleIndex.max_epss).nullslast(),
                            desc(VulnRuleIndex.max_cvss).nullslast(),
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
        changes: list[RuleImportImpactChange] = []

        with self.session_factory() as db:
            open_finding_counts = self._count_open_findings_by_rule(db)

        for payload in imported_payloads:
            rule_id = payload["id"]
            current_payload = existing_payloads.get(rule_id)
            if current_payload is None:
                created_ids.append(rule_id)
                changes.append(
                    RuleImportImpactChange(
                        rule_id=rule_id,
                        operation="create",
                        changed_fields=["new_rule"],
                        affected_open_findings=0,
                    )
                )
                continue

            if mode == "skip_existing":
                skipped_ids.append(rule_id)
                continue

            if self.rule_store._payloads_equal(current_payload, payload):
                skipped_ids.append(rule_id)
                continue

            changed_fields = self._detect_changed_fields(current_payload, payload)
            high_risk_flags = self._detect_high_risk_flags(current_payload, payload)
            updated_ids.append(rule_id)
            changes.append(
                RuleImportImpactChange(
                    rule_id=rule_id,
                    operation="update",
                    changed_fields=changed_fields,
                    high_risk_flags=high_risk_flags,
                    affected_open_findings=open_finding_counts.get(rule_id, 0),
                )
            )

        impact_preview = RuleImportImpactPreview(
            created_rule_ids=created_ids,
            updated_rule_ids=updated_ids,
            skipped_rule_ids=skipped_ids,
            total_affected_open_findings=sum(item.affected_open_findings for item in changes),
            high_risk_rule_ids=[item.rule_id for item in changes if item.high_risk_flags],
            changes=changes,
        )

        return VulnRuleImportResult(
            dry_run=True,
            mode=mode,
            detected_format="yaml",
            total_in_file=len(imported_payloads),
            created_ids=created_ids,
            updated_ids=updated_ids,
            skipped_ids=skipped_ids,
            impact_preview=impact_preview,
        )

    def _load_rule_governance_map(self, db: Session, rule_ids: list[str]) -> dict[str, VulnRuleGovernance]:
        if not rule_ids:
            return {}
        rows = db.execute(
            select(VulnRuleGovernance).where(VulnRuleGovernance.rule_id.in_(rule_ids))
        ).scalars().all()
        return {row.rule_id: row for row in rows}

    def _ensure_rule_governance_rows(self, db: Session, rule_ids: list[str]) -> dict[str, VulnRuleGovernance]:
        governance_rows = self._load_rule_governance_map(db, rule_ids)
        for rule_id in rule_ids:
            if rule_id in governance_rows:
                continue
            row = VulnRuleGovernance(rule_id=rule_id, review_status="published")
            db.add(row)
            governance_rows[rule_id] = row
        db.flush()
        return governance_rows

    def _delete_rule_governance(self, rule_ids: list[str]) -> None:
        normalized_rule_ids = [item for item in dict.fromkeys(rule_ids) if item]
        if not normalized_rule_ids:
            return
        with self.session_factory() as db:
            db.execute(delete(VulnRuleGovernance).where(VulnRuleGovernance.rule_id.in_(normalized_rule_ids)))
            db.commit()

    def _count_open_findings_by_rule(self, db: Session) -> dict[str, int]:
        findings = db.execute(
            select(RiskFinding.evidence_json).where(RiskFinding.status == FindingStatus.OPEN)
        ).scalars().all()
        counts: dict[str, int] = {}
        for evidence in findings:
            if not isinstance(evidence, dict):
                continue
            rule_id = str(evidence.get("yaml_rule_id") or "").strip()
            if not rule_id:
                continue
            counts[rule_id] = counts.get(rule_id, 0) + 1
        return counts

    def _detect_changed_fields(self, current_payload: dict[str, Any], incoming_payload: dict[str, Any]) -> list[str]:
        changed_fields: list[str] = []
        for field_name in self._TRACKED_IMPORT_FIELDS:
            if self._stable_payload_value(current_payload.get(field_name)) != self._stable_payload_value(incoming_payload.get(field_name)):
                changed_fields.append(field_name)
        return changed_fields

    def _detect_high_risk_flags(self, current_payload: dict[str, Any], incoming_payload: dict[str, Any]) -> list[str]:
        flags: list[str] = []

        current_severity = str(current_payload.get("severity") or "").strip().lower()
        incoming_severity = str(incoming_payload.get("severity") or "").strip().lower()
        if current_severity and incoming_severity and self._SEVERITY_RANK.get(incoming_severity, 0) < self._SEVERITY_RANK.get(current_severity, 0):
            flags.append("severity_downgraded")

        current_cves = {str(item or "").strip().upper() for item in current_payload.get("cve_ids") or [] if str(item or "").strip()}
        incoming_cves = {str(item or "").strip().upper() for item in incoming_payload.get("cve_ids") or [] if str(item or "").strip()}
        if current_cves - incoming_cves:
            flags.append("cve_ids_removed")

        if current_payload.get("active_check") and not incoming_payload.get("active_check"):
            flags.append("active_check_removed")

        if current_payload.get("remediation") and not incoming_payload.get("remediation"):
            flags.append("remediation_removed")

        return flags

    @staticmethod
    def _stable_payload_value(value: Any) -> str:
        return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)

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
        intel_summaries = build_rule_intel_summary_map(db, rules)
        # Serialize index rebuild writers to avoid concurrent delete-and-reinsert races.
        if getattr(getattr(db, "bind", None), "dialect", None) and db.bind.dialect.name != "sqlite":
            db.execute(text("LOCK TABLE vuln_rule_index IN EXCLUSIVE MODE"))
        db.execute(delete(VulnRuleIndex))
        db.flush()
        for rule in rules:
            intel_summary = intel_summaries.get(rule.rule_id, RuleIntelSummary(cve_count=len(rule.cve_ids or [])))
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
                    cve_count=intel_summary.cve_count,
                    max_cvss=intel_summary.max_cvss,
                    max_epss=intel_summary.max_epss,
                    kev_flag=intel_summary.kev_flag,
                    exploit_maturity=intel_summary.exploit_maturity,
                    intel_synced_at=intel_summary.intel_synced_at,
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
            search_blob = (
                func.coalesce(VulnRuleIndex.rule_id, "")
                + " "
                + func.coalesce(VulnRuleIndex.name, "")
                + " "
                + func.coalesce(VulnRuleIndex.service, "")
                + " "
                + func.coalesce(func.cast(VulnRuleIndex.cve_ids, String), "")
                + " "
                + func.coalesce(func.cast(VulnRuleIndex.tags, String), "")
            )
            conditions.append(
                func.lower(search_blob).like(like_value)
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
