from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.common import ORMModel, PageMeta


class VulnRuleActiveCheck(BaseModel):
    detector: str = Field(min_length=1, max_length=64)
    trigger: str = Field(min_length=1, max_length=32)
    timeout_seconds: int = Field(default=5, ge=1, le=60)
    params: dict[str, Any] = Field(default_factory=dict)


class VulnRulePackageMatch(BaseModel):
    manager: str = Field(min_length=1, max_length=32)
    name: str = Field(min_length=1, max_length=128)
    compare: str = Field(min_length=1, max_length=32)
    fixed_versions: dict[str, dict[str, str]]


class VulnRuleRemediationAction(BaseModel):
    action_type: Literal[
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
    ]
    title: str = Field(min_length=1, max_length=255)
    params: dict[str, Any] = Field(default_factory=dict)
    requires_confirmation: bool | None = None
    rollback_hint: str | None = None
    target_files: list[str] = Field(default_factory=list)
    target_services: list[str] = Field(default_factory=list)
    target_paths: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)


class VulnRuleRemediation(BaseModel):
    summary: str = Field(min_length=1)
    automation_level: Literal["callable"]
    impact_summary: str | None = None
    precheck_items: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_notes: list[str] = Field(default_factory=list)
    actions: list[VulnRuleRemediationAction] = Field(min_length=1)
    references: list[str] = Field(default_factory=list)


class VulnRuleMatch(BaseModel):
    version: str | None = None
    config: dict[str, dict[str, Any]] | None = None
    nse: dict[str, dict[str, Any]] | None = None
    package: VulnRulePackageMatch | None = None

    @model_validator(mode="after")
    def validate_presence(self) -> "VulnRuleMatch":
        if not self.version and not self.config and not self.nse and not self.package:
            raise ValueError("请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配")
        return self


class VulnRuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    service: str = Field(min_length=1, max_length=128)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    description: str = Field(min_length=1)
    match: VulnRuleMatch
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    affected_versions_text: str | None = None
    exploit_module: str | None = None
    preconditions: list[str] = Field(default_factory=list)
    verify_playbook: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    remediation: VulnRuleRemediation | None = None
    references: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    active_check: VulnRuleActiveCheck | None = None


class VulnRuleCreate(VulnRuleBase):
    id: str = Field(min_length=1, max_length=128)


class VulnRuleUpdate(VulnRuleBase):
    pass


class VulnIntelSummaryRead(BaseModel):
    cve_count: int
    max_cvss: float | None = None
    max_epss: float | None = None
    kev_flag: bool
    exploit_maturity: str | None = None
    intel_synced_at: datetime | None = None
    stale: bool = False


class VulnRuleGovernanceRead(BaseModel):
    owner_id: str | None = None
    review_status: str
    change_ticket: str | None = None
    last_validated_at: datetime | None = None
    last_preview_at: datetime | None = None
    updated_at: datetime | None = None


class VulnRuleRead(ORMModel):
    id: str
    name: str
    enabled: bool
    service: str
    severity: str
    description: str
    match: VulnRuleMatch
    cve_ids: list[str]
    cwe_ids: list[str]
    affected_versions_text: str | None
    exploit_module: str | None
    preconditions: list[str]
    verify_playbook: list[str]
    mitigations: list[str]
    remediation: VulnRuleRemediation | None = None
    references: list[str]
    tags: list[str]
    active_check: VulnRuleActiveCheck | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    intel_summary: VulnIntelSummaryRead = Field(default_factory=lambda: VulnIntelSummaryRead(cve_count=0, kev_flag=False))
    governance: VulnRuleGovernanceRead = Field(default_factory=lambda: VulnRuleGovernanceRead(review_status="published"))
    affected_open_finding_count: int = 0


class VulnRuleListResponse(BaseModel):
    items: list[VulnRuleRead]
    meta: PageMeta


class RuleEngineStatusRead(BaseModel):
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


class VulnRuleImportErrorRead(BaseModel):
    rule_id: str | None
    message: str


class RuleImportImpactChangeRead(BaseModel):
    rule_id: str
    operation: str
    changed_fields: list[str] = Field(default_factory=list)
    high_risk_flags: list[str] = Field(default_factory=list)
    affected_open_findings: int = 0


class RuleImportImpactPreviewRead(BaseModel):
    created_rule_ids: list[str] = Field(default_factory=list)
    updated_rule_ids: list[str] = Field(default_factory=list)
    skipped_rule_ids: list[str] = Field(default_factory=list)
    total_affected_open_findings: int = 0
    high_risk_rule_ids: list[str] = Field(default_factory=list)
    changes: list[RuleImportImpactChangeRead] = Field(default_factory=list)


class VulnRuleImportResponse(BaseModel):
    dry_run: bool
    mode: Literal["skip_existing", "upsert"]
    detected_format: Literal["yaml", "json"]
    total_in_file: int
    created: int
    updated: int
    skipped: int
    error_count: int
    created_ids: list[str]
    updated_ids: list[str]
    skipped_ids: list[str]
    errors: list[VulnRuleImportErrorRead]
    impact_preview: RuleImportImpactPreviewRead | None = None


class VulnIntelStatusRead(BaseModel):
    total_cves: int
    tracked_rule_cves: int
    synced_cves: int
    stale: bool
    stale_count: int
    last_synced_at: datetime | None = None
    sources: list[str] = Field(default_factory=list)
    updated_cves: int = 0


class VulnRuleBatchStatusRequest(BaseModel):
    rule_ids: list[str] = Field(min_length=1)
    enabled: bool


class VulnRuleBatchStatusResponse(BaseModel):
    enabled: bool
    updated: int
    unchanged: int
    missing: int
    updated_ids: list[str]
    unchanged_ids: list[str]
    missing_ids: list[str]


class VulnRuleIndexRebuildResponse(BaseModel):
    indexed_rule_count: int
    index_synced_at: datetime | None
    index_in_sync: bool
    source_hash: str | None
    index_last_error: str | None
