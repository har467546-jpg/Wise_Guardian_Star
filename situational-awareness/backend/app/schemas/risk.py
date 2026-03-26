from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.db.models.enums import FindingStatus, RiskSeverity
from app.schemas.common import ORMModel, PageMeta


class RiskFindingRead(ORMModel):
    id: str
    asset_id: str
    asset_port_id: str | None
    severity: RiskSeverity
    status: FindingStatus
    title: str
    description: str
    evidence_json: dict
    detected_at: datetime
    resolved_at: datetime | None
    priority_score: int | None = None
    priority_tier: str | None = None
    priority_reason: dict[str, Any] | None = None
    owner_id: str | None = None
    sla_due_at: datetime | None = None
    waiver_status: str = "none"


class RiskFindingListResponse(BaseModel):
    items: list[RiskFindingRead]


class FindingGovernanceRead(BaseModel):
    finding_id: str
    priority_score: int
    priority_tier: str
    priority_reason: dict[str, Any]
    owner_id: str | None = None
    sla_due_at: datetime | None = None
    status: str
    updated_at: datetime


class FindingWaiverRead(BaseModel):
    id: str
    finding_id: str
    waiver_type: Literal["false_positive", "accepted_risk", "temporary_exception"]
    reason: str
    expires_at: datetime | None = None
    approved_by: str | None = None
    status: str
    created_at: datetime
    updated_at: datetime


class RiskFindingMobileRead(BaseModel):
    id: str
    asset_id: str
    asset_ip: str
    asset_hostname: str | None
    asset_port_id: str | None
    severity: RiskSeverity
    status: FindingStatus
    title: str
    description: str
    evidence_json: dict
    detected_at: datetime
    resolved_at: datetime | None
    priority_score: int | None = None
    priority_tier: str | None = None
    priority_reason: dict[str, Any] | None = None
    owner_id: str | None = None
    sla_due_at: datetime | None = None
    waiver_status: str = "none"
    governance: FindingGovernanceRead | None = None
    waivers: list[FindingWaiverRead] = Field(default_factory=list)


class RiskFindingPageResponse(BaseModel):
    items: list[RiskFindingMobileRead]
    meta: PageMeta


class RiskVerifyRequest(BaseModel):
    pass


class RiskBatchVerifyRequest(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=200)


class RiskBatchVerifyResponse(BaseModel):
    queued: int
    task_ids: list[str]


class RiskFindingAssignRequest(BaseModel):
    owner_id: str | None = None


class RiskFindingWaiverCreateRequest(BaseModel):
    waiver_type: Literal["false_positive", "accepted_risk", "temporary_exception"]
    reason: str = Field(min_length=1, max_length=1000)
    expires_at: datetime | None = None


class RiskRemediationActionRead(BaseModel):
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
    title: str
    params: dict[str, Any]
    requires_confirmation: bool | None = None
    rollback_hint: str | None = None
    target_files: list[str] = Field(default_factory=list)
    target_services: list[str] = Field(default_factory=list)
    target_paths: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)


class RiskRemediationSourceRefsRead(BaseModel):
    yaml_rule_id: str | None = None
    service: str | None = None
    generated: bool
    references: list[str] = Field(default_factory=list)


class RiskRemediationTemplateRead(BaseModel):
    finding_id: str
    rule_id: str
    rule_name: str
    asset_id: str
    asset_port_id: str | None
    service_name: str | None
    severity: RiskSeverity
    summary: str
    automation_level: Literal["callable"]
    impact_summary: str | None = None
    precheck_items: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_notes: list[str] = Field(default_factory=list)
    actions: list[RiskRemediationActionRead]
    source_refs: RiskRemediationSourceRefsRead
