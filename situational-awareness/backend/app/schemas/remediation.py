from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.db.models.enums import RiskSeverity, TaskExecutionStatus
from app.schemas.common import PageMeta


class RemediationAssetCardRead(BaseModel):
    asset_id: str
    ip: str
    hostname: str | None = None
    os_name: str | None = None
    status: str
    highest_severity: RiskSeverity | None = None
    finding_count: int = 0
    effective_privilege: str | None = None
    last_verified_at: str | None = None
    last_collection_at: str | None = None
    recommended_finding_id: str | None = None
    runner_status: str | None = None
    runner_install_status: str | None = None
    active_session_id: str | None = None
    active_session_status: str | None = None


class RemediationAssetListRead(BaseModel):
    items: list[RemediationAssetCardRead] = Field(default_factory=list)
    meta: PageMeta


class RemediationWorkspaceAssetRead(BaseModel):
    id: str
    ip: str
    hostname: str | None = None
    os_name: str | None = None
    status: str


class RemediationWorkspaceAuthorizationRead(BaseModel):
    credential_bound: bool
    admin_authorized: bool
    last_verified_at: str | None = None
    last_verification_status: str | None = None
    effective_privilege: str | None = None
    execution_ready: bool
    blocked_reasons: list[str] = Field(default_factory=list)


class RemediationWorkspaceCollectionRead(BaseModel):
    status: str | None = None
    collected_at: str | None = None
    summary_json: dict[str, Any] = Field(default_factory=dict)


class RemediationWorkspaceFindingRead(BaseModel):
    finding_id: str
    rule_id: str | None = None
    title: str
    severity: RiskSeverity
    status: str
    service_name: str | None = None
    detected_at: datetime
    has_template: bool


class RemediationWorkspaceRead(BaseModel):
    asset: RemediationWorkspaceAssetRead
    authorization: RemediationWorkspaceAuthorizationRead
    latest_collection: RemediationWorkspaceCollectionRead | None = None
    findings: list[RemediationWorkspaceFindingRead] = Field(default_factory=list)
    last_task_id: str | None = None


class RemediationBackupPlanRead(BaseModel):
    kind: str
    targets: list[str] = Field(default_factory=list)
    note: str | None = None


class RemediationPlanStepRead(BaseModel):
    step_id: str
    action_type: str
    title: str
    supported: bool
    execution_state: Literal["ready", "blocked"]
    blocked_reason: str | None = None
    generated_command: str | None = None
    requires_confirmation: bool = True
    backup_plan: RemediationBackupPlanRead | None = None
    render_reason: str
    target_files: list[str] = Field(default_factory=list)
    target_services: list[str] = Field(default_factory=list)
    target_paths: list[str] = Field(default_factory=list)
    fallback_strategy: str | None = None
    fallback_candidates: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_hint: str | None = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    idempotent: bool = False
    dry_run_supported: bool = False
    rollback_supported: bool = False
    evidence_items: list[str] = Field(default_factory=list)
    requires_maintenance_window: bool = False
    adapter_id: str | None = None
    adapter_version: str | None = None


class RemediationPlanRead(BaseModel):
    asset_id: str
    finding_id: str
    rule_id: str
    rule_name: str
    service_name: str | None = None
    severity: RiskSeverity
    summary: str
    automation_level: Literal["callable"]
    impact_summary: str | None = None
    precheck_items: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_notes: list[str] = Field(default_factory=list)
    execution_ready: bool
    blocked_reasons: list[str] = Field(default_factory=list)
    steps: list[RemediationPlanStepRead] = Field(default_factory=list)
    source_refs: dict[str, Any] = Field(default_factory=dict)


class RemediationExecuteStepInput(BaseModel):
    step_id: str


class RemediationExecuteRequest(BaseModel):
    steps: list[RemediationExecuteStepInput] = Field(default_factory=list)
    execution_mode: Literal["dry_run", "apply"] = "dry_run"
    change_ticket: str | None = None
    maintenance_window_id: str | None = None


class RemediationExecuteResponse(BaseModel):
    task_id: str
    status: TaskExecutionStatus
    stream_url: str
    execution_mode: Literal["dry_run", "apply"] = "dry_run"


class RemediationTaskStepResultRead(BaseModel):
    step_id: str
    title: str
    status: str
    generated_command: str | None = None
    exit_status: int | None = None
    backup_paths: list[str] = Field(default_factory=list)
    output_tail: list[str] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


class RemediationTaskRead(BaseModel):
    task_id: str
    status: TaskExecutionStatus
    progress: int
    message: str | None = None
    asset_id: str | None = None
    finding_id: str | None = None
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    event_count: int = 0
    last_event_at: datetime | None = None
    execution_boundary: Literal["template_generated", "runner_dispatch", "dry_run_preview"] | None = None
    execution_mode: Literal["dry_run", "apply"] | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    plan: dict[str, Any] = Field(default_factory=dict)
    execution: dict[str, Any] = Field(default_factory=dict)
    backups: dict[str, Any] = Field(default_factory=dict)
    reverify: dict[str, Any] = Field(default_factory=dict)


class RemediationTaskEvidenceItemRead(BaseModel):
    item_id: str
    item_type: str
    step_id: str | None = None
    title: str
    status: str
    summary: str
    payload_json: dict[str, Any] = Field(default_factory=dict)
    collected_at: str | None = None


class RemediationTaskEvidenceRead(BaseModel):
    task_id: str
    execution_mode: Literal["dry_run", "apply"] | None = None
    execution_boundary: Literal["template_generated", "runner_dispatch", "dry_run_preview"] | None = None
    generated_at: str | None = None
    item_count: int = 0
    items: list[RemediationTaskEvidenceItemRead] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)


class HostRunnerRead(BaseModel):
    runner_id: str | None = None
    asset_id: str
    status: str
    install_status: str
    version: str | None = None
    platform_url: str | None = None
    last_seen_at: str | None = None
    last_error: str | None = None
    runtime_kind: Literal["python_script", "shell_bundle", "bundled_binary"] | None = None
    install_mode: Literal["system", "user"] | None = None
    service_mode: Literal["systemd", "sysvinit", "crontab", "detached"] | None = None
    detected_os: str | None = None
    detected_arch: str | None = None
    compatibility_issues: list[str] = Field(default_factory=list)
    capabilities_json: dict[str, Any] = Field(default_factory=dict)


class HostRunnerInstallRead(BaseModel):
    task_id: str
    status: TaskExecutionStatus
    runner_id: str | None = None
    stream_url: str


class RemediationSessionMessageActionRead(BaseModel):
    action_id: str
    label: str
    intent: str


class RemediationMessageRead(BaseModel):
    id: str
    role: str
    message_type: str
    content: str
    payload_json: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    actions: list[RemediationSessionMessageActionRead] = Field(default_factory=list)


class RemediationBlockerRead(BaseModel):
    code: str
    message: str
    scope: Literal["global", "stage", "step"]
    blocking: Literal["hard", "soft"] = "hard"
    stage_code: str | None = None
    step_id: str | None = None


class HostRemediationRelatedFindingRead(BaseModel):
    finding_id: str
    rule_id: str | None = None
    title: str | None = None
    severity: RiskSeverity | None = None
    service_name: str | None = None


class HostRemediationPlanStepRead(BaseModel):
    step_id: str
    finding_id: str | None = None
    finding_title: str | None = None
    action_type: str
    title: str
    phase_code: str
    phase_name: str
    execution_state: Literal["ready", "blocked"]
    blocked_reason: str | None = None
    generated_command: str | None = None
    backup_plan: RemediationBackupPlanRead | None = None
    render_reason: str | None = None
    service_name: str | None = None
    target_files: list[str] = Field(default_factory=list)
    target_services: list[str] = Field(default_factory=list)
    target_paths: list[str] = Field(default_factory=list)
    fallback_strategy: str | None = None
    fallback_candidates: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_hint: str | None = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    idempotent: bool = False
    dry_run_supported: bool = False
    rollback_supported: bool = False
    evidence_items: list[str] = Field(default_factory=list)
    requires_maintenance_window: bool = False
    adapter_id: str | None = None
    adapter_version: str | None = None
    blockers: list[RemediationBlockerRead] = Field(default_factory=list)
    related_findings: list[HostRemediationRelatedFindingRead] = Field(default_factory=list)
    related_rules: list[str] = Field(default_factory=list)


class HostRemediationPhaseRead(BaseModel):
    phase_code: str
    phase_name: str
    order: int
    summary: str
    ready_count: int = 0
    blocked_count: int = 0


class HostRemediationStageRead(BaseModel):
    stage_code: str
    stage_name: str
    order: int
    summary: str
    gate_status: Literal["locked", "ready", "running", "completed", "blocked"]
    ready_step_count: int = 0
    blocked_step_count: int = 0
    global_blockers: list[RemediationBlockerRead] = Field(default_factory=list)
    related_finding_ids: list[str] = Field(default_factory=list)
    related_rule_ids: list[str] = Field(default_factory=list)
    related_services: list[str] = Field(default_factory=list)
    steps: list[HostRemediationPlanStepRead] = Field(default_factory=list)


class HostRemediationPlanRead(BaseModel):
    execution_ready: bool
    plan_mode: Literal["ready", "partial", "blocked", "running", "completed", "failed"] = "blocked"
    current_stage_code: str | None = None
    blocked_reasons: list[str] = Field(default_factory=list)
    global_blockers: list[RemediationBlockerRead] = Field(default_factory=list)
    step_blockers: list[RemediationBlockerRead] = Field(default_factory=list)
    findings_covered_count: int = 0
    service_count: int = 0
    impacted_services: list[str] = Field(default_factory=list)
    phase_count: int = 0
    ready_stage_count: int = 0
    blocked_stage_count: int = 0
    ready_step_count: int = 0
    blocked_step_count: int = 0
    summary_text: str
    impact_summary: str | None = None
    precheck_items: list[str] = Field(default_factory=list)
    verify_items: list[str] = Field(default_factory=list)
    rollback_notes: list[str] = Field(default_factory=list)
    phases: list[HostRemediationPhaseRead] = Field(default_factory=list)
    steps: list[HostRemediationPlanStepRead] = Field(default_factory=list)
    stages: list[HostRemediationStageRead] = Field(default_factory=list)


class RemediationSessionFindingRead(BaseModel):
    finding_id: str
    rule_id: str | None = None
    title: str
    severity: RiskSeverity
    status: str
    service_name: str | None = None
    detected_at: datetime
    has_template: bool


class RemediationAssetDetailRead(BaseModel):
    asset: RemediationWorkspaceAssetRead
    authorization: RemediationWorkspaceAuthorizationRead
    latest_collection: RemediationWorkspaceCollectionRead | None = None
    findings: list[RemediationSessionFindingRead] = Field(default_factory=list)
    runner: HostRunnerRead
    active_session_id: str | None = None
    active_session_status: str | None = None
    latest_task_id: str | None = None
    can_install_runner: bool = False
    runner_install_blocked_reasons: list[str] = Field(default_factory=list)


class RemediationSessionRead(BaseModel):
    session_id: str
    asset_id: str
    status: str
    asset: RemediationWorkspaceAssetRead
    authorization: RemediationWorkspaceAuthorizationRead
    latest_collection: RemediationWorkspaceCollectionRead | None = None
    runner: HostRunnerRead
    findings: list[RemediationSessionFindingRead] = Field(default_factory=list)
    plan: HostRemediationPlanRead
    messages: list[RemediationMessageRead] = Field(default_factory=list)
    last_task_id: str | None = None
    approved_at: str | None = None
    approved_by: str | None = None


class RemediationSessionCreateRequest(BaseModel):
    note: str | None = None


class RemediationSessionMessageCreateRequest(BaseModel):
    intent: str
    note: str | None = None


class RemediationSessionApproveRequest(BaseModel):
    stage_code: str | None = None
    execution_mode: Literal["dry_run", "apply"] = "apply"
    change_ticket: str | None = None
    maintenance_window_id: str | None = None


class RemediationSessionApproveResponse(BaseModel):
    session_id: str
    task_id: str
    status: TaskExecutionStatus
    stream_url: str
    execution_mode: Literal["dry_run", "apply"] = "apply"


class RunnerRegisterRequest(BaseModel):
    registration_token: str
    asset_id: str
    version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    runtime_kind: Literal["python_script", "shell_bundle", "bundled_binary"] | None = None
    install_mode: Literal["system", "user"] | None = None
    service_mode: Literal["systemd", "sysvinit", "crontab", "detached"] | None = None
    host_facts: dict[str, Any] = Field(default_factory=dict)
    compatibility_issues: list[str] = Field(default_factory=list)


class RunnerRegisterResponse(BaseModel):
    runner_id: str
    runner_token: str
    poll_interval_seconds: int = 10


class RunnerHeartbeatRequest(BaseModel):
    version: str | None = None
    status: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    last_error: str | None = None
    runtime_kind: Literal["python_script", "shell_bundle", "bundled_binary"] | None = None
    install_mode: Literal["system", "user"] | None = None
    service_mode: Literal["systemd", "sysvinit", "crontab", "detached"] | None = None
    host_facts: dict[str, Any] = Field(default_factory=dict)
    compatibility_issues: list[str] = Field(default_factory=list)


class RunnerPollRequest(BaseModel):
    max_tasks: int = 1


class RunnerTaskStepRead(BaseModel):
    step_id: str
    title: str
    action_type: str
    generated_command: str | None = None
    execution_state: Literal["ready", "blocked"]
    blocked_reason: str | None = None
    backup_plan: RemediationBackupPlanRead | None = None
    risk_level: Literal["low", "medium", "high"] = "medium"
    idempotent: bool = False
    dry_run_supported: bool = False
    rollback_supported: bool = False
    evidence_items: list[str] = Field(default_factory=list)
    requires_maintenance_window: bool = False
    adapter_id: str | None = None
    adapter_version: str | None = None


class RunnerTaskAssignmentRead(BaseModel):
    task_id: str
    asset_id: str
    session_id: str | None = None
    task_type: Literal["remediation_execute"]
    summary: str
    execution_mode: Literal["apply"] = "apply"
    plan: HostRemediationPlanRead
    steps: list[RunnerTaskStepRead] = Field(default_factory=list)


class RunnerPollResponse(BaseModel):
    assignments: list[RunnerTaskAssignmentRead] = Field(default_factory=list)
    poll_interval_seconds: int = 10
    next_task_id: str | None = None
    next_summary: str | None = None
    next_execution_script_b64: str | None = None


class RunnerTaskEventRead(BaseModel):
    event_type: str
    level: str = "info"
    stage_code: str | None = None
    stage_name: str | None = None
    message: str | None = None
    progress: int | None = None
    payload_json: dict[str, Any] = Field(default_factory=dict)


class RunnerTaskEventBatch(BaseModel):
    events: list[RunnerTaskEventRead] = Field(default_factory=list)


class RunnerTaskStepResultRead(BaseModel):
    step_id: str
    title: str
    status: str
    generated_command: str | None = None
    exit_status: int | None = None
    backup_paths: list[str] = Field(default_factory=list)
    output_tail: list[str] = Field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None


class RunnerTaskCompleteRequest(BaseModel):
    status: Literal["success", "failure"]
    execution: dict[str, Any] = Field(default_factory=dict)
    backups: dict[str, Any] = Field(default_factory=dict)
    step_results: list[RunnerTaskStepResultRead] = Field(default_factory=list)
    message: str | None = None
