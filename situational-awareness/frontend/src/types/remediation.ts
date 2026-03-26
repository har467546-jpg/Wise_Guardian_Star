export type RemediationAssetCard = {
  asset_id: string;
  ip: string;
  hostname: string | null;
  os_name: string | null;
  status: string;
  highest_severity: "low" | "medium" | "high" | "critical" | null;
  finding_count: number;
  effective_privilege: "root" | "sudo" | string | null;
  last_verified_at: string | null;
  last_collection_at: string | null;
  recommended_finding_id: string | null;
  runner_status: string | null;
  runner_install_status: string | null;
  active_session_id: string | null;
  active_session_status: string | null;
};

export type RemediationAssetList = {
  items: RemediationAssetCard[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type RemediationWorkspace = {
  asset: {
    id: string;
    ip: string;
    hostname: string | null;
    os_name: string | null;
    status: string;
  };
  authorization: {
    credential_bound: boolean;
    admin_authorized: boolean;
    last_verified_at: string | null;
    last_verification_status: string | null;
    effective_privilege: string | null;
    execution_ready: boolean;
    blocked_reasons: string[];
  };
  latest_collection: {
    status: string | null;
    collected_at: string | null;
    summary_json: Record<string, unknown>;
  } | null;
  findings: Array<{
    finding_id: string;
    rule_id: string | null;
    title: string;
    severity: "low" | "medium" | "high" | "critical";
    status: string;
    service_name: string | null;
    detected_at: string;
    has_template: boolean;
  }>;
  last_task_id: string | null;
};

export type RemediationPlanStep = {
  step_id: string;
  action_type: string;
  title: string;
  supported: boolean;
  execution_state: "ready" | "blocked";
  blocked_reason: string | null;
  generated_command: string | null;
  requires_confirmation: boolean;
  backup_plan: {
    kind: string;
    targets: string[];
    note: string | null;
  } | null;
  render_reason: string;
  target_files: string[];
  target_services: string[];
  target_paths: string[];
  fallback_strategy: string | null;
  fallback_candidates: string[];
  verify_items: string[];
  rollback_hint: string | null;
  risk_level: "low" | "medium" | "high";
  idempotent: boolean;
  dry_run_supported: boolean;
  rollback_supported: boolean;
  evidence_items: string[];
  requires_maintenance_window: boolean;
  adapter_id: string | null;
  adapter_version: string | null;
};

export type RemediationPlan = {
  asset_id: string;
  finding_id: string;
  rule_id: string;
  rule_name: string;
  service_name: string | null;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  automation_level: "callable";
  impact_summary: string | null;
  precheck_items: string[];
  verify_items: string[];
  rollback_notes: string[];
  execution_ready: boolean;
  blocked_reasons: string[];
  steps: RemediationPlanStep[];
  source_refs: Record<string, unknown>;
};

export type RemediationExecuteRequest = {
  steps: Array<{
    step_id: string;
  }>;
  execution_mode?: "dry_run" | "apply";
  change_ticket?: string | null;
  maintenance_window_id?: string | null;
};

export type RemediationExecuteResponse = {
  task_id: string;
  status: "pending" | "running" | "retry" | "success" | "failure" | "canceled";
  stream_url: string;
  execution_mode: "dry_run" | "apply";
};

export type RemediationTask = {
  task_id: string;
  status: "pending" | "running" | "retry" | "success" | "failure" | "canceled";
  progress: number;
  message: string | null;
  asset_id: string | null;
  finding_id: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  event_count: number;
  last_event_at: string | null;
  execution_boundary: "template_generated" | "runner_dispatch" | "dry_run_preview" | null;
  execution_mode: "dry_run" | "apply" | null;
  context: Record<string, unknown>;
  plan: Record<string, unknown>;
  execution: Record<string, unknown>;
  backups: Record<string, unknown>;
  reverify: Record<string, unknown>;
};

export type RemediationTaskEvidenceItem = {
  item_id: string;
  item_type: string;
  step_id: string | null;
  title: string;
  status: string;
  summary: string;
  payload_json: Record<string, unknown>;
  collected_at: string | null;
};

export type RemediationTaskEvidence = {
  task_id: string;
  execution_mode: "dry_run" | "apply" | null;
  execution_boundary: "template_generated" | "runner_dispatch" | "dry_run_preview" | null;
  generated_at: string | null;
  item_count: number;
  items: RemediationTaskEvidenceItem[];
  summary: Record<string, unknown>;
};

export type HostRunner = {
  runner_id: string | null;
  asset_id: string;
  status: string;
  install_status: string;
  version: string | null;
  platform_url: string | null;
  last_seen_at: string | null;
  last_error: string | null;
  runtime_kind: "python_script" | "shell_bundle" | "bundled_binary" | null;
  install_mode: "system" | "user" | null;
  service_mode: "systemd" | "sysvinit" | "crontab" | "detached" | null;
  detected_os: string | null;
  detected_arch: string | null;
  compatibility_issues: string[];
  capabilities_json: Record<string, unknown>;
};

export type RemediationAssetDetail = {
  asset: RemediationWorkspace["asset"];
  authorization: RemediationWorkspace["authorization"];
  latest_collection: RemediationWorkspace["latest_collection"];
  findings: RemediationWorkspace["findings"];
  runner: HostRunner;
  active_session_id: string | null;
  active_session_status: string | null;
  latest_task_id: string | null;
  can_install_runner: boolean;
  runner_install_blocked_reasons: string[];
};

export type HostRemediationPlanStep = {
  step_id: string;
  finding_id: string | null;
  finding_title: string | null;
  action_type: string;
  title: string;
  phase_code: string;
  phase_name: string;
  execution_state: "ready" | "blocked";
  blocked_reason: string | null;
  generated_command: string | null;
  backup_plan: RemediationPlanStep["backup_plan"];
  render_reason: string | null;
  service_name: string | null;
  target_files: string[];
  target_services: string[];
  target_paths: string[];
  fallback_strategy: string | null;
  fallback_candidates: string[];
  verify_items: string[];
  rollback_hint: string | null;
  risk_level: "low" | "medium" | "high";
  idempotent: boolean;
  dry_run_supported: boolean;
  rollback_supported: boolean;
  evidence_items: string[];
  requires_maintenance_window: boolean;
  adapter_id: string | null;
  adapter_version: string | null;
  blockers: RemediationBlocker[];
  related_findings: HostRemediationRelatedFinding[];
  related_rules: string[];
};

export type HostRemediationPhase = {
  phase_code: string;
  phase_name: string;
  order: number;
  summary: string;
  ready_count: number;
  blocked_count: number;
};

export type RemediationBlocker = {
  code: string;
  message: string;
  scope: "global" | "stage" | "step";
  blocking: "hard" | "soft";
  stage_code: string | null;
  step_id: string | null;
};

export type HostRemediationRelatedFinding = {
  finding_id: string;
  rule_id: string | null;
  title: string | null;
  severity: "low" | "medium" | "high" | "critical" | null;
  service_name: string | null;
};

export type HostRemediationStage = {
  stage_code: string;
  stage_name: string;
  order: number;
  summary: string;
  gate_status: "locked" | "ready" | "running" | "completed" | "blocked";
  ready_step_count: number;
  blocked_step_count: number;
  global_blockers: RemediationBlocker[];
  related_finding_ids: string[];
  related_rule_ids: string[];
  related_services: string[];
  steps: HostRemediationPlanStep[];
};

export type HostRemediationPlan = {
  execution_ready: boolean;
  plan_mode: "ready" | "partial" | "blocked" | "running" | "completed" | "failed";
  current_stage_code: string | null;
  blocked_reasons: string[];
  global_blockers: RemediationBlocker[];
  step_blockers: RemediationBlocker[];
  findings_covered_count: number;
  service_count: number;
  impacted_services: string[];
  phase_count: number;
  ready_stage_count: number;
  blocked_stage_count: number;
  ready_step_count: number;
  blocked_step_count: number;
  summary_text: string;
  impact_summary: string | null;
  precheck_items: string[];
  verify_items: string[];
  rollback_notes: string[];
  phases: HostRemediationPhase[];
  steps: HostRemediationPlanStep[];
  stages: HostRemediationStage[];
};

export type RemediationMessageAction = {
  action_id: string;
  label: string;
  intent: string;
};

export type RemediationMessage = {
  id: string;
  role: string;
  message_type: string;
  content: string;
  payload_json: Record<string, unknown>;
  created_at: string;
  actions: RemediationMessageAction[];
};

export type RemediationSession = {
  session_id: string;
  asset_id: string;
  status: string;
  asset: RemediationWorkspace["asset"];
  authorization: RemediationWorkspace["authorization"];
  latest_collection: RemediationWorkspace["latest_collection"];
  runner: HostRunner;
  findings: RemediationWorkspace["findings"];
  plan: HostRemediationPlan;
  messages: RemediationMessage[];
  last_task_id: string | null;
  approved_at: string | null;
  approved_by: string | null;
};

export type RemediationSessionCreateRequest = {
  note?: string | null;
};

export type RemediationSessionMessageCreateRequest = {
  intent: string;
  note?: string | null;
};

export type RemediationSessionApproveResponse = {
  session_id: string;
  task_id: string;
  status: "pending" | "running" | "retry" | "success" | "failure" | "canceled";
  stream_url: string;
  execution_mode: "dry_run" | "apply";
};

export type RemediationSessionApproveRequest = {
  stage_code?: string | null;
  execution_mode?: "dry_run" | "apply";
  change_ticket?: string | null;
  maintenance_window_id?: string | null;
};

export type HostRunnerInstallResponse = {
  task_id: string;
  status: "pending" | "running" | "retry" | "success" | "failure" | "canceled";
  runner_id: string | null;
  stream_url: string;
};

export type RemediationStreamEnvelope =
  | { type: "task"; task: { task_id: string; status: string; progress: number; message: string | null } }
  | { type: "event"; event: Record<string, unknown> }
  | { type: "complete"; status: string }
  | { type: "error"; message: string };

export type RemediationSessionStreamEnvelope =
  | { type: "session_snapshot"; session: RemediationSession }
  | { type: "ai_generation_started"; reason: string | null }
  | { type: "session_message_added"; message: RemediationMessage }
  | { type: "error"; message: string };
