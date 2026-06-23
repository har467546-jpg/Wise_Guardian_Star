export type VulnRuleMatch = {
  version?: string | null;
  config?: Record<string, Record<string, unknown>> | null;
  nse?: Record<string, Record<string, unknown>> | null;
  package?: {
    manager: string;
    name: string;
    compare: string;
    fixed_versions: Record<string, Record<string, string>>;
  } | null;
};

export type VulnRuleRemediationAutomationLevel = "callable";

export type VulnRuleRemediationActionType =
  | "upgrade_package"
  | "set_config"
  | "remove_config"
  | "restart_service"
  | "reload_service"
  | "disable_service"
  | "restrict_network"
  | "remove_exposure"
  | "permission_set"
  | "toggle_feature"
  | "set_bind_scope"
  | "set_access_policy"
  | "remove_path"
  | "set_path_permission";

export type VulnRuleRemediationAction = {
  action_type: VulnRuleRemediationActionType;
  title: string;
  params: Record<string, unknown>;
  requires_confirmation?: boolean | null;
  rollback_hint?: string | null;
  target_files: string[];
  target_services: string[];
  target_paths: string[];
  verify_items: string[];
};

export type VulnRuleRemediation = {
  summary: string;
  automation_level: VulnRuleRemediationAutomationLevel;
  impact_summary: string | null;
  precheck_items: string[];
  verify_items: string[];
  rollback_notes: string[];
  actions: VulnRuleRemediationAction[];
  references: string[];
};

export type VulnRuleActiveCheckDetector =
  | "vsftpd_smiley_backdoor"
  | "ftp_anonymous_login"
  | "tomcat_manager_default_creds"
  | "distccd_rce_probe"
  | "unrealircd_backdoor_probe"
  | "redis_unauth_info_probe"
  | "http_risky_methods_probe";

export type VulnRuleActiveCheckTrigger = "on_passive_match" | "on_service_present";

export type VulnRuleActiveCheck = {
  detector: VulnRuleActiveCheckDetector;
  trigger: VulnRuleActiveCheckTrigger;
  timeout_seconds: number;
  params: Record<string, unknown>;
};

export type VulnIntelSummary = {
  cve_count: number;
  max_cvss: number | null;
  max_epss: number | null;
  kev_flag: boolean;
  exploit_maturity: string | null;
  intel_synced_at: string | null;
  stale: boolean;
};

export type VulnRuleGovernance = {
  owner_id: string | null;
  review_status: string;
  change_ticket: string | null;
  last_validated_at: string | null;
  last_preview_at: string | null;
  updated_at: string | null;
};

export type VulnRule = {
  id: string;
  name: string;
  enabled: boolean;
  service: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  match: VulnRuleMatch;
  cve_ids: string[];
  cwe_ids: string[];
  affected_versions_text: string | null;
  exploit_module: string | null;
  preconditions: string[];
  verify_playbook: string[];
  mitigations: string[];
  remediation: VulnRuleRemediation | null;
  references: string[];
  tags: string[];
  active_check: VulnRuleActiveCheck | null;
  created_at: string | null;
  updated_at: string | null;
  intel_summary: VulnIntelSummary;
  governance: VulnRuleGovernance;
  affected_open_finding_count: number;
};

export type VulnRuleInput = {
  id?: string;
  name: string;
  enabled: boolean;
  service: string;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  match: VulnRuleMatch;
  cve_ids: string[];
  cwe_ids: string[];
  affected_versions_text?: string | null;
  exploit_module?: string | null;
  preconditions: string[];
  verify_playbook: string[];
  mitigations: string[];
  remediation?: VulnRuleRemediation | null;
  references: string[];
  tags: string[];
  active_check?: VulnRuleActiveCheck | null;
};

export type VulnRuleListResponse = {
  items: VulnRule[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type VulnLibraryStatus = {
  path: string;
  loaded_at: string | null;
  source_mtime: number | null;
  rule_count: number;
  last_error: string | null;
  schema_ready: boolean;
  schema_error: string | null;
  indexed_rule_count: number;
  index_synced_at: string | null;
  index_in_sync: boolean;
  index_last_error: string | null;
};

export type VulnRuleImportMode = "skip_existing" | "upsert";
export type VulnRuleFileFormat = "auto" | "yaml" | "json";
export type VulnRuleExportFormat = "yaml" | "json";

export type VulnRuleImportError = {
  rule_id: string | null;
  message: string;
};

export type RuleImportImpactChange = {
  rule_id: string;
  operation: string;
  changed_fields: string[];
  high_risk_flags: string[];
  affected_open_findings: number;
};

export type RuleImportImpactPreview = {
  created_rule_ids: string[];
  updated_rule_ids: string[];
  skipped_rule_ids: string[];
  total_affected_open_findings: number;
  high_risk_rule_ids: string[];
  changes: RuleImportImpactChange[];
};

export type VulnRuleImportResponse = {
  dry_run: boolean;
  mode: VulnRuleImportMode;
  detected_format: "yaml" | "json";
  total_in_file: number;
  created: number;
  updated: number;
  skipped: number;
  error_count: number;
  created_ids: string[];
  updated_ids: string[];
  skipped_ids: string[];
  errors: VulnRuleImportError[];
  impact_preview: RuleImportImpactPreview | null;
};

export type VulnRuleBatchStatusResponse = {
  enabled: boolean;
  updated: number;
  unchanged: number;
  missing: number;
  updated_ids: string[];
  unchanged_ids: string[];
  missing_ids: string[];
};

export type VulnRuleIndexRebuildResponse = {
  indexed_rule_count: number;
  index_synced_at: string | null;
  index_in_sync: boolean;
  source_hash: string | null;
  index_last_error: string | null;
};

export type VulnIntelStatus = {
  total_cves: number;
  tracked_rule_cves: number;
  synced_cves: number;
  stale: boolean;
  stale_count: number;
  last_synced_at: string | null;
  sources: string[];
  updated_cves: number;
  sync_status: "fresh" | "stale" | "queued" | "schema_not_ready" | "unknown" | string;
  sync_task_id: string | null;
  auto_sync_queued: boolean;
};

export type VulnRuleCatalogView = "default" | "all" | "legacy";
