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

export type VulnRuleCatalogView = "default" | "all" | "legacy";
