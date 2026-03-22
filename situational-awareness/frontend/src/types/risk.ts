export type RiskFinding = {
  id: string;
  asset_id: string;
  asset_ip?: string;
  asset_hostname?: string | null;
  asset_port_id: string | null;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "ignored" | "fixed";
  title: string;
  description: string;
  evidence_json: Record<string, unknown>;
  detected_at: string;
  resolved_at: string | null;
};

export type RiskFindingListResponse = {
  items: RiskFinding[];
};

export type RiskFindingPageResponse = {
  items: RiskFinding[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type RiskRemediationAction = {
  action_type:
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
  title: string;
  params: Record<string, unknown>;
  requires_confirmation?: boolean | null;
  rollback_hint?: string | null;
  target_files: string[];
  target_services: string[];
  target_paths: string[];
  verify_items: string[];
};

export type RiskRemediationTemplate = {
  finding_id: string;
  rule_id: string;
  rule_name: string;
  asset_id: string;
  asset_port_id: string | null;
  service_name: string | null;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  automation_level: "callable";
  impact_summary: string | null;
  precheck_items: string[];
  verify_items: string[];
  rollback_notes: string[];
  actions: RiskRemediationAction[];
  source_refs: {
    yaml_rule_id: string | null;
    service: string | null;
    generated: boolean;
    references: string[];
  };
};

export type RiskBatchVerifyRequest = {
  asset_ids: string[];
};

export type RiskBatchVerifyResponse = {
  queued: number;
  task_ids: string[];
};
