export type ScannerZone = {
  id: string;
  name: string;
  zone_type: "office" | "dormitory" | "wireless" | "server" | "iot" | "custom";
  description: string | null;
  priority: number;
  enabled: boolean;
  cidrs_json: string[];
  default_scan_profile_json: Record<string, unknown>;
  allowed_data_source_types_json: string[];
  created_at: string;
  updated_at: string;
};

export type ScannerZoneWrite = {
  name: string;
  zone_type: ScannerZone["zone_type"];
  description?: string | null;
  priority: number;
  enabled: boolean;
  cidrs_json: string[];
  default_scan_profile_json: Record<string, unknown>;
  allowed_data_source_types_json: Array<"dhcp_lease" | "snmp_switch">;
};

export type ScannerNodeAssignment = {
  id: string;
  scanner_zone_id: string;
  asset_id: string;
  enabled: boolean;
  priority: number;
  visible_cidrs_json: string[];
  max_concurrent_jobs: number;
  created_at: string;
  updated_at: string;
};

export type ScannerNodeAssignmentWrite = {
  asset_id: string;
  enabled: boolean;
  priority: number;
  visible_cidrs_json: string[];
  max_concurrent_jobs: number;
};

export type CampusDataSource = {
  id: string;
  scanner_zone_id: string;
  asset_id: string | null;
  name: string;
  source_type: "dhcp_lease" | "snmp_switch";
  enabled: boolean;
  collection_interval_seconds: number;
  config_json: Record<string, unknown>;
  last_summary_json: Record<string, unknown>;
  last_collected_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

export type CampusDataSourceWrite = {
  scanner_zone_id: string;
  asset_id?: string | null;
  name: string;
  source_type: "dhcp_lease" | "snmp_switch";
  enabled: boolean;
  collection_interval_seconds: number;
  config_json: Record<string, unknown>;
  secret_plaintext?: string | null;
};

export type CampusDataSourceTestResult = {
  ok: boolean;
  source_type: "dhcp_lease" | "snmp_switch";
  message: string;
  summary_json: Record<string, unknown>;
};

export type DiscoveryJobExecution = {
  id: string;
  discovery_job_id: string;
  scanner_zone_id: string | null;
  asset_id: string | null;
  target_cidr: string;
  status: string;
  progress: number;
  task_run_id: string | null;
  summary_json: Record<string, unknown>;
  error_json: Record<string, unknown>;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
};

export type ScannerZoneListResponse = {
  items: ScannerZone[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type DiscoveryJobExecutionListResponse = {
  items: DiscoveryJobExecution[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};
