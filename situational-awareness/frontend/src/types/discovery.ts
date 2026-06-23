export type DiscoveryJob = {
  id: string;
  cidr: string;
  status: "pending" | "running" | "completed" | "failed";
  label: string | null;
  scanner_zone_id?: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  summary_json: Record<string, unknown>;
};

export type DiscoveryJobCreateResponse = {
  job: DiscoveryJob;
  task_id: string;
  status: "pending" | "reused";
  reused: boolean;
};

export type DiscoveryJobListResponse = {
  items: DiscoveryJob[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type DiscoverySchedulingOption = {
  recommended_zone_ids: string[];
  scanner_zones: Array<{
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
  }>;
  runner_assets: Array<{
    runner_id: string | null;
    asset_id: string;
    asset_ip: string | null;
    asset_hostname: string | null;
    status: string;
    install_status: string;
    version: string | null;
    scanner_zone_id: string | null;
    last_seen_at: string | null;
    detected_os: string | null;
    detected_arch: string | null;
    compatibility_issues: string[];
    capabilities_json: Record<string, unknown>;
  }>;
};
