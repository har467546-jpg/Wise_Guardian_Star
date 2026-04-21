export type AssetPort = {
  id: string;
  port: number;
  protocol: string;
  service_name: string | null;
  service_version: string | null;
  fingerprint_json: Record<string, unknown>;
  state: string;
  last_seen_at: string;
};

export type Asset = {
  id: string;
  ip: string;
  mac_address?: string | null;
  vendor?: string | null;
  hostname: string | null;
  os_name: string | null;
  network_zone?: string | null;
  network_vlan?: string | null;
  building?: string | null;
  department?: string | null;
  asset_category?: string | null;
  device_role?: string | null;
  device_assessment_json?: Record<string, unknown>;
  identity_source?: string | null;
  last_auth_time?: string | null;
  is_infrastructure_device?: boolean;
  is_iot?: boolean;
  is_virtual_network_component?: boolean;
  ipv6_addresses_json?: string[];
  status: "online" | "offline" | "collecting" | "unknown";
  is_local?: boolean;
  local_hint?: string | null;
  first_seen_at: string;
  last_seen_at: string;
  ports: AssetPort[];
};

export type AssetListResponse = {
  items: Asset[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type AssetBatchDeleteRequest = {
  asset_ids: string[];
};

export type AssetBatchDeleteResponse = {
  requested: number;
  deleted: number;
  missing_ids: string[];
};
