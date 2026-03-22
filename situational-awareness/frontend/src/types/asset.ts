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
  hostname: string | null;
  os_name: string | null;
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
