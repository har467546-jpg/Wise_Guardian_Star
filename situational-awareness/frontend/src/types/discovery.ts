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
