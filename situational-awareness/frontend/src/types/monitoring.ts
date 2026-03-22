export type PlatformCpuLiveMetrics = {
  usage_percent: number;
  logical_cores: number | null;
  load_avg_1m: number | null;
  load_avg_5m: number | null;
  load_avg_15m: number | null;
  source: string;
};

export type PlatformMemoryLiveMetrics = {
  total_bytes: number;
  used_bytes: number;
  available_bytes: number;
  usage_percent: number;
  source: string;
};

export type PlatformDiskLiveMetrics = {
  mount_path: string;
  total_bytes: number;
  used_bytes: number;
  free_bytes: number;
  usage_percent: number;
  read_bytes_per_sec: number;
  write_bytes_per_sec: number;
  total_bytes_per_sec: number;
  io_source: string;
  usage_source: string;
};

export type PlatformNetworkLiveMetrics = {
  received_bytes_per_sec: number;
  transmitted_bytes_per_sec: number;
  total_bytes_per_sec: number;
  interface_count: number;
  source: string;
};

export type PlatformLiveMetrics = {
  sampled_at: string;
  sample_window_seconds: number;
  cpu: PlatformCpuLiveMetrics;
  memory: PlatformMemoryLiveMetrics;
  disk: PlatformDiskLiveMetrics;
  network: PlatformNetworkLiveMetrics;
};
