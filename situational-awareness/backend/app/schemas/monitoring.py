from pydantic import BaseModel, Field


class PlatformCpuLiveMetrics(BaseModel):
    usage_percent: float = Field(ge=0, le=100)
    logical_cores: int | None = Field(default=None, ge=1)
    load_avg_1m: float | None = Field(default=None, ge=0)
    load_avg_5m: float | None = Field(default=None, ge=0)
    load_avg_15m: float | None = Field(default=None, ge=0)
    source: str


class PlatformMemoryLiveMetrics(BaseModel):
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    available_bytes: int = Field(ge=0)
    usage_percent: float = Field(ge=0, le=100)
    source: str


class PlatformDiskLiveMetrics(BaseModel):
    mount_path: str
    total_bytes: int = Field(ge=0)
    used_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)
    usage_percent: float = Field(ge=0, le=100)
    read_bytes_per_sec: float = Field(ge=0)
    write_bytes_per_sec: float = Field(ge=0)
    total_bytes_per_sec: float = Field(ge=0)
    io_source: str
    usage_source: str


class PlatformNetworkLiveMetrics(BaseModel):
    received_bytes_per_sec: float = Field(ge=0)
    transmitted_bytes_per_sec: float = Field(ge=0)
    total_bytes_per_sec: float = Field(ge=0)
    interface_count: int = Field(ge=0)
    source: str


class PlatformLiveMetricsRead(BaseModel):
    sampled_at: str
    sample_window_seconds: float = Field(ge=0)
    cpu: PlatformCpuLiveMetrics
    memory: PlatformMemoryLiveMetrics
    disk: PlatformDiskLiveMetrics
    network: PlatformNetworkLiveMetrics
