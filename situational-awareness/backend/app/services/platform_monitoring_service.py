from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from app.schemas.monitoring import (
    PlatformCpuLiveMetrics,
    PlatformDiskLiveMetrics,
    PlatformLiveMetricsRead,
    PlatformMemoryLiveMetrics,
    PlatformNetworkLiveMetrics,
)

_CPU_STAT_PATH = Path("/sys/fs/cgroup/cpu.stat")
_CPU_MAX_PATH = Path("/sys/fs/cgroup/cpu.max")
_CPUSET_PATHS = (
    Path("/sys/fs/cgroup/cpuset.cpus.effective"),
    Path("/sys/fs/cgroup/cpuset.cpus"),
)
_MEMORY_CURRENT_PATH = Path("/sys/fs/cgroup/memory.current")
_MEMORY_MAX_PATH = Path("/sys/fs/cgroup/memory.max")
_IO_STAT_PATH = Path("/sys/fs/cgroup/io.stat")
_PROC_STAT_PATH = Path("/proc/stat")
_PROC_MEMINFO_PATH = Path("/proc/meminfo")
_PROC_NET_DEV_PATH = Path("/proc/net/dev")


@dataclass(slots=True)
class _CpuSnapshot:
    usage_usec: int | None
    total_ticks: int | None
    idle_ticks: int | None
    logical_cores: int | None
    load_averages: tuple[float | None, float | None, float | None]
    source: str


@dataclass(slots=True)
class _MemorySnapshot:
    total_bytes: int
    used_bytes: int
    available_bytes: int
    source: str


@dataclass(slots=True)
class _DiskSnapshot:
    mount_path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    read_bytes: int | None
    write_bytes: int | None
    io_source: str
    usage_source: str


@dataclass(slots=True)
class _NetworkSnapshot:
    received_bytes: int
    transmitted_bytes: int
    interface_count: int
    source: str


@dataclass(slots=True)
class _RawPlatformSnapshot:
    captured_at: float
    captured_at_utc: datetime
    cpu: _CpuSnapshot
    memory: _MemorySnapshot
    disk: _DiskSnapshot
    network: _NetworkSnapshot


def _safe_read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _clamp_percent(value: float) -> float:
    return round(min(max(value, 0.0), 100.0), 2)


def _rate_per_second(current: int | None, previous: int | None, duration_seconds: float) -> float:
    if current is None or previous is None or duration_seconds <= 0:
        return 0.0
    return round(max(current - previous, 0) / duration_seconds, 2)


def _parse_cpuset_count(raw: str | None) -> int | None:
    if not raw:
        return None
    count = 0
    for token in raw.split(","):
        part = token.strip()
        if not part:
            continue
        if "-" in part:
            start_raw, end_raw = part.split("-", 1)
            try:
                start = int(start_raw)
                end = int(end_raw)
            except ValueError:
                continue
            if end >= start:
                count += end - start + 1
        else:
            try:
                int(part)
            except ValueError:
                continue
            count += 1
    return count or None


def _detect_logical_cores() -> int | None:
    for path in _CPUSET_PATHS:
        parsed = _parse_cpuset_count(_safe_read_text(path))
        if parsed:
            return parsed

    cpu_max_raw = _safe_read_text(_CPU_MAX_PATH)
    if cpu_max_raw:
        parts = cpu_max_raw.split()
        if len(parts) == 2 and parts[0] != "max":
            try:
                quota = int(parts[0])
                period = int(parts[1])
            except ValueError:
                quota = 0
                period = 0
            if quota > 0 and period > 0:
                return max(1, int(round(quota / period)))

    return os.cpu_count()


def _read_cpu_usage_usec() -> int | None:
    content = _safe_read_text(_CPU_STAT_PATH)
    if not content:
        return None
    for line in content.splitlines():
        if line.startswith("usage_usec "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def _read_proc_cpu_ticks() -> tuple[int, int] | None:
    content = _safe_read_text(_PROC_STAT_PATH)
    if not content:
        return None
    for line in content.splitlines():
        if not line.startswith("cpu "):
            continue
        parts = line.split()[1:]
        try:
            values = [int(item) for item in parts]
        except ValueError:
            return None
        if not values:
            return None
        total = sum(values)
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        return total, idle
    return None


def _read_load_averages() -> tuple[float | None, float | None, float | None]:
    try:
        load_1m, load_5m, load_15m = os.getloadavg()
        return round(load_1m, 2), round(load_5m, 2), round(load_15m, 2)
    except OSError:
        return None, None, None


def _read_memory_snapshot() -> _MemorySnapshot:
    cgroup_total_raw = _safe_read_text(_MEMORY_MAX_PATH)
    cgroup_used_raw = _safe_read_text(_MEMORY_CURRENT_PATH)
    if cgroup_total_raw and cgroup_total_raw != "max" and cgroup_used_raw:
        try:
            total_bytes = int(cgroup_total_raw)
            used_bytes = int(cgroup_used_raw)
        except ValueError:
            total_bytes = 0
            used_bytes = 0
        if total_bytes > 0:
            used_bytes = min(max(used_bytes, 0), total_bytes)
            available_bytes = max(total_bytes - used_bytes, 0)
            return _MemorySnapshot(
                total_bytes=total_bytes,
                used_bytes=used_bytes,
                available_bytes=available_bytes,
                source="container_cgroup",
            )

    total_bytes = 0
    available_bytes = 0
    content = _safe_read_text(_PROC_MEMINFO_PATH)
    if content:
        meminfo: dict[str, int] = {}
        for line in content.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            parts = value.strip().split()
            if not parts:
                continue
            try:
                amount = int(parts[0])
            except ValueError:
                continue
            if len(parts) > 1 and parts[1].lower() == "kb":
                amount *= 1024
            meminfo[key.strip()] = amount
        total_bytes = int(meminfo.get("MemTotal") or 0)
        available_bytes = int(meminfo.get("MemAvailable") or meminfo.get("MemFree") or 0)
    used_bytes = max(total_bytes - available_bytes, 0)
    return _MemorySnapshot(
        total_bytes=total_bytes,
        used_bytes=used_bytes,
        available_bytes=max(available_bytes, 0),
        source="host_proc",
    )


def _read_disk_io_bytes() -> tuple[int | None, int | None, str]:
    content = _safe_read_text(_IO_STAT_PATH)
    if content:
        read_bytes = 0
        write_bytes = 0
        matched = False
        for line in content.splitlines():
            parts = line.split()
            for token in parts[1:]:
                if token.startswith("rbytes="):
                    try:
                        read_bytes += int(token.split("=", 1)[1])
                        matched = True
                    except ValueError:
                        continue
                elif token.startswith("wbytes="):
                    try:
                        write_bytes += int(token.split("=", 1)[1])
                        matched = True
                    except ValueError:
                        continue
        if matched:
            return read_bytes, write_bytes, "container_cgroup"
    return None, None, "unavailable"


def _read_disk_snapshot() -> _DiskSnapshot:
    usage = shutil.disk_usage("/")
    read_bytes, write_bytes, io_source = _read_disk_io_bytes()
    return _DiskSnapshot(
        mount_path="/",
        total_bytes=usage.total,
        used_bytes=usage.used,
        free_bytes=usage.free,
        read_bytes=read_bytes,
        write_bytes=write_bytes,
        io_source=io_source,
        usage_source="filesystem",
    )


def _read_network_snapshot() -> _NetworkSnapshot:
    content = _safe_read_text(_PROC_NET_DEV_PATH)
    if not content:
        return _NetworkSnapshot(
            received_bytes=0,
            transmitted_bytes=0,
            interface_count=0,
            source="unavailable",
        )

    received_bytes = 0
    transmitted_bytes = 0
    interface_count = 0
    for line in content.splitlines()[2:]:
        if ":" not in line:
            continue
        interface_name, stats = line.split(":", 1)
        if interface_name.strip() == "lo":
            continue
        parts = stats.split()
        if len(parts) < 16:
            continue
        try:
            received_bytes += int(parts[0])
            transmitted_bytes += int(parts[8])
        except ValueError:
            continue
        interface_count += 1
    return _NetworkSnapshot(
        received_bytes=received_bytes,
        transmitted_bytes=transmitted_bytes,
        interface_count=interface_count,
        source="container_netns",
    )


def _capture_snapshot() -> _RawPlatformSnapshot:
    cpu_ticks = _read_proc_cpu_ticks()
    return _RawPlatformSnapshot(
        captured_at=time.monotonic(),
        captured_at_utc=datetime.now(timezone.utc),
        cpu=_CpuSnapshot(
            usage_usec=_read_cpu_usage_usec(),
            total_ticks=cpu_ticks[0] if cpu_ticks else None,
            idle_ticks=cpu_ticks[1] if cpu_ticks else None,
            logical_cores=_detect_logical_cores(),
            load_averages=_read_load_averages(),
            source="container_cgroup" if _read_cpu_usage_usec() is not None else "host_proc",
        ),
        memory=_read_memory_snapshot(),
        disk=_read_disk_snapshot(),
        network=_read_network_snapshot(),
    )


def _build_live_metrics(previous: _RawPlatformSnapshot, current: _RawPlatformSnapshot) -> PlatformLiveMetricsRead:
    duration_seconds = max(current.captured_at - previous.captured_at, 0.000001)

    cpu_usage_percent = 0.0
    if (
        current.cpu.usage_usec is not None
        and previous.cpu.usage_usec is not None
        and current.cpu.logical_cores
        and current.cpu.logical_cores > 0
    ):
        delta_usage_usec = max(current.cpu.usage_usec - previous.cpu.usage_usec, 0)
        cpu_usage_percent = _clamp_percent((delta_usage_usec / (duration_seconds * 1_000_000 * current.cpu.logical_cores)) * 100)
    elif (
        current.cpu.total_ticks is not None
        and previous.cpu.total_ticks is not None
        and current.cpu.idle_ticks is not None
        and previous.cpu.idle_ticks is not None
    ):
        delta_total = max(current.cpu.total_ticks - previous.cpu.total_ticks, 0)
        delta_idle = max(current.cpu.idle_ticks - previous.cpu.idle_ticks, 0)
        if delta_total > 0:
            cpu_usage_percent = _clamp_percent((1 - (delta_idle / delta_total)) * 100)

    memory_usage_percent = 0.0
    if current.memory.total_bytes > 0:
        memory_usage_percent = _clamp_percent((current.memory.used_bytes / current.memory.total_bytes) * 100)

    disk_usage_percent = 0.0
    if current.disk.total_bytes > 0:
        disk_usage_percent = _clamp_percent((current.disk.used_bytes / current.disk.total_bytes) * 100)

    disk_read_per_sec = _rate_per_second(current.disk.read_bytes, previous.disk.read_bytes, duration_seconds)
    disk_write_per_sec = _rate_per_second(current.disk.write_bytes, previous.disk.write_bytes, duration_seconds)
    network_rx_per_sec = _rate_per_second(
        current.network.received_bytes,
        previous.network.received_bytes,
        duration_seconds,
    )
    network_tx_per_sec = _rate_per_second(
        current.network.transmitted_bytes,
        previous.network.transmitted_bytes,
        duration_seconds,
    )

    return PlatformLiveMetricsRead(
        sampled_at=current.captured_at_utc.isoformat(),
        sample_window_seconds=round(duration_seconds, 3),
        cpu=PlatformCpuLiveMetrics(
            usage_percent=cpu_usage_percent,
            logical_cores=current.cpu.logical_cores,
            load_avg_1m=current.cpu.load_averages[0],
            load_avg_5m=current.cpu.load_averages[1],
            load_avg_15m=current.cpu.load_averages[2],
            source=current.cpu.source,
        ),
        memory=PlatformMemoryLiveMetrics(
            total_bytes=current.memory.total_bytes,
            used_bytes=current.memory.used_bytes,
            available_bytes=current.memory.available_bytes,
            usage_percent=memory_usage_percent,
            source=current.memory.source,
        ),
        disk=PlatformDiskLiveMetrics(
            mount_path=current.disk.mount_path,
            total_bytes=current.disk.total_bytes,
            used_bytes=current.disk.used_bytes,
            free_bytes=current.disk.free_bytes,
            usage_percent=disk_usage_percent,
            read_bytes_per_sec=disk_read_per_sec,
            write_bytes_per_sec=disk_write_per_sec,
            total_bytes_per_sec=round(disk_read_per_sec + disk_write_per_sec, 2),
            io_source=current.disk.io_source,
            usage_source=current.disk.usage_source,
        ),
        network=PlatformNetworkLiveMetrics(
            received_bytes_per_sec=network_rx_per_sec,
            transmitted_bytes_per_sec=network_tx_per_sec,
            total_bytes_per_sec=round(network_rx_per_sec + network_tx_per_sec, 2),
            interface_count=current.network.interface_count,
            source=current.network.source,
        ),
    )


class PlatformMonitoringService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._previous_snapshot: _RawPlatformSnapshot | None = None
        self._current_snapshot: _RawPlatformSnapshot | None = None

    def get_live_metrics(self) -> PlatformLiveMetricsRead:
        with self._lock:
            latest = _capture_snapshot()
            if self._current_snapshot is None:
                self._current_snapshot = latest
                self._previous_snapshot = latest
            else:
                self._previous_snapshot = self._current_snapshot
                self._current_snapshot = latest
            previous = self._previous_snapshot or latest
            current = self._current_snapshot or latest
        return _build_live_metrics(previous, current)


platform_monitoring_service = PlatformMonitoringService()
