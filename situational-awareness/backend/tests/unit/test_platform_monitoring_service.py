from datetime import datetime, timezone

from app.services.platform_monitoring_service import (
    _CpuSnapshot,
    _DiskSnapshot,
    _MemorySnapshot,
    _NetworkSnapshot,
    _RawPlatformSnapshot,
    _build_live_metrics,
    _parse_cpuset_count,
)


def _make_snapshot(
    *,
    captured_at: float,
    cpu_usage_usec: int,
    rx_bytes: int,
    tx_bytes: int,
    read_bytes: int,
    write_bytes: int,
) -> _RawPlatformSnapshot:
    return _RawPlatformSnapshot(
        captured_at=captured_at,
        captured_at_utc=datetime(2026, 3, 19, tzinfo=timezone.utc),
        cpu=_CpuSnapshot(
            usage_usec=cpu_usage_usec,
            total_ticks=None,
            idle_ticks=None,
            logical_cores=2,
            load_averages=(0.5, 0.3, 0.2),
            source="container_cgroup",
        ),
        memory=_MemorySnapshot(
            total_bytes=8 * 1024 * 1024 * 1024,
            used_bytes=3 * 1024 * 1024 * 1024,
            available_bytes=5 * 1024 * 1024 * 1024,
            source="container_cgroup",
        ),
        disk=_DiskSnapshot(
            mount_path="/",
            total_bytes=1000,
            used_bytes=400,
            free_bytes=600,
            read_bytes=read_bytes,
            write_bytes=write_bytes,
            io_source="container_cgroup",
            usage_source="filesystem",
        ),
        network=_NetworkSnapshot(
            received_bytes=rx_bytes,
            transmitted_bytes=tx_bytes,
            interface_count=1,
            source="container_netns",
        ),
    )


def test_parse_cpuset_count_supports_ranges_and_singles() -> None:
    assert _parse_cpuset_count("0-3,5,7-8") == 7
    assert _parse_cpuset_count("2") == 1
    assert _parse_cpuset_count("") is None


def test_build_live_metrics_calculates_usage_and_rates() -> None:
    previous = _make_snapshot(
        captured_at=10.0,
        cpu_usage_usec=1_000_000,
        rx_bytes=1_000,
        tx_bytes=2_000,
        read_bytes=10_000,
        write_bytes=20_000,
    )
    current = _make_snapshot(
        captured_at=12.0,
        cpu_usage_usec=2_000_000,
        rx_bytes=3_000,
        tx_bytes=5_000,
        read_bytes=14_000,
        write_bytes=28_000,
    )

    metrics = _build_live_metrics(previous, current)

    assert metrics.cpu.usage_percent == 25.0
    assert metrics.memory.usage_percent == 37.5
    assert metrics.disk.usage_percent == 40.0
    assert metrics.disk.read_bytes_per_sec == 2000.0
    assert metrics.disk.write_bytes_per_sec == 4000.0
    assert metrics.network.received_bytes_per_sec == 1000.0
    assert metrics.network.transmitted_bytes_per_sec == 1500.0
