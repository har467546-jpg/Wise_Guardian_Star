from __future__ import annotations

from functools import lru_cache
from pathlib import Path

NMAP_SERVICES_CANDIDATES: tuple[Path, ...] = (
    Path("/usr/share/nmap/nmap-services"),
    Path("/usr/local/share/nmap/nmap-services"),
    Path("/opt/homebrew/share/nmap/nmap-services"),
)


@lru_cache(maxsize=16)
def load_top_tcp_ports(limit: int = 1000, services_path: str | None = None) -> tuple[int, ...]:
    normalized_limit = max(1, int(limit))
    candidates = (Path(services_path),) if services_path else NMAP_SERVICES_CANDIDATES

    for path in candidates:
        if not path.is_file():
            continue
        ports = _parse_nmap_services(path, normalized_limit)
        if ports:
            return ports
    return ()


def resolve_scan_ports(
    *,
    curated_ports: tuple[int, ...],
    high_backdoor_ports: tuple[int, ...],
    mode: str,
    top_ports_limit: int,
) -> tuple[int, ...]:
    normalized_mode = (mode or "top1000_plus_custom").strip().lower()
    if normalized_mode == "curated":
        return tuple(sorted(set(curated_ports) | set(high_backdoor_ports)))
    if normalized_mode == "full":
        return tuple(range(1, 65536))

    top_ports = load_top_tcp_ports(top_ports_limit)
    return tuple(sorted(set(curated_ports) | set(high_backdoor_ports) | set(top_ports)))


def _parse_nmap_services(path: Path, limit: int) -> tuple[int, ...]:
    scored_ports: list[tuple[float, int]] = []
    seen: set[int] = set()

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            parts = stripped.split()
            if len(parts) < 3:
                continue

            port_proto = parts[1].strip().lower()
            if not port_proto.endswith("/tcp"):
                continue

            try:
                port = int(port_proto.split("/", 1)[0])
                frequency = float(parts[2])
            except ValueError:
                continue

            if port < 1 or port > 65535 or port in seen:
                continue
            seen.add(port)
            scored_ports.append((frequency, port))

    scored_ports.sort(key=lambda item: (-item[0], item[1]))
    return tuple(port for _, port in scored_ports[:limit])
