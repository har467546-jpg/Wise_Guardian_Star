from __future__ import annotations

HOSTNAME_COMMAND = "hostnamectl --static 2>/dev/null || hostname"
OS_COMMAND = "(cat /etc/os-release 2>/dev/null | head -n 20; lsb_release -d 2>/dev/null; cat /etc/issue 2>/dev/null | head -n 1)"
KERNEL_COMMAND = "uname -r && uname -v"
CPU_COMMAND = "lscpu 2>/dev/null || cat /proc/cpuinfo"
MEMORY_COMMAND = "free -b 2>/dev/null || cat /proc/meminfo"
SERVICES_COMMAND = "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null"
SERVICES_FALLBACK_COMMAND = "service --status-all 2>/dev/null"


def parse_hostname(raw: str | None) -> str | None:
    if not raw:
        return None
    line = raw.strip().splitlines()[0].strip()
    return line or None


def parse_os_release(raw: str | None) -> dict[str, str | None]:
    data: dict[str, str | None] = {
        "name": None,
        "version": None,
        "pretty_name": None,
    }
    if not raw:
        return data

    parsed: dict[str, str] = {}
    plain_lines: list[str] = []
    for line in raw.splitlines():
        normalized_line = line.strip()
        if not normalized_line:
            continue
        if "=" in normalized_line:
            key, value = normalized_line.split("=", 1)
            parsed[key.strip()] = value.strip().strip('"')
            continue
        if ":" in normalized_line:
            key, value = normalized_line.split(":", 1)
            parsed[key.strip()] = value.strip().strip('"')
            continue
        sanitized = (
            normalized_line
            .replace("\\l", "")
            .replace("\\n", "")
            .replace("\\r", "")
            .strip()
        )
        if sanitized:
            plain_lines.append(sanitized)

    data["name"] = parsed.get("NAME") or parsed.get("Distributor ID")
    data["version"] = parsed.get("VERSION_ID") or parsed.get("VERSION") or parsed.get("Release")
    data["pretty_name"] = parsed.get("PRETTY_NAME") or parsed.get("Description") or parsed.get("NAME")
    if (not data["pretty_name"]) and plain_lines:
        data["pretty_name"] = plain_lines[0]
    if data["pretty_name"]:
        inferred_name, inferred_version = _infer_name_and_version_from_pretty_name(data["pretty_name"])
        data["name"] = data["name"] or inferred_name
        data["version"] = data["version"] or inferred_version
    return data


def summarize_os_release(raw: str | None) -> str | None:
    os_info = parse_os_release(raw)
    return os_info.get("pretty_name") or os_info.get("name")


def parse_kernel(raw: str | None) -> dict[str, str | None]:
    data = {"release": None, "version": None}
    if not raw:
        return data

    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if lines:
        data["release"] = lines[0]
    if len(lines) > 1:
        data["version"] = lines[1]
    return data


def summarize_kernel(raw: str | None) -> str | None:
    kernel = parse_kernel(raw)
    return kernel.get("release") or kernel.get("version")


def parse_cpu(raw: str | None) -> dict[str, int | str | None]:
    data: dict[str, int | str | None] = {
        "model": None,
        "architecture": None,
        "cores": None,
        "threads": None,
    }
    if not raw:
        return data

    if "Architecture:" in raw or "Model name:" in raw:
        kv: dict[str, str] = {}
        for line in raw.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            kv[key.strip()] = value.strip()

        sockets = _to_int(kv.get("Socket(s)"))
        cores_per_socket = _to_int(kv.get("Core(s) per socket"))
        cpu_count = _to_int(kv.get("CPU(s)"))
        data["model"] = kv.get("Model name")
        data["architecture"] = kv.get("Architecture")
        data["threads"] = cpu_count
        if sockets and cores_per_socket:
            data["cores"] = sockets * cores_per_socket
        else:
            data["cores"] = cpu_count
        return data

    current: dict[str, str] = {}
    processors: list[dict[str, str]] = []
    for line in raw.splitlines():
        if not line.strip():
            if current:
                processors.append(current)
                current = {}
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current[key.strip()] = value.strip()
    if current:
        processors.append(current)

    if processors:
        first = processors[0]
        data["model"] = first.get("model name")
        data["architecture"] = first.get("vendor_id")
        data["threads"] = len(processors)
        cpu_cores = _to_int(first.get("cpu cores"))
        siblings = _to_int(first.get("siblings"))
        if cpu_cores:
            physical = len({entry.get("physical id", "0") for entry in processors})
            data["cores"] = cpu_cores * max(physical, 1)
        else:
            data["cores"] = siblings or len(processors)
    return data


def parse_memory(raw: str | None) -> dict[str, int | None]:
    data = {"total_bytes": None, "available_bytes": None}
    if not raw:
        return data

    if raw.lstrip().startswith("total") or "\nMem:" in raw:
        for line in raw.splitlines():
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "Mem:" and len(parts) >= 7:
                data["total_bytes"] = _to_int(parts[1])
                data["available_bytes"] = _to_int(parts[6])
                return data

    meminfo: dict[str, int] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parts = value.strip().split()
        if not parts:
            continue
        number = _to_int(parts[0])
        if number is None:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            number *= 1024
        meminfo[key.strip()] = number

    data["total_bytes"] = meminfo.get("MemTotal")
    data["available_bytes"] = meminfo.get("MemAvailable") or meminfo.get("MemFree")
    return data


def parse_running_services(raw: str | None, fallback: bool = False) -> list[dict[str, str | int | None]]:
    if not raw:
        return []
    if fallback:
        return _parse_service_status_all(raw)
    return _parse_systemctl_units(raw)


def _parse_systemctl_units(raw: str) -> list[dict[str, str | int | None]]:
    services: list[dict[str, str | int | None]] = []
    for line in raw.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        unit = parts[0]
        active = parts[2]
        sub_state = parts[3]
        services.append(
            {
                "name": unit.removesuffix(".service"),
                "state": sub_state,
                "enabled": None,
                "pid": None,
            }
        )
    return services


def _parse_service_status_all(raw: str) -> list[dict[str, str | int | None]]:
    services: list[dict[str, str | int | None]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        if len(line) < 5:
            continue
        marker = line[2]
        if marker != "+":
            continue
        name = line.split("]", 1)[1].strip()
        services.append({"name": name, "state": "running", "enabled": None, "pid": None})
    return services


def _to_int(raw: str | None) -> int | None:
    if raw is None:
        return None
    digits = "".join(ch for ch in raw if ch.isdigit())
    if not digits:
        return None
    return int(digits)


def _infer_name_and_version_from_pretty_name(raw: str) -> tuple[str | None, str | None]:
    cleaned = " ".join(raw.split()).strip()
    if not cleaned:
        return None, None
    tokens = cleaned.split()
    name_parts: list[str] = []
    version_parts: list[str] = []
    version_started = False
    for token in tokens:
        if not version_started and any(ch.isdigit() for ch in token):
            version_started = True
        if version_started:
            version_parts.append(token)
        else:
            name_parts.append(token)
    name = " ".join(name_parts).strip() or None
    version = " ".join(version_parts).strip() or None
    return name, version
