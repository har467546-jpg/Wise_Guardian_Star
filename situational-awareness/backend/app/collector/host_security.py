from __future__ import annotations

from collections.abc import Iterable
import re
from typing import Any

from packaging.version import InvalidVersion, Version

from app.utils.versioning import compare_debian_package_versions, normalize_linux_distro, normalize_version_token

SUDOERS_COMMAND = (
    "sh -lc 'grep -R -Eiv \"^[[:space:]]*(#|$)\" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -n 200 || true'"
)
SUDO_LIST_COMMAND = "sudo -S -p '' -l"
SUDO_LOCAL_COMMAND = (
    "sh -lc 'path=$(command -v sudo 2>/dev/null || true); "
    "[ -n \"$path\" ] || exit 0; "
    "printf \"path=%s\\n\" \"$path\"; "
    "stat -c \"mode=%a|owner=%U|group=%G\" \"$path\" 2>/dev/null || true'"
)
SUID_SGID_COMMAND = (
    "sh -lc 'find / -xdev \\( -perm -4000 -o -perm -2000 \\) -type f 2>/dev/null | head -n 200'"
)
CAPABILITIES_COMMAND = (
    "sh -lc 'if command -v getcap >/dev/null 2>&1; then getcap -r / 2>/dev/null | head -n 200; fi'"
)
WORLD_WRITABLE_COMMAND = (
    "sh -lc 'find /etc /usr/local/bin /usr/local/sbin /opt /home -xdev \\( -type f -o -type d \\) -perm -0002 2>/dev/null | head -n 200'"
)
NMAP_LOCAL_COMMAND = (
    "sh -lc 'path=$(command -v nmap 2>/dev/null || true); "
    "[ -n \"$path\" ] || exit 0; "
    "printf \"path=%s\\n\" \"$path\"; "
    "stat -c \"mode=%a|owner=%U|group=%G\" \"$path\" 2>/dev/null || true; "
    "if find \"$path\" -maxdepth 0 -perm -4000 2>/dev/null | grep -q .; then printf \"suid=true\\n\"; else printf \"suid=false\\n\"; fi; "
    "caps=$(getcap \"$path\" 2>/dev/null || true); "
    "[ -n \"$caps\" ] && printf \"capability=%s\\n\" \"$caps\" || true'"
)
SCREEN_LOCAL_COMMAND = (
    "sh -lc 'path=$(command -v screen 2>/dev/null || true); "
    "[ -n \"$path\" ] || exit 0; "
    "printf \"path=%s\\n\" \"$path\"; "
    "stat -c \"mode=%a|owner=%U|group=%G\" \"$path\" 2>/dev/null || true; "
    "if find \"$path\" -maxdepth 0 -perm -4000 2>/dev/null | grep -q .; then printf \"suid=true\\n\"; else printf \"suid=false\\n\"; fi'"
)
DOCKER_LOCAL_COMMAND = (
    "sh -lc 'for sock in /var/run/docker.sock /run/docker.sock; do "
    "[ -S \"$sock\" ] || continue; "
    "stat_line=$(stat -c \"%a|%U|%G\" \"$sock\" 2>/dev/null || true); "
    "printf \"socket=%s|%s\\n\" \"$sock\" \"$stat_line\"; "
    "done; "
    "id -Gn 2>/dev/null | tr \" \" \"\\n\" | sed \"/^$/d;s/^/group=/\" | head -n 32'"
)
DOCKER_DAEMON_LOCAL_COMMAND = (
    "sh -lc '"
    "if [ -f /etc/docker/daemon.json ]; then "
    "printf \"source=daemon_json\\n\"; "
    "sed -n \"1,200p\" /etc/docker/daemon.json 2>/dev/null; "
    "fi; "
    "if command -v systemctl >/dev/null 2>&1; then "
    "printf \"source=systemd\\n\"; "
    "systemctl cat docker.service 2>/dev/null | sed -n \"1,200p\"; "
    "fi; "
    "printf \"source=ps\\n\"; "
    "ps -eo args 2>/dev/null | grep -E \"[d]ockerd([[:space:]]|$)\" | head -n 20 || true'"
)
SYSTEMD_LOCAL_COMMAND = (
    "sh -lc 'find /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system "
    "-maxdepth 2 -type f \\( -name \"*.service\" -o -name \"*.socket\" -o -name \"*.timer\" -o -name \"*.path\" \\) "
    "2>/dev/null | head -n 80 | while IFS= read -r unit; do "
    "[ -f \"$unit\" ] || continue; "
    "unit_writable=0; "
    "if find \"$unit\" -maxdepth 0 -perm /022 2>/dev/null | grep -q . || find \"$(dirname \"$unit\")\" -maxdepth 0 -perm /022 2>/dev/null | grep -q .; then unit_writable=1; fi; "
    "exec_target=$(grep -E \"^[[:space:]]*Exec(Start|Reload|Stop)=\" \"$unit\" 2>/dev/null | head -n 1 | sed -E \"s/^[[:space:]]*Exec(Start|Reload|Stop)=//\" | sed -E \"s/^[-@:+!]+//\" | awk \"{print \\$1}\"); "
    "exec_writable=0; "
    "if [ -n \"$exec_target\" ] && [ -e \"$exec_target\" ]; then "
    "if find \"$exec_target\" -maxdepth 0 -perm /022 2>/dev/null | grep -q . || find \"$(dirname \"$exec_target\")\" -maxdepth 0 -perm /022 2>/dev/null | grep -q .; then exec_writable=1; fi; "
    "fi; "
    "if [ \"$unit_writable\" -eq 1 ] || [ \"$exec_writable\" -eq 1 ]; then "
    "printf \"unit=%s|exec=%s|unit_writable=%s|exec_writable=%s\\n\" \"$unit\" \"$exec_target\" \"$unit_writable\" \"$exec_writable\"; "
    "fi; "
    "done'"
)
CRON_LOCAL_COMMAND = (
    "sh -lc 'for path in /etc/crontab /etc/anacrontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/anacron.d /var/spool/cron /var/spool/cron/crontabs; do "
    "[ -e \"$path\" ] || continue; "
    "if find \"$path\" -maxdepth 0 -perm /022 2>/dev/null | grep -q .; then printf \"path=%s|kind=direct\\n\" \"$path\"; fi; "
    "if [ -d \"$path\" ]; then find \"$path\" -maxdepth 2 \\( -type f -o -type d \\) -perm /022 2>/dev/null | head -n 20 | sed \"s#^#path=#;s#$#|kind=nested#\"; fi; "
    "done | head -n 80'"
)
LOGROTATE_LOCAL_COMMAND = (
    "sh -lc 'for file in /etc/logrotate.conf /etc/logrotate.d/*; do "
    "[ -f \"$file\" ] || continue; "
    "if grep -Eiq \"^[[:space:]]*(prerotate|postrotate|firstaction|lastaction)\\b\" \"$file\" 2>/dev/null; then "
    "printf \"action=%s\\n\" \"$file\"; "
    "if find \"$file\" -maxdepth 0 -perm /022 2>/dev/null | grep -q . || find \"$(dirname \"$file\")\" -maxdepth 0 -perm /022 2>/dev/null | grep -q .; then printf \"writable_action=%s\\n\" \"$file\"; fi; "
    "fi; "
    "done | head -n 60'"
)
POLKIT_LOCAL_COMMAND = (
    "sh -lc 'pkexec_path=$(command -v pkexec 2>/dev/null || true); "
    "[ -n \"$pkexec_path\" ] && printf \"pkexec_path=%s\\n\" \"$pkexec_path\"; "
    "[ -n \"$pkexec_path\" ] && if find \"$pkexec_path\" -maxdepth 0 -perm -4000 2>/dev/null | grep -q .; then "
    "printf \"pkexec_suid=true\\n\"; else printf \"pkexec_suid=false\\n\"; fi; "
    "path=$(command -v pkcheck 2>/dev/null || true); "
    "[ -n \"$path\" ] || path=\"$pkexec_path\"; "
    "[ -n \"$path\" ] && printf \"path=%s\\n\" \"$path\"; '"
)
POLKIT_RULES_LOCAL_COMMAND = (
    "sh -lc 'for path in /etc/polkit-1/rules.d /usr/share/polkit-1/rules.d /etc/polkit-1/localauthority /var/lib/polkit-1/localauthority; do "
    "[ -e \"$path\" ] || continue; "
    "find \"$path\" -maxdepth 2 -perm /022 2>/dev/null | head -n 20 | sed \"s#^#writable_path=#\"; "
    "done | head -n 40 || true'"
)

_SUDO_FIXED_VERSIONS: dict[str, dict[str, str]] = {
    "ubuntu": {
        "8.04": "1.8.32",
        "16.04": "1.8.16-0ubuntu1.10",
        "18.04": "1.8.21p2-3ubuntu1.4",
        "20.04": "1.8.31-1ubuntu1.2",
        "20.10": "1.9.1-1ubuntu1.1",
    },
    "debian": {
        "10": "1.8.27-1+deb10u3",
        "11": "1.9.5p2-3+deb11u1",
    },
}
_POLKIT_FIXED_VERSIONS: dict[str, dict[str, str]] = {
    "ubuntu": {
        "18.04": "0.105-20ubuntu0.18.04.6",
        "20.04": "0.105-26ubuntu1.2",
        "21.10": "0.105-31ubuntu0.1",
    },
    "debian": {
        "10": "0.105-25+deb10u1",
        "11": "0.105-31+deb11u1",
    },
}

_DANGEROUS_SUID_BASENAMES = {
    "bash",
    "busybox",
    "cp",
    "find",
    "less",
    "more",
    "nano",
    "nmap",
    "openssl",
    "perl",
    "php",
    "pkexec",
    "python",
    "ruby",
    "screen",
    "sh",
    "tar",
    "tcpdump",
    "vim",
    "wget",
    "zip",
}
_DANGEROUS_CAPABILITY_TOKENS = {
    "cap_dac_override",
    "cap_setgid",
    "cap_setuid",
    "cap_sys_admin",
}
_DANGEROUS_ENV_KEEP_TOKENS = {
    "BASH_ENV",
    "ENV",
    "IFS",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PATH",
    "PERL5LIB",
    "PYTHONPATH",
    "RUBYLIB",
}
_PRIVILEGED_RUNTIME_GROUPS = {"docker", "lxd", "libvirt", "libvirtd", "kvm"}
_PACKAGE_NAME_ALIASES: dict[str, tuple[str, ...]] = {
    "nmap": ("nmap",),
    "screen": ("screen",),
    "sudo": ("sudo",),
    "polkit": ("policykit-1", "polkit"),
}


def _non_empty_lines(raw: str | None) -> list[str]:
    return [line.strip() for line in (raw or "").splitlines() if line.strip()]


def _parse_boolean(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def _extract_package_version(packages: Iterable[dict[str, Any]] | None, package_key: str) -> str | None:
    metadata = _extract_package_metadata(packages, package_key)
    if not metadata:
        return None
    version = metadata.get("version")
    return str(version).strip() if isinstance(version, str) and version.strip() else None


def _extract_package_metadata(packages: Iterable[dict[str, Any]] | None, package_key: str) -> dict[str, Any] | None:
    aliases = _PACKAGE_NAME_ALIASES.get(package_key, ())
    if not aliases:
        return None

    best_match: tuple[int, dict[str, Any]] | None = None
    for item in packages or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        if not name:
            continue
        score = _score_package_name(name, aliases)
        if score is None:
            continue
        if best_match is None or score < best_match[0]:
            best_match = (score, item)
    return dict(best_match[1]) if best_match else None


def _score_package_name(name: str, aliases: tuple[str, ...]) -> int | None:
    for alias in aliases:
        if name == alias:
            return 0
    for alias in aliases:
        if name.startswith(f"{alias}-") or name.startswith(f"{alias}:"):
            return 1
    for alias in aliases:
        if alias in name:
            return 2
    return None


def _parse_prefixed_fields(raw: str | None) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for line in _non_empty_lines(raw):
        prefix, _, value = line.partition("=")
        if not prefix or not value:
            continue
        parsed.setdefault(prefix.strip(), []).append(value.strip())
    return parsed


def _line_enables_setenv(line: str) -> bool:
    upper = line.upper()
    return "SETENV" in upper and "!SETENV" not in upper and "NOSETENV" not in upper


def _extract_dangerous_env_keep_tokens(lines: Iterable[str]) -> list[str]:
    found: list[str] = []
    for line in lines:
        if "env_keep" not in line.lower() or "!env_keep" in line.lower():
            continue
        for match in re.finditer(r"env_keep\s*(?:[+\-:]?\s*=)\s*(.+)", line, flags=re.IGNORECASE):
            payload = match.group(1).strip()
            payload = payload.strip("\"'")
            tokens = [
                token.strip().strip("\"'").upper()
                for token in re.split(r"[\s,]+", payload)
                if token.strip().strip("\"'")
            ]
            for token in tokens:
                if token in _DANGEROUS_ENV_KEEP_TOKENS and token not in found:
                    found.append(token)
    return found[:20]


def _extract_prefixed_source_files(lines: Iterable[str]) -> list[str]:
    source_files: list[str] = []
    for line in lines:
        prefix = line.split(":", 1)[0].strip()
        normalized = prefix.lower()
        if (
            prefix.startswith("/")
            and ".bak.sa." not in normalized
            and not normalized.endswith(".bak.sa")
            and not normalized.endswith(".disabled.sa")
            and prefix not in source_files
        ):
            source_files.append(prefix)
    return source_files[:20]


def _extract_docker_hosts(content: str) -> list[str]:
    hosts: list[str] = []
    for host in re.findall(r"((?:tcp|unix|fd)://[^\s\"',]+)", content, flags=re.IGNORECASE):
        normalized = host.strip().rstrip(",")
        if normalized and normalized not in hosts:
            hosts.append(normalized)
    return hosts


def _docker_tlsverify_enabled(content: str) -> bool:
    if re.search(r"\"tlsverify\"\s*:\s*true", content, flags=re.IGNORECASE):
        return True
    if re.search(r"(?:^|\s)--tlsverify(?:[=\s]+(?:1|true|yes|on))?(?=\s|$)", content, flags=re.IGNORECASE):
        return True
    return False


def _package_context(
    packages: Iterable[dict[str, Any]] | None,
    package_key: str,
    os_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = _extract_package_metadata(packages, package_key) or {}
    raw_version = str(metadata.get("version") or "").strip() or None
    distro_name, distro_release = normalize_linux_distro(
        str((os_info or {}).get("name") or "") or None,
        str((os_info or {}).get("version") or "") or None,
    )
    return {
        "package_name": str(metadata.get("name") or "").strip().lower() or None,
        "package_version_raw": raw_version,
        "package_version_normalized": normalize_version_token(raw_version),
        "package_manager": str(metadata.get("manager") or "").strip().lower() or None,
        "package_arch": str(metadata.get("arch") or "").strip() or None,
        "distro_name": distro_name,
        "distro_release": distro_release,
    }


def _evaluate_distro_aware_exposure(
    *,
    package_manager: str | None,
    distro_name: str | None,
    distro_release: str | None,
    package_version_raw: str | None,
    fixed_versions: dict[str, dict[str, str]],
) -> dict[str, Any]:
    result = {
        "distro_aware_supported": package_manager == "dpkg" and distro_name in {"ubuntu", "debian"},
        "distro_aware_inconclusive": False,
        "distro_aware_exposed": False,
        "fixed_version": None,
    }
    if not result["distro_aware_supported"] or not package_version_raw or not distro_release or not distro_name:
        return result

    fixed_version = fixed_versions.get(distro_name, {}).get(distro_release)
    if not fixed_version:
        result["distro_aware_inconclusive"] = True
        return result

    result["fixed_version"] = fixed_version
    try:
        result["distro_aware_exposed"] = compare_debian_package_versions(package_version_raw, fixed_version) < 0
    except Exception:
        result["distro_aware_inconclusive"] = True
    return result


def parse_sudoers(raw: str | None) -> dict[str, Any]:
    lines = _non_empty_lines(raw)
    nopasswd_entries = [line for line in lines if "NOPASSWD" in line.upper()]
    full_privilege_entries = [
        line
        for line in lines
        if "ALL=(ALL" in line.upper() and line.rstrip().upper().endswith(" ALL")
    ]
    setenv_entries = [line for line in lines if _line_enables_setenv(line)]
    dangerous_env_keep_tokens = _extract_dangerous_env_keep_tokens(lines)
    return {
        "line_count": len(lines),
        "source_files": _extract_prefixed_source_files(lines),
        "nopasswd_present": bool(nopasswd_entries),
        "nopasswd_entries": nopasswd_entries[:20],
        "full_privilege_rule": bool(full_privilege_entries),
        "full_privilege_entries": full_privilege_entries[:20],
        "setenv_present": bool(setenv_entries),
        "setenv_entries": setenv_entries[:20],
        "dangerous_env_keep_present": bool(dangerous_env_keep_tokens),
        "dangerous_env_keep_tokens": dangerous_env_keep_tokens,
        "sample": lines[:40],
    }


def parse_sudo_list(raw: str | None) -> dict[str, Any]:
    lines = _non_empty_lines(raw)
    command_lines = [line for line in lines if line.startswith("(") or line.startswith("NOPASSWD:")]
    return {
        "line_count": len(lines),
        "command_count": len(command_lines),
        "sample": lines[:40],
    }


def parse_suid_sgid(raw: str | None) -> dict[str, Any]:
    entries = _non_empty_lines(raw)
    dangerous = []
    dangerous_by_binary: dict[str, bool] = {}
    for entry in entries:
        basename = entry.rsplit("/", 1)[-1].strip().lower()
        if basename in _DANGEROUS_SUID_BASENAMES:
            dangerous.append(entry)
            dangerous_by_binary[basename] = True
    return {
        "count": len(entries),
        "sample": entries[:40],
        "dangerous_count": len(dangerous),
        "dangerous_entries": dangerous[:20],
        "dangerous_suid_present": bool(dangerous),
        "dangerous_suid_by_binary": dangerous_by_binary,
    }


def parse_capabilities(raw: str | None) -> dict[str, Any]:
    entries = _non_empty_lines(raw)
    dangerous = []
    dangerous_by_binary: dict[str, bool] = {}
    for entry in entries:
        lowered = entry.lower()
        if any(token in lowered for token in _DANGEROUS_CAPABILITY_TOKENS):
            dangerous.append(entry)
            basename = entry.split(" ", 1)[0].rsplit("/", 1)[-1].strip().lower()
            if basename:
                dangerous_by_binary[basename] = True
    return {
        "count": len(entries),
        "sample": entries[:40],
        "dangerous_count": len(dangerous),
        "dangerous_entries": dangerous[:20],
        "dangerous_capability_present": bool(dangerous),
        "dangerous_capability_by_binary": dangerous_by_binary,
    }


def parse_sensitive_world_writable(raw: str | None) -> dict[str, Any]:
    entries = _non_empty_lines(raw)
    return {
        "count": len(entries),
        "sample": entries[:40],
        "sensitive_world_writable_present": bool(entries),
    }


def parse_nmap_local(raw: str | None, packages: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    fields = _parse_prefixed_fields(raw)
    package_version = _extract_package_version(packages, "nmap")
    capability_entries = fields.get("capability", [])
    path = fields.get("path", [None])[0]
    mode_owner_group = fields.get("mode", [None])[0]
    owner = fields.get("owner", [None])[0]
    group = fields.get("group", [None])[0]
    return {
        "installed": bool(path),
        "binary_path": path,
        "package_version": package_version,
        "normalized_version": normalize_version_token(package_version),
        "mode": mode_owner_group,
        "owner": owner,
        "group": group,
        "suid_present": _parse_boolean(fields.get("suid", ["false"])[0]),
        "dangerous_capability_present": bool(capability_entries),
        "capabilities": capability_entries[:10],
    }


def parse_screen_local(raw: str | None, packages: Iterable[dict[str, Any]] | None = None) -> dict[str, Any]:
    fields = _parse_prefixed_fields(raw)
    package_version = _extract_package_version(packages, "screen")
    path = fields.get("path", [None])[0]
    mode_owner_group = fields.get("mode", [None])[0]
    owner = fields.get("owner", [None])[0]
    group = fields.get("group", [None])[0]
    return {
        "installed": bool(path),
        "binary_path": path,
        "package_version": package_version,
        "normalized_version": normalize_version_token(package_version),
        "mode": mode_owner_group,
        "owner": owner,
        "group": group,
        "suid_present": _parse_boolean(fields.get("suid", ["false"])[0]),
    }


def parse_sudo_local(
    raw: str | None,
    *,
    packages: Iterable[dict[str, Any]] | None = None,
    os_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields = _parse_prefixed_fields(raw)
    package_context = _package_context(packages, "sudo", os_info)
    path = fields.get("path", [None])[0]
    return {
        "installed": bool(path) or bool(package_context.get("package_version_raw")),
        "binary_path": path,
        **package_context,
    }


def parse_polkit_local(
    raw: str | None,
    *,
    packages: Iterable[dict[str, Any]] | None = None,
    os_info: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fields = _parse_prefixed_fields(raw)
    package_context = _package_context(packages, "polkit", os_info)
    path = fields.get("path", [None])[0]
    pkexec_path = fields.get("pkexec_path", [None])[0]
    return {
        "installed": bool(path) or bool(pkexec_path) or bool(package_context.get("package_version_raw")),
        "binary_path": path,
        "pkexec_present": bool(pkexec_path),
        "pkexec_path": pkexec_path,
        "pkexec_suid_present": _parse_boolean(fields.get("pkexec_suid", ["false"])[0]),
        **package_context,
    }


def parse_docker_local(raw: str | None) -> dict[str, Any]:
    sockets: list[dict[str, str | None]] = []
    groups: list[str] = []
    for line in _non_empty_lines(raw):
        if line.startswith("socket="):
            payload = line.removeprefix("socket=")
            parts = payload.split("|")
            sockets.append(
                {
                    "path": parts[0] if len(parts) > 0 else None,
                    "mode": parts[1] if len(parts) > 1 else None,
                    "owner": parts[2] if len(parts) > 2 else None,
                    "group": parts[3] if len(parts) > 3 else None,
                }
            )
        elif line.startswith("group="):
            group = line.removeprefix("group=").strip().lower()
            if group:
                groups.append(group)

    privileged_groups = [group for group in groups if group in _PRIVILEGED_RUNTIME_GROUPS]
    return {
        "socket_present": bool(sockets),
        "socket_count": len(sockets),
        "sockets": sockets[:10],
        "group_memberships": groups[:20],
        "privileged_runtime_groups": privileged_groups[:10],
        "privileged_runtime_group_membership_present": bool(privileged_groups),
    }


def parse_docker_daemon_local(raw: str | None) -> dict[str, Any]:
    content = raw or ""
    daemon_hosts = list(dict.fromkeys(_extract_docker_hosts(content)))
    tcp_hosts = [host for host in daemon_hosts if host.lower().startswith("tcp://")]
    tlsverify_enabled = _docker_tlsverify_enabled(content)
    source_files: list[str] = []
    if "source=daemon_json" in content:
        source_files.append("/etc/docker/daemon.json")
    if "source=systemd" in content:
        source_files.append("/etc/systemd/system/docker.service")
    return {
        "source_files": source_files,
        "daemon_hosts": daemon_hosts[:20],
        "tcp_listener_present": bool(tcp_hosts),
        "tcp_listener_without_tlsverify": bool(tcp_hosts) and not tlsverify_enabled,
        "tlsverify_enabled": tlsverify_enabled,
    }


def parse_polkit_rules_local(raw: str | None) -> dict[str, Any]:
    writable_paths = [
        line.removeprefix("writable_path=").strip()
        for line in _non_empty_lines(raw)
        if line.startswith("writable_path=") and line.removeprefix("writable_path=").strip()
    ]
    deduped = list(dict.fromkeys(writable_paths))
    return {
        "writable_rules_path_present": bool(deduped),
        "writable_rules_paths": deduped[:20],
    }


def parse_systemd_local(raw: str | None) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for line in _non_empty_lines(raw):
        values: dict[str, str] = {}
        for segment in line.split("|"):
            key, _, value = segment.partition("=")
            if key and value:
                values[key.strip()] = value.strip()
        if not values:
            continue
        entries.append(
            {
                "unit": values.get("unit"),
                "exec": values.get("exec") or None,
                "unit_writable": _parse_boolean(values.get("unit_writable")),
                "exec_writable": _parse_boolean(values.get("exec_writable")),
            }
        )
    return {
        "writable_unit_chain_present": bool(entries),
        "writable_chain_count": len(entries),
        "sample": entries[:20],
    }


def parse_cron_local(raw: str | None) -> dict[str, Any]:
    entries: list[dict[str, str | None]] = []
    for line in _non_empty_lines(raw):
        values: dict[str, str] = {}
        for segment in line.split("|"):
            key, _, value = segment.partition("=")
            if key and value:
                values[key.strip()] = value.strip()
        path = values.get("path")
        if not path:
            continue
        entries.append({"path": path, "kind": values.get("kind")})
    return {
        "root_writable_job_chain_present": bool(entries),
        "writable_chain_count": len(entries),
        "sample": entries[:20],
    }


def parse_logrotate_local(raw: str | None) -> dict[str, Any]:
    action_files: list[str] = []
    writable_action_files: list[str] = []
    for line in _non_empty_lines(raw):
        if line.startswith("action="):
            action_files.append(line.removeprefix("action=").strip())
        elif line.startswith("writable_action="):
            writable_action_files.append(line.removeprefix("writable_action=").strip())
    return {
        "action_block_present": bool(action_files),
        "action_config_count": len(action_files),
        "action_configs": action_files[:20],
        "writable_script_chain_present": bool(writable_action_files),
        "writable_chain_count": len(writable_action_files),
        "writable_action_configs": writable_action_files[:20],
    }


def build_sudo_config(*, sudoers: dict[str, Any], sudo_list: dict[str, Any], sudo_local: dict[str, Any]) -> dict[str, Any]:
    config = {
        "installed": bool(sudo_local.get("installed")),
        "binary_path": sudo_local.get("binary_path"),
        "source_files": list(sudoers.get("source_files") or [])[:20],
        "package_name": sudo_local.get("package_name"),
        "package_version_raw": sudo_local.get("package_version_raw"),
        "package_version_normalized": sudo_local.get("package_version_normalized"),
        "package_manager": sudo_local.get("package_manager"),
        "distro_name": sudo_local.get("distro_name"),
        "distro_release": sudo_local.get("distro_release"),
        "nopasswd_present": bool(sudoers.get("nopasswd_present")),
        "full_privilege_rule": bool(sudoers.get("full_privilege_rule")),
        "setenv_present": bool(sudoers.get("setenv_present")),
        "dangerous_env_keep_present": bool(sudoers.get("dangerous_env_keep_present")),
        "dangerous_env_keep_tokens": list(sudoers.get("dangerous_env_keep_tokens") or [])[:20],
        "sudo_rule_count": int(sudoers.get("line_count") or 0),
        "sudo_list_command_count": int(sudo_list.get("command_count") or 0),
    }
    config.update(
        _evaluate_distro_aware_exposure(
            package_manager=config.get("package_manager"),
            distro_name=config.get("distro_name"),
            distro_release=config.get("distro_release"),
            package_version_raw=config.get("package_version_raw"),
            fixed_versions=_SUDO_FIXED_VERSIONS,
        )
    )
    return config


def build_polkit_config(*, polkit_local: dict[str, Any], polkit_rules_local: dict[str, Any] | None = None) -> dict[str, Any]:
    polkit_rules_local = polkit_rules_local or {}
    config = {
        "installed": bool(polkit_local.get("installed")),
        "binary_path": polkit_local.get("binary_path"),
        "rules_paths": list(polkit_rules_local.get("writable_rules_paths") or [])[:20],
        "package_name": polkit_local.get("package_name"),
        "package_version_raw": polkit_local.get("package_version_raw"),
        "package_version_normalized": polkit_local.get("package_version_normalized"),
        "package_manager": polkit_local.get("package_manager"),
        "distro_name": polkit_local.get("distro_name"),
        "distro_release": polkit_local.get("distro_release"),
        "pkexec_present": bool(polkit_local.get("pkexec_present")),
        "pkexec_path": polkit_local.get("pkexec_path"),
        "pkexec_suid_present": bool(polkit_local.get("pkexec_suid_present")),
        "writable_rules_path_present": bool(polkit_rules_local.get("writable_rules_path_present")),
        "writable_rules_paths": list(polkit_rules_local.get("writable_rules_paths") or [])[:20],
    }
    config.update(
        _evaluate_distro_aware_exposure(
            package_manager=config.get("package_manager"),
            distro_name=config.get("distro_name"),
            distro_release=config.get("distro_release"),
            package_version_raw=config.get("package_version_raw"),
            fixed_versions=_POLKIT_FIXED_VERSIONS,
        )
    )
    config["distro_aware_exposed"] = bool(
        config.get("distro_aware_exposed") and config.get("pkexec_present") and config.get("pkexec_suid_present")
    )
    return config


def build_nmap_config(*, nmap_local: dict[str, Any]) -> dict[str, Any]:
    normalized_version = normalize_version_token(nmap_local.get("package_version"))
    suid_present = bool(nmap_local.get("suid_present"))
    capability_present = bool(nmap_local.get("dangerous_capability_present"))
    legacy_exposed = False
    if normalized_version and suid_present:
        try:
            legacy_exposed = Version(normalized_version) < Version("5.21")
        except InvalidVersion:
            legacy_exposed = False
    return {
        "installed": bool(nmap_local.get("installed")),
        "binary_path": nmap_local.get("binary_path"),
        "package_version": nmap_local.get("package_version"),
        "normalized_version": normalized_version,
        "suid_present": suid_present,
        "dangerous_capability_present": capability_present,
        "legacy_interactive_privesc_exposed": legacy_exposed,
    }


def build_screen_config(*, screen_local: dict[str, Any]) -> dict[str, Any]:
    normalized_version = normalize_version_token(screen_local.get("package_version"))
    suid_present = bool(screen_local.get("suid_present"))
    return {
        "installed": bool(screen_local.get("installed")),
        "binary_path": screen_local.get("binary_path"),
        "package_version": screen_local.get("package_version"),
        "normalized_version": normalized_version,
        "suid_present": suid_present,
        "legacy_setuid_privesc_exposed": normalized_version == "4.5.0" and suid_present,
    }


def build_docker_config(
    *,
    docker_local: dict[str, Any],
    docker_daemon_local: dict[str, Any] | None = None,
) -> dict[str, Any]:
    docker_daemon_local = docker_daemon_local or {}
    return {
        "source_files": list(docker_daemon_local.get("source_files") or [])[:20],
        "socket_present": bool(docker_local.get("socket_present")),
        "socket_count": int(docker_local.get("socket_count") or 0),
        "privileged_runtime_group_membership_present": bool(
            docker_local.get("privileged_runtime_group_membership_present")
        ),
        "privileged_runtime_groups": list(docker_local.get("privileged_runtime_groups") or [])[:10],
        "tcp_listener_present": bool(docker_daemon_local.get("tcp_listener_present")),
        "tcp_listener_without_tlsverify": bool(docker_daemon_local.get("tcp_listener_without_tlsverify")),
        "daemon_hosts": list(docker_daemon_local.get("daemon_hosts") or [])[:20],
        "tlsverify_enabled": bool(docker_daemon_local.get("tlsverify_enabled")),
    }


def build_systemd_config(*, systemd_local: dict[str, Any]) -> dict[str, Any]:
    return {
        "writable_unit_chain_present": bool(systemd_local.get("writable_unit_chain_present")),
        "writable_unit_chain_count": int(systemd_local.get("writable_chain_count") or 0),
    }


def build_cron_config(*, cron_local: dict[str, Any]) -> dict[str, Any]:
    return {
        "root_writable_job_chain_present": bool(cron_local.get("root_writable_job_chain_present")),
        "root_writable_job_chain_count": int(cron_local.get("writable_chain_count") or 0),
    }


def build_logrotate_config(*, logrotate_local: dict[str, Any]) -> dict[str, Any]:
    return {
        "writable_script_chain_present": bool(logrotate_local.get("writable_script_chain_present")),
        "writable_script_chain_count": int(logrotate_local.get("writable_chain_count") or 0),
    }


def build_linux_host_config(
    *,
    suid_sgid: dict[str, Any],
    capabilities: dict[str, Any],
    sensitive_world_writable: dict[str, Any],
    docker_local: dict[str, Any] | None = None,
) -> dict[str, Any]:
    docker_local = docker_local or {}
    return {
        "dangerous_suid_present": bool(suid_sgid.get("dangerous_suid_present")),
        "dangerous_suid_count": int(suid_sgid.get("dangerous_count") or 0),
        "dangerous_suid_by_binary": dict(suid_sgid.get("dangerous_suid_by_binary") or {}),
        "dangerous_capability_present": bool(capabilities.get("dangerous_capability_present")),
        "dangerous_capability_count": int(capabilities.get("dangerous_count") or 0),
        "dangerous_capability_by_binary": dict(capabilities.get("dangerous_capability_by_binary") or {}),
        "sensitive_world_writable_present": bool(sensitive_world_writable.get("sensitive_world_writable_present")),
        "sensitive_world_writable_count": int(sensitive_world_writable.get("count") or 0),
        "privileged_runtime_group_membership_present": bool(
            docker_local.get("privileged_runtime_group_membership_present")
        ),
        "privileged_runtime_groups": list(docker_local.get("privileged_runtime_groups") or [])[:10],
    }


def build_local_privilege_summary(service_configs: dict[str, dict[str, Any]] | None) -> dict[str, int]:
    service_configs = service_configs or {}
    ssh_config = service_configs.get("ssh") if isinstance(service_configs.get("ssh"), dict) else {}
    mysql_config = service_configs.get("mysql") if isinstance(service_configs.get("mysql"), dict) else {}
    nmap_config = service_configs.get("nmap") if isinstance(service_configs.get("nmap"), dict) else {}
    screen_config = service_configs.get("screen") if isinstance(service_configs.get("screen"), dict) else {}
    docker_config = service_configs.get("docker") if isinstance(service_configs.get("docker"), dict) else {}
    systemd_config = service_configs.get("systemd") if isinstance(service_configs.get("systemd"), dict) else {}
    cron_config = service_configs.get("cron") if isinstance(service_configs.get("cron"), dict) else {}
    logrotate_config = service_configs.get("logrotate") if isinstance(service_configs.get("logrotate"), dict) else {}
    linux_host_config = service_configs.get("linux-host") if isinstance(service_configs.get("linux-host"), dict) else {}
    sudo_config = service_configs.get("sudo") if isinstance(service_configs.get("sudo"), dict) else {}
    polkit_config = service_configs.get("polkit") if isinstance(service_configs.get("polkit"), dict) else {}

    high_risk_version_exposure_count = int(bool(nmap_config.get("legacy_interactive_privesc_exposed"))) + int(
        bool(screen_config.get("legacy_setuid_privesc_exposed"))
    )
    distro_aware_version_exposure_count = int(bool(sudo_config.get("distro_aware_exposed"))) + int(
        bool(polkit_config.get("distro_aware_exposed"))
    )
    distro_aware_inconclusive_count = int(bool(sudo_config.get("distro_aware_inconclusive"))) + int(
        bool(polkit_config.get("distro_aware_inconclusive"))
    )
    writable_exec_chain_count = (
        int(bool(systemd_config.get("writable_unit_chain_present")))
        + int(bool(cron_config.get("root_writable_job_chain_present")))
        + int(bool(logrotate_config.get("writable_script_chain_present")))
    )
    privileged_runtime_exposure_count = int(bool(docker_config.get("socket_present"))) + int(
        bool(linux_host_config.get("privileged_runtime_group_membership_present"))
    )
    config_exposure_count = (
        int(bool(sudo_config.get("setenv_present")))
        + int(bool(sudo_config.get("dangerous_env_keep_present")))
        + int(bool(polkit_config.get("writable_rules_path_present")))
        + int(bool(docker_config.get("tcp_listener_without_tlsverify")))
    )
    service_config_exposure_count = (
        int(bool(ssh_config.get("permit_empty_passwords")))
        + int(bool(mysql_config.get("skip_grant_tables")))
        + int(bool(mysql_config.get("local_infile")))
        + int(bool(mysql_config.get("bind_all_interfaces")))
    )
    local_privesc_exposure_count = (
        high_risk_version_exposure_count
        + distro_aware_version_exposure_count
        + writable_exec_chain_count
        + privileged_runtime_exposure_count
        + int(bool((linux_host_config.get("dangerous_suid_by_binary") or {}).get("nmap")))
        + int(bool((linux_host_config.get("dangerous_suid_by_binary") or {}).get("screen")))
    )
    return {
        "local_privesc_exposure_count": local_privesc_exposure_count,
        "high_risk_version_exposure_count": high_risk_version_exposure_count,
        "distro_aware_version_exposure_count": distro_aware_version_exposure_count,
        "sudo_polkit_exposure_count": distro_aware_version_exposure_count,
        "distro_aware_inconclusive_count": distro_aware_inconclusive_count,
        "writable_exec_chain_count": writable_exec_chain_count,
        "privileged_runtime_exposure_count": privileged_runtime_exposure_count,
        "config_exposure_count": config_exposure_count,
        "service_config_exposure_count": service_config_exposure_count,
    }
