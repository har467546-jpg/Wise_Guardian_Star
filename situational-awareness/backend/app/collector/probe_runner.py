from __future__ import annotations

import asyncio
import importlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from time import monotonic
from typing import Any

from app.collector.ssh_collector import SSHCollectProfile

_OUTPUT_LIMIT = 5000

PROBE_PRESETS: dict[str, list[tuple[str, str]]] = {
    "baseline": [
        ("hostname", "hostnamectl --static 2>/dev/null || hostname"),
        ("os_release", "(cat /etc/os-release 2>/dev/null | head -n 12; lsb_release -d 2>/dev/null; cat /etc/issue 2>/dev/null | head -n 1)"),
        ("kernel", "uname -a"),
        ("uptime", "uptime"),
        ("listening_ports", "ss -tulpen 2>/dev/null | head -n 80 || netstat -tulpen 2>/dev/null | head -n 80"),
    ],
}


@dataclass(slots=True)
class ProbeCommandExecution:
    name: str
    command: str
    success: bool
    exit_status: int | None
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "success": self.success,
            "exit_status": self.exit_status,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
        }


@dataclass(slots=True)
class SSHProbeResult:
    asset_id: str
    ip: str
    preset: str
    status: str
    results: list[ProbeCommandExecution] = field(default_factory=list)
    errors: list[dict[str, str | None]] = field(default_factory=list)
    summary_json: dict[str, Any] = field(default_factory=dict)
    detail_json: dict[str, Any] = field(default_factory=dict)
    friendly_text: list[str] = field(default_factory=list)
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "preset": self.preset,
            "status": self.status,
            "probe_method": "ssh",
            "results": [item.to_dict() for item in self.results],
            "errors": self.errors,
            "summary_json": self.summary_json,
            "detail_json": self.detail_json,
            "friendly_text": self.friendly_text,
            "executed_at": self.executed_at.isoformat(),
        }


class AsyncSSHProbeRunner:
    async def run(
        self,
        profile: SSHCollectProfile,
        *,
        preset: str = "baseline",
        connect_timeout: float = 20.0,
        command_timeout: float = 20.0,
        known_hosts: str | None = None,
    ) -> SSHProbeResult:
        commands = PROBE_PRESETS.get(preset)
        if not commands:
            return SSHProbeResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                preset=preset,
                status="failed",
                errors=[{"stage": "preset", "message": f"unsupported preset: {preset}", "command": None}],
            )

        asyncssh = _load_asyncssh()
        connect_kwargs: dict[str, Any] = {
            "host": profile.ip,
            "port": profile.port,
            "username": profile.username,
            "known_hosts": known_hosts,
            "connect_timeout": connect_timeout,
            "login_timeout": max(float(connect_timeout), 20.0),
        }
        if profile.private_key:
            try:
                connect_kwargs["client_keys"] = [asyncssh.import_private_key(profile.private_key)]
            except Exception as exc:
                return SSHProbeResult(
                    asset_id=profile.asset_id,
                    ip=profile.ip,
                    preset=preset,
                    status="failed",
                    errors=[{"stage": "auth", "message": f"私钥无效：{exc}", "command": None}],
                )
        elif profile.password:
            connect_kwargs["password"] = profile.password

        try:
            async with asyncssh.connect(**connect_kwargs) as connection:
                executions: list[ProbeCommandExecution] = []
                errors: list[dict[str, str | None]] = []
                for name, command in commands:
                    exec_item = await self._run_command(connection, name=name, command=command, timeout=command_timeout)
                    executions.append(exec_item)
                    if not exec_item.success:
                        errors.append({"stage": name, "message": exec_item.stderr or f"退出状态码 {exec_item.exit_status}", "command": command})

                status = "success" if not errors else ("partial" if any(item.success for item in executions) else "failed")
                summary_json, detail_json, friendly_text = _build_structured_probe_payload(executions)
                return SSHProbeResult(
                    asset_id=profile.asset_id,
                    ip=profile.ip,
                    preset=preset,
                    status=status,
                    results=executions,
                    errors=errors,
                    summary_json=summary_json,
                    detail_json=detail_json,
                    friendly_text=friendly_text,
                )
        except Exception as exc:
            message = _normalize_connect_error(exc, connect_timeout=connect_timeout)
            return SSHProbeResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                preset=preset,
                status="failed",
                errors=[{"stage": "connect", "message": message, "command": None}],
            )

    async def _run_command(self, connection: Any, *, name: str, command: str, timeout: float) -> ProbeCommandExecution:
        start = monotonic()
        try:
            result = await asyncio.wait_for(connection.run(command, check=False), timeout=timeout)
            duration_ms = int((monotonic() - start) * 1000)
            stdout = _truncate_text((getattr(result, "stdout", "") or "").strip())
            stderr = _truncate_text((getattr(result, "stderr", "") or "").strip())
            exit_status = getattr(result, "exit_status", None)
            success = exit_status == 0
            if not success and not stderr:
                stderr = f"退出状态码 {exit_status}"
            return ProbeCommandExecution(
                name=name,
                command=command,
                success=success,
                exit_status=exit_status,
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )
        except asyncio.TimeoutError:
            duration_ms = int((monotonic() - start) * 1000)
            return ProbeCommandExecution(
                name=name,
                command=command,
                success=False,
                exit_status=None,
                stdout="",
                stderr=f"命令执行超时，已超过 {int(timeout)} 秒",
                duration_ms=duration_ms,
            )
        except Exception as exc:
            duration_ms = int((monotonic() - start) * 1000)
            message = str(exc).strip() or exc.__class__.__name__
            return ProbeCommandExecution(
                name=name,
                command=command,
                success=False,
                exit_status=None,
                stdout="",
                stderr=message,
                duration_ms=duration_ms,
            )


def _truncate_text(text: str) -> str:
    if len(text) <= _OUTPUT_LIMIT:
        return text
    return f"{text[:_OUTPUT_LIMIT]}...<已截断>"


def _load_asyncssh() -> Any:
    return importlib.import_module("asyncssh")


def _normalize_connect_error(exc: Exception, *, connect_timeout: float) -> str:
    raw = str(exc).strip()
    class_name = exc.__class__.__name__
    lowered = raw.lower()
    if isinstance(exc, asyncio.TimeoutError) or class_name == "TimeoutError":
        return f"SSH 连接或认证超时（>{int(connect_timeout)}s）"
    if class_name in {"PermissionDenied", "AuthenticationFailed"}:
        return "SSH 认证失败，请检查用户名/密码或私钥"
    if "permission denied" in lowered or "authentication failed" in lowered:
        return "SSH 认证失败，请检查用户名/密码或私钥"
    if "no matching" in lowered and "method" in lowered:
        return "SSH 认证方式不匹配，请检查目标主机支持的认证方式"
    if "connection refused" in lowered:
        return "SSH 端口拒绝连接，请确认 22 端口可达"
    if "network is unreachable" in lowered or "no route to host" in lowered:
        return "网络不可达，请检查容器到目标主机的连通性"
    return raw or class_name


def _build_structured_probe_payload(
    executions: list[ProbeCommandExecution],
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    results_by_name = {item.name: item for item in executions}
    hostname = _first_line(results_by_name.get("hostname"))
    os_name = _parse_os_release(_read_stdout(results_by_name.get("os_release")))
    kernel = _first_line(results_by_name.get("kernel"))
    if not os_name and kernel:
        if kernel.lower().startswith("linux"):
            os_name = "Linux（未识别发行版）"
        else:
            os_name = kernel.split(" ", 1)[0]
    uptime = _first_line(results_by_name.get("uptime"))
    listening_raw = _read_stdout(results_by_name.get("listening_ports"))
    listening_entries = _parse_listening_entries(listening_raw)
    listening_ports = sorted({int(item["port"]) for item in listening_entries})
    external_listening_entries = [item for item in listening_entries if item.get("scope") == "external"]
    external_listening_ports = sorted({int(item["port"]) for item in external_listening_entries})

    command_health = _build_command_health(executions)
    key_hints = _build_key_hints(
        hostname=hostname,
        os_name=os_name,
        listening_ports=listening_ports,
        command_health=command_health,
    )

    summary_json = {
        "hostname": hostname,
        "os": os_name,
        "kernel": kernel,
        "uptime": uptime,
        "listening_port_count": len(listening_ports),
        "listening_ports": listening_ports,
        "external_listening_port_count": len(external_listening_ports),
        "external_listening_ports": external_listening_ports,
        "key_hints": key_hints,
    }
    detail_json = {
        "system_info": {
            "hostname": hostname,
            "os": os_name,
            "kernel": kernel,
            "uptime": uptime,
        },
        "listening_ports": {
            "count": len(listening_ports),
            "ports": listening_ports,
            "external_count": len(external_listening_ports),
            "external_ports": external_listening_ports,
            "entries": listening_entries,
            "sample_lines": _sample_lines(listening_raw, limit=16),
        },
        "listening_entries": listening_entries,
        "command_health": command_health,
    }
    friendly_text = _build_friendly_text(
        hostname=hostname,
        os_name=os_name,
        uptime=uptime,
        listening_ports=listening_ports,
        command_health=command_health,
    )
    return summary_json, detail_json, friendly_text


def _read_stdout(item: ProbeCommandExecution | None) -> str:
    if item is None:
        return ""
    return (item.stdout or "").strip()


def _first_line(item: ProbeCommandExecution | None) -> str | None:
    text = _read_stdout(item)
    if not text:
        return None
    first = text.splitlines()[0].strip()
    return first or None


def _parse_os_release(raw: str) -> str | None:
    if not raw:
        return None

    kv: dict[str, str] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().upper()
        value = value.strip().strip('"').strip("'")
        kv[key] = value

    if kv.get("PRETTY_NAME"):
        return kv["PRETTY_NAME"]
    if kv.get("NAME") and kv.get("VERSION_ID"):
        return f"{kv['NAME']} {kv['VERSION_ID']}"
    if kv.get("NAME"):
        return kv["NAME"]
    fallback = _first_non_empty_line(raw)
    if not fallback:
        return None
    if fallback.lower().startswith("description:"):
        return fallback.split(":", 1)[-1].strip() or None
    return fallback


def _first_non_empty_line(text: str) -> str | None:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _parse_listening_ports(raw: str) -> list[int]:
    return sorted({int(item["port"]) for item in _parse_listening_entries(raw)})


def _parse_listening_entries(raw: str) -> list[dict[str, Any]]:
    if not raw:
        return []

    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for line in raw.splitlines():
        normalized = line.strip()
        if not normalized:
            continue
        if normalized.lower().startswith(("netid", "proto", "active")):
            continue

        protocol = _extract_protocol(normalized)
        if protocol is None:
            continue
        local_token = _extract_local_endpoint(normalized)
        if not local_token:
            continue
        port = _extract_port(local_token)
        if port is None:
            continue
        local_address = _extract_local_address(local_token)
        if not local_address:
            continue
        process_name = _extract_process_name(normalized)
        scope = _classify_scope(local_address)

        dedupe_key = (protocol, local_address, port, process_name or "")
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        entries.append(
            {
                "port": port,
                "protocol": protocol,
                "local_address": local_address,
                "process_name": process_name,
                "scope": scope,
            }
        )

    return sorted(entries, key=lambda item: (int(item["port"]), str(item["protocol"]), str(item["local_address"])))


def _extract_protocol(line: str) -> str | None:
    first = line.split()[0].strip().lower()
    if first.startswith("tcp"):
        return "tcp"
    if first.startswith("udp"):
        return "udp"
    return None


def _extract_local_endpoint(line: str) -> str | None:
    tokens = line.split()
    if len(tokens) < 2:
        return None

    skip_prefixes = ("users:", "ino:", "sk:", "uid:")
    for token in tokens:
        if ":" not in token:
            continue
        if token.startswith(skip_prefixes):
            continue
        if _extract_port(token) is None:
            continue
        return token

    return None


def _extract_port(endpoint: str) -> int | None:
    cleaned = endpoint.replace("[", "").replace("]", "")
    if ":" not in cleaned:
        return None
    candidate = cleaned.rsplit(":", 1)[-1].strip()
    candidate = re.sub(r"[^0-9].*$", "", candidate)
    if not candidate.isdigit():
        return None
    port = int(candidate)
    if 0 < port <= 65535:
        return port
    return None


def _extract_local_address(endpoint: str) -> str | None:
    cleaned = endpoint.replace("[", "").replace("]", "")
    if ":" not in cleaned:
        return None
    address = cleaned.rsplit(":", 1)[0].strip().lower()
    return address or None


def _extract_process_name(line: str) -> str | None:
    users_match = re.search(r'users:\(\("(?P<name>[^"]+)"', line)
    if users_match:
        value = users_match.group("name").strip().lower()
        return value or None
    pid_program_match = re.search(r"\b\d+/(?P<name>[A-Za-z0-9_.-]+)", line)
    if pid_program_match:
        value = pid_program_match.group("name").strip().lower()
        return value or None
    return None


def _classify_scope(local_address: str) -> str:
    value = local_address.strip().lower()
    if not value:
        return "external"
    if value in {"localhost", "::1"}:
        return "loopback"
    if value.startswith("127."):
        return "loopback"
    if value.startswith("::1%"):
        return "loopback"
    return "external"


def _sample_lines(raw: str, *, limit: int) -> list[str]:
    if not raw:
        return []
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    return lines[:limit]


def _build_command_health(executions: list[ProbeCommandExecution]) -> dict[str, Any]:
    total = len(executions)
    success = sum(1 for item in executions if item.success)
    failed = total - success
    rate = round((success / total) * 100, 1) if total else 0.0
    failed_commands = [
        {"name": item.name, "message": item.stderr or f"退出状态码 {item.exit_status}"}
        for item in executions
        if not item.success
    ]
    return {
        "total": total,
        "success": success,
        "failed": failed,
        "success_rate": rate,
        "failed_commands": failed_commands,
    }


def _build_key_hints(
    *,
    hostname: str | None,
    os_name: str | None,
    listening_ports: list[int],
    command_health: dict[str, Any],
) -> list[str]:
    hints: list[str] = []
    if hostname:
        hints.append(f"识别到主机名：{hostname}")
    if os_name:
        hints.append(f"识别到系统：{os_name}")
    if listening_ports:
        top_ports = "、".join(str(port) for port in listening_ports[:6])
        hints.append(f"检测到 {len(listening_ports)} 个监听端口（示例：{top_ports}）")
    failed = int(command_health.get("failed", 0) or 0)
    if failed:
        hints.append(f"有 {failed} 条探测命令执行失败，建议查看原始输出")
    return hints


def _build_friendly_text(
    *,
    hostname: str | None,
    os_name: str | None,
    uptime: str | None,
    listening_ports: list[int],
    command_health: dict[str, Any],
) -> list[str]:
    texts: list[str] = []
    if hostname or os_name:
        joined = "，".join([part for part in [f"主机名 {hostname}" if hostname else None, f"系统 {os_name}" if os_name else None] if part])
        texts.append(f"基础信息：{joined}。")
    if uptime:
        texts.append(f"运行状态：{uptime}。")
    if listening_ports:
        preview = "、".join(str(port) for port in listening_ports[:8])
        texts.append(f"网络监听：发现 {len(listening_ports)} 个端口，主要为 {preview}。")
    else:
        texts.append("网络监听：暂未提取到明确的监听端口数据。")

    failed = int(command_health.get("failed", 0) or 0)
    if failed > 0:
        texts.append(f"执行质量：有 {failed} 条命令失败，请在原始输出中查看具体原因。")
    else:
        texts.append("执行质量：本次基础探测命令均执行成功。")

    return texts[:4]
