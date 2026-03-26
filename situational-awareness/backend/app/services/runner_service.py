from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import secrets
import shlex
import tarfile
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collector.ssh_collector import (
    SSHCollectOptions,
    SSHCollectProfile,
    _build_connect_kwargs,
    _connect_with_legacy_hostkey_fallback,
    _load_asyncssh,
)
from app.core.config import settings
from app.core.crypto import decrypt_text
from app.db.models.asset import Asset
from app.db.models.credential import SSHCredential
from app.db.models.enums import CredentialAuthType, TaskExecutionStatus, TaskType
from app.db.models.host_runner import HostRunner
from app.db.models.remediation_message import RemediationMessage
from app.db.models.remediation_session import RemediationSession
from app.db.models.task_run import TaskRun
from app.repositories.task_event_repo import create_task_event
from app.repositories.task_repo import create_task_run, get_latest_task_run_for_scope, get_task_run, update_task_run
from app.schemas.remediation import (
    HostRunnerRead,
    RunnerHeartbeatRequest,
    RunnerPollResponse,
    RunnerRegisterRequest,
    RunnerRegisterResponse,
    RunnerTaskAssignmentRead,
    RunnerTaskCompleteRequest,
    RunnerTaskEventBatch,
    RunnerTaskStepRead,
)
from app.services.remediation_evidence_service import build_remediation_evidence
from app.tasks.task_runtime import append_current_task_event
from app.tasks.verify_tasks import run_risk_verify_task
from app.db.session import SessionLocal

RUNNER_VERSION = "2.0.0"
RUNNER_BUNDLE_DIR = Path(__file__).resolve().parents[1] / "runner_bundle"
RUNNER_SUPPORTED_TASK_TYPES = {TaskType.REMEDIATION_EXECUTE, TaskType.RUNNER_INSTALL}
_RUNNER_PRIMARY_ARCHES = {"x86_64", "amd64", "aarch64", "arm64"}
_RUNNER_SUPPORTED_RUNTIME_KINDS = {"python_script", "shell_bundle"}
_RUNNER_SUPPORTED_INSTALL_MODES = {"system", "user"}
_RUNNER_SUPPORTED_SERVICE_MODES = {"systemd", "sysvinit", "crontab", "detached"}
_RUNNER_INTERNAL_HOSTS = {"backend", "localhost", "0.0.0.0", "::1", "ip6-localhost"}


@dataclass(slots=True)
class RunnerInstallContext:
    asset: Asset
    credential: SSHCredential
    host_runner: HostRunner
    platform_url: str
    registration_token: str


@dataclass(slots=True)
class RunnerInstallProbe:
    detected_os: str
    detected_arch: str
    can_system_install: bool
    has_sudo: bool
    sudo_nopasswd: bool
    sudo_password_works: bool
    has_systemd: bool
    has_sysvinit: bool
    has_crontab: bool
    has_user_systemd: bool
    has_bash: bool
    has_sh: bool
    has_tar: bool
    has_mktemp: bool
    http_tool: str
    platform_ok: bool
    package_manager: str
    os_release_like: str
    missing_tools: list[str]
    bootstrap_needed: bool
    bootstrap_supported: bool
    bootstrap_status: str
    compatibility_issues: list[str]


class RunnerInstallError(RuntimeError):
    def __init__(self, message: str, *, probe: RunnerInstallProbe | None = None) -> None:
        super().__init__(message)
        self.probe = probe


def hash_runner_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_runner_token() -> str:
    return secrets.token_urlsafe(36)


def _runner_poll_interval_seconds() -> int:
    return max(1, int(settings.RUNNER_POLL_INTERVAL_SECONDS))


def _runner_offline_grace_seconds() -> int:
    return max(5, int(settings.RUNNER_OFFLINE_GRACE_SECONDS))


def _runner_install_stale_seconds() -> int:
    return max(180, _runner_offline_grace_seconds() * 4)


def _normalize_runner_url(value: str | None) -> str:
    return str(value or "").strip().rstrip("/")


def resolve_runner_public_url(*candidate_urls: str | None) -> str:
    configured = _normalize_runner_url(settings.RUNNER_PUBLIC_BASE_URL)
    if configured:
        return configured
    for candidate in candidate_urls:
        normalized = _normalize_runner_url(candidate)
        if not normalized:
            continue
        parsed = urlparse(normalized)
        hostname = str(parsed.hostname or "").strip().lower()
        if hostname in _RUNNER_INTERNAL_HOSTS:
            continue
        if parsed.scheme in {"http", "https"}:
            return normalized
    raise RuntimeError("无法解析可供目标主机访问的平台地址，请配置 RUNNER_PUBLIC_BASE_URL 或从前端浏览器访问平台")


def _normalize_runtime_kind(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    if normalized in {"bundled_binary", "shell-bundle"}:
        return "shell_bundle"
    return normalized if normalized in _RUNNER_SUPPORTED_RUNTIME_KINDS else None


def _normalize_install_mode(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _RUNNER_SUPPORTED_INSTALL_MODES else None


def _normalize_service_mode(value: str | None) -> str | None:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in _RUNNER_SUPPORTED_SERVICE_MODES else None


def _normalize_string_list(items: Any) -> list[str]:
    if not isinstance(items, list):
        return []
    normalized: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text:
            normalized.append(text)
    return normalized


def _merge_runner_capabilities(
    existing: dict[str, Any] | None,
    *,
    capabilities: dict[str, Any] | None = None,
    runtime_kind: str | None = None,
    install_mode: str | None = None,
    service_mode: str | None = None,
    host_facts: dict[str, Any] | None = None,
    compatibility_issues: list[str] | None = None,
) -> dict[str, Any]:
    merged = dict(existing or {})
    if isinstance(capabilities, dict) and capabilities:
        merged.update(capabilities)
    normalized_runtime_kind = _normalize_runtime_kind(runtime_kind)
    if normalized_runtime_kind:
        merged["runtime_kind"] = normalized_runtime_kind
    normalized_install_mode = _normalize_install_mode(install_mode)
    if normalized_install_mode:
        merged["install_mode"] = normalized_install_mode
    normalized_service_mode = _normalize_service_mode(service_mode)
    if normalized_service_mode:
        merged["service_mode"] = normalized_service_mode
    if isinstance(host_facts, dict) and host_facts:
        merged["host_facts"] = dict(host_facts)
    if compatibility_issues is not None:
        merged["compatibility_issues"] = _normalize_string_list(compatibility_issues)
    return merged


def _runner_metadata(capabilities_json: dict[str, Any] | None) -> dict[str, Any]:
    capabilities = dict(capabilities_json or {})
    host_facts = capabilities.get("host_facts") if isinstance(capabilities.get("host_facts"), dict) else {}
    runtime_kind = _normalize_runtime_kind(str(capabilities.get("runtime_kind") or ""))
    if runtime_kind is None and capabilities.get("python"):
        runtime_kind = "python_script"
    if runtime_kind is None and capabilities:
        runtime_kind = "shell_bundle" if capabilities.get("transport") == "shell-bundle" else "python_script"
    return {
        "runtime_kind": runtime_kind,
        "install_mode": _normalize_install_mode(str(capabilities.get("install_mode") or "")),
        "service_mode": _normalize_service_mode(str(capabilities.get("service_mode") or "")),
        "detected_os": str(host_facts.get("os") or capabilities.get("detected_os") or "").strip() or None,
        "detected_arch": str(host_facts.get("arch") or capabilities.get("detected_arch") or "").strip() or None,
        "compatibility_issues": _normalize_string_list(capabilities.get("compatibility_issues")),
    }


def serialize_host_runner(asset_id: str, host_runner: HostRunner | None) -> HostRunnerRead:
    status = "not_installed"
    install_status = "not_installed"
    version = None
    platform_url = None
    last_seen_at = None
    last_error = None
    capabilities_json: dict[str, Any] = {}
    runner_id = None
    runtime_kind = None
    install_mode = None
    service_mode = None
    detected_os = None
    detected_arch = None
    compatibility_issues: list[str] = []
    if host_runner is not None:
        runner_id = host_runner.id
        version = host_runner.version
        platform_url = host_runner.platform_url
        last_seen_at = host_runner.last_seen_at.isoformat() if host_runner.last_seen_at else None
        last_error = host_runner.last_error
        capabilities_json = dict(host_runner.capabilities_json or {})
        install_status = str(host_runner.install_status or "pending")
        status = _runner_status_value(host_runner)
        metadata = _runner_metadata(capabilities_json)
        runtime_kind = metadata["runtime_kind"]
        install_mode = metadata["install_mode"]
        service_mode = metadata["service_mode"]
        detected_os = metadata["detected_os"]
        detected_arch = metadata["detected_arch"]
        compatibility_issues = metadata["compatibility_issues"]
    return HostRunnerRead(
        runner_id=runner_id,
        asset_id=asset_id,
        status=status,
        install_status=install_status,
        version=version,
        platform_url=platform_url,
        last_seen_at=last_seen_at,
        last_error=last_error,
        runtime_kind=runtime_kind,
        install_mode=install_mode,
        service_mode=service_mode,
        detected_os=detected_os,
        detected_arch=detected_arch,
        compatibility_issues=compatibility_issues,
        capabilities_json=capabilities_json,
    )


def _runner_status_value(host_runner: HostRunner) -> str:
    raw_status = str(host_runner.status or "").strip().lower()
    if raw_status == "not_installed":
        return raw_status
    if host_runner.last_seen_at is None:
        return "offline" if raw_status in {"online", "busy"} else raw_status or "offline"
    if datetime.now(timezone.utc) - host_runner.last_seen_at > timedelta(seconds=_runner_offline_grace_seconds()):
        return "offline"
    return raw_status or "offline"


def resolve_runner_by_asset(db: Session, asset_id: str) -> HostRunner | None:
    return db.scalar(select(HostRunner).where(HostRunner.asset_id == asset_id))


def resolve_runner_by_asset_for_read(db: Session, asset_id: str) -> HostRunner | None:
    host_runner = resolve_runner_by_asset(db, asset_id)
    if host_runner is None:
        return None
    latest_install_task = get_latest_task_run_for_scope(
        db,
        scope_type="asset",
        scope_id=asset_id,
        task_type=TaskType.RUNNER_INSTALL,
        statuses=[
            TaskExecutionStatus.PENDING,
            TaskExecutionStatus.RUNNING,
            TaskExecutionStatus.RETRY,
            TaskExecutionStatus.SUCCESS,
            TaskExecutionStatus.FAILURE,
            TaskExecutionStatus.CANCELED,
        ],
    )
    task_updated = False
    runner_updated = False

    if host_runner.token_hash:
        if str(host_runner.install_status or "").strip().lower() != "installed":
            host_runner.install_status = "installed"
            runner_updated = True
        normalized_status = _runner_status_value(host_runner)
        if str(host_runner.status or "").strip().lower() != normalized_status:
            host_runner.status = normalized_status
            runner_updated = True

    if str(host_runner.install_status or "").strip().lower() == "installing" and not host_runner.token_hash:
        if latest_install_task is not None and latest_install_task.status in {
            TaskExecutionStatus.FAILURE,
            TaskExecutionStatus.CANCELED,
        }:
            next_install_status = "failed" if latest_install_task.status == TaskExecutionStatus.FAILURE else "canceled"
            message = str(latest_install_task.message or "").strip() or "Host Runner 安装未完成"
            if str(host_runner.install_status or "").strip().lower() != next_install_status:
                host_runner.install_status = next_install_status
                runner_updated = True
            if str(host_runner.status or "").strip().lower() != "offline":
                host_runner.status = "offline"
                runner_updated = True
            if next_install_status == "failed" and host_runner.last_error != message:
                host_runner.last_error = message
                runner_updated = True
        elif latest_install_task is not None and latest_install_task.status == TaskExecutionStatus.SUCCESS:
            message = "Host Runner 安装任务已完成，但 Runner 未完成平台注册"
            host_runner.install_status = "failed"
            host_runner.status = "offline"
            host_runner.last_error = message
            runner_updated = True
        elif latest_install_task is not None and latest_install_task.status in {
            TaskExecutionStatus.PENDING,
            TaskExecutionStatus.RUNNING,
            TaskExecutionStatus.RETRY,
        }:
            task_updated_at = latest_install_task.updated_at or latest_install_task.started_at or latest_install_task.created_at
            if (
                task_updated_at is not None
                and datetime.now(timezone.utc) - task_updated_at > timedelta(seconds=_runner_install_stale_seconds())
            ):
                message = "Host Runner 安装任务长时间未完成平台注册，请重新安装"
                _mark_runner_install_task_failed(db, latest_install_task, message=message)
                task_updated = True
                host_runner.install_status = "failed"
                host_runner.status = "offline"
                host_runner.last_error = message
                runner_updated = True

    if task_updated or runner_updated:
        db.add(host_runner)
        db.commit()
        db.refresh(host_runner)
    return host_runner


def _mark_runner_install_task_failed(db: Session, task: TaskRun, *, message: str) -> None:
    error_json = {"error": message}
    update_task_run(
        db,
        task,
        status=TaskExecutionStatus.FAILURE,
        progress=100,
        message=message,
        retry_count=task.retry_count,
        error_json=error_json,
        commit=False,
        refresh=False,
    )
    create_task_event(
        db,
        task_run_id=task.id,
        event_type="failure",
        level="error",
        message=message,
        progress=100,
        payload_json=error_json,
    )


def runner_install_blocked_reasons(credential: SSHCredential | None) -> list[str]:
    reasons: list[str] = []
    if credential is None:
        return ["当前资产未配置 SSH 管理员凭据"]
    if credential.admin_authorized is not True:
        reasons.append("当前 SSH 凭据尚未确认管理员授权")
    return reasons


def queue_runner_install(
    db: Session,
    *,
    asset: Asset,
    credential: SSHCredential | None,
    platform_url: str,
) -> tuple[HostRunner, str, str]:
    blocked = runner_install_blocked_reasons(credential)
    if blocked:
        raise RuntimeError("；".join(blocked))
    host_runner = resolve_runner_by_asset(db, asset.id)
    if host_runner is None:
        host_runner = HostRunner(
            asset_id=asset.id,
            status="offline",
            install_status="installing",
            platform_url=platform_url,
        )
        db.add(host_runner)
        db.flush()
    registration_token = generate_runner_token()
    host_runner.registration_token_hash = hash_runner_token(registration_token)
    host_runner.token_hash = None
    host_runner.version = RUNNER_VERSION
    host_runner.platform_url = platform_url
    host_runner.install_status = "installing"
    host_runner.status = "offline"
    host_runner.last_error = None
    db.add(host_runner)
    db.commit()
    db.refresh(host_runner)
    task_run = create_task_run(
        db,
        task_type=TaskType.RUNNER_INSTALL,
        scope_type="asset",
        scope_id=asset.id,
        message="Host Runner 安装任务已入队",
    )
    result_json = {
        "context": {"asset_id": asset.id, "runner_id": host_runner.id, "platform_url": platform_url},
        "install": {"status": "queued"},
    }
    update_task_run(db, task_run, result_json=result_json)
    return host_runner, task_run.id, registration_token


def record_runner_install_failure(db: Session, *, asset_id: str, message: str) -> None:
    host_runner = resolve_runner_by_asset(db, asset_id)
    if host_runner is None:
        return
    host_runner.install_status = "failed"
    host_runner.status = "offline"
    host_runner.last_error = str(message or "").strip() or "Host Runner 安装失败"
    db.add(host_runner)
    db.commit()


def record_runner_install_canceled(db: Session, *, asset_id: str) -> None:
    host_runner = resolve_runner_by_asset(db, asset_id)
    if host_runner is None:
        return
    host_runner.install_status = "canceled"
    host_runner.status = "offline"
    db.add(host_runner)
    db.commit()


def build_runner_bundle(
    *,
    platform_url: str,
    asset_id: str,
    runner_id: str,
    registration_token: str,
) -> bytes:
    bootstrap_payload = {
        "SA_RUNNER_ID": runner_id,
        "SA_RUNNER_ASSET_ID": asset_id,
        "SA_RUNNER_PLATFORM_URL": platform_url.rstrip("/"),
        "SA_RUNNER_REGISTRATION_TOKEN": registration_token,
        "SA_RUNNER_VERSION": RUNNER_VERSION,
        "SA_RUNNER_POLL_INTERVAL_SECONDS": str(_runner_poll_interval_seconds()),
        "SA_RUNNER_DEFAULT_STATE_FILE": "state.env",
        "SA_RUNNER_DEFAULT_METADATA_FILE": "metadata.env",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for filename in ("runner.sh", "install.sh", "sa-runner.service"):
            path = RUNNER_BUNDLE_DIR / filename
            info = tarfile.TarInfo(name=filename)
            data = path.read_bytes()
            info.size = len(data)
            info.mode = 0o755 if filename.endswith(".sh") or filename.endswith(".py") else 0o644
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(data))
        bootstrap_lines = [f"{key}={shlex.quote(value)}" for key, value in bootstrap_payload.items()]
        bootstrap_data = ("\n".join(bootstrap_lines) + "\n").encode("utf-8")
        bootstrap_info = tarfile.TarInfo(name="bootstrap.env")
        bootstrap_info.size = len(bootstrap_data)
        bootstrap_info.mode = 0o644
        bootstrap_info.mtime = int(time.time())
        archive.addfile(bootstrap_info, io.BytesIO(bootstrap_data))
    return buffer.getvalue()


def _append_compatibility_issue(issues: list[str], message: str) -> None:
    text = str(message or "").strip()
    if text and text not in issues:
        issues.append(text)


def _runner_probe_payload(probe: RunnerInstallProbe) -> dict[str, Any]:
    return {
        "detected_os": probe.detected_os,
        "detected_arch": probe.detected_arch,
        "can_system_install": probe.can_system_install,
        "has_sudo": probe.has_sudo,
        "sudo_nopasswd": probe.sudo_nopasswd,
        "sudo_password_works": probe.sudo_password_works,
        "has_systemd": probe.has_systemd,
        "has_sysvinit": probe.has_sysvinit,
        "has_crontab": probe.has_crontab,
        "has_user_systemd": probe.has_user_systemd,
        "has_bash": probe.has_bash,
        "has_sh": probe.has_sh,
        "has_tar": probe.has_tar,
        "has_mktemp": probe.has_mktemp,
        "http_tool": probe.http_tool,
        "platform_ok": probe.platform_ok,
        "package_manager": probe.package_manager,
        "os_release_like": probe.os_release_like,
        "missing_tools": list(probe.missing_tools),
        "bootstrap_needed": probe.bootstrap_needed,
        "bootstrap_supported": probe.bootstrap_supported,
        "bootstrap_status": probe.bootstrap_status,
        "compatibility_issues": probe.compatibility_issues,
    }


def _persist_runner_probe_metadata(db: Session, host_runner: HostRunner, probe: RunnerInstallProbe) -> None:
    host_runner.capabilities_json = _merge_runner_capabilities(
        host_runner.capabilities_json,
        capabilities={
            "transport": "shell-bundle",
            "probe": _runner_probe_payload(probe),
        },
        runtime_kind="shell_bundle",
        host_facts={
            "os": probe.detected_os,
            "arch": probe.detected_arch,
        },
        compatibility_issues=list(probe.compatibility_issues),
    )
    db.add(host_runner)
    db.commit()
    db.refresh(host_runner)


def _runner_missing_tools(probe: RunnerInstallProbe) -> list[str]:
    missing: list[str] = []
    if not probe.has_bash:
        missing.append("bash")
    if not probe.has_tar:
        missing.append("tar")
    if not probe.has_mktemp:
        missing.append("mktemp")
    if probe.http_tool == "none":
        missing.append("curl/wget")
    return missing


def _runner_missing_tools_text(items: list[str]) -> str:
    return "、".join(items)


def _supports_runner_bootstrap(package_manager: str) -> bool:
    return str(package_manager or "").strip().lower() == "apt"


def _build_runner_bootstrap_packages(missing_tools: list[str]) -> list[str]:
    packages: list[str] = []
    seen: set[str] = set()

    def add(package_name: str) -> None:
        normalized = str(package_name or "").strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            packages.append(normalized)

    for item in missing_tools:
        if item == "bash":
            add("bash")
        elif item == "tar":
            add("tar")
        elif item == "mktemp":
            add("coreutils")
        elif item == "curl/wget":
            add("ca-certificates")
            add("curl")
            add("wget")
    return packages


def _build_runner_bootstrap_command(*, packages: list[str], sudo_password: str | None) -> str:
    install_command = "\n".join(
        [
            "export DEBIAN_FRONTEND=noninteractive",
            "export APT_LISTCHANGES_FRONTEND=none",
            "export NEEDRESTART_MODE=a",
            "apt-get update",
            "apt-get install -y --no-install-recommends -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "
            + " ".join(shlex.quote(package_name) for package_name in packages),
        ]
    )
    encoded_sudo_password = _b64_encode_text(sudo_password or "")
    return "\n".join(
        [
            f'SUDO_PASSWORD_B64={shlex.quote(encoded_sudo_password)}',
            'SUDO_PASSWORD=""',
            'if [ -n "$SUDO_PASSWORD_B64" ]; then',
            '  if command -v base64 >/dev/null 2>&1; then',
            '    SUDO_PASSWORD="$(printf "%s" "$SUDO_PASSWORD_B64" | base64 -d 2>/dev/null || printf "%s" "$SUDO_PASSWORD_B64" | base64 --decode 2>/dev/null || true)"',
            '  elif command -v openssl >/dev/null 2>&1; then',
            '    SUDO_PASSWORD="$(printf "%s" "$SUDO_PASSWORD_B64" | openssl base64 -d -A 2>/dev/null || true)"',
            '  fi',
            'fi',
            'if ! command -v apt-get >/dev/null 2>&1; then',
            '  echo "当前目标主机未检测到 apt-get，无法自动补齐 Runner 依赖" >&2',
            '  exit 1',
            'fi',
            f'INSTALL_CMD={shlex.quote(install_command)}',
            'if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then',
            '  sh -lc "$INSTALL_CMD"',
            'elif command -v sudo >/dev/null 2>&1; then',
            '  if [ -n "$SUDO_PASSWORD" ] && printf "%s\\n" "$SUDO_PASSWORD" | sudo -S -p "" true >/dev/null 2>&1; then',
            '    printf "%s\\n" "$SUDO_PASSWORD" | sudo -S -p "" sh -lc "$INSTALL_CMD"',
            '  else',
            '    sudo -n sh -lc "$INSTALL_CMD"',
            '  fi',
            'else',
            '  echo "当前绑定凭据没有已验证的管理员权限，无法自动补齐 Runner 依赖" >&2',
            '  exit 1',
            'fi',
        ]
    )


def _validate_runner_install_probe_minimal(probe: RunnerInstallProbe) -> None:
    if probe.detected_os != "linux":
        _append_compatibility_issue(probe.compatibility_issues, "当前仅支持 Linux 目标主机安装 Shell Runner")
        raise RunnerInstallError(
            f"当前仅支持 Linux 目标主机安装 Runner，检测到系统为 {probe.detected_os or 'unknown'}",
            probe=probe,
        )
    if not probe.has_sh:
        _append_compatibility_issue(probe.compatibility_issues, "目标主机缺少 sh，无法执行 Runner 最小探测与预引导")
        raise RunnerInstallError("目标主机缺少 sh，无法执行 Runner 最小探测与预引导", probe=probe)
    if not probe.bootstrap_needed:
        probe.bootstrap_status = "not_needed"
        return
    missing_text = _runner_missing_tools_text(probe.missing_tools)
    if not probe.can_system_install:
        probe.bootstrap_status = "missing_admin"
        _append_compatibility_issue(
            probe.compatibility_issues,
            f"目标主机缺少 Runner 依赖（{missing_text}），当前绑定凭据没有已验证的管理员权限，无法自动补齐",
        )
        raise RunnerInstallError(
            f"目标主机缺少 Runner 依赖（{missing_text}），当前绑定凭据没有已验证的管理员权限，无法自动补齐",
            probe=probe,
        )
    if not probe.bootstrap_supported:
        probe.bootstrap_status = "unsupported"
        _append_compatibility_issue(
            probe.compatibility_issues,
            f"目标主机缺少 Runner 依赖（{missing_text}），当前发行版不支持自动预引导",
        )
        raise RunnerInstallError(
            f"目标主机缺少 Runner 依赖（{missing_text}），当前发行版不支持自动预引导",
            probe=probe,
        )
    probe.bootstrap_status = "pending"
    _append_compatibility_issue(
        probe.compatibility_issues,
        f"检测到目标主机缺少 Runner 依赖（{missing_text}），将尝试通过 apt 自动补齐",
    )


def _validate_runner_install_probe(probe: RunnerInstallProbe, *, platform_url: str) -> None:
    if probe.detected_os != "linux":
        _append_compatibility_issue(probe.compatibility_issues, "当前仅支持 Linux 目标主机安装 Shell Runner")
        raise RunnerInstallError(
            f"当前仅支持 Linux 目标主机安装 Runner，检测到系统为 {probe.detected_os or 'unknown'}",
            probe=probe,
        )
    if not probe.has_sh:
        _append_compatibility_issue(probe.compatibility_issues, "目标主机缺少 sh，无法安装 Shell Runner")
        raise RunnerInstallError("目标主机缺少 sh，无法安装 Shell Runner", probe=probe)
    missing_tools = _runner_missing_tools(probe)
    if missing_tools:
        missing_text = _runner_missing_tools_text(missing_tools)
        if probe.bootstrap_status == "failed":
            _append_compatibility_issue(
                probe.compatibility_issues,
                f"目标主机缺少 Runner 依赖，已尝试自动补齐但失败：{missing_text}",
            )
            raise RunnerInstallError(f"目标主机缺少 Runner 依赖，已尝试自动补齐但失败：{missing_text}", probe=probe)
        if not probe.can_system_install:
            _append_compatibility_issue(
                probe.compatibility_issues,
                f"目标主机缺少 Runner 依赖（{missing_text}），当前绑定凭据没有已验证的管理员权限，无法自动补齐",
            )
            raise RunnerInstallError(
                f"目标主机缺少 Runner 依赖（{missing_text}），当前绑定凭据没有已验证的管理员权限，无法自动补齐",
                probe=probe,
            )
        if not probe.bootstrap_supported:
            _append_compatibility_issue(
                probe.compatibility_issues,
                f"目标主机缺少 Runner 依赖（{missing_text}），当前发行版不支持自动预引导",
            )
            raise RunnerInstallError(
                f"目标主机缺少 Runner 依赖（{missing_text}），当前发行版不支持自动预引导",
                probe=probe,
            )
        _append_compatibility_issue(
            probe.compatibility_issues,
            f"目标主机缺少 Runner 依赖（{missing_text}），自动补齐后仍未满足安装条件",
        )
        raise RunnerInstallError(f"目标主机缺少 Runner 依赖，自动补齐后仍未满足安装条件：{missing_text}", probe=probe)
    if not probe.platform_ok:
        _append_compatibility_issue(probe.compatibility_issues, f"目标主机无法访问平台地址 {platform_url.rstrip('/')}")
        raise RunnerInstallError(f"目标主机无法访问平台地址 {platform_url.rstrip('/')}", probe=probe)


async def _bootstrap_runner_prereqs(connection: Any, *, probe: RunnerInstallProbe, sudo_password: str | None) -> None:
    if not probe.bootstrap_needed:
        probe.bootstrap_status = "not_needed"
        return
    packages = _build_runner_bootstrap_packages(probe.missing_tools)
    if not packages:
        probe.bootstrap_status = "not_needed"
        return
    append_current_task_event(
        event_type="stage",
        stage_code="bootstrap_runner_prereqs",
        stage_name="补齐 Runner 依赖",
        message=f"检测到目标主机缺少 Runner 依赖（{_runner_missing_tools_text(probe.missing_tools)}），正在通过 apt 自动补齐",
        payload_json={
            "missing_tools": list(probe.missing_tools),
            "package_manager": probe.package_manager,
            "bootstrap_status": "running",
            "packages": packages,
        },
    )
    command = _build_runner_bootstrap_command(packages=packages, sudo_password=sudo_password)
    result = await connection.run(f"sh -lc {shlex.quote(command)}", check=False)
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    if int(getattr(result, "exit_status", 1) or 0) != 0:
        probe.bootstrap_status = "failed"
        failure_message = stderr.strip() or stdout.strip() or "apt 预引导执行失败"
        _append_compatibility_issue(
            probe.compatibility_issues,
            f"目标主机缺少 Runner 依赖，已尝试通过 apt 自动补齐但失败：{failure_message}",
        )
        append_current_task_event(
            event_type="warning",
            level="warning",
            stage_code="bootstrap_runner_prereqs",
            stage_name="补齐 Runner 依赖",
            message=f"Runner 依赖自动补齐失败：{failure_message}",
            payload_json={
                "missing_tools": list(probe.missing_tools),
                "package_manager": probe.package_manager,
                "bootstrap_status": probe.bootstrap_status,
                "packages": packages,
            },
        )
        raise RunnerInstallError(f"目标主机缺少 Runner 依赖，已尝试自动补齐但失败：{failure_message}", probe=probe)
    probe.bootstrap_status = "succeeded"
    _append_compatibility_issue(
        probe.compatibility_issues,
        f"目标主机缺少 Runner 依赖（{_runner_missing_tools_text(probe.missing_tools)}），已通过 apt 自动补齐",
    )
    append_current_task_event(
        event_type="success",
        stage_code="bootstrap_runner_prereqs",
        stage_name="补齐 Runner 依赖",
        message="已通过 apt 自动补齐 Runner 最低依赖",
        payload_json={
            "missing_tools": list(probe.missing_tools),
            "package_manager": probe.package_manager,
            "bootstrap_status": probe.bootstrap_status,
            "packages": packages,
        },
    )


def run_runner_install(
    db: Session,
    *,
    task_run_id: str,
    asset_id: str,
    platform_url: str,
    registration_token: str,
) -> dict[str, Any]:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise RuntimeError("资产不存在")
    credential = db.scalar(select(SSHCredential).where(SSHCredential.name == f"manual-asset-{asset.id}"))
    host_runner = resolve_runner_by_asset(db, asset.id)
    if credential is None or host_runner is None:
        raise RuntimeError("当前资产缺少可安装的 Host Runner 上下文")
    context = RunnerInstallContext(
        asset=asset,
        credential=credential,
        host_runner=host_runner,
        platform_url=platform_url,
        registration_token=registration_token,
    )
    probe: RunnerInstallProbe | None = None
    try:
        probe = asyncio.run(_install_runner_bundle(context))
    except RunnerInstallError as exc:
        if exc.probe is not None:
            _persist_runner_probe_metadata(db, host_runner, exc.probe)
        raise RuntimeError(str(exc)) from exc
    if probe is not None:
        _persist_runner_probe_metadata(db, host_runner, probe)
    _wait_for_runner_registration(host_runner.id)
    with SessionLocal() as refresh_db:
        refreshed = refresh_db.get(HostRunner, host_runner.id)
        if refreshed is None:
            raise RuntimeError("Host Runner 记录不存在")
        if not refreshed.token_hash:
            raise RuntimeError("Host Runner 已安装，但尚未完成平台注册")
        refreshed.install_status = "installed"
        refreshed.status = _runner_status_value(refreshed)
        refresh_db.add(refreshed)
        refresh_db.commit()
        refresh_db.refresh(refreshed)
        runner_read = serialize_host_runner(asset.id, refreshed)
        return {
            "context": {
                "asset_id": asset.id,
                "runner_id": refreshed.id,
                "platform_url": refreshed.platform_url,
                "runtime_kind": runner_read.runtime_kind,
                "install_mode": runner_read.install_mode,
                "service_mode": runner_read.service_mode,
            },
            "install": {
                "status": refreshed.install_status,
                "runner_status": refreshed.status,
                "last_seen_at": refreshed.last_seen_at.isoformat() if refreshed.last_seen_at else None,
                "runtime_kind": runner_read.runtime_kind,
                "install_mode": runner_read.install_mode,
                "service_mode": runner_read.service_mode,
                "detected_os": runner_read.detected_os,
                "detected_arch": runner_read.detected_arch,
                "compatibility_issues": runner_read.compatibility_issues,
            },
        }


def register_runner(db: Session, payload: RunnerRegisterRequest) -> RunnerRegisterResponse:
    host_runner = resolve_runner_by_asset(db, payload.asset_id)
    if host_runner is None:
        raise RuntimeError("Host Runner 尚未初始化")
    if hash_runner_token(payload.registration_token) != str(host_runner.registration_token_hash or ""):
        raise RuntimeError("Runner 注册令牌无效")
    runner_token = generate_runner_token()
    host_runner.token_hash = hash_runner_token(runner_token)
    host_runner.registration_token_hash = None
    host_runner.version = payload.version or host_runner.version or RUNNER_VERSION
    host_runner.capabilities_json = _merge_runner_capabilities(
        host_runner.capabilities_json,
        capabilities=dict(payload.capabilities or {}),
        runtime_kind=payload.runtime_kind,
        install_mode=payload.install_mode,
        service_mode=payload.service_mode,
        host_facts=dict(payload.host_facts or {}),
        compatibility_issues=list(payload.compatibility_issues or []),
    )
    host_runner.install_status = "installed"
    host_runner.status = "online"
    host_runner.last_seen_at = datetime.now(timezone.utc)
    host_runner.last_error = None
    db.add(host_runner)
    db.commit()
    db.refresh(host_runner)
    return RunnerRegisterResponse(
        runner_id=host_runner.id,
        runner_token=runner_token,
        poll_interval_seconds=_runner_poll_interval_seconds(),
    )


def authenticate_runner(db: Session, token: str) -> HostRunner | None:
    token_hash = hash_runner_token(token)
    runner = db.scalar(select(HostRunner).where(HostRunner.token_hash == token_hash))
    return runner


def record_runner_heartbeat(db: Session, runner: HostRunner, payload: RunnerHeartbeatRequest) -> HostRunnerRead:
    runner.status = str(payload.status or runner.status or "online").strip().lower() or "online"
    runner.version = payload.version or runner.version or RUNNER_VERSION
    runner.capabilities_json = _merge_runner_capabilities(
        runner.capabilities_json,
        capabilities=dict(payload.capabilities or {}),
        runtime_kind=payload.runtime_kind,
        install_mode=payload.install_mode,
        service_mode=payload.service_mode,
        host_facts=dict(payload.host_facts or {}),
        compatibility_issues=list(payload.compatibility_issues or []),
    )
    runner.last_error = payload.last_error
    runner.last_seen_at = datetime.now(timezone.utc)
    db.add(runner)
    db.commit()
    db.refresh(runner)
    return serialize_host_runner(runner.asset_id, runner)


def poll_runner_assignments(db: Session, runner: HostRunner, max_tasks: int = 1) -> RunnerPollResponse:
    assignments: list[RunnerTaskAssignmentRead] = []
    next_task_id: str | None = None
    next_summary: str | None = None
    next_execution_script_b64: str | None = None
    task_stmt = select_task_runs_for_runner(runner.asset_id)
    tasks = db.execute(task_stmt).scalars().all()
    for task in tasks:
        if len(assignments) >= max(1, max_tasks):
            break
        result_json = task.result_json if isinstance(task.result_json, dict) else {}
        context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
        if not context.get("session_id"):
            continue
        plan = result_json.get("plan") if isinstance(result_json.get("plan"), dict) else {}
        execution = result_json.get("execution") if isinstance(result_json.get("execution"), dict) else {}
        submitted_steps = execution.get("submitted_steps") if isinstance(execution.get("submitted_steps"), list) else []
        submitted_step_ids = {
            str(item.get("step_id") or "").strip()
            for item in submitted_steps
            if isinstance(item, dict) and str(item.get("step_id") or "").strip()
        }
        all_steps = plan.get("steps") if isinstance(plan.get("steps"), list) else []
        steps = [
            step for step in all_steps
            if isinstance(step, dict) and (not submitted_step_ids or str(step.get("step_id") or "").strip() in submitted_step_ids)
        ]
        stage_name = str(execution.get("stage_name") or context.get("stage_name") or "").strip()
        assignment = RunnerTaskAssignmentRead(
            task_id=task.id,
            asset_id=runner.asset_id,
            session_id=context.get("session_id"),
            task_type="remediation_execute",
            summary=stage_name or str((plan.get("summary_text") or plan.get("summary") or "整机修复计划")).strip(),
            execution_mode="apply",
            plan=plan,
            steps=[
                RunnerTaskStepRead(
                    step_id=str(step.get("step_id") or ""),
                    title=str(step.get("title") or step.get("step_id") or ""),
                    action_type=str(step.get("action_type") or ""),
                    generated_command=str(step.get("generated_command") or "").strip() or None,
                    execution_state="blocked" if str(step.get("execution_state") or "").strip().lower() == "blocked" else "ready",
                    blocked_reason=str(step.get("blocked_reason") or "").strip() or None,
                    backup_plan=step.get("backup_plan"),
                    risk_level=str(step.get("risk_level") or "medium"),
                    idempotent=bool(step.get("idempotent")),
                    dry_run_supported=bool(step.get("dry_run_supported")),
                    rollback_supported=bool(step.get("rollback_supported")),
                    evidence_items=[str(item).strip() for item in (step.get("evidence_items") or []) if str(item).strip()],
                    requires_maintenance_window=bool(step.get("requires_maintenance_window")),
                    adapter_id=str(step.get("adapter_id") or "").strip() or None,
                    adapter_version=str(step.get("adapter_version") or "").strip() or None,
                )
                for step in steps
                if isinstance(step, dict)
            ],
        )
        result_json.setdefault("context", {})
        result_json["context"]["runner_id"] = runner.id
        result_json["context"]["runner_status"] = _runner_status_value(runner)
        update_task_run(
            db,
            task,
            status=TaskExecutionStatus.RUNNING,
            progress=max(10, task.progress),
            message="Host Runner 已接单，开始执行整机修复计划",
            result_json=result_json,
        )
        create_task_event(
            db,
            task_run_id=task.id,
            event_type="stage",
            level="info",
            stage_code="runner_dispatch",
            stage_name="Runner 接单",
            message="Host Runner 已获取待执行计划",
            progress=task.progress,
            payload_json={"runner_id": runner.id},
        )
        assignments.append(assignment)
        if next_task_id is None:
            next_task_id = assignment.task_id
            next_summary = assignment.summary
            next_execution_script_b64 = base64.b64encode(
                _build_assignment_execution_script(task_id=task.id, summary=assignment.summary, steps=assignment.steps).encode("utf-8")
            ).decode("ascii")
    runner.last_seen_at = datetime.now(timezone.utc)
    runner.status = "busy" if assignments else "online"
    db.add(runner)
    db.commit()
    return RunnerPollResponse(
        assignments=assignments,
        poll_interval_seconds=_runner_poll_interval_seconds(),
        next_task_id=next_task_id,
        next_summary=next_summary,
        next_execution_script_b64=next_execution_script_b64,
    )


def append_runner_task_events(db: Session, runner: HostRunner, task_id: str, batch: RunnerTaskEventBatch) -> None:
    task = get_task_run(db, task_id)
    if task is None or task.task_type != TaskType.REMEDIATION_EXECUTE:
        raise RuntimeError("修复任务不存在")
    runner.last_seen_at = datetime.now(timezone.utc)
    runner.status = "busy"
    db.add(runner)
    for item in batch.events:
        create_task_event(
            db,
            task_run_id=task_id,
            event_type=item.event_type,
            level=item.level,
            stage_code=item.stage_code,
            stage_name=item.stage_name,
            message=item.message,
            progress=item.progress,
            payload_json=dict(item.payload_json or {}),
        )
        if item.progress is not None or item.message:
            update_task_run(
                db,
                task,
                progress=item.progress if item.progress is not None else task.progress,
                message=item.message if item.message is not None else task.message,
                commit=False,
                refresh=False,
            )
    db.commit()


def complete_runner_task(db: Session, runner: HostRunner, task_id: str, payload: RunnerTaskCompleteRequest) -> dict[str, Any]:
    task = get_task_run(db, task_id)
    if task is None or task.task_type != TaskType.REMEDIATION_EXECUTE:
        raise RuntimeError("修复任务不存在")
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    execution = dict(payload.execution or {})
    if payload.step_results:
        execution["step_results"] = [item.model_dump(mode="json") for item in payload.step_results]
    backups = dict(payload.backups or execution.get("backup_map") or {})
    step_results = execution.get("step_results") if isinstance(execution.get("step_results"), list) else []
    success_count = int(execution.get("success_count") or 0)
    if step_results and success_count <= 0:
        success_count = sum(1 for item in step_results if isinstance(item, dict) and str(item.get("status") or "").strip() == "success")
    execution["success_count"] = success_count
    failed_count = int(execution.get("failed_count") or 0)
    if step_results and failed_count <= 0:
        failed_count = sum(1 for item in step_results if isinstance(item, dict) and str(item.get("status") or "").strip() == "failed")
    execution["failed_count"] = failed_count
    reverify = {"reverify_triggered": False, "reverify_task_id": None, "reverify_status": None}
    if bool(settings.REMEDIATION_AUTO_REVERIFY_ENABLED) and success_count > 0:
        reverify_task = create_task_run(
            db,
            task_type=TaskType.RISK_VERIFY,
            scope_type="asset",
            scope_id=runner.asset_id,
            message="风险验证任务已入队",
        )
        celery_task = run_risk_verify_task.delay(reverify_task.id, runner.asset_id)
        update_task_run(db, reverify_task, celery_task_id=celery_task.id)
        reverify = {
            "reverify_triggered": True,
            "reverify_task_id": reverify_task.id,
            "reverify_status": "pending",
        }
        create_task_event(
            db,
            task_run_id=task.id,
            event_type="reverify",
            level="info",
            stage_code="auto_reverify",
            stage_name="自动复测",
            message="修复后已自动触发风险复测",
            payload_json=reverify,
        )

    execution_mode = str(execution.get("execution_mode") or "apply").strip().lower() or "apply"
    if failed_count > 0 or payload.status == "failure":
        overall_status = "apply_failed"
        final_message = payload.message or f"共有 {failed_count or 1} 个 Runner 修复步骤执行失败"
    elif reverify.get("reverify_triggered"):
        overall_status = "applied_pending_reverify"
        final_message = payload.message or "Host Runner 已执行修复命令，自动复测已触发，等待复测结论"
    else:
        overall_status = "applied"
        final_message = payload.message or "Host Runner 已完成整机修复计划"
    execution["execution_mode"] = execution_mode
    execution["overall_status"] = overall_status
    execution["final_message"] = final_message
    plan = result_json.get("plan") if isinstance(result_json.get("plan"), dict) else {}
    execution_context = result_json.get("execution") if isinstance(result_json.get("execution"), dict) else {}
    submitted_steps = execution_context.get("submitted_steps") if isinstance(execution_context.get("submitted_steps"), list) else []
    submitted_step_ids = {
        str(item.get("step_id") or "").strip()
        for item in submitted_steps
        if isinstance(item, dict) and str(item.get("step_id") or "").strip()
    }
    selected_steps = [
        dict(step)
        for step in (plan.get("steps") or [])
        if isinstance(step, dict) and (not submitted_step_ids or str(step.get("step_id") or "").strip() in submitted_step_ids)
    ]
    result_json["evidence"] = build_remediation_evidence(
        task_id=task.id,
        plan=plan,
        selected_steps=selected_steps,
        execution_mode=execution_mode,
        execution_boundary=str(execution.get("execution_boundary") or "runner_dispatch"),
        step_results=[dict(item) for item in step_results if isinstance(item, dict)],
        reverify=reverify,
        change_ticket=str(execution_context.get("change_ticket") or execution.get("change_ticket") or "").strip() or None,
        maintenance_window_id=str(execution_context.get("maintenance_window_id") or execution.get("maintenance_window_id") or "").strip() or None,
        stage_code=str(execution_context.get("stage_code") or "").strip() or None,
        stage_name=str(execution_context.get("stage_name") or "").strip() or None,
    )
    result_json["execution"] = execution
    result_json["backups"] = backups
    result_json["reverify"] = reverify
    result_json.setdefault("context", {})
    result_json["context"]["runner_id"] = runner.id
    status = TaskExecutionStatus.SUCCESS if overall_status != "apply_failed" else TaskExecutionStatus.FAILURE
    update_task_run(
        db,
        task,
        status=status,
        progress=100,
        message=final_message,
        result_json=result_json,
    )
    create_task_event(
        db,
        task_run_id=task.id,
        event_type="success" if status == TaskExecutionStatus.SUCCESS else "failure",
        level="info" if status == TaskExecutionStatus.SUCCESS else "error",
        message=final_message,
        progress=100,
        payload_json=result_json,
    )
    runner.last_seen_at = datetime.now(timezone.utc)
    runner.status = "online"
    runner.last_error = None if payload.status == "success" else payload.message
    db.add(runner)
    session_id = ((result_json.get("context") or {}) if isinstance(result_json.get("context"), dict) else {}).get("session_id")
    committed = False
    if session_id:
        session = db.get(RemediationSession, session_id)
        if session is not None:
            context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
            stage_code = str(context.get("stage_code") or "").strip() or None
            summary_json = dict(session.summary_json or {}) if isinstance(session.summary_json, dict) else {}
            completed_stage_codes = [
                str(item).strip()
                for item in (summary_json.get("completed_stage_codes") or [])
                if str(item).strip()
            ]
            if payload.status == "success" and stage_code and stage_code not in completed_stage_codes:
                completed_stage_codes.append(stage_code)
            summary_json["completed_stage_codes"] = completed_stage_codes
            summary_json["running_stage_code"] = None
            session.summary_json = summary_json
            session.status = "draft" if payload.status == "success" else "failed"
            session.last_task_id = task.id
            session.updated_at = datetime.now(timezone.utc)
            db.add(session)
            from app.services.remediation_session_service import get_remediation_session_read

            get_remediation_session_read(db, session_id, queue_ai=True)
            committed = True
    if not committed:
        db.commit()
    return result_json


def _b64_encode_text(value: str | None) -> str:
    return base64.b64encode(str(value or "").encode("utf-8")).decode("ascii")


def _build_assignment_execution_script(*, task_id: str, summary: str, steps: list[RunnerTaskStepRead]) -> str:
    encoded_summary = _b64_encode_text(summary)
    lines = [
        "#!/bin/sh",
        "set -eu",
        f"TASK_ID={shlex.quote(task_id)}",
        f"SUMMARY_B64={shlex.quote(encoded_summary)}",
        'PLATFORM_URL="${SA_RUNNER_PLATFORM_URL:-}"',
        'RUNNER_TOKEN="${SA_RUNNER_TOKEN:-}"',
        'HTTP_TOOL="${SA_RUNNER_HTTP_TOOL:-}"',
        'STEP_TIMEOUT_SECONDS="${SA_RUNNER_STEP_TIMEOUT_SECONDS:-180}"',
        'JSON_PYTHON_BIN=""',
        "",
        'decode_b64() {',
        '  value="${1:-}"',
        '  if [ -z "$value" ]; then',
        "    return 0",
        "  fi",
        "  if command -v base64 >/dev/null 2>&1; then",
        '    printf "%s" "$value" | base64 -d 2>/dev/null && return 0',
        '    printf "%s" "$value" | base64 --decode 2>/dev/null && return 0',
        "  fi",
        "  if command -v openssl >/dev/null 2>&1; then",
        '    printf "%s" "$value" | openssl base64 -d -A 2>/dev/null && return 0',
        "  fi",
        "  return 1",
        "}",
        "",
        'resolve_json_python() {',
        '  if [ -n "$JSON_PYTHON_BIN" ]; then',
        "    return 0",
        "  fi",
        '  if command -v python3 >/dev/null 2>&1; then',
        '    if python3 -c "import json" >/dev/null 2>&1; then',
        '      JSON_PYTHON_BIN="$(command -v python3)"',
        "      return 0",
        "    fi",
        "  fi",
        '  if command -v python >/dev/null 2>&1; then',
        '    if python -c "import json" >/dev/null 2>&1; then',
        '      JSON_PYTHON_BIN="$(command -v python)"',
        "      return 0",
        "    fi",
        "  fi",
        "  return 1",
        "}",
        "",
        'json_escape_fallback() {',
        '  printf "%s" "${1:-}" | LC_ALL=C tr -d \'\\000-\\010\\013\\014\\016-\\037\' | sed \':a;N;$!ba;s/\\\\/\\\\\\\\/g;s/"/\\\\\\"/g;s/\\n/\\\\n/g\'',
        "}",
        "",
        'json_quote() {',
        '  if resolve_json_python; then',
        '    printf "%s" "${1:-}" | "$JSON_PYTHON_BIN" -c \'import json, sys; sys.stdout.write(json.dumps(sys.stdin.read(), ensure_ascii=False))\'',
        "    return 0",
        "  fi",
        '  printf \'\"%s\"\' \"$(json_escape_fallback \"${1:-}\")\"',
        "}",
        "",
        'json_string_or_null() {',
        '  if [ -n "${1:-}" ]; then',
        '    json_quote "$1"',
        "  else",
        "    printf 'null'",
        "  fi",
        "}",
        "",
        'http_post_json() {',
        '  path="$1"',
        '  body="$2"',
        '  if [ "$HTTP_TOOL" = "curl" ]; then',
        '    curl -fsS --connect-timeout 5 --max-time 30 -X POST -H "Content-Type: application/json" -H "X-Runner-Token: $RUNNER_TOKEN" --data "$body" "${PLATFORM_URL%/}$path"',
        "    return $?",
        "  fi",
        '  wget -qO- --timeout=30 --header="Content-Type: application/json" --header="X-Runner-Token: $RUNNER_TOKEN" --post-data="$body" "${PLATFORM_URL%/}$path"',
        "}",
        "",
        'post_events() {',
        '  http_post_json "/api/v1/runner/tasks/$TASK_ID/events" "$1" >/dev/null 2>&1 || true',
        "}",
        "",
        'emit_stage() {',
        '  event_type="$1"',
        '  stage_code="$2"',
        '  stage_name="$3"',
        '  message_text="$4"',
        '  progress_value="$5"',
        '  payload_json="$6"',
        '  body=$(printf \'{"events":[{"event_type":%s,"stage_code":%s,"stage_name":%s,"message":%s,"progress":%s,"payload_json":%s}]}\' "$(json_quote "$event_type")" "$(json_quote "$stage_code")" "$(json_quote "$stage_name")" "$(json_string_or_null "$message_text")" "$progress_value" "$payload_json")',
        '  post_events "$body"',
        "}",
        "",
        'emit_stream_line() {',
        '  step_id="$1"',
        '  line_text="$(printf "%s" "${2:-}" | cut -c1-800)"',
        '  payload_json=$(printf \'{"step_id":%s,"stream":"stdout","text":%s}\' "$(json_quote "$step_id")" "$(json_quote "$line_text")")',
        '  body=$(printf \'{"events":[{"event_type":"stream","stage_code":"execute_steps","stage_name":"Runner 执行步骤","message":%s,"payload_json":%s}]}\' "$(json_string_or_null "$(printf "%s" "$line_text" | cut -c1-255)")" "$payload_json")',
        '  post_events "$body"',
        "}",
        "",
        'append_step_result() {',
        '  if [ -n "$STEP_RESULTS_JSON" ]; then',
        '    STEP_RESULTS_JSON="$STEP_RESULTS_JSON,$1"',
        "  else",
        '    STEP_RESULTS_JSON="$1"',
        "  fi",
        "}",
        "",
        'run_command_with_timeout() {',
        '  command_text="$1"',
        '  output_file="$2"',
        '  timeout_seconds="${3:-180}"',
        '  timeout_marker="$(mktemp "${TASK_ID}.timeout.XXXXXX")"',
        '  rm -f "$timeout_marker"',
        '  sh -lc "$command_text" >"$output_file" 2>&1 &',
        '  command_pid="$!"',
        '  (',
        '    sleep "$timeout_seconds"',
        '    if kill -0 "$command_pid" >/dev/null 2>&1; then',
        '      : >"$timeout_marker"',
        '      kill "$command_pid" >/dev/null 2>&1 || true',
        '      sleep 2',
        '      kill -9 "$command_pid" >/dev/null 2>&1 || true',
        '    fi',
        '  ) &',
        '  watcher_pid="$!"',
        '  wait "$command_pid"',
        '  exit_code="$?"',
        '  kill "$watcher_pid" >/dev/null 2>&1 || true',
        '  wait "$watcher_pid" 2>/dev/null || true',
        '  if [ -f "$timeout_marker" ]; then',
        '    rm -f "$timeout_marker"',
        '    return 124',
        '  fi',
        '  rm -f "$timeout_marker"',
        '  return "$exit_code"',
        "}",
        "",
        'json_array_from_file_tail() {',
        '  file_path="$1"',
        '  limit="${2:-20}"',
        '  if [ ! -f "$file_path" ]; then',
        "    printf '[]'",
        "    return 0",
        "  fi",
        '  tail_file="$(mktemp)"',
        '  tail -n "$limit" "$file_path" >"$tail_file" 2>/dev/null || cat "$file_path" >"$tail_file" 2>/dev/null || true',
        '  json_items=""',
        '  while IFS= read -r raw_line || [ -n "$raw_line" ]; do',
        '    item="$(json_quote "$raw_line")"',
        '    if [ -n "$json_items" ]; then',
        '      json_items="$json_items,$item"',
        "    else",
        '      json_items="$item"',
        "    fi",
        '  done < "$tail_file"',
        '  rm -f "$tail_file"',
        '  printf \'[%s]\' "$json_items"',
        "}",
        "",
        'build_backup_paths_json() {',
        '  backup_kind="${1:-}"',
        '  encoded_targets="${2:-}"',
        '  if [ -z "$backup_kind" ] || [ -z "$encoded_targets" ]; then',
        "    printf '[]'",
        "    return 0",
        "  fi",
        '  targets_content="$(decode_b64 "$encoded_targets" 2>/dev/null || true)"',
        '  if [ -z "$targets_content" ]; then',
        "    printf '[]'",
        "    return 0",
        "  fi",
        '  old_ifs="$IFS"',
        "  IFS='",
        "'",
        '  json_items=""',
        '  for target in $targets_content; do',
        '    [ -n "$target" ] || continue',
        '    item_value=""',
        '    if [ "$backup_kind" = "file_copy" ] && [ -e "$target" ]; then',
        '      backup_path="${target}.bak.sa.$(date +"%Y%m%d%H%M%S")"',
        '      cp -p "$target" "$backup_path" >/dev/null 2>&1 || cp "$target" "$backup_path" >/dev/null 2>&1 || true',
        '      if [ -e "$backup_path" ]; then',
        '        item_value="$backup_path"',
        "      fi",
        '    elif [ "$backup_kind" = "permission_snapshot" ] && [ -e "$target" ]; then',
        '      stat_value="$(stat -c "%a|%u|%g" "$target" 2>/dev/null || true)"',
        '      if [ -n "$stat_value" ]; then',
        '        item_value="${target}|${stat_value}"',
        "      fi",
        "    fi",
        '    if [ -n "$item_value" ]; then',
        '      item_json="$(json_quote "$item_value")"',
        '      if [ -n "$json_items" ]; then',
        '        json_items="$json_items,$item_json"',
        "      else",
        '        json_items="$item_json"',
        "      fi",
        "    fi",
        "  done",
        '  IFS="$old_ifs"',
        '  printf \'[%s]\' "$json_items"',
        "}",
        "",
        'run_step() {',
        '  index="$1"',
        '  total="$2"',
        '  step_id_b64="$3"',
        '  title_b64="$4"',
        '  execution_state="$5"',
        '  command_b64="$6"',
        '  blocked_reason_b64="$7"',
        '  backup_kind="${8:-}"',
        '  backup_targets_b64="${9:-}"',
        '  step_id="$(decode_b64 "$step_id_b64" 2>/dev/null || true)"',
        '  title="$(decode_b64 "$title_b64" 2>/dev/null || true)"',
        '  command_text="$(decode_b64 "$command_b64" 2>/dev/null || true)"',
        '  blocked_reason="$(decode_b64 "$blocked_reason_b64" 2>/dev/null || true)"',
        '  if [ "$execution_state" = "blocked" ]; then',
        '    result_json=$(printf \'{"step_id":%s,"title":%s,"status":"blocked","generated_command":null,"exit_status":null,"backup_paths":[],"output_tail":[],"started_at":null,"finished_at":null,"error":%s}\' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_string_or_null "$blocked_reason")")',
        '    append_step_result "$result_json"',
        "    return 0",
        "  fi",
        '  EXECUTED_COUNT=$((EXECUTED_COUNT + 1))',
        '  progress_value=$((10 + (index * 70 / total)))',
        '  emit_stage "stage" "execute_steps" "Runner 执行步骤" "$title" "$progress_value" "{}"',
        '  backup_paths_json="$(build_backup_paths_json "$backup_kind" "$backup_targets_b64")"',
        '  output_file="$(mktemp)"',
        '  started_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"',
        '  if run_command_with_timeout "$command_text" "$output_file" "$STEP_TIMEOUT_SECONDS"; then',
        '    step_status="success"',
        '    exit_code="0"',
        '    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))',
        "  else",
        '    step_status="failure"',
        '    exit_code="$?"',
        '    FAILED_COUNT=$((FAILED_COUNT + 1))',
        '    FINAL_STATUS="failure"',
        "  fi",
        '  if [ "$step_status" != "success" ] && [ "$exit_code" = "124" ]; then',
        '    printf "%s\n" "步骤执行超时，已在 ${STEP_TIMEOUT_SECONDS}s 后终止" >>"$output_file"',
        "  fi",
        '  line_count="0"',
        '  while IFS= read -r line || [ -n "$line" ]; do',
        '    [ -n "$line" ] || continue',
        '    emit_stream_line "$step_id" "$line"',
        '    line_count=$((line_count + 1))',
        '    if [ "$line_count" -ge 80 ]; then',
        "      break",
        "    fi",
        "  done < \"$output_file\"",
        '  finished_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"',
        '  error_text=""',
        '  if [ "$step_status" != "success" ]; then',
        '    if [ "$exit_code" = "124" ]; then',
        '      error_text="命令执行超时，已超过 ${STEP_TIMEOUT_SECONDS}s"',
        '    else',
        '      error_text="命令执行失败，退出码 $exit_code"',
        '    fi',
        "  fi",
        '  output_tail_json="$(json_array_from_file_tail "$output_file")"',
        '  result_json=$(printf \'{"step_id":%s,"title":%s,"status":%s,"generated_command":%s,"exit_status":%s,"backup_paths":%s,"output_tail":%s,"started_at":%s,"finished_at":%s,"error":%s}\' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_quote "$step_status")" "$(json_string_or_null "$command_text")" "$exit_code" "$backup_paths_json" "$output_tail_json" "$(json_quote "$started_at")" "$(json_quote "$finished_at")" "$(json_string_or_null "$error_text")")',
        '  append_step_result "$result_json"',
        '  if [ "$step_status" != "success" ]; then',
        '    LAST_FAILURE_TITLE="$title"',
        '    LAST_FAILURE_ERROR="$error_text"',
        "  fi",
        '  rm -f "$output_file"',
        '  if [ "$step_status" != "success" ]; then',
        "    return 1",
        "  fi",
        "  return 0",
        "}",
        "",
        'if [ -z "$PLATFORM_URL" ] || [ -z "$RUNNER_TOKEN" ]; then',
        '  exit 91',
        "fi",
        'EXECUTED_COUNT="0"',
        'SUCCESS_COUNT="0"',
        'FAILED_COUNT="0"',
        'FINAL_STATUS="success"',
        'STEP_RESULTS_JSON=""',
        'LAST_FAILURE_TITLE=""',
        'LAST_FAILURE_ERROR=""',
        'summary_text="$(decode_b64 "$SUMMARY_B64" 2>/dev/null || printf "整机修复计划")"',
        'emit_stage "stage" "execute_steps" "Runner 执行步骤" "Host Runner 已开始执行整机修复计划" "10" "$(printf \'{"assignment":%s}\' "$(json_quote "$summary_text")")"',
    ]
    total_steps = max(1, len(steps))
    for index, step in enumerate(steps, start=1):
        backup_plan = step.backup_plan.model_dump(mode="json") if step.backup_plan is not None else {}
        backup_kind = str(backup_plan.get("kind") or "").strip()
        backup_targets = [str(item).strip() for item in backup_plan.get("targets", []) if str(item).strip()]
        lines.append(
            "run_step "
            + " ".join(
                [
                    str(index),
                    str(total_steps),
                    shlex.quote(_b64_encode_text(step.step_id)),
                    shlex.quote(_b64_encode_text(step.title)),
                    shlex.quote(step.execution_state),
                    shlex.quote(_b64_encode_text(step.generated_command or "")),
                    shlex.quote(_b64_encode_text(step.blocked_reason or "")),
                    shlex.quote(backup_kind),
                    shlex.quote(_b64_encode_text("\n".join(backup_targets))),
                ]
            )
            + " || break"
        )
    lines.extend(
        [
            'if [ -n "$STEP_RESULTS_JSON" ]; then',
            '  STEP_RESULTS_PAYLOAD="[$STEP_RESULTS_JSON]"',
            "else",
            '  STEP_RESULTS_PAYLOAD="[]"',
            "fi",
            'if [ "$FINAL_STATUS" = "success" ]; then',
            '  final_message="Host Runner 已完成整机修复计划"',
            "else",
            '  if [ -n "$LAST_FAILURE_TITLE" ]; then',
            '    final_message="Host Runner 执行失败：$LAST_FAILURE_TITLE"',
            "  else",
            '    final_message="Host Runner 执行失败，请查看任务输出"',
            "  fi",
            "fi",
            'complete_payload=$(printf \'{"status":%s,"execution":{"executed_count":%s,"success_count":%s,"failed_count":%s,"execution_boundary":"runner_dispatch"},"backups":{},"step_results":%s,"message":%s}\' "$(json_quote "$FINAL_STATUS")" "$EXECUTED_COUNT" "$SUCCESS_COUNT" "$FAILED_COUNT" "$STEP_RESULTS_PAYLOAD" "$(json_quote "$final_message")")',
            'http_post_json "/api/v1/runner/tasks/$TASK_ID/complete" "$complete_payload" >/dev/null',
        ]
    )
    return "\n".join(lines) + "\n"


def select_task_runs_for_runner(asset_id: str):
    from app.db.models.task_run import TaskRun

    return (
        select(TaskRun)
        .where(
            TaskRun.task_type == TaskType.REMEDIATION_EXECUTE,
            TaskRun.scope_type == "asset",
            TaskRun.scope_id == asset_id,
            TaskRun.status == TaskExecutionStatus.PENDING,
        )
        .order_by(TaskRun.created_at.asc())
    )


def _wait_for_runner_registration(runner_id: str) -> None:
    deadline = time.time() + 40
    while time.time() < deadline:
        with SessionLocal() as db:
            runner = db.get(HostRunner, runner_id)
            if runner is not None and runner.token_hash and runner.last_seen_at:
                return
        time.sleep(2)
    raise RuntimeError("Host Runner 服务已启动，但未在预期时间内回连平台注册")


def _parse_key_value_output(raw: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in str(raw or "").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if not key:
            continue
        result[key] = value.strip()
    return result


def _bool_from_probe(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


async def _probe_remote_runner_install(connection: Any, *, platform_url: str, sudo_password: str | None) -> RunnerInstallProbe:
    health_url = f"{platform_url.rstrip('/')}/health"
    encoded_sudo_password = _b64_encode_text(sudo_password or "")
    command = "\n".join(
        [
            f'SUDO_PASSWORD_B64={shlex.quote(encoded_sudo_password)}',
            'UNAME_S="$(uname -s 2>/dev/null || echo unknown)"',
            'UNAME_M="$(uname -m 2>/dev/null || echo unknown)"',
            'OS_RELEASE_ID=""',
            'OS_RELEASE_LIKE=""',
            'if [ -r /etc/os-release ]; then',
            '  OS_RELEASE_ID="$(sed -n \'s/^ID=//p\' /etc/os-release | head -n 1 | tr -d \'"\' | tr \'[:upper:]\' \'[:lower:]\')"',
            '  OS_RELEASE_LIKE="$(sed -n \'s/^ID_LIKE=//p\' /etc/os-release | head -n 1 | tr -d \'"\' | tr \'[:upper:]\' \'[:lower:]\')"',
            'fi',
            'if [ -z "$OS_RELEASE_ID" ] && [ -r /etc/debian_version ]; then',
            '  OS_RELEASE_ID="debian"',
            'fi',
            'if [ -z "$OS_RELEASE_LIKE" ] && [ -n "$OS_RELEASE_ID" ]; then',
            '  OS_RELEASE_LIKE="$OS_RELEASE_ID"',
            'fi',
            'IS_ROOT="0"',
            'if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then IS_ROOT="1"; fi',
            'SUDO_PASSWORD=""',
            'if [ -n "$SUDO_PASSWORD_B64" ]; then',
            '  if command -v base64 >/dev/null 2>&1; then',
            '    SUDO_PASSWORD="$(printf "%s" "$SUDO_PASSWORD_B64" | base64 -d 2>/dev/null || printf "%s" "$SUDO_PASSWORD_B64" | base64 --decode 2>/dev/null || true)"',
            '  elif command -v openssl >/dev/null 2>&1; then',
            '    SUDO_PASSWORD="$(printf "%s" "$SUDO_PASSWORD_B64" | openssl base64 -d -A 2>/dev/null || true)"',
            '  fi',
            'fi',
            'HAS_SUDO="0"',
            'if command -v sudo >/dev/null 2>&1; then HAS_SUDO="1"; fi',
            'SUDO_NOPASSWD="0"',
            'if [ "$HAS_SUDO" = "1" ] && sudo -n true >/dev/null 2>&1; then SUDO_NOPASSWD="1"; fi',
            'SUDO_PASSWORD_WORKS="0"',
            'if [ "$HAS_SUDO" = "1" ] && [ -n "$SUDO_PASSWORD" ] && printf "%s\\n" "$SUDO_PASSWORD" | sudo -S -p "" true >/dev/null 2>&1; then SUDO_PASSWORD_WORKS="1"; fi',
            'HAS_SYSTEMD="0"',
            'if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then HAS_SYSTEMD="1"; fi',
            'HAS_SYSVINIT="0"',
            'if command -v service >/dev/null 2>&1 || [ -d /etc/init.d ]; then HAS_SYSVINIT="1"; fi',
            'HAS_CRONTAB="0"',
            'if command -v crontab >/dev/null 2>&1; then HAS_CRONTAB="1"; fi',
            'HAS_USER_SYSTEMD="0"',
            'if command -v systemctl >/dev/null 2>&1; then HAS_USER_SYSTEMD="1"; fi',
            'HAS_BASH="0"',
            'if command -v bash >/dev/null 2>&1; then HAS_BASH="1"; fi',
            'HAS_SH="0"',
            'if command -v sh >/dev/null 2>&1; then HAS_SH="1"; fi',
            'HAS_TAR="0"',
            'if command -v tar >/dev/null 2>&1; then HAS_TAR="1"; fi',
            'HAS_MKTEMP="0"',
            'if command -v mktemp >/dev/null 2>&1; then HAS_MKTEMP="1"; fi',
            'PACKAGE_MANAGER="none"',
            'if command -v apt-get >/dev/null 2>&1; then',
            '  PACKAGE_MANAGER="apt"',
            'elif command -v dnf >/dev/null 2>&1; then',
            '  PACKAGE_MANAGER="dnf"',
            'elif command -v yum >/dev/null 2>&1; then',
            '  PACKAGE_MANAGER="yum"',
            'elif command -v apk >/dev/null 2>&1; then',
            '  PACKAGE_MANAGER="apk"',
            'elif command -v zypper >/dev/null 2>&1; then',
            '  PACKAGE_MANAGER="zypper"',
            'fi',
            'HTTP_TOOL="none"',
            'PLATFORM_OK="0"',
            f'HEALTH_URL={shlex.quote(health_url)}',
            'if command -v curl >/dev/null 2>&1; then',
            '  HTTP_TOOL="curl"',
            '  curl -fsS --connect-timeout 5 --max-time 10 "$HEALTH_URL" >/dev/null 2>&1 && PLATFORM_OK="1" || true',
            'elif command -v wget >/dev/null 2>&1; then',
            '  HTTP_TOOL="wget"',
            '  wget -qO- --timeout=10 "$HEALTH_URL" >/dev/null 2>&1 && PLATFORM_OK="1" || true',
            'fi',
            'echo "detected_os=$UNAME_S"',
            'echo "detected_arch=$UNAME_M"',
            'echo "os_release_like=$OS_RELEASE_LIKE"',
            'echo "is_root=$IS_ROOT"',
            'echo "has_sudo=$HAS_SUDO"',
            'echo "sudo_nopasswd=$SUDO_NOPASSWD"',
            'echo "sudo_password_works=$SUDO_PASSWORD_WORKS"',
            'echo "has_systemd=$HAS_SYSTEMD"',
            'echo "has_sysvinit=$HAS_SYSVINIT"',
            'echo "has_crontab=$HAS_CRONTAB"',
            'echo "has_user_systemd=$HAS_USER_SYSTEMD"',
            'echo "has_bash=$HAS_BASH"',
            'echo "has_sh=$HAS_SH"',
            'echo "has_tar=$HAS_TAR"',
            'echo "has_mktemp=$HAS_MKTEMP"',
            'echo "package_manager=$PACKAGE_MANAGER"',
            'echo "http_tool=$HTTP_TOOL"',
            'echo "platform_ok=$PLATFORM_OK"',
        ]
    )
    result = await connection.run(f"sh -lc {shlex.quote(command)}", check=False)
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    if int(getattr(result, "exit_status", 1) or 0) != 0:
        raise RunnerInstallError(stderr.strip() or stdout.strip() or "无法探测目标主机的 Runner 安装能力")
    parsed = _parse_key_value_output(stdout)
    detected_os = str(parsed.get("detected_os") or "").strip().lower()
    raw_arch = str(parsed.get("detected_arch") or "").strip().lower() or "unknown"
    http_tool = str(parsed.get("http_tool") or "none").strip().lower()
    package_manager = str(parsed.get("package_manager") or "none").strip().lower()
    os_release_like = str(parsed.get("os_release_like") or "").strip().lower()
    has_sudo = _bool_from_probe(parsed.get("has_sudo"))
    sudo_nopasswd = _bool_from_probe(parsed.get("sudo_nopasswd"))
    sudo_password_works = _bool_from_probe(parsed.get("sudo_password_works"))
    can_system_install = _bool_from_probe(parsed.get("is_root")) or sudo_nopasswd or sudo_password_works
    compatibility_issues: list[str] = []
    if raw_arch not in _RUNNER_PRIMARY_ARCHES:
        _append_compatibility_issue(compatibility_issues, f"检测到目标机架构 {raw_arch}，将按通用 Shell Runner 兼容路径安装")
    has_bash = _bool_from_probe(parsed.get("has_bash"))
    has_sh = _bool_from_probe(parsed.get("has_sh"))
    has_tar = _bool_from_probe(parsed.get("has_tar"))
    has_mktemp = _bool_from_probe(parsed.get("has_mktemp"))
    missing_tools: list[str] = []
    if not has_bash:
        missing_tools.append("bash")
    if not has_tar:
        missing_tools.append("tar")
    if not has_mktemp:
        missing_tools.append("mktemp")
    if http_tool == "none":
        missing_tools.append("curl/wget")
    if has_sudo and sudo_password and not sudo_nopasswd and not sudo_password_works:
        if missing_tools:
            _append_compatibility_issue(compatibility_issues, "当前提供的 sudo 凭据不可用，若缺少 Runner 依赖将无法自动补齐")
        else:
            _append_compatibility_issue(compatibility_issues, "当前提供的 sudo 凭据不可用，将回退到用户态安装")
    if not can_system_install and not missing_tools:
        _append_compatibility_issue(compatibility_issues, "当前未检测到可用的 root/sudo，将优先尝试用户态安装")
    if not _bool_from_probe(parsed.get("has_systemd")):
        _append_compatibility_issue(compatibility_issues, "当前主机未检测到 systemd，将回退到其他托管方式")
    bootstrap_needed = bool(missing_tools)
    bootstrap_supported = bootstrap_needed and _supports_runner_bootstrap(package_manager)
    bootstrap_status = "pending" if bootstrap_supported else ("unsupported" if bootstrap_needed else "not_needed")
    return RunnerInstallProbe(
        detected_os=detected_os,
        detected_arch=raw_arch,
        can_system_install=can_system_install,
        has_sudo=has_sudo,
        sudo_nopasswd=sudo_nopasswd,
        sudo_password_works=sudo_password_works,
        has_systemd=_bool_from_probe(parsed.get("has_systemd")),
        has_sysvinit=_bool_from_probe(parsed.get("has_sysvinit")),
        has_crontab=_bool_from_probe(parsed.get("has_crontab")),
        has_user_systemd=_bool_from_probe(parsed.get("has_user_systemd")),
        has_bash=has_bash,
        has_sh=has_sh,
        has_tar=has_tar,
        has_mktemp=has_mktemp,
        http_tool=http_tool,
        platform_ok=_bool_from_probe(parsed.get("platform_ok")),
        package_manager=package_manager,
        os_release_like=os_release_like,
        missing_tools=missing_tools,
        bootstrap_needed=bootstrap_needed,
        bootstrap_supported=bootstrap_supported,
        bootstrap_status=bootstrap_status,
        compatibility_issues=compatibility_issues,
    )


async def _install_runner_bundle(context: RunnerInstallContext) -> RunnerInstallProbe:
    profile = _build_profile(context.asset, context.credential)
    asyncssh = _load_asyncssh()
    connect_kwargs = _build_connect_kwargs(asyncssh=asyncssh, profile=profile, options=SSHCollectOptions())
    if connect_kwargs is None:
        raise RuntimeError("SSH 凭据内容无效，无法安装 Host Runner")

    bundle = build_runner_bundle(
        platform_url=context.platform_url,
        asset_id=context.asset.id,
        runner_id=context.host_runner.id,
        registration_token=context.registration_token,
    )
    remote_root = f"/tmp/sa-runner-install-{context.host_runner.id}-{secrets.token_hex(4)}"
    remote_bundle = f"{remote_root}/sa-runner.tar.gz"
    async with _connect_with_legacy_hostkey_fallback(asyncssh=asyncssh, connect_kwargs=connect_kwargs) as connection:
        probe = await _probe_remote_runner_install(
            connection,
            platform_url=context.platform_url,
            sudo_password=profile.sudo_password,
        )
        append_current_task_event(
            event_type="stage",
            stage_code="verify_runner_install_context",
            stage_name="校验上下文",
            message="已完成目标主机 Runner 安装能力探测",
            payload_json=_runner_probe_payload(probe),
        )
        _validate_runner_install_probe_minimal(probe)
        if probe.bootstrap_needed:
            await _bootstrap_runner_prereqs(connection, probe=probe, sudo_password=profile.sudo_password)
            final_probe = await _probe_remote_runner_install(
                connection,
                platform_url=context.platform_url,
                sudo_password=profile.sudo_password,
            )
            final_probe.bootstrap_needed = True
            final_probe.bootstrap_supported = True
            final_probe.bootstrap_status = probe.bootstrap_status
            for issue in probe.compatibility_issues:
                _append_compatibility_issue(final_probe.compatibility_issues, issue)
            probe = final_probe
            append_current_task_event(
                event_type="stage",
                stage_code="verify_runner_install_context",
                stage_name="校验上下文",
                message="已完成 Runner 依赖补齐后的二次探测",
                payload_json=_runner_probe_payload(probe),
            )
        _validate_runner_install_probe(probe, platform_url=context.platform_url)
        try:
            await connection.run(f"sh -lc {shlex.quote('mkdir -p ' + shlex.quote(remote_root))}", check=True)
        except Exception as exc:
            raise RunnerInstallError(f"创建 Runner 安装临时目录失败：{exc}", probe=probe) from exc
        try:
            await _upload_bundle(connection, bundle, remote_bundle)
        except Exception as exc:
            raise RunnerInstallError(f"上传 Runner 安装包失败：{exc}", probe=probe) from exc
        append_current_task_event(
            event_type="stage",
            stage_code="prepare_bundle",
            stage_name="上传 Runner 包",
            message="Host Runner 安装包已上传",
            payload_json={"remote_bundle": remote_bundle},
        )
        install_command = "\n".join(
            [
                f"tar -xzf {shlex.quote(remote_bundle)} -C {shlex.quote(remote_root)}",
                f"chmod +x {shlex.quote(remote_root + '/runner.sh')}",
                f"chmod +x {shlex.quote(remote_root + '/install.sh')}",
                f"SA_RUNNER_SUDO_PASSWORD_B64={shlex.quote(_b64_encode_text(profile.sudo_password or ''))} bash {shlex.quote(remote_root + '/install.sh')}",
            ]
        )
        result = await connection.run(f"sh -lc {shlex.quote(install_command)}", check=False)
        stdout = str(getattr(result, "stdout", "") or "")
        stderr = str(getattr(result, "stderr", "") or "")
        if int(getattr(result, "exit_status", 1) or 0) != 0:
            raise RunnerInstallError(stderr.strip() or stdout.strip() or "Host Runner 安装命令执行失败", probe=probe)
        append_current_task_event(
            event_type="success",
            stage_code="install_runner",
            stage_name="安装 Runner",
            message="Host Runner 服务已在目标主机启动",
            payload_json={
                "remote_root": remote_root,
                "detected_os": probe.detected_os,
                "detected_arch": probe.detected_arch,
                "compatibility_issues": probe.compatibility_issues,
            },
        )
        return probe


async def _upload_bundle(connection: Any, bundle: bytes, remote_path: str) -> None:
    with tempfile.NamedTemporaryFile(prefix="sa-runner-", suffix=".tar.gz", delete=False) as handle:
        handle.write(bundle)
        temp_path = handle.name
    try:
        async with connection.start_sftp_client() as sftp:
            await sftp.put(temp_path, remote_path)
    finally:
        try:
            Path(temp_path).unlink(missing_ok=True)
        except OSError:
            pass


def _build_profile(asset: Asset, credential: SSHCredential) -> SSHCollectProfile:
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    if credential.auth_type == CredentialAuthType.PASSWORD:
        password = _decrypt_optional(credential.secret_ciphertext)
    elif credential.auth_type == CredentialAuthType.KEY:
        private_key = _decrypt_optional(credential.key_ciphertext)
    sudo_password = _decrypt_optional(credential.sudo_secret_ciphertext)
    return SSHCollectProfile(
        asset_id=asset.id,
        ip=str(asset.ip),
        username=credential.username,
        password=password,
        private_key=private_key,
        sudo_password=sudo_password,
    )


def _decrypt_optional(value: str | None) -> str | None:
    if not value:
        return None
    return decrypt_text(value)
