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
from app.db.models.enums import CredentialAuthType, DiscoveryJobStatus, TaskExecutionStatus, TaskType
from app.db.models.host_runner import HostRunner
from app.db.models.remediation_message import RemediationMessage
from app.db.models.remediation_session import RemediationSession
from app.db.models.task_run import TaskRun
from app.repositories.task_event_repo import create_task_event
from app.repositories.task_repo import create_task_run, get_latest_task_run_for_scope, get_task_run, update_task_run
from app.scanner.port_catalog import resolve_scan_ports
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
from app.services.remediation_business_service import (
    BUSINESS_STATUS_PENDING_REVERIFY,
    BUSINESS_STATUS_VERIFIED_FAILED,
    EXECUTION_STATUS_FAILED,
    EXECUTION_STATUS_SUCCEEDED,
    build_business_status_message,
    queue_remediation_reverify,
)
from app.services.remediation_evidence_service import build_remediation_evidence
from app.services.campus_discovery_service import aggregate_campus_discovery_job, update_discovery_execution_from_task
from app.services.campus_zone_service import get_scanner_zone, merge_zone_profile_with_defaults
from app.tasks.task_runtime import append_current_task_event
from app.db.session import SessionLocal

RUNNER_VERSION = "2.0.0"
RUNNER_BUNDLE_DIR = Path(__file__).resolve().parents[1] / "runner_bundle"
RUNNER_SUPPORTED_TASK_TYPES = {TaskType.REMEDIATION_EXECUTE, TaskType.RUNNER_INSTALL, TaskType.ASSET_SCAN}
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
    node_role = None
    scanner_zone_id = None
    visible_cidrs_json: list[str] = []
    max_concurrent_jobs = 1
    detected_os = None
    detected_arch = None
    compatibility_issues: list[str] = []
    if host_runner is not None:
        runner_id = host_runner.id
        version = host_runner.version
        node_role = host_runner.node_role
        scanner_zone_id = host_runner.scanner_zone_id
        visible_cidrs_json = [str(item).strip() for item in (host_runner.visible_cidrs_json or []) if str(item).strip()]
        max_concurrent_jobs = int(host_runner.max_concurrent_jobs or 1)
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
        node_role=node_role,
        scanner_zone_id=scanner_zone_id,
        visible_cidrs_json=visible_cidrs_json,
        max_concurrent_jobs=max_concurrent_jobs,
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
    last_seen_at = _coerce_utc_datetime(host_runner.last_seen_at)
    if last_seen_at is None:
        return "offline" if raw_status in {"online", "busy"} else raw_status or "offline"
    if datetime.now(timezone.utc) - last_seen_at > timedelta(seconds=_runner_offline_grace_seconds()):
        return "offline"
    return raw_status or "offline"


def _coerce_utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


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
            task_updated_at = _coerce_utc_datetime(
                latest_install_task.updated_at or latest_install_task.started_at or latest_install_task.created_at
            )
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


def _task_targets_runner(task: TaskRun, runner: HostRunner) -> bool:
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
    if task.task_type == TaskType.REMEDIATION_EXECUTE:
        return task.scope_type == "asset" and task.scope_id == runner.asset_id
    if task.task_type == TaskType.ASSET_SCAN:
        return str(context.get("runner_asset_id") or "").strip() == runner.asset_id
    return False


def _build_runner_asset_scan_config() -> dict[str, Any]:
    liveness_ports = [
        int(item)
        for item in str(getattr(settings, "DISCOVERY_LIVENESS_PORTS", "22,80,443,8080,8443")).split(",")
        if str(item).strip().isdigit() and 1 <= int(str(item).strip()) <= 65535
    ]
    service_ports = [
        int(item)
        for item in str(getattr(settings, "DISCOVERY_SERVICE_PORTS", "")).split(",")
        if str(item).strip().isdigit() and 1 <= int(str(item).strip()) <= 65535
    ]
    high_backdoor_ports = [
        int(item)
        for item in str(getattr(settings, "DISCOVERY_HIGH_BACKDOOR_PORTS", "")).split(",")
        if str(item).strip().isdigit() and 1 <= int(str(item).strip()) <= 65535
    ]
    portset_mode = str(getattr(settings, "DISCOVERY_PORTSET_MODE", "top1000_plus_custom") or "top1000_plus_custom").strip().lower() or "top1000_plus_custom"
    campus_default_portset_mode = str(getattr(settings, "CAMPUS_DEFAULT_PORTSET_MODE", "top1000_plus_custom") or "top1000_plus_custom").strip().lower() or "top1000_plus_custom"
    if portset_mode == "full" and not bool(getattr(settings, "CAMPUS_ALLOW_FULL_SCAN_DEFAULT", False)):
        portset_mode = campus_default_portset_mode
    top_ports_limit = max(1, int(getattr(settings, "DISCOVERY_TOP_PORTS_LIMIT", 1000)))
    scan_ports = list(
        resolve_scan_ports(
            curated_ports=tuple(service_ports),
            high_backdoor_ports=tuple(high_backdoor_ports),
            mode=portset_mode,
            top_ports_limit=top_ports_limit,
        )
    )
    if portset_mode == "full" or (scan_ports and len(scan_ports) == 65535):
        rendered_scan_ports: list[int] = []
    else:
        rendered_scan_ports = scan_ports
    return {
        "liveness_mode": str(getattr(settings, "DISCOVERY_LIVENESS_MODE", "multi_source") or "multi_source"),
        "liveness_ports": liveness_ports or [22, 80, 443, 8080, 8443],
        "enable_arp_discovery": bool(getattr(settings, "DISCOVERY_ENABLE_ARP_DISCOVERY", True)),
        "enable_fping": bool(getattr(settings, "DISCOVERY_ENABLE_FPING", True)),
        "nmap_host_discovery_profile": str(getattr(settings, "DISCOVERY_NMAP_HOST_DISCOVERY_PROFILE", "balanced") or "balanced"),
        "nmap_min_rate": max(1, int(getattr(settings, "DISCOVERY_NMAP_MIN_RATE", 100000))),
        "nmap_liveness_timeout_seconds": max(1, int(getattr(settings, "DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS", 90))),
        "nmap_full_scan_timeout_seconds": max(1, int(getattr(settings, "DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS", 90))),
        "nmap_version_intensity": max(0, int(getattr(settings, "DISCOVERY_NMAP_VERSION_INTENSITY", 5))),
        "scan_ports": rendered_scan_ports,
        "portset_mode": portset_mode,
        "top_ports_limit": top_ports_limit,
        "high_backdoor_ports": high_backdoor_ports,
    }


def _build_runner_asset_scan_assignment(
    db: Session,
    runner: HostRunner,
    task: TaskRun,
) -> tuple[RunnerTaskAssignmentRead, str] | None:
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
    job_id = str(context.get("job_id") or task.scope_id or "").strip()
    if not job_id:
        return None

    from app.db.models.discovery_job import DiscoveryJob

    job = db.get(DiscoveryJob, job_id)
    if job is None:
        return None

    zone = get_scanner_zone(
        db,
        str(context.get("scanner_zone_id") or "").strip()
        or str(getattr(job, "scanner_zone_id", "") or "").strip()
        or None,
    )
    scan_config = merge_zone_profile_with_defaults(zone, _build_runner_asset_scan_config())
    target_cidr = str(context.get("target_cidr") or job.cidr).strip()
    summary = f"扫描网段 {target_cidr}" if zone is None else f"分区 {zone.name} 扫描 {target_cidr}"
    assignment = RunnerTaskAssignmentRead(
        task_id=task.id,
        asset_id=runner.asset_id,
        session_id=None,
        task_type="asset_scan",
        summary=summary,
        execution_mode="apply",
        plan={
            "cidr": target_cidr,
            "runner_asset_id": runner.asset_id,
            "scanner_zone_id": str(context.get("scanner_zone_id") or "").strip() or getattr(job, "scanner_zone_id", None),
            "scan_config": scan_config,
        },
        steps=[],
    )
    return assignment, _build_discovery_assignment_execution_script(task_id=task.id, cidr=target_cidr, scan_config=scan_config)


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
        if not _task_targets_runner(task, runner):
            continue
        result_json = task.result_json if isinstance(task.result_json, dict) else {}
        context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
        if task.task_type == TaskType.ASSET_SCAN:
            built = _build_runner_asset_scan_assignment(db, runner, task)
            if built is None:
                continue
            assignment, execution_script = built
            result_json.setdefault("context", {})
            result_json["context"]["runner_id"] = runner.id
            result_json["context"]["runner_status"] = _runner_status_value(runner)
            update_task_run(
                db,
                task,
                status=TaskExecutionStatus.RUNNING,
                progress=max(5, task.progress),
                message="扫描节点已接单，开始执行多源资产发现",
                result_json=result_json,
            )
            create_task_event(
                db,
                task_run_id=task.id,
                event_type="stage",
                level="info",
                stage_code="runner_dispatch",
                stage_name="扫描节点接单",
                message="扫描节点已获取待执行的真实网络发现任务",
                progress=task.progress,
                payload_json={"runner_id": runner.id},
            )
            if task.scope_type in {"discovery_job", "discovery_execution"}:
                update_discovery_execution_from_task(
                    db,
                    task_id=task.id,
                    status="running",
                    progress=max(5, task.progress),
                    summary_json=result_json,
                )
            if task.scope_type == "discovery_job" and task.scope_id:
                from app.db.models.discovery_job import DiscoveryJob

                job = db.get(DiscoveryJob, task.scope_id)
                if job is not None:
                    job.status = DiscoveryJobStatus.RUNNING
                    if job.started_at is None:
                        job.started_at = datetime.now(timezone.utc)
                    db.add(job)
                    db.commit()
            assignments.append(assignment)
            if next_task_id is None:
                next_task_id = assignment.task_id
                next_summary = assignment.summary
                next_execution_script_b64 = base64.b64encode(execution_script.encode("utf-8")).decode("ascii")
            continue
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
                    rollback_command=str(step.get("rollback_command") or "").strip() or None,
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
    if task is None or task.task_type not in {TaskType.REMEDIATION_EXECUTE, TaskType.ASSET_SCAN}:
        raise RuntimeError("Runner 任务不存在")
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
    if task is None:
        raise RuntimeError("Runner 任务不存在")
    if task.task_type == TaskType.ASSET_SCAN:
        return _complete_runner_asset_scan_task(db, runner, task, payload)
    if task.task_type != TaskType.REMEDIATION_EXECUTE:
        raise RuntimeError("Runner 任务不存在")
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    execution = dict(payload.execution or {})
    if payload.step_results:
        execution["step_results"] = [item.model_dump(mode="json") for item in payload.step_results]
    backups = dict(payload.backups or execution.get("backup_map") or {})
    step_results = execution.get("step_results") if isinstance(execution.get("step_results"), list) else []
    rollback_artifacts = {
        str(item.get("step_id") or "").strip(): dict(item.get("rollback_artifact") or {})
        for item in step_results
        if isinstance(item, dict)
        and str(item.get("step_id") or "").strip()
        and isinstance(item.get("rollback_artifact"), dict)
        and item.get("rollback_artifact")
    }
    success_count = int(execution.get("success_count") or 0)
    if step_results and success_count <= 0:
        success_count = sum(1 for item in step_results if isinstance(item, dict) and str(item.get("status") or "").strip() == "success")
    execution["success_count"] = success_count
    failed_count = int(execution.get("failed_count") or 0)
    if step_results and failed_count <= 0:
        failed_count = sum(1 for item in step_results if isinstance(item, dict) and str(item.get("status") or "").strip() == "failed")
    execution["failed_count"] = failed_count
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
    reverify = {"reverify_triggered": False, "reverify_task_id": None, "reverify_status": None}
    if bool(settings.REMEDIATION_AUTO_REVERIFY_ENABLED) and success_count > 0:
        reverify = queue_remediation_reverify(
            db,
            asset_id=runner.asset_id,
            remediation_task_id=task.id,
            plan=plan,
            selected_steps=selected_steps,
            stage_code=str(execution_context.get("stage_code") or "").strip() or None,
            stage_name=str(execution_context.get("stage_name") or "").strip() or None,
            session_id=str(result_json.get("context", {}).get("session_id") or "").strip() or None,
        )
        create_task_event(
            db,
            task_run_id=task.id,
            event_type="reverify",
            level="info",
            stage_code="auto_reverify",
            stage_name="自动复测",
            message="修复后已自动触发业务复验",
            payload_json=reverify,
        )

    execution_mode = str(execution.get("execution_mode") or "apply").strip().lower() or "apply"
    if failed_count > 0 or payload.status == "failure":
        overall_status = "apply_failed"
        final_message = payload.message or build_business_status_message(
            BUSINESS_STATUS_VERIFIED_FAILED,
            stage_name=str(execution_context.get("stage_name") or "").strip() or None,
        )
        execution_status = EXECUTION_STATUS_FAILED
        business_status = BUSINESS_STATUS_VERIFIED_FAILED
    elif reverify.get("reverify_triggered"):
        overall_status = "applied_pending_reverify"
        final_message = payload.message or build_business_status_message(
            BUSINESS_STATUS_PENDING_REVERIFY,
            stage_name=str(execution_context.get("stage_name") or "").strip() or None,
        )
        execution_status = EXECUTION_STATUS_SUCCEEDED
        business_status = BUSINESS_STATUS_PENDING_REVERIFY
    else:
        overall_status = "applied"
        final_message = payload.message or "Host Runner 已完成当前阶段执行"
        execution_status = EXECUTION_STATUS_SUCCEEDED
        business_status = None
    execution["execution_mode"] = execution_mode
    execution["overall_status"] = overall_status
    execution["final_message"] = final_message
    execution["execution_status"] = execution_status
    execution["rollback_artifacts"] = rollback_artifacts
    if business_status:
        execution["business_status"] = business_status
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
    result_json["execution_status"] = execution_status
    result_json["business_status"] = business_status
    result_json["backups"] = backups
    result_json["reverify"] = reverify
    result_json["reverify_task_id"] = reverify.get("reverify_task_id")
    result_json["reverify_summary"] = {}
    result_json["targeted_finding_outcomes"] = []
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


def _complete_runner_asset_scan_task(
    db: Session,
    runner: HostRunner,
    task: TaskRun,
    payload: RunnerTaskCompleteRequest,
) -> dict[str, Any]:
    result_json = task.result_json if isinstance(task.result_json, dict) else {}
    execution = dict(payload.execution or {})
    execution["execution_boundary"] = "runner_dispatch"
    scan_result = execution.get("scan_result") if isinstance(execution.get("scan_result"), dict) else {}
    context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
    job_id = str(context.get("job_id") or task.scope_id or "").strip()
    scan_summary = {
        "host_count": int(scan_result.get("host_count") or len(scan_result.get("hosts") or []))
        if isinstance(scan_result.get("hosts"), list)
        else int(scan_result.get("host_count") or 0),
        "open_port_count": int(
            scan_result.get("open_port_count")
            or sum(
                len(item.get("ports") or [])
                for item in (scan_result.get("hosts") or [])
                if isinstance(item, dict)
            )
        ),
        "source_stats": scan_result.get("discovery_source_stats") if isinstance(scan_result.get("discovery_source_stats"), dict) else {},
    }

    if payload.status == "success" and job_id and scan_result:
        if task.scope_type == "discovery_execution":
            execution_summary = {
                "scan_result": scan_result,
                "scan_summary": scan_summary,
                "context": context,
            }
            update_discovery_execution_from_task(
                db,
                task_id=task.id,
                status="success",
                progress=100,
                summary_json=execution_summary,
            )
            aggregated = aggregate_campus_discovery_job(db, job_id=job_id)
            if aggregated:
                scan_summary = {
                    "host_count": int(aggregated.get("host_count") or 0),
                    "open_port_count": int((aggregated.get("port_scan_stats") or {}).get("open_port_count") or 0)
                    if isinstance(aggregated.get("port_scan_stats"), dict)
                    else 0,
                    "source_stats": aggregated.get("discovery_source_stats") if isinstance(aggregated.get("discovery_source_stats"), dict) else {},
                }
        else:
            from app.tasks.discovery_tasks import apply_runner_discovery_scan_result

            scan_summary = apply_runner_discovery_scan_result(job_id, scan_result)
        final_status = TaskExecutionStatus.SUCCESS
        final_message = payload.message or "扫描节点已完成多源资产发现"
    else:
        final_status = TaskExecutionStatus.FAILURE
        final_message = payload.message or "扫描节点执行发现任务失败"
        if task.scope_type == "discovery_execution":
            update_discovery_execution_from_task(
                db,
                task_id=task.id,
                status="failure",
                progress=100,
                summary_json={"scan_result": scan_result, "context": context},
                error_json={"message": final_message},
            )
            aggregate_campus_discovery_job(db, job_id=job_id)
        if job_id:
            from app.db.models.discovery_job import DiscoveryJob

            job = db.get(DiscoveryJob, job_id)
            if job is not None:
                job.status = DiscoveryJobStatus.FAILED
                job.finished_at = datetime.now(timezone.utc)
                summary_json = dict(job.summary_json or {}) if isinstance(job.summary_json, dict) else {}
                summary_json["runner_scan_failure"] = {"message": final_message}
                job.summary_json = summary_json
                db.add(job)

    result_json.setdefault("context", {})
    result_json["context"]["runner_id"] = runner.id
    result_json["context"]["runner_status"] = "online"
    result_json["execution"] = execution
    result_json["scan_summary"] = scan_summary
    if job_id:
        result_json["context"]["job_id"] = job_id

    update_task_run(
        db,
        task,
        status=final_status,
        progress=100,
        message=final_message,
        result_json=result_json,
        commit=False,
        refresh=False,
    )
    create_task_event(
        db,
        task_run_id=task.id,
        event_type="success" if final_status == TaskExecutionStatus.SUCCESS else "failure",
        level="info" if final_status == TaskExecutionStatus.SUCCESS else "error",
        stage_code="runner_complete",
        stage_name="扫描节点回传",
        message=final_message,
        progress=100,
        payload_json={"scan_summary": scan_summary},
    )
    runner.last_seen_at = datetime.now(timezone.utc)
    runner.status = "online"
    runner.last_error = None if payload.status == "success" else final_message
    db.add(runner)
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
        '    elif [ "$backup_kind" = "package_context" ]; then',
        '      item_value="$(capture_package_context_raw "$target" 2>/dev/null || true)"',
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
        'capture_package_context_raw() {',
        '  target="${1:-}"',
        '  manager="${target%%:*}"',
        '  package_name="${target#*:}"',
        '  if [ "$package_name" = "$target" ]; then',
        '    package_name="$target"',
        '    manager=""',
        "  fi",
        '  if [ -z "$package_name" ]; then',
        "    return 1",
        "  fi",
        '  if [ "$manager" = "dpkg" ]; then',
        '    if dpkg-query -W -f=\'dpkg|${binary:Package}|${Version}|${Architecture}|${Status}\\n\' "$package_name" 2>/dev/null; then',
        "      return 0",
        "    fi",
        '    printf \'dpkg|%s|not-installed|||\\n\' "$package_name"',
        "    return 0",
        "  fi",
        '  if [ "$manager" = "rpm" ]; then',
        '    if rpm -q --queryformat \'rpm|%{NAME}|%{EPOCHNUM}:%{VERSION}-%{RELEASE}|%{ARCH}|installed\\n\' "$package_name" 2>/dev/null; then',
        "      return 0",
        "    fi",
        '    printf \'rpm|%s|not-installed|||\\n\' "$package_name"',
        "    return 0",
        "  fi",
        '  if [ "$manager" = "apk" ]; then',
        '    if apk info -e "$package_name" >/dev/null 2>&1; then',
        '      version="$(apk info -v "$package_name" 2>/dev/null | head -n 1)"',
        '      printf \'apk|%s|%s|||\\n\' "$package_name" "$version"',
        "      return 0",
        "    fi",
        '    printf \'apk|%s|not-installed|||\\n\' "$package_name"',
        "    return 0",
        "  fi",
        '  printf \'unknown|%s|unresolved|||\\n\' "$package_name"',
        "}",
        "",
        'package_context_json_from_raw() {',
        '  raw="${1:-}"',
        '  if [ -z "$raw" ]; then',
        "    printf 'null'",
        "    return 0",
        "  fi",
        '  manager="$(printf "%s" "$raw" | cut -d"|" -f1)"',
        '  package_name="$(printf "%s" "$raw" | cut -d"|" -f2)"',
        '  version="$(printf "%s" "$raw" | cut -d"|" -f3)"',
        '  arch="$(printf "%s" "$raw" | cut -d"|" -f4)"',
        '  state="$(printf "%s" "$raw" | cut -d"|" -f5-)"',
        '  installed_json="false"',
        '  if [ -n "$version" ] && [ "$version" != "not-installed" ] && [ "$version" != "unresolved" ]; then',
        '    installed_json="true"',
        "  fi",
        '  printf \'{"manager":%s,"package_name":%s,"version":%s,"arch":%s,"state":%s,"installed":%s}\' "$(json_quote "$manager")" "$(json_quote "$package_name")" "$(json_string_or_null "$version")" "$(json_string_or_null "$arch")" "$(json_string_or_null "$state")" "$installed_json"',
        "}",
        "",
        'extract_transaction_id_from_file() {',
        '  file_path="${1:-}"',
        '  if [ ! -f "$file_path" ]; then',
        "    return 0",
        "  fi",
        '  grep -E "SA_TRANSACTION_ID=|Transaction ID[[:space:]]*:" "$file_path" 2>/dev/null | tail -n 1 | sed -e \'s/^.*SA_TRANSACTION_ID=//\' -e \'s/^.*Transaction ID[[:space:]]*:[[:space:]]*//\'',
        "}",
        "",
        'build_package_rollback_artifact_json() {',
        '  target="${1:-}"',
        '  before_raw="${2:-}"',
        '  rollback_command="${3:-}"',
        '  output_file="${4:-}"',
        '  if [ -z "$target" ] || [ -z "$before_raw" ] || [ -z "$rollback_command" ]; then',
        "    printf 'null'",
        "    return 0",
        "  fi",
        '  manager="${target%%:*}"',
        '  package_name="${target#*:}"',
        '  if [ "$package_name" = "$target" ]; then',
        '    package_name="$target"',
        "  fi",
        '  rollback_version="$(printf "%s" "$before_raw" | cut -d"|" -f3)"',
        '  transaction_id="$(extract_transaction_id_from_file "$output_file")"',
        '  after_raw="$(capture_package_context_raw "$target" 2>/dev/null || true)"',
        '  before_json="$(package_context_json_from_raw "$before_raw")"',
        '  after_json="$(package_context_json_from_raw "$after_raw")"',
        '  printf \'{"kind":"package_version_replay","package_name":%s,"manager":%s,"rollback_version":%s,"rollback_command":%s,"transaction_id":%s,"before":%s,"after":%s}\' "$(json_quote "$package_name")" "$(json_string_or_null "$manager")" "$(json_string_or_null "$rollback_version")" "$(json_string_or_null "$rollback_command")" "$(json_string_or_null "$transaction_id")" "$before_json" "$after_json"',
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
        '  rollback_command_b64="${10:-}"',
        '  step_id="$(decode_b64 "$step_id_b64" 2>/dev/null || true)"',
        '  title="$(decode_b64 "$title_b64" 2>/dev/null || true)"',
        '  command_text="$(decode_b64 "$command_b64" 2>/dev/null || true)"',
        '  blocked_reason="$(decode_b64 "$blocked_reason_b64" 2>/dev/null || true)"',
        '  rollback_command="$(decode_b64 "$rollback_command_b64" 2>/dev/null || true)"',
        '  if [ "$execution_state" = "blocked" ]; then',
        '    result_json=$(printf \'{"step_id":%s,"title":%s,"status":"blocked","generated_command":null,"rollback_command":%s,"rollback_artifact":{},"exit_status":null,"backup_paths":[],"output_tail":[],"started_at":null,"finished_at":null,"error":%s}\' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_string_or_null "$rollback_command")" "$(json_string_or_null "$blocked_reason")")',
        '    append_step_result "$result_json"',
        "    return 0",
        "  fi",
        '  EXECUTED_COUNT=$((EXECUTED_COUNT + 1))',
        '  progress_value=$((10 + (index * 70 / total)))',
        '  emit_stage "stage" "execute_steps" "Runner 执行步骤" "$title" "$progress_value" "{}"',
        '  package_context_target=""',
        '  package_context_before=""',
        '  if [ "$backup_kind" = "package_context" ]; then',
        '    targets_content="$(decode_b64 "$backup_targets_b64" 2>/dev/null || true)"',
        '    old_ifs="$IFS"',
        "    IFS='",
        "'",
        '    for target in $targets_content; do',
        '      [ -n "$target" ] || continue',
        '      package_context_target="$target"',
        "      break",
        "    done",
        '    IFS="$old_ifs"',
        '    if [ -n "$package_context_target" ]; then',
        '      package_context_before="$(capture_package_context_raw "$package_context_target" 2>/dev/null || true)"',
        "    fi",
        "  fi",
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
        '  rollback_artifact_json="{}"',
        '  if [ -n "$package_context_target" ] && [ -n "$package_context_before" ] && [ -n "$rollback_command" ]; then',
        '    rollback_artifact_json="$(build_package_rollback_artifact_json "$package_context_target" "$package_context_before" "$rollback_command" "$output_file")"',
        '    if [ -z "$rollback_artifact_json" ] || [ "$rollback_artifact_json" = "null" ]; then',
        '      rollback_artifact_json="{}"',
        "    fi",
        "  fi",
        '  result_json=$(printf \'{"step_id":%s,"title":%s,"status":%s,"generated_command":%s,"rollback_command":%s,"rollback_artifact":%s,"exit_status":%s,"backup_paths":%s,"output_tail":%s,"started_at":%s,"finished_at":%s,"error":%s}\' "$(json_quote "$step_id")" "$(json_quote "$title")" "$(json_quote "$step_status")" "$(json_string_or_null "$command_text")" "$(json_string_or_null "$rollback_command")" "$rollback_artifact_json" "$exit_code" "$backup_paths_json" "$output_tail_json" "$(json_quote "$started_at")" "$(json_quote "$finished_at")" "$(json_string_or_null "$error_text")")',
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
                    shlex.quote(_b64_encode_text(step.rollback_command or "")),
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


def _build_discovery_assignment_execution_script(*, task_id: str, cidr: str, scan_config: dict[str, Any]) -> str:
    encoded_config = _b64_encode_text(json.dumps(scan_config, ensure_ascii=False, separators=(",", ":")))
    lines = [
        "#!/bin/sh",
        "set -eu",
        f"TASK_ID={shlex.quote(task_id)}",
        f"TARGET_CIDR={shlex.quote(cidr)}",
        f"SCAN_CONFIG_B64={shlex.quote(encoded_config)}",
        'PLATFORM_URL="${SA_RUNNER_PLATFORM_URL:-}"',
        'RUNNER_TOKEN="${SA_RUNNER_TOKEN:-}"',
        'HTTP_TOOL="${SA_RUNNER_HTTP_TOOL:-}"',
        'resolve_python() {',
        '  if command -v python3 >/dev/null 2>&1; then',
        '    command -v python3',
        '    return 0',
        "  fi",
        '  if command -v python >/dev/null 2>&1; then',
        '    command -v python',
        '    return 0',
        "  fi",
        "  return 1",
        "}",
        'post_failure_without_python() {',
        '  message="扫描节点缺少 Python 运行时，无法执行真实网络发现脚本"',
        '  payload="{\\"status\\":\\"failure\\",\\"message\\":\\"${message}\\",\\"execution\\":{\\"execution_boundary\\":\\"runner_dispatch\\"}}"',
        '  url="${PLATFORM_URL%/}/api/v1/runner/tasks/${TASK_ID}/complete"',
        '  if [ "${HTTP_TOOL:-}" = "curl" ] && command -v curl >/dev/null 2>&1; then',
        '    curl -fsS --connect-timeout 5 --max-time 30 -X POST -H "Content-Type: application/json" -H "X-Runner-Token: ${RUNNER_TOKEN}" --data "${payload}" "${url}" >/dev/null || true',
        '    return 0',
        "  fi",
        '  if command -v wget >/dev/null 2>&1; then',
        '    wget -qO- --timeout=30 --header="Content-Type: application/json" --header="X-Runner-Token: ${RUNNER_TOKEN}" --post-data="${payload}" "${url}" >/dev/null || true',
        "  fi",
        "}",
        'if ! PYTHON_BIN="$(resolve_python)"; then',
        '  post_failure_without_python',
        '  exit 0',
        "fi",
        'DISCOVERY_TASK_ID="${TASK_ID}" DISCOVERY_TARGET_CIDR="${TARGET_CIDR}" DISCOVERY_SCAN_CONFIG_B64="${SCAN_CONFIG_B64}" DISCOVERY_PLATFORM_URL="${PLATFORM_URL}" DISCOVERY_RUNNER_TOKEN="${RUNNER_TOKEN}" "${PYTHON_BIN}" - <<\'PY\'',
        "import base64",
        "import ipaddress",
        "import json",
        "import os",
        "import re",
        "import shutil",
        "import socket",
        "import subprocess",
        "import sys",
        "import urllib.request",
        "from collections import defaultdict",
        "from xml.etree import ElementTree as ET",
        "",
        "TASK_ID = os.environ['DISCOVERY_TASK_ID']",
        "TARGET_CIDR = os.environ['DISCOVERY_TARGET_CIDR']",
        "PLATFORM_URL = os.environ['DISCOVERY_PLATFORM_URL'].rstrip('/')",
        "RUNNER_TOKEN = os.environ['DISCOVERY_RUNNER_TOKEN']",
        "SCAN_CONFIG = json.loads(base64.b64decode(os.environ['DISCOVERY_SCAN_CONFIG_B64']).decode('utf-8'))",
        "IP_LINE_RE = re.compile(r'^\\d+:\\s+(?P<name>\\S+)\\s+inet\\s+(?P<cidr>\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)\\b')",
        "",
        "def request_json(path, payload):",
        "    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')",
        "    request = urllib.request.Request(f'{PLATFORM_URL}{path}', data=body, method='POST')",
        "    request.add_header('Content-Type', 'application/json')",
        "    request.add_header('X-Runner-Token', RUNNER_TOKEN)",
        "    with urllib.request.urlopen(request, timeout=30) as response:",
        "        raw = response.read().decode('utf-8')",
        "    return json.loads(raw) if raw else {}",
        "",
        "def emit_event(event_type, message, *, stage_code, stage_name, progress=None, level='info', payload_json=None):",
        "    request_json(f'/api/v1/runner/tasks/{TASK_ID}/events', {'events': [{'event_type': event_type, 'level': level, 'stage_code': stage_code, 'stage_name': stage_name, 'message': message, 'progress': progress, 'payload_json': payload_json or {}}]})",
        "",
        "def complete(status, message, execution):",
        "    request_json(f'/api/v1/runner/tasks/{TASK_ID}/complete', {'status': status, 'message': message, 'execution': execution, 'backups': {}, 'step_results': []})",
        "",
        "def run_cmd(cmd, *, timeout, allow_codes=(0,)):",
        "    process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)",
        "    if process.returncode not in allow_codes:",
        "        stderr = (process.stderr or '').strip()",
        "        command_text = ' '.join(cmd)",
        "        raise RuntimeError(f'command failed rc={process.returncode}: {command_text} :: {stderr}')",
        "    return process.stdout, process.stderr, process.returncode",
        "",
        "def list_local_ipv4_interfaces():",
        "    try:",
        "        stdout, _, _ = run_cmd(['ip', '-o', '-4', 'addr', 'show', 'up'], timeout=5)",
        "    except Exception:",
        "        return []",
        "    items = []",
        "    for raw_line in stdout.splitlines():",
        "        match = IP_LINE_RE.match(raw_line.strip())",
        "        if match is None:",
        "            continue",
        "        name = match.group('name').strip()",
        "        cidr = match.group('cidr').strip()",
        "        if not name or name == 'lo':",
        "            continue",
        "        try:",
        "            interface = ipaddress.IPv4Interface(cidr)",
        "        except ValueError:",
        "            continue",
        "        if interface.ip.is_loopback:",
        "            continue",
        "        items.append({'name': name, 'ip': str(interface.ip), 'network': str(interface.network), 'prefixlen': interface.network.prefixlen})",
        "    return items",
        "",
        "def find_local_interface_for_network(cidr):",
        "    target = ipaddress.ip_network(cidr, strict=False)",
        "    if not isinstance(target, ipaddress.IPv4Network):",
        "        return None",
        "    candidates = []",
        "    for entry in list_local_ipv4_interfaces():",
        "        try:",
        "            network = ipaddress.ip_network(entry['network'], strict=False)",
        "        except ValueError:",
        "            continue",
        "        if target.subnet_of(network):",
        "            candidates.append((network.prefixlen, entry))",
        "    if not candidates:",
        "        return None",
        "    candidates.sort(key=lambda item: item[0], reverse=True)",
        "    return candidates[0][1]",
        "",
        "def parse_nmap_ping_xml(output):",
        "    root = ET.fromstring(output)",
        "    hosts = []",
        "    for host in root.findall('host'):",
        "        status = host.find('status')",
        "        if status is None or status.get('state') != 'up':",
        "            continue",
        "        address = next((item for item in host.findall('address') if item.get('addrtype') == 'ipv4'), None)",
        "        if address is None:",
        "            continue",
        "        candidate = (address.get('addr') or '').strip()",
        "        if not candidate:",
        "            continue",
        "        hosts.append(candidate)",
        "    return sorted(set(hosts), key=ipaddress.ip_address)",
        "",
        "def parse_nmap_port_xml(ip, output):",
        "    root = ET.fromstring(output)",
        "    open_ports = []",
        "    for host in root.findall('host'):",
        "        address = next((item for item in host.findall('address') if item.get('addrtype') == 'ipv4'), None)",
        "        if address is None or (address.get('addr') or '').strip() != ip:",
        "            continue",
        "        ports_node = host.find('ports')",
        "        if ports_node is None:",
        "            continue",
        "        for port_node in ports_node.findall('port'):",
        "            if port_node.get('protocol') != 'tcp':",
        "                continue",
        "            state_node = port_node.find('state')",
        "            if state_node is None or state_node.get('state') != 'open':",
        "                continue",
        "            try:",
        "                port = int(port_node.get('portid') or '')",
        "            except ValueError:",
        "                continue",
        "            open_ports.append(port)",
        "    return sorted(set(open_ports))",
        "",
        "def parse_nmap_service_xml(ip, output):",
        "    root = ET.fromstring(output)",
        "    services = []",
        "    for host in root.findall('host'):",
        "        address = next((item for item in host.findall('address') if item.get('addrtype') == 'ipv4'), None)",
        "        if address is None or (address.get('addr') or '').strip() != ip:",
        "            continue",
        "        ports_node = host.find('ports')",
        "        if ports_node is None:",
        "            continue",
        "        for port_node in ports_node.findall('port'):",
        "            if port_node.get('protocol') != 'tcp':",
        "                continue",
        "            state_node = port_node.find('state')",
        "            if state_node is None or state_node.get('state') != 'open':",
        "                continue",
        "            try:",
        "                port = int(port_node.get('portid') or '')",
        "            except ValueError:",
        "                continue",
        "            service_node = port_node.find('service')",
        "            raw_name = (service_node.get('name') if service_node is not None else '') or 'unknown'",
        "            raw_product = (service_node.get('product') if service_node is not None else '') or None",
        "            raw_version = (service_node.get('version') if service_node is not None else '') or None",
        "            raw_extrainfo = (service_node.get('extrainfo') if service_node is not None else '') or None",
        "            raw_tunnel = (service_node.get('tunnel') if service_node is not None else '') or ''",
        "            evidence = [f'nmap_service={raw_name}']",
        "            if raw_product:",
        "                evidence.append(f'nmap_product={raw_product}')",
        "            if raw_version:",
        "                evidence.append(f'nmap_version={raw_version}')",
        "            if raw_extrainfo:",
        "                evidence.append(f'nmap_extrainfo={raw_extrainfo}')",
        "            services.append({",
        "                'port': port,",
        "                'service': raw_name or 'unknown',",
        "                'version': raw_version,",
        "                'probe_method': 'nmap',",
        "                'transport_service': raw_name or 'unknown',",
        "                'application_service': raw_product or raw_name or 'unknown',",
        "                'product_name': raw_product,",
        "                'product_version': raw_version,",
        "                'tls_detected': raw_tunnel == 'ssl',",
        "                'source': 'nmap',",
        "                'confidence': 95 if raw_product and raw_version else 80,",
        "                'reason': 'runner_nmap_service_scan',",
        "                'evidence': evidence,",
        "                'probe_chain': ['nmap'],",
        "                'nmap_service': raw_name or None,",
        "                'nmap_product': raw_product,",
        "            })",
        "    return services",
        "",
        "def parse_arp_scan_output(output):",
        "    hosts = []",
        "    for raw_line in output.splitlines():",
        "        parts = raw_line.strip().split()",
        "        if not parts:",
        "            continue",
        "        candidate = parts[0].strip()",
        "        try:",
        "            hosts.append(str(ipaddress.ip_address(candidate)))",
        "        except ValueError:",
        "            continue",
        "    return sorted(set(hosts), key=ipaddress.ip_address)",
        "",
        "def merge_source(records, hosts, source):",
        "    for ip in hosts:",
        "        item = records.setdefault(ip, {'sources': set(), 'evidence': []})",
        "        item['sources'].add(source)",
        "        evidence = f'{source}:{ip}'",
        "        if evidence not in item['evidence']:",
        "            item['evidence'].append(evidence)",
        "",
        "def scan_host_discovery(cidr, config):",
        "    records = {}",
        "    errors = []",
        "    local_interface = find_local_interface_for_network(cidr)",
        "    if config.get('enable_arp_discovery') and local_interface is not None:",
        "        if shutil.which('arp-scan'):",
        "            try:",
        "                stdout, _, rc = run_cmd(['arp-scan', '--interface', local_interface['name'], '--retry=1', '--timeout=250', '--ignoredups', '--plain', cidr], timeout=30, allow_codes=(0,1))",
        "                merge_source(records, parse_arp_scan_output(stdout), 'arp_scan')",
        "            except Exception as exc:",
        "                errors.append(str(exc))",
        "        elif shutil.which('arping'):",
        "            network = ipaddress.ip_network(cidr, strict=False)",
        "            if network.num_addresses <= 1024:",
        "                for host in network.hosts():",
        "                    process = subprocess.run(['arping', '-c', '1', '-w', '1', '-I', local_interface['name'], str(host)], capture_output=True, text=True, timeout=3, check=False)",
        "                    if process.returncode == 0:",
        "                        merge_source(records, [str(host)], 'arping')",
        "            else:",
        "                errors.append(f'arping 回退不支持大网段 {cidr}')",
        "    if config.get('enable_fping') and shutil.which('fping'):",
        "        try:",
        "            stdout, _, rc = run_cmd(['fping', '-a', '-q', '-r0', '-g', cidr], timeout=max(5, int(config.get('nmap_liveness_timeout_seconds', 90))), allow_codes=(0,1))",
        "            fping_hosts = []",
        "            for raw_line in stdout.splitlines():",
        "                candidate = raw_line.strip()",
        "                if candidate:",
        "                    fping_hosts.append(candidate)",
        "            merge_source(records, fping_hosts, 'fping')",
        "        except Exception as exc:",
        "            errors.append(str(exc))",
        "    if shutil.which('nmap'):",
        "        cmd = ['nmap', '-sn', '-n', '-PE', '-PS22,80,443,445,3389', '-PA80,443,445,3389']",
        "        if str(config.get('nmap_host_discovery_profile') or '').strip().lower() == 'aggressive':",
        "            cmd.append('-PU53,161')",
        "        cmd.extend(['-T4', '--min-rate', str(max(1, int(config.get('nmap_min_rate', 100000)))), cidr, '-oX', '-'])",
        "        try:",
        "            stdout, _, rc = run_cmd(cmd, timeout=max(5, int(config.get('nmap_liveness_timeout_seconds', 90))), allow_codes=(0,1))",
        "            merge_source(records, parse_nmap_ping_xml(stdout), 'nmap_host_discovery')",
        "        except Exception as exc:",
        "            errors.append(str(exc))",
        "    if not records and errors:",
        "        raise RuntimeError('；'.join(errors))",
        "    source_stats = defaultdict(int)",
        "    for item in records.values():",
        "        for source in item['sources']:",
        "            source_stats[source] += 1",
        "    return records, dict(sorted(source_stats.items())), local_interface",
        "",
        "def scan_ports_for_host(ip, config):",
        "    scan_ports = [int(item) for item in (config.get('scan_ports') or []) if 1 <= int(item) <= 65535]",
        "    if str(config.get('portset_mode') or '').strip().lower() == 'full' or len(scan_ports) == 65535:",
        "        stdout, _, _ = run_cmd(['nmap', '-Pn', '-n', '-T4', '--min-rate', str(max(1, int(config.get('nmap_min_rate', 100000)))), '--open', '-p-', ip, '-oX', '-'], timeout=max(5, int(config.get('nmap_full_scan_timeout_seconds', 90))), allow_codes=(0,1))",
        "        return parse_nmap_port_xml(ip, stdout), {'protocol': 'tcp', 'scope_kind': 'all_tcp', 'scanned_port_count': 65535}",
        "    port_csv = ','.join(str(port) for port in scan_ports)",
        "    stdout, _, _ = run_cmd(['nmap', '-Pn', '-n', '--open', '-p', port_csv, ip, '-oX', '-'], timeout=max(5, int(config.get('nmap_full_scan_timeout_seconds', 90))), allow_codes=(0,1))",
        "    return parse_nmap_port_xml(ip, stdout), {'protocol': 'tcp', 'scope_kind': 'explicit', 'ports': scan_ports, 'scanned_port_count': len(scan_ports)}",
        "",
        "def scan_services_for_host(ip, open_ports, config):",
        "    if not open_ports:",
        "        return []",
        "    port_csv = ','.join(str(port) for port in sorted(set(open_ports)))",
        "    stdout, _, _ = run_cmd(['nmap', '-Pn', '-n', '-sV', '--version-intensity', str(max(0, int(config.get('nmap_version_intensity', 7)))), '-p', port_csv, ip, '-oX', '-'], timeout=max(5, int(config.get('nmap_full_scan_timeout_seconds', 90))), allow_codes=(0,1))",
        "    return parse_nmap_service_xml(ip, stdout)",
        "",
        "def build_result(cidr, config):",
        "    emit_event('stage', '扫描节点开始执行多源主机发现', stage_code='runner_discover_hosts', stage_name='Runner 主机发现', progress=10, payload_json={'cidr': cidr})",
        "    records, source_stats, local_interface = scan_host_discovery(cidr, config)",
        "    emit_event('stage', '主机探活完成，开始执行端口与服务扫描', stage_code='runner_scan_ports', stage_name='Runner 端口扫描', progress=40, payload_json={'host_count': len(records), 'source_stats': source_stats})",
        "    hosts = []",
        "    scan_errors = []",
        "    for ip in sorted(records, key=ipaddress.ip_address):",
        "        open_ports = []",
        "        scan_scope = {'protocol': 'tcp', 'scope_kind': 'explicit', 'ports': [], 'scanned_port_count': 0}",
        "        services = []",
        "        host_error = None",
        "        try:",
        "            open_ports, scan_scope = scan_ports_for_host(ip, config)",
        "        except Exception as exc:",
        "            host_error = f'port_scan_failed: {exc}'",
        "        if host_error is None and open_ports:",
        "            try:",
        "                services = scan_services_for_host(ip, open_ports, config)",
        "            except Exception as exc:",
        "                host_error = f'service_scan_failed: {exc}'",
        "        host_entry = {",
        "            'ip': ip,",
        "            'hostname': None,",
        "            'ports': open_ports,",
        "            'services': services,",
        "            'discovery_sources': sorted(records[ip]['sources']),",
        "            'discovery_evidence': list(records[ip]['evidence']),",
        "            'scan_scope': scan_scope,",
        "        }",
        "        if host_error:",
        "            host_entry['scan_error'] = host_error",
        "            scan_errors.append({'ip': ip, 'error': host_error})",
        "        hosts.append(host_entry)",
        "    local_hostnames = [name for name in {socket.gethostname(), socket.getfqdn()} if name]",
        "    baseline_host_count = len(hosts)",
        "    result = {",
        "        'cidr': cidr,",
        "        'hosts': hosts,",
        "        'host_count': len(hosts),",
        "        'open_port_count': sum(len(item.get('ports') or []) for item in hosts),",
        "        'discovery_source_stats': source_stats,",
        "        'baseline_diff_summary': {",
        "            'baseline_host_count': baseline_host_count,",
        "            'accepted_host_count': baseline_host_count,",
        "            'excluded_host_count': 0,",
        "            'extra_host_count': 0,",
        "            'unexplained_missing_host_count': 0,",
        "        },",
        "        'port_scan_stats': {",
        "            'host_count': len(hosts),",
        "            'open_port_count': sum(len(item.get('ports') or []) for item in hosts),",
        "            'scanned_port_count': sum(int((item.get('scan_scope') or {}).get('scanned_port_count') or 0) for item in hosts),",
        "            'service_probe_target_count': sum(len(item.get('ports') or []) for item in hosts),",
        "            'closed_port_count': 0,",
        "            'filtered_or_unknown_count': 0,",
        "            'reconciled_stale_port_count': 0,",
        "        },",
        "        'local_node_hints': {",
        "            'ips': [item['ip'] for item in list_local_ipv4_interfaces()],",
        "            'hostnames': sorted({name.lower() for name in local_hostnames}),",
        "        },",
        "        'runner_interface': local_interface,",
        "        'runner_scan_errors': scan_errors,",
        "    }",
        "    emit_event('stage', '扫描节点已完成端口与服务识别，准备回传结果', stage_code='runner_complete_scan', stage_name='Runner 回传结果', progress=85, payload_json={'host_count': result['host_count'], 'open_port_count': result['open_port_count']})",
        "    return result",
        "",
        "try:",
        "    result = build_result(TARGET_CIDR, SCAN_CONFIG)",
        "    complete('success', '扫描节点已完成多源资产发现', {'execution_boundary': 'runner_dispatch', 'scan_result': result, 'host_count': result.get('host_count', 0), 'open_port_count': result.get('open_port_count', 0)})",
        "except Exception as exc:",
        "    emit_event('failure', f'扫描节点执行失败: {exc}', stage_code='runner_scan_failed', stage_name='Runner 扫描失败', progress=100, level='error', payload_json={'error': str(exc)})",
        "    complete('failure', f'扫描节点执行失败: {exc}', {'execution_boundary': 'runner_dispatch'})",
        "PY",
    ]
    return "\n".join(lines) + "\n"


def select_task_runs_for_runner(asset_id: str):
    from app.db.models.task_run import TaskRun

    return (
        select(TaskRun)
        .where(
            TaskRun.task_type.in_([TaskType.REMEDIATION_EXECUTE, TaskType.ASSET_SCAN]),
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
