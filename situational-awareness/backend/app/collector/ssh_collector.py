from __future__ import annotations

import asyncio
import importlib
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.collector.host_security import (
    CAPABILITIES_COMMAND,
    CRON_LOCAL_COMMAND,
    DOCKER_DAEMON_LOCAL_COMMAND,
    DOCKER_LOCAL_COMMAND,
    LOGROTATE_LOCAL_COMMAND,
    NMAP_LOCAL_COMMAND,
    POLKIT_LOCAL_COMMAND,
    POLKIT_RULES_LOCAL_COMMAND,
    SCREEN_LOCAL_COMMAND,
    SUDO_LOCAL_COMMAND,
    SUDOERS_COMMAND,
    SUDO_LIST_COMMAND,
    SUID_SGID_COMMAND,
    SYSTEMD_LOCAL_COMMAND,
    WORLD_WRITABLE_COMMAND,
    build_cron_config,
    build_docker_config,
    build_linux_host_config,
    build_logrotate_config,
    build_nmap_config,
    build_polkit_config,
    build_screen_config,
    build_systemd_config,
    build_sudo_config,
    parse_capabilities,
    parse_cron_local,
    parse_docker_daemon_local,
    parse_docker_local,
    parse_logrotate_local,
    parse_nmap_local,
    parse_polkit_local,
    parse_polkit_rules_local,
    parse_sensitive_world_writable,
    parse_screen_local,
    parse_systemd_local,
    parse_sudo_local,
    parse_sudo_list,
    parse_sudoers,
    parse_suid_sgid,
)
from app.collector.package_collector import PACKAGE_COLLECTION_PLANS, parse_packages
from app.collector.service_config import (
    SERVICE_CONFIG_COLLECTION_PLANS,
    detect_collectable_services,
    parse_service_config,
)
from app.collector.system_info import (
    CPU_COMMAND,
    HOSTNAME_COMMAND,
    KERNEL_COMMAND,
    MEMORY_COMMAND,
    OS_COMMAND,
    SERVICES_COMMAND,
    SERVICES_FALLBACK_COMMAND,
    parse_cpu,
    parse_hostname,
    parse_kernel,
    parse_memory,
    parse_os_release,
    parse_running_services,
)


@dataclass(slots=True)
class SSHCollectError:
    stage: str
    message: str
    command: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "stage": self.stage,
            "message": self.message,
            "command": self.command,
        }


@dataclass(slots=True)
class SSHCollectProfile:
    asset_id: str
    ip: str
    username: str
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    port: int = 22


@dataclass(slots=True)
class SSHCollectOptions:
    connect_timeout: float = 8.0
    command_timeout: float = 20.0
    asset_timeout: float = 45.0
    known_hosts: str | None = None


@dataclass(slots=True)
class SSHAuthorizationResult:
    asset_id: str
    ip: str
    status: str
    username: str | None
    effective_user: str | None
    effective_privilege: str | None
    summary: str
    errors: list[SSHCollectError] = field(default_factory=list)
    detail_json: dict[str, Any] = field(default_factory=dict)
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def ok(self) -> bool:
        return self.status == "success" and self.effective_privilege in {"root", "sudo"}

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "status": self.status,
            "username": self.username,
            "effective_user": self.effective_user,
            "effective_privilege": self.effective_privilege,
            "summary": self.summary,
            "errors": [item.to_dict() for item in self.errors],
            "detail_json": self.detail_json,
            "verified_at": self.verified_at.isoformat(),
        }


@dataclass(slots=True)
class SSHCollectResult:
    asset_id: str
    ip: str
    status: str
    hostname: str | None
    os: dict[str, str | None]
    kernel: dict[str, str | None]
    cpu: dict[str, int | str | None]
    memory: dict[str, int | None]
    packages: list[dict[str, str | None]]
    services: list[dict[str, str | int | None]]
    service_configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    authorization: dict[str, Any] = field(default_factory=dict)
    host_checks: dict[str, Any] = field(default_factory=dict)
    errors: list[SSHCollectError] = field(default_factory=list)
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def failed(
        cls,
        asset_id: str,
        ip: str,
        stage: str,
        message: str,
        command: str | None = None,
        *,
        authorization: dict[str, Any] | None = None,
    ) -> "SSHCollectResult":
        return cls(
            asset_id=asset_id,
            ip=ip,
            status="failed",
            hostname=None,
            os={"name": None, "version": None, "pretty_name": None},
            kernel={"release": None, "version": None},
            cpu={"model": None, "architecture": None, "cores": None, "threads": None},
            memory={"total_bytes": None, "available_bytes": None},
            packages=[],
            services=[],
            authorization=authorization or {},
            errors=[SSHCollectError(stage=stage, message=message, command=command)],
        )

    def os_release_text(self) -> str | None:
        return self.os.get("pretty_name") or self.os.get("name")

    def kernel_summary(self) -> str | None:
        return self.kernel.get("release") or self.kernel.get("version")

    def effective_privilege(self) -> str | None:
        value = self.authorization.get("effective_privilege")
        return str(value).strip().lower() if isinstance(value, str) and value.strip() else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "status": self.status,
            "hostname": self.hostname,
            "os": self.os,
            "kernel": self.kernel,
            "cpu": self.cpu,
            "memory": self.memory,
            "packages": self.packages,
            "services": self.services,
            "service_configs": self.service_configs,
            "authorization": self.authorization,
            "host_checks": self.host_checks,
            "errors": [error.to_dict() for error in self.errors],
            "collected_at": self.collected_at.isoformat(),
        }


@dataclass(slots=True)
class _CommandExecution:
    stage: str
    command: str
    stdout: str | None = None
    ok: bool = False
    error: SSHCollectError | None = None


class AsyncSSHCollector:
    async def verify_authorization(
        self,
        profile: SSHCollectProfile,
        options: SSHCollectOptions | None = None,
    ) -> SSHAuthorizationResult:
        options = options or SSHCollectOptions()
        asyncssh = _load_asyncssh()
        connect_kwargs = _build_connect_kwargs(asyncssh=asyncssh, profile=profile, options=options)
        if connect_kwargs is None:
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="failed",
                username=profile.username,
                effective_user=None,
                effective_privilege=None,
                summary="SSH 凭据无效，无法执行授权验证",
                errors=[SSHCollectError(stage="auth", message="私钥无效")],
            )

        try:
            async with _connect_with_legacy_hostkey_fallback(asyncssh=asyncssh, connect_kwargs=connect_kwargs) as connection:
                return await self._verify_authorization_on_connection(connection, profile, options.command_timeout)
        except Exception as exc:
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="failed",
                username=profile.username,
                effective_user=None,
                effective_privilege=None,
                summary=f"SSH 授权验证失败：{exc}",
                errors=[SSHCollectError(stage="connect", message=str(exc))],
            )

    async def collect_one(
        self,
        profile: SSHCollectProfile,
        options: SSHCollectOptions | None = None,
        *,
        authorization_result: SSHAuthorizationResult | None = None,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> SSHCollectResult:
        options = options or SSHCollectOptions()
        try:
            return await asyncio.wait_for(
                self._collect_one(profile, options, authorization_result=authorization_result, on_stage=on_stage),
                timeout=options.asset_timeout,
            )
        except asyncio.TimeoutError:
            return SSHCollectResult.failed(
                asset_id=profile.asset_id,
                ip=profile.ip,
                stage="asset_timeout",
                message=f"采集超时，已超过 {options.asset_timeout:.0f} 秒",
                authorization=authorization_result.to_dict() if authorization_result else None,
            )

    async def collect_many(
        self,
        profiles: list[SSHCollectProfile],
        options: SSHCollectOptions | None = None,
        concurrency: int = 20,
    ) -> list[SSHCollectResult]:
        options = options or SSHCollectOptions()
        semaphore = asyncio.Semaphore(concurrency)

        async def _run(profile: SSHCollectProfile) -> SSHCollectResult:
            async with semaphore:
                return await self.collect_one(profile, options)

        results = await asyncio.gather(*[asyncio.create_task(_run(profile)) for profile in profiles])
        return list(results)

    async def _collect_one(
        self,
        profile: SSHCollectProfile,
        options: SSHCollectOptions,
        *,
        authorization_result: SSHAuthorizationResult | None = None,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> SSHCollectResult:
        asyncssh = _load_asyncssh()
        connect_kwargs = _build_connect_kwargs(asyncssh=asyncssh, profile=profile, options=options)
        if connect_kwargs is None:
            return SSHCollectResult.failed(profile.asset_id, profile.ip, "auth", "私钥无效")

        try:
            async with _connect_with_legacy_hostkey_fallback(asyncssh=asyncssh, connect_kwargs=connect_kwargs) as connection:
                auth_result = authorization_result or await self._verify_authorization_on_connection(connection, profile, options.command_timeout)
                if not auth_result.ok:
                    return SSHCollectResult.failed(
                        profile.asset_id,
                        profile.ip,
                        "authorization",
                        auth_result.summary,
                        authorization=auth_result.to_dict(),
                    )
                return await self._collect_via_connection(profile, connection, options, auth_result, on_stage=on_stage)
        except Exception as exc:
            return SSHCollectResult.failed(profile.asset_id, profile.ip, "connect", str(exc))

    async def _collect_via_connection(
        self,
        profile: SSHCollectProfile,
        connection: Any,
        options: SSHCollectOptions,
        authorization_result: SSHAuthorizationResult,
        *,
        on_stage: Callable[[str, str], None] | None = None,
    ) -> SSHCollectResult:
        if on_stage:
            on_stage("collect_inventory", "基础清单采集")

        core_commands = [
            ("hostname", HOSTNAME_COMMAND),
            ("os", OS_COMMAND),
            ("kernel", KERNEL_COMMAND),
            ("cpu", CPU_COMMAND),
            ("memory", MEMORY_COMMAND),
        ]
        executions = await asyncio.gather(
            *[
                asyncio.create_task(
                    self._run_command(connection, stage=stage, command=command, timeout=options.command_timeout)
                )
                for stage, command in core_commands
            ]
        )
        execution_map = {item.stage: item for item in executions}

        services, service_errors = await self._collect_services(connection, options.command_timeout)
        packages, package_errors = await self._collect_packages(connection, options.command_timeout)
        os_info = parse_os_release(execution_map["os"].stdout)
        service_configs, config_errors = await self._collect_service_configs(
            connection,
            services,
            packages,
            options.command_timeout,
            profile=profile,
            privilege=authorization_result.effective_privilege,
        )

        if on_stage:
            on_stage("collect_host_security", "主机安全检查")
        host_checks, host_configs, host_errors = await self._collect_host_security(
            connection,
            profile=profile,
            packages=packages,
            os_info=os_info,
            timeout=options.command_timeout,
            privilege=authorization_result.effective_privilege,
        )

        merged_service_configs = dict(service_configs)
        merged_service_configs.update(host_configs)

        errors = [item.error for item in executions if item.error is not None]
        errors.extend(service_errors)
        errors.extend(package_errors)
        errors.extend(config_errors)
        errors.extend(host_errors)

        hostname = parse_hostname(execution_map["hostname"].stdout)
        kernel_info = parse_kernel(execution_map["kernel"].stdout)
        cpu_info = parse_cpu(execution_map["cpu"].stdout)
        memory_info = parse_memory(execution_map["memory"].stdout)

        status = "success"
        if errors:
            has_primary_data = any(
                [
                    hostname,
                    os_info.get("pretty_name"),
                    kernel_info.get("release"),
                    cpu_info.get("model"),
                    memory_info.get("total_bytes"),
                    packages,
                    services,
                ]
            )
            status = "partial" if has_primary_data else "failed"

        return SSHCollectResult(
            asset_id=profile.asset_id,
            ip=profile.ip,
            status=status,
            hostname=hostname,
            os=os_info,
            kernel=kernel_info,
            cpu=cpu_info,
            memory=memory_info,
            packages=packages,
            services=services,
            service_configs=merged_service_configs,
            authorization=authorization_result.to_dict(),
            host_checks=host_checks,
            errors=errors,
        )

    async def _verify_authorization_on_connection(
        self,
        connection: Any,
        profile: SSHCollectProfile,
        timeout: float,
    ) -> SSHAuthorizationResult:
        whoami = await self._run_command(connection, "whoami", "whoami", timeout)
        uid = await self._run_command(connection, "id_u", "id -u", timeout)
        errors = [item.error for item in [whoami, uid] if item.error is not None]

        effective_user = _first_line(whoami.stdout)
        effective_uid = _first_line(uid.stdout)
        detail_json: dict[str, Any] = {
            "whoami": effective_user,
            "uid": effective_uid,
            "username": profile.username,
        }
        if errors:
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="failed",
                username=profile.username,
                effective_user=effective_user,
                effective_privilege=None,
                summary="SSH 登录成功，但无法确认当前会话权限",
                errors=errors,
                detail_json=detail_json,
            )

        if effective_user == "root" or effective_uid == "0":
            detail_json["sudo_check"] = "skipped"
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="success",
                username=profile.username,
                effective_user=effective_user or profile.username,
                effective_privilege="root",
                summary="管理员权限验证成功：已确认 root 登录",
                detail_json=detail_json,
            )

        if not (profile.sudo_password or "").strip():
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="failed",
                username=profile.username,
                effective_user=effective_user or profile.username,
                effective_privilege=None,
                summary="当前用户不是 root，且未提供 sudo 密码",
                detail_json=detail_json,
            )

        sudo_uid = await self._run_command(
            connection,
            "sudo_id_u",
            "id -u",
            timeout,
            privileged=True,
            sudo_password=profile.sudo_password,
        )
        detail_json["sudo_uid"] = _first_line(sudo_uid.stdout)
        if sudo_uid.ok and _first_line(sudo_uid.stdout) == "0":
            detail_json["sudo_check"] = "success"
            return SSHAuthorizationResult(
                asset_id=profile.asset_id,
                ip=profile.ip,
                status="success",
                username=profile.username,
                effective_user=effective_user or profile.username,
                effective_privilege="sudo",
                summary="管理员权限验证成功：已确认 sudo 权限",
                detail_json=detail_json,
            )

        errors = [item for item in [sudo_uid.error] if item is not None]
        detail_json["sudo_check"] = "failed"
        return SSHAuthorizationResult(
            asset_id=profile.asset_id,
            ip=profile.ip,
            status="failed",
            username=profile.username,
            effective_user=effective_user or profile.username,
            effective_privilege=None,
            summary="SSH 登录成功，但未验证到管理员权限",
            errors=errors,
            detail_json=detail_json,
        )

    async def _collect_services(self, connection: Any, timeout: float) -> tuple[list[dict[str, str | int | None]], list[SSHCollectError]]:
        primary = await self._run_command(connection, "services", SERVICES_COMMAND, timeout)
        if primary.ok:
            return parse_running_services(primary.stdout), []

        fallback = await self._run_command(connection, "services_fallback", SERVICES_FALLBACK_COMMAND, timeout)
        if fallback.ok:
            services = parse_running_services(fallback.stdout, fallback=True)
            errors = [primary.error] if primary.error else []
            return services, errors

        errors = [error for error in [primary.error, fallback.error] if error is not None]
        return [], errors

    async def _collect_packages(self, connection: Any, timeout: float) -> tuple[list[dict[str, str | None]], list[SSHCollectError]]:
        for plan in PACKAGE_COLLECTION_PLANS:
            detected = await self._run_command(connection, f"packages_detect_{plan.manager}", plan.detect_command, timeout)
            if not detected.ok:
                continue

            collected = await self._run_command(connection, "packages", plan.collect_command, timeout)
            if not collected.ok:
                return [], [error for error in [collected.error] if error is not None]
            return parse_packages(plan.manager, collected.stdout), []

        return [], [SSHCollectError(stage="packages", message="未识别到受支持的包管理器")]

    async def _collect_service_configs(
        self,
        connection: Any,
        services: list[dict[str, str | int | None]],
        packages: list[dict[str, str | None]],
        timeout: float,
        *,
        profile: SSHCollectProfile,
        privilege: str | None,
    ) -> tuple[dict[str, dict[str, Any]], list[SSHCollectError]]:
        collectable_services = detect_collectable_services(services, packages)
        if not collectable_services:
            return {}, []

        privileged = privilege == "sudo"
        executions = await asyncio.gather(
            *[
                asyncio.create_task(
                    self._run_command(
                        connection,
                        stage=f"config_{service}",
                        command=SERVICE_CONFIG_COLLECTION_PLANS[service].command,
                        timeout=timeout,
                        privileged=privileged,
                        sudo_password=profile.sudo_password,
                    )
                )
                for service in collectable_services
            ]
        )

        configs: dict[str, dict[str, Any]] = {}
        errors: list[SSHCollectError] = []
        for service, execution in zip(collectable_services, executions, strict=False):
            if execution.ok:
                parsed = parse_service_config(service, execution.stdout)
                if parsed:
                    configs[service] = parsed
                continue
            if execution.error is not None:
                errors.append(execution.error)
        return configs, errors

    async def _collect_host_security(
        self,
        connection: Any,
        *,
        profile: SSHCollectProfile,
        packages: list[dict[str, Any]],
        os_info: dict[str, Any],
        timeout: float,
        privilege: str | None,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]], list[SSHCollectError]]:
        if privilege not in {"root", "sudo"}:
            return {}, {}, [SSHCollectError(stage="host_security", message="当前会话不具备管理员权限，已跳过主机安全检查")]

        privileged = privilege == "sudo"
        sudo_list = await self._run_command(
            connection,
            "sudo_list",
            SUDO_LIST_COMMAND,
            timeout,
            privileged=False,
            sudo_password=profile.sudo_password,
        )
        executions = await asyncio.gather(
            *[
                asyncio.create_task(
                    self._run_command(
                        connection,
                        stage=stage,
                        command=command,
                        timeout=timeout,
                        privileged=use_privilege,
                        sudo_password=profile.sudo_password,
                    )
                )
                for stage, command, use_privilege in [
                    ("sudoers", SUDOERS_COMMAND, privileged),
                    ("sudo_local", SUDO_LOCAL_COMMAND, False),
                    ("suid_sgid", SUID_SGID_COMMAND, privileged),
                    ("capabilities", CAPABILITIES_COMMAND, privileged),
                    ("world_writable", WORLD_WRITABLE_COMMAND, privileged),
                    ("nmap_local", NMAP_LOCAL_COMMAND, privileged),
                    ("screen_local", SCREEN_LOCAL_COMMAND, privileged),
                    ("docker_local", DOCKER_LOCAL_COMMAND, False),
                    ("docker_daemon_local", DOCKER_DAEMON_LOCAL_COMMAND, privileged),
                    ("polkit_local", POLKIT_LOCAL_COMMAND, privileged),
                    ("polkit_rules_local", POLKIT_RULES_LOCAL_COMMAND, privileged),
                    ("systemd_local", SYSTEMD_LOCAL_COMMAND, privileged),
                    ("cron_local", CRON_LOCAL_COMMAND, privileged),
                    ("logrotate_local", LOGROTATE_LOCAL_COMMAND, privileged),
                ]
            ]
        )

        execution_map = {item.stage: item for item in executions}
        errors = [item.error for item in [sudo_list] + executions if item.error is not None]

        sudoers = parse_sudoers(execution_map.get("sudoers").stdout if execution_map.get("sudoers") else None)
        sudo_list_payload = parse_sudo_list(sudo_list.stdout)
        sudo_local = parse_sudo_local(
            execution_map.get("sudo_local").stdout if execution_map.get("sudo_local") else None,
            packages=packages,
            os_info=os_info,
        )
        suid_sgid = parse_suid_sgid(execution_map.get("suid_sgid").stdout if execution_map.get("suid_sgid") else None)
        capabilities = parse_capabilities(execution_map.get("capabilities").stdout if execution_map.get("capabilities") else None)
        world_writable = parse_sensitive_world_writable(
            execution_map.get("world_writable").stdout if execution_map.get("world_writable") else None
        )
        nmap_local = parse_nmap_local(
            execution_map.get("nmap_local").stdout if execution_map.get("nmap_local") else None,
            packages=packages,
        )
        screen_local = parse_screen_local(
            execution_map.get("screen_local").stdout if execution_map.get("screen_local") else None,
            packages=packages,
        )
        docker_local = parse_docker_local(execution_map.get("docker_local").stdout if execution_map.get("docker_local") else None)
        docker_daemon_local = parse_docker_daemon_local(
            execution_map.get("docker_daemon_local").stdout if execution_map.get("docker_daemon_local") else None
        )
        polkit_local = parse_polkit_local(
            execution_map.get("polkit_local").stdout if execution_map.get("polkit_local") else None,
            packages=packages,
            os_info=os_info,
        )
        polkit_rules_local = parse_polkit_rules_local(
            execution_map.get("polkit_rules_local").stdout if execution_map.get("polkit_rules_local") else None
        )
        systemd_local = parse_systemd_local(
            execution_map.get("systemd_local").stdout if execution_map.get("systemd_local") else None
        )
        cron_local = parse_cron_local(execution_map.get("cron_local").stdout if execution_map.get("cron_local") else None)
        logrotate_local = parse_logrotate_local(
            execution_map.get("logrotate_local").stdout if execution_map.get("logrotate_local") else None
        )

        host_checks = {
            "sudoers": sudoers,
            "sudo_list": sudo_list_payload,
            "sudo_local": sudo_local,
            "suid_sgid": suid_sgid,
            "capabilities": capabilities,
            "sensitive_world_writable": world_writable,
            "nmap_local": nmap_local,
            "screen_local": screen_local,
            "docker_local": docker_local,
            "docker_daemon_local": docker_daemon_local,
            "polkit_local": polkit_local,
            "polkit_rules_local": polkit_rules_local,
            "systemd_local": systemd_local,
            "cron_local": cron_local,
            "logrotate_local": logrotate_local,
        }
        configs = {
            "sudo": build_sudo_config(sudoers=sudoers, sudo_list=sudo_list_payload, sudo_local=sudo_local),
            "nmap": build_nmap_config(nmap_local=nmap_local),
            "screen": build_screen_config(screen_local=screen_local),
            "docker": build_docker_config(docker_local=docker_local, docker_daemon_local=docker_daemon_local),
            "polkit": build_polkit_config(polkit_local=polkit_local, polkit_rules_local=polkit_rules_local),
            "systemd": build_systemd_config(systemd_local=systemd_local),
            "cron": build_cron_config(cron_local=cron_local),
            "logrotate": build_logrotate_config(logrotate_local=logrotate_local),
            "linux-host": build_linux_host_config(
                suid_sgid=suid_sgid,
                capabilities=capabilities,
                sensitive_world_writable=world_writable,
                docker_local=docker_local,
            ),
        }
        return host_checks, configs, errors

    async def _run_command(
        self,
        connection: Any,
        stage: str,
        command: str,
        timeout: float,
        *,
        privileged: bool = False,
        sudo_password: str | None = None,
    ) -> _CommandExecution:
        actual_command = command
        if privileged:
            if not (sudo_password or "").strip():
                return _CommandExecution(
                    stage=stage,
                    command=command,
                    error=SSHCollectError(stage=stage, command=command, message="缺少 sudo 密码，无法执行管理员检查"),
                )
            actual_command = _build_password_piped_command(
                f"sudo -S -p '' sh -lc {shlex.quote(command)}",
                sudo_password,
            )
        elif stage == "sudo_list" and sudo_password:
            actual_command = _build_password_piped_command(command, sudo_password)

        try:
            result = await asyncio.wait_for(connection.run(actual_command, check=False), timeout=timeout)
        except asyncio.TimeoutError:
            return _CommandExecution(
                stage=stage,
                command=actual_command,
                error=SSHCollectError(stage=stage, command=actual_command, message=f"命令执行超时，已超过 {timeout:.0f} 秒"),
            )
        except Exception as exc:
            return _CommandExecution(
                stage=stage,
                command=actual_command,
                error=SSHCollectError(stage=stage, command=actual_command, message=str(exc)),
            )

        if getattr(result, "exit_status", 1) != 0:
            message = (getattr(result, "stderr", "") or f"退出状态码 {result.exit_status}").strip()
            return _CommandExecution(
                stage=stage,
                command=actual_command,
                stdout=getattr(result, "stdout", None),
                error=SSHCollectError(stage=stage, command=actual_command, message=message),
            )

        return _CommandExecution(
            stage=stage,
            command=actual_command,
            stdout=getattr(result, "stdout", None),
            ok=True,
        )


def _first_line(raw: str | None) -> str:
    for line in (raw or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _build_connect_kwargs(*, asyncssh: Any, profile: SSHCollectProfile, options: SSHCollectOptions) -> dict[str, Any] | None:
    connect_kwargs: dict[str, Any] = {
        "host": profile.ip,
        "port": profile.port,
        "username": profile.username,
        "known_hosts": options.known_hosts,
        "connect_timeout": options.connect_timeout,
    }
    if profile.private_key:
        try:
            connect_kwargs["client_keys"] = [asyncssh.import_private_key(profile.private_key)]
        except Exception:
            return None
    elif profile.password:
        connect_kwargs["password"] = profile.password
    return connect_kwargs


def _connect_with_legacy_hostkey_fallback(*, asyncssh: Any, connect_kwargs: dict[str, Any]) -> Any:
    return _LegacyHostKeyConnectContext(asyncssh=asyncssh, connect_kwargs=connect_kwargs)


class _LegacyHostKeyConnectContext:
    def __init__(self, *, asyncssh: Any, connect_kwargs: dict[str, Any]) -> None:
        self._asyncssh = asyncssh
        self._connect_kwargs = connect_kwargs
        self._inner: Any = None

    async def __aenter__(self) -> Any:
        try:
            self._inner = self._asyncssh.connect(**self._connect_kwargs)
            return await self._inner.__aenter__()
        except Exception as exc:
            if not _should_retry_with_legacy_hostkey_algs(exc):
                raise

        fallback_kwargs = dict(self._connect_kwargs)
        fallback_kwargs["server_host_key_algs"] = _legacy_server_host_key_algs()
        self._inner = self._asyncssh.connect(**fallback_kwargs)
        return await self._inner.__aenter__()

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        if self._inner is None:
            return False
        return await self._inner.__aexit__(exc_type, exc, tb)


def _should_retry_with_legacy_hostkey_algs(exc: Exception) -> bool:
    message = str(exc).strip().lower()
    if not message:
        return False
    return "no matching host key type found" in message and ("ssh-rsa" in message or "ssh-dss" in message)


def _legacy_server_host_key_algs() -> list[str]:
    return [
        "rsa-sha2-512",
        "rsa-sha2-256",
        "ssh-rsa",
        "ssh-dss",
    ]


def _build_password_piped_command(command: str, password: str) -> str:
    return f"printf '%s\\n' {shlex.quote(password)} | {command}"


def _load_asyncssh() -> Any:
    return importlib.import_module("asyncssh")
