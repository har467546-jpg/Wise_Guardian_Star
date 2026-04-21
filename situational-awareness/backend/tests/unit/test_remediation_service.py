import pytest

import app.services.remediation_service as remediation_service
from app.core.config import settings
from app.db.models.credential import SSHCredential
from app.db.models.enums import CredentialAuthType, FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding
from app.schemas.remediation import RemediationPlanRead, RemediationPlanStepRead
from app.services.remediation_service import (
    RemediationCommandPlanner,
    _filter_login_user_required_suid_actions,
    _build_comment_out_regex_command,
    _build_docker_remove_tcp_listener_command,
    _build_ini_section_directive_command,
    _build_package_rollback_command,
    _build_package_upgrade_command,
    _build_replace_or_append_command,
    _build_service_control_command,
    select_executable_plan_steps,
)


def _build_finding(*, rule_id: str, service_name: str) -> RiskFinding:
    return RiskFinding(
        id="finding-1",
        asset_id="asset-1",
        severity=RiskSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        title="test finding",
        evidence_json={
            "yaml_rule_id": rule_id,
            "service_name": service_name,
        },
    )


def _legacy_debian_context(
    *,
    packages: list[dict] | None = None,
    config_by_service: dict | None = None,
    services: list[dict] | None = None,
    host_checks: dict | None = None,
    os_release: str = "Metasploitable2 Ubuntu Hardy",
    has_systemd: str = "0",
    has_sysvinit: str = "1",
) -> dict:
    return {
        "os_release": os_release,
        "config_by_service": config_by_service or {},
        "host_checks": host_checks or {},
        "packages": packages or [],
        "services": services or [],
        "runner_capabilities": {
            "probe": {
                "package_manager": "apt",
                "os_release_like": "ubuntu",
                "has_systemd": has_systemd,
                "has_sysvinit": has_sysvinit,
            }
        },
    }


def test_samba_remove_exposure_step_is_renderable_with_default_config_path() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="samba.writable_guest_share.enabled", service_name="samba"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_exposure",
                    "title": "收敛 samba 的暴露面",
                    "params": {
                        "service_name": "samba",
                        "config_key": "writable_guest_share",
                        "rule_id": "samba.writable_guest_share.enabled",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "/etc/samba/smb.conf" in (step.generated_command or "")
    assert "'map to guest': 'Never'" in (step.generated_command or "")
    assert "managed-by-sa" in (step.generated_command or "")
    assert step.risk_level == "medium"
    assert step.dry_run_supported is True
    assert step.rollback_supported is True
    assert step.apply_supported is False
    assert "默认配置路径" in (step.apply_blocked_reason or "")
    assert step.adapter_id == "linux.exposure.remove"


def test_apache_remove_exposure_filters_runtime_backup_paths_from_snapshot_context() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="apache.directory_listing.enabled", service_name="apache"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_exposure",
                    "title": "关闭 Apache 目录浏览",
                    "params": {
                        "service_name": "apache",
                        "config_key": "directory_listing_enabled",
                        "rule_id": "apache.directory_listing.enabled",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {
                "apache": {
                    "source_files": [
                        "/etc/apache2/sites-enabled/000-default.conf.bak.sa.20260421074824",
                    ],
                }
            },
            "host_checks": {},
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "/etc/apache2/sites-enabled/000-default.conf.bak.sa.20260421074824" not in (step.generated_command or "")
    assert "/etc/apache2/apache2.conf" in (step.generated_command or "")
    assert step.apply_supported is False
    assert "默认配置路径" in (step.apply_blocked_reason or "")


def test_samba_guest_access_remove_exposure_step_is_renderable() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="samba.guest.access.enabled", service_name="samba"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_exposure",
                    "title": "关闭 samba guest access",
                    "params": {
                        "service_name": "samba",
                        "config_key": "guest_access",
                        "rule_id": "samba.guest.access.enabled",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "/etc/samba/smb.conf" in (step.generated_command or "")
    assert "'map to guest': 'Never'" in (step.generated_command or "")
    assert "for svc in smbd samba nmbd; do" in (step.generated_command or "")


def test_tomcat_remove_path_without_backup_target_is_blocked_for_enterprise_execution() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="tomcat.manager.exposed", service_name="tomcat"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_exposure",
                    "title": "移除 Tomcat manager 暴露入口",
                    "params": {
                        "service_name": "tomcat",
                        "config_key": "manager_exposed",
                        "rule_id": "tomcat.manager.exposed",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "blocked"
    assert "备份目标" in (step.blocked_reason or "")
    assert step.rollback_supported is False


def test_samba_restrict_network_step_is_renderable_with_configured_admin_cidrs() -> None:
    original_admin_cidrs = settings.SECURITY_ADMIN_CIDRS
    settings.SECURITY_ADMIN_CIDRS = "192.168.130.0/24,10.10.10.0/24"
    try:
        planner = RemediationCommandPlanner(
            finding=_build_finding(rule_id="samba.writable_share.nse.confirmed", service_name="samba"),
            rendered_template={
                "actions": [
                    {
                        "action_type": "restrict_network",
                        "title": "限制 samba 暴露来源",
                        "params": {
                            "service_name": "samba",
                            "target_scope": "admin_segment_only",
                            "rule_id": "samba.writable_share.nse.confirmed",
                        },
                    }
                ]
            },
            snapshot=None,
            credential=None,
            snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
        )

        step = planner.build_steps()[0]

        assert step.execution_state == "ready"
        assert "'hosts allow': '127.0.0.1 ::1 192.168.130.0/24 10.10.10.0/24'" in (step.generated_command or "")
        assert "'hosts deny': '0.0.0.0/0 ::/0'" in (step.generated_command or "")
    finally:
        settings.SECURITY_ADMIN_CIDRS = original_admin_cidrs


def test_samba_restrict_network_step_requires_admin_cidrs() -> None:
    original_admin_cidrs = settings.SECURITY_ADMIN_CIDRS
    settings.SECURITY_ADMIN_CIDRS = ""
    try:
        planner = RemediationCommandPlanner(
            finding=_build_finding(rule_id="samba.writable_share.nse.confirmed", service_name="samba"),
            rendered_template={
                "actions": [
                    {
                        "action_type": "restrict_network",
                        "title": "限制 samba 暴露来源",
                        "params": {
                            "service_name": "samba",
                            "target_scope": "admin_segment_only",
                            "rule_id": "samba.writable_share.nse.confirmed",
                        },
                    }
                ]
            },
            snapshot=None,
            credential=None,
            snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
        )

        step = planner.build_steps()[0]

        assert step.execution_state == "blocked"
        assert "管理网段" in (step.blocked_reason or "")
    finally:
        settings.SECURITY_ADMIN_CIDRS = original_admin_cidrs


def test_apache_remove_exposure_prefers_collected_source_files() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="apache.webdav.enabled", service_name="apache"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_exposure",
                    "title": "关闭 Apache WebDAV",
                    "params": {
                        "service_name": "apache",
                        "config_key": "webdav_enabled",
                        "rule_id": "apache.webdav.enabled",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {
                "apache": {
                    "source_files": ["/opt/apache/conf/extra/webdav.conf"],
                }
            },
            "host_checks": {},
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "/opt/apache/conf/extra/webdav.conf" in (step.generated_command or "")
    assert "/etc/apache2/apache2.conf" not in (step.generated_command or "")


def test_sudo_full_privilege_rule_step_is_renderable() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="sudo.full_privilege_rule.enabled", service_name="sudo"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_config",
                    "title": "调整 sudo 配置：full_privilege_rule",
                    "params": {
                        "service_name": "sudo",
                        "config_key": "full_privilege_rule",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "visudo -cf /etc/sudoers" in (step.generated_command or "")
    assert "managed-by-sa" in (step.generated_command or "")


def test_nmap_legacy_privesc_permission_step_is_renderable() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="nmap.legacy_interactive_privesc.exposed", service_name="nmap"),
        rendered_template={
            "actions": [
                {
                    "action_type": "permission_set",
                    "title": "收紧 nmap 的权限配置",
                    "params": {
                        "service_name": "nmap",
                        "config_key": "suid_present",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {"nmap_local": {"binary_path": "/usr/bin/nmap"}},
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.generated_command == "chmod a-s /usr/bin/nmap"


def test_filter_login_user_required_suid_actions_keeps_upgrade_step() -> None:
    filtered, excluded = _filter_login_user_required_suid_actions(
        finding=_build_finding(rule_id="nmap.legacy_interactive_privesc.exposed", service_name="nmap"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 nmap",
                    "params": {
                        "service_name": "nmap",
                        "package_name": "nmap",
                        "rule_id": "nmap.legacy_interactive_privesc.exposed",
                    },
                },
                {
                    "action_type": "set_path_permission",
                    "title": "移除 nmap suid",
                    "params": {
                        "rule_id": "nmap.legacy_interactive_privesc.exposed",
                    },
                },
            ]
        },
        credential=None,
        snapshot_context={
            "detail_json": {"authorization": {"username": "msfadmin"}},
            "summary_json": {"login_user": "msfadmin"},
            "host_checks": {
                "nmap_local": {
                    "binary_path": "/usr/bin/nmap",
                    "suid_present": True,
                }
            },
        },
    )

    assert excluded == {"nmap"}
    assert [item["action_type"] for item in filtered["actions"]] == ["upgrade_package"]


def test_cron_root_writable_job_chain_permission_step_is_renderable() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="cron.root_writable_job_chain.exposed", service_name="cron"),
        rendered_template={
            "actions": [
                {
                    "action_type": "permission_set",
                    "title": "收紧 root cron 路径权限",
                    "params": {
                        "rule_id": "cron.root_writable_job_chain.exposed",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {
                "cron_local": {
                    "sample": [
                        {"path": "/var/spool/cron/crontabs/root"},
                    ]
                }
            },
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "chmod go-w /var/spool/cron/crontabs/root" in (step.generated_command or "")


def test_linux_host_dangerous_suid_permission_step_is_renderable() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="linux-host.dangerous_suid.present", service_name="linux-host"),
        rendered_template={
            "actions": [
                {
                    "action_type": "permission_set",
                    "title": "移除危险 suid/sgid",
                    "params": {
                        "rule_id": "linux-host.dangerous_suid.present",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {
                "suid_sgid": {
                    "dangerous_entries": ["/usr/bin/screen", "/usr/bin/nmap"],
                }
            },
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "chmod a-s /usr/bin/screen" in (step.generated_command or "")
    assert "chmod a-s /usr/bin/nmap" in (step.generated_command or "")


def test_linux_host_dangerous_suid_permission_step_excludes_login_user_required_binary() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="linux-host.dangerous_suid.present", service_name="linux-host"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_path_permission",
                    "title": "移除危险 suid/sgid",
                    "params": {
                        "rule_id": "linux-host.dangerous_suid.present",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {
                "suid_sgid": {
                    "dangerous_entries": ["/usr/bin/screen", "/usr/bin/vim"],
                }
            },
            "packages": [],
        },
        excluded_suid_binaries={"screen"},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.target_paths == ["/usr/bin/vim"]
    assert "chmod a-s /usr/bin/vim" in (step.generated_command or "")
    assert "screen" not in (step.generated_command or "")


def test_remove_path_step_is_renderable_with_explicit_target_path() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="phpmyadmin.path.exposed.apache", service_name="phpmyadmin"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_path",
                    "title": "下线 phpMyAdmin 暴露目录",
                    "params": {
                        "service_name": "phpmyadmin",
                    },
                    "target_paths": ["/usr/share/phpmyadmin"],
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.target_paths == ["/usr/share/phpmyadmin"]
    assert "mv /usr/share/phpmyadmin /usr/share/phpmyadmin.disabled.sa" in (step.generated_command or "")


def test_set_bind_scope_step_is_renderable_for_redis() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="redis.bind_all_interfaces.enabled", service_name="redis"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_bind_scope",
                    "title": "将 Redis 监听面收敛到管理网段",
                    "params": {
                        "service_name": "redis",
                        "config_key": "bind_all_interfaces",
                        "target_scope": "admin_segment_only",
                        "rule_id": "redis.bind_all_interfaces.enabled",
                    },
                    "target_files": ["/etc/redis/redis.conf"],
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "/etc/redis/redis.conf" in step.target_files
    assert "directive = 'bind'" in (step.generated_command or "")
    assert "protected-mode" in (step.generated_command or "")


def test_toggle_feature_step_is_renderable_for_apache_directory_listing() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="apache.directory_listing.enabled", service_name="apache"),
        rendered_template={
            "actions": [
                {
                    "action_type": "toggle_feature",
                    "title": "关闭 Apache 目录浏览",
                    "params": {
                        "service_name": "apache",
                        "config_key": "directory_listing_enabled",
                        "rule_id": "apache.directory_listing.enabled",
                    },
                    "target_files": ["/etc/httpd/conf.d/autoindex.conf"],
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "Indexes" in (step.generated_command or "")
    assert "systemctl reload" in (step.generated_command or "") or "service \"$svc\" reload" in (step.generated_command or "")


def test_set_access_policy_step_is_renderable_for_postgresql_trust_auth() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="postgresql.trust_auth_enabled", service_name="postgresql"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_access_policy",
                    "title": "收紧 PostgreSQL 访问策略",
                    "params": {
                        "service_name": "postgresql",
                        "config_key": "trust_auth_enabled",
                        "target_scope": "admin_segment_only",
                        "rule_id": "postgresql.trust_auth_enabled",
                    },
                    "target_files": ["/var/lib/pgsql/data/pg_hba.conf"],
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert any("pg_hba.conf" in path for path in step.target_files)
    assert "listen_addresses" in (step.generated_command or "")
    assert "trust" in (step.generated_command or "")


def test_set_path_permission_step_is_renderable_for_explicit_target_path() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="linux-host.dangerous_suid.present", service_name="linux-host"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_path_permission",
                    "title": "移除危险 suid/sgid",
                    "params": {
                        "rule_id": "linux-host.dangerous_suid.present",
                    },
                    "target_paths": ["/usr/bin/screen"],
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {
                "suid_sgid": {
                    "dangerous_entries": ["/usr/bin/screen"],
                }
            },
            "packages": [],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.target_paths == ["/usr/bin/screen"]
    assert step.generated_command == "chmod a-s /usr/bin/screen"


def test_build_asset_plans_skips_login_user_required_suid_only_plan(monkeypatch) -> None:
    finding = _build_finding(rule_id="linux-host.suid.screen.present", service_name="linux-host")

    monkeypatch.setattr(remediation_service, "get_manual_credential", lambda db, asset_id: None)
    monkeypatch.setattr(remediation_service, "get_latest_collection_snapshot", lambda db, asset_id: None)
    monkeypatch.setattr(remediation_service, "list_findings_by_asset", lambda db, asset_id: [finding])
    monkeypatch.setattr(remediation_service, "_open_asset_port_id_set", lambda db, findings: set())
    monkeypatch.setattr(remediation_service, "_finding_is_remediation_candidate", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        remediation_service,
        "_build_plan_from_finding",
        lambda *args, **kwargs: RemediationPlanRead(
            asset_id="asset-1",
            finding_id=finding.id,
            rule_id="linux-host.suid.screen.present",
            rule_name="screen suid",
            service_name="linux-host",
            severity=RiskSeverity.HIGH,
            summary="filtered",
            automation_level="callable",
            execution_ready=False,
            blocked_reasons=["当前登录用户依赖必要的 SUID 程序（screen），相关 SUID 权限问题默认不纳入自动修复计划"],
            steps=[],
            source_refs={"excluded_for_login_user_required_suid": True},
        ),
    )

    assert remediation_service.build_asset_plans(db=None, asset_id="asset-1") == {}


def test_upgrade_package_step_keeps_target_service_metadata() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ssh.openssh.package.outdated", service_name="ssh"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 OpenSSH 服务包",
                    "params": {
                        "service_name": "ssh",
                        "package_name": "openssh-server",
                        "package_manager": "dpkg",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {},
            "packages": [{"name": "openssh-server", "manager": "dpkg", "version": "1:8.9p1-3"}],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "apt-get install -y" in (step.generated_command or "")
    assert "openssh-server" in (step.generated_command or "")
    assert step.backup_plan is not None
    assert step.backup_plan.targets == ["dpkg:openssh-server"]
    assert step.rollback_supported is True
    assert step.rollback_command is not None
    assert "openssh-server=1:8.9p1-3" in (step.rollback_command or "")
    assert step.target_services == ["ssh"]


def test_upgrade_package_step_resolves_fixed_version_from_host_os_context() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="sudo.package.outdated", service_name="sudo"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 sudo 软件包",
                    "params": {
                        "service_name": "sudo",
                        "package_name": "sudo",
                        "package_manager": "dpkg",
                        "fixed_versions": {"ubuntu": {"20.04": "1.8.31-1ubuntu1.2"}},
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "os_release": "Ubuntu 20.04.6 LTS",
            "config_by_service": {},
            "host_checks": {},
            "packages": [{"name": "sudo", "manager": "dpkg", "version": "1:1.8.31-1ubuntu1.1"}],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.apply_supported is True
    assert "sudo=1.8.31-1ubuntu1.2" in (step.generated_command or "")
    assert step.rollback_supported is True
    assert "sudo=1:1.8.31-1ubuntu1.1" in (step.rollback_command or "")


def test_upgrade_package_step_is_preview_only_without_resolved_fixed_version() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="sudo.package.outdated", service_name="sudo"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 sudo 软件包",
                    "params": {
                        "service_name": "sudo",
                        "package_name": "sudo",
                        "package_manager": "dpkg",
                        "fixed_versions": {"ubuntu": {"20.04": "1.8.31-1ubuntu1.2"}},
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "config_by_service": {},
            "host_checks": {},
            "packages": [{"name": "sudo", "manager": "dpkg", "version": "1:1.8.31-1ubuntu1.1"}],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.apply_supported is False
    assert "发行版修复版本" in (step.apply_blocked_reason or "")


def test_upgrade_package_step_allows_rpm_apply_with_resolved_fixed_version() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ssh.openssh.rpm.outdated", service_name="ssh"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 openssh-server 软件包",
                    "params": {
                        "service_name": "ssh",
                        "package_name": "openssh-server",
                        "package_manager": "rpm",
                        "fixed_versions": {"rocky": {"9": "1:8.7p1-40.el9"}},
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context={
            "os_release": "Rocky Linux 9.4",
            "config_by_service": {},
            "host_checks": {},
            "packages": [{"name": "openssh-server", "manager": "rpm", "version": "1:8.7p1-38.el9"}],
        },
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.apply_supported is True
    assert step.rollback_supported is True
    assert "SA_ROLLBACK_VERSION=1:8.7p1-38.el9" in (step.rollback_command or "")
    assert "SA_FIXED_VERSION=1:8.7p1-40.el9" in (step.generated_command or "")
    assert 'SA_PACKAGE_TOKEN="${SA_PACKAGE_NAME}-${SA_FIXED_VERSION}"' in (step.generated_command or "")


def test_legacy_debian_upgrade_package_step_uses_family_candidates() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="apache.package.outdated", service_name="apache"),
        rendered_template={
            "actions": [
                {
                    "action_type": "upgrade_package",
                    "title": "升级 Apache 软件包",
                    "params": {
                        "service_name": "apache",
                        "package_name": "apache",
                        "package_manager": "dpkg",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context=_legacy_debian_context(
            packages=[{"name": "apache2", "manager": "dpkg", "version": "2.2.8-1ubuntu0.15"}],
        ),
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.fallback_strategy == remediation_service._LEGACY_DEBIAN_FALLBACK_STRATEGY
    assert step.fallback_candidates == ["apache2", "apache"]
    assert "自动解析软件包" in (step.generated_command or "")
    assert "自动替换组件" in (step.generated_command or "")
    assert "apt-get install -y" in (step.generated_command or "")


def test_legacy_debian_service_control_step_prefers_installed_ftp_daemon() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ftp.service.reload.required", service_name="ftp"),
        rendered_template={
            "actions": [
                {
                    "action_type": "restart_service",
                    "title": "重启 FTP 服务",
                    "params": {
                        "service_name": "ftp",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context=_legacy_debian_context(
            packages=[{"name": "vsftpd", "manager": "dpkg", "version": "2.0.7-1"}],
            services=[{"name": "vsftpd", "state": "running"}],
        ),
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.fallback_strategy == remediation_service._LEGACY_DEBIAN_FALLBACK_STRATEGY
    assert step.fallback_candidates == ["vsftpd", "proftpd"]
    assert "自动解析服务目标" in (step.generated_command or "")
    assert "apt-get install -y" in (step.generated_command or "")
    assert "/etc/init.d/$SA_RESOLVED_SERVICE restart" in (step.generated_command or "")


def test_legacy_debian_ssh_config_step_uses_absolute_validation_and_initd_reload() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ssh.password_authentication.enabled", service_name="ssh"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_config",
                    "title": "关闭 SSH 密码登录",
                    "params": {
                        "service_name": "ssh",
                        "config_key": "password_authentication",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context=_legacy_debian_context(
            config_by_service={"ssh": {"source_files": ["/etc/ssh/sshd_config"]}},
        ),
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.fallback_strategy == remediation_service._LEGACY_DEBIAN_FALLBACK_STRATEGY
    assert step.fallback_candidates == ["ssh"]
    assert "/usr/sbin/sshd -t" in (step.generated_command or "")
    assert "/etc/init.d/$SA_RESOLVED_SERVICE reload" in (step.generated_command or "")


def test_legacy_debian_linux_kernel_restart_step_is_blocked() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="linux-kernel.package.outdated", service_name="linux-kernel"),
        rendered_template={
            "actions": [
                {
                    "action_type": "restart_service",
                    "title": "重启内核服务",
                    "params": {
                        "service_name": "linux-kernel",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context=_legacy_debian_context(),
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "blocked"
    assert "人工安排重启窗口" in (step.blocked_reason or "")
    assert step.fallback_strategy == remediation_service._LEGACY_DEBIAN_FALLBACK_STRATEGY


def test_non_legacy_service_step_keeps_generic_rendering() -> None:
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ssh.service.reload.required", service_name="ssh"),
        rendered_template={
            "actions": [
                {
                    "action_type": "reload_service",
                    "title": "重载 SSH 服务",
                    "params": {
                        "service_name": "ssh",
                    },
                }
            ]
        },
        snapshot=None,
        credential=None,
        snapshot_context=_legacy_debian_context(os_release="Ubuntu 22.04", has_systemd="1", has_sysvinit="0"),
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert step.fallback_strategy is None
    assert step.fallback_candidates == []
    assert "for svc in ssh sshd; do" in (step.generated_command or "")


def test_service_control_command_tries_multiple_linux_service_managers_for_ssh() -> None:
    command = _build_service_control_command("reload", "ssh")

    assert "systemctl reload \"$svc\"" in command
    assert "systemctl reload \"${svc}.service\"" in command
    assert "systemctl try-reload-or-restart \"$svc\"" in command
    assert "service \"$svc\" reload" in command
    assert "service \"$svc\" restart" in command
    assert "rc-service \"$svc\" reload" in command
    assert "rc-service \"$svc\" restart" in command
    assert "/etc/init.d/$svc reload" in command
    assert "/etc/init.d/$svc restart" in command


def test_service_control_command_can_warn_without_failing_when_service_is_missing() -> None:
    command = _build_service_control_command("reload", "ssh", allow_missing=True)

    assert "未找到可管理的服务单元：ssh；已保留配置变更，请人工确认是否需要重载服务" in command
    assert command.endswith("exit 0")


def test_legacy_python_edit_commands_avoid_python3_only_syntax() -> None:
    replace_command = _build_replace_or_append_command(
        source_files=["/etc/ssh/sshd_config"],
        directive="PasswordAuthentication",
        value="no",
        validate_command="sshd -t",
        service_command=_build_service_control_command("reload", "ssh"),
    )
    comment_command = _build_comment_out_regex_command(
        source_files=["/etc/sudoers"],
        pattern=r"^\s*[^#\n].*\bALL\s*=\s*\(ALL(?::ALL)?\)\s+ALL\s*$",
        validate_command="visudo -cf /etc/sudoers",
        service_command=None,
    )
    ini_command = _build_ini_section_directive_command(
        source_files=["/etc/samba/smb.conf"],
        section_name="global",
        directives={"map to guest": "Never"},
        validate_command=None,
        service_command=_build_service_control_command("restart", "samba"),
    )

    for command in (replace_command, comment_command, ini_command):
        assert "import pathlib" not in command
        assert "path.read_text(" not in command
        assert "path.write_text(" not in command
        assert "codecs.open" in command
    assert "replacement = '%s %s' % (directive, value)" in replace_command
    assert "rendered.append('# managed-by-sa ' + line)" in comment_command
    assert "directive_keys = {}" in ini_command
    assert "rendered.append('[%s]' % section_name)" in ini_command


def test_docker_remove_tcp_listener_command_avoids_pathlib() -> None:
    command = _build_docker_remove_tcp_listener_command(["/etc/docker/daemon.json"])

    assert "import pathlib" not in command
    assert "docker daemon.json 不是合法 JSON" in command
    assert "json.dumps(data, indent=2)" in command


def test_package_upgrade_command_for_dpkg_is_noninteractive_and_preserves_conffiles() -> None:
    command = _build_package_upgrade_command(manager="dpkg", package_name="openssh-server", fixed_version=None)

    assert "export DEBIAN_FRONTEND=noninteractive" in command
    assert "export APT_LISTCHANGES_FRONTEND=none" in command
    assert "export NEEDRESTART_MODE=a" in command
    assert "Dpkg::Options::=--force-confdef" in command
    assert "Dpkg::Options::=--force-confold" in command


def test_package_upgrade_command_for_rpm_can_pin_fixed_version() -> None:
    command = _build_package_upgrade_command(
        manager="rpm",
        package_name="openssh-server",
        fixed_version="1:8.7p1-40.el9",
    )

    assert 'SA_PACKAGE_NAME=openssh-server' in command
    assert "SA_FIXED_VERSION=1:8.7p1-40.el9" in command
    assert 'dnf install -y "$SA_PACKAGE_TOKEN"' in command
    assert 'yum install -y "$SA_PACKAGE_TOKEN"' in command
    assert 'rpm -q --queryformat "%{EPOCHNUM}:%{VERSION}-%{RELEASE}" "$SA_PACKAGE_NAME"' in command
    assert "rpm 精确版本校验失败" in command


def test_package_rollback_command_for_dpkg_uses_exact_version() -> None:
    command = _build_package_rollback_command(
        manager="dpkg",
        package_name="openssh-server",
        rollback_version="1:8.9p1-3",
    )

    assert command is not None
    assert "apt-get update" in command
    assert "openssh-server=1:8.9p1-3" in command


def test_package_rollback_command_for_rpm_uses_exact_version_and_verifies_result() -> None:
    command = _build_package_rollback_command(
        manager="rpm",
        package_name="openssh-server",
        rollback_version="1:8.7p1-38.el9",
    )

    assert command is not None
    assert "SA_ROLLBACK_VERSION=1:8.7p1-38.el9" in command
    assert 'dnf downgrade -y "$SA_PACKAGE_TOKEN"' in command
    assert 'yum downgrade -y "$SA_PACKAGE_TOKEN"' in command
    assert "rpm 回滚版本校验失败" in command


def test_select_executable_plan_steps_rejects_preview_only_step_for_apply() -> None:
    preview_only_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="set_config",
        title="关闭 SSH 密码登录",
        supported=True,
        execution_state="ready",
        generated_command="echo preview",
        requires_confirmation=True,
        render_reason="preview only",
        apply_supported=False,
        apply_blocked_reason="当前仅支持预演",
    )

    with pytest.raises(RuntimeError, match="当前仅支持预演"):
        select_executable_plan_steps([preview_only_step], require_apply_supported=True)


def test_sudo_self_lock_step_is_blocked_for_sudo_chain() -> None:
    credential = SSHCredential(
        name="manual-asset-1",
        username="msfadmin",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        last_effective_privilege="sudo",
    )
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="sudo.full_privilege_rule.enabled", service_name="sudo"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_config",
                    "title": "调整 sudo 配置：full_privilege_rule",
                    "params": {
                        "service_name": "sudo",
                        "config_key": "full_privilege_rule",
                    },
                }
            ]
        },
        snapshot=None,
        credential=credential,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "blocked"
    assert step.blocked_reason == remediation_service._SELF_LOCK_SUDO_MESSAGE
    assert step.generated_command is None
    assert "/etc/sudoers" in step.target_files


def test_sudo_self_lock_step_remains_ready_for_root_direct() -> None:
    credential = SSHCredential(
        name="manual-asset-1",
        username="root",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        last_effective_privilege="root",
    )
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="sudo.full_privilege_rule.enabled", service_name="sudo"),
        rendered_template={
            "actions": [
                {
                    "action_type": "set_config",
                    "title": "调整 sudo 配置：full_privilege_rule",
                    "params": {
                        "service_name": "sudo",
                        "config_key": "full_privilege_rule",
                    },
                }
            ]
        },
        snapshot=None,
        credential=credential,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "ready"
    assert "visudo -cf /etc/sudoers" in (step.generated_command or "")


def test_sudo_self_lock_detection_blocks_explicit_sudoers_target_path() -> None:
    credential = SSHCredential(
        name="manual-asset-1",
        username="msfadmin",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        last_effective_privilege="sudo",
    )
    planner = RemediationCommandPlanner(
        finding=_build_finding(rule_id="ssh.password_authentication.enabled", service_name="ssh"),
        rendered_template={
            "actions": [
                {
                    "action_type": "remove_path",
                    "title": "移除 sudoers drop-in",
                    "params": {
                        "service_name": "ssh",
                    },
                    "target_paths": ["/etc/sudoers.d/ops-team"],
                }
            ]
        },
        snapshot=None,
        credential=credential,
        snapshot_context={"config_by_service": {}, "host_checks": {}, "packages": []},
    )

    step = planner.build_steps()[0]

    assert step.execution_state == "blocked"
    assert step.blocked_reason == remediation_service._SELF_LOCK_SUDO_MESSAGE
    assert step.target_paths == ["/etc/sudoers.d/ops-team"]


def test_select_executable_plan_steps_rejects_blocked_self_lock_step() -> None:
    ready_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="toggle_feature",
        title="关闭密码登录",
        supported=True,
        execution_state="ready",
        generated_command="echo ok",
        requires_confirmation=True,
        render_reason="test ready step",
    )
    blocked_step = RemediationPlanStepRead(
        step_id="step-2",
        action_type="set_config",
        title="调整 sudo 配置",
        supported=False,
        execution_state="blocked",
        blocked_reason=remediation_service._SELF_LOCK_SUDO_MESSAGE,
        generated_command=None,
        requires_confirmation=True,
        render_reason=remediation_service._SELF_LOCK_SUDO_MESSAGE,
        target_files=["/etc/sudoers"],
    )

    with pytest.raises(RuntimeError, match="sudo 管理链路"):
        select_executable_plan_steps([ready_step, blocked_step], submitted_step_ids=["step-2"])


def test_select_executable_plan_steps_keeps_all_ready_steps_when_ids_repeat() -> None:
    first_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="toggle_feature",
        title="关闭 Apache 目录列表",
        supported=True,
        execution_state="ready",
        generated_command="echo first",
        requires_confirmation=True,
        render_reason="first ready step",
    )
    second_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="toggle_feature",
        title="关闭 SSH 密码登录",
        supported=True,
        execution_state="ready",
        generated_command="echo second",
        requires_confirmation=True,
        render_reason="second ready step",
    )

    selected = select_executable_plan_steps([first_step, second_step])

    assert [item.title for item in selected] == ["关闭 Apache 目录列表", "关闭 SSH 密码登录"]


def test_select_executable_plan_steps_rejects_ambiguous_submitted_step_id() -> None:
    first_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="toggle_feature",
        title="关闭 Apache 目录列表",
        supported=True,
        execution_state="ready",
        generated_command="echo first",
        requires_confirmation=True,
        render_reason="first ready step",
    )
    second_step = RemediationPlanStepRead(
        step_id="step-1",
        action_type="toggle_feature",
        title="关闭 SSH 密码登录",
        supported=True,
        execution_state="ready",
        generated_command="echo second",
        requires_confirmation=True,
        render_reason="second ready step",
    )

    with pytest.raises(RuntimeError, match="重复步骤标识"):
        select_executable_plan_steps([first_step, second_step], submitted_step_ids=["step-1"])
