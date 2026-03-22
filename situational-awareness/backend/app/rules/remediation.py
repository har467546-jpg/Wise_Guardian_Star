from __future__ import annotations

import json
import re
from typing import Any

from app.rules.rule_matcher import (
    PackageMatchDefinition,
    RemediationActionDefinition,
    RuleDefinition,
    RuleRemediationDefinition,
)

_TEMPLATE_PATTERN = re.compile(r"{{\s*([a-zA-Z0-9_.-]+)\s*}}")
_EXPOSURE_KEYWORDS = ("exposed", "exposure", "directory_listing", "path", "manager", "webdav", "risky_methods")
_AUTH_KEYWORDS = (
    "anonymous",
    "unauthorized",
    "default_credential",
    "default_creds",
    "password_authentication",
    "permit_root_login",
    "permit_empty_passwords",
    "trust",
)
_LOCAL_PRIVESC_SERVICES = {"linux-host", "sudo", "polkit", "screen", "nmap", "docker", "systemd", "cron", "logrotate"}
_RELOADABLE_SERVICES = {"apache", "http", "nginx", "ssh", "sshd", "tomcat", "phpmyadmin", "twiki"}
_AUTO_ACTION_TYPES = {
    "upgrade_package",
    "set_config",
    "remove_config",
    "restart_service",
    "reload_service",
    "disable_service",
    "restrict_network",
    "remove_exposure",
    "permission_set",
    "toggle_feature",
    "set_bind_scope",
    "set_access_policy",
    "remove_path",
    "set_path_permission",
}
_REMOVED_LEGACY_ACTION_TYPES = {"rotate_credential", "manual_step"}
_REMOVE_EXPOSURE_KEYS = {
    "anonymous_enabled",
    "anonymous_write_enabled",
    "default_credentials",
    "directory_listing_enabled",
    "guest_access",
    "manager_exposed",
    "sample_apps_enabled",
    "webdav_enabled",
    "writable_guest_share",
}
_FEATURE_TOGGLE_KEYS = {
    "anonymous_enabled",
    "anonymous_write_enabled",
    "default_credentials",
    "directory_listing_enabled",
    "guest_access",
    "local_infile",
    "manager_exposed",
    "permit_empty_passwords",
    "permit_root_login",
    "password_authentication",
    "protected_mode",
    "pubkey_authentication",
    "sample_apps_enabled",
    "skip_grant_tables",
    "webdav_enabled",
    "writable_guest_share",
}
_BIND_SCOPE_KEYS = {
    "bind_all_interfaces",
    "listen_all_interfaces",
    "tcp_listener_without_tlsverify",
}
_ACCESS_POLICY_KEYS = {
    "requirepass",
    "trust_auth_enabled",
}
_DEFAULT_TARGET_FILES: dict[str, list[str]] = {
    "ssh": ["/etc/ssh/sshd_config"],
    "mysql": ["/etc/mysql/my.cnf", "/etc/my.cnf"],
    "sudo": ["/etc/sudoers"],
    "samba": ["/etc/samba/smb.conf"],
    "redis": ["/etc/redis/redis.conf", "/etc/redis.conf"],
    "postgresql": [
        "/etc/postgresql/16/main/postgresql.conf",
        "/etc/postgresql/16/main/pg_hba.conf",
        "/etc/postgresql/15/main/postgresql.conf",
        "/etc/postgresql/15/main/pg_hba.conf",
        "/var/lib/pgsql/data/postgresql.conf",
        "/var/lib/pgsql/data/pg_hba.conf",
    ],
    "apache": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/autoindex.conf"],
    "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf"],
    "docker": ["/etc/docker/daemon.json", "/etc/systemd/system/docker.service"],
    "vsftpd": ["/etc/vsftpd.conf"],
    "tomcat": ["/etc/tomcat/server.xml", "/var/lib/tomcat/webapps", "/opt/tomcat/webapps"],
    "php": ["/etc/php.ini", "/etc/php/*/apache2/php.ini", "/etc/php/*/fpm/php.ini"],
    "phpmyadmin": ["/etc/phpmyadmin/config.inc.php", "/usr/share/phpmyadmin"],
    "twiki": ["/var/www/twiki", "/usr/share/twiki", "/opt/twiki"],
    "cron": ["/etc/crontab", "/etc/cron.d"],
    "polkit": ["/etc/polkit-1/rules.d", "/usr/share/polkit-1/rules.d"],
    "linux-host": ["/usr/bin", "/usr/local/bin"],
    "nmap": ["/usr/bin/nmap", "/usr/local/bin/nmap"],
    "screen": ["/usr/bin/screen", "/usr/local/bin/screen"],
    "logrotate": ["/etc/logrotate.conf", "/etc/logrotate.d"],
}
_PATH_RULE_HINTS: dict[str, list[str]] = {
    "tomcat.manager": ["/manager", "/host-manager", "webapps/manager", "webapps/host-manager"],
    "phpmyadmin": ["/phpmyadmin", "/usr/share/phpmyadmin", "/var/www/html/phpmyadmin"],
    "twiki": ["/twiki", "/usr/share/twiki", "/var/www/twiki"],
    "sample_apps": ["/examples", "/docs", "/ROOT"],
    "directory_listing": ["/var/www", "/srv/www", "/usr/share/nginx/html"],
}


def resolve_rule_remediation(rule: RuleDefinition) -> RuleRemediationDefinition:
    generated = generate_rule_remediation(rule)
    if rule.remediation is None:
        return generated
    if rule.remediation.automation_level != "callable":
        return _with_merged_references(generated, rule)
    if any(action.action_type not in _AUTO_ACTION_TYPES for action in rule.remediation.actions):
        return _with_merged_references(generated, rule)
    return _normalize_remediation(rule.remediation, rule)


def serialize_remediation(remediation: RuleRemediationDefinition) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "summary": remediation.summary,
        "automation_level": remediation.automation_level,
        "actions": [],
    }
    if remediation.impact_summary:
        payload["impact_summary"] = remediation.impact_summary
    if remediation.precheck_items:
        payload["precheck_items"] = remediation.precheck_items
    if remediation.verify_items:
        payload["verify_items"] = remediation.verify_items
    if remediation.rollback_notes:
        payload["rollback_notes"] = remediation.rollback_notes
    for action in remediation.actions:
        item: dict[str, Any] = {
            "action_type": action.action_type,
            "title": action.title,
            "params": action.params,
        }
        if action.requires_confirmation is not None:
            item["requires_confirmation"] = action.requires_confirmation
        if action.rollback_hint is not None:
            item["rollback_hint"] = action.rollback_hint
        if action.target_files:
            item["target_files"] = action.target_files
        if action.target_services:
            item["target_services"] = action.target_services
        if action.target_paths:
            item["target_paths"] = action.target_paths
        if action.verify_items:
            item["verify_items"] = action.verify_items
        payload["actions"].append(item)
    if remediation.references:
        payload["references"] = remediation.references
    return payload


def render_remediation_with_context(
    remediation: RuleRemediationDefinition,
    context: dict[str, Any],
) -> dict[str, Any]:
    return _render_value(serialize_remediation(remediation), context)


def generate_rule_remediation(rule: RuleDefinition) -> RuleRemediationDefinition:
    actions: list[RemediationActionDefinition] = []
    summary_parts: list[str] = []

    if rule.package_conditions is not None:
        actions.append(_build_package_upgrade_action(rule.package_conditions, service_name=rule.service))
        restart_action = _build_service_reload_action(rule.service)
        if restart_action is not None:
            actions.append(restart_action)
        summary_parts.append(f"升级 {rule.package_conditions.name} 软件包到发行版修复版本")
    elif rule.version_constraint:
        actions.append(_build_version_upgrade_action(rule))
        restart_action = _build_service_reload_action(rule.service)
        if restart_action is not None:
            actions.append(restart_action)
        summary_parts.append(f"升级或替换受影响的 {rule.service} 版本")

    if rule.config_conditions:
        config_actions = _build_config_actions(rule)
        actions.extend(config_actions)
        if config_actions:
            summary_parts.append(f"收敛 {rule.service} 的配置与暴露面")

    if rule.nse_conditions and not rule.config_conditions:
        exposure_actions = _build_exposure_actions(rule)
        actions.extend(exposure_actions)
        if exposure_actions:
            summary_parts.append(f"收敛 {rule.service} 的远程暴露入口")

    if _is_local_privesc_rule(rule):
        local_actions = _build_local_privesc_actions(
            rule,
            include_upgrade_action=not (rule.package_conditions is not None or bool(rule.version_constraint)),
        )
        actions.extend(local_actions)
        if local_actions:
            summary_parts.append("收敛本地提权暴露链")

    deduped_actions = _dedupe_actions(actions)
    if not deduped_actions:
        deduped_actions = _build_fallback_auto_actions(rule)

    summary = "；".join(dict.fromkeys(item.strip() for item in summary_parts if item.strip()))
    if not summary:
        summary = _default_summary(rule)

    return RuleRemediationDefinition(
        summary=summary,
        automation_level="callable",
        impact_summary=_default_impact_summary(rule, deduped_actions),
        precheck_items=_default_precheck_items(rule, deduped_actions),
        verify_items=_default_verify_items(rule, deduped_actions),
        rollback_notes=_default_rollback_notes(rule, deduped_actions),
        actions=[_normalize_action(action, rule) for action in deduped_actions],
        references=_merged_references(rule.references),
    )


def _build_package_upgrade_action(
    package_condition: PackageMatchDefinition,
    *,
    service_name: str,
) -> RemediationActionDefinition:
    return RemediationActionDefinition(
        action_type="upgrade_package",
        title=f"升级 {package_condition.name} 到已修复版本",
        params={
            "service_name": service_name,
            "package_name": package_condition.name,
            "package_manager": package_condition.manager,
            "compare": package_condition.compare,
            "fixed_versions": package_condition.fixed_versions,
        },
        requires_confirmation=True,
        rollback_hint=f"保留 {package_condition.name} 升级前的包版本与发行版回滚方案。",
        target_services=_dedupe_strings([service_name]),
        verify_items=_default_service_verify_items(service_name),
    )


def _build_version_upgrade_action(rule: RuleDefinition) -> RemediationActionDefinition:
    return RemediationActionDefinition(
        action_type="upgrade_package",
        title=f"升级 {rule.service} 到不受影响版本",
        params={
            "service_name": rule.service,
            "package_name": rule.service,
            "version_constraint": rule.version_constraint,
            "rule_id": rule.rule_id,
        },
        requires_confirmation=True,
        rollback_hint=f"记录 {rule.service} 当前版本，并在变更窗口内完成升级回退验证。",
        target_services=_dedupe_strings([rule.service]),
        verify_items=_default_service_verify_items(rule.service),
    )


def _build_service_reload_action(service_name: str) -> RemediationActionDefinition | None:
    normalized = (service_name or "").strip().lower()
    if not normalized:
        return None
    action_type = "reload_service" if normalized in _RELOADABLE_SERVICES else "restart_service"
    title = "重载服务配置" if action_type == "reload_service" else "重启服务使修复生效"
    return RemediationActionDefinition(
        action_type=action_type,
        title=f"{title}：{normalized}",
        params={"service_name": normalized},
        requires_confirmation=True,
        rollback_hint="确认服务管理窗口与健康检查后再执行回滚。",
        target_services=[normalized],
        verify_items=_default_service_verify_items(normalized),
    )


def _build_config_actions(rule: RuleDefinition) -> list[RemediationActionDefinition]:
    actions: list[RemediationActionDefinition] = []
    for key, operations in (rule.config_conditions or {}).items():
        action = _build_config_action(rule, key, operations)
        if action is not None:
            actions.append(action)
    return actions


def _build_config_action(
    rule: RuleDefinition,
    key: str,
    operations: dict[str, Any],
) -> RemediationActionDefinition | None:
    normalized_key = key.strip().lower()
    action_type = _select_action_type(normalized_key, rule.rule_id)
    safe_value = _suggest_secure_value(normalized_key, operations)
    title = _action_title(action_type, rule.service, normalized_key)
    params: dict[str, Any]
    target_paths = _infer_target_paths(rule, action_type)

    if action_type == "remove_config":
        params = {
            "service_name": rule.service,
            "config_key": normalized_key,
            "remove_tokens": _extract_risky_tokens(operations),
        }
    elif action_type == "set_bind_scope":
        params = {
            "service_name": rule.service,
            "config_key": normalized_key,
            "target_scope": safe_value or "admin_segment_only",
            "rule_id": rule.rule_id,
        }
    elif action_type == "set_access_policy":
        params = {
            "service_name": rule.service,
            "config_key": normalized_key,
            "target_policy": safe_value or "least_privilege",
            "rule_id": rule.rule_id,
        }
    elif action_type == "set_path_permission":
        params = {
            "service_name": rule.service,
            "config_key": normalized_key,
            "target_value": safe_value or "remove_unsafe_permission",
            "rule_id": rule.rule_id,
        }
    elif action_type == "toggle_feature":
        params = {
            "service_name": rule.service,
            "config_key": normalized_key,
            "feature_key": normalized_key,
            "desired_state": True if safe_value is True else False,
            "rule_id": rule.rule_id,
        }
    else:
        if safe_value is None:
            params = {
                "service_name": rule.service,
                "config_key": normalized_key,
                "rule_id": rule.rule_id,
            }
        else:
            params = {
                "service_name": rule.service,
                "config_key": normalized_key,
                "target_value": safe_value,
            }

    return RemediationActionDefinition(
        action_type=action_type,
        title=title,
        params=params,
        requires_confirmation=action_type not in {"reload_service"},
        rollback_hint="变更前保留原配置并验证业务影响。",
        target_files=_default_target_files(rule.service, action_type),
        target_services=_default_target_services(rule.service, action_type),
        target_paths=target_paths,
        verify_items=_default_action_verify_items(
            action_type=action_type,
            service_name=rule.service,
            target_paths=target_paths,
        ),
    )


def _build_exposure_actions(rule: RuleDefinition) -> list[RemediationActionDefinition]:
    rule_id = rule.rule_id.lower()
    actions: list[RemediationActionDefinition] = []
    target_paths = _infer_target_paths(rule, "remove_path")
    if "backdoor" in rule_id:
        actions.append(
            RemediationActionDefinition(
                action_type="disable_service",
                title=f"临时下线受影响的 {rule.service} 服务",
                params={"service_name": rule.service},
                requires_confirmation=True,
                rollback_hint="修复完成并复测通过后再恢复服务。",
                target_services=_default_target_services(rule.service, "disable_service"),
                verify_items=_default_service_verify_items(rule.service),
            )
        )
        actions.append(_build_version_upgrade_action(rule))
        return actions

    if any(keyword in rule_id for keyword in _AUTH_KEYWORDS):
        feature_key = _infer_auth_feature_key(rule)
        actions.append(
            RemediationActionDefinition(
                action_type="toggle_feature",
                title=f"关闭 {rule.service} 的弱认证或匿名入口",
                params={
                    "service_name": rule.service,
                    "config_key": feature_key,
                    "feature_key": feature_key,
                    "desired_state": False,
                    "rule_id": rule.rule_id,
                },
                requires_confirmation=True,
                rollback_hint="保留原认证策略备份并验证替代认证方式。",
                target_files=_default_target_files(rule.service, "toggle_feature"),
                target_services=_default_target_services(rule.service, "toggle_feature"),
                verify_items=_default_action_verify_items(action_type="toggle_feature", service_name=rule.service, target_paths=[]),
            )
        )
        actions.append(
            RemediationActionDefinition(
                action_type="set_bind_scope",
                title=f"限制 {rule.service} 管理入口来源网段",
                params={"service_name": rule.service, "target_scope": "admin_segment_only", "rule_id": rule.rule_id},
                requires_confirmation=True,
                rollback_hint="保留变更前的访问控制策略。",
                target_files=_default_target_files(rule.service, "set_bind_scope"),
                target_services=_default_target_services(rule.service, "set_bind_scope"),
                verify_items=_default_action_verify_items(action_type="set_bind_scope", service_name=rule.service, target_paths=[]),
            )
        )
        return actions

    if any(keyword in rule_id for keyword in _EXPOSURE_KEYWORDS):
        remove_action_type = "remove_path" if target_paths else "toggle_feature"
        remove_params: dict[str, Any] = {
            "service_name": rule.service,
            "rule_id": rule.rule_id,
            "exposure_id": rule.rule_id,
        }
        if remove_action_type == "toggle_feature":
            feature_key = _infer_exposure_feature_key(rule)
            remove_params.update(
                {
                    "config_key": feature_key,
                    "feature_key": feature_key,
                    "desired_state": False,
                }
            )
        actions.append(
            RemediationActionDefinition(
                action_type=remove_action_type,
                title=f"下线或隐藏 {rule.service} 暴露面",
                params=remove_params,
                requires_confirmation=True,
                rollback_hint="确认替代访问路径或管理入口后再回滚。",
                target_files=_default_target_files(rule.service, remove_action_type),
                target_services=_default_target_services(rule.service, remove_action_type),
                target_paths=target_paths,
                verify_items=_default_action_verify_items(
                    action_type=remove_action_type,
                    service_name=rule.service,
                    target_paths=target_paths,
                ),
            )
        )
        if remove_action_type != "remove_path":
            actions.append(
                RemediationActionDefinition(
                    action_type="set_bind_scope",
                    title=f"限制 {rule.service} 暴露来源",
                    params={"service_name": rule.service, "target_scope": "admin_segment_only", "rule_id": rule.rule_id},
                    requires_confirmation=True,
                    rollback_hint="回滚前确认访问控制变更不会重新暴露公网或办公网。",
                    target_files=_default_target_files(rule.service, "set_bind_scope"),
                    target_services=_default_target_services(rule.service, "set_bind_scope"),
                    verify_items=_default_action_verify_items(action_type="set_bind_scope", service_name=rule.service, target_paths=[]),
                )
            )
        return actions

    if rule.service and rule.service not in {"http", "https"}:
        actions.append(
            RemediationActionDefinition(
                action_type="disable_service",
                title=f"临时下线受影响的 {rule.service} 服务",
                params={"service_name": rule.service},
                requires_confirmation=True,
                rollback_hint="修复完成并复测通过后再恢复服务。",
                target_services=_default_target_services(rule.service, "disable_service"),
                verify_items=_default_service_verify_items(rule.service),
            )
        )
    actions.append(
        RemediationActionDefinition(
            action_type="set_bind_scope",
            title=f"限制 {rule.service} 暴露来源",
            params={"service_name": rule.service, "target_scope": "admin_segment_only", "rule_id": rule.rule_id},
            requires_confirmation=True,
            rollback_hint="保留原访问控制策略并在回滚前核实业务影响。",
            target_files=_default_target_files(rule.service, "set_bind_scope"),
            target_services=_default_target_services(rule.service, "set_bind_scope"),
            verify_items=_default_action_verify_items(action_type="set_bind_scope", service_name=rule.service, target_paths=[]),
        )
    )
    return actions


def _build_local_privesc_actions(
    rule: RuleDefinition,
    *,
    include_upgrade_action: bool,
) -> list[RemediationActionDefinition]:
    rule_id = rule.rule_id.lower()
    actions: list[RemediationActionDefinition] = []
    target_paths = _infer_target_paths(rule, "set_path_permission")
    if include_upgrade_action and (rule.package_conditions is not None or rule.version_constraint):
        package_name = rule.package_conditions.name if rule.package_conditions is not None else rule.service
        actions.append(
            RemediationActionDefinition(
                action_type="upgrade_package",
                title=f"升级本地组件 {package_name}",
                params={
                    "service_name": rule.service,
                    "package_name": package_name,
                    "version_constraint": rule.version_constraint,
                    "fixed_versions": rule.package_conditions.fixed_versions if rule.package_conditions else None,
                },
                requires_confirmation=True,
                rollback_hint="保留升级前软件包版本和系统快照。",
                target_services=_default_target_services(rule.service, "upgrade_package"),
                verify_items=_default_service_verify_items(rule.service),
            )
        )
    if "socket" in rule_id or "group" in rule_id or "writable" in rule_id or "suid" in rule_id or "capability" in rule_id:
        actions.append(
            RemediationActionDefinition(
                action_type="set_path_permission",
                title="移除危险文件权限链",
                params={
                    "service_name": rule.service,
                    "target_value": "remove_unsafe_permission",
                    "rule_id": rule.rule_id,
                },
                requires_confirmation=True,
                rollback_hint="保留原始权限元数据并先做业务兼容性验证。",
                target_paths=target_paths,
                verify_items=_default_action_verify_items(
                    action_type="set_path_permission",
                    service_name=rule.service,
                    target_paths=target_paths,
                ),
            )
        )
    if "setenv" in rule_id or "env_keep" in rule_id:
        actions.append(
            RemediationActionDefinition(
                action_type="remove_config",
                title="移除危险 sudo 环境透传配置",
                params={
                    "service_name": rule.service,
                    "config_key": "env_keep",
                    "remove_tokens": ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH"],
                },
                requires_confirmation=True,
                rollback_hint="保留 sudoers 变更前备份并验证管理脚本兼容性。",
                target_files=_default_target_files(rule.service, "remove_config"),
                target_services=_default_target_services(rule.service, "remove_config"),
                verify_items=_default_action_verify_items(action_type="remove_config", service_name=rule.service, target_paths=[]),
            )
        )
    return actions


def _build_fallback_auto_actions(rule: RuleDefinition) -> list[RemediationActionDefinition]:
    actions: list[RemediationActionDefinition] = []
    if rule.version_constraint or rule.package_conditions is not None:
        actions.append(_build_version_upgrade_action(rule))
        restart_action = _build_service_reload_action(rule.service)
        if restart_action is not None:
            actions.append(restart_action)
    else:
        actions.append(
            RemediationActionDefinition(
                action_type="set_bind_scope",
                title=f"限制 {rule.service} 暴露来源",
                params={"service_name": rule.service, "target_scope": "admin_segment_only", "rule_id": rule.rule_id},
                requires_confirmation=True,
                rollback_hint="回滚前确认业务网段与管理网段边界。",
                target_files=_default_target_files(rule.service, "set_bind_scope"),
                target_services=_default_target_services(rule.service, "set_bind_scope"),
                verify_items=_default_action_verify_items(action_type="set_bind_scope", service_name=rule.service, target_paths=[]),
            )
        )
        if rule.service and rule.service not in {"http", "https"}:
            actions.append(
                RemediationActionDefinition(
                    action_type="disable_service",
                    title=f"临时下线 {rule.service} 暴露面",
                    params={"service_name": rule.service},
                    requires_confirmation=True,
                    rollback_hint="修复完成并确认替代路径后再恢复。",
                    target_services=_default_target_services(rule.service, "disable_service"),
                    verify_items=_default_service_verify_items(rule.service),
                )
            )
    return _dedupe_actions(actions)


def _select_action_type(config_key: str, rule_id: str) -> str:
    key = f"{rule_id.lower()}::{config_key}"
    if config_key in _FEATURE_TOGGLE_KEYS or any(
        token in key for token in ("directory_listing", "webdav", "manager_exposed", "default_credentials", "anonymous", "guest", "sample_apps")
    ):
        return "toggle_feature"
    if config_key in _ACCESS_POLICY_KEYS or "trust" in key:
        return "set_access_policy"
    if config_key in _BIND_SCOPE_KEYS or any(token in key for token in ("bind", "listen", "interface", "exposure", "remote_api", "tcp_listener")):
        return "set_bind_scope"
    if "env_keep" in key:
        return "remove_config"
    if any(token in key for token in ("writable", "suid", "capability", "permission", "socket", "group")):
        return "set_path_permission"
    return "set_config"


def _action_title(action_type: str, service_name: str, config_key: str) -> str:
    if action_type == "set_bind_scope":
        return f"限制 {service_name} 的监听与来源范围"
    if action_type == "toggle_feature":
        return f"关闭 {service_name} 的高风险特性"
    if action_type == "set_access_policy":
        return f"收紧 {service_name} 的访问策略"
    if action_type == "set_path_permission":
        return f"收紧 {service_name} 的本地路径权限"
    if action_type == "remove_path":
        return f"移除 {service_name} 的暴露路径或入口"
    if action_type == "remove_config":
        return f"移除 {service_name} 中的危险配置项"
    return f"调整 {service_name} 配置：{config_key}"


def _suggest_secure_value(config_key: str, operations: dict[str, Any]) -> Any:
    key = config_key.lower()
    if any(token in key for token in ("password", "credential", "secret", "requirepass")) and operations.get("exists") is False:
        return None
    if any(token in key for token in ("default_credentials", "anonymous", "guest")):
        return False
    if "env_keep" in key:
        return "remove_unsafe_entries"
    if "bind" in key or "listen" in key or "interface" in key:
        return "admin_segment_only"
    if any(token in key for token in ("directory_listing", "webdav", "sample_apps", "manager_exposed", "tcp_listener_without_tlsverify", "trust_auth")):
        return False
    if any(token in key for token in ("anonymous", "guest", "empty_password", "permit_root_login", "password_authentication")):
        return False
    if any(token in key for token in ("pubkey_authentication", "protected_mode", "tlsverify")):
        return True
    if any(token in key for token in ("skip_grant_tables", "local_infile", "setenv")):
        return False

    if "eq" in operations and isinstance(operations["eq"], bool):
        return not operations["eq"]
    if "eq" in operations and isinstance(operations["eq"], str):
        eq_value = operations["eq"].strip().lower()
        if eq_value in {"yes", "on", "true", "enabled"}:
            return "no"
        if eq_value in {"no", "off", "false", "disabled"}:
            return "yes"
    if operations.get("exists") is False:
        return None
    if "contains" in operations:
        return None
    return None


def _extract_risky_tokens(operations: dict[str, Any]) -> list[str]:
    value = operations.get("contains")
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _infer_auth_feature_key(rule: RuleDefinition) -> str:
    rule_id = rule.rule_id.lower()
    if "anonymous" in rule_id:
        return "anonymous_enabled"
    if "default_credential" in rule_id or "default_creds" in rule_id:
        return "default_credentials"
    if "password_authentication" in rule_id:
        return "password_authentication"
    if "permit_root_login" in rule_id:
        return "permit_root_login"
    if "permit_empty_passwords" in rule_id:
        return "permit_empty_passwords"
    if "trust" in rule_id:
        return "trust_auth_enabled"
    return "weak_authentication"


def _infer_exposure_feature_key(rule: RuleDefinition) -> str:
    rule_id = rule.rule_id.lower()
    if "directory_listing" in rule_id:
        return "directory_listing_enabled"
    if "webdav" in rule_id or "risky_methods" in rule_id:
        return "webdav_enabled"
    if "sample_apps" in rule_id:
        return "sample_apps_enabled"
    if "manager" in rule_id:
        return "manager_exposed"
    if "guest" in rule_id:
        return "guest_access"
    return "exposure_disabled"


def _infer_target_paths(rule: RuleDefinition, action_type: str) -> list[str]:
    if action_type not in {"remove_path", "set_path_permission"}:
        return []
    rule_id = rule.rule_id.lower()
    inferred: list[str] = []
    if "tomcat" in rule_id and "manager" in rule_id:
        inferred.extend(_PATH_RULE_HINTS["tomcat.manager"])
    if "phpmyadmin" in rule_id:
        inferred.extend(_PATH_RULE_HINTS["phpmyadmin"])
    if "twiki" in rule_id:
        inferred.extend(_PATH_RULE_HINTS["twiki"])
    if "sample_apps" in rule_id:
        inferred.extend(_PATH_RULE_HINTS["sample_apps"])
    if "directory_listing" in rule_id:
        inferred.extend(_PATH_RULE_HINTS["directory_listing"])
    if any(token in rule_id for token in ("suid", "writable", "capability", "screen", "nmap", "cron", "polkit")):
        inferred.extend(_DEFAULT_TARGET_FILES.get(rule.service, []))
    return _dedupe_strings(inferred)


def _default_target_files(service_name: str, action_type: str) -> list[str]:
    normalized = str(service_name or "").strip().lower()
    if action_type in {"upgrade_package", "reload_service", "restart_service", "disable_service"}:
        return []
    return list(_DEFAULT_TARGET_FILES.get(normalized, []))


def _default_target_services(service_name: str, action_type: str) -> list[str]:
    normalized = str(service_name or "").strip().lower()
    if not normalized:
        return []
    if action_type in {"remove_path"} and normalized in {"phpmyadmin", "twiki"}:
        return []
    return [normalized]


def _default_action_verify_items(*, action_type: str, service_name: str, target_paths: list[str]) -> list[str]:
    normalized = str(service_name or "").strip().lower()
    if action_type == "upgrade_package":
        return _default_service_verify_items(normalized)
    if action_type in {"reload_service", "restart_service", "disable_service"}:
        return _default_service_verify_items(normalized)
    if action_type in {"toggle_feature", "set_config", "remove_config"}:
        return [f"确认 {normalized or '目标服务'} 风险配置已按预期生效。"]
    if action_type in {"set_bind_scope", "set_access_policy"}:
        return [f"确认 {normalized or '目标服务'} 仅对管理范围开放，且未再暴露高风险入口。"]
    if action_type == "remove_path":
        return [f"确认暴露路径已不可访问：{path}" for path in target_paths[:3]] or ["确认高风险暴露路径已不可访问。"]
    if action_type == "set_path_permission":
        return [f"确认本地路径权限已收敛：{path}" for path in target_paths[:3]] or ["确认危险文件权限链已被移除。"]
    return []


def _default_service_verify_items(service_name: str) -> list[str]:
    normalized = str(service_name or "").strip().lower()
    if not normalized:
        return ["确认修复动作执行成功并完成目标服务健康检查。"]
    return [
        f"确认 {normalized} 相关风险点已复测通过。",
        f"确认 {normalized} 服务健康检查与关键访问路径正常。",
    ]


def _default_precheck_items(rule: RuleDefinition, actions: list[RemediationActionDefinition]) -> list[str]:
    items = list(rule.preconditions or [])
    if any(action.action_type == "upgrade_package" for action in actions):
        items.append("确认目标主机已识别软件包管理器，并记录当前版本与回滚版本。")
    if any(action.action_type in {"toggle_feature", "set_bind_scope", "set_access_policy", "set_config", "remove_config", "remove_path"} for action in actions):
        items.append("确认已完成 SSH 深度检查，并识别稳定的配置文件或暴露路径。")
    if any(action.action_type == "set_path_permission" for action in actions):
        items.append("确认目标文件或目录权限收敛不会影响现有作业、计划任务或运维脚本。")
    if any(action.requires_confirmation for action in actions):
        items.append("确认当前处于可接受的业务维护窗口，并已准备配置或路径备份。")
    return _dedupe_strings(items)


def _default_verify_items(rule: RuleDefinition, actions: list[RemediationActionDefinition]) -> list[str]:
    items = list(rule.verify_playbook or [])
    for action in actions:
        items.extend(action.verify_items)
    return _dedupe_strings(items)


def _default_rollback_notes(rule: RuleDefinition, actions: list[RemediationActionDefinition]) -> list[str]:
    notes = [action.rollback_hint for action in actions if action.rollback_hint]
    if not notes:
        if rule.version_constraint or rule.package_conditions:
            notes.append(f"保留 {rule.service} 当前版本信息和相关配置备份，以便快速回退。")
        else:
            notes.append("执行前保留原配置、路径或权限元数据，必要时按备份恢复。")
    return _dedupe_strings(notes)


def _default_impact_summary(rule: RuleDefinition, actions: list[RemediationActionDefinition]) -> str:
    action_types = {action.action_type for action in actions}
    service_name = rule.service
    if "upgrade_package" in action_types:
        return f"该模板会升级 {service_name} 或相关组件，并在修复后重载或重启服务，期间可能出现短暂业务抖动。"
    if {"toggle_feature", "set_bind_scope", "set_access_policy", "remove_path"} & action_types:
        return f"该模板会收敛 {service_name} 的暴露入口、监听范围或访问策略，可能影响当前管理路径与来源网段。"
    if "set_path_permission" in action_types:
        return "该模板会调整本地文件或目录权限，可能影响依赖危险权限链的脚本、计划任务或提权路径。"
    return f"该模板会对 {service_name} 执行自动化加固与复测，可能影响相关服务配置与运行时状态。"


def _normalize_remediation(remediation: RuleRemediationDefinition, rule: RuleDefinition) -> RuleRemediationDefinition:
    normalized_actions = [_normalize_action(action, rule) for action in _dedupe_actions(remediation.actions)]
    verify_items = remediation.verify_items or rule.verify_playbook or _collect_action_verify_items(normalized_actions)
    rollback_notes = remediation.rollback_notes or _collect_action_rollbacks(normalized_actions)
    return RuleRemediationDefinition(
        summary=remediation.summary,
        automation_level="callable",
        impact_summary=remediation.impact_summary or _default_impact_summary(rule, normalized_actions),
        precheck_items=remediation.precheck_items or rule.preconditions or _default_precheck_items(rule, normalized_actions),
        verify_items=_dedupe_strings(verify_items),
        rollback_notes=_dedupe_strings(rollback_notes or _default_rollback_notes(rule, normalized_actions)),
        actions=normalized_actions,
        references=_merged_references(rule.references, remediation.references),
    )


def _normalize_action(action: RemediationActionDefinition, rule: RuleDefinition) -> RemediationActionDefinition:
    target_paths = action.target_paths or _infer_target_paths(rule, action.action_type)
    return RemediationActionDefinition(
        action_type=action.action_type,
        title=action.title,
        params=action.params,
        requires_confirmation=action.requires_confirmation,
        rollback_hint=action.rollback_hint,
        target_files=_dedupe_strings(action.target_files or _default_target_files(rule.service, action.action_type)),
        target_services=_dedupe_strings(action.target_services or _default_target_services(rule.service, action.action_type)),
        target_paths=_dedupe_strings(target_paths),
        verify_items=_dedupe_strings(
            action.verify_items
            or _default_action_verify_items(
                action_type=action.action_type,
                service_name=rule.service,
                target_paths=target_paths,
            )
        ),
    )


def _collect_action_verify_items(actions: list[RemediationActionDefinition]) -> list[str]:
    items: list[str] = []
    for action in actions:
        items.extend(action.verify_items)
    return _dedupe_strings(items)


def _collect_action_rollbacks(actions: list[RemediationActionDefinition]) -> list[str]:
    return _dedupe_strings([action.rollback_hint for action in actions if action.rollback_hint])


def _is_local_privesc_rule(rule: RuleDefinition) -> bool:
    tags = {tag.strip().lower() for tag in rule.tags}
    if "authorized-local" in tags or "local-privesc" in tags:
        return True
    return rule.service in _LOCAL_PRIVESC_SERVICES


def _default_summary(rule: RuleDefinition) -> str:
    if rule.mitigations:
        return rule.mitigations[0]
    if rule.package_conditions or rule.version_constraint:
        return f"升级 {rule.service} 并移除当前风险版本暴露。"
    if rule.config_conditions:
        return f"调整 {rule.service} 配置并收敛相关暴露。"
    if rule.nse_conditions:
        return f"收敛 {rule.service} 暴露面并按最小权限原则整改。"
    return f"收敛 {rule.service} 当前暴露面并完成自动复测。"


def _dedupe_actions(actions: list[RemediationActionDefinition]) -> list[RemediationActionDefinition]:
    deduped: list[RemediationActionDefinition] = []
    seen: set[str] = set()
    for action in actions:
        signature = json.dumps(
            {
                "action_type": action.action_type,
                "title": action.title,
                "params": action.params,
                "target_files": action.target_files,
                "target_services": action.target_services,
                "target_paths": action.target_paths,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(action)
    return deduped


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    for item in values:
        normalized = str(item or "").strip()
        if normalized and normalized not in deduped:
            deduped.append(normalized)
    return deduped


def _merged_references(*reference_groups: list[str] | None) -> list[str]:
    merged: list[str] = []
    for group in reference_groups:
        if not group:
            continue
        for item in group:
            normalized = str(item or "").strip()
            if normalized and normalized not in merged:
                merged.append(normalized)
    return merged


def _with_merged_references(remediation: RuleRemediationDefinition, rule: RuleDefinition) -> RuleRemediationDefinition:
    return RuleRemediationDefinition(
        summary=remediation.summary,
        automation_level="callable",
        impact_summary=remediation.impact_summary,
        precheck_items=remediation.precheck_items,
        verify_items=remediation.verify_items,
        rollback_notes=remediation.rollback_notes,
        actions=remediation.actions,
        references=_merged_references(rule.references, remediation.references),
    )


def _render_value(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _render_string(value, context)
    if isinstance(value, list):
        return [_render_value(item, context) for item in value]
    if isinstance(value, dict):
        return {key: _render_value(item, context) for key, item in value.items()}
    return value


def _render_string(value: str, context: dict[str, Any]) -> Any:
    full_match = _TEMPLATE_PATTERN.fullmatch(value)
    if full_match:
        resolved = _resolve_context_value(context, full_match.group(1))
        if resolved is not None:
            return resolved

    def _replace(match: re.Match[str]) -> str:
        resolved = _resolve_context_value(context, match.group(1))
        if resolved is None:
            return match.group(0)
        if isinstance(resolved, (dict, list)):
            return json.dumps(resolved, ensure_ascii=False)
        return str(resolved)

    return _TEMPLATE_PATTERN.sub(_replace, value)


def _resolve_context_value(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for segment in path.split("."):
        if isinstance(current, dict) and segment in current:
            current = current[segment]
            continue
        return None
    return current
