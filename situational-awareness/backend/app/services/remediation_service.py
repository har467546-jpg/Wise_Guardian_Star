from __future__ import annotations

import shlex
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.endpoints import risks as risks_endpoint
from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import SSHCredential
from app.db.models.enums import FindingStatus, RiskSeverity, TaskExecutionStatus, TaskType
from app.db.models.host_runner import HostRunner
from app.db.models.remediation_session import RemediationSession
from app.db.models.risk_finding import RiskFinding
from app.db.models.snapshot import HostSnapshot
from app.repositories.risk_repo import list_findings_by_asset
from app.repositories.task_repo import get_latest_task_run_for_scope
from app.rules import render_remediation_with_context, resolve_rule_remediation
from app.schemas.remediation import (
    RemediationAssetCardRead,
    RemediationAssetListRead,
    RemediationBackupPlanRead,
    RemediationPlanRead,
    RemediationPlanStepRead,
    RemediationWorkspaceAssetRead,
    RemediationWorkspaceAuthorizationRead,
    RemediationWorkspaceCollectionRead,
    RemediationWorkspaceFindingRead,
    RemediationWorkspaceRead,
)

PROBE_SNAPSHOT_TYPE = "ssh_probe_baseline"
NETWORK_INITIAL_SNAPSHOT_TYPE = "network_initial"
SUPPORTED_CONFIG_KEYS = {
    ("ssh", "password_authentication"),
    ("ssh", "permit_root_login"),
    ("ssh", "permit_empty_passwords"),
    ("ssh", "pubkey_authentication"),
    ("mysql", "skip_grant_tables"),
    ("mysql", "local_infile"),
    ("mysql", "bind_all_interfaces"),
    ("sudo", "setenv_present"),
    ("sudo", "dangerous_env_keep_present"),
    ("sudo", "full_privilege_rule"),
    ("redis", "protected_mode"),
    ("redis", "bind_all_interfaces"),
    ("postgresql", "listen_all_interfaces"),
    ("postgresql", "trust_auth_enabled"),
    ("apache", "directory_listing_enabled"),
    ("apache", "webdav_enabled"),
    ("nginx", "directory_listing_enabled"),
    ("nginx", "webdav_enabled"),
    ("docker", "tcp_listener_without_tlsverify"),
    ("vsftpd", "anonymous_enabled"),
    ("vsftpd", "anonymous_write_enabled"),
}
SUPPORTED_PERMISSION_RULE_IDS = {
    "polkit.rules_path.writable.exposed",
    "cron.root_writable_job_chain.exposed",
    "linux-host.dangerous_suid.present",
    "linux-host.suid.nmap.present",
    "linux-host.suid.screen.present",
    "nmap.legacy_interactive_privesc.exposed",
}
_SUID_PERMISSION_ACTION_TYPES = {
    "permission_set",
    "set_path_permission",
}
_LOGIN_USER_REQUIRED_SUID_RULE_BINARIES = {
    "linux-host.suid.nmap.present": "nmap",
    "nmap.legacy_interactive_privesc.exposed": "nmap",
    "linux-host.suid.screen.present": "screen",
    "screen.legacy_setuid_privesc.exposed": "screen",
}
_LOGIN_USER_OPTIONAL_SUID_BINARIES = {"nmap", "screen"}
_SELF_LOCK_SUDO_MESSAGE = "该步骤会影响当前绑定凭据依赖的 sudo 管理链路，已为避免自锁而阻止自动执行"
_SELF_LOCK_SUDO_TARGETS = {"/etc/sudoers", "/usr/bin/sudo"}
_SELF_LOCK_SUDO_TARGET_PREFIXES = ("/etc/sudoers.d/",)
_DEFAULT_CONFIG_FILES: dict[str, list[str]] = {
    "ssh": ["/etc/ssh/sshd_config"],
    "mysql": ["/etc/mysql/my.cnf", "/etc/my.cnf"],
    "sudo": ["/etc/sudoers"],
    "samba": ["/etc/samba/smb.conf"],
    "redis": ["/etc/redis/redis.conf", "/etc/redis.conf"],
    "postgresql": [
        "/etc/postgresql/16/main/postgresql.conf",
        "/etc/postgresql/15/main/postgresql.conf",
        "/etc/postgresql/14/main/postgresql.conf",
        "/etc/postgresql/13/main/postgresql.conf",
        "/etc/postgresql/12/main/postgresql.conf",
        "/etc/postgresql/11/main/postgresql.conf",
        "/etc/postgresql/16/main/pg_hba.conf",
        "/etc/postgresql/15/main/pg_hba.conf",
        "/etc/postgresql/14/main/pg_hba.conf",
        "/etc/postgresql/13/main/pg_hba.conf",
        "/etc/postgresql/12/main/pg_hba.conf",
        "/etc/postgresql/11/main/pg_hba.conf",
        "/var/lib/pgsql/data/postgresql.conf",
        "/var/lib/pgsql/data/pg_hba.conf",
        "/var/lib/postgresql/data/postgresql.conf",
        "/var/lib/postgresql/data/pg_hba.conf",
    ],
    "apache": ["/etc/apache2/apache2.conf", "/etc/httpd/conf/httpd.conf", "/etc/httpd/conf.d/autoindex.conf"],
    "nginx": ["/etc/nginx/nginx.conf", "/etc/nginx/conf.d/default.conf"],
    "docker": ["/etc/docker/daemon.json", "/etc/systemd/system/docker.service"],
    "vsftpd": ["/etc/vsftpd.conf"],
}
_SERVICE_CONTROL_CANDIDATES: dict[str, list[str]] = {
    "ssh": ["ssh", "sshd"],
    "mysql": ["mysql", "mysqld", "mariadb"],
    "samba": ["smbd", "samba", "nmbd"],
    "apache": ["apache2", "httpd"],
    "nginx": ["nginx"],
    "tomcat": ["tomcat", "tomcat9", "tomcat8", "tomcat7"],
    "redis": ["redis", "redis-server"],
    "postgresql": ["postgresql", "postgresql@main", "postgres"],
}
_LEGACY_DEBIAN_FALLBACK_STRATEGY = "legacy_debian_auto_guess"
_LEGACY_DEBIAN_OS_TOKENS = ("debian", "ubuntu", "metasploitable")
_LEGACY_DEBIAN_OLD_RELEASE_TOKENS = (
    "metasploitable",
    "hardy",
    "dapper",
    "jaunty",
    "karmic",
    "intrepid",
    "etch",
    "lenny",
    "squeeze",
)
_LEGACY_DEBIAN_PACKAGE_FAMILIES: dict[str, list[str]] = {
    "apache": ["apache", "apache2"],
    "php": ["php5"],
    "ftp": ["proftpd", "vsftpd"],
    "ssh": ["ssh", "openssh-server"],
    "mysql": ["mysql-server", "mysql-server-5.0"],
    "samba": ["samba"],
    "vsftpd": ["vsftpd"],
}
_LEGACY_DEBIAN_SERVICE_FAMILIES: dict[str, list[str]] = {
    "apache": ["apache2"],
    "php": ["apache2"],
    "ftp": ["proftpd", "vsftpd"],
    "ssh": ["ssh"],
    "mysql": ["mysql"],
    "samba": ["samba"],
    "vsftpd": ["vsftpd"],
}
_LEGACY_DEBIAN_SERVICE_PACKAGE_FAMILIES: dict[str, list[str]] = {
    "apache": ["apache2"],
    "php": ["apache2", "php5"],
    "ftp": ["proftpd", "vsftpd"],
    "ssh": ["ssh", "openssh-server"],
    "mysql": ["mysql-server", "mysql-server-5.0"],
    "samba": ["samba"],
    "vsftpd": ["vsftpd"],
}
_SEVERITY_RANK = {
    RiskSeverity.CRITICAL: 4,
    RiskSeverity.HIGH: 3,
    RiskSeverity.MEDIUM: 2,
    RiskSeverity.LOW: 1,
}
REMEDIATION_ADAPTER_VERSION = "2026-03-26-enterprise-p0"
_BACKUP_REQUIRED_ACTION_TYPES = {
    "set_config",
    "remove_config",
    "permission_set",
    "set_path_permission",
    "remove_path",
    "remove_exposure",
    "restrict_network",
    "set_bind_scope",
    "set_access_policy",
}
_ACTION_ADAPTER_CONTRACTS: dict[str, dict[str, Any]] = {
    "upgrade_package": {
        "risk_level": "high",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.package.upgrade",
        "evidence_items": ["package_version_before", "command_preview", "package_version_after", "reverify_result"],
    },
    "reload_service": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.service.reload",
        "evidence_items": ["service_state_before", "command_preview", "service_state_after", "reverify_result"],
    },
    "restart_service": {
        "risk_level": "high",
        "idempotent": False,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.service.restart",
        "evidence_items": ["service_state_before", "command_preview", "service_state_after", "reverify_result"],
    },
    "disable_service": {
        "risk_level": "high",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.service.disable",
        "evidence_items": ["service_state_before", "command_preview", "service_state_after", "reverify_result"],
    },
    "set_config": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.config.set",
        "evidence_items": ["config_snapshot_before", "command_preview", "config_snapshot_after", "reverify_result"],
    },
    "remove_config": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.config.remove",
        "evidence_items": ["config_snapshot_before", "command_preview", "config_snapshot_after", "reverify_result"],
    },
    "permission_set": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.path.permission_set",
        "evidence_items": ["permission_snapshot_before", "command_preview", "permission_snapshot_after", "reverify_result"],
    },
    "remove_exposure": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.exposure.remove",
        "evidence_items": ["target_snapshot_before", "command_preview", "target_snapshot_after", "reverify_result"],
    },
    "restrict_network": {
        "risk_level": "high",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.network.restrict",
        "evidence_items": ["bind_snapshot_before", "command_preview", "bind_snapshot_after", "reverify_result"],
    },
    "toggle_feature": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.feature.toggle",
        "evidence_items": ["config_snapshot_before", "command_preview", "config_snapshot_after", "reverify_result"],
    },
    "set_bind_scope": {
        "risk_level": "high",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.network.bind_scope",
        "evidence_items": ["bind_snapshot_before", "command_preview", "bind_snapshot_after", "reverify_result"],
    },
    "set_access_policy": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.access.policy",
        "evidence_items": ["policy_snapshot_before", "command_preview", "policy_snapshot_after", "reverify_result"],
    },
    "remove_path": {
        "risk_level": "high",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": True,
        "adapter_id": "linux.path.remove",
        "evidence_items": ["path_snapshot_before", "command_preview", "path_snapshot_after", "reverify_result"],
    },
    "set_path_permission": {
        "risk_level": "medium",
        "idempotent": True,
        "dry_run_supported": True,
        "requires_maintenance_window": False,
        "adapter_id": "linux.path.permission_set",
        "evidence_items": ["permission_snapshot_before", "command_preview", "permission_snapshot_after", "reverify_result"],
    },
}


def get_manual_credential(db: Session, asset_id: str) -> SSHCredential | None:
    return db.scalar(select(SSHCredential).where(SSHCredential.name == f"manual-asset-{asset_id}"))


def get_latest_collection_snapshot(db: Session, asset_id: str) -> HostSnapshot | None:
    snapshots = db.scalars(
        select(HostSnapshot).where(HostSnapshot.asset_id == asset_id).order_by(HostSnapshot.collected_at.desc()).limit(100)
    ).all()
    collection_snapshots = [item for item in snapshots if _snapshot_type(item) not in {PROBE_SNAPSHOT_TYPE, NETWORK_INITIAL_SNAPSHOT_TYPE}]
    if not collection_snapshots:
        return None
    return max(collection_snapshots, key=lambda item: item.collected_at)


def list_remediation_assets(
    db: Session,
    *,
    page: int = 1,
    page_size: int = 20,
    keyword: str | None = None,
) -> RemediationAssetListRead:
    rule_cache: dict[str, Any | None] = {}
    credentials = db.scalars(select(SSHCredential)).all()
    credential_by_asset_id: dict[str, SSHCredential] = {}
    for credential in credentials:
        asset_id = _asset_id_from_manual_credential(credential)
        if not asset_id:
            continue
        if not _credential_ready_for_remediation_listing(credential):
            continue
        credential_by_asset_id[asset_id] = credential
    if not credential_by_asset_id:
        return RemediationAssetListRead(items=[], meta={"total": 0, "page": page, "page_size": page_size})

    candidate_asset_ids = list(credential_by_asset_id.keys())
    snapshots = db.scalars(
        select(HostSnapshot)
        .where(HostSnapshot.asset_id.in_(candidate_asset_ids))
        .order_by(HostSnapshot.asset_id.asc(), HostSnapshot.collected_at.desc())
    ).all()
    snapshot_by_asset_id: dict[str, HostSnapshot] = {}
    for snapshot in snapshots:
        if snapshot.asset_id in snapshot_by_asset_id:
            continue
        if _snapshot_type(snapshot) in {PROBE_SNAPSHOT_TYPE, NETWORK_INITIAL_SNAPSHOT_TYPE}:
            continue
        snapshot_by_asset_id[snapshot.asset_id] = snapshot
    candidate_asset_ids = [asset_id for asset_id in candidate_asset_ids if asset_id in snapshot_by_asset_id]
    if not candidate_asset_ids:
        return RemediationAssetListRead(items=[], meta={"total": 0, "page": page, "page_size": page_size})

    findings = db.scalars(
        select(RiskFinding)
        .where(
            RiskFinding.asset_id.in_(candidate_asset_ids),
            RiskFinding.status == FindingStatus.OPEN,
        )
        .order_by(RiskFinding.detected_at.desc())
    ).all()
    findings_by_asset_id: dict[str, list[RiskFinding]] = {}
    open_asset_port_ids = _open_asset_port_id_set(db, findings)
    for finding in findings:
        if not _finding_is_remediation_candidate(
            finding,
            open_asset_port_ids=open_asset_port_ids,
            rule_cache=rule_cache,
        ):
            continue
        findings_by_asset_id.setdefault(finding.asset_id, []).append(finding)
    candidate_asset_ids = [asset_id for asset_id in candidate_asset_ids if findings_by_asset_id.get(asset_id)]
    if not candidate_asset_ids:
        return RemediationAssetListRead(items=[], meta={"total": 0, "page": page, "page_size": page_size})

    assets = db.scalars(select(Asset).where(Asset.id.in_(candidate_asset_ids))).all()
    runner_by_asset_id = {
        item.asset_id: item
        for item in db.scalars(select(HostRunner).where(HostRunner.asset_id.in_(candidate_asset_ids))).all()
    }
    session_by_asset_id: dict[str, RemediationSession] = {}
    sessions = db.scalars(
        select(RemediationSession)
        .where(RemediationSession.asset_id.in_(candidate_asset_ids))
        .order_by(RemediationSession.asset_id.asc(), RemediationSession.created_at.desc())
    ).all()
    for item in sessions:
        session_by_asset_id.setdefault(item.asset_id, item)
    cards: list[RemediationAssetCardRead] = []
    keyword_value = (keyword or "").strip().lower()
    for asset in assets:
        related_findings = findings_by_asset_id.get(asset.id, [])
        if not related_findings:
            continue
        recommended = _pick_recommended_finding(related_findings)
        highest_severity = _pick_highest_severity(related_findings)
        credential = credential_by_asset_id.get(asset.id)
        snapshot = snapshot_by_asset_id.get(asset.id)
        host_runner = runner_by_asset_id.get(asset.id)
        active_session = session_by_asset_id.get(asset.id)
        if credential is None or snapshot is None or recommended is None:
            continue
        card = RemediationAssetCardRead(
            asset_id=asset.id,
            ip=str(asset.ip),
            hostname=asset.hostname,
            os_name=asset.os_name,
            status=asset.status.value if hasattr(asset.status, "value") else str(asset.status),
            highest_severity=highest_severity,
            finding_count=len(related_findings),
            effective_privilege=credential.last_effective_privilege,
            last_verified_at=credential.last_verified_at.isoformat() if credential.last_verified_at else None,
            last_collection_at=snapshot.collected_at.isoformat() if snapshot.collected_at else None,
            recommended_finding_id=recommended.id,
            runner_status=_runner_card_status(host_runner),
            runner_install_status=str(host_runner.install_status or "").strip().lower() if host_runner else "not_installed",
            active_session_id=active_session.id if active_session else None,
            active_session_status=active_session.status if active_session else None,
        )
        if keyword_value and keyword_value not in " ".join(
            [
                card.ip.lower(),
                (card.hostname or "").lower(),
                (card.os_name or "").lower(),
            ]
        ):
            continue
        cards.append(card)
    cards.sort(
        key=lambda item: (
            _severity_sort_value(item.highest_severity),
            item.finding_count,
            item.last_collection_at or "",
        ),
        reverse=True,
    )
    total = len(cards)
    start = max(0, (page - 1) * page_size)
    end = start + page_size
    return RemediationAssetListRead(
        items=cards[start:end],
        meta={"total": total, "page": page, "page_size": page_size},
    )


def build_workspace(db: Session, asset_id: str) -> RemediationWorkspaceRead:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise LookupError("资产不存在")
    credential = get_manual_credential(db, asset_id)
    snapshot = get_latest_collection_snapshot(db, asset_id)
    blocked_reasons = _compute_blocked_reasons(credential, snapshot)
    findings: list[RemediationWorkspaceFindingRead] = []
    asset_findings = list_findings_by_asset(db, asset_id)
    open_asset_port_ids = _open_asset_port_id_set(db, asset_findings)
    rule_cache: dict[str, Any | None] = {}
    for item in asset_findings:
        has_template = _finding_has_remediation_template(item, rule_cache=rule_cache)
        if not _finding_is_remediation_candidate(
            item,
            open_asset_port_ids=open_asset_port_ids,
            has_remediation_template=has_template,
        ):
            continue
        rule_id = _yaml_rule_id(item)
        findings.append(
            RemediationWorkspaceFindingRead(
                finding_id=item.id,
                rule_id=rule_id,
                title=item.title,
                severity=item.severity,
                status=item.status.value if hasattr(item.status, "value") else str(item.status),
                service_name=_service_name_from_finding(item),
                detected_at=item.detected_at,
                has_template=has_template,
            )
        )
    latest_collection = None
    if snapshot is not None:
        latest_collection = RemediationWorkspaceCollectionRead(
            status=snapshot.collection_status,
            collected_at=snapshot.collected_at.isoformat(),
            summary_json=_summary_json_from_snapshot(snapshot),
        )
    latest_task = get_latest_task_run_for_scope(
        db,
        scope_type="asset",
        scope_id=asset_id,
        task_type=TaskType.REMEDIATION_EXECUTE,
        statuses=[
            TaskExecutionStatus.PENDING,
            TaskExecutionStatus.RUNNING,
            TaskExecutionStatus.RETRY,
            TaskExecutionStatus.SUCCESS,
            TaskExecutionStatus.FAILURE,
            TaskExecutionStatus.CANCELED,
        ],
    )
    return RemediationWorkspaceRead(
        asset=RemediationWorkspaceAssetRead(
            id=asset.id,
            ip=str(asset.ip),
            hostname=asset.hostname,
            os_name=asset.os_name,
            status=asset.status.value if hasattr(asset.status, "value") else str(asset.status),
        ),
        authorization=RemediationWorkspaceAuthorizationRead(
            credential_bound=credential is not None,
            admin_authorized=bool(credential.admin_authorized) if credential else False,
            last_verified_at=credential.last_verified_at.isoformat() if credential and credential.last_verified_at else None,
            last_verification_status=credential.last_verification_status if credential else None,
            effective_privilege=credential.last_effective_privilege if credential else None,
            execution_ready=not blocked_reasons,
            blocked_reasons=blocked_reasons,
        ),
        latest_collection=latest_collection,
        findings=findings,
        last_task_id=latest_task.id if latest_task else None,
    )


def build_plan(db: Session, finding_id: str) -> RemediationPlanRead:
    finding = db.get(RiskFinding, finding_id)
    if finding is None:
        raise LookupError("风险发现不存在")
    credential = get_manual_credential(db, finding.asset_id)
    snapshot = get_latest_collection_snapshot(db, finding.asset_id)
    host_runner = db.scalar(select(HostRunner).where(HostRunner.asset_id == finding.asset_id)) if db is not None else None
    blocked_reasons = _compute_blocked_reasons(credential, snapshot)
    snapshot_context = _build_snapshot_planner_context(snapshot, host_runner=host_runner)
    return _build_plan_from_finding(
        finding,
        credential=credential,
        snapshot=snapshot,
        blocked_reasons=blocked_reasons,
        snapshot_context=snapshot_context,
    )


def build_asset_plans(db: Session, asset_id: str) -> dict[str, RemediationPlanRead]:
    credential = get_manual_credential(db, asset_id)
    snapshot = get_latest_collection_snapshot(db, asset_id)
    host_runner = db.scalar(select(HostRunner).where(HostRunner.asset_id == asset_id)) if db is not None else None
    blocked_reasons = _compute_blocked_reasons(credential, snapshot)
    snapshot_context = _build_snapshot_planner_context(snapshot, host_runner=host_runner)
    rule_cache: dict[str, Any | None] = {}
    remediation_cache: dict[str, Any] = {}
    plans: dict[str, RemediationPlanRead] = {}
    findings = list_findings_by_asset(db, asset_id)
    open_asset_port_ids = _open_asset_port_id_set(db, findings)
    for finding in findings:
        if not _finding_is_remediation_candidate(
            finding,
            open_asset_port_ids=open_asset_port_ids,
            rule_cache=rule_cache,
        ):
            continue
        try:
            plan = _build_plan_from_finding(
                finding,
                credential=credential,
                snapshot=snapshot,
                blocked_reasons=blocked_reasons,
                snapshot_context=snapshot_context,
                rule_cache=rule_cache,
                remediation_cache=remediation_cache,
            )
        except LookupError:
            continue
        if not plan.steps and bool(plan.source_refs.get("excluded_for_login_user_required_suid")):
            continue
        plans[finding.id] = plan
    return plans


def _build_plan_from_finding(
    finding: RiskFinding,
    *,
    credential: SSHCredential | None,
    snapshot: HostSnapshot | None,
    blocked_reasons: list[str],
    snapshot_context: dict[str, Any] | None = None,
    rule_cache: dict[str, Any | None] | None = None,
    remediation_cache: dict[str, Any] | None = None,
) -> RemediationPlanRead:
    rule_id = _yaml_rule_id(finding)
    if not rule_id:
        raise LookupError("风险发现未关联 YAML 规则")
    rule = None
    if rule_cache is not None:
        rule = rule_cache.get(rule_id)
    if rule is None:
        rule = risks_endpoint.RULE_STORE.get_rule(rule_id)
        if rule_cache is not None:
            rule_cache[rule_id] = rule
    if rule is None:
        raise LookupError(f"规则不存在：{rule_id}")
    remediation = remediation_cache.get(rule_id) if remediation_cache is not None else None
    if remediation is None:
        remediation = resolve_rule_remediation(rule)
        if remediation_cache is not None:
            remediation_cache[rule_id] = remediation
    rendered = render_remediation_with_context(
        remediation,
        risks_endpoint._build_remediation_context(finding, rule, _evidence_dict(finding)),
    )
    rendered, excluded_suid_binaries = _filter_login_user_required_suid_actions(
        finding=finding,
        rendered_template=rendered,
        credential=credential,
        snapshot_context=snapshot_context,
    )
    planner = RemediationCommandPlanner(
        finding=finding,
        rendered_template=rendered,
        snapshot=snapshot,
        credential=credential,
        snapshot_context=snapshot_context,
        excluded_suid_binaries=excluded_suid_binaries,
    )
    steps = planner.build_steps()
    filtered_due_to_login_user_required_suid = bool(excluded_suid_binaries) and not steps and bool(
        remediation.actions
    )
    contract_gap_reasons = [
        f"步骤“{step.title}”缺少完整的企业执行元数据"
        for step in steps
        if step.execution_state == "ready" and not _step_has_enterprise_contract(step)
    ]
    plan_blocked_reasons = list(
        dict.fromkeys(
            [
                *blocked_reasons,
                *contract_gap_reasons,
                *[
                    step.blocked_reason
                    for step in steps
                    if step.execution_state == "blocked" and step.blocked_reason
                ],
            ]
        )
    )
    if filtered_due_to_login_user_required_suid:
        plan_blocked_reasons.append(_login_user_required_suid_message(excluded_suid_binaries))
    return RemediationPlanRead(
        asset_id=finding.asset_id,
        finding_id=finding.id,
        rule_id=rule.rule_id,
        rule_name=rule.name or rule.rule_id,
        service_name=_service_name_from_finding(finding),
        severity=finding.severity,
        summary=str(rendered.get("summary") or ""),
        automation_level=str(rendered.get("automation_level") or "callable"),
        impact_summary=str(rendered.get("impact_summary") or "").strip() or None,
        precheck_items=[str(item).strip() for item in (rendered.get("precheck_items") or []) if str(item).strip()],
        verify_items=[str(item).strip() for item in (rendered.get("verify_items") or []) if str(item).strip()],
        rollback_notes=[str(item).strip() for item in (rendered.get("rollback_notes") or []) if str(item).strip()],
        execution_ready=bool(steps) and not plan_blocked_reasons and all(
            step.execution_state == "ready" and _step_has_enterprise_contract(step) for step in steps
        ),
        blocked_reasons=plan_blocked_reasons,
        steps=steps,
        source_refs={
            "yaml_rule_id": rule_id,
            "service": rule.service,
            "generated": rule.remediation is None,
            "references": list(dict.fromkeys([*(rule.references or []), *(remediation.references or [])])),
            "excluded_for_login_user_required_suid": filtered_due_to_login_user_required_suid,
            "excluded_suid_binaries": sorted(excluded_suid_binaries),
        },
    )


class RemediationCommandPlanner:
    def __init__(
        self,
        *,
        finding: RiskFinding,
        rendered_template: dict[str, Any],
        snapshot: HostSnapshot | None,
        credential: SSHCredential | None,
        snapshot_context: dict[str, Any] | None = None,
        excluded_suid_binaries: set[str] | None = None,
    ) -> None:
        self.finding = finding
        self.rendered_template = rendered_template
        self.snapshot = snapshot
        self.credential = credential
        context = snapshot_context or _build_snapshot_planner_context(snapshot)
        self.os_release = str(context.get("os_release") or (snapshot.os_release if snapshot is not None else "") or "").strip()
        self.kernel_version = str(context.get("kernel_version") or (snapshot.kernel_version if snapshot is not None else "") or "").strip()
        self.detail_json = dict(context.get("detail_json") or {})
        self.summary_json = dict(context.get("summary_json") or {})
        self.config_by_service = dict(context.get("config_by_service") or {})
        self.host_checks = dict(context.get("host_checks") or {})
        self.packages = [dict(item) for item in (context.get("packages") or []) if isinstance(item, dict)]
        self.services = [dict(item) for item in (context.get("services") or []) if isinstance(item, dict)]
        self.runner_capabilities = dict(context.get("runner_capabilities") or {})
        self.excluded_suid_binaries = {
            str(item).strip().lower()
            for item in (excluded_suid_binaries or set())
            if str(item).strip()
        }
        self.legacy_debian_profile = self._build_legacy_debian_profile()

    def _build_legacy_debian_profile(self) -> dict[str, Any]:
        probe_payload = (
            self.runner_capabilities.get("probe")
            if isinstance(self.runner_capabilities.get("probe"), dict)
            else {}
        )
        manager = self._default_package_manager()
        os_text = " ".join(
            item
            for item in [
                self.os_release,
                str(self.summary_json.get("os") or "").strip(),
                str(probe_payload.get("os_release_like") or "").strip(),
                str(self.runner_capabilities.get("os_release_like") or "").strip(),
                str(self.runner_capabilities.get("detected_os") or "").strip(),
            ]
            if item
        ).strip().lower()
        has_systemd = _coerce_bool(probe_payload.get("has_systemd"))
        if has_systemd is None:
            has_systemd = _coerce_bool(self.runner_capabilities.get("has_systemd"))
        has_sysvinit = _coerce_bool(probe_payload.get("has_sysvinit"))
        if has_sysvinit is None:
            has_sysvinit = _coerce_bool(self.runner_capabilities.get("has_sysvinit"))
        os_supported = any(token in os_text for token in _LEGACY_DEBIAN_OS_TOKENS)
        old_release_hint = any(token in os_text for token in _LEGACY_DEBIAN_OLD_RELEASE_TOKENS)
        legacy_init_hint = old_release_hint or has_sysvinit is True or has_systemd is False
        return {
            "enabled": manager in {"apt", "dpkg"} and os_supported and legacy_init_hint,
            "package_manager": manager,
            "os_text": os_text,
            "has_systemd": has_systemd,
            "has_sysvinit": has_sysvinit,
        }

    def _default_package_manager(self) -> str | None:
        probe_payload = (
            self.runner_capabilities.get("probe")
            if isinstance(self.runner_capabilities.get("probe"), dict)
            else {}
        )
        for candidate in [
            probe_payload.get("package_manager"),
            self.runner_capabilities.get("package_manager"),
        ]:
            value = str(candidate or "").strip().lower()
            if value:
                return "dpkg" if value == "apt" else value
        for item in self.packages:
            value = str(item.get("manager") or "").strip().lower()
            if value:
                return value
        for config in self.config_by_service.values():
            if not isinstance(config, dict):
                continue
            value = str(config.get("package_manager") or "").strip().lower()
            if value:
                return value
        return None

    def _legacy_debian_enabled(self) -> bool:
        return bool(self.legacy_debian_profile.get("enabled"))

    def _known_package_names(self) -> set[str]:
        names: set[str] = set()
        for item in self.packages:
            value = str(item.get("name") or "").strip().lower()
            if value:
                names.add(value)
        return names

    def _known_service_names(self) -> set[str]:
        names: set[str] = set()
        for item in self.services:
            value = str(item.get("name") or item.get("service_name") or "").strip().lower()
            if value:
                names.add(value)
        return names

    def _prefer_known_legacy_candidates(self, candidates: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in candidates:
            value = str(item or "").strip().lower()
            if value and value not in normalized:
                normalized.append(value)
        if not normalized:
            return []
        known_packages = self._known_package_names()
        known_services = self._known_service_names()
        preferred = [item for item in normalized if item in known_packages or item in known_services]
        remaining = [item for item in normalized if item not in preferred]
        return [*preferred, *remaining]

    def _legacy_package_candidates(self, *, package_name: str, service_name: str) -> list[str]:
        family_key = package_name.strip().lower() or service_name.strip().lower()
        candidates = _LEGACY_DEBIAN_PACKAGE_FAMILIES.get(family_key)
        if not candidates:
            return []
        return self._prefer_known_legacy_candidates(candidates)

    def _legacy_service_candidates(self, service_name: str) -> tuple[list[str], list[str]]:
        normalized_name = service_name.strip().lower()
        candidates = _LEGACY_DEBIAN_SERVICE_FAMILIES.get(normalized_name)
        packages = _LEGACY_DEBIAN_SERVICE_PACKAGE_FAMILIES.get(normalized_name)
        if not candidates:
            return [], []
        return (
            self._prefer_known_legacy_candidates(candidates),
            self._prefer_known_legacy_candidates(packages or []),
        )

    def build_steps(self) -> list[RemediationPlanStepRead]:
        steps: list[RemediationPlanStepRead] = []
        for index, action in enumerate(self.rendered_template.get("actions") or [], start=1):
            step_id = f"step-{index}"
            rendered = self._render_step(step_id, action)
            steps.append(rendered)
        return steps

    def _render_step(self, step_id: str, action: dict[str, Any]) -> RemediationPlanStepRead:
        action_type = str(action.get("action_type") or "").strip()
        title = str(action.get("title") or step_id)
        params = dict(action.get("params") or {}) if isinstance(action.get("params"), dict) else {}
        params["_target_files"] = action.get("target_files") if isinstance(action.get("target_files"), list) else []
        params["_target_services"] = action.get("target_services") if isinstance(action.get("target_services"), list) else []
        params["_target_paths"] = action.get("target_paths") if isinstance(action.get("target_paths"), list) else []
        requires_confirmation = bool(action.get("requires_confirmation", True))
        renderer = getattr(self, f"_render_{action_type}", None)
        if renderer is None:
            return _decorate_step_with_enterprise_contract(
                self._blocked_step(step_id, action_type, title, requires_confirmation, "当前动作类型不在自动执行白名单内")
            )
        rendered = renderer(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params=params,
            requires_confirmation=requires_confirmation,
        )
        target_files = _merge_string_lists(rendered.target_files, action.get("target_files"))
        target_services = _merge_string_lists(rendered.target_services, action.get("target_services"))
        target_paths = _merge_string_lists(rendered.target_paths, action.get("target_paths"))
        if action_type in _SUID_PERMISSION_ACTION_TYPES and rendered.target_paths:
            target_paths = list(rendered.target_paths)
        updated = rendered.model_copy(
            update={
                "target_files": target_files,
                "target_services": target_services,
                "target_paths": target_paths,
                "verify_items": _merge_string_lists(rendered.verify_items, action.get("verify_items")),
                "rollback_hint": str(action.get("rollback_hint") or "").strip() or rendered.rollback_hint,
            }
        )
        # Keep risky steps visible, but never auto-run a step which would cut off
        # the currently bound sudo-based admin chain.
        if _is_self_locking_sudo_step(
            finding=self.finding,
            action=action,
            step=updated,
            credential=self.credential,
        ):
            updated = _block_self_lock_step(updated)
        return _decorate_step_with_enterprise_contract(updated)

    def _render_upgrade_package(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        package_name = str(params.get("package_name") or params.get("service_name") or "").strip()
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        manager = self._resolve_package_manager(package_name, str(params.get("package_manager") or "").strip().lower() or None)
        fixed_version = self._resolve_fixed_version(params.get("fixed_versions"))
        if not package_name or not manager:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未识别到稳定的软件包管理器或包名")
        fallback_strategy = None
        fallback_candidates: list[str] = []
        render_reason = "已基于主机快照的软件包管理器渲染升级命令"
        if self._legacy_debian_enabled() and manager == "dpkg":
            fallback_candidates = self._legacy_package_candidates(package_name=package_name, service_name=service_name)
            if fallback_candidates:
                fallback_strategy = _LEGACY_DEBIAN_FALLBACK_STRATEGY
                render_reason = "已按旧版 Debian 自动解析路径渲染软件包升级命令"
        command = (
            _build_legacy_debian_package_upgrade_command(
                original_package_name=package_name,
                candidates=fallback_candidates,
                fixed_version=fixed_version,
            )
            if fallback_candidates and fallback_strategy
            else _build_package_upgrade_command(manager=manager, package_name=package_name, fixed_version=fixed_version)
        )
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            backup_plan=RemediationBackupPlanRead(kind="package_context", note="执行前记录当前包版本与管理器信息"),
            render_reason=render_reason,
            target_services=[service_name] if service_name else [],
            fallback_strategy=fallback_strategy,
            fallback_candidates=fallback_candidates,
        )

    def _render_reload_service(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        if not service_name:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未识别到可重载的服务名")
        fallback_strategy = None
        fallback_candidates: list[str] = []
        render_reason = "已按常见 service/systemd 管理方式渲染重载命令"
        if self._legacy_debian_enabled():
            fallback_candidates, package_candidates = self._legacy_service_candidates(service_name)
            if fallback_candidates:
                fallback_strategy = _LEGACY_DEBIAN_FALLBACK_STRATEGY
                render_reason = "已按旧版 Debian 自动解析路径渲染服务重载命令"
                command = _build_legacy_debian_service_control_command(
                    action="reload",
                    original_service_name=service_name,
                    service_candidates=fallback_candidates,
                    package_candidates=package_candidates,
                )
            else:
                command = _build_service_control_command("reload", service_name)
        else:
            command = _build_service_control_command("reload", service_name)
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            render_reason=render_reason,
            target_services=[service_name],
            fallback_strategy=fallback_strategy,
            fallback_candidates=fallback_candidates,
        )

    def _render_restart_service(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        if not service_name:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未识别到可重启的服务名")
        if self._legacy_debian_enabled() and service_name == "linux-kernel":
            blocked = self._blocked_step(
                step_id,
                action_type,
                title,
                requires_confirmation,
                "旧版 Debian 主机上的内核整改需要人工安排重启窗口，不自动生成 linux-kernel 服务重启命令",
            )
            return blocked.model_copy(
                update={
                    "target_services": [service_name],
                    "fallback_strategy": _LEGACY_DEBIAN_FALLBACK_STRATEGY,
                    "fallback_candidates": [],
                }
            )
        fallback_strategy = None
        fallback_candidates: list[str] = []
        render_reason = "已按常见 service/systemd 管理方式渲染重启命令"
        if self._legacy_debian_enabled():
            fallback_candidates, package_candidates = self._legacy_service_candidates(service_name)
            if fallback_candidates:
                fallback_strategy = _LEGACY_DEBIAN_FALLBACK_STRATEGY
                render_reason = "已按旧版 Debian 自动解析路径渲染服务重启命令"
                command = _build_legacy_debian_service_control_command(
                    action="restart",
                    original_service_name=service_name,
                    service_candidates=fallback_candidates,
                    package_candidates=package_candidates,
                )
            else:
                command = _build_service_control_command("restart", service_name)
        else:
            command = _build_service_control_command("restart", service_name)
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            render_reason=render_reason,
            target_services=[service_name],
            fallback_strategy=fallback_strategy,
            fallback_candidates=fallback_candidates,
        )

    def _render_disable_service(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        if not service_name:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未识别到可禁用的服务名")
        fallback_strategy = None
        fallback_candidates: list[str] = []
        render_reason = "已按常见 service/systemd 管理方式渲染禁用命令"
        if self._legacy_debian_enabled():
            fallback_candidates, package_candidates = self._legacy_service_candidates(service_name)
            if fallback_candidates:
                fallback_strategy = _LEGACY_DEBIAN_FALLBACK_STRATEGY
                render_reason = "已按旧版 Debian 自动解析路径渲染服务禁用命令"
                command = _build_legacy_debian_service_control_command(
                    action="disable",
                    original_service_name=service_name,
                    service_candidates=fallback_candidates,
                    package_candidates=package_candidates,
                )
            else:
                command = _build_service_control_command("disable", service_name)
        else:
            command = _build_service_control_command("disable", service_name)
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            render_reason=render_reason,
            target_services=[service_name],
            fallback_strategy=fallback_strategy,
            fallback_candidates=fallback_candidates,
        )

    def _render_set_config(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        config_key = str(params.get("config_key") or "").strip().lower()
        if (service_name, config_key) not in SUPPORTED_CONFIG_KEYS:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "当前配置整改项缺少自动修复适配器")
        target_value = params.get("target_value")
        source_files = self._resolve_source_files(service_name)
        if not source_files:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未从 SSH 深度检查结果中解析到稳定的配置文件路径")
        command = _render_config_command(
            service_name=service_name,
            config_key=config_key,
            target_value=target_value,
            source_files=source_files,
            legacy_debian=self._legacy_debian_enabled(),
        )
        if not command:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "当前配置整改项无法稳定渲染为自动化命令")
        fallback_strategy = None
        fallback_candidates: list[str] = []
        if self._legacy_debian_enabled() and service_name == "ssh":
            fallback_strategy = _LEGACY_DEBIAN_FALLBACK_STRATEGY
            fallback_candidates, _ = self._legacy_service_candidates(service_name)
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            backup_plan=RemediationBackupPlanRead(kind="file_copy", targets=source_files, note="执行前保留原配置备份"),
            render_reason="已基于 SSH 快照中的配置路径渲染修改与校验命令",
            target_files=source_files,
            target_services=[service_name] if service_name else [],
            fallback_strategy=fallback_strategy,
            fallback_candidates=fallback_candidates,
        )

    def _render_remove_config(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        return self._render_set_config(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params=params,
            requires_confirmation=requires_confirmation,
        )

    def _render_permission_set(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        rule_id = _yaml_rule_id(self.finding) or ""
        if rule_id not in SUPPORTED_PERMISSION_RULE_IDS:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "当前权限整改项缺少自动修复适配器")
        command, targets = _render_permission_command(
            rule_id=rule_id,
            host_checks=self.host_checks,
            config_by_service=self.config_by_service,
            excluded_suid_binaries=self.excluded_suid_binaries,
        )
        if not command or not targets:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未解析到稳定的本地文件或目录目标")
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            generated_command=command,
            requires_confirmation=requires_confirmation,
            backup_plan=RemediationBackupPlanRead(kind="permission_snapshot", targets=targets, note="执行前记录当前文件权限元数据"),
            render_reason="已基于 SSH 深度检查结果中的本地路径渲染权限收敛命令",
            target_paths=targets,
        )

    def _render_remove_exposure(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        config_key = str(params.get("config_key") or "").strip().lower()
        rule_id = str(params.get("rule_id") or _yaml_rule_id(self.finding) or "").strip()
        source_files = self._resolve_source_files(service_name)
        command = _render_exposure_command(service_name=service_name, config_key=config_key, rule_id=rule_id, source_files=source_files)
        if not command:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "当前暴露面整改项无法稳定渲染为自动化命令")
        if not source_files and not (service_name == "tomcat" and "manager" in rule_id.lower()):
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未解析到可用于收敛暴露面的稳定配置文件或路径")
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            blocked_reason=None,
            generated_command=command,
            requires_confirmation=requires_confirmation,
            backup_plan=RemediationBackupPlanRead(kind="file_copy", targets=source_files, note="执行前保留相关配置或入口文件备份") if source_files else None,
            render_reason="已基于识别到的配置文件与规则上下文渲染暴露面收敛命令",
            target_files=source_files,
            target_services=[service_name] if service_name else [],
        )

    def _render_restrict_network(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        config_key = str(params.get("config_key") or "").strip().lower()
        rule_id = str(params.get("rule_id") or _yaml_rule_id(self.finding) or "").strip()
        target_scope = str(params.get("target_scope") or "admin_segment_only").strip().lower()
        source_files = self._resolve_source_files(service_name)
        if not source_files:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "未解析到可用于收敛网络暴露面的稳定配置文件")
        command = _render_network_command(
            service_name=service_name,
            config_key=config_key,
            rule_id=rule_id,
            target_scope=target_scope,
            source_files=source_files,
        )
        if not command:
            return self._blocked_step(step_id, action_type, title, requires_confirmation, "当前网络收敛动作缺少稳定的自动执行适配器")
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=True,
            execution_state="ready",
            blocked_reason=None,
            generated_command=command,
            requires_confirmation=requires_confirmation,
            backup_plan=RemediationBackupPlanRead(kind="file_copy", targets=source_files, note="执行前保留网络监听与访问控制相关配置备份"),
            render_reason="已基于配置文件与规则上下文渲染网络暴露面收敛命令",
            target_files=source_files,
            target_services=[service_name] if service_name else [],
        )

    def _render_toggle_feature(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        feature_key = str(params.get("config_key") or params.get("feature_key") or "").strip().lower()
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        if feature_key in {"directory_listing_enabled", "webdav_enabled", "anonymous_enabled", "anonymous_write_enabled", "manager_exposed", "sample_apps_enabled", "default_credentials", "guest_access", "writable_guest_share", "weak_authentication"}:
            return self._render_remove_exposure(
                step_id=step_id,
                action_type=action_type,
                title=title,
                params={
                    "service_name": service_name,
                    "config_key": feature_key,
                    "rule_id": str(params.get("rule_id") or _yaml_rule_id(self.finding) or "").strip(),
                },
                requires_confirmation=requires_confirmation,
            )
        return self._render_set_config(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params={
                "service_name": service_name,
                "config_key": feature_key,
                "target_value": params.get("desired_state"),
            },
            requires_confirmation=requires_confirmation,
        )

    def _render_set_bind_scope(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        return self._render_restrict_network(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params={
                "service_name": params.get("service_name"),
                "config_key": params.get("config_key"),
                "rule_id": params.get("rule_id"),
                "target_scope": params.get("target_scope"),
            },
            requires_confirmation=requires_confirmation,
        )

    def _render_set_access_policy(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        config_key = str(params.get("config_key") or "").strip().lower()
        if config_key in {"trust_auth_enabled", "requirepass"}:
            return self._render_restrict_network(
                step_id=step_id,
                action_type=action_type,
                title=title,
                params={
                    "service_name": params.get("service_name"),
                    "config_key": config_key,
                    "rule_id": params.get("rule_id"),
                    "target_scope": params.get("target_scope") or "admin_segment_only",
                },
                requires_confirmation=requires_confirmation,
            )
        return self._render_set_config(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params={
                "service_name": params.get("service_name"),
                "config_key": config_key,
                "target_value": params.get("target_policy"),
            },
            requires_confirmation=requires_confirmation,
        )

    def _render_remove_path(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        explicit_paths = [str(item).strip() for item in (params.get("_target_paths") or []) if str(item).strip()]
        service_name = str(params.get("service_name") or _service_name_from_finding(self.finding) or "").strip().lower()
        if explicit_paths:
            command = _build_remove_path_command(
                explicit_paths,
                service_command=_build_service_control_command("restart", service_name, allow_missing=True) if service_name in _SERVICE_CONTROL_CANDIDATES else None,
            )
            return RemediationPlanStepRead(
                step_id=step_id,
                action_type=action_type,
                title=title,
                supported=True,
                execution_state="ready",
                generated_command=command,
                requires_confirmation=requires_confirmation,
                backup_plan=RemediationBackupPlanRead(kind="file_copy", targets=explicit_paths, note="执行前保留原路径或目录备份"),
                render_reason="已基于显式路径渲染暴露入口移除命令",
                target_paths=explicit_paths,
                target_services=[service_name] if service_name else [],
            )
        return self._render_remove_exposure(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params={
                "service_name": service_name,
                "config_key": params.get("config_key"),
                "rule_id": params.get("rule_id"),
            },
            requires_confirmation=requires_confirmation,
        )

    def _render_set_path_permission(self, *, step_id: str, action_type: str, title: str, params: dict[str, Any], requires_confirmation: bool) -> RemediationPlanStepRead:
        return self._render_permission_set(
            step_id=step_id,
            action_type=action_type,
            title=title,
            params=params,
            requires_confirmation=requires_confirmation,
        )

    def _blocked_step(self, step_id: str, action_type: str, title: str, requires_confirmation: bool, reason: str) -> RemediationPlanStepRead:
        return RemediationPlanStepRead(
            step_id=step_id,
            action_type=action_type,
            title=title,
            supported=False,
            execution_state="blocked",
            blocked_reason=reason,
            generated_command=None,
            requires_confirmation=requires_confirmation,
            render_reason=reason,
        )

    def _resolve_source_files(self, service_name: str) -> list[str]:
        service_config = self.config_by_service.get(service_name, {})
        source_files = [str(item).strip() for item in service_config.get("source_files", []) if str(item).strip()]
        if service_name == "polkit":
            source_files.extend(
                [str(item).strip() for item in service_config.get("rules_paths", []) if str(item).strip()]
            )
        if source_files:
            return list(dict.fromkeys(source_files))[:20]
        return list(_DEFAULT_CONFIG_FILES.get(service_name, []))

    def _resolve_package_manager(self, package_name: str, preferred: str | None) -> str | None:
        if preferred:
            return preferred
        normalized_name = package_name.strip().lower()
        for item in self.packages:
            name = str(item.get("name") or "").strip().lower()
            if name == normalized_name or name.startswith(f"{normalized_name}-") or normalized_name in name:
                manager = str(item.get("manager") or "").strip().lower()
                if manager:
                    return manager
        managers = [str(item.get("manager") or "").strip().lower() for item in self.packages if str(item.get("manager") or "").strip()]
        return managers[0] if managers else None

    def _resolve_fixed_version(self, fixed_versions: Any) -> str | None:
        if not isinstance(fixed_versions, dict):
            return None
        distro_name = None
        distro_release = None
        for service_name in ("sudo", "polkit"):
            config = self.config_by_service.get(service_name, {})
            distro_name = str(config.get("distro_name") or "").strip().lower() or distro_name
            distro_release = str(config.get("distro_release") or "").strip() or distro_release
        if not distro_name or not distro_release:
            return None
        distro_versions = fixed_versions.get(distro_name)
        if not isinstance(distro_versions, dict):
            return None
        value = distro_versions.get(distro_release)
        return str(value).strip() if isinstance(value, str) and value.strip() else None


def _snapshot_type(snapshot: HostSnapshot) -> str | None:
    for payload in [snapshot.error_json, snapshot.services_json, snapshot.software_json]:
        if isinstance(payload, dict) and payload.get("snapshot_type"):
            return str(payload["snapshot_type"])
    return None


def _asset_id_from_manual_credential(credential: SSHCredential) -> str | None:
    name = str(credential.name or "").strip()
    prefix = "manual-asset-"
    if not name.startswith(prefix):
        return None
    asset_id = name[len(prefix) :].strip()
    return asset_id or None


def _compute_blocked_reasons(credential: SSHCredential | None, snapshot: HostSnapshot | None) -> list[str]:
    reasons: list[str] = []
    if credential is None:
        reasons.append("当前资产未配置 SSH 管理员凭据")
        return reasons
    if credential.admin_authorized is not True:
        reasons.append("当前 SSH 凭据尚未确认管理员授权")
    if str(credential.last_verification_status or "").strip().lower() != "success":
        reasons.append("当前 SSH 凭据尚未完成管理员权限验证")
    if str(credential.last_effective_privilege or "").strip().lower() not in {"root", "sudo"}:
        reasons.append("当前 SSH 凭据未验证到管理员权限")
    if snapshot is None:
        reasons.append("暂无 SSH 授权深度检查结果")
    return reasons


def _credential_ready_for_remediation_listing(credential: SSHCredential | None) -> bool:
    if credential is None:
        return False
    if credential.admin_authorized is not True:
        return False
    if str(credential.last_verification_status or "").strip().lower() != "success":
        return False
    return str(credential.last_effective_privilege or "").strip().lower() in {"root", "sudo"}


def _step_field(step: Any, field: str) -> Any:
    if isinstance(step, dict):
        return step.get(field)
    return getattr(step, field, None)


def select_executable_plan_steps(steps: list[Any], *, submitted_step_ids: list[str] | None = None) -> list[Any]:
    step_map: dict[str, Any] = {}
    duplicate_step_ids: set[str] = set()
    for step in steps:
        step_id = str(_step_field(step, "step_id") or "").strip()
        if not step_id:
            continue
        if step_id in step_map:
            duplicate_step_ids.add(step_id)
            continue
        step_map[step_id] = step

    if submitted_step_ids:
        normalized_ids = list(dict.fromkeys([str(item or "").strip() for item in submitted_step_ids if str(item or "").strip()]))
        if not normalized_ids:
            raise RuntimeError("当前没有可提交的执行步骤")
        ambiguous_step_ids = [step_id for step_id in normalized_ids if step_id in duplicate_step_ids]
        if ambiguous_step_ids:
            raise RuntimeError(f"执行计划存在重复步骤标识：{ambiguous_step_ids[0]}")
        missing_step_ids = [step_id for step_id in normalized_ids if step_id not in step_map]
        if missing_step_ids:
            raise RuntimeError(f"提交的修复步骤不存在：{missing_step_ids[0]}")
        selected_steps = [step_map[step_id] for step_id in normalized_ids]
    else:
        selected_steps = [step for step in steps if str(_step_field(step, "execution_state") or "").strip().lower() == "ready"]

    if not selected_steps:
        raise RuntimeError("当前没有可提交的执行步骤")

    for step in selected_steps:
        if str(_step_field(step, "execution_state") or "").strip().lower() == "ready":
            continue
        title = str(_step_field(step, "title") or _step_field(step, "step_id") or "未知步骤").strip()
        blocked_reason = str(_step_field(step, "blocked_reason") or "").strip()
        raise RuntimeError(blocked_reason or f"步骤“{title}”当前不可执行")
    return selected_steps


def selected_steps_require_maintenance_window(steps: list[Any]) -> bool:
    return any(bool(_step_field(step, "requires_maintenance_window")) for step in steps)


def _open_asset_port_id_set(db: Session, findings: list[RiskFinding]) -> set[str]:
    port_ids = sorted({finding.asset_port_id for finding in findings if finding.asset_port_id})
    if not port_ids:
        return set()
    rows = db.execute(select(AssetPort.id, AssetPort.state).where(AssetPort.id.in_(port_ids))).all()
    return {
        port_id
        for port_id, state in rows
        if str(state or "").strip().lower() == "open"
    }


def _finding_is_remediation_candidate(
    finding: RiskFinding,
    *,
    open_asset_port_ids: set[str],
    has_remediation_template: bool | None = None,
    rule_cache: dict[str, Any | None] | None = None,
) -> bool:
    if finding.status != FindingStatus.OPEN:
        return False
    if has_remediation_template is None:
        has_remediation_template = _finding_has_remediation_template(finding, rule_cache=rule_cache)
    if not has_remediation_template:
        return False
    if finding.asset_port_id is None:
        return True
    return finding.asset_port_id in open_asset_port_ids


def _finding_has_remediation_template(
    finding: RiskFinding,
    *,
    rule_cache: dict[str, Any | None] | None = None,
) -> bool:
    rule_id = _yaml_rule_id(finding)
    if not rule_id:
        return False
    if rule_cache is not None:
        if rule_id not in rule_cache:
            rule_cache[rule_id] = risks_endpoint.RULE_STORE.get_rule(rule_id)
        return bool(rule_cache[rule_id])
    return bool(risks_endpoint.RULE_STORE.get_rule(rule_id))


def _pick_recommended_finding(findings: list[RiskFinding]) -> RiskFinding | None:
    if not findings:
        return None
    return sorted(
        findings,
        key=lambda item: (
            _severity_sort_value(item.severity),
            item.detected_at.isoformat() if item.detected_at else "",
        ),
        reverse=True,
    )[0]


def _pick_highest_severity(findings: list[RiskFinding]) -> RiskSeverity | None:
    if not findings:
        return None
    return sorted(findings, key=lambda item: _severity_sort_value(item.severity), reverse=True)[0].severity


def _severity_sort_value(value: RiskSeverity | str | None) -> int:
    if value in _SEVERITY_RANK:
        return _SEVERITY_RANK[value]  # type: ignore[index]
    raw = str(value or "").strip().lower()
    for severity, rank in _SEVERITY_RANK.items():
        if severity.value == raw:
            return rank
    return 0


def _yaml_rule_id(finding: RiskFinding) -> str | None:
    evidence = _evidence_dict(finding)
    value = str(evidence.get("yaml_rule_id") or "").strip()
    return value or None


def _service_name_from_finding(finding: RiskFinding) -> str | None:
    evidence = _evidence_dict(finding)
    service_name = str(evidence.get("service_name") or "").strip()
    if service_name:
        return service_name
    if finding.asset_port and str(finding.asset_port.service_name or "").strip():
        return str(finding.asset_port.service_name).strip()
    return None


def _evidence_dict(finding: RiskFinding) -> dict[str, Any]:
    return dict(finding.evidence_json) if isinstance(finding.evidence_json, dict) else {}


def _build_snapshot_planner_context(snapshot: HostSnapshot | None, *, host_runner: HostRunner | None = None) -> dict[str, Any]:
    return {
        "os_release": str(snapshot.os_release or "").strip() if snapshot is not None else "",
        "kernel_version": str(snapshot.kernel_version or "").strip() if snapshot is not None else "",
        "detail_json": _detail_json_from_snapshot(snapshot),
        "summary_json": _summary_json_from_snapshot(snapshot),
        "config_by_service": _config_by_service(snapshot),
        "host_checks": _host_checks(snapshot),
        "packages": _packages(snapshot),
        "services": _services(snapshot),
        "runner_capabilities": dict(host_runner.capabilities_json or {}) if host_runner and isinstance(host_runner.capabilities_json, dict) else {},
    }


def _filter_login_user_required_suid_actions(
    *,
    finding: RiskFinding,
    rendered_template: dict[str, Any],
    credential: SSHCredential | None,
    snapshot_context: dict[str, Any] | None,
) -> tuple[dict[str, Any], set[str]]:
    excluded_suid_binaries = _login_user_required_suid_binaries(
        snapshot_context=snapshot_context,
        credential=credential,
    )
    if not excluded_suid_binaries:
        return rendered_template, set()
    filtered_actions: list[dict[str, Any]] = []
    for action in rendered_template.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if _should_omit_login_user_required_suid_action(
            finding=finding,
            action=action,
            excluded_suid_binaries=excluded_suid_binaries,
            snapshot_context=snapshot_context,
        ):
            continue
        filtered_actions.append(action)
    filtered_template = dict(rendered_template)
    filtered_template["actions"] = filtered_actions
    return filtered_template, excluded_suid_binaries


def _summary_json_from_snapshot(snapshot: HostSnapshot | None) -> dict[str, Any]:
    if snapshot is None or not isinstance(snapshot.software_json, dict):
        return {}
    return dict(snapshot.software_json.get("summary_json") or {})


def _detail_json_from_snapshot(snapshot: HostSnapshot | None) -> dict[str, Any]:
    if snapshot is None or not isinstance(snapshot.software_json, dict):
        return {}
    return dict(snapshot.software_json.get("detail_json") or {})


def _config_by_service(snapshot: HostSnapshot | None) -> dict[str, dict[str, Any]]:
    if snapshot is None or not isinstance(snapshot.services_json, dict):
        return {}
    data = snapshot.services_json.get("config_by_service") or {}
    return dict(data) if isinstance(data, dict) else {}


def _runner_card_status(host_runner: HostRunner | None) -> str | None:
    if host_runner is None:
        return "not_installed"
    status = str(host_runner.status or "").strip().lower() or "offline"
    if host_runner.last_seen_at and datetime.now(timezone.utc) - host_runner.last_seen_at > timedelta(seconds=45):
        return "offline"
    return status


def _host_checks(snapshot: HostSnapshot | None) -> dict[str, Any]:
    if snapshot is None or not isinstance(snapshot.software_json, dict):
        return {}
    data = snapshot.software_json.get("host_checks") or {}
    return dict(data) if isinstance(data, dict) else {}


def _packages(snapshot: HostSnapshot | None) -> list[dict[str, Any]]:
    if snapshot is None or not isinstance(snapshot.software_json, dict):
        return []
    raw = snapshot.software_json.get("packages") or []
    return [dict(item) for item in raw if isinstance(item, dict)]


def _services(snapshot: HostSnapshot | None) -> list[dict[str, Any]]:
    if snapshot is None or not isinstance(snapshot.services_json, dict):
        return []
    raw = snapshot.services_json.get("services") or []
    return [dict(item) for item in raw if isinstance(item, dict)]


def _normalized_login_user(
    *,
    snapshot_context: dict[str, Any] | None,
    credential: SSHCredential | None,
) -> str | None:
    context = snapshot_context or {}
    detail_json = context.get("detail_json") if isinstance(context.get("detail_json"), dict) else {}
    summary_json = context.get("summary_json") if isinstance(context.get("summary_json"), dict) else {}
    authorization = detail_json.get("authorization") if isinstance(detail_json.get("authorization"), dict) else {}
    value = (
        authorization.get("username")
        or summary_json.get("login_user")
        or (credential.username if credential is not None else None)
    )
    normalized = str(value or "").strip().lower()
    return normalized or None


def _credential_admin_chain_kind(credential: SSHCredential | None) -> str:
    if credential is None:
        return "unsupported"
    username = str(credential.username or "").strip().lower()
    privilege = str(credential.last_effective_privilege or "").strip().lower()
    if username == "root" or privilege == "root":
        return "root_direct"
    if username and username != "root" and privilege == "sudo":
        return "sudo_chain"
    return "unsupported"


def _path_hits_sudo_management_plane(value: str | None) -> bool:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return False
    return normalized in _SELF_LOCK_SUDO_TARGETS or any(normalized.startswith(prefix) for prefix in _SELF_LOCK_SUDO_TARGET_PREFIXES)


def _block_self_lock_step(step: RemediationPlanStepRead) -> RemediationPlanStepRead:
    return step.model_copy(
        update={
            "supported": False,
            "execution_state": "blocked",
            "blocked_reason": _SELF_LOCK_SUDO_MESSAGE,
            "generated_command": None,
            "render_reason": _SELF_LOCK_SUDO_MESSAGE,
        }
    )


def _step_has_real_backup_target(step: RemediationPlanStepRead) -> bool:
    backup_plan = step.backup_plan
    return bool(backup_plan and backup_plan.targets)


def _step_has_enterprise_contract(step: RemediationPlanStepRead) -> bool:
    return bool(
        step.adapter_id
        and step.adapter_version
        and step.dry_run_supported
        and step.evidence_items
    )


def _decorate_step_with_enterprise_contract(step: RemediationPlanStepRead) -> RemediationPlanStepRead:
    contract = dict(_ACTION_ADAPTER_CONTRACTS.get(step.action_type, {}))
    backup_required = step.action_type in _BACKUP_REQUIRED_ACTION_TYPES
    backup_ready = _step_has_real_backup_target(step)
    rollback_supported = backup_ready and step.action_type != "upgrade_package"
    updates: dict[str, Any] = {
        "risk_level": contract.get("risk_level", "medium"),
        "idempotent": bool(contract.get("idempotent", False)),
        "dry_run_supported": bool(contract.get("dry_run_supported", False)),
        "rollback_supported": rollback_supported,
        "evidence_items": list(contract.get("evidence_items", [])),
        "requires_maintenance_window": bool(contract.get("requires_maintenance_window", False)),
        "adapter_id": contract.get("adapter_id"),
        "adapter_version": REMEDIATION_ADAPTER_VERSION if contract else None,
    }
    if backup_required and not backup_ready and step.execution_state == "ready":
        blocked_reason = "当前步骤缺少可验证的备份目标，已阻止自动执行"
        updates.update(
            {
                "supported": False,
                "execution_state": "blocked",
                "blocked_reason": blocked_reason,
                "generated_command": None,
                "render_reason": blocked_reason,
                "rollback_supported": False,
            }
        )
    return step.model_copy(update=updates)


def _is_self_locking_sudo_step(
    *,
    finding: RiskFinding,
    action: dict[str, Any],
    step: RemediationPlanStepRead,
    credential: SSHCredential | None,
) -> bool:
    if _credential_admin_chain_kind(credential) != "sudo_chain":
        return False
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    rule_id = str(params.get("rule_id") or _yaml_rule_id(finding) or "").strip().lower()
    if rule_id.startswith("sudo."):
        return True
    service_names = {
        str(item).strip().lower()
        for item in [
            *list(step.target_services),
            params.get("service_name"),
            _service_name_from_finding(finding),
        ]
        if str(item).strip()
    }
    targets_sudo_plane = any(_path_hits_sudo_management_plane(item) for item in [*list(step.target_files), *list(step.target_paths)])
    if "sudo" in service_names or targets_sudo_plane:
        return True
    return False


def _binary_path_from_host_checks(host_checks: dict[str, Any], binary: str) -> str:
    key = f"{binary.strip().lower()}_local"
    data = host_checks.get(key) if isinstance(host_checks.get(key), dict) else {}
    return str(data.get("binary_path") or "").strip()


def _actionable_dangerous_suid_paths(
    host_checks: dict[str, Any],
    *,
    excluded_suid_binaries: set[str] | None = None,
) -> list[str]:
    excluded = {
        str(item).strip().lower()
        for item in (excluded_suid_binaries or set())
        if str(item).strip()
    }
    suid_sgid = host_checks.get("suid_sgid") if isinstance(host_checks.get("suid_sgid"), dict) else {}
    paths = []
    for item in suid_sgid.get("dangerous_entries", []):
        path = str(item).strip()
        if not path:
            continue
        basename = path.rsplit("/", 1)[-1].strip().lower()
        if basename in excluded:
            continue
        paths.append(path)
    if not paths:
        dangerous_by_binary = (
            suid_sgid.get("dangerous_suid_by_binary")
            if isinstance(suid_sgid.get("dangerous_suid_by_binary"), dict)
            else {}
        )
        fallback_paths: list[str] = []
        for binary in sorted(_LOGIN_USER_OPTIONAL_SUID_BINARIES):
            if binary in excluded or not dangerous_by_binary.get(binary):
                continue
            path = _binary_path_from_host_checks(host_checks, binary)
            if path:
                fallback_paths.append(path)
        paths = fallback_paths
    return list(dict.fromkeys(paths))


def _login_user_required_suid_binaries(
    *,
    snapshot_context: dict[str, Any] | None,
    credential: SSHCredential | None,
) -> set[str]:
    login_user = _normalized_login_user(snapshot_context=snapshot_context, credential=credential)
    if not login_user or login_user == "root":
        return set()
    context = snapshot_context or {}
    host_checks = context.get("host_checks") if isinstance(context.get("host_checks"), dict) else {}
    required: set[str] = set()
    for binary in _LOGIN_USER_OPTIONAL_SUID_BINARIES:
        local_check = host_checks.get(f"{binary}_local") if isinstance(host_checks.get(f"{binary}_local"), dict) else {}
        if bool(local_check.get("suid_present")):
            required.add(binary)
    dangerous_paths = _actionable_dangerous_suid_paths(host_checks)
    for path in dangerous_paths:
        basename = path.rsplit("/", 1)[-1].strip().lower()
        if basename in _LOGIN_USER_OPTIONAL_SUID_BINARIES:
            required.add(basename)
    return required


def _should_omit_login_user_required_suid_action(
    *,
    finding: RiskFinding,
    action: dict[str, Any],
    excluded_suid_binaries: set[str],
    snapshot_context: dict[str, Any] | None,
) -> bool:
    action_type = str(action.get("action_type") or "").strip().lower()
    if action_type not in _SUID_PERMISSION_ACTION_TYPES:
        return False
    params = action.get("params") if isinstance(action.get("params"), dict) else {}
    rule_id = str(params.get("rule_id") or _yaml_rule_id(finding) or "").strip()
    binary = _LOGIN_USER_REQUIRED_SUID_RULE_BINARIES.get(rule_id)
    if binary:
        return binary in excluded_suid_binaries
    if rule_id != "linux-host.dangerous_suid.present":
        return False
    context = snapshot_context or {}
    host_checks = context.get("host_checks") if isinstance(context.get("host_checks"), dict) else {}
    return not _actionable_dangerous_suid_paths(
        host_checks,
        excluded_suid_binaries=excluded_suid_binaries,
    )


def _login_user_required_suid_message(excluded_suid_binaries: set[str]) -> str:
    binary_text = "、".join(sorted(excluded_suid_binaries))
    return f"当前登录用户依赖必要的 SUID 程序（{binary_text}），相关 SUID 权限问题默认不纳入自动修复计划"


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    normalized = str(value or "").strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def _build_ssh_validate_command(*, legacy_debian: bool) -> str:
    if not legacy_debian:
        return "sshd -t"
    return "\n".join(
        [
            "if [ -x /usr/sbin/sshd ]; then",
            "  /usr/sbin/sshd -t",
            "elif command -v sshd >/dev/null 2>&1; then",
            '  "$(command -v sshd)" -t',
            "else",
            "  echo '未找到 sshd 校验命令' >&2",
            "  exit 1",
            "fi",
        ]
    )


def _build_legacy_debian_package_upgrade_command(
    *,
    original_package_name: str,
    candidates: list[str],
    fixed_version: str | None,
) -> str:
    ordered_candidates = [str(item).strip().lower() for item in candidates if str(item).strip()]
    if not ordered_candidates:
        ordered_candidates = [str(original_package_name).strip().lower()]
    candidate_tokens = " ".join(shlex.quote(item) for item in ordered_candidates)
    display_candidates = " / ".join(ordered_candidates)
    fixed_version_value = str(fixed_version or "").strip()
    lines = [
        "export DEBIAN_FRONTEND=noninteractive",
        "export APT_LISTCHANGES_FRONTEND=none",
        "export NEEDRESTART_MODE=a",
        f"SA_ORIGINAL_PACKAGE={shlex.quote(original_package_name)}",
        "SA_RESOLVED_PACKAGE=",
        f"echo '旧版 Debian 自动解析：准备检查软件包 {original_package_name}'",
        f"for pkg in {candidate_tokens}; do",
        "  if dpkg-query -W -f='${Status}' \"$pkg\" 2>/dev/null | grep -q 'install ok installed'; then",
        "    SA_RESOLVED_PACKAGE=\"$pkg\"",
        "    break",
        "  fi",
        "done",
        "if [ -z \"$SA_RESOLVED_PACKAGE\" ]; then",
        f"  for pkg in {candidate_tokens}; do",
        "    if apt-cache policy \"$pkg\" 2>/dev/null | grep -F 'Candidate:' | grep -vq '(none)'; then",
        "      SA_RESOLVED_PACKAGE=\"$pkg\"",
        "      break",
        "    fi",
        "  done",
        "fi",
        "if [ -z \"$SA_RESOLVED_PACKAGE\" ]; then",
        f"  echo '未找到可用的软件包候选：{original_package_name}（候选：{display_candidates}）' >&2",
        "  exit 1",
        "fi",
        "if [ \"$SA_RESOLVED_PACKAGE\" = \"$SA_ORIGINAL_PACKAGE\" ]; then",
        "  echo \"自动解析软件包：沿用模板目标 $SA_RESOLVED_PACKAGE\"",
        "else",
        "  echo \"自动解析软件包：$SA_ORIGINAL_PACKAGE -> $SA_RESOLVED_PACKAGE\"",
        "  echo \"自动替换组件：$SA_ORIGINAL_PACKAGE -> $SA_RESOLVED_PACKAGE\"",
        "fi",
        "if dpkg-query -W -f='${Status}' \"$SA_RESOLVED_PACKAGE\" 2>/dev/null | grep -q 'install ok installed'; then",
        "  echo \"目标包已安装，将直接升级：$SA_RESOLVED_PACKAGE\"",
        "else",
        "  echo \"目标包未安装，将自动补装：$SA_RESOLVED_PACKAGE\"",
        "fi",
        "apt-get update",
        "SA_PACKAGE_TOKEN=\"$SA_RESOLVED_PACKAGE\"",
    ]
    if fixed_version_value:
        lines.extend(
            [
                f"SA_FIXED_VERSION={shlex.quote(fixed_version_value)}",
                'if [ -n "$SA_FIXED_VERSION" ] && [ "$SA_RESOLVED_PACKAGE" = "$SA_ORIGINAL_PACKAGE" ]; then',
                '  SA_PACKAGE_TOKEN="${SA_RESOLVED_PACKAGE}=${SA_FIXED_VERSION}"',
                'elif [ -n "$SA_FIXED_VERSION" ]; then',
                '  echo "已切换到同族候选 $SA_RESOLVED_PACKAGE，跳过原目标固定版本约束 $SA_FIXED_VERSION"',
                "fi",
            ]
        )
    lines.append(
        'apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$SA_PACKAGE_TOKEN"'
    )
    return "\n".join(lines)


def _build_legacy_debian_service_control_command(
    *,
    action: str,
    original_service_name: str,
    service_candidates: list[str],
    package_candidates: list[str] | None = None,
    allow_missing: bool = False,
) -> str:
    ordered_service_candidates = [str(item).strip().lower() for item in service_candidates if str(item).strip()]
    ordered_package_candidates = [str(item).strip().lower() for item in (package_candidates or []) if str(item).strip()]
    if not ordered_service_candidates:
        ordered_service_candidates = [str(original_service_name).strip().lower()]
    service_tokens = " ".join(shlex.quote(item) for item in ordered_service_candidates)
    package_tokens = " ".join(shlex.quote(item) for item in ordered_package_candidates)
    service_display = " / ".join(ordered_service_candidates)
    service_subcommand = {"reload": "reload", "restart": "restart", "disable": "stop"}.get(action, action)
    fallback_subcommand = "restart" if action == "reload" else None
    lines = [
        "export DEBIAN_FRONTEND=noninteractive",
        "export APT_LISTCHANGES_FRONTEND=none",
        "export NEEDRESTART_MODE=a",
        f"SA_ORIGINAL_SERVICE={shlex.quote(original_service_name)}",
        "SA_RESOLVED_SERVICE=",
        f"echo '旧版 Debian 自动解析：准备检查服务 {original_service_name}'",
        f"for svc in {service_tokens}; do",
        "  if [ -x \"/etc/init.d/$svc\" ]; then",
        "    SA_RESOLVED_SERVICE=\"$svc\"",
        "    break",
        "  fi",
        "done",
    ]
    if ordered_package_candidates:
        lines.extend(
            [
                "if [ -z \"$SA_RESOLVED_SERVICE\" ]; then",
                "  SA_APT_UPDATED=0",
                f"  for pkg in {package_tokens}; do",
                "    if ! apt-cache policy \"$pkg\" 2>/dev/null | grep -F 'Candidate:' | grep -vq '(none)'; then",
                "      continue",
                "    fi",
                '    if [ "$SA_APT_UPDATED" = "0" ]; then',
                "      apt-get update",
                "      SA_APT_UPDATED=1",
                "    fi",
                "    if dpkg-query -W -f='${Status}' \"$pkg\" 2>/dev/null | grep -q 'install ok installed'; then",
                '      echo "候选组件已安装，继续检查服务脚本：$pkg"',
                "    else",
                '      echo "目标服务缺少候选组件，将自动补装：$pkg"',
                '      apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$pkg" || { echo "自动补装组件失败：$pkg" >&2; exit 1; }',
                "    fi",
                f"    for svc in {service_tokens}; do",
                "      if [ -x \"/etc/init.d/$svc\" ]; then",
                "        SA_RESOLVED_SERVICE=\"$svc\"",
                "        break 2",
                "      fi",
                "    done",
                "  done",
                "fi",
            ]
        )
    lines.extend(
        [
            "if [ -z \"$SA_RESOLVED_SERVICE\" ]; then",
        ]
    )
    if allow_missing:
        lines.extend(
            [
                f"  echo '未找到可管理的服务单元：{original_service_name}；已尝试旧版 Debian 自动解析（候选：{service_display}）' >&2",
                "  exit 0",
                "fi",
            ]
        )
    else:
        lines.extend(
            [
                f"  echo '未找到可管理的服务单元：{original_service_name}；已尝试旧版 Debian 自动解析（候选：{service_display}）' >&2",
                "  exit 1",
                "fi",
            ]
        )
    lines.extend(
        [
            "if [ \"$SA_RESOLVED_SERVICE\" = \"$SA_ORIGINAL_SERVICE\" ]; then",
            "  echo \"自动解析服务目标：沿用模板目标 $SA_RESOLVED_SERVICE\"",
            "else",
            "  echo \"自动解析服务目标：$SA_ORIGINAL_SERVICE -> $SA_RESOLVED_SERVICE\"",
            "fi",
        ]
    )
    if action == "disable":
        lines.extend(
            [
                'if command -v service >/dev/null 2>&1; then service "$SA_RESOLVED_SERVICE" stop >/dev/null 2>&1 || true; fi',
                'if [ -x "/etc/init.d/$SA_RESOLVED_SERVICE" ]; then /etc/init.d/$SA_RESOLVED_SERVICE stop >/dev/null 2>&1 || true; fi',
                'if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f "$SA_RESOLVED_SERVICE" remove >/dev/null 2>&1 && exit 0; fi',
                'echo "未找到可禁用的旧版 Debian 服务目标：$SA_RESOLVED_SERVICE" >&2',
                "exit 1",
            ]
        )
        return "\n".join(lines)
    lines.extend(
        [
            'if command -v service >/dev/null 2>&1; then',
            f'  service "$SA_RESOLVED_SERVICE" {service_subcommand} >/dev/null 2>&1 && exit 0',
        ]
    )
    if fallback_subcommand:
        lines.append(f'  service "$SA_RESOLVED_SERVICE" {fallback_subcommand} >/dev/null 2>&1 && exit 0')
    lines.extend(
        [
            "fi",
            'if [ -x "/etc/init.d/$SA_RESOLVED_SERVICE" ]; then',
            f'  /etc/init.d/$SA_RESOLVED_SERVICE {service_subcommand} >/dev/null 2>&1 && exit 0',
        ]
    )
    if fallback_subcommand:
        lines.append(f'  /etc/init.d/$SA_RESOLVED_SERVICE {fallback_subcommand} >/dev/null 2>&1 && exit 0')
    lines.extend(
        [
            "fi",
            f'echo "旧版 Debian 服务控制失败：$SA_RESOLVED_SERVICE ({action})" >&2',
            "exit 1",
        ]
    )
    return "\n".join(lines)


def _build_package_upgrade_command(*, manager: str, package_name: str, fixed_version: str | None) -> str:
    package_token = f"{package_name}={fixed_version}" if fixed_version and manager == "dpkg" else package_name
    if manager == "dpkg":
        return "\n".join(
            [
                "export DEBIAN_FRONTEND=noninteractive",
                "export APT_LISTCHANGES_FRONTEND=none",
                "export NEEDRESTART_MODE=a",
                "apt-get update",
                f"apt-get install -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold {shlex.quote(package_token)}",
            ]
        )
    if manager in {"dnf", "yum", "rpm"}:
        return "\n".join(
            [
                "if command -v dnf >/dev/null 2>&1; then",
                f"  dnf upgrade -y {shlex.quote(package_name)}",
                "elif command -v yum >/dev/null 2>&1; then",
                f"  yum update -y {shlex.quote(package_name)}",
                "else",
                "  echo '未识别到 dnf/yum，无法自动执行 rpm 系升级' >&2",
                "  exit 1",
                "fi",
            ]
        )
    if manager == "apk":
        return f"apk add --no-cache --upgrade {shlex.quote(package_name)}"
    return ""


def _build_service_control_command(action: str, service_name: str, *, allow_missing: bool = False) -> str:
    candidates = _SERVICE_CONTROL_CANDIDATES.get(service_name, [service_name])
    if not candidates:
        candidates = [service_name]
    candidate_tokens = " ".join(shlex.quote(item) for item in candidates)
    service_subcommand = {"reload": "reload", "restart": "restart", "disable": "disable --now"}.get(action, action)
    legacy_subcommand = {"reload": "reload", "restart": "restart", "disable": "stop"}.get(action, action)
    legacy_fallback_subcommand = "restart" if action == "reload" else None
    lines = [
        f"for svc in {candidate_tokens}; do",
        "  if command -v systemctl >/dev/null 2>&1; then",
        f"    systemctl {service_subcommand} \"$svc\" >/dev/null 2>&1 && exit 0",
        f"    systemctl {service_subcommand} \"${{svc}}.service\" >/dev/null 2>&1 && exit 0",
    ]
    if action == "reload":
        lines.extend(
            [
                "    systemctl try-reload-or-restart \"$svc\" >/dev/null 2>&1 && exit 0",
                "    systemctl try-reload-or-restart \"${svc}.service\" >/dev/null 2>&1 && exit 0",
            ]
        )
    lines.extend(
        [
            "  fi",
            "  if command -v service >/dev/null 2>&1; then",
            f"    service \"$svc\" {legacy_subcommand} >/dev/null 2>&1 && exit 0",
            "  fi",
        ]
    )
    if legacy_fallback_subcommand:
        lines.extend(
            [
                "  if command -v service >/dev/null 2>&1; then",
                f"    service \"$svc\" {legacy_fallback_subcommand} >/dev/null 2>&1 && exit 0",
                "  fi",
            ]
        )
    if action == "disable":
        lines.extend(
            [
                "  if command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then",
                "    rc-service \"$svc\" stop >/dev/null 2>&1 && rc-update del \"$svc\" default >/dev/null 2>&1 && exit 0",
                "  fi",
            ]
        )
    else:
        lines.extend(
            [
                "  if command -v rc-service >/dev/null 2>&1; then",
                f"    rc-service \"$svc\" {legacy_subcommand} >/dev/null 2>&1 && exit 0",
                "  fi",
            ]
        )
        if legacy_fallback_subcommand:
            lines.extend(
                [
                    "  if command -v rc-service >/dev/null 2>&1; then",
                    f"    rc-service \"$svc\" {legacy_fallback_subcommand} >/dev/null 2>&1 && exit 0",
                    "  fi",
                ]
            )
    lines.extend(
        [
            "  if [ -x \"/etc/init.d/$svc\" ]; then",
            f"    /etc/init.d/$svc {legacy_subcommand} >/dev/null 2>&1 && exit 0",
            "  fi",
        ]
    )
    if legacy_fallback_subcommand:
        lines.extend(
            [
                "  if [ -x \"/etc/init.d/$svc\" ]; then",
                f"    /etc/init.d/$svc {legacy_fallback_subcommand} >/dev/null 2>&1 && exit 0",
                "  fi",
            ]
        )
    lines.extend(
        [
            "done",
        ]
    )
    if allow_missing:
        lines.extend(
            [
                f"echo '未找到可管理的服务单元：{service_name}；已保留配置变更，请人工确认是否需要重载服务' >&2",
                "exit 0",
            ]
        )
    else:
        lines.extend(
            [
                f"echo '未找到可管理的服务单元：{service_name}' >&2",
                "exit 1",
            ]
        )
    return "\n".join(lines)


def _build_legacy_python_file_command(
    *,
    source_files: list[str],
    imports: str,
    script_lines: list[str],
    validate_command: str | None = None,
    service_command: str | None = None,
) -> str:
    paths = " ".join(shlex.quote(path) for path in source_files)
    lines = [
        "PYTHON_BIN=$(command -v python3 || command -v python)",
        'if [ -z "$PYTHON_BIN" ]; then echo "未找到 python 解释器" >&2; exit 1; fi',
        f'"$PYTHON_BIN" - {paths} <<\'PY\'',
        f"import {imports}",
        "def _read_text(path):",
        "    if not os.path.exists(path):",
        "        return ''",
        "    handle = codecs.open(path, 'r', 'utf-8', 'ignore')",
        "    try:",
        "        return handle.read()",
        "    finally:",
        "        handle.close()",
        "def _write_text(path, text):",
        "    handle = codecs.open(path, 'w', 'utf-8')",
        "    try:",
        "        handle.write(text)",
        "    finally:",
        "        handle.close()",
        *script_lines,
        "PY",
    ]
    if validate_command:
        lines.append(validate_command)
    if service_command:
        lines.append(service_command)
    return "\n".join(lines)


def _render_config_command(
    *,
    service_name: str,
    config_key: str,
    target_value: Any,
    source_files: list[str],
    legacy_debian: bool = False,
) -> str:
    if service_name == "ssh":
        value_map = {
            "password_authentication": ("PasswordAuthentication", "no"),
            "permit_root_login": ("PermitRootLogin", "no"),
            "permit_empty_passwords": ("PermitEmptyPasswords", "no"),
            "pubkey_authentication": ("PubkeyAuthentication", "yes"),
        }
        directive, value = value_map.get(config_key, (None, None))
        if not directive or value is None:
            return ""
        return _build_replace_or_append_command(
            source_files=source_files[:1],
            directive=directive,
            value=value,
            validate_command=_build_ssh_validate_command(legacy_debian=legacy_debian),
            service_command=(
                _build_legacy_debian_service_control_command(
                    action="reload",
                    original_service_name="ssh",
                    service_candidates=_LEGACY_DEBIAN_SERVICE_FAMILIES["ssh"],
                    package_candidates=_LEGACY_DEBIAN_SERVICE_PACKAGE_FAMILIES["ssh"],
                    allow_missing=True,
                )
                if legacy_debian
                else _build_service_control_command("reload", "ssh", allow_missing=True)
            ),
        )
    if service_name == "mysql":
        if config_key == "skip_grant_tables":
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"^\s*(?:#\s*)?skip[-_]grant[-_]tables\b.*$",
                service_command=_build_service_control_command("restart", "mysql", allow_missing=True),
            )
        if config_key == "local_infile":
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="local_infile",
                value="0",
                validate_command=None,
                service_command=_build_service_control_command("restart", "mysql", allow_missing=True),
            )
        if config_key == "bind_all_interfaces":
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="bind-address",
                value="127.0.0.1",
                validate_command=None,
                service_command=_build_service_control_command("restart", "mysql", allow_missing=True),
            )
    if service_name == "sudo":
        if config_key == "setenv_present":
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"\bSETENV\b",
                service_command="visudo -cf /etc/sudoers",
            )
        if config_key == "dangerous_env_keep_present":
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)",
                service_command="visudo -cf /etc/sudoers",
            )
        if config_key == "full_privilege_rule":
            return _build_comment_out_regex_command(
                source_files=source_files,
                pattern=r"^\s*[^#\n].*\bALL\s*=\s*\(ALL(?::ALL)?\)\s+ALL\s*$",
                validate_command="visudo -cf /etc/sudoers",
                service_command=None,
            )
    if service_name == "redis":
        if config_key == "protected_mode":
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="protected-mode",
                value="yes",
                validate_command=None,
                service_command=_build_service_control_command("restart", "redis", allow_missing=True),
            )
        if config_key == "bind_all_interfaces":
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="bind",
                value="127.0.0.1 ::1",
                validate_command=None,
                service_command=_build_service_control_command("restart", "redis", allow_missing=True),
            )
    if service_name == "postgresql":
        if config_key == "listen_all_interfaces":
            return _build_replace_or_append_command(
                source_files=_pick_matching_source_files(source_files, "postgresql.conf"),
                directive="listen_addresses",
                value="'localhost'",
                validate_command=None,
                service_command=_build_service_control_command("restart", "postgresql", allow_missing=True),
            )
        if config_key == "trust_auth_enabled":
            return _build_remove_regex_command(
                source_files=_pick_matching_source_files(source_files, "pg_hba.conf"),
                pattern=r"(^|\s)trust(\s|$)",
                service_command=_build_service_control_command("restart", "postgresql", allow_missing=True),
            )
    return ""


def _render_exposure_command(*, service_name: str, config_key: str, rule_id: str, source_files: list[str]) -> str:
    normalized_rule_id = rule_id.lower()
    if service_name == "apache":
        if config_key == "directory_listing_enabled" or "directory_listing" in normalized_rule_id:
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"\bIndexes\b",
                service_command=_build_service_control_command("reload", "apache", allow_missing=True),
            )
        if config_key == "webdav_enabled" or "webdav" in normalized_rule_id or "risky_methods" in normalized_rule_id:
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"\bDav\s+On\b|\bLimitExcept\s+(?!GET|HEAD|POST).*$",
                service_command=_build_service_control_command("reload", "apache", allow_missing=True),
            )
    if service_name == "nginx":
        if config_key == "directory_listing_enabled" or "directory_listing" in normalized_rule_id:
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="autoindex",
                value="off;",
                validate_command="nginx -t",
                service_command=_build_service_control_command("reload", "nginx", allow_missing=True),
            )
        if config_key == "webdav_enabled" or "webdav" in normalized_rule_id or "risky_methods" in normalized_rule_id:
            return _build_remove_regex_command(
                source_files=source_files,
                pattern=r"\bdav_methods\b.*$",
                service_command="\n".join(["nginx -t", _build_service_control_command("reload", "nginx", allow_missing=True)]),
            )
    if service_name == "vsftpd":
        if config_key == "anonymous_enabled":
            return _build_replace_or_append_command(
                source_files=source_files,
                directive="anonymous_enable",
                value="NO",
                validate_command=None,
                service_command=_build_service_control_command("restart", "vsftpd", allow_missing=True),
            )
        if config_key == "anonymous_write_enabled":
            return "\n".join(
                [
                    _build_replace_or_append_command(
                        source_files=source_files,
                        directive="write_enable",
                        value="NO",
                        validate_command=None,
                        service_command=None,
                    ),
                    _build_replace_or_append_command(
                        source_files=source_files,
                        directive="anon_upload_enable",
                        value="NO",
                        validate_command=None,
                        service_command=None,
                    ),
                    _build_replace_or_append_command(
                        source_files=source_files,
                        directive="anon_mkdir_write_enable",
                        value="NO",
                        validate_command=None,
                        service_command=_build_service_control_command("restart", "vsftpd", allow_missing=True),
                    ),
                ]
            )
    if service_name == "samba":
        if (
            config_key in {"writable_guest_share", "guest_access", "weak_authentication"}
            or "writable_guest_share" in normalized_rule_id
            or "guest.access" in normalized_rule_id
            or "anonymous_share" in normalized_rule_id
        ):
            parts = [
                _build_comment_out_regex_command(
                    source_files=source_files,
                    pattern=r"^\s*(guest ok|guest only|public|writ(?:e)?able)\s*=\s*yes\b.*$",
                    validate_command=None,
                    service_command=None,
                ),
                _build_ini_section_directive_command(
                    source_files=source_files,
                    section_name="global",
                    directives={"map to guest": "Never"},
                    validate_command=None,
                    service_command=_build_service_control_command("restart", "samba", allow_missing=True),
                ),
            ]
            return "\n".join(part for part in parts if part).strip()
    if service_name == "tomcat" and "manager" in normalized_rule_id:
        return _build_tomcat_manager_disable_command()
    return ""


def _render_network_command(*, service_name: str, config_key: str, rule_id: str, target_scope: str, source_files: list[str]) -> str:
    normalized_rule_id = rule_id.lower()
    if service_name == "mysql":
        return _render_config_command(service_name=service_name, config_key="bind_all_interfaces", target_value="127.0.0.1", source_files=source_files)
    if service_name == "redis":
        if config_key in {"bind_all_interfaces", "requirepass", ""} or "unauthorized" in normalized_rule_id or "auth" in normalized_rule_id:
            return "\n".join(
                [
                    _render_config_command(service_name="redis", config_key="bind_all_interfaces", target_value=True, source_files=source_files),
                    _render_config_command(service_name="redis", config_key="protected_mode", target_value=True, source_files=source_files),
                ]
            ).strip()
    if service_name == "postgresql":
        if config_key in {"listen_all_interfaces", "trust_auth_enabled", ""} or "trust" in normalized_rule_id:
            parts = [
                _render_config_command(service_name="postgresql", config_key="listen_all_interfaces", target_value=False, source_files=source_files),
            ]
            trust_cmd = _render_config_command(service_name="postgresql", config_key="trust_auth_enabled", target_value=False, source_files=source_files)
            if trust_cmd:
                parts.append(trust_cmd)
            return "\n".join([part for part in parts if part]).strip()
    if service_name == "docker" and (config_key == "tcp_listener_without_tlsverify" or "docker" in normalized_rule_id):
        return _build_docker_remove_tcp_listener_command(source_files)
    if service_name == "samba" and target_scope == "admin_segment_only":
        return _build_ini_section_directive_command(
            source_files=source_files,
            section_name="global",
            directives={
                "hosts allow": "127.0.0.1 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7",
                "hosts deny": "0.0.0.0/0 ::/0",
            },
            validate_command=None,
            service_command=_build_service_control_command("restart", "samba", allow_missing=True),
        )
    if service_name in {"apache", "nginx", "http", "https", "tomcat", "php", "phpmyadmin", "twiki"} and target_scope == "admin_segment_only":
        web_service = service_name
        if service_name in {"http", "https", "php", "phpmyadmin", "twiki"}:
            web_service = "apache"
        return _render_exposure_command(service_name=web_service, config_key=config_key, rule_id=rule_id, source_files=source_files)
    return ""


def _build_replace_or_append_command(*, source_files: list[str], directive: str, value: str, validate_command: str | None, service_command: str | None) -> str:
    return _build_legacy_python_file_command(
        source_files=source_files,
        imports="codecs, os, re, sys",
        script_lines=[
            f"directive = {directive!r}",
            f"value = {value!r}",
            "pattern = re.compile(r'(?im)^\\s*#?\\s*' + re.escape(directive) + r'\\b[^\\n]*$')",
            "replacement = '%s %s' % (directive, value)",
            "for raw_path in sys.argv[1:]:",
            "    text = _read_text(raw_path)",
            "    if pattern.search(text):",
            "        text = pattern.sub(replacement, text)",
            "    else:",
            "        if text and not text.endswith('\\n'):",
            "            text += '\\n'",
            "        text += replacement + '\\n'",
            "    _write_text(raw_path, text)",
        ],
        validate_command=validate_command,
        service_command=service_command,
    )


def _build_remove_regex_command(*, source_files: list[str], pattern: str, service_command: str | None) -> str:
    return _build_legacy_python_file_command(
        source_files=source_files,
        imports="codecs, os, re, sys",
        script_lines=[
            f"pattern = re.compile({pattern!r}, re.IGNORECASE)",
            "for raw_path in sys.argv[1:]:",
            "    if not os.path.exists(raw_path):",
            "        continue",
            "    kept = []",
            "    for line in _read_text(raw_path).splitlines():",
            "        if pattern.search(line):",
            "            continue",
            "        kept.append(line)",
            "    text = '\\n'.join(kept)",
            "    if text and not text.endswith('\\n'):",
            "        text += '\\n'",
            "    _write_text(raw_path, text)",
        ],
        service_command=service_command,
    )


def _build_comment_out_regex_command(
    *,
    source_files: list[str],
    pattern: str,
    validate_command: str | None,
    service_command: str | None,
) -> str:
    return _build_legacy_python_file_command(
        source_files=source_files,
        imports="codecs, os, re, sys",
        script_lines=[
            f"pattern = re.compile({pattern!r}, re.IGNORECASE)",
            "for raw_path in sys.argv[1:]:",
            "    if not os.path.exists(raw_path):",
            "        continue",
            "    rendered = []",
            "    for line in _read_text(raw_path).splitlines():",
            "        stripped = line.lstrip()",
            "        if stripped.startswith('#') or stripped.startswith(';'):",
            "            rendered.append(line)",
            "            continue",
            "        if pattern.search(line):",
            "            rendered.append('# managed-by-sa ' + line)",
            "            continue",
            "        rendered.append(line)",
            "    text = '\\n'.join(rendered)",
            "    if text and not text.endswith('\\n'):",
            "        text += '\\n'",
            "    _write_text(raw_path, text)",
        ],
        validate_command=validate_command,
        service_command=service_command,
    )


def _build_ini_section_directive_command(
    *,
    source_files: list[str],
    section_name: str,
    directives: dict[str, str],
    validate_command: str | None,
    service_command: str | None,
) -> str:
    return _build_legacy_python_file_command(
        source_files=source_files,
        imports="codecs, os, re, sys",
        script_lines=[
            f"section_name = {section_name!r}.strip().lower()",
            f"directives = {directives!r}",
            "directive_keys = {}",
            "for key in directives:",
            "    directive_keys[str(key).lower()] = key",
            "section_pattern = re.compile(r'^\\s*\\[([^\\]]+)\\]\\s*$')",
            "kv_pattern = re.compile(r'^\\s*[#;]?\\s*([^=]+?)\\s*=.*$')",
            "for raw_path in sys.argv[1:]:",
            "    text = _read_text(raw_path)",
            "    rendered = text.splitlines()",
            "    start = None",
            "    end = None",
            "    for index, line in enumerate(rendered):",
            "        match = section_pattern.match(line)",
            "        if not match:",
            "            continue",
            "        normalized_section = match.group(1).strip().lower()",
            "        if start is None and normalized_section == section_name:",
            "            start = index",
            "            continue",
            "        if start is not None:",
            "            end = index",
            "            break",
            "    if start is None:",
            "        if rendered and rendered[-1].strip():",
            "            rendered.append('')",
            "        rendered.append('[%s]' % section_name)",
            "        for key in directives:",
            "            rendered.append('%s = %s' % (key, directives[key]))",
            "    else:",
            "        if end is None:",
            "            end = len(rendered)",
            "        section_lines = rendered[start + 1:end]",
            "        updated_section = []",
            "        seen = {}",
            "        for line in section_lines:",
            "            match = kv_pattern.match(line)",
            "            if match:",
            "                raw_key = match.group(1).strip().lower()",
            "                if raw_key in directive_keys:",
            "                    if raw_key in seen:",
            "                        continue",
            "                    display_key = directive_keys[raw_key]",
            "                    updated_section.append('%s = %s' % (display_key, directives[display_key]))",
            "                    seen[raw_key] = True",
            "                    continue",
            "            updated_section.append(line)",
            "        for display_key in directives:",
            "            normalized_key = str(display_key).lower()",
            "            if normalized_key in seen:",
            "                continue",
            "            updated_section.append('%s = %s' % (display_key, directives[display_key]))",
            "        rendered = rendered[: start + 1] + updated_section + rendered[end:]",
            "    output = '\\n'.join(rendered)",
            "    if output and not output.endswith('\\n'):",
            "        output += '\\n'",
            "    _write_text(raw_path, output)",
        ],
        validate_command=validate_command,
        service_command=service_command,
    )


def _pick_matching_source_files(source_files: list[str], suffix: str) -> list[str]:
    matched = [path for path in source_files if path.endswith(suffix)]
    return matched or source_files


def _build_tomcat_manager_disable_command() -> str:
    return "\n".join(
        [
            "dirs=$(find /var/lib /usr/share /opt -maxdepth 5 -type d \\( -path '*/tomcat*/webapps/manager' -o -path '*/apache-tomcat*/webapps/manager' -o -path '*/tomcat/webapps/manager' \\) 2>/dev/null || true)",
            "if [ -z \"$dirs\" ]; then echo '未找到 Tomcat manager 目录' >&2; exit 1; fi",
            "printf '%s\n' \"$dirs\" | while IFS= read -r dir; do",
            "  [ -d \"$dir\" ] || continue",
            "  mv \"$dir\" \"${dir}.disabled.sa\"",
            "done",
            _build_service_control_command("restart", "tomcat", allow_missing=True),
        ]
    )


def _build_remove_path_command(paths: list[str], *, service_command: str | None) -> str:
    lines = [
        "set -e",
    ]
    for raw_path in paths:
        path = str(raw_path).strip()
        if not path:
            continue
        quoted = shlex.quote(path)
        lines.extend(
            [
                f"if [ -e {quoted} ]; then",
                f"  mv {quoted} {shlex.quote(path + '.disabled.sa')}",
                "fi",
            ]
        )
    if service_command:
        lines.append(service_command)
    return "\n".join(lines)


def _build_docker_remove_tcp_listener_command(source_files: list[str]) -> str:
    json_files = [path for path in source_files if path.endswith("daemon.json")]
    if json_files:
        return _build_legacy_python_file_command(
            source_files=json_files,
            imports="codecs, os, sys",
            script_lines=[
                "try:",
                "    import json",
                "except ImportError:",
                "    import simplejson as json",
                "for raw_path in sys.argv[1:]:",
                "    if not os.path.exists(raw_path):",
                "        continue",
                "    content = _read_text(raw_path).strip()",
                "    if content:",
                "        try:",
                "            data = json.loads(content)",
                "        except Exception:",
                "            raise SystemExit('docker daemon.json 不是合法 JSON')",
                "    else:",
                "        data = {}",
                "    hosts = data.get('hosts') or []",
                "    if isinstance(hosts, list):",
                "        filtered = []",
                "        for item in hosts:",
                "            if str(item).lower().startswith('tcp://'):",
                "                continue",
                "            filtered.append(item)",
                "        data['hosts'] = filtered or ['unix:///var/run/docker.sock']",
                "    _write_text(raw_path, json.dumps(data, indent=2) + '\\n')",
            ],
            service_command=_build_service_control_command("restart", "docker", allow_missing=True),
        )
    systemd_files = [path for path in source_files if path.endswith("docker.service")]
    if systemd_files:
        return _build_remove_regex_command(
            source_files=systemd_files,
            pattern=r"tcp://[^\s]+",
            service_command="\n".join(["systemctl daemon-reload", _build_service_control_command("restart", "docker", allow_missing=True)]),
        )
    return ""


def _render_permission_command(
    *,
    rule_id: str,
    host_checks: dict[str, Any],
    config_by_service: dict[str, dict[str, Any]],
    excluded_suid_binaries: set[str] | None = None,
) -> tuple[str, list[str]]:
    excluded = {
        str(item).strip().lower()
        for item in (excluded_suid_binaries or set())
        if str(item).strip()
    }
    if rule_id == "linux-host.suid.nmap.present":
        if "nmap" in excluded:
            return "", []
        path = str(((host_checks.get("nmap_local") or {}) if isinstance(host_checks.get("nmap_local"), dict) else {}).get("binary_path") or "").strip()
        if not path:
            return "", []
        return _build_remove_special_permission_bits_command([path]), [path]
    if rule_id == "nmap.legacy_interactive_privesc.exposed":
        if "nmap" in excluded:
            return "", []
        path = str(((host_checks.get("nmap_local") or {}) if isinstance(host_checks.get("nmap_local"), dict) else {}).get("binary_path") or "").strip()
        if not path:
            return "", []
        return _build_remove_special_permission_bits_command([path]), [path]
    if rule_id == "linux-host.suid.screen.present":
        if "screen" in excluded:
            return "", []
        path = str(((host_checks.get("screen_local") or {}) if isinstance(host_checks.get("screen_local"), dict) else {}).get("binary_path") or "").strip()
        if not path:
            return "", []
        return _build_remove_special_permission_bits_command([path]), [path]
    if rule_id == "linux-host.dangerous_suid.present":
        paths = _actionable_dangerous_suid_paths(
            host_checks,
            excluded_suid_binaries=excluded,
        )
        deduped_paths = list(dict.fromkeys(paths))
        if not deduped_paths:
            return "", []
        return _build_remove_special_permission_bits_command(deduped_paths), deduped_paths
    if rule_id == "cron.root_writable_job_chain.exposed":
        cron_local = host_checks.get("cron_local") if isinstance(host_checks.get("cron_local"), dict) else {}
        sample_entries = cron_local.get("sample") if isinstance(cron_local.get("sample"), list) else []
        targets = [
            str(item.get("path") or "").strip()
            for item in sample_entries
            if isinstance(item, dict) and str(item.get("path") or "").strip()
        ]
        deduped_targets = list(dict.fromkeys(targets))
        if not deduped_targets:
            return "", []
        return _build_remove_group_world_write_command(deduped_targets), deduped_targets
    if rule_id == "polkit.rules_path.writable.exposed":
        polkit_config = config_by_service.get("polkit", {})
        paths = [str(item).strip() for item in polkit_config.get("writable_rules_paths", []) if str(item).strip()]
        if not paths:
            paths = [str(item).strip() for item in polkit_config.get("rules_paths", []) if str(item).strip()]
        if not paths:
            return "", []
        command = _build_remove_group_world_write_command(paths)
        return command, paths
    return "", []


def _build_remove_special_permission_bits_command(paths: list[str]) -> str:
    return "\n".join([f"chmod a-s {shlex.quote(path)}" for path in paths if str(path).strip()])


def _build_remove_group_world_write_command(paths: list[str]) -> str:
    lines: list[str] = []
    for raw_path in paths:
        path = str(raw_path).strip()
        if not path:
            continue
        quoted = shlex.quote(path)
        lines.append(f'if [ -e {quoted} ]; then chmod go-w {quoted}; fi')
    return "\n".join(lines)


def _merge_string_lists(*groups: Any) -> list[str]:
    merged: list[str] = []
    for group in groups:
        if not isinstance(group, list):
            continue
        for item in group:
            normalized = str(item or "").strip()
            if normalized and normalized not in merged:
                merged.append(normalized)
    return merged
