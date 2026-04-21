from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.db.models.asset import Asset, AssetPort
from app.db.models.enums import FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding
from app.db.models.snapshot import HostSnapshot
from app.rules.rule_engine import RuleEngine
from app.services.risk_verification_service import RiskVerificationService
from app.verifiers.base import VerificationResult


@pytest.fixture(autouse=True)
def _stub_device_alert_publish(monkeypatch):
    monkeypatch.setattr("app.services.risk_verification_service.publish_device_abnormal_alert", lambda event: None)


class _FakeDB:
    def __init__(self, asset):
        self.asset = asset
        self.added = []
        self.executed = []
        self.committed = False

    def get(self, model, asset_id):
        return self.asset if self.asset.id == asset_id else None

    def execute(self, stmt):
        self.executed.append(stmt)

    def add(self, item):
        self.added.append(item)

    def commit(self):
        self.committed = True


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def _build_asset(
    service_name: str,
    service_version: str,
    *,
    config: dict | None = None,
    nse: dict | None = None,
) -> Asset:
    normalized_service = "vsftpd" if "vsftpd" in service_version.lower() else service_name
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {normalized_service: config or {}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-1", ip="10.0.0.10")
    asset.ports = [
        AssetPort(
            id="port-1",
            asset_id="asset-1",
            port=21 if service_name == "vsftpd" else 8080,
            protocol="tcp",
            service_name=service_name,
            service_version=service_version,
            fingerprint_json={"banner": service_version, "nse": nse or {}},
        )
    ]
    asset.snapshots = [snapshot]
    asset.findings = []
    return asset


def _existing_finding(
    *,
    rule_id: str,
    asset_id: str = "asset-1",
    asset_port_id: str = "port-1",
    title: str = "existing finding",
    severity: RiskSeverity = RiskSeverity.CRITICAL,
) -> RiskFinding:
    return RiskFinding(
        id="finding-existing-1",
        asset_id=asset_id,
        asset_port_id=asset_port_id,
        yaml_rule_id=rule_id,
        severity=severity,
        status=FindingStatus.OPEN,
        title=title,
        description="existing description",
        evidence_json={
            "yaml_rule_id": rule_id,
            "evidence_scope": "network",
            "match_source": "active_only",
            "verification_status": "confirmed",
            "verification_summary": "历史确认",
            "service_name": "vsftpd",
            "port": 21,
        },
    )


def test_risk_verification_service_confirms_on_passive_match(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: vsftpd.backdoor.2_3_4
    name: vsftpd backdoor
    enabled: true
    service: vsftpd
    severity: critical
    description: vsftpd backdoor
    match:
      version: ==2.3.4
    active_check:
      detector: vsftpd_smiley_backdoor
      trigger: on_passive_match
      timeout_seconds: 5
      params: {}
""",
        encoding="utf-8",
    )
    asset = _build_asset("ftp", "vsftpd 2.3.4")
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="confirmed", summary="命中 marker", detector=context.rule.active_check.detector, evidence={"marker": "ok"})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.created_finding_count == 1
    assert summary.active_confirmed_count == 1
    assert db.committed is True
    assert db.added[0].evidence_json["verification_status"] == "confirmed"
    assert db.added[0].evidence_json["match_source"] == "active"


def test_risk_verification_service_keeps_passive_match_when_active_check_rejects(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: vsftpd.backdoor.2_3_4
    name: vsftpd backdoor
    enabled: true
    service: vsftpd
    severity: critical
    description: vsftpd backdoor
    match:
      version: ==2.3.4
    active_check:
      detector: vsftpd_smiley_backdoor
      trigger: on_passive_match
      timeout_seconds: 5
      params: {}
""",
        encoding="utf-8",
    )
    asset = _build_asset("ftp", "vsftpd 2.3.4")
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="rejected", summary="未发现后门", detector=context.rule.active_check.detector, evidence={})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.created_finding_count == 1
    assert summary.active_rejected_count == 1
    assert db.added[0].evidence_json["verification_status"] == "rejected"
    assert db.added[0].evidence_json["match_source"] == "passive"


def test_risk_verification_service_creates_on_service_present_confirmation(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ftp.anonymous.enabled
    name: ftp anonymous
    enabled: true
    service: vsftpd
    severity: high
    description: anonymous ftp
    match:
      config:
        anonymous_enabled:
          eq: true
    active_check:
      detector: ftp_anonymous_login
      trigger: on_service_present
      timeout_seconds: 5
      params: {}
""",
        encoding="utf-8",
    )
    asset = _build_asset("ftp", "vsftpd 2.3.4", config={"anonymous_enabled": False})
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="confirmed", summary="匿名登录成功", detector=context.rule.active_check.detector, evidence={})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 0
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["verification_status"] == "confirmed"
    assert db.added[0].evidence_json["match_source"] == "active_only"


def test_risk_verification_service_upserts_existing_finding_instead_of_creating_duplicate(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: redis.legacy.lt_3_2
    name: redis legacy
    enabled: true
    service: redis
    severity: high
    description: legacy redis
    match:
      version: <3.2
""",
        encoding="utf-8",
    )
    asset = _build_asset("redis", "redis 2.8.24")
    existing = RiskFinding(
        id="finding-existing-1",
        asset_id="asset-1",
        asset_port_id="port-1",
        yaml_rule_id="redis.legacy.lt_3_2",
        severity=RiskSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="legacy redis old title",
        description="old description",
        evidence_json={
            "yaml_rule_id": "redis.legacy.lt_3_2",
            "evidence_scope": "network",
            "match_source": "passive",
            "verification_status": "skipped",
            "service_name": "redis",
            "port": 8080,
        },
    )
    asset.findings = [existing]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.created_finding_count == 1
    assert db.added == []
    assert existing.id == "finding-existing-1"
    assert existing.title == "redis legacy"
    assert existing.description == "legacy redis"
    assert existing.status == FindingStatus.OPEN
    assert existing.resolved_at is None


def test_risk_verification_service_marks_missing_finding_fixed_instead_of_deleting(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    asset = _build_asset("redis", "redis 7.0.0")
    existing = RiskFinding(
        id="finding-existing-1",
        asset_id="asset-1",
        asset_port_id="port-1",
        yaml_rule_id="redis.legacy.lt_3_2",
        severity=RiskSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="legacy redis",
        description="legacy redis",
        evidence_json={
            "yaml_rule_id": "redis.legacy.lt_3_2",
            "evidence_scope": "network",
            "match_source": "passive",
            "verification_status": "confirmed",
            "service_name": "redis",
            "port": 8080,
        },
    )
    asset.findings = [existing]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.created_finding_count == 0
    assert db.added == []
    assert existing.status == FindingStatus.FIXED
    assert existing.resolved_at is not None


def test_risk_verification_service_preserves_active_only_finding_on_rejected_probe(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ftp.anonymous.enabled
    name: ftp anonymous
    enabled: true
    service: vsftpd
    severity: high
    description: anonymous ftp
    match:
      config:
        anonymous_enabled:
          eq: true
    active_check:
      detector: ftp_anonymous_login
      trigger: on_service_present
      timeout_seconds: 5
      params: {}
""",
        encoding="utf-8",
    )
    asset = _build_asset("ftp", "vsftpd 2.3.4", config={"anonymous_enabled": False})
    existing = _existing_finding(rule_id="ftp.anonymous.enabled", title="ftp anonymous")
    asset.findings = [existing]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="rejected", summary="匿名登录失败", detector=context.rule.active_check.detector, evidence={})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.created_finding_count == 0
    assert db.added == []
    assert existing.status == FindingStatus.OPEN
    assert existing.resolved_at is None
    assert existing.evidence_json["verification_status"] == "rejected"
    assert existing.evidence_json["match_source"] == "active_only"


def test_risk_verification_service_falls_back_to_package_version(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: redis.legacy.lt_3_2
    name: redis legacy
    enabled: true
    service: redis
    severity: high
    description: legacy redis
    match:
      version: <3.2
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"redis": {}}},
        software_json={"packages": [{"name": "redis-server", "version": "2.8.24"}]},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-1", ip="10.0.0.10")
    asset.ports = [
        AssetPort(
            id="port-1",
            asset_id="asset-1",
            port=6379,
            protocol="tcp",
            service_name="redis",
            service_version=None,
            fingerprint_json={"banner": "redis"},
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["service_version"] == "2.8.24"


def test_risk_verification_service_supports_authorized_local_kernel_and_host_config(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: linux-kernel.legacy.lt_3_10
    name: Linux 内核遗留版本暴露
    enabled: true
    service: linux-kernel
    severity: high
    description: legacy kernel
    match:
      version: <3.10
  - id: sudo.nopasswd.enabled
    name: sudo 存在免密授权
    enabled: true
    service: sudo
    severity: high
    description: sudo nopasswd
    match:
      config:
        nopasswd_present:
          eq: true
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-local-1",
        kernel_version="2.6.24",
        services_json={"config_by_service": {"sudo": {"nopasswd_present": True}, "linux-host": {}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-local-1", ip="10.0.0.50")
    asset.ports = [
        AssetPort(
            id="port-ssh-1",
            asset_id="asset-local-1",
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version="OpenSSH 4.7",
            fingerprint_json={
                "service_aliases": ["ssh", "linux-kernel", "sudo", "linux-host"],
                "authorization_scope": "authorized_local",
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-local-1")

    assert summary.created_finding_count == 2
    assert {item.evidence_json["yaml_rule_id"] for item in db.added} == {
        "linux-kernel.legacy.lt_3_10",
        "sudo.nopasswd.enabled",
    }
    assert all(item.evidence_json["evidence_scope"] == "authorized_local" for item in db.added)


def test_risk_verification_service_matches_authorized_local_privesc_v2_rules(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: nmap.legacy_interactive_privesc.exposed
    name: nmap legacy
    enabled: true
    service: nmap
    severity: critical
    description: nmap legacy
    match:
      version: <5.21
      config:
        suid_present:
          eq: true
  - id: screen.legacy_setuid_privesc.exposed
    name: screen legacy
    enabled: true
    service: screen
    severity: critical
    description: screen legacy
    match:
      version: ==4.5.0
      config:
        suid_present:
          eq: true
  - id: docker.socket.exposed
    name: docker socket
    enabled: true
    service: docker
    severity: critical
    description: docker socket
    match:
      config:
        socket_present:
          eq: true
  - id: linux-host.privileged_runtime_group.membership
    name: runtime group
    enabled: true
    service: linux-host
    severity: high
    description: runtime group
    match:
      config:
        privileged_runtime_group_membership_present:
          eq: true
  - id: systemd.writable_unit_chain.exposed
    name: systemd writable
    enabled: true
    service: systemd
    severity: high
    description: systemd writable
    match:
      config:
        writable_unit_chain_present:
          eq: true
  - id: cron.root_writable_job_chain.exposed
    name: cron writable
    enabled: true
    service: cron
    severity: high
    description: cron writable
    match:
      config:
        root_writable_job_chain_present:
          eq: true
  - id: logrotate.writable_script_chain.exposed
    name: logrotate writable
    enabled: true
    service: logrotate
    severity: high
    description: logrotate writable
    match:
      config:
        writable_script_chain_present:
          eq: true
  - id: linux-host.suid.nmap.present
    name: suid nmap
    enabled: true
    service: linux-host
    severity: high
    description: suid nmap
    match:
      config:
        dangerous_suid_by_binary.nmap:
          eq: true
  - id: linux-host.suid.screen.present
    name: suid screen
    enabled: true
    service: linux-host
    severity: high
    description: suid screen
    match:
      config:
        dangerous_suid_by_binary.screen:
          eq: true
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-local-v2",
        services_json={
            "config_by_service": {
                "nmap": {"suid_present": True},
                "screen": {"suid_present": True},
                "docker": {"socket_present": True},
                "systemd": {"writable_unit_chain_present": True},
                "cron": {"root_writable_job_chain_present": True},
                "logrotate": {"writable_script_chain_present": True},
                "linux-host": {
                    "privileged_runtime_group_membership_present": True,
                    "dangerous_suid_by_binary": {"nmap": True, "screen": True},
                },
            }
        },
        software_json={
            "packages": [
                {"name": "nmap", "version": "1:5.20-1ubuntu1"},
                {"name": "screen", "version": "4.5.0-1"},
            ]
        },
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-local-v2", ip="10.0.0.60")
    asset.ports = [
        AssetPort(
            id="port-ssh-v2",
            asset_id="asset-local-v2",
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version="OpenSSH 7.2p2",
            fingerprint_json={
                "service_aliases": [
                    "ssh",
                    "linux-host",
                    "nmap",
                    "screen",
                    "docker",
                    "systemd",
                    "cron",
                    "logrotate",
                ],
                "authorization_scope": "authorized_local",
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-local-v2")

    assert summary.created_finding_count == 9
    assert {item.evidence_json["yaml_rule_id"] for item in db.added} == {
        "nmap.legacy_interactive_privesc.exposed",
        "screen.legacy_setuid_privesc.exposed",
        "docker.socket.exposed",
        "linux-host.privileged_runtime_group.membership",
        "systemd.writable_unit_chain.exposed",
        "cron.root_writable_job_chain.exposed",
        "logrotate.writable_script_chain.exposed",
        "linux-host.suid.nmap.present",
        "linux-host.suid.screen.present",
    }


def test_risk_verification_service_matches_high_value_config_gap_rules(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: sudo.setenv.enabled
    name: sudo setenv
    enabled: true
    service: sudo
    severity: high
    description: sudo setenv
    match:
      config:
        setenv_present:
          eq: true
  - id: sudo.dangerous_env_keep.enabled
    name: sudo env_keep
    enabled: true
    service: sudo
    severity: high
    description: sudo env_keep
    match:
      config:
        dangerous_env_keep_present:
          eq: true
  - id: polkit.rules_path.writable.exposed
    name: polkit writable
    enabled: true
    service: polkit
    severity: high
    description: polkit writable
    match:
      config:
        writable_rules_path_present:
          eq: true
  - id: docker.remote_api.tcp_no_tls.exposed
    name: docker tcp no tls
    enabled: true
    service: docker
    severity: critical
    description: docker tcp no tls
    match:
      config:
        tcp_listener_without_tlsverify:
          eq: true
  - id: ssh.permit_empty_passwords.enabled
    name: ssh empty password
    enabled: true
    service: ssh
    severity: critical
    description: ssh empty password
    match:
      config:
        permit_empty_passwords:
          eq: true
  - id: mysql.skip_grant_tables.enabled
    name: mysql skip grant
    enabled: true
    service: mysql
    severity: critical
    description: mysql skip grant
    match:
      config:
        skip_grant_tables:
          eq: true
  - id: mysql.local_infile.enabled
    name: mysql local infile
    enabled: true
    service: mysql
    severity: high
    description: mysql local infile
    match:
      config:
        local_infile:
          eq: true
  - id: mysql.bind_all_interfaces.enabled
    name: mysql bind all
    enabled: true
    service: mysql
    severity: high
    description: mysql bind all
    match:
      config:
        bind_all_interfaces:
          eq: true
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-config-gap",
        services_json={
            "config_by_service": {
                "ssh": {"permit_empty_passwords": True},
                "sudo": {"setenv_present": True, "dangerous_env_keep_present": True},
                "polkit": {"writable_rules_path_present": True},
                "docker": {"tcp_listener_without_tlsverify": True},
                "mysql": {
                    "skip_grant_tables": True,
                    "local_infile": True,
                    "bind_all_interfaces": True,
                },
            }
        },
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-config-gap", ip="10.0.0.61")
    asset.ports = [
        AssetPort(
            id="port-ssh-gap",
            asset_id="asset-config-gap",
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version="OpenSSH 8.2",
            fingerprint_json={
                "service_aliases": ["ssh", "sudo", "polkit", "docker"],
                "authorization_scope": "authorized_local",
            },
        ),
        AssetPort(
            id="port-mysql-gap",
            asset_id="asset-config-gap",
            port=3306,
            protocol="tcp",
            service_name="mysql",
            service_version="8.0.36",
            fingerprint_json={"banner": "mysql"},
        ),
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-config-gap")

    assert summary.passive_match_count == 8
    assert summary.created_finding_count == 8
    assert {item.evidence_json["yaml_rule_id"] for item in db.added} == {
        "sudo.setenv.enabled",
        "sudo.dangerous_env_keep.enabled",
        "polkit.rules_path.writable.exposed",
        "docker.remote_api.tcp_no_tls.exposed",
        "ssh.permit_empty_passwords.enabled",
        "mysql.skip_grant_tables.enabled",
        "mysql.local_infile.enabled",
        "mysql.bind_all_interfaces.enabled",
    }
    host_rule_ids = {
        "sudo.setenv.enabled",
        "sudo.dangerous_env_keep.enabled",
        "polkit.rules_path.writable.exposed",
        "docker.remote_api.tcp_no_tls.exposed",
        "ssh.permit_empty_passwords.enabled",
    }
    assert all(
        item.evidence_json["evidence_scope"] == "authorized_local"
        for item in db.added
        if item.evidence_json["yaml_rule_id"] in host_rule_ids
    )


def test_risk_verification_service_prefers_fingerprint_application_and_version(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: nginx.version.lt_1_18
    name: nginx 低版本暴露
    enabled: true
    service: nginx
    severity: high
    description: nginx legacy
    match:
      version: <1.18
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"nginx": {}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-1", ip="10.0.0.20")
    asset.ports = [
        AssetPort(
            id="port-1",
            asset_id="asset-1",
            port=8080,
            protocol="tcp",
            service_name="http",
            service_version=None,
            fingerprint_json={
                "application_service": "nginx",
                "product_name": "nginx",
                "product_version": "1.16.1",
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.16.1\r\n\r\n",
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["service_name"] == "nginx"
    assert db.added[0].evidence_json["service_version"] == "1.16.1"


def test_risk_verification_service_matches_nse_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ftp.anonymous.nse.enabled
    name: FTP 匿名访问开启
    enabled: true
    service: vsftpd
    severity: high
    description: FTP 支持匿名访问
    match:
      nse:
        ftp-anon.hit:
          eq: true
        ftp-anon.anonymous_allowed:
          eq: true
""",
        encoding="utf-8",
    )
    asset = _build_asset(
        "ftp",
        "vsftpd 2.3.4",
        nse={
            "ftp-anon": {
                "hit": True,
                "anonymous_allowed": True,
                "summary": "Anonymous FTP login allowed",
                "listing": ["pub"],
            }
        },
    )
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["nse_match"] is True
    assert db.added[0].evidence_json["passive_match_types"] == ["nse"]
    assert db.added[0].evidence_json["nse_scripts"] == ["ftp-anon"]
    assert db.added[0].evidence_json["nse_evidence"]["ftp-anon"]["anonymous_allowed"] is True


def test_risk_verification_service_creates_active_only_finding_for_redis_probe(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: redis.unauthorized.info.confirmed
    name: Redis 未授权 INFO 可用
    enabled: true
    service: redis
    severity: critical
    description: redis unauth info
    match:
      nse:
        redis-info.redis_version:
          exists: true
    active_check:
      detector: redis_unauth_info_probe
      trigger: on_service_present
      timeout_seconds: 5
      params: {}
""",
        encoding="utf-8",
    )
    asset = _build_asset("redis", "redis 7.0.0")
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="confirmed", summary="Redis 未授权 INFO 可用", detector=context.rule.active_check.detector, evidence={"ping_response": "+PONG"})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 0
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["verification_status"] == "confirmed"
    assert db.added[0].evidence_json["active_detector"] == "redis_unauth_info_probe"


def test_risk_verification_service_confirms_webdav_risky_methods_rule(tmp_path, monkeypatch) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: apache.webdav.risky_methods.confirmed
    name: Apache WebDAV 风险方法暴露
    enabled: true
    service: apache
    severity: critical
    description: webdav risky methods
    match:
      config:
        webdav_enabled:
          eq: true
      nse:
        http-methods.risky_methods:
          contains: PUT
    active_check:
      detector: http_risky_methods_probe
      trigger: on_passive_match
      timeout_seconds: 5
      params:
        path: /
""",
        encoding="utf-8",
    )
    asset = _build_asset(
        "apache",
        "Apache httpd 2.4.58",
        config={"webdav_enabled": True},
        nse={"http-methods": {"hit": True, "risky_methods": ["PUT", "DELETE"], "summary": "检测到风险方法：PUT, DELETE"}},
    )
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    async def _verifier(context):
        return VerificationResult(status="confirmed", summary="HTTP 服务暴露风险方法", detector=context.rule.active_check.detector, evidence={"confirmed_methods": ["PUT"]})

    monkeypatch.setattr("app.services.risk_verification_service.get_verifier", lambda detector: _verifier)

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.active_confirmed_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["nse_scripts"] == ["http-methods"]
    assert db.added[0].evidence_json["match_source"] == "active"


def test_risk_verification_service_attaches_hit_nse_evidence_for_legacy_rule(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: vsftpd.backdoor.2_3_4
    name: vsftpd 后门版本
    enabled: true
    service: vsftpd
    severity: critical
    description: vsftpd 2.3.4 后门版本
    match:
      version: ==2.3.4
""",
        encoding="utf-8",
    )
    asset = _build_asset(
        "ftp",
        "vsftpd 2.3.4",
        nse={
            "ftp-vsftpd-backdoor": {
                "hit": True,
                "vulnerable": True,
                "summary": "命中漏洞特征：后门响应可用",
            },
            "ftp-syst": {
                "hit": False,
                "summary": "UNIX Type: L8",
            },
        },
    )
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["nse_match"] is False
    assert db.added[0].evidence_json["nse_scripts"] == ["ftp-vsftpd-backdoor"]
    assert db.added[0].evidence_json["nse_evidence"]["ftp-vsftpd-backdoor"]["vulnerable"] is True


def test_risk_verification_service_matches_ftp_rule_via_vsftpd_alias(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ftp.legacy.lt_3
    name: FTP 低版本暴露
    enabled: true
    service: ftp
    severity: high
    description: ftp legacy
    match:
      version: <3.0
""",
        encoding="utf-8",
    )
    asset = _build_asset("vsftpd", "vsftpd 2.3.4")
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["service_name"] == "ftp"
    assert db.added[0].evidence_json["service_version"] == "2.3.4"


def test_risk_verification_service_matches_apache_and_php_rules_via_phpmyadmin_aliases(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache 低版本暴露
    enabled: true
    service: apache
    severity: high
    description: apache legacy
    match:
      version: <2.2.9
  - id: php.legacy.lt_5_2_5
    name: PHP 低版本暴露
    enabled: true
    service: php
    severity: high
    description: php legacy
    match:
      version: <5.2.5
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"phpmyadmin": {}, "apache": {}, "php": {}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-1", ip="10.0.0.30")
    asset.ports = [
        AssetPort(
            id="port-1",
            asset_id="asset-1",
            port=80,
            protocol="tcp",
            service_name="phpmyadmin",
            service_version="4.0.10",
            fingerprint_json={
                "application_service": "phpmyadmin",
                "product_name": "phpmyadmin",
                "product_version": "4.0.10",
                "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.2.8\r\nX-Powered-By: PHP/5.2.4\r\n\r\n",
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 2
    assert summary.created_finding_count == 2
    findings = {item.evidence_json["service_name"]: item.evidence_json["service_version"] for item in db.added}
    assert findings["apache"] == "2.2.8"
    assert findings["php"] == "5.2.4"


def test_risk_verification_service_matches_tomcat_rule_via_nse_aliases(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: tomcat.legacy.lte_5_5_20
    name: Tomcat 低版本暴露
    enabled: true
    service: tomcat
    severity: high
    description: tomcat legacy
    match:
      version: <=5.5.20
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"tomcat": {}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-1", ip="10.0.0.40")
    asset.ports = [
        AssetPort(
            id="port-1",
            asset_id="asset-1",
            port=8180,
            protocol="tcp",
            service_name="unknown",
            service_version=None,
            fingerprint_json={
                "nse": {
                    "http-title": {"hit": True, "title": "Apache Tomcat/5.5"},
                    "http-headers": {"hit": True, "headers": {"server": "Apache-Coyote/1.1"}},
                }
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].evidence_json["service_name"] == "tomcat"
    assert db.added[0].evidence_json["service_version"] == "5.5"


def test_risk_verification_service_matches_distro_aware_sudo_and_polkit_rules(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: sudo.baron_samedit.cve_2021_3156.exposed
    name: sudo vulnerable
    enabled: true
    service: sudo
    severity: critical
    description: sudo vulnerable
    match:
      package:
        manager: dpkg
        name: sudo
        compare: lt_fixed
        fixed_versions:
          ubuntu:
            "20.04": "1.8.31-1ubuntu1.2"
  - id: polkit.pwnkit.cve_2021_4034.exposed
    name: polkit vulnerable
    enabled: true
    service: polkit
    severity: critical
    description: polkit vulnerable
    match:
      config:
        pkexec_present:
          eq: true
        pkexec_suid_present:
          eq: true
      package:
        manager: dpkg
        name: policykit-1
        compare: lt_fixed
        fixed_versions:
          debian:
            "11": "0.105-31+deb11u1"
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-local-v3",
        services_json={
            "config_by_service": {
                "sudo": {
                    "package_name": "sudo",
                    "package_version_raw": "1:1.8.31-1ubuntu1.1",
                    "package_manager": "dpkg",
                    "distro_name": "ubuntu",
                    "distro_release": "20.04",
                },
                "polkit": {
                    "package_name": "policykit-1",
                    "package_version_raw": "0.105-31+deb11u0",
                    "package_manager": "dpkg",
                    "distro_name": "debian",
                    "distro_release": "11",
                    "pkexec_present": True,
                    "pkexec_suid_present": True,
                },
            }
        },
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-local-v3", ip="10.0.0.60")
    asset.ports = [
        AssetPort(
            id="port-ssh-v3",
            asset_id="asset-local-v3",
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version="OpenSSH 8.2",
            fingerprint_json={
                "service_aliases": ["ssh", "sudo", "polkit"],
                "authorization_scope": "authorized_local",
            },
        )
    ]
    asset.snapshots = [snapshot]
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-local-v3")

    assert summary.passive_match_count == 2
    assert summary.created_finding_count == 2
    findings = {item.evidence_json["service_name"]: item.evidence_json["package"] for item in db.added}
    assert findings["sudo"]["version"] == "1:1.8.31-1ubuntu1.1"
    assert findings["polkit"]["name"] == "policykit-1"
    assert all(item.evidence_json["evidence_scope"] == "authorized_local" for item in db.added)


def test_risk_verification_service_matches_rpm_package_rule_with_snapshot_distro_fallback(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ssh.openssh.rpm.outdated
    name: openssh rpm outdated
    enabled: true
    service: ssh
    severity: high
    description: openssh rpm vulnerable
    match:
      package:
        manager: rpm
        name: openssh-server
        compare: lt_fixed
        fixed_versions:
          rocky:
            "9": "1:8.7p1-40.el9"
""",
        encoding="utf-8",
    )
    snapshot = HostSnapshot(
        asset_id="asset-rpm-1",
        os_release="Rocky Linux 9.4",
        services_json={"config_by_service": {"ssh": {}}},
        software_json={"packages": [{"name": "openssh-server", "version": "1:8.7p1-38.el9", "manager": "rpm"}]},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )
    asset = Asset(id="asset-rpm-1", ip="10.0.0.70")
    asset.ports = [
        AssetPort(
            id="port-ssh-rpm",
            asset_id="asset-rpm-1",
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version=None,
            fingerprint_json={"banner": "OpenSSH"},
        )
    ]
    asset.snapshots = [snapshot]
    asset.findings = []
    db = _FakeDB(asset)
    service = RiskVerificationService(RuleEngine(path), _FakeSessionLocal(db))

    summary = service.evaluate_asset("asset-rpm-1")

    assert summary.passive_match_count == 1
    assert summary.created_finding_count == 1
    assert db.added[0].yaml_rule_id == "ssh.openssh.rpm.outdated"
    assert db.added[0].evidence_json["package"]["manager"] == "rpm"
    assert db.added[0].evidence_json["package"]["distro"] == "rocky"
    assert db.added[0].evidence_json["package"]["release"] == "9"
