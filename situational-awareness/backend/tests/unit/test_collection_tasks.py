from datetime import datetime, timezone
from types import SimpleNamespace

from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import SSHCredential
from app.db.models.enums import AssetStatus, CredentialAuthType, TaskType
from app.db.models.snapshot import HostSnapshot
from app.tasks.collection_tasks import (
    _apply_collection_nse_results,
    _build_collect_options,
    _build_profile,
    _persist_collection_result,
    _queue_followup_risk_verify_task,
)
from app.collector.ssh_collector import SSHCollectResult


def test_build_profile_with_password(monkeypatch) -> None:
    asset = Asset(id="asset-1", ip="10.0.0.10")
    credential = SSHCredential(
        id="cred-1",
        name="pw",
        username="root",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
    )
    monkeypatch.setattr("app.tasks.collection_tasks.decrypt_text", lambda raw: "secret")

    profile = _build_profile(asset, credential)

    assert profile is not None
    assert profile.password == "secret"
    assert profile.private_key is None
    assert profile.sudo_password is None


def test_build_profile_with_private_key(monkeypatch) -> None:
    asset = Asset(id="asset-2", ip="10.0.0.20")
    credential = SSHCredential(
        id="cred-2",
        name="key",
        username="ec2-user",
        auth_type=CredentialAuthType.KEY,
        key_ciphertext="cipher-key",
    )
    monkeypatch.setattr("app.tasks.collection_tasks.decrypt_text", lambda raw: "PRIVATE KEY")

    profile = _build_profile(asset, credential)

    assert profile is not None
    assert profile.password is None
    assert profile.private_key == "PRIVATE KEY"


def test_build_profile_with_sudo_password(monkeypatch) -> None:
    asset = Asset(id="asset-sudo", ip="10.0.0.30")
    credential = SSHCredential(
        id="cred-sudo",
        name="sudo",
        username="admin",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        sudo_secret_ciphertext="sudo-cipher",
        admin_authorized=True,
    )
    monkeypatch.setattr("app.tasks.collection_tasks.decrypt_text", lambda raw: "secret" if raw == "cipher" else "sudo-secret")

    profile = _build_profile(asset, credential)

    assert profile is not None
    assert profile.password == "secret"
    assert profile.sudo_password == "sudo-secret"


def test_build_collect_options_uses_defaults() -> None:
    options = _build_collect_options(None, None, None)
    assert options.connect_timeout == 8
    assert options.command_timeout == 20
    assert options.asset_timeout == 45


class _DummyDB:
    def __init__(self) -> None:
        self.items = []
        self.commit_count = 0

    def add(self, item) -> None:
        self.items.append(item)

    def commit(self) -> None:
        self.commit_count += 1


def test_persist_collection_result_marks_asset_online() -> None:
    db = _DummyDB()
    asset = Asset(id="asset-10", ip="10.0.0.10", status=AssetStatus.COLLECTING)
    result = SSHCollectResult(
        asset_id=asset.id,
        ip=str(asset.ip),
        status="success",
        hostname="node-10",
        os={"name": "ubuntu", "version": "22.04", "pretty_name": "Ubuntu 22.04"},
        kernel={"release": "6.8.0", "version": "#1 SMP"},
        cpu={"model": "x86_64", "architecture": "x86_64", "cores": 4, "threads": 8},
        memory={"total_bytes": 1024, "available_bytes": 512},
        packages=[],
        services=[],
        service_configs={
            "ssh": {"password_authentication": True, "permit_empty_passwords": True},
            "mysql": {
                "skip_grant_tables": True,
                "local_infile": True,
                "bind_all_interfaces": True,
            },
            "sudo": {"setenv_present": True},
            "nmap": {"legacy_interactive_privesc_exposed": True},
            "screen": {"legacy_setuid_privesc_exposed": False},
            "docker": {"socket_present": True, "tcp_listener_without_tlsverify": True},
            "polkit": {"writable_rules_path_present": True},
            "systemd": {"writable_unit_chain_present": True},
            "cron": {"root_writable_job_chain_present": False},
            "logrotate": {"writable_script_chain_present": True},
            "linux-host": {"dangerous_suid_by_binary": {"nmap": True}},
        },
        authorization={
            "status": "success",
            "username": "root",
            "effective_user": "root",
            "effective_privilege": "root",
            "verified_at": datetime(2026, 3, 15, 8, 0, tzinfo=timezone.utc).isoformat(),
        },
        host_checks={"sudoers": {"full_privilege_rule": True}},
        errors=[],
    )

    _persist_collection_result(db=db, asset=asset, result=result)

    assert asset.status == AssetStatus.ONLINE
    assert asset.hostname == "node-10"
    assert asset.os_name == "Ubuntu 22.04"
    assert len(db.items) == 3
    assert db.items[0].services_json["config_by_service"]["ssh"] == {
        "password_authentication": True,
        "permit_empty_passwords": True,
    }
    assert db.items[0].software_json["summary_json"]["local_privesc_exposure_count"] == 5
    assert db.items[0].software_json["summary_json"]["distro_aware_version_exposure_count"] == 0
    assert db.items[0].software_json["summary_json"]["distro_aware_inconclusive_count"] == 0
    assert db.items[0].software_json["summary_json"]["writable_exec_chain_count"] == 2
    assert db.items[0].software_json["summary_json"]["config_exposure_count"] == 3
    assert db.items[0].software_json["summary_json"]["service_config_exposure_count"] == 4
    anchor_ports = [item for item in db.items if isinstance(item, AssetPort) and item.port == 22]
    assert len(anchor_ports) == 1
    assert "linux-kernel" in anchor_ports[0].fingerprint_json["service_aliases"]
    assert "nmap" in anchor_ports[0].fingerprint_json["service_aliases"]
    assert "logrotate" in anchor_ports[0].fingerprint_json["service_aliases"]
    assert "polkit" in anchor_ports[0].fingerprint_json["service_aliases"]


def test_persist_collection_result_marks_asset_unknown_on_failure() -> None:
    db = _DummyDB()
    asset = Asset(
        id="asset-11",
        ip="10.0.0.11",
        hostname="existing-host",
        os_name="Existing OS",
        status=AssetStatus.COLLECTING,
    )
    result = SSHCollectResult.failed(asset_id=asset.id, ip=str(asset.ip), stage="connect", message="auth failed")

    _persist_collection_result(db=db, asset=asset, result=result)

    assert asset.status == AssetStatus.UNKNOWN
    assert asset.hostname == "existing-host"
    assert asset.os_name == "Existing OS"
    assert len(db.items) == 2


def test_apply_collection_nse_results_merges_scripts_and_updates_snapshot() -> None:
    db = _DummyDB()
    collected_at = datetime(2026, 3, 13, 8, 0, tzinfo=timezone.utc)
    asset = Asset(id="asset-nse-1", ip="10.0.0.21")
    asset.ports = [
        AssetPort(
            asset_id=asset.id,
            port=21,
            protocol="tcp",
            service_name="ftp",
            service_version="vsftpd 2.3.4",
            state="open",
            fingerprint_json={
                "nse": {
                    "ftp-syst": {
                        "hit": False,
                        "summary": "UNIX Type: L8",
                        "system_type": "UNIX Type: L8",
                    }
                },
                "nse_summary": {
                    "requested_scripts": ["ftp-syst"],
                    "returned_scripts": ["ftp-syst"],
                    "hit_scripts": [],
                    "script_count": 1,
                    "hit_count": 0,
                    "script_summaries": {"ftp-syst": "UNIX Type: L8"},
                },
            },
        )
    ]
    snapshot = HostSnapshot(asset_id=asset.id, services_json={"services": [], "config_by_service": {}}, software_json={}, error_json={})

    hit_count = _apply_collection_nse_results(
        db=db,
        asset=asset,
        snapshot=snapshot,
        requested_by_port={21: ["ftp-anon"]},
        results_by_port={
            21: {
                "ftp-anon": {
                    "hit": True,
                    "summary": "Anonymous FTP login allowed",
                    "anonymous_allowed": True,
                    "raw_output": "Anonymous FTP login allowed",
                }
            }
        },
        collected_at=collected_at,
    )

    fingerprint = asset.ports[0].fingerprint_json
    assert hit_count == 1
    assert fingerprint["nse"]["ftp-anon"]["anonymous_allowed"] is True
    assert fingerprint["nse"]["ftp-syst"]["system_type"] == "UNIX Type: L8"
    assert fingerprint["nse_last_phase"] == "collection"
    assert fingerprint["nse_last_collected_at"] == collected_at.isoformat()
    assert snapshot.services_json["nse_by_port"]["21"]["ftp-anon"]["hit"] is True
    assert snapshot.services_json["nse_summary"]["last_phase"] == "collection"
    assert snapshot.services_json["nse_summary"]["hit_count"] == 1


def test_apply_collection_nse_results_clears_stale_requested_script_payload() -> None:
    db = _DummyDB()
    collected_at = datetime(2026, 3, 13, 9, 0, tzinfo=timezone.utc)
    asset = Asset(id="asset-nse-2", ip="10.0.0.22")
    asset.ports = [
        AssetPort(
            asset_id=asset.id,
            port=21,
            protocol="tcp",
            service_name="ftp",
            service_version="vsftpd 2.3.4",
            state="open",
            fingerprint_json={
                "nse": {
                    "ftp-anon": {
                        "hit": True,
                        "summary": "old anon",
                        "anonymous_allowed": True,
                    },
                    "ftp-syst": {
                        "hit": False,
                        "summary": "UNIX Type: L8",
                    },
                }
            },
        )
    ]
    snapshot = HostSnapshot(asset_id=asset.id, services_json={"services": [], "config_by_service": {}}, software_json={}, error_json={})

    _apply_collection_nse_results(
        db=db,
        asset=asset,
        snapshot=snapshot,
        requested_by_port={21: ["ftp-anon"]},
        results_by_port={},
        collected_at=collected_at,
    )

    fingerprint = asset.ports[0].fingerprint_json
    assert "ftp-anon" not in fingerprint["nse"]
    assert "ftp-syst" in fingerprint["nse"]
    assert fingerprint["nse_summary"]["requested_scripts"] == ["ftp-anon", "ftp-syst"]


def test_queue_followup_risk_verify_task_creates_task_run(monkeypatch) -> None:
    db = _DummyDB()
    monkeypatch.setattr(
        "app.tasks.collection_tasks.run_risk_verify_task",
        SimpleNamespace(delay=lambda task_run_id, asset_id: SimpleNamespace(id=f"celery-{asset_id}-{task_run_id}")),
    )

    task_id = _queue_followup_risk_verify_task(db=db, asset_id="asset-risk-1")

    created = [item for item in db.items if getattr(item, "task_type", None) == TaskType.RISK_VERIFY]
    assert task_id
    assert created
    assert created[-1].scope_id == "asset-risk-1"
    assert created[-1].celery_task_id.startswith("celery-asset-risk-1-")
    assert db.commit_count == 2
