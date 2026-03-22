from types import SimpleNamespace
from datetime import datetime, timezone

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.v1.endpoints import collection as collection_endpoint
from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import SSHCredential
from app.db.models.enums import CredentialAuthType
from app.db.models.snapshot import HostSnapshot
from app.schemas.collection import AssetCredentialUpsertRequest, CollectProbeRunRequest, CollectProbeRunResponse


class _FakeDB:
    def __init__(self, asset: Asset | None, binding_exists: bool = False) -> None:
        self._asset = asset
        self._binding_exists = binding_exists
        self.added: list[object] = []
        self.committed = False
        self.flushed = False
        self.refreshed = False

    def get(self, model, key):
        if model is Asset:
            return self._asset if self._asset and self._asset.id == key else None
        return None

    def add(self, item) -> None:
        self.added.append(item)

    def flush(self) -> None:
        self.flushed = True
        for item in self.added:
            if isinstance(item, SSHCredential) and not item.id:
                item.id = "cred-generated"

    def commit(self) -> None:
        self.committed = True

    def refresh(self, _item) -> None:
        self.refreshed = True

    def scalar(self, _stmt):
        return "binding-1" if self._binding_exists else None


def test_asset_credential_request_requires_password_for_password_mode() -> None:
    with pytest.raises(ValidationError):
        AssetCredentialUpsertRequest(auth_type="password", username="root", admin_authorized=True)


def test_asset_credential_request_requires_private_key_for_key_mode() -> None:
    with pytest.raises(ValidationError):
        AssetCredentialUpsertRequest(auth_type="key", username="root", admin_authorized=True)


def test_asset_credential_request_requires_authorization_confirmation() -> None:
    with pytest.raises(ValidationError):
        AssetCredentialUpsertRequest(auth_type="password", username="root", password="secret", admin_authorized=False)


def test_asset_credential_request_requires_sudo_password_for_non_root() -> None:
    with pytest.raises(ValidationError):
        AssetCredentialUpsertRequest(auth_type="password", username="admin", password="secret", admin_authorized=True)


def test_probe_request_only_accepts_baseline_preset() -> None:
    with pytest.raises(ValidationError):
        CollectProbeRunRequest(preset="network")


def test_upsert_asset_credential_creates_password_credential(monkeypatch) -> None:
    asset = Asset(id="asset-1", ip="10.0.0.10")
    db = _FakeDB(asset)
    captured: dict[str, str] = {}

    monkeypatch.setattr(collection_endpoint, "_get_manual_credential", lambda db, asset_id: None)
    monkeypatch.setattr(collection_endpoint, "encrypt_text", lambda raw: f"enc:{raw}")

    def _capture_binding(db, asset_id, credential_id):
        captured["asset_id"] = asset_id
        captured["credential_id"] = credential_id

    monkeypatch.setattr(collection_endpoint, "_ensure_manual_binding", _capture_binding)

    response = collection_endpoint.upsert_asset_credential(
        asset_id="asset-1",
        payload=AssetCredentialUpsertRequest(auth_type="password", username="root", password="secret", admin_authorized=True),
        db=db,
        current_user=SimpleNamespace(id="user-1"),
    )

    assert response.asset_id == "asset-1"
    assert response.bound is True
    assert response.auth_type == "password"
    assert response.username == "root"
    assert response.admin_authorized is True
    assert response.last_verification_status is None
    created = [item for item in db.added if isinstance(item, SSHCredential)][0]
    assert created.auth_type == CredentialAuthType.PASSWORD
    assert created.secret_ciphertext == "enc:secret"
    assert created.key_ciphertext is None
    assert created.treat_success_as_risk is False
    assert created.admin_authorized is True
    assert captured["asset_id"] == "asset-1"
    assert captured["credential_id"] == created.id


def test_get_asset_credential_returns_bound_false_without_manual_credential(monkeypatch) -> None:
    asset = Asset(id="asset-2", ip="10.0.0.20")
    db = _FakeDB(asset)
    monkeypatch.setattr(collection_endpoint, "_get_manual_credential", lambda db, asset_id: None)

    response = collection_endpoint.get_asset_credential("asset-2", db=db, _=SimpleNamespace(id="user-1"))

    assert response.asset_id == "asset-2"
    assert response.bound is False
    assert response.credential_id is None
    assert response.admin_authorized is False


def test_verify_asset_credential_updates_last_verification_fields(monkeypatch) -> None:
    asset = Asset(id="asset-verify-1", ip="10.0.0.25")
    credential = SSHCredential(
        id="cred-verify-1",
        name="manual-asset-asset-verify-1",
        username="root",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        admin_authorized=True,
    )
    db = _FakeDB(asset)

    monkeypatch.setattr(collection_endpoint, "_get_manual_credential", lambda db, asset_id: credential)
    monkeypatch.setattr(collection_endpoint, "decrypt_text", lambda raw: "secret")
    async def _fake_verify(self, profile, options=None):
        return SimpleNamespace(
            verified_at=datetime(2026, 3, 15, 8, 0, tzinfo=timezone.utc),
            to_dict=lambda: {
                "asset_id": profile.asset_id,
                "ip": profile.ip,
                "status": "success",
                "username": profile.username,
                "effective_user": "root",
                "effective_privilege": "root",
                "summary": "管理员权限验证成功：已确认 root 登录",
                "errors": [],
                "detail_json": {"uid": "0"},
                "verified_at": datetime(2026, 3, 15, 8, 0, tzinfo=timezone.utc).isoformat(),
            },
            status="success",
            effective_privilege="root",
        )

    monkeypatch.setattr(collection_endpoint.AsyncSSHCollector, "verify_authorization", _fake_verify)

    response = collection_endpoint.verify_asset_credential("asset-verify-1", db=db, _=SimpleNamespace(id="user-1"))

    assert response.status == "success"
    assert response.effective_privilege == "root"
    assert credential.last_verification_status == "success"
    assert credential.last_effective_privilege == "root"


def test_run_collection_rejects_unverified_credential(monkeypatch) -> None:
    asset = Asset(id="asset-run-1", ip="10.0.0.26")
    db = _FakeDB(asset)
    credential = SSHCredential(
        id="cred-run-1",
        name="manual-asset-asset-run-1",
        username="root",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        admin_authorized=True,
        last_verification_status="failed",
    )
    monkeypatch.setattr(collection_endpoint, "_resolve_credential", lambda db, asset, credential_id: credential)

    with pytest.raises(HTTPException) as exc:
        collection_endpoint.run_collection("asset-run-1", payload=SimpleNamespace(credential_id=None, connect_timeout_seconds=None, command_timeout_seconds=None, asset_timeout_seconds=None), db=db, _=SimpleNamespace(id="user-1"))

    assert exc.value.status_code == 400
    assert "管理员权限验证" in str(exc.value.detail)


def test_persist_probe_result_stores_probe_snapshot_and_updates_asset() -> None:
    asset = Asset(id="asset-3", ip="10.0.0.30")
    db = _FakeDB(asset)
    response = CollectProbeRunResponse(
        asset_id="asset-3",
        ip="10.0.0.30",
        preset="baseline",
        status="partial",
        probe_method="ssh",
        results=[],
        errors=[],
        summary_json={
            "hostname": "web-03",
            "os": "Ubuntu 22.04",
            "kernel": "Linux",
        },
        detail_json={"command_health": {"failed": 1}},
        friendly_text=["ok"],
        executed_at=datetime.now(timezone.utc).isoformat(),
    )

    collection_endpoint._persist_probe_result(db=db, asset=asset, result=response)

    snapshots = [item for item in db.added if isinstance(item, HostSnapshot)]
    assert snapshots
    snapshot = snapshots[0]
    assert snapshot.error_json["snapshot_type"] == "ssh_probe_baseline"
    assert snapshot.services_json["summary_json"]["hostname"] == "web-03"
    assert asset.hostname == "web-03"
    assert asset.os_name == "Ubuntu 22.04"


def test_persist_probe_result_syncs_external_ports_to_asset_ports() -> None:
    asset = Asset(id="asset-3b", ip="10.0.0.31")
    existing = AssetPort(
        asset_id="asset-3b",
        port=22,
        protocol="tcp",
        service_name="ssh",
        service_version="9.0",
        fingerprint_json={"source": "nmap"},
        state="open",
        last_seen_at=datetime(2026, 3, 11, 10, 0, tzinfo=timezone.utc),
    )
    asset.ports = [existing]
    db = _FakeDB(asset)
    response = CollectProbeRunResponse(
        asset_id="asset-3b",
        ip="10.0.0.31",
        preset="baseline",
        status="success",
        probe_method="ssh",
        results=[],
        errors=[],
        summary_json={"hostname": "web-03b", "os": "Ubuntu 22.04", "kernel": "Linux"},
        detail_json={
            "listening_entries": [
                {"port": 22, "protocol": "tcp", "local_address": "0.0.0.0", "process_name": "sshd", "scope": "external"},
                {"port": 8080, "protocol": "tcp", "local_address": "0.0.0.0", "process_name": "nginx", "scope": "external"},
                {"port": 9090, "protocol": "tcp", "local_address": "0.0.0.0", "process_name": None, "scope": "external"},
                {"port": 10001, "protocol": "tcp", "local_address": "0.0.0.0", "process_name": "nc", "scope": "external"},
                {"port": 5432, "protocol": "tcp", "local_address": "127.0.0.1", "process_name": "postgres", "scope": "loopback"},
            ],
            "command_health": {"failed": 0},
        },
        friendly_text=[],
        executed_at=datetime.now(timezone.utc).isoformat(),
    )

    collection_endpoint._persist_probe_result(db=db, asset=asset, result=response)

    created_ports = [item for item in db.added if isinstance(item, AssetPort) and item.port == 8080]
    assert len(created_ports) == 1
    assert created_ports[0].service_name == "http"
    assert created_ports[0].fingerprint_json["source"] == "ssh_probe"
    assert created_ports[0].fingerprint_json["scope"] == "external"
    assert created_ports[0].service_version is None
    mapped_default = [item for item in db.added if isinstance(item, AssetPort) and item.port == 9090]
    assert len(mapped_default) == 1
    assert mapped_default[0].service_name == "prometheus"
    backdoor_created = [item for item in db.added if isinstance(item, AssetPort) and item.port == 10001]
    assert len(backdoor_created) == 1
    assert backdoor_created[0].service_name == "unknown"
    assert backdoor_created[0].service_version is None
    assert backdoor_created[0].fingerprint_json["nmap_skipped"] is True
    assert backdoor_created[0].fingerprint_json["nmap_skip_reason"] == "backdoor_candidate_policy"
    assert backdoor_created[0].fingerprint_json["version_skipped"] is True
    assert not any(isinstance(item, AssetPort) and item.port == 5432 for item in db.added)
    assert existing.fingerprint_json["source"] == "nmap"
    assert existing.fingerprint_json["scope"] == "external"
    assert existing.service_version == "9.0"


def test_build_probe_response_from_snapshot_restores_structured_payload() -> None:
    asset = Asset(id="asset-4", ip="10.0.0.40")
    snapshot = HostSnapshot(
        asset_id="asset-4",
        services_json={"summary_json": {"hostname": "web-04"}, "detail_json": {"command_health": {"failed": 0}}},
        software_json={"raw_results": [{"name": "hostname", "command": "hostname", "success": True, "exit_status": 0, "stdout": "web-04", "stderr": "", "duration_ms": 8}], "friendly_text": ["探测完成"]},
        error_json={"snapshot_type": "ssh_probe_baseline", "errors": []},
        collection_status="success",
        collected_at=datetime.now(timezone.utc),
    )

    response = collection_endpoint._build_probe_response_from_snapshot(asset, snapshot)

    assert response.asset_id == "asset-4"
    assert response.summary_json["hostname"] == "web-04"
    assert response.detail_json["command_health"]["failed"] == 0
    assert response.friendly_text == ["探测完成"]


def test_get_latest_asset_collection_reads_summary_and_detail_from_snapshot() -> None:
    asset = Asset(id="asset-latest-1", ip="10.0.0.41")
    snapshot = HostSnapshot(
        asset_id="asset-latest-1",
        collection_status="partial",
        collected_at=datetime.now(timezone.utc),
        software_json={
            "summary_json": {"kernel": "6.8.0", "effective_privilege": "root"},
            "detail_json": {"authorization": {"effective_privilege": "root"}, "host_checks": {"sudoers": {"line_count": 1}}},
        },
        services_json={},
        error_json={},
    )

    class _SnapshotDB(_FakeDB):
        def scalars(self, _stmt):
            return SimpleNamespace(all=lambda: [snapshot])

    db = _SnapshotDB(asset)
    response = collection_endpoint.get_latest_asset_collection("asset-latest-1", db=db, _=SimpleNamespace(id="user-1"))

    assert response.status == "partial"
    assert response.summary_json["effective_privilege"] == "root"
    assert response.detail_json["host_checks"]["sudoers"]["line_count"] == 1


def test_pick_latest_probe_snapshot_prefers_success() -> None:
    failed_latest = HostSnapshot(
        asset_id="asset-5",
        services_json={},
        software_json={},
        error_json={"snapshot_type": "ssh_probe_baseline", "errors": [{"stage": "connect", "message": "failed"}]},
        collection_status="failed",
        collected_at=datetime(2026, 3, 11, 10, 0, tzinfo=timezone.utc),
    )
    success_older = HostSnapshot(
        asset_id="asset-5",
        services_json={"summary_json": {"hostname": "ok"}},
        software_json={},
        error_json={"snapshot_type": "ssh_probe_baseline", "errors": []},
        collection_status="success",
        collected_at=datetime(2026, 3, 11, 9, 0, tzinfo=timezone.utc),
    )

    chosen = collection_endpoint._pick_latest_probe_snapshot([failed_latest, success_older])

    assert chosen is success_older


def test_pick_latest_network_initial_snapshot() -> None:
    initial = HostSnapshot(
        asset_id="asset-6",
        services_json={},
        software_json={"snapshot_type": "network_initial", "summary_json": {"hostname": "node-6"}},
        error_json={},
        collection_status="success",
        collected_at=datetime(2026, 3, 11, 11, 0, tzinfo=timezone.utc),
    )
    probe = HostSnapshot(
        asset_id="asset-6",
        services_json={},
        software_json={"snapshot_type": "ssh_probe_baseline"},
        error_json={},
        collection_status="success",
        collected_at=datetime(2026, 3, 11, 12, 0, tzinfo=timezone.utc),
    )

    chosen = collection_endpoint._pick_latest_network_initial_snapshot([probe, initial])
    assert chosen is initial


def test_build_initial_from_asset_fallback() -> None:
    asset = Asset(id="asset-7", ip="10.0.0.70", hostname="node-7")
    asset.ports = [
        AssetPort(
            asset_id="asset-7",
            port=443,
            protocol="tcp",
            service_name="https",
            service_version="nginx/1.26.1",
            fingerprint_json={"confidence": 90, "source": "nmap", "reason": "nmap match"},
            state="open",
            last_seen_at=datetime(2026, 3, 11, 10, 0, tzinfo=timezone.utc),
        )
    ]

    summary_json, detail_json, status_value = collection_endpoint._build_initial_from_asset(asset)

    assert summary_json["ip"] == "10.0.0.70"
    assert summary_json["hostname"] == "node-7"
    assert detail_json["ports"] == [443]
    assert status_value == "success"
    assert isinstance(summary_json.get("key_observations"), list)
    assert any("降级结果" in item for item in summary_json["key_observations"])
