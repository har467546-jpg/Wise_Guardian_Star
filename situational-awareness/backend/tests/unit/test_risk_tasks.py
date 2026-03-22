from datetime import datetime, timezone

from app.db.models.asset import Asset, AssetPort
from app.db.models.snapshot import HostSnapshot
from app.tasks import risk_tasks


class _FakeEngine:
    def __init__(self) -> None:
        self.inputs = []

    def match_one(self, rule_input):
        self.inputs.append(rule_input)
        return []


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


class _FakeRiskVerificationService:
    def __init__(self) -> None:
        self.calls = []

    def evaluate_asset(self, asset_id: str, progress_callback=None):
        self.calls.append((asset_id, progress_callback))
        return type("Summary", (), {"to_dict": lambda self: {"asset_id": asset_id, "created_finding_count": 1}})()


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def test_extract_service_config_prefers_service_mapping() -> None:
    snapshot = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"redis": {"requirepass": ""}}},
        software_json={},
        error_json={},
        collected_at=datetime.now(timezone.utc),
    )

    config = risk_tasks._extract_service_config(snapshot, "redis")

    assert config == {"requirepass": ""}


def test_normalize_service_name_maps_http_nginx_and_openssh() -> None:
    nginx_port = AssetPort(port=80, protocol="tcp", service_name="http", service_version="nginx/1.17.10")
    ssh_port = AssetPort(port=22, protocol="tcp", service_name="ssh", service_version="OpenSSH_7.4")

    assert risk_tasks._normalize_service_name(nginx_port) == "nginx"
    assert risk_tasks._normalize_service_name(ssh_port) == "ssh"


def test_latest_snapshot_skips_probe_snapshots() -> None:
    older = HostSnapshot(
        asset_id="asset-1",
        services_json={"config_by_service": {"ssh": {"password_authentication": True}}},
        software_json={},
        error_json={},
        collected_at=datetime(2026, 3, 11, 8, 0, tzinfo=timezone.utc),
    )
    probe_like = HostSnapshot(
        asset_id="asset-1",
        services_json={"summary_json": {"hostname": "node-1"}},
        software_json={},
        error_json={"snapshot_type": "ssh_probe_baseline"},
        collected_at=datetime(2026, 3, 11, 9, 0, tzinfo=timezone.utc),
    )

    chosen = risk_tasks._latest_snapshot([older, probe_like])

    assert chosen is older


def test_execute_risk_evaluation_uses_verification_service(monkeypatch) -> None:
    fake_service = _FakeRiskVerificationService()
    monkeypatch.setattr(risk_tasks, "RISK_VERIFICATION_SERVICE", fake_service)

    result = risk_tasks.execute_risk_evaluation("asset-1")

    assert result["asset_id"] == "asset-1"
    assert result["created_finding_count"] == 1
    assert fake_service.calls[0][0] == "asset-1"
