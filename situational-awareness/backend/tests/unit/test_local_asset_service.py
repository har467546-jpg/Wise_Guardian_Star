from datetime import datetime, timezone

from fastapi.testclient import TestClient

import app.main as main_module
from app.db.models.asset import Asset
from app.services import local_asset_service


class _ScalarResult:
    def __init__(self, items):
        self._items = list(items)

    def all(self):
        return list(self._items)


class _FakeAssetDB:
    def __init__(self, assets):
        self.assets = list(assets)
        self.deleted: list[Asset] = []

    def scalars(self, _stmt):
        return _ScalarResult(self.assets)

    def delete(self, asset: Asset) -> None:
        self.deleted.append(asset)


class _FakeMiddlewareDB:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


def _make_asset(ip: str, hostname: str | None) -> Asset:
    asset = Asset(ip=ip, hostname=hostname)
    asset.id = f"asset-{ip}"
    asset.first_seen_at = datetime.now(timezone.utc)
    asset.last_seen_at = datetime.now(timezone.utc)
    return asset


def test_purge_local_assets_deletes_only_local_records(monkeypatch) -> None:
    local_asset = _make_asset("192.168.10.131", "soc-host")
    remote_asset = _make_asset("192.168.10.88", "target-host")
    db = _FakeAssetDB([local_asset, remote_asset])

    monkeypatch.setattr(
        local_asset_service,
        "resolve_local_asset",
        lambda ip, hostname=None: (True, "匹配平台本机 IP") if ip == "192.168.10.131" else (False, None),
    )

    removed = local_asset_service.purge_local_assets(db)

    assert db.deleted == [local_asset]
    assert removed == [
        {
            "id": local_asset.id,
            "ip": "192.168.10.131",
            "hostname": "soc-host",
            "reason": "匹配平台本机 IP",
        }
    ]


def test_runtime_hint_middleware_purges_existing_local_assets(monkeypatch) -> None:
    db = _FakeMiddlewareDB()
    purge_calls: list[object] = []

    def _noop_create_all(*args, **kwargs) -> None:
        return None

    main_module._LOCAL_ASSET_PURGE_COMPLETED = False
    monkeypatch.setattr(main_module.Base.metadata, "create_all", _noop_create_all)
    monkeypatch.setattr(
        main_module,
        "remember_local_asset_hint",
        lambda value: value == "192.168.10.131:3000",
    )

    def _fake_purge_local_assets(session):
        purge_calls.append(session)
        return [{"ip": "192.168.10.131", "hostname": "soc-host", "reason": "匹配平台本机 IP"}]

    monkeypatch.setattr(main_module, "purge_local_assets", _fake_purge_local_assets)
    monkeypatch.setattr(main_module, "SessionLocal", _FakeSessionLocal(db))

    client = TestClient(main_module.create_app())
    response = client.get("/health", headers={"host": "192.168.10.131:3000"})

    assert response.status_code == 200
    assert purge_calls == [db]
    assert db.committed is True
    assert db.rolled_back is False


def test_runtime_hint_middleware_purges_once_after_startup_even_without_new_hint(monkeypatch) -> None:
    db = _FakeMiddlewareDB()
    purge_calls: list[object] = []

    def _noop_create_all(*args, **kwargs) -> None:
        return None

    main_module._LOCAL_ASSET_PURGE_COMPLETED = False
    monkeypatch.setattr(main_module.Base.metadata, "create_all", _noop_create_all)
    monkeypatch.setattr(main_module, "remember_local_asset_hint", lambda value: False)

    def _fake_purge_local_assets(session):
        purge_calls.append(session)
        return []

    monkeypatch.setattr(main_module, "purge_local_assets", _fake_purge_local_assets)
    monkeypatch.setattr(main_module, "SessionLocal", _FakeSessionLocal(db))

    client = TestClient(main_module.create_app())
    first = client.get("/health")
    second = client.get("/health")

    assert first.status_code == 200
    assert second.status_code == 200
    assert purge_calls == [db]
