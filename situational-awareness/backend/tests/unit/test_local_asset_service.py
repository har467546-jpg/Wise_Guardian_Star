from types import SimpleNamespace

from app.services import local_asset_service


def test_purge_local_assets_keeps_assets_with_host_runner(monkeypatch) -> None:
    deleted: list[object] = []

    class _FakeDB:
        def scalars(self, _stmt):
            return SimpleNamespace(
                all=lambda: [
                    SimpleNamespace(id="asset-1", ip="192.168.10.5", hostname="scan-node", host_runner=object()),
                    SimpleNamespace(id="asset-2", ip="192.168.10.6", hostname="platform-host", host_runner=None),
                ]
            )

        def delete(self, item):
            deleted.append(item)

    monkeypatch.setattr(
        local_asset_service,
        "resolve_local_asset",
        lambda ip, hostname=None: (True, "匹配平台本机 IP") if ip == "192.168.10.6" else (False, None),
    )

    removed = local_asset_service.purge_local_assets(_FakeDB())

    assert len(removed) == 1
    assert removed[0]["ip"] == "192.168.10.6"
    assert len(deleted) == 1
