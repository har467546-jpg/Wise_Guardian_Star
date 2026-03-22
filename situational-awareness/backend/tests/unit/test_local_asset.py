from app.utils import local_asset


def test_resolve_local_asset_loopback() -> None:
    is_local, hint = local_asset.resolve_local_asset("127.0.0.1")
    assert is_local is True
    assert hint is not None


def test_resolve_local_asset_unknown_ip() -> None:
    is_local, hint = local_asset.resolve_local_asset("198.51.100.77")
    assert is_local is False
    assert hint is None


def test_remember_local_asset_hint_persists_runtime_ip(tmp_path, monkeypatch) -> None:
    runtime_path = tmp_path / "local_asset_hints.json"
    monkeypatch.setattr(local_asset, "RUNTIME_LOCAL_ASSET_HINTS_PATH", runtime_path)
    local_asset.clear_local_asset_matcher_cache()

    changed = local_asset.remember_local_asset_hint("http://192.168.10.131:3000")

    assert changed is True
    is_local, hint = local_asset.resolve_local_asset("192.168.10.131")
    assert is_local is True
    assert hint == "匹配平台本机 IP"


def test_remember_local_asset_hint_persists_runtime_hostname(tmp_path, monkeypatch) -> None:
    runtime_path = tmp_path / "local_asset_hints.json"
    monkeypatch.setattr(local_asset, "RUNTIME_LOCAL_ASSET_HINTS_PATH", runtime_path)
    local_asset.clear_local_asset_matcher_cache()

    changed = local_asset.remember_local_asset_hint("soc-console.local:3000")

    assert changed is True
    is_local, hint = local_asset.resolve_local_asset("198.51.100.77", hostname="soc-console.local")
    assert is_local is True
    assert hint == "主机名匹配平台本机"


def test_get_local_asset_matcher_does_not_resolve_hostname_dns(tmp_path, monkeypatch) -> None:
    runtime_path = tmp_path / "local_asset_hints.json"
    monkeypatch.setattr(local_asset, "RUNTIME_LOCAL_ASSET_HINTS_PATH", runtime_path)
    monkeypatch.setattr(local_asset.settings, "LOCAL_ASSET_IPS", "127.0.0.1")
    monkeypatch.setattr(local_asset.socket, "gethostname", lambda: "scanner-host")
    monkeypatch.setattr(local_asset.socket, "getfqdn", lambda: "scanner-host.local")

    def _unexpected(*args, **kwargs):
        raise AssertionError("不应触发 DNS 解析")

    monkeypatch.setattr(local_asset.socket, "gethostbyname_ex", _unexpected, raising=True)
    monkeypatch.setattr(local_asset.socket, "getaddrinfo", _unexpected, raising=True)
    local_asset.clear_local_asset_matcher_cache()

    matcher = local_asset.get_local_asset_matcher()

    assert "scanner-host" in matcher.hostnames
    assert "scanner-host.local" in matcher.hostnames
