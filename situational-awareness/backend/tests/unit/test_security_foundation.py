import json
from types import SimpleNamespace

from cryptography.fernet import Fernet

from app.core import crypto, security
from app.services import (
    audit_log_service,
    client_ip_service,
    rate_limit_service,
    refresh_token_service,
    secret_migration_service,
    token_denylist_service,
    ws_ticket_service,
)


class _QueryParams:
    def __init__(self, items):
        self._items = items

    def multi_items(self):
        return list(self._items)


def _request(*, path: str = "/api/v1/assets", method: str = "GET", headers: dict | None = None, query_items=None):
    return SimpleNamespace(
        method=method,
        url=SimpleNamespace(path=path),
        headers=headers or {},
        query_params=_QueryParams(query_items or []),
        client=SimpleNamespace(host="10.0.0.10"),
    )


def test_encrypt_text_uses_aes_256_gcm_and_decrypts(monkeypatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", key)

    ciphertext = crypto.encrypt_text("ssh-secret")

    assert ciphertext.startswith(crypto.AES_GCM_PREFIX)
    assert crypto.decrypt_text(ciphertext) == "ssh-secret"


def test_decrypt_text_keeps_legacy_fernet_compatibility(monkeypatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", key)
    legacy_ciphertext = Fernet(key.encode()).encrypt(b"legacy-secret").decode()

    assert crypto.decrypt_text(legacy_ciphertext) == "legacy-secret"


def test_decrypt_text_keeps_secret_key_derived_fernet_compatibility(monkeypatch) -> None:
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(crypto.settings, "SECRET_KEY", "legacy-secret-key")
    derived_key = crypto.base64.urlsafe_b64encode(crypto.hashlib.sha256(b"legacy-secret-key").digest())
    legacy_ciphertext = Fernet(derived_key).encrypt(b"derived-secret").decode()

    assert crypto.decrypt_text(legacy_ciphertext) == "derived-secret"


def test_rate_limit_local_window_counter() -> None:
    rate_limit_service._local_windows.clear()

    first = rate_limit_service._increment_local_window("rate:key", 1)
    second = rate_limit_service._increment_local_window("rate:key", 1)
    third = rate_limit_service._increment_local_window("rate:key", 1)

    assert first == 1
    assert second == 2
    assert third == 3


def test_audit_resource_and_query_redaction() -> None:
    request = _request(
        path="/api/v1/assets/asset-1",
        method="PUT",
        query_items=[("password", "secret"), ("view", "detail")],
    )

    resource = audit_log_service.resolve_audit_resource(request.method, request.url.path)
    query_payload = audit_log_service.build_query_payload(request)

    assert resource.action == "put:assets:asset-1"
    assert resource.resource_type == "assets"
    assert resource.resource_id == "asset-1"
    assert query_payload["password"] == "[REDACTED]"
    assert query_payload["view"] == "detail"


def test_client_ip_only_trusts_forwarded_headers_from_trusted_proxy(monkeypatch) -> None:
    monkeypatch.setattr(client_ip_service.settings, "SECURITY_TRUSTED_PROXY_CIDRS", "10.0.0.0/24")
    client_ip_service._trusted_proxy_networks.cache_clear()

    trusted = client_ip_service.resolve_client_ip({"x-forwarded-for": "203.0.113.10, 10.0.0.5"}, "10.0.0.8")
    untrusted = client_ip_service.resolve_client_ip({"x-forwarded-for": "203.0.113.10"}, "198.51.100.7")

    assert trusted == "203.0.113.10"
    assert untrusted == "198.51.100.7"


def test_access_token_contains_jti_for_stateful_revocation(monkeypatch) -> None:
    monkeypatch.setattr(security.settings, "SECRET_KEY", "test-secret-for-jti")

    token = security.create_access_token(subject="user-1", extra={"role": "admin"})
    payload = security.decode_access_token(token, verify_denylist=False)

    assert payload["sub"] == "user-1"
    assert payload["jti"]
    assert payload["token_type"] == "access"


def test_access_decoder_rejects_refresh_token(monkeypatch) -> None:
    monkeypatch.setattr(security.settings, "SECRET_KEY", "test-secret-for-token-type")

    token = security.create_refresh_token(subject="user-1", extra={"role": "admin"})

    try:
        security.decode_access_token(token, verify_denylist=False)
    except security.SecurityError as exc:
        assert "token type" in str(exc).lower()
    else:
        raise AssertionError("Expected refresh token to be rejected by access decoder")


def test_token_denylist_uses_jti_with_expiry(monkeypatch) -> None:
    store: dict[str, str] = {}
    expiries: dict[str, int] = {}

    class _FakeRedis:
        def set(self, key: str, value: str, ex: int) -> bool:
            store[key] = value
            expiries[key] = ex
            return True

        def exists(self, key: str) -> bool:
            return key in store

        def close(self) -> None:
            return None

    monkeypatch.setattr(token_denylist_service.Redis, "from_url", lambda *_, **__: _FakeRedis())
    payload = {"jti": "jwt-id-1", "exp": 4102444800}

    assert token_denylist_service.denylist_token_payload(payload) is True
    assert token_denylist_service.is_token_payload_denied(payload) is True
    assert expiries[f"{token_denylist_service.settings.SECURITY_TOKEN_DENYLIST_REDIS_PREFIX}:jwt-id-1"] > 0


def test_refresh_token_rotation_grace_and_replay_revocation(monkeypatch) -> None:
    store: dict[str, str] = {}

    class _FakeRedis:
        def set(self, key: str, value: str, ex: int | None = None, nx: bool = False) -> bool:
            if nx and key in store:
                return False
            store[key] = value
            return True

        def get(self, key: str) -> str | None:
            return store.get(key)

        def exists(self, key: str) -> bool:
            return key in store

        def delete(self, key: str) -> None:
            store.pop(key, None)

        def close(self) -> None:
            return None

    monkeypatch.setattr(security.settings, "SECRET_KEY", "test-secret-for-refresh-rotation")
    monkeypatch.setattr(refresh_token_service.Redis, "from_url", lambda *_, **__: _FakeRedis())
    monkeypatch.setattr(
        refresh_token_service,
        "get_user_auth_state",
        lambda db, user_id: SimpleNamespace(user_id=user_id, role="admin", is_active=True),
    )
    monkeypatch.setattr(refresh_token_service, "is_user_token_revoked", lambda user_id, issued_at: False)

    pair = refresh_token_service.issue_token_pair(user_id="user-1", role="admin")
    first_rotation = refresh_token_service.rotate_refresh_token(SimpleNamespace(), pair.refresh_token)
    grace_replay = refresh_token_service.rotate_refresh_token(SimpleNamespace(), pair.refresh_token)

    assert grace_replay.refresh_token == first_rotation.refresh_token

    old_payload = security.decode_refresh_token(pair.refresh_token, verify_denylist=False)
    old_key = refresh_token_service._refresh_token_key(old_payload["jti"])
    old_record = json.loads(store[old_key])
    old_record["grace_until"] = 0
    store[old_key] = json.dumps(old_record)

    try:
        refresh_token_service.rotate_refresh_token(SimpleNamespace(), pair.refresh_token)
    except refresh_token_service.RefreshTokenReplayError:
        pass
    else:
        raise AssertionError("Expected stale refresh token replay to be rejected")

    family_key = refresh_token_service._family_revoked_key(old_payload["family_id"])
    assert store[family_key] == "1"


def test_websocket_ticket_is_single_use_and_resource_bound(monkeypatch) -> None:
    store: dict[str, str] = {}

    class _FakeRedis:
        def set(self, key: str, value: str, ex: int) -> bool:
            store[key] = value
            return True

        def getdel(self, key: str) -> str | None:
            return store.pop(key, None)

        def close(self) -> None:
            return None

    monkeypatch.setattr(ws_ticket_service.Redis, "from_url", lambda *_, **__: _FakeRedis())

    issued = ws_ticket_service.issue_websocket_ticket(
        user_id="user-1",
        role="admin",
        resource_type="ssh_terminal_asset",
        resource_id="asset-1",
    )
    mismatched = ws_ticket_service.consume_websocket_ticket(
        ticket=issued.ticket,
        resource_type="ssh_terminal_asset",
        resource_id="asset-2",
    )

    assert mismatched is None
    assert ws_ticket_service.consume_websocket_ticket(
        ticket=issued.ticket,
        resource_type="ssh_terminal_asset",
        resource_id="asset-1",
    ) is None


def test_strict_audit_request_classification() -> None:
    assert audit_log_service.should_strict_audit_request(
        _request(path="/api/v1/remediation/assets/asset-1/terminal/tickets", method="POST")
    )
    assert audit_log_service.should_strict_audit_request(
        _request(path="/api/v1/data-exchange/export/servers", method="GET")
    )
    assert not audit_log_service.should_strict_audit_request(_request(path="/api/v1/assets", method="GET"))


def test_production_crypto_validation_rejects_default_secret(monkeypatch) -> None:
    monkeypatch.setattr(crypto.settings, "ENV", "prod")
    monkeypatch.setattr(crypto.settings, "SECRET_KEY", "change-this-secret")
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", Fernet.generate_key().decode())

    try:
        crypto.validate_production_crypto_settings()
    except RuntimeError as exc:
        assert "SECRET_KEY" in str(exc)
    else:
        raise AssertionError("Expected weak production SECRET_KEY to be rejected")


def test_secret_cipher_migration_rewrites_legacy_fernet(monkeypatch) -> None:
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(crypto.settings, "ENCRYPTION_KEY", key)
    model = SimpleNamespace(secret_ciphertext=Fernet(key.encode()).encrypt(b"legacy-secret").decode())

    changed, failed = secret_migration_service._migrate_field(model, "secret_ciphertext")

    assert changed is True
    assert failed is False
    assert model.secret_ciphertext.startswith(crypto.AES_GCM_PREFIX)
    assert crypto.decrypt_text(model.secret_ciphertext) == "legacy-secret"
