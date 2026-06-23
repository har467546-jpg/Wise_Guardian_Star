from types import SimpleNamespace

from cryptography.fernet import Fernet

from app.core import crypto
from app.services import audit_log_service, rate_limit_service


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
