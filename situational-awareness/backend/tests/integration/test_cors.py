from fastapi.testclient import TestClient

from app.main import create_app
from app.core.config import settings


def test_cors_allow_all_accepts_any_origin(monkeypatch) -> None:
    monkeypatch.setattr(settings, "CORS_ALLOW_ALL", True)
    monkeypatch.setattr(settings, "CORS_ALLOW_ORIGINS", "http://localhost:3000")
    client = TestClient(create_app())

    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "*"


def test_cors_allowlist_rejects_unknown_origin(monkeypatch) -> None:
    monkeypatch.setattr(settings, "CORS_ALLOW_ALL", False)
    monkeypatch.setattr(settings, "CORS_ALLOW_ORIGINS", "http://localhost:3000")
    client = TestClient(create_app())

    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400


def test_cors_allowlist_accepts_wildcard_private_network_origin(monkeypatch) -> None:
    monkeypatch.setattr(settings, "CORS_ALLOW_ALL", False)
    monkeypatch.setattr(settings, "CORS_ALLOW_ORIGINS", "http://192.168.*.*:3000,http://10.*.*.*:3000")
    client = TestClient(create_app())

    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://192.168.130.137:3000",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://192.168.130.137:3000"


def test_cors_allowlist_rejects_non_matching_wildcard_origin(monkeypatch) -> None:
    monkeypatch.setattr(settings, "CORS_ALLOW_ALL", False)
    monkeypatch.setattr(settings, "CORS_ALLOW_ORIGINS", "http://192.168.*.*:3000")
    client = TestClient(create_app())

    response = client.options(
        "/api/v1/auth/login",
        headers={
            "Origin": "http://172.15.1.9:3000",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
