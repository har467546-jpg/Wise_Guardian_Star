from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_user
from app.db.base import Base
from app.db.models.enums import TaskExecutionStatus, TaskType, UserRole
from app.db.models.task_run import TaskRun
import app.db.session as db_session_module
import app.main as app_main_module
from app.main import create_app
from app.services.ai import providers as providers_module
from app.services import platform_settings_service

SessionLocal = db_session_module.SessionLocal
engine = db_session_module.engine
_OPEN_TEST_CLIENTS: list[TestClient] = []
_OPEN_TEST_ENGINES = []


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "JSON"


@compiles(INET, "sqlite")
def _compile_inet_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


@compiles(CIDR, "sqlite")
def _compile_cidr_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


def _override_user(role: UserRole):
    def _resolver():
        return SimpleNamespace(id="user-1", role=role, is_active=True)

    return _resolver


class _FakeHelperResponse:
    def __init__(self, payload: dict | None = None) -> None:
        self._payload = payload or {"accepted": True}
        self.content = b'{"accepted": true}'

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


def _install_test_database() -> None:
    global SessionLocal, engine

    test_engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    test_session_local = sessionmaker(
        bind=test_engine,
        autocommit=False,
        autoflush=False,
        expire_on_commit=False,
        class_=Session,
    )

    db_session_module.engine = test_engine
    db_session_module.SessionLocal = test_session_local
    app_main_module.engine = test_engine
    app_main_module.SessionLocal = test_session_local

    SessionLocal = test_session_local
    engine = test_engine
    _OPEN_TEST_ENGINES.append(test_engine)


@pytest.fixture(autouse=True)
def _cleanup_test_clients_and_engines():  # type: ignore[no-untyped-def]
    yield
    while _OPEN_TEST_CLIENTS:
        _OPEN_TEST_CLIENTS.pop().close()
    while _OPEN_TEST_ENGINES:
        _OPEN_TEST_ENGINES.pop().dispose()


def _build_client(monkeypatch, tmp_path, role: UserRole = UserRole.ADMIN) -> TestClient:  # type: ignore[no-untyped-def]
    _install_test_database()
    Base.metadata.create_all(bind=engine)
    runtime_env = tmp_path / ".env.runtime"
    example_env = tmp_path / ".env.example"
    example_env.write_text(
        "\n".join(
            [
                "SECRET_KEY=test-secret",
                "DATABASE_URL=postgresql+psycopg://asset:asset@postgres:5432/assetdb",
                "REDIS_URL=redis://redis:6379/0",
                "SETTINGS_HELPER_URL=http://settings-helper.test/internal/apply",
                "SETTINGS_HELPER_TOKEN=test-helper-token",
                "LLM_PROVIDER=mock",
                "LLM_MODEL=gpt-4o-mini",
                "LLM_BASE_URL=",
                "LLM_WIRE_API=responses",
                "LLM_TIMEOUT_SECONDS=60",
                "LLM_API_KEY=",
                "CORS_ALLOW_ALL=true",
                "CORS_ALLOW_ORIGINS=http://localhost:3000",
                "LOCAL_ASSET_IPS=127.0.0.1,::1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    runtime_env.write_text(example_env.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(platform_settings_service, "RUNTIME_ENV_PATH", runtime_env)
    monkeypatch.setattr(platform_settings_service, "EXAMPLE_ENV_PATH", example_env)
    monkeypatch.setattr(platform_settings_service.settings, "SETTINGS_HELPER_URL", "http://settings-helper.test/internal/apply")
    monkeypatch.setattr(platform_settings_service.settings, "SETTINGS_HELPER_TOKEN", "test-helper-token")
    monkeypatch.setattr(platform_settings_service.settings, "ENCRYPTION_KEY", "c0e8AJIwQJdya6z-6H0f5uZ-hgV11FXGeUXLEVXe3G8=")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_API_KEY", "")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_PROVIDER", "mock")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_BASE_URL", "")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_TIMEOUT_SECONDS", 60)

    app = create_app()
    app.dependency_overrides[get_current_user] = _override_user(role)
    client = TestClient(app)
    _OPEN_TEST_CLIENTS.append(client)
    return client


def test_get_settings_requires_admin(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path, role=UserRole.ANALYST)

    response = client.get("/api/v1/settings")

    assert response.status_code == 403


def test_get_settings_returns_secret_state(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    monkeypatch.setattr(platform_settings_service.settings, "RUNNER_POLL_INTERVAL_SECONDS", 15)
    monkeypatch.setattr(platform_settings_service.settings, "CORS_ALLOW_ALL", False)
    monkeypatch.setattr(platform_settings_service.settings, "CORS_ALLOW_ORIGINS", "http://console.local")

    response = client.get("/api/v1/settings")

    assert response.status_code == 200
    body = response.json()
    assert body["runner_poll_interval_seconds"] == 15
    assert body["cors_allow_all"] is False
    assert body["cors_allow_origins"] == "http://console.local"
    assert body["llm_base_url"] == ""
    assert body["llm_wire_api"] == "responses"
    assert body["llm_timeout_seconds"] == 60
    assert body["llm_api_key"]["configured"] is False
    assert body["llm_api_key"]["editable"] is True


def test_get_settings_rejects_legacy_openai_compatible_provider(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    runtime_env = tmp_path / ".env.runtime"
    runtime_env.write_text(
        runtime_env.read_text(encoding="utf-8")
        .replace("LLM_PROVIDER=mock\n", "LLM_PROVIDER=openai_compatible\n")
        .replace("LLM_BASE_URL=\n", "LLM_BASE_URL=relay.example.com/models\n")
        .replace("LLM_WIRE_API=responses\n", "LLM_WIRE_API=auto\n"),
        encoding="utf-8",
    )

    response = client.get("/api/v1/settings")

    assert response.status_code == 400
    assert response.json()["detail"] == "当前模型接入方式不受支持，请迁移到 custom_proxy"


def test_get_settings_prefers_runtime_env_ai_values_over_cached_settings(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    runtime_env = tmp_path / ".env.runtime"
    runtime_env.write_text(
        "\n".join(
            [
                "SECRET_KEY=test-secret",
                "DATABASE_URL=postgresql+psycopg://asset:asset@postgres:5432/assetdb",
                "REDIS_URL=redis://redis:6379/0",
                "SETTINGS_HELPER_URL=http://settings-helper.test/internal/apply",
                "SETTINGS_HELPER_TOKEN=test-helper-token",
                "LLM_PROVIDER=minimax",
                "LLM_MODEL=MiniMax-M2.5",
                "LLM_BASE_URL=api.minimaxi.com",
                "LLM_WIRE_API=chat_completions",
                "LLM_TIMEOUT_SECONDS=75",
                "LLM_API_KEY=sk-runtime-secret",
                "CORS_ALLOW_ALL=true",
                "CORS_ALLOW_ORIGINS=http://localhost:3000",
                "LOCAL_ASSET_IPS=127.0.0.1,::1",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(platform_settings_service.settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(platform_settings_service.settings, "LLM_TIMEOUT_SECONDS", 60)
    monkeypatch.setattr(platform_settings_service.settings, "LLM_API_KEY", "sk-cached-secret")

    response = client.get("/api/v1/settings")

    assert response.status_code == 200
    body = response.json()
    assert body["llm_provider"] == "minimax"
    assert body["llm_model"] == "MiniMax-M2.5"
    assert body["llm_base_url"] == "https://api.minimaxi.com/v1"
    assert body["llm_wire_api"] == "chat_completions"
    assert body["llm_timeout_seconds"] == 75
    assert body["llm_api_key"]["masked_value"] == "sk-***ret"


def test_get_settings_preserves_corrected_custom_proxy_root_base_url(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    runtime_env = tmp_path / ".env.runtime"
    runtime_env.write_text(
        runtime_env.read_text(encoding="utf-8")
        .replace("LLM_PROVIDER=mock\n", "LLM_PROVIDER=custom_proxy\n")
        .replace("LLM_BASE_URL=\n", "LLM_BASE_URL=https://relay.example.com\n"),
        encoding="utf-8",
    )

    response = client.get("/api/v1/settings")

    assert response.status_code == 200
    body = response.json()
    assert body["llm_base_url"] == "https://relay.example.com"


def test_put_settings_dispatches_helper_with_plaintext_api_key(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeHelperResponse()

    monkeypatch.setattr(platform_settings_service.httpx, "post", _fake_post)

    response = client.put(
        "/api/v1/settings",
        json={
            "runner_poll_interval_seconds": 12,
            "runner_offline_grace_seconds": 60,
            "remediation_auto_reverify_enabled": True,
            "remediation_stop_on_failure": True,
            "remediation_prepare_backups_enabled": True,
            "discovery_liveness_ports": "22,80,443",
            "discovery_liveness_mode": "nmap_icmp",
            "discovery_service_ports": "22,80,443,3306",
            "discovery_high_backdoor_ports": "",
            "discovery_portset_mode": "full",
            "discovery_top_ports_limit": 1000,
            "discovery_nmap_mode": "enrich",
            "discovery_nmap_min_rate": 100000,
            "discovery_nmap_timeout_seconds": 8,
            "discovery_nmap_liveness_timeout_seconds": 90,
            "discovery_nmap_full_scan_timeout_seconds": 90,
            "discovery_nmap_version_intensity": 7,
            "discovery_low_confidence_threshold": 70,
            "discovery_full_scan_host_concurrency": 8,
            "discovery_full_scan_port_concurrency": 256,
            "discovery_service_probe_host_concurrency": 32,
            "discovery_nse_mode": "whitelist",
            "discovery_nse_timeout_seconds": 8,
            "discovery_nse_host_concurrency": 8,
            "discovery_nse_enable_vuln_scripts": True,
            "risk_active_verify_connect_timeout_seconds": 3,
            "risk_active_verify_read_timeout_seconds": 3,
            "risk_active_verify_max_concurrency": 4,
            "llm_provider": "openai",
            "llm_model": "gpt-4o-mini",
            "llm_base_url": "https://api.openai.com/v1",
            "llm_timeout_seconds": 45,
            "llm_api_key": "sk-test-secret",
            "clear_llm_api_key": False,
            "cors_allow_all": True,
            "cors_allow_origins": "http://localhost:3000",
            "local_asset_ips": "127.0.0.1,::1",
            "access_token_expire_minutes": 480,
        },
    )

    assert response.status_code == 202
    helper_json = captured["json"]
    assert isinstance(helper_json, dict)
    env_content = str(helper_json["env_content"])
    assert helper_json["compose_file"] == "/workspace/infra/docker-compose.yml"
    assert helper_json["restart_targets"] == ["backend", "worker"]
    assert "LLM_API_KEY=sk-test-secret" in env_content
    assert "LLM_API_KEY_ENCRYPTED=" not in env_content
    assert "LLM_BASE_URL=https://api.openai.com/v1" in env_content
    assert "LLM_WIRE_API=responses" in env_content
    assert "LLM_TIMEOUT_SECONDS=45" in env_content
    with SessionLocal() as db:
        task = db.get(TaskRun, response.json()["task_id"])
        assert task is not None
        assert task.task_type == TaskType.SETTINGS_APPLY
        assert task.status == TaskExecutionStatus.RUNNING


def test_put_settings_normalizes_custom_proxy_base_url(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["json"] = json
        return _FakeHelperResponse()

    monkeypatch.setattr(platform_settings_service.httpx, "post", _fake_post)

    response = client.put(
        "/api/v1/settings",
        json={
            "runner_poll_interval_seconds": 12,
            "runner_offline_grace_seconds": 60,
            "remediation_auto_reverify_enabled": True,
            "remediation_stop_on_failure": True,
            "remediation_prepare_backups_enabled": True,
            "discovery_liveness_ports": "22,80,443",
            "discovery_liveness_mode": "nmap_icmp",
            "discovery_service_ports": "22,80,443,3306",
            "discovery_high_backdoor_ports": "",
            "discovery_portset_mode": "full",
            "discovery_top_ports_limit": 1000,
            "discovery_nmap_mode": "enrich",
            "discovery_nmap_min_rate": 100000,
            "discovery_nmap_timeout_seconds": 8,
            "discovery_nmap_liveness_timeout_seconds": 90,
            "discovery_nmap_full_scan_timeout_seconds": 90,
            "discovery_nmap_version_intensity": 7,
            "discovery_low_confidence_threshold": 70,
            "discovery_full_scan_host_concurrency": 8,
            "discovery_full_scan_port_concurrency": 256,
            "discovery_service_probe_host_concurrency": 32,
            "discovery_nse_mode": "whitelist",
            "discovery_nse_timeout_seconds": 8,
            "discovery_nse_host_concurrency": 8,
            "discovery_nse_enable_vuln_scripts": True,
            "risk_active_verify_connect_timeout_seconds": 3,
            "risk_active_verify_read_timeout_seconds": 3,
            "risk_active_verify_max_concurrency": 4,
            "llm_provider": "custom_proxy",
            "llm_model": "gpt-5.4",
            "llm_base_url": "relay.example.com/models",
            "llm_wire_api": "auto",
            "llm_timeout_seconds": 45,
            "llm_api_key": "relay-secret",
            "clear_llm_api_key": False,
            "cors_allow_all": True,
            "cors_allow_origins": "http://localhost:3000",
            "local_asset_ips": "127.0.0.1,::1",
            "access_token_expire_minutes": 480,
        },
    )

    assert response.status_code == 202
    helper_json = captured["json"]
    assert isinstance(helper_json, dict)
    env_content = str(helper_json["env_content"])
    assert "LLM_PROVIDER=custom_proxy" in env_content
    assert "LLM_BASE_URL=https://relay.example.com/v1" in env_content
    assert "LLM_WIRE_API=auto" in env_content


def test_put_settings_preserves_corrected_custom_proxy_root_base_url(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["json"] = json
        return _FakeHelperResponse()

    monkeypatch.setattr(platform_settings_service.httpx, "post", _fake_post)

    response = client.put(
        "/api/v1/settings",
        json={
            "runner_poll_interval_seconds": 12,
            "runner_offline_grace_seconds": 60,
            "remediation_auto_reverify_enabled": True,
            "remediation_stop_on_failure": True,
            "remediation_prepare_backups_enabled": True,
            "discovery_liveness_ports": "22,80,443",
            "discovery_liveness_mode": "nmap_icmp",
            "discovery_service_ports": "22,80,443,3306",
            "discovery_high_backdoor_ports": "",
            "discovery_portset_mode": "full",
            "discovery_top_ports_limit": 1000,
            "discovery_nmap_mode": "enrich",
            "discovery_nmap_min_rate": 100000,
            "discovery_nmap_timeout_seconds": 8,
            "discovery_nmap_liveness_timeout_seconds": 90,
            "discovery_nmap_full_scan_timeout_seconds": 90,
            "discovery_nmap_version_intensity": 7,
            "discovery_low_confidence_threshold": 70,
            "discovery_full_scan_host_concurrency": 8,
            "discovery_full_scan_port_concurrency": 256,
            "discovery_service_probe_host_concurrency": 32,
            "discovery_nse_mode": "whitelist",
            "discovery_nse_timeout_seconds": 8,
            "discovery_nse_host_concurrency": 8,
            "discovery_nse_enable_vuln_scripts": True,
            "risk_active_verify_connect_timeout_seconds": 3,
            "risk_active_verify_read_timeout_seconds": 3,
            "risk_active_verify_max_concurrency": 4,
            "llm_provider": "custom_proxy",
            "llm_model": "gpt-5.4",
            "llm_base_url": "https://relay.example.com",
            "llm_wire_api": "auto",
            "llm_timeout_seconds": 45,
            "llm_api_key": "relay-secret",
            "clear_llm_api_key": False,
            "cors_allow_all": True,
            "cors_allow_origins": "http://localhost:3000",
            "local_asset_ips": "127.0.0.1,::1",
            "access_token_expire_minutes": 480,
        },
    )

    assert response.status_code == 202
    helper_json = captured["json"]
    assert isinstance(helper_json, dict)
    env_content = str(helper_json["env_content"])
    assert "LLM_PROVIDER=custom_proxy" in env_content
    assert "LLM_BASE_URL=https://relay.example.com\n" in env_content


def test_put_settings_applies_minimax_defaults_when_wire_api_omitted(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["json"] = json
        return _FakeHelperResponse()

    monkeypatch.setattr(platform_settings_service.httpx, "post", _fake_post)

    response = client.put(
        "/api/v1/settings",
        json={
            "runner_poll_interval_seconds": 12,
            "runner_offline_grace_seconds": 60,
            "remediation_auto_reverify_enabled": True,
            "remediation_stop_on_failure": True,
            "remediation_prepare_backups_enabled": True,
            "discovery_liveness_ports": "22,80,443",
            "discovery_liveness_mode": "nmap_icmp",
            "discovery_service_ports": "22,80,443,3306",
            "discovery_high_backdoor_ports": "",
            "discovery_portset_mode": "full",
            "discovery_top_ports_limit": 1000,
            "discovery_nmap_mode": "enrich",
            "discovery_nmap_min_rate": 100000,
            "discovery_nmap_timeout_seconds": 8,
            "discovery_nmap_liveness_timeout_seconds": 90,
            "discovery_nmap_full_scan_timeout_seconds": 90,
            "discovery_nmap_version_intensity": 7,
            "discovery_low_confidence_threshold": 70,
            "discovery_full_scan_host_concurrency": 8,
            "discovery_full_scan_port_concurrency": 256,
            "discovery_service_probe_host_concurrency": 32,
            "discovery_nse_mode": "whitelist",
            "discovery_nse_timeout_seconds": 8,
            "discovery_nse_host_concurrency": 8,
            "discovery_nse_enable_vuln_scripts": True,
            "risk_active_verify_connect_timeout_seconds": 3,
            "risk_active_verify_read_timeout_seconds": 3,
            "risk_active_verify_max_concurrency": 4,
            "llm_provider": "minimax",
            "llm_model": "MiniMax-M2.5",
            "llm_base_url": "",
            "llm_timeout_seconds": 45,
            "llm_api_key": "mini-secret",
            "clear_llm_api_key": False,
            "cors_allow_all": True,
            "cors_allow_origins": "http://localhost:3000",
            "local_asset_ips": "127.0.0.1,::1",
            "access_token_expire_minutes": 480,
        },
    )

    assert response.status_code == 202
    helper_json = captured["json"]
    assert isinstance(helper_json, dict)
    env_content = str(helper_json["env_content"])
    assert "LLM_PROVIDER=minimax" in env_content
    assert "LLM_BASE_URL=https://api.minimaxi.com/v1" in env_content
    assert "LLM_WIRE_API=chat_completions" in env_content


def test_internal_complete_marks_task_success(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)

    monkeypatch.setattr(platform_settings_service.httpx, "post", lambda *args, **kwargs: _FakeHelperResponse())  # type: ignore[no-untyped-def]
    create_response = client.put(
        "/api/v1/settings",
        json={
            "runner_poll_interval_seconds": 10,
            "runner_offline_grace_seconds": 45,
            "remediation_auto_reverify_enabled": True,
            "remediation_stop_on_failure": True,
            "remediation_prepare_backups_enabled": True,
            "discovery_liveness_ports": "22,80,443",
            "discovery_liveness_mode": "nmap_icmp",
            "discovery_service_ports": "22,80,443,3306",
            "discovery_high_backdoor_ports": "",
            "discovery_portset_mode": "full",
            "discovery_top_ports_limit": 1000,
            "discovery_nmap_mode": "enrich",
            "discovery_nmap_min_rate": 100000,
            "discovery_nmap_timeout_seconds": 8,
            "discovery_nmap_liveness_timeout_seconds": 90,
            "discovery_nmap_full_scan_timeout_seconds": 90,
            "discovery_nmap_version_intensity": 7,
            "discovery_low_confidence_threshold": 70,
            "discovery_full_scan_host_concurrency": 8,
            "discovery_full_scan_port_concurrency": 256,
            "discovery_service_probe_host_concurrency": 32,
            "discovery_nse_mode": "whitelist",
            "discovery_nse_timeout_seconds": 8,
            "discovery_nse_host_concurrency": 8,
            "discovery_nse_enable_vuln_scripts": True,
            "risk_active_verify_connect_timeout_seconds": 3,
            "risk_active_verify_read_timeout_seconds": 3,
            "risk_active_verify_max_concurrency": 4,
            "llm_provider": "mock",
            "llm_model": "gpt-4o-mini",
            "llm_base_url": "",
            "llm_timeout_seconds": 60,
            "llm_api_key": "",
            "clear_llm_api_key": False,
            "cors_allow_all": True,
            "cors_allow_origins": "http://localhost:3000",
            "local_asset_ips": "127.0.0.1,::1",
            "access_token_expire_minutes": 480,
        },
    )
    task_id = create_response.json()["task_id"]

    response = client.post(
        f"/api/v1/settings/internal/tasks/{task_id}/complete",
        headers={"X-Settings-Helper-Token": "test-helper-token"},
        json={
            "status": "success",
            "message": "系统设置已应用并完成服务重启",
            "result_json": {
                "changed_keys": ["RUNNER_POLL_INTERVAL_SECONDS"],
                "restart_targets": ["backend", "worker"],
                "runtime_env_path": "backend/.env.runtime",
                "helper_result": {
                    "compose_stdout": "ok",
                    "runtime_sync": {
                        "verification_keys": ["RUNNER_POLL_INTERVAL_SECONDS"],
                        "backend": {
                            "ok": True,
                            "attempts": 1,
                            "actual_values": {"RUNNER_POLL_INTERVAL_SECONDS": "10"},
                            "mismatches": {},
                            "exec_error": None,
                        },
                        "worker": {
                            "ok": True,
                            "attempts": 1,
                            "actual_values": {"RUNNER_POLL_INTERVAL_SECONDS": "10"},
                            "mismatches": {},
                            "exec_error": None,
                        },
                    },
                },
                "applied_at": "2026-03-16T08:00:00+00:00",
            },
            "error_json": {},
            "stage_events": [
                {
                    "event_type": "stage",
                    "level": "info",
                    "stage_code": "write_runtime_env",
                    "stage_name": "写入运行时环境",
                    "message": "运行时环境文件已写入",
                    "progress": 45,
                    "payload_json": {"runtime_env_path": "/workspace/backend/.env.runtime"},
                },
                {
                    "event_type": "stage",
                    "level": "info",
                    "stage_code": "verify_backend_runtime",
                    "stage_name": "校验 backend 配置",
                    "message": "backend 已加载最新运行时配置",
                    "progress": 92,
                    "payload_json": {"ok": True},
                },
                {
                    "event_type": "stage",
                    "level": "info",
                    "stage_code": "verify_worker_runtime",
                    "stage_name": "校验 worker 配置",
                    "message": "worker 已加载最新运行时配置",
                    "progress": 96,
                    "payload_json": {"ok": True},
                }
            ],
        },
    )

    assert response.status_code == 200
    with SessionLocal() as db:
        task = db.get(TaskRun, task_id)
        assert task is not None
        assert task.status == TaskExecutionStatus.SUCCESS
        assert task.result_json["applied_at"] == "2026-03-16T08:00:00+00:00"
        helper_result = task.result_json["helper_result"]
        assert helper_result["runtime_sync"]["verification_keys"] == ["RUNNER_POLL_INTERVAL_SECONDS"]
        assert helper_result["runtime_sync"]["backend"]["ok"] is True
        assert helper_result["runtime_sync"]["worker"]["ok"] is True


def test_validate_ai_settings_returns_ok_for_mock(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "mock",
            "llm_model": "gpt-4o-mini",
            "llm_base_url": "",
            "llm_timeout_seconds": 60,
            "llm_api_key": "",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["provider"] == "mock"
    assert "Mock 模式" in body["message"]


def test_validate_ai_settings_uses_saved_api_key_when_form_key_missing(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}
    runtime_env = tmp_path / ".env.runtime"
    runtime_env.write_text(
        runtime_env.read_text(encoding="utf-8").replace("LLM_API_KEY=\n", "LLM_API_KEY=sk-saved-secret\n"),
        encoding="utf-8",
    )

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeHelperResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "OK"}],
                    }
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "openai",
            "llm_model": "gpt-4o-mini",
            "llm_base_url": "",
            "llm_timeout_seconds": 60,
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["used_saved_api_key"] is True
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer sk-saved-secret"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["input"] == [{"role": "user", "content": [{"type": "input_text", "text": "仅返回 OK"}]}]


def test_validate_ai_settings_prefers_runtime_saved_api_key_when_cached_settings_stale(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}
    runtime_env = tmp_path / ".env.runtime"
    runtime_env.write_text(
        runtime_env.read_text(encoding="utf-8").replace("LLM_API_KEY=\n", "LLM_API_KEY=sk-runtime-secret\n"),
        encoding="utf-8",
    )
    monkeypatch.setattr(platform_settings_service.settings, "LLM_API_KEY", "sk-cached-secret")

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["headers"] = headers
        return _FakeHelperResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "OK"}],
                    }
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "openai",
            "llm_model": "gpt-4o-mini",
            "llm_base_url": "",
            "llm_timeout_seconds": 60,
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["used_saved_api_key"] is True
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer sk-runtime-secret"


def test_validate_ai_settings_returns_failure_payload_for_missing_base_url(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "ollama_remote",
            "llm_model": "qwen2.5:7b",
            "llm_base_url": "",
            "llm_timeout_seconds": 30,
            "llm_api_key": "",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "Base URL" in body["message"]


def test_validate_ai_settings_normalizes_minimax_base_url(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        return _FakeHelperResponse({"choices": [{"message": {"content": "OK"}}]})

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "minimax",
            "llm_model": "MiniMax-M2.5",
            "llm_base_url": "api.minimaxi.com",
            "llm_wire_api": "chat_completions",
            "llm_timeout_seconds": 30,
            "llm_api_key": "mini-secret",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["provider"] == "minimax"
    assert body["resolved_base_url"] == "https://api.minimaxi.com/v1"
    assert captured["url"] == "https://api.minimaxi.com/v1/chat/completions"


def test_validate_ai_settings_returns_actual_base_url_after_custom_proxy_fallback(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url == "https://relay.example.com/v1/responses":
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "not found"}},
            )
        return _FakeHelperResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "OK"}],
                    }
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "custom_proxy",
            "llm_model": "gpt-5.4",
            "llm_base_url": "https://relay.example.com/v1",
            "llm_wire_api": "responses",
            "llm_timeout_seconds": 30,
            "llm_api_key": "relay-secret",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["provider"] == "custom_proxy"
    assert body["resolved_base_url"] == "https://relay.example.com"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/responses",
    ]


def test_list_ai_models_returns_actual_base_url_after_custom_proxy_fallback(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)
    captured_urls: list[str] = []

    def _fake_get(url: str, *, headers: dict[str, str], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("GET", url)
        if url == "https://relay.example.com/v1/models":
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "not found"}},
            )
        return _FakeHelperResponse(
            {
                "data": [
                    {"id": "gpt-5.4", "display_name": "GPT-5.4", "owned_by": "relay"},
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "get", _fake_get)

    response = client.post(
        "/api/v1/settings/ai/models",
        json={
            "llm_provider": "custom_proxy",
            "llm_base_url": "https://relay.example.com/v1",
            "llm_wire_api": "auto",
            "llm_timeout_seconds": 30,
            "llm_api_key": "relay-secret",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["provider"] == "custom_proxy"
    assert body["resolved_base_url"] == "https://relay.example.com"
    assert [item["id"] for item in body["models"]] == ["gpt-5.4"]
    assert captured_urls == [
        "https://relay.example.com/v1/models",
        "https://relay.example.com/models",
    ]


def test_validate_ai_settings_summarizes_html_502_error(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)

    def _fake_build_provider(**kwargs):  # type: ignore[no-untyped-def]
        class _BrokenProvider:
            def generate(self, request):  # type: ignore[no-untyped-def]
                http_request = httpx.Request("POST", "https://risingsun.top/v1/responses")
                http_response = httpx.Response(
                    502,
                    request=http_request,
                    headers={"content-type": "text/html; charset=UTF-8"},
                    text="""
<!DOCTYPE html>
<html lang="en-US">
<head><title>risingsun.top | 502: Bad gateway</title></head>
<body><h1>Bad gateway</h1><p>Cloudflare</p></body>
</html>
                    """.strip(),
                )
                raise httpx.HTTPStatusError("bad gateway", request=http_request, response=http_response)

        return SimpleNamespace(
            provider_name="custom_proxy",
            model="gpt-5.4",
            resolved_base_url="https://risingsun.top/v1",
            provider=_BrokenProvider(),
        )

    monkeypatch.setattr(platform_settings_service, "build_provider", _fake_build_provider)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "custom_proxy",
            "llm_model": "gpt-5.4",
            "llm_base_url": "https://risingsun.top/v1",
            "llm_timeout_seconds": 30,
            "llm_api_key": "sk-test",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False
    assert "Cloudflare 错误页" in body["message"]
    assert "502: Bad gateway" in body["message"]


def test_validate_ai_settings_rejects_legacy_openai_compatible_provider(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    client = _build_client(monkeypatch, tmp_path)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "openai_compatible",
            "llm_model": "gpt-5.4",
            "llm_base_url": "https://relay.example.com/v1",
            "llm_timeout_seconds": 30,
            "llm_api_key": "sk-test",
            "clear_llm_api_key": False,
        },
    )

    assert response.status_code == 422
