from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.db.base import Base
from app.db.models.enums import TaskExecutionStatus, TaskType, UserRole
from app.db.models.task_run import TaskRun
from app.db.session import SessionLocal, engine
from app.main import create_app
from app.services.ai import providers as providers_module
from app.services import platform_settings_service


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


def _build_client(monkeypatch, tmp_path, role: UserRole = UserRole.ADMIN) -> TestClient:  # type: ignore[no-untyped-def]
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
    return TestClient(app)


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
                "helper_result": {"compose_stdout": "ok"},
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
    monkeypatch.setattr(platform_settings_service.settings, "LLM_API_KEY", "sk-saved-secret")

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
            provider_name="openai_compatible",
            model="gpt-5.4",
            resolved_base_url="https://risingsun.top/v1",
            provider=_BrokenProvider(),
        )

    monkeypatch.setattr(platform_settings_service, "build_provider", _fake_build_provider)

    response = client.post(
        "/api/v1/settings/ai/validate",
        json={
            "llm_provider": "openai_compatible",
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
