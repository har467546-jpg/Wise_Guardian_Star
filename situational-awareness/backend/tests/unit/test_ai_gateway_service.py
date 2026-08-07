from __future__ import annotations

import json
from types import SimpleNamespace

import httpx

from app.services.ai import model_router_service
from app.services.ai.providers import LLMRequest


class _NoRedis:
    @classmethod
    def from_url(cls, *_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("redis disabled in unit test")


def _patch_gateway_runtime(monkeypatch, channels: list[dict]) -> None:  # type: ignore[no-untyped-def]
    class _Row:
        def __init__(self, payload: dict) -> None:
            self.id = payload["id"]
            self.name = payload["name"]
            self.provider = payload["provider"]
            self.api_base = payload["api_base"]
            self.api_key_ciphertext = payload.get("api_key_ciphertext")
            self.model_name = payload["model_name"]
            self.priority = payload.get("priority", 100)
            self.status = payload.get("status", "active")
            self.config_json = payload.get("config_json", {})

    monkeypatch.setattr(model_router_service, "Redis", _NoRedis)
    monkeypatch.setattr(model_router_service, "SessionLocal", lambda: SimpleNamespace(__enter__=lambda self: self, __exit__=lambda *args: None))  # type: ignore[assignment]
    monkeypatch.setattr(
        model_router_service,
        "_load_channels_from_db",
        lambda: [model_router_service._channel_from_model(_Row(item)) for item in channels],
    )
    model_router_service.reset_local_gateway_state()


def test_gateway_failover_records_cooldown(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_gateway_runtime(
        monkeypatch,
        [
            {
                "id": 1,
                "name": "primary",
                "provider": "custom_proxy",
                "api_base": "https://primary.example/v1",
                "api_key_ciphertext": "cipher",
                "model_name": "gpt-primary",
                "priority": 100,
                "status": "active",
                "config_json": {"supports_json_mode": True},
            },
            {
                "id": 2,
                "name": "backup",
                "provider": "custom_proxy",
                "api_base": "https://backup.example/v1",
                "api_key_ciphertext": "cipher",
                "model_name": "gpt-backup",
                "priority": 90,
                "status": "active",
                "config_json": {"supports_json_mode": True},
            },
        ],
    )
    calls: list[int] = []

    def _fake_build_gateway_provider(*, channel, **_kwargs):  # type: ignore[no-untyped-def]
        class _Provider:
            def generate(self, _request):
                calls.append(channel.id)
                if channel.id == 1:
                    request = httpx.Request("POST", channel.api_base)
                    response = httpx.Response(503, request=request)
                    raise httpx.HTTPStatusError("down", request=request, response=response)
                return '{"reply_markdown":"ok"}'

        return SimpleNamespace(provider_name=channel.provider_name, model=channel.model_name, resolved_base_url=channel.api_base, provider=_Provider())

    monkeypatch.setattr(model_router_service, "build_gateway_provider", _fake_build_gateway_provider)

    result = model_router_service.generate_with_gateway(LLMRequest.from_text("hi"))

    assert result.channel.id == 2
    assert calls == [1, 2]
    assert result.attempts[0].success is False
    assert result.attempts[1].success is True
    assert model_router_service.get_channel_health(1)["health_status"] == "cooldown"


def test_gateway_auth_failure_disables_channel(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_gateway_runtime(
        monkeypatch,
        [
            {
                "id": 3,
                "name": "auth",
                "provider": "openai",
                "api_base": "https://auth.example/v1",
                "api_key_ciphertext": "cipher",
                "model_name": "gpt-auth",
                "priority": 100,
                "status": "active",
                "config_json": {"supports_json_mode": True},
            }
        ],
    )

    disabled: list[int] = []
    monkeypatch.setattr(model_router_service, "disable_gateway_channel", lambda channel_id, reason="": disabled.append(int(channel_id)))

    def _fake_build_gateway_provider(*, channel, **_kwargs):  # type: ignore[no-untyped-def]
        class _Provider:
            def generate(self, _request):
                request = httpx.Request("POST", channel.api_base)
                response = httpx.Response(401, request=request)
                raise httpx.HTTPStatusError("unauthorized", request=request, response=response)

        return SimpleNamespace(provider_name=channel.provider_name, model=channel.model_name, resolved_base_url=channel.api_base, provider=_Provider())

    monkeypatch.setattr(model_router_service, "build_gateway_provider", _fake_build_gateway_provider)

    try:
        model_router_service.generate_with_gateway(LLMRequest.from_text("hi"))
    except Exception:
        pass

    assert disabled == [3]


def test_gateway_secure_ssh_filters_to_local_channels(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_gateway_runtime(
        monkeypatch,
        [
            {
                "id": 4,
                "name": "remote",
                "provider": "openai",
                "api_base": "https://remote.example/v1",
                "api_key_ciphertext": "cipher",
                "model_name": "gpt-remote",
                "priority": 100,
                "status": "active",
                "config_json": {"supports_json_mode": True},
            },
            {
                "id": 5,
                "name": "local",
                "provider": "ollama",
                "api_base": "http://ollama:11434",
                "api_key_ciphertext": None,
                "model_name": "qwen",
                "priority": 90,
                "status": "active",
                "config_json": {"supports_streaming": True, "tags": ["local"]},
            },
        ],
    )

    channels = model_router_service.select_gateway_channels(task_type="secure_ssh", capability="any")

    assert [channel.id for channel in channels] == [5]
