from __future__ import annotations

import json
from types import SimpleNamespace

import httpx

from app.services.ai import model_pool_service
from app.services.ai.providers import LLMRequest


class _NoRedis:
    @classmethod
    def from_url(cls, *_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("redis disabled in unit test")


def _patch_runtime_pool(monkeypatch, nodes: list[dict]) -> None:  # type: ignore[no-untyped-def]
    raw_pool = json.dumps(nodes, ensure_ascii=False)

    def _fake_runtime_value(key: str, fallback: str = "") -> str:
        if key == "LLM_MODEL_POOL":
            return raw_pool
        if key == "LLM_PROVIDER":
            return "mock"
        return str(fallback or "")

    monkeypatch.setattr(model_pool_service, "read_runtime_env_value", _fake_runtime_value)
    monkeypatch.setattr(model_pool_service, "Redis", _NoRedis)
    model_pool_service.reset_local_model_pool_state()


def test_model_pool_selects_json_nodes_by_priority(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_runtime_pool(
        monkeypatch,
        [
            {
                "id": "ollama-fast",
                "provider": "ollama_remote",
                "model": "qwen2.5",
                "base_url": "http://ollama:11434",
                "priority": 1,
                "supports_json_mode": False,
                "supports_streaming": True,
            },
            {
                "id": "openai-json",
                "provider": "custom_proxy",
                "model": "gpt-4o-mini",
                "base_url": "https://relay.example/v1",
                "api_key": "sk-test",
                "priority": 2,
                "supports_json_mode": True,
                "supports_streaming": True,
            },
        ],
    )

    nodes = model_pool_service.select_model_pool_nodes(capability="json_mode", purpose="agent_decision")

    assert [node.id for node in nodes] == ["openai-json"]


def test_model_pool_falls_back_and_records_metrics(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_runtime_pool(
        monkeypatch,
        [
            {
                "id": "primary",
                "provider": "custom_proxy",
                "model": "gpt-primary",
                "base_url": "https://primary.example/v1",
                "api_key": "sk-primary",
                "priority": 1,
                "supports_json_mode": True,
            },
            {
                "id": "backup",
                "provider": "custom_proxy",
                "model": "gpt-backup",
                "base_url": "https://backup.example/v1",
                "api_key": "sk-backup",
                "priority": 2,
                "supports_json_mode": True,
            },
        ],
    )
    calls: list[str] = []

    def _fake_build_model_pool_provider(*, node, **_kwargs):  # type: ignore[no-untyped-def]
        class _Provider:
            wire_api = "responses"

            def generate(self, _request):
                calls.append(node.id)
                if node.id == "primary":
                    request = httpx.Request("POST", "https://primary.example/v1/responses")
                    response = httpx.Response(503, request=request)
                    raise httpx.HTTPStatusError("unavailable", request=request, response=response)
                return '{"reply_markdown":"备用模型成功","conversation_state":"answer"}'

        return SimpleNamespace(provider_name=node.provider_name, model=node.model, resolved_base_url=node.base_url, provider=_Provider())

    monkeypatch.setattr(model_pool_service, "build_model_pool_provider", _fake_build_model_pool_provider)

    result = model_pool_service.generate_with_model_pool(
        LLMRequest.from_text("继续"),
        capability="json_mode",
        purpose="agent_decision",
    )
    status = model_pool_service.get_model_pool_status()
    snapshots = {item["id"]: item for item in status["nodes"]}

    assert result.node.id == "backup"
    assert calls == ["primary", "backup"]
    assert [attempt.success for attempt in result.attempts] == [False, True]
    assert snapshots["primary"]["error_count"] == 1
    assert snapshots["backup"]["success_count"] == 1


def test_model_pool_streaming_filters_capability(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _patch_runtime_pool(
        monkeypatch,
        [
            {
                "id": "json-only",
                "provider": "custom_proxy",
                "model": "gpt-json",
                "base_url": "https://json.example/v1",
                "api_key": "sk-json",
                "priority": 1,
                "supports_json_mode": True,
                "supports_streaming": False,
            },
            {
                "id": "streaming",
                "provider": "ollama_remote",
                "model": "qwen2.5",
                "base_url": "http://ollama:11434",
                "priority": 2,
                "supports_json_mode": False,
                "supports_streaming": True,
            },
        ],
    )

    nodes = model_pool_service.select_model_pool_nodes(capability="streaming", purpose="streaming_reply")

    assert [node.id for node in nodes] == ["streaming"]
