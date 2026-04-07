from __future__ import annotations

import httpx
import pytest

from app.services.ai import gateway as gateway_module
from app.services.ai import providers as providers_module
from app.services.ai.gateway import LLMGateway


class _FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self._payload


class _FakeStreamResponse:
    def __init__(
        self,
        *,
        lines: list[str] | None = None,
        error: Exception | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._lines = lines or []
        self._error = error
        self.headers = headers or {"content-type": "application/json; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def raise_for_status(self) -> None:
        return None

    def iter_lines(self):
        for line in self._lines:
            yield line
        if self._error is not None:
            raise self._error


@pytest.fixture(autouse=True)
def _use_test_runtime_values(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(gateway_module, "read_runtime_env_value", lambda _key, fallback="": str(fallback))


@pytest.fixture(autouse=True)
def _clear_auto_wire_api_preferences() -> None:
    providers_module._AUTO_WIRE_API_PREFERENCES.clear()
    yield
    providers_module._AUTO_WIRE_API_PREFERENCES.clear()


def _assert_conservative_model_headers(
    headers: dict[str, str],
    *,
    api_key: str = "",
    expect_content_type: bool,
) -> None:
    assert headers["Accept"] == "application/json"
    assert headers["Accept-Language"] == providers_module.DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE
    assert headers["User-Agent"] == providers_module.DEFAULT_OPENAI_COMPAT_USER_AGENT
    assert headers["X-Client-Name"] == providers_module.DEFAULT_MODEL_REQUEST_CLIENT_NAME
    if expect_content_type:
        assert headers["Content-Type"] == "application/json"
    else:
        assert "Content-Type" not in headers
    if api_key:
        assert headers["Authorization"] == f"Bearer {api_key}"
    else:
        assert "Authorization" not in headers


def test_custom_proxy_provider_uses_custom_base_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "兼容接口输出"}],
                    }
                ]
            }
        )

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "custom_proxy")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "兼容接口输出"
    assert captured["url"] == "https://relay.example.com/v1/responses"
    assert captured["timeout"] == 33
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="relay-token", expect_content_type=True)
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["instructions"] == providers_module.DEFAULT_SYSTEM_PROMPT
    assert payload["input"] == [
        {
            "role": "user",
            "content": [{"type": "input_text", "text": "请生成摘要"}],
        }
    ]


def test_gateway_prefers_runtime_env_values_over_cached_settings(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}
    runtime_values = {
        "LLM_PROVIDER": "custom_proxy",
        "LLM_MODEL": "gpt-5.4",
        "LLM_BASE_URL": "relay.runtime.example.com/models",
        "LLM_WIRE_API": "chat_completions",
        "LLM_TIMEOUT_SECONDS": "41",
        "LLM_API_KEY": "sk-runtime-new",
    }

    def _fake_runtime_env_value(key: str, fallback: str = "") -> str:
        return str(runtime_values.get(key, fallback))

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _FakeResponse({"choices": [{"message": {"content": "运行时配置输出"}}]})

    monkeypatch.setattr(gateway_module, "read_runtime_env_value", _fake_runtime_env_value)
    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 20)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "sk-cached-old")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "运行时配置输出"
    assert captured["url"] == "https://relay.runtime.example.com/v1/chat/completions"
    assert captured["timeout"] == 41
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="sk-runtime-new", expect_content_type=True)


def test_build_provider_rejects_legacy_openai_compatible_provider() -> None:
    with pytest.raises(ValueError, match="当前模型接入方式不受支持"):
        providers_module.build_provider(
            provider_name="openai_compatible",
            model="gpt-5.4",
            base_url="relay.example.com",
            timeout_seconds=20,
        )


def test_build_provider_rejects_legacy_openai_compatible_provider_even_with_mock_fallback() -> None:
    with pytest.raises(ValueError, match="当前模型接入方式不受支持"):
        providers_module.build_provider(
            provider_name="openai_compatible",
            model="gpt-5.4",
            base_url="relay.example.com",
            timeout_seconds=20,
            fallback_to_mock=True,
        )


def test_build_provider_applies_minimax_defaults() -> None:
    result = providers_module.build_provider(
        provider_name="minimax",
        model="MiniMax-M2.5",
        base_url="",
        timeout_seconds=20,
        api_key="minimax-key",
        wire_api="",
    )

    assert result.provider_name == "minimax"
    assert result.resolved_base_url == providers_module.DEFAULT_MINIMAX_BASE_URL
    assert isinstance(result.provider, providers_module.OpenAICompatibleProvider)
    assert result.provider.wire_api == "chat_completions"


@pytest.mark.parametrize("provider_name", ["openai", "minimax", "custom_proxy"])
def test_build_provider_requires_api_key_for_remote_openai_like_providers(provider_name: str) -> None:
    with pytest.raises(ValueError, match="API Key"):
        providers_module.build_provider(
            provider_name=provider_name,
            model="gpt-5.4",
            base_url="https://relay.example.com/v1" if provider_name == "custom_proxy" else "",
            timeout_seconds=20,
            api_key="",
        )


def test_build_provider_can_fallback_to_mock_when_custom_proxy_api_key_missing() -> None:
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="",
        fallback_to_mock=True,
    )

    assert result.provider_name == "mock"
    assert isinstance(result.provider, providers_module.MockProvider)
    assert "API Key" in result.provider.notice


@pytest.mark.parametrize(
    ("provider_name", "base_url", "expected"),
    [
        ("custom_proxy", "relay.example.com", ["https://relay.example.com/v1", "https://relay.example.com"]),
        ("custom_proxy", "https://relay.example.com/models", ["https://relay.example.com/v1", "https://relay.example.com"]),
        ("custom_proxy", "https://relay.example.com/responses", ["https://relay.example.com/v1", "https://relay.example.com"]),
        ("custom_proxy", "https://relay.example.com/chat/completions", ["https://relay.example.com/v1", "https://relay.example.com"]),
        ("custom_proxy", "https://relay.example.com/v1", ["https://relay.example.com/v1"]),
        ("custom_proxy", "https://relay.example.com/private/openai", ["https://relay.example.com/private/openai"]),
        ("minimax", "api.minimaxi.com", ["https://api.minimaxi.com/v1"]),
        ("minimax", "https://api.minimax.io/v1", ["https://api.minimax.io/v1"]),
        ("ollama_remote", "192.168.1.20:11434/api/tags", ["http://192.168.1.20:11434"]),
    ],
)
def test_resolve_provider_base_url_candidates_matrix(provider_name: str, base_url: str, expected: list[str]) -> None:
    assert providers_module.resolve_provider_base_url_candidates(provider_name, base_url) == expected


def test_custom_proxy_runtime_probe_candidates_include_root_for_v1_base_url() -> None:
    assert providers_module.resolve_provider_base_url_candidates(
        "custom_proxy",
        "https://relay.example.com/v1",
        allow_runtime_probe_fallback=True,
    ) == ["https://relay.example.com/v1", "https://relay.example.com"]


def test_custom_proxy_runtime_probe_candidates_include_v1_for_custom_path() -> None:
    assert providers_module.resolve_provider_base_url_candidates(
        "custom_proxy",
        "https://relay.example.com/anthropic",
        allow_runtime_probe_fallback=True,
    ) == ["https://relay.example.com/anthropic", "https://relay.example.com/v1"]


def test_resolve_provider_base_url_normalizes_openai_like_urls() -> None:
    assert providers_module.resolve_provider_base_url("custom_proxy", "relay.example.com") == "https://relay.example.com/v1"
    assert providers_module.resolve_provider_base_url("custom_proxy", "https://relay.example.com/models") == "https://relay.example.com/v1"
    assert providers_module.resolve_provider_base_url("custom_proxy", "https://relay.example.com/responses") == "https://relay.example.com/v1"
    assert providers_module.resolve_provider_base_url("custom_proxy", "https://relay.example.com/chat/completions") == "https://relay.example.com/v1"
    assert providers_module.resolve_provider_base_url("custom_proxy", "https://relay.example.com/private/openai") == "https://relay.example.com/private/openai"
    assert providers_module.resolve_provider_base_url("openai", "/responses") == providers_module.DEFAULT_OPENAI_BASE_URL
    assert providers_module.resolve_provider_base_url("custom_proxy", "/responses") == ""


def test_resolve_provider_base_url_strips_ollama_endpoint() -> None:
    assert providers_module.resolve_provider_base_url("ollama_remote", "192.168.1.20:11434/api/tags") == "http://192.168.1.20:11434"


def test_ollama_remote_provider_uses_generate_api(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse({"response": "Ollama 输出"})

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "ollama_remote")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "qwen2.5:7b")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "http://ollama.example.com:11434")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 21)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "ollama-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Ollama 输出"
    assert captured["url"] == "http://ollama.example.com:11434/api/generate"
    assert captured["timeout"] == 21
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="ollama-token", expect_content_type=True)
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert "system:\n" in str(payload["prompt"])
    assert "user:\n请生成摘要" in str(payload["prompt"])


def test_gateway_falls_back_to_mock_when_provider_call_fails(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _fake_post(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("network down")

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-4o-mini")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 20)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "sk-test")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert "AI 调用失败" in summary
    assert "请生成摘要" in summary


def test_custom_proxy_provider_auto_prefers_responses_then_falls_back_to_chat(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url.endswith("/responses"):
            return httpx.Response(
                404,
                request=request,
                json={
                    "error": {
                        "message": "Responses API is not supported by this relay.",
                    }
                },
            )
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "Chat 输出"}}]},
        )

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "custom_proxy")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-5.1-codex-mini")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "auto")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Chat 输出"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/chat/completions",
    ]


def test_custom_proxy_provider_auto_reuses_cached_chat_completions_after_first_fallback(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url.endswith("/responses"):
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "Responses API is not supported by this relay."}},
            )
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "Chat 输出"}}]},
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    first_provider = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        wire_api="auto",
        timeout_seconds=30,
        api_key="relay-token",
        fallback_to_mock=False,
    )
    second_provider = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        wire_api="auto",
        timeout_seconds=30,
        api_key="relay-token",
        fallback_to_mock=False,
    )

    assert first_provider.provider.generate(providers_module.LLMRequest.from_text("请生成摘要")) == "Chat 输出"
    assert second_provider.provider.generate(providers_module.LLMRequest.from_text("请继续")) == "Chat 输出"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/chat/completions",
        "https://relay.example.com/v1/chat/completions",
    ]


def test_custom_proxy_provider_auto_reuses_cached_chat_completions_for_streaming(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_stream(method: str, url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        del method, headers, json, timeout
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url.endswith("/responses"):
            return _FakeStreamResponse(
                error=httpx.HTTPStatusError(
                    "Responses API is not supported by this relay.",
                    request=request,
                    response=httpx.Response(404, request=request, json={"error": {"message": "Responses API is not supported by this relay."}}),
                )
            )
        return _FakeStreamResponse(
            lines=[
                'data: {"choices":[{"delta":{"content":"Chat "}}]}',
                'data: {"choices":[{"delta":{"content":"输出"}}]}',
                "data: [DONE]",
            ]
        )

    monkeypatch.setattr(providers_module.httpx, "stream", _fake_stream)

    first_provider = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        wire_api="auto",
        timeout_seconds=30,
        api_key="relay-token",
        fallback_to_mock=False,
    )
    second_provider = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        wire_api="auto",
        timeout_seconds=30,
        api_key="relay-token",
        fallback_to_mock=False,
    )

    assert "".join(first_provider.provider.stream_generate(providers_module.LLMRequest.from_text("请生成摘要"))) == "Chat 输出"
    assert "".join(second_provider.provider.stream_generate(providers_module.LLMRequest.from_text("请继续"))) == "Chat 输出"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/chat/completions",
        "https://relay.example.com/v1/chat/completions",
    ]


def test_custom_proxy_provider_auto_accepts_anthropic_style_chat_payload(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url.endswith("/responses"):
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "Responses API is not supported by this relay."}},
            )
        return httpx.Response(
            200,
            request=request,
            json={
                "id": "msg_123",
                "role": "assistant",
                "content": [{"type": "text", "text": "Anthropic 风格输出"}],
            },
        )

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "custom_proxy")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "MiniMax-M2.5")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "auto")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Anthropic 风格输出"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/chat/completions",
    ]


def test_gateway_surfaces_upstream_error_payload_instead_of_missing_choices(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        return _FakeResponse({"error": {"message": "relay returned invalid model mapping"}})

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "custom_proxy")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "MiniMax-M2.5")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com/v1")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "chat_completions")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert "AI 调用失败" in summary
    assert "relay returned invalid model mapping" in summary


def test_openai_chat_completions_merges_multiple_system_messages(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse({"choices": [{"message": {"content": "OK"}}]})

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    provider_result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="MiniMax-M2.5",
        base_url="https://relay.example.com/v1",
        wire_api="chat_completions",
        timeout_seconds=20,
        api_key="relay-token",
    )

    request = providers_module.LLMRequest(
        messages=[
            providers_module.LLMMessage.from_text("system", "系统指令 A"),
            providers_module.LLMMessage.from_text("system", "系统指令 B"),
            providers_module.LLMMessage.from_text("user", "用户问题"),
        ]
    )
    summary = provider_result.provider.generate(request)

    assert summary == "OK"
    assert captured["url"] == "https://relay.example.com/v1/chat/completions"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["messages"] == [
        {"role": "system", "content": "系统指令 A\n\n系统指令 B"},
        {"role": "user", "content": "用户问题"},
    ]


def test_custom_proxy_provider_can_force_responses_api(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeResponse(
            {
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "Responses 直连输出"}],
                    }
                ]
            }
        )

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "custom_proxy")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-5.3-codex")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Responses 直连输出"
    assert captured["url"] == "https://relay.example.com/v1/responses"


def test_custom_proxy_runtime_falls_back_to_root_base_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
        return httpx.Response(
            200,
            request=request,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "根地址输出"}],
                    }
                ]
            },
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    summary = result.provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert summary == "根地址输出"


def test_custom_proxy_runtime_falls_back_from_custom_path_to_v1_base_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if url in {
            "https://relay.example.com/anthropic/responses",
            "https://relay.example.com/anthropic/chat/completions",
        }:
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "not found"}},
            )
        if url == "https://relay.example.com/responses":
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "not found"}},
            )
        if url == "https://relay.example.com/v1/responses":
            return httpx.Response(
                404,
                request=request,
                json={"error": {"message": "not found"}},
            )
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "根地址输出", "role": "assistant"}}]},
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="MiniMax-M2.7",
        base_url="https://relay.example.com/anthropic",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="auto",
    )

    summary = result.provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert summary == "根地址输出"
    assert captured_urls == [
        "https://relay.example.com/anthropic/responses",
        "https://relay.example.com/anthropic/chat/completions",
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/chat/completions",
    ]
    assert result.provider.base_url == "https://relay.example.com/v1"

@pytest.mark.parametrize("status_code", [401, 403])
def test_custom_proxy_runtime_does_not_switch_base_url_for_auth_errors(monkeypatch, status_code: int) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        return httpx.Response(
            status_code,
            request=request,
            json={"error": {"message": "auth failed"}},
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    with pytest.raises(httpx.HTTPStatusError):
        result.provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert captured_urls == ["https://relay.example.com/v1/responses"]
    assert result.provider.base_url == "https://relay.example.com/v1"


def test_custom_proxy_runtime_does_not_switch_base_url_for_timeout(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    with pytest.raises(httpx.ReadTimeout):
        result.provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert set(captured_urls) == {"https://relay.example.com/v1/responses"}
    assert "https://relay.example.com/responses" not in captured_urls
    assert result.provider.base_url == "https://relay.example.com/v1"


def test_custom_proxy_runtime_does_not_switch_base_url_for_5xx(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        return httpx.Response(
            502,
            request=request,
            json={"error": {"message": "bad gateway"}},
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    with pytest.raises(httpx.HTTPStatusError):
        result.provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert set(captured_urls) == {"https://relay.example.com/v1/responses"}
    assert "https://relay.example.com/responses" not in captured_urls
    assert result.provider.base_url == "https://relay.example.com/v1"


def test_custom_proxy_provider_retries_transient_502(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request("POST", url)
        if len(captured_urls) == 1:
            return httpx.Response(
                502,
                request=request,
                headers={"content-type": "text/html; charset=UTF-8"},
                text="""
<!DOCTYPE html>
<html lang=\"en-US\">
<head><title>relay.example.com | 502: Bad gateway</title></head>
<body><h1>Bad gateway</h1><p>Cloudflare</p></body>
</html>
                """.strip(),
            )
        return httpx.Response(
            200,
            request=request,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "重试成功"}],
                    }
                ]
            },
        )

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    provider = providers_module.OpenAICompatibleProvider(
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    summary = provider.generate(providers_module.LLMRequest.from_text("请生成摘要"))

    assert summary == "重试成功"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/v1/responses",
    ]


def test_chat_completions_maps_structured_message_history(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_post(url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse({"choices": [{"message": {"content": "结构化历史输出"}}]})

    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)
    provider = providers_module.OpenAICompatibleProvider(
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="chat_completions",
    )

    summary = provider.generate(
        providers_module.LLMRequest(
            messages=[
                providers_module.LLMMessage.from_text("system", "系统规则"),
                providers_module.LLMMessage.from_text("user", "第一轮用户输入"),
                providers_module.LLMMessage.from_text("assistant", "第一轮助手回复"),
                providers_module.LLMMessage.from_text("user", "第二轮用户输入"),
            ]
        )
    )

    assert summary == "结构化历史输出"
    assert captured["url"] == "https://relay.example.com/v1/chat/completions"
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["messages"] == [
        {"role": "system", "content": "系统规则"},
        {"role": "user", "content": "第一轮用户输入"},
        {"role": "assistant", "content": "第一轮助手回复"},
        {"role": "user", "content": "第二轮用户输入"},
    ]


def test_responses_input_degrades_assistant_history_to_user_context() -> None:
    request = providers_module.LLMRequest(
        messages=[
            providers_module.LLMMessage.from_text("system", "系统规则"),
            providers_module.LLMMessage.from_text("assistant", "上一轮助手回复"),
            providers_module.LLMMessage.from_text("user", "本轮用户问题"),
        ]
    )

    payload = providers_module._build_openai_responses_input(request)

    assert payload == [
        {
            "role": "user",
            "content": [{"type": "input_text", "text": "[assistant]\n上一轮助手回复"}],
        },
        {
            "role": "user",
            "content": [{"type": "input_text", "text": "本轮用户问题"}],
        },
    ]


def test_list_remote_models_uses_models_endpoint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_get(url: str, *, headers: dict[str, str], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _FakeResponse(
            {
                "data": [
                    {"id": "gpt-5.3-codex", "display_name": "GPT-5.3 Codex", "owned_by": "openai"},
                    {"id": "gpt-5.4", "display_name": "GPT-5.4", "owned_by": "openai"},
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "get", _fake_get)

    resolved_base_url, models = providers_module.list_remote_models(
        provider_name="custom_proxy",
        base_url="https://relay.example.com/responses",
        api_key="relay-token",
        timeout_seconds=15,
    )

    assert resolved_base_url == "https://relay.example.com/v1"
    assert captured["url"] == "https://relay.example.com/v1/models"
    assert captured["timeout"] == 15
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="relay-token", expect_content_type=False)
    assert [item.id for item in models] == ["gpt-5.3-codex", "gpt-5.4"]


def test_list_remote_models_falls_back_to_root_base_url_for_custom_proxy(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
        return httpx.Response(
            200,
            request=request,
            json={
                "data": [
                    {"id": "gpt-5.4", "display_name": "GPT-5.4", "owned_by": "relay"},
                ]
            },
        )

    monkeypatch.setattr(providers_module.httpx, "get", _fake_get)

    resolved_base_url, models = providers_module.list_remote_models(
        provider_name="custom_proxy",
        base_url="https://relay.example.com/v1",
        api_key="relay-token",
        timeout_seconds=15,
    )

    assert resolved_base_url == "https://relay.example.com"
    assert captured_urls == [
        "https://relay.example.com/v1/models",
        "https://relay.example.com/models",
    ]
    assert [item.id for item in models] == ["gpt-5.4"]


def test_list_remote_models_uses_ollama_tags_endpoint(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_get(url: str, *, headers: dict[str, str], timeout: int):  # type: ignore[no-untyped-def]
        captured["url"] = url
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _FakeResponse(
            {
                "models": [
                    {"name": "qwen2.5:7b"},
                    {"name": "llama3.1:8b"},
                ]
            }
        )

    monkeypatch.setattr(providers_module.httpx, "get", _fake_get)

    resolved_base_url, models = providers_module.list_remote_models(
        provider_name="ollama_remote",
        base_url="http://ollama.example.com:11434/api/tags",
        api_key="ollama-token",
        timeout_seconds=18,
    )

    assert resolved_base_url == "http://ollama.example.com:11434"
    assert captured["url"] == "http://ollama.example.com:11434/api/tags"
    assert captured["timeout"] == 18
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="ollama-token", expect_content_type=False)
    assert [item.id for item in models] == ["qwen2.5:7b", "llama3.1:8b"]


def test_list_remote_models_rejects_html_response(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _fake_get(url: str, *, headers: dict[str, str], timeout: int):  # type: ignore[no-untyped-def]
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            request=request,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"<html>gateway page</html>",
        )

    monkeypatch.setattr(providers_module.httpx, "get", _fake_get)

    try:
        providers_module.list_remote_models(
            provider_name="custom_proxy",
            base_url="https://relay.example.com",
            api_key="relay-token",
            timeout_seconds=15,
        )
    except ValueError as exc:
        assert "API 根地址" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_list_remote_models_requires_api_key_for_custom_proxy() -> None:
    with pytest.raises(ValueError, match="API Key"):
        providers_module.list_remote_models(
            provider_name="custom_proxy",
            base_url="https://relay.example.com",
            api_key="",
            timeout_seconds=15,
        )


def test_custom_proxy_provider_stream_generate_reads_responses_stream(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _fake_stream(method: str, url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        assert method == "POST"
        assert url == "https://relay.example.com/v1/responses"
        assert json["stream"] is True
        return _FakeStreamResponse(
            lines=[
                'data: {"type":"response.output_text.delta","delta":"实时"}',
                'data: {"type":"response.output_text.delta","delta":"输出"}',
                "data: [DONE]",
            ]
        )

    monkeypatch.setattr(providers_module.httpx, "stream", _fake_stream)
    provider = providers_module.OpenAICompatibleProvider(
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    chunks = list(provider.stream_generate(providers_module.LLMRequest.from_text("请生成摘要")))

    assert chunks == ["实时", "输出"]


def test_custom_proxy_stream_generate_falls_back_to_root_base_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured_urls: list[str] = []

    class _ErrorStreamResponse(_FakeStreamResponse):
        def __init__(self, response: httpx.Response) -> None:
            super().__init__(lines=[])
            self._response = response

        def raise_for_status(self) -> None:
            self._response.raise_for_status()

    def _fake_stream(method: str, url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured_urls.append(url)
        request = httpx.Request(method, url)
        if url == "https://relay.example.com/v1/responses":
            return _ErrorStreamResponse(
                httpx.Response(
                    404,
                    request=request,
                    json={"error": {"message": "not found"}},
                )
            )
        return _FakeStreamResponse(
            lines=[
                'data: {"type":"response.output_text.delta","delta":"根地址"}',
                'data: {"type":"response.output_text.delta","delta":"流式输出"}',
            ]
        )

    monkeypatch.setattr(providers_module.httpx, "stream", _fake_stream)
    result = providers_module.build_provider(
        provider_name="custom_proxy",
        model="gpt-5.4",
        base_url="https://relay.example.com/v1",
        timeout_seconds=20,
        api_key="relay-token",
        wire_api="responses",
    )

    chunks = list(result.provider.stream_generate(providers_module.LLMRequest.from_text("请生成摘要")))

    assert chunks == ["根地址", "流式输出"]
    assert result.provider.base_url == "https://relay.example.com"
    assert captured_urls == [
        "https://relay.example.com/v1/responses",
        "https://relay.example.com/responses",
    ]


def test_ollama_remote_provider_stream_generate_falls_back_to_generate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    def _fake_stream(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("stream down")

    monkeypatch.setattr(providers_module.httpx, "stream", _fake_stream)
    provider = providers_module.OllamaRemoteProvider(
        model="qwen2.5:7b",
        base_url="http://ollama.example.com:11434",
        timeout_seconds=20,
    )
    monkeypatch.setattr(provider, "generate", lambda request: "回放结果")

    chunks = list(provider.stream_generate(providers_module.LLMRequest.from_text("请生成摘要")))

    assert "".join(chunks) == "回放结果"


def test_ollama_remote_provider_stream_generate_uses_conservative_headers(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def _fake_stream(method: str, url: str, *, headers: dict[str, str], json: dict[str, object], timeout: int):  # type: ignore[no-untyped-def]
        captured["method"] = method
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _FakeStreamResponse(lines=['{"response":"实时输出"}'])

    monkeypatch.setattr(providers_module.httpx, "stream", _fake_stream)
    provider = providers_module.OllamaRemoteProvider(
        model="qwen2.5:7b",
        base_url="http://ollama.example.com:11434",
        timeout_seconds=20,
        api_key="ollama-token",
    )

    chunks = list(provider.stream_generate(providers_module.LLMRequest.from_text("请生成摘要")))

    assert chunks == ["实时输出"]
    assert captured["method"] == "POST"
    assert captured["url"] == "http://ollama.example.com:11434/api/generate"
    assert captured["timeout"] == 20
    headers = captured["headers"]
    assert isinstance(headers, dict)
    _assert_conservative_model_headers(headers, api_key="ollama-token", expect_content_type=True)
