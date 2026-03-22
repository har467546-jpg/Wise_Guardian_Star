from __future__ import annotations

import httpx

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
    def __init__(self, *, lines: list[str] | None = None, error: Exception | None = None) -> None:
        self._lines = lines or []
        self._error = error

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


def test_openai_compatible_provider_uses_custom_base_url(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "openai_compatible")
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
    assert headers["Authorization"] == "Bearer relay-token"
    assert headers["Accept"] == "application/json"
    assert "User-Agent" in headers
    payload = captured["json"]
    assert isinstance(payload, dict)
    assert payload["instructions"] == providers_module.DEFAULT_SYSTEM_PROMPT
    assert payload["input"] == [
        {
            "role": "user",
            "content": [{"type": "input_text", "text": "请生成摘要"}],
        }
    ]


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
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Ollama 输出"
    assert captured["url"] == "http://ollama.example.com:11434/api/generate"
    assert captured["timeout"] == 21
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


def test_openai_compatible_provider_auto_prefers_responses_then_falls_back_to_chat(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "openai_compatible")
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


def test_openai_compatible_provider_can_force_responses_api(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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

    monkeypatch.setattr(gateway_module.settings, "LLM_PROVIDER", "openai_compatible")
    monkeypatch.setattr(gateway_module.settings, "LLM_MODEL", "gpt-5.3-codex")
    monkeypatch.setattr(gateway_module.settings, "LLM_BASE_URL", "https://relay.example.com")
    monkeypatch.setattr(gateway_module.settings, "LLM_WIRE_API", "responses")
    monkeypatch.setattr(gateway_module.settings, "LLM_TIMEOUT_SECONDS", 33)
    monkeypatch.setattr(gateway_module.settings, "LLM_API_KEY", "relay-token")
    monkeypatch.setattr(providers_module.httpx, "post", _fake_post)

    summary = LLMGateway().summarize("请生成摘要")

    assert summary == "Responses 直连输出"
    assert captured["url"] == "https://relay.example.com/responses"


def test_openai_compatible_provider_retries_transient_502(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
        provider_name="openai_compatible",
        base_url="https://relay.example.com/v1",
        api_key="relay-token",
        timeout_seconds=15,
    )

    assert resolved_base_url == "https://relay.example.com/v1"
    assert captured["url"] == "https://relay.example.com/v1/models"
    assert captured["timeout"] == 15
    assert [item.id for item in models] == ["gpt-5.3-codex", "gpt-5.4"]


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
            provider_name="openai_compatible",
            base_url="https://relay.example.com",
            api_key="relay-token",
            timeout_seconds=15,
        )
    except ValueError as exc:
        assert "API 根地址" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_openai_compatible_provider_stream_generate_reads_responses_stream(monkeypatch) -> None:  # type: ignore[no-untyped-def]
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
