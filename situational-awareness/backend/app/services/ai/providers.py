from __future__ import annotations

import json
from dataclasses import dataclass, field
from time import sleep
from typing import Any, Iterator, Literal

import httpx


DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_SYSTEM_PROMPT = "你是资产态势感知平台的安全分析助手，请使用简洁中文输出可执行结论。"
DEFAULT_OPENAI_COMPAT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"
DEFAULT_TRANSIENT_RETRY_ATTEMPTS = 3


@dataclass(slots=True)
class LLMContentBlock:
    type: Literal["text"] = "text"
    text: str = ""

    def __post_init__(self) -> None:
        self.type = "text"
        self.text = str(self.text or "")


@dataclass(slots=True)
class LLMMessage:
    role: str
    content: list[LLMContentBlock] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.role = _normalize_message_role(self.role)
        normalized_content: list[LLMContentBlock] = []
        for item in self.content:
            if isinstance(item, LLMContentBlock):
                block = item
            elif isinstance(item, dict):
                block = LLMContentBlock(
                    type="text",
                    text=str(item.get("text") or ""),
                )
            else:
                continue
            if block.text.strip():
                normalized_content.append(block)
        self.content = normalized_content

    @classmethod
    def from_text(cls, role: str, text: str) -> "LLMMessage":
        normalized_text = str(text or "")
        if not normalized_text.strip():
            return cls(role=role, content=[])
        return cls(role=role, content=[LLMContentBlock(text=normalized_text)])

    def text_content(self) -> str:
        return "\n".join(block.text.strip() for block in self.content if block.text.strip()).strip()


@dataclass(slots=True)
class LLMRequest:
    messages: list[LLMMessage] = field(default_factory=list)

    def __post_init__(self) -> None:
        normalized_messages: list[LLMMessage] = []
        for item in self.messages:
            if isinstance(item, LLMMessage):
                message = item
            elif isinstance(item, dict):
                message = LLMMessage(
                    role=str(item.get("role") or "user"),
                    content=item.get("content") if isinstance(item.get("content"), list) else [],
                )
            else:
                continue
            if message.text_content():
                normalized_messages.append(message)
        self.messages = normalized_messages

    @classmethod
    def from_text(cls, prompt: str, *, system_prompt: str = DEFAULT_SYSTEM_PROMPT) -> "LLMRequest":
        messages: list[LLMMessage] = []
        normalized_system_prompt = str(system_prompt or "")
        normalized_prompt = str(prompt or "")
        if normalized_system_prompt.strip():
            messages.append(LLMMessage.from_text("system", normalized_system_prompt))
        if normalized_prompt.strip():
            messages.append(LLMMessage.from_text("user", normalized_prompt))
        return cls(messages=messages)

    def system_instructions(self) -> str:
        parts = [message.text_content() for message in self.messages if message.role == "system" and message.text_content()]
        return "\n\n".join(parts).strip()

    def conversation_messages(self) -> list[LLMMessage]:
        return [message for message in self.messages if message.role != "system" and message.text_content()]

    def flattened_text(self) -> str:
        parts: list[str] = []
        for message in self.messages:
            text = message.text_content()
            if not text:
                continue
            parts.append(f"{message.role}:\n{text}")
        return "\n\n".join(parts).strip()


@dataclass(slots=True)
class RemoteModelOption:
    id: str
    display_name: str | None = None
    owned_by: str | None = None


def _join_endpoint(base_url: str, suffix: str) -> str:
    normalized_base = str(base_url or "").strip().rstrip("/")
    normalized_suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    if normalized_base.endswith(normalized_suffix):
        return normalized_base
    return f"{normalized_base}{normalized_suffix}"


def _strip_endpoint_suffix(base_url: str, suffixes: list[str]) -> str:
    normalized = str(base_url or "").strip().rstrip("/")
    for suffix in suffixes:
        if normalized.endswith(suffix):
            trimmed = normalized[: -len(suffix)].rstrip("/")
            return trimmed or normalized
    return normalized


def _parse_json_response(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception as exc:
        content_type = str(response.headers.get("content-type") or "").lower()
        if "text/html" in content_type:
            raise ValueError("上游返回页面内容，请检查 Base URL 是否指向 API 根地址") from exc
        raise ValueError("上游返回非 JSON 响应，请检查 Base URL 是否正确") from exc
    if not isinstance(payload, dict):
        raise ValueError("上游返回格式不符合预期")
    return payload


def _normalize_message_role(role: str | None) -> str:
    normalized = str(role or "user").strip().lower() or "user"
    if normalized not in {"system", "user", "assistant"}:
        return "user"
    return normalized


def _openai_message_text(message: LLMMessage) -> str:
    return message.text_content()


def _build_openai_chat_messages(request: LLMRequest) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    for item in request.messages:
        text = _openai_message_text(item)
        if not text:
            continue
        messages.append({"role": item.role, "content": text})
    return messages


def _build_openai_responses_input(request: LLMRequest) -> list[dict[str, Any]]:
    input_messages: list[dict[str, Any]] = []
    for item in request.conversation_messages():
        role = item.role if item.role == "user" else "user"
        content_blocks = [
            {
                "type": "input_text",
                "text": block.text if item.role == "user" else f"[assistant]\n{block.text}",
            }
            for block in item.content
            if block.text.strip()
        ]
        if not content_blocks:
            continue
        input_messages.append({"role": role, "content": content_blocks})
    return input_messages


def _render_ollama_prompt(request: LLMRequest) -> str:
    sections: list[str] = []
    instructions = request.system_instructions()
    if instructions:
        sections.append(f"system:\n{instructions}")
    for message in request.conversation_messages():
        sections.append(f"{message.role}:\n{message.text_content()}")
    return "\n\n".join(section for section in sections if section.strip()).strip()


def _extract_openai_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("模型返回缺少 choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = str(item.get("text") or "").strip()
                if text:
                    parts.append(text)
        if parts:
            return "\n".join(parts)
    raise ValueError("模型返回缺少可读取内容")


def _extract_openai_responses_content(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    output = payload.get("output")
    if not isinstance(output, list) or not output:
        raise ValueError("Responses 返回缺少 output")

    parts: list[str] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        content = item.get("content")
        if not isinstance(content, list):
            text = item.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") not in {"output_text", "text"}:
                continue
            text = block.get("text")
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())

    if parts:
        return "\n".join(parts)
    raise ValueError("Responses 返回缺少可读取内容")


def _extract_ollama_content(payload: dict[str, Any]) -> str:
    response = payload.get("response")
    if isinstance(response, str) and response.strip():
        return response.strip()
    message = payload.get("message") or {}
    content = message.get("content")
    if isinstance(content, str) and content.strip():
        return content.strip()
    raise ValueError("Ollama 返回缺少 response 字段")


def _iter_text_chunks(text: str, *, chunk_size: int = 24) -> Iterator[str]:
    normalized = str(text or "")
    if not normalized:
        return
    lines = normalized.splitlines(keepends=True)
    for line in lines:
        if not line:
            continue
        start = 0
        while start < len(line):
            yield line[start : start + chunk_size]
            start += chunk_size


def _extract_openai_models(payload: dict[str, Any]) -> list[RemoteModelOption]:
    data = payload.get("data")
    if not isinstance(data, list):
        raise ValueError("模型列表返回格式不符合预期")
    models: list[RemoteModelOption] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = str(item.get("id") or "").strip()
        if not model_id:
            continue
        display_name = str(item.get("display_name") or "").strip() or None
        owned_by = str(item.get("owned_by") or "").strip() or None
        models.append(RemoteModelOption(id=model_id, display_name=display_name, owned_by=owned_by))
    if not models:
        raise ValueError("上游未返回可用模型")
    return models


def _extract_ollama_models(payload: dict[str, Any]) -> list[RemoteModelOption]:
    data = payload.get("models")
    if not isinstance(data, list):
        raise ValueError("模型列表返回格式不符合预期")
    models: list[RemoteModelOption] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        model_id = str(item.get("model") or item.get("name") or "").strip()
        if not model_id:
            continue
        display_name = str(item.get("name") or "").strip() or None
        models.append(RemoteModelOption(id=model_id, display_name=display_name))
    if not models:
        raise ValueError("上游未返回可用模型")
    return models


class BaseProvider:
    def generate(self, request: LLMRequest) -> str:
        raise NotImplementedError

    def stream_generate(self, request: LLMRequest) -> Iterator[str]:
        yield from _iter_text_chunks(self.generate(request))


class MockProvider(BaseProvider):
    def __init__(self, notice: str | None = None) -> None:
        self.notice = notice or "模型未配置，已使用模板摘要。"

    def generate(self, request: LLMRequest) -> str:
        return f"# 风险报告\n\n{self.notice}\n\n{request.flattened_text()}"

    def stream_generate(self, request: LLMRequest) -> Iterator[str]:
        yield from _iter_text_chunks(self.generate(request), chunk_size=18)


class OpenAICompatibleProvider(BaseProvider):
    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        timeout_seconds: int,
        api_key: str = "",
        wire_api: str = "responses",
        provider_label: str = "OpenAI 兼容接口",
    ) -> None:
        self.model = model
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key
        self.wire_api = str(wire_api or "responses").strip().lower() or "responses"
        self.provider_label = provider_label
        self.max_attempts = DEFAULT_TRANSIENT_RETRY_ATTEMPTS

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Language": DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE,
            "User-Agent": DEFAULT_OPENAI_COMPAT_USER_AGENT,
            "X-Client-Name": "asset-situational-awareness",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _should_retry_with_chat_completions(self, exc: httpx.HTTPStatusError) -> bool:
        if exc.response.status_code not in {400, 404, 405, 422}:
            return False

        message_parts: list[str] = []
        try:
            payload = exc.response.json()
        except Exception:
            payload = None

        if isinstance(payload, dict):
            for key in ("error", "detail", "message"):
                value = payload.get(key)
                if isinstance(value, dict):
                    nested_message = value.get("message")
                    if isinstance(nested_message, str) and nested_message.strip():
                        message_parts.append(nested_message.strip())
                elif isinstance(value, str) and value.strip():
                    message_parts.append(value.strip())

        raw_text = exc.response.text.strip()
        if raw_text:
            message_parts.append(raw_text)

        combined_message = " ".join(message_parts).lower()
        if exc.response.status_code in {404, 405}:
            return True

        retry_markers = (
            "/responses",
            "responses api",
            "responses is not supported",
            "unknown url",
            "unknown path",
            "not found",
            "unsupported parameter",
            "invalid input",
            "invalid request",
            "unrecognized request argument",
        )
        return any(token in combined_message for token in retry_markers)

    def _should_retry_transient_error(self, exc: Exception) -> bool:
        if isinstance(exc, httpx.TimeoutException):
            return True
        if isinstance(exc, httpx.RequestError):
            return True
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code in {429, 500, 502, 503, 504}:
                return True
        return False

    def _post_with_retry(self, *, endpoint: str, payload: dict[str, Any]) -> httpx.Response:
        last_exc: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                response = httpx.post(
                    _join_endpoint(self.base_url, endpoint),
                    headers=self._build_headers(),
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                response.raise_for_status()
                return response
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt >= self.max_attempts or not self._should_retry_transient_error(exc):
                    raise
                sleep(min(0.4 * attempt, 1.2))
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("AI 请求失败")

    def _generate_chat_completions(self, request: LLMRequest) -> str:
        response = self._post_with_retry(
            endpoint="/chat/completions",
            payload={
                "model": self.model,
                "messages": _build_openai_chat_messages(request),
                "temperature": 0.2,
            },
        )
        return _extract_openai_content(response.json())

    def _stream_chat_completions(self, request: LLMRequest) -> Iterator[str]:
        with httpx.stream(
            "POST",
            _join_endpoint(self.base_url, "/chat/completions"),
            headers=self._build_headers(),
            json={
                "model": self.model,
                "messages": _build_openai_chat_messages(request),
                "temperature": 0.2,
                "stream": True,
            },
            timeout=self.timeout_seconds,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line:
                    continue
                payload_line = line[5:].strip() if line.startswith("data:") else line.strip()
                if not payload_line or payload_line == "[DONE]":
                    continue
                try:
                    payload = json.loads(payload_line)
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                choices = payload.get("choices")
                if not isinstance(choices, list) or not choices:
                    continue
                delta = choices[0].get("delta") if isinstance(choices[0], dict) else {}
                if not isinstance(delta, dict):
                    continue
                content = delta.get("content")
                if isinstance(content, str) and content:
                    yield content
                    continue
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            text = item.get("text")
                            if isinstance(text, str) and text:
                                yield text

    def _generate_responses(self, request: LLMRequest) -> str:
        response = self._post_with_retry(
            endpoint="/responses",
            payload={
                "model": self.model,
                "instructions": request.system_instructions(),
                "input": _build_openai_responses_input(request),
            },
        )
        return _extract_openai_responses_content(response.json())

    def _stream_responses(self, request: LLMRequest) -> Iterator[str]:
        with httpx.stream(
            "POST",
            _join_endpoint(self.base_url, "/responses"),
            headers=self._build_headers(),
            json={
                "model": self.model,
                "instructions": request.system_instructions(),
                "input": _build_openai_responses_input(request),
                "stream": True,
            },
            timeout=self.timeout_seconds,
        ) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if not line:
                    continue
                payload_line = line[5:].strip() if line.startswith("data:") else line.strip()
                if not payload_line or payload_line == "[DONE]":
                    continue
                try:
                    payload = json.loads(payload_line)
                except Exception:
                    continue
                if not isinstance(payload, dict):
                    continue
                event_type = str(payload.get("type") or "").strip().lower()
                if event_type in {"response.output_text.delta", "output_text.delta"}:
                    delta = payload.get("delta")
                    if isinstance(delta, str) and delta:
                        yield delta
                    continue
                if event_type in {"response.output_text.done", "output_text.done"}:
                    text = payload.get("text")
                    if isinstance(text, str) and text:
                        yield text

    def generate(self, request: LLMRequest) -> str:
        if self.wire_api == "responses":
            return self._generate_responses(request)
        if self.wire_api == "chat_completions":
            return self._generate_chat_completions(request)
        try:
            return self._generate_responses(request)
        except httpx.HTTPStatusError as exc:
            if not self._should_retry_with_chat_completions(exc):
                raise
        return self._generate_chat_completions(request)

    def stream_generate(self, request: LLMRequest) -> Iterator[str]:
        emitted_any = False
        try:
            if self.wire_api == "responses":
                for chunk in self._stream_responses(request):
                    emitted_any = True
                    yield chunk
                return
            if self.wire_api == "chat_completions":
                for chunk in self._stream_chat_completions(request):
                    emitted_any = True
                    yield chunk
                return
            try:
                for chunk in self._stream_responses(request):
                    emitted_any = True
                    yield chunk
                return
            except httpx.HTTPStatusError as exc:
                if not self._should_retry_with_chat_completions(exc):
                    raise
            for chunk in self._stream_chat_completions(request):
                emitted_any = True
                yield chunk
        except Exception:
            if emitted_any:
                raise
            yield from super().stream_generate(request)


class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(self, *, api_key: str, model: str, timeout_seconds: int, base_url: str = DEFAULT_OPENAI_BASE_URL, wire_api: str = "responses") -> None:
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=base_url or DEFAULT_OPENAI_BASE_URL,
            timeout_seconds=timeout_seconds,
            wire_api=wire_api,
            provider_label="OpenAI",
        )


class OllamaRemoteProvider(BaseProvider):
    def __init__(self, *, model: str, base_url: str, timeout_seconds: int, api_key: str = "") -> None:
        self.model = model
        self.base_url = base_url or DEFAULT_OLLAMA_BASE_URL
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key

    def generate(self, request: LLMRequest) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        response = httpx.post(
            _join_endpoint(self.base_url, "/api/generate"),
            headers=headers,
            json={
                "model": self.model,
                "prompt": _render_ollama_prompt(request),
                "stream": False,
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        return _extract_ollama_content(response.json())

    def stream_generate(self, request: LLMRequest) -> Iterator[str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        emitted_any = False
        try:
            with httpx.stream(
                "POST",
                _join_endpoint(self.base_url, "/api/generate"),
                headers=headers,
                json={
                    "model": self.model,
                    "prompt": _render_ollama_prompt(request),
                    "stream": True,
                },
                timeout=self.timeout_seconds,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(payload, dict):
                        continue
                    chunk = payload.get("response")
                    if isinstance(chunk, str) and chunk:
                        emitted_any = True
                        yield chunk
        except Exception:
            if emitted_any:
                raise
            yield from super().stream_generate(request)


@dataclass(slots=True)
class ProviderBuildResult:
    provider_name: str
    model: str
    resolved_base_url: str
    provider: BaseProvider


def resolve_provider_base_url(provider_name: str, base_url: str = "") -> str:
    normalized_provider = str(provider_name or "mock").strip().lower() or "mock"
    normalized_base_url = str(base_url or "").strip().rstrip("/")
    if normalized_provider == "openai":
        return normalized_base_url or DEFAULT_OPENAI_BASE_URL
    if normalized_provider in {"openai_compatible", "ollama_remote"}:
        return normalized_base_url
    return ""


def resolve_provider_models_base_url(provider_name: str, base_url: str = "") -> str:
    normalized_provider = str(provider_name or "mock").strip().lower() or "mock"
    resolved = resolve_provider_base_url(normalized_provider, base_url)
    if normalized_provider in {"openai", "openai_compatible"}:
        return _strip_endpoint_suffix(resolved, ["/models", "/responses", "/chat/completions"])
    if normalized_provider == "ollama_remote":
        return _strip_endpoint_suffix(resolved, ["/api/tags", "/api/generate"])
    return resolved


def list_remote_models(
    *,
    provider_name: str,
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 60,
) -> tuple[str, list[RemoteModelOption]]:
    normalized_provider = str(provider_name or "mock").strip().lower() or "mock"
    normalized_api_key = str(api_key or "").strip()
    normalized_timeout = max(int(timeout_seconds or 60), 1)

    if normalized_provider == "mock":
        return "", [RemoteModelOption(id="gpt-4o-mini", display_name="Mock 默认模型")]

    if normalized_provider in {"openai", "openai_compatible"}:
        resolved_base_url = resolve_provider_models_base_url(normalized_provider, base_url)
        headers = {
            "Accept": "application/json",
            "Accept-Language": DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE,
            "User-Agent": DEFAULT_OPENAI_COMPAT_USER_AGENT,
            "X-Client-Name": "asset-situational-awareness",
        }
        if normalized_api_key:
            headers["Authorization"] = f"Bearer {normalized_api_key}"
        response = httpx.get(
            _join_endpoint(resolved_base_url, "/models"),
            headers=headers,
            timeout=normalized_timeout,
        )
        response.raise_for_status()
        payload = _parse_json_response(response)
        return resolved_base_url, _extract_openai_models(payload)

    if normalized_provider == "ollama_remote":
        resolved_base_url = resolve_provider_models_base_url(normalized_provider, base_url)
        headers = {"Accept": "application/json"}
        if normalized_api_key:
            headers["Authorization"] = f"Bearer {normalized_api_key}"
        response = httpx.get(
            _join_endpoint(resolved_base_url, "/api/tags"),
            headers=headers,
            timeout=normalized_timeout,
        )
        response.raise_for_status()
        payload = _parse_json_response(response)
        return resolved_base_url, _extract_ollama_models(payload)

    raise ValueError("当前模型接入方式不支持获取模型列表")


def build_provider(
    *,
    provider_name: str,
    model: str,
    base_url: str = "",
    wire_api: str = "responses",
    timeout_seconds: int = 60,
    api_key: str = "",
    fallback_to_mock: bool = False,
) -> ProviderBuildResult:
    normalized_provider = str(provider_name or "mock").strip().lower() or "mock"
    normalized_model = str(model or "").strip() or "gpt-4o-mini"
    normalized_base_url = str(base_url or "").strip().rstrip("/")
    normalized_wire_api = str(wire_api or "responses").strip().lower() or "responses"
    normalized_api_key = str(api_key or "").strip()
    normalized_timeout = max(int(timeout_seconds or 60), 1)

    if normalized_provider == "mock":
        return ProviderBuildResult(
            provider_name="mock",
            model=normalized_model,
            resolved_base_url="",
            provider=MockProvider(),
        )

    if normalized_provider == "openai":
        resolved_base_url = normalized_base_url or DEFAULT_OPENAI_BASE_URL
        if not normalized_api_key:
            if fallback_to_mock:
                return ProviderBuildResult(
                    provider_name="mock",
                    model=normalized_model,
                    resolved_base_url="",
                    provider=MockProvider("OpenAI Provider 未配置 API Key，已回退到模板摘要。"),
                )
            raise ValueError("当前模型接入方式必须填写 API Key")
        return ProviderBuildResult(
            provider_name="openai",
            model=normalized_model,
            resolved_base_url=resolved_base_url,
            provider=OpenAIProvider(
                api_key=normalized_api_key,
                model=normalized_model,
                timeout_seconds=normalized_timeout,
                base_url=resolved_base_url,
                wire_api=normalized_wire_api,
            ),
        )

    if normalized_provider == "openai_compatible":
        if not normalized_base_url:
            if fallback_to_mock:
                return ProviderBuildResult(
                    provider_name="mock",
                    model=normalized_model,
                    resolved_base_url="",
                    provider=MockProvider("OpenAI 兼容接口未配置 Base URL，已回退到模板摘要。"),
                )
            raise ValueError("当前模型接入方式必须填写 Base URL")
        return ProviderBuildResult(
            provider_name="openai_compatible",
            model=normalized_model,
            resolved_base_url=normalized_base_url,
            provider=OpenAICompatibleProvider(
                api_key=normalized_api_key,
                model=normalized_model,
                base_url=normalized_base_url,
                timeout_seconds=normalized_timeout,
                wire_api=normalized_wire_api,
            ),
        )

    if normalized_provider == "ollama_remote":
        if not normalized_base_url:
            if fallback_to_mock:
                return ProviderBuildResult(
                    provider_name="mock",
                    model=normalized_model,
                    resolved_base_url="",
                    provider=MockProvider("远程 Ollama 未配置 Base URL，已回退到模板摘要。"),
                )
            raise ValueError("当前模型接入方式必须填写 Base URL")
        return ProviderBuildResult(
            provider_name="ollama_remote",
            model=normalized_model,
            resolved_base_url=normalized_base_url,
            provider=OllamaRemoteProvider(
                api_key=normalized_api_key,
                model=normalized_model,
                base_url=normalized_base_url,
                timeout_seconds=normalized_timeout,
            ),
        )

    if fallback_to_mock:
        return ProviderBuildResult(
            provider_name="mock",
            model=normalized_model,
            resolved_base_url="",
            provider=MockProvider("模型接入方式不受支持，已回退到模板摘要。"),
        )
    raise ValueError("当前模型接入方式不受支持")
