from __future__ import annotations

import json
from dataclasses import dataclass, field
from threading import Lock
from time import sleep
from typing import Any, Iterator, Literal
from urllib.parse import urlparse

import httpx


DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MINIMAX_BASE_URL = "https://api.minimaxi.com/v1"
DEFAULT_OLLAMA_BASE_URL = "http://127.0.0.1:11434"
DEFAULT_SYSTEM_PROMPT = "你是资产态势感知平台的安全分析助手，请使用简洁中文输出可执行结论。"
DEFAULT_OPENAI_COMPAT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
)
DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8"
DEFAULT_MODEL_REQUEST_CLIENT_NAME = "asset-situational-awareness"
DEFAULT_TRANSIENT_RETRY_ATTEMPTS = 3
OPENAI_STYLE_ENDPOINT_SUFFIXES = ["/models", "/responses", "/chat/completions"]
OLLAMA_ENDPOINT_SUFFIXES = ["/api/tags", "/api/generate"]
AUTO_WIRE_API_CHOICES = {"responses", "chat_completions"}
_AUTO_WIRE_API_PREFERENCES: dict[str, str] = {}
_AUTO_WIRE_API_PREFERENCES_LOCK = Lock()


@dataclass(frozen=True, slots=True)
class ProviderMeta:
    default_base_url: str = ""
    default_wire_api: str = "responses"
    requires_base_url: bool = False
    requires_api_key: bool = False
    url_style: Literal["none", "openai_like", "ollama"] = "none"


def _auto_wire_api_cache_key(base_url: str) -> str:
    return str(base_url or "").strip().rstrip("/").lower()


def get_cached_auto_wire_api(base_url: str) -> str:
    cache_key = _auto_wire_api_cache_key(base_url)
    if not cache_key:
        return ""
    with _AUTO_WIRE_API_PREFERENCES_LOCK:
        return str(_AUTO_WIRE_API_PREFERENCES.get(cache_key) or "")


def set_cached_auto_wire_api(base_url: str, wire_api: str) -> None:
    cache_key = _auto_wire_api_cache_key(base_url)
    normalized_wire_api = str(wire_api or "").strip().lower()
    if not cache_key or normalized_wire_api not in AUTO_WIRE_API_CHOICES:
        return
    with _AUTO_WIRE_API_PREFERENCES_LOCK:
        _AUTO_WIRE_API_PREFERENCES[cache_key] = normalized_wire_api


PROVIDER_META = {
    "mock": ProviderMeta(),
    "openai": ProviderMeta(
        default_base_url=DEFAULT_OPENAI_BASE_URL,
        default_wire_api="responses",
        requires_api_key=True,
        url_style="openai_like",
    ),
    "minimax": ProviderMeta(
        default_base_url=DEFAULT_MINIMAX_BASE_URL,
        default_wire_api="chat_completions",
        requires_api_key=True,
        url_style="openai_like",
    ),
    "custom_proxy": ProviderMeta(
        default_wire_api="auto",
        requires_base_url=True,
        requires_api_key=True,
        url_style="openai_like",
    ),
    "ollama_remote": ProviderMeta(
        default_wire_api="responses",
        requires_base_url=True,
        url_style="ollama",
    ),
}


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


def _matches_endpoint_path(raw_value: str, suffixes: list[str]) -> bool:
    normalized = str(raw_value or "").strip()
    if not normalized or "://" in normalized:
        return False
    normalized_path = f"/{normalized.strip('/')}"
    return normalized_path in suffixes


def _ensure_url_scheme(base_url: str, *, default_scheme: str) -> str:
    normalized = str(base_url or "").strip()
    if not normalized:
        return ""
    if "://" in normalized:
        return normalized
    return f"{default_scheme}://{normalized.lstrip('/')}"


def _validate_normalized_url(base_url: str) -> tuple[str, str, str]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Base URL 必须是有效的 http:// 或 https:// 地址")
    return parsed.scheme, parsed.netloc, parsed.path.rstrip("/")


def _normalize_openai_like_base_url(base_url: str, *, default_base_url: str = "") -> str:
    raw_value = str(base_url or "").strip()
    fallback_value = str(default_base_url or "").strip()
    if not raw_value:
        raw_value = fallback_value
    elif _matches_endpoint_path(raw_value, OPENAI_STYLE_ENDPOINT_SUFFIXES):
        raw_value = fallback_value
    if not raw_value:
        return ""
    candidate = _ensure_url_scheme(raw_value, default_scheme="https")
    scheme, netloc, path = _validate_normalized_url(candidate)
    stripped = _strip_endpoint_suffix(f"{scheme}://{netloc}{path}", OPENAI_STYLE_ENDPOINT_SUFFIXES)
    stripped_scheme, stripped_netloc, stripped_path = _validate_normalized_url(stripped)
    if not stripped_path:
        return f"{stripped_scheme}://{stripped_netloc}/v1"
    return f"{stripped_scheme}://{stripped_netloc}{stripped_path}"


def _normalize_ollama_base_url(base_url: str, *, default_base_url: str = "") -> str:
    raw_value = str(base_url or "").strip()
    fallback_value = str(default_base_url or "").strip()
    if not raw_value:
        raw_value = fallback_value
    elif _matches_endpoint_path(raw_value, OLLAMA_ENDPOINT_SUFFIXES):
        raw_value = fallback_value
    if not raw_value:
        return ""
    candidate = _ensure_url_scheme(raw_value, default_scheme="http")
    scheme, netloc, path = _validate_normalized_url(candidate)
    stripped = _strip_endpoint_suffix(f"{scheme}://{netloc}{path}", OLLAMA_ENDPOINT_SUFFIXES)
    stripped_scheme, stripped_netloc, stripped_path = _validate_normalized_url(stripped)
    return f"{stripped_scheme}://{stripped_netloc}{stripped_path}"


def _append_unique_candidate(candidates: list[str], candidate: str) -> None:
    normalized = str(candidate or "").strip()
    if not normalized or normalized in candidates:
        return
    candidates.append(normalized)


def _resolve_openai_like_base_url_candidates(
    base_url: str,
    *,
    default_base_url: str = "",
    allow_root_fallback: bool = False,
    allow_root_fallback_for_v1: bool = False,
    allow_root_fallback_for_custom_path: bool = False,
) -> list[str]:
    raw_value = str(base_url or "").strip()
    fallback_value = str(default_base_url or "").strip()
    if not raw_value:
        raw_value = fallback_value
    elif _matches_endpoint_path(raw_value, OPENAI_STYLE_ENDPOINT_SUFFIXES):
        raw_value = fallback_value
    if not raw_value:
        return []
    candidate = _ensure_url_scheme(raw_value, default_scheme="https")
    scheme, netloc, path = _validate_normalized_url(candidate)
    stripped = _strip_endpoint_suffix(f"{scheme}://{netloc}{path}", OPENAI_STYLE_ENDPOINT_SUFFIXES)
    stripped_scheme, stripped_netloc, stripped_path = _validate_normalized_url(stripped)
    root_base_url = f"{stripped_scheme}://{stripped_netloc}"
    primary_base_url = f"{root_base_url}{stripped_path}" if stripped_path else f"{root_base_url}/v1"
    candidates: list[str] = []
    _append_unique_candidate(candidates, primary_base_url)
    fallback_candidate = ""
    if allow_root_fallback and not stripped_path:
        fallback_candidate = root_base_url
    elif allow_root_fallback_for_v1 and stripped_path == "/v1":
        fallback_candidate = root_base_url
    elif allow_root_fallback_for_custom_path and stripped_path not in {"", "/v1"}:
        fallback_candidate = f"{root_base_url}/v1"
    if fallback_candidate:
        _append_unique_candidate(candidates, fallback_candidate)
    return candidates


def _resolve_ollama_base_url_candidates(base_url: str, *, default_base_url: str = "") -> list[str]:
    normalized = _normalize_ollama_base_url(base_url, default_base_url=default_base_url)
    return [normalized] if normalized else []


def _resolve_explicit_custom_proxy_root_base_url(base_url: str) -> str:
    raw_value = str(base_url or "").strip()
    if not raw_value or "://" not in raw_value:
        return ""
    scheme, netloc, path = _validate_normalized_url(raw_value)
    if path:
        return ""
    return f"{scheme}://{netloc}"


def normalize_provider_name(provider_name: str) -> str:
    normalized = str(provider_name or "mock").strip().lower() or "mock"
    return normalized


def get_provider_meta(provider_name: str) -> ProviderMeta:
    normalized_provider = normalize_provider_name(provider_name)
    return PROVIDER_META.get(normalized_provider, PROVIDER_META["mock"])


def resolve_provider_default_base_url(provider_name: str) -> str:
    return get_provider_meta(provider_name).default_base_url


def resolve_provider_default_wire_api(provider_name: str) -> str:
    return get_provider_meta(provider_name).default_wire_api


def provider_requires_base_url(provider_name: str) -> bool:
    return get_provider_meta(provider_name).requires_base_url


def provider_requires_api_key(provider_name: str) -> bool:
    return get_provider_meta(provider_name).requires_api_key


def resolve_provider_base_url_candidates(
    provider_name: str,
    base_url: str = "",
    *,
    allow_runtime_probe_fallback: bool = False,
) -> list[str]:
    normalized_provider = normalize_provider_name(provider_name)
    meta = get_provider_meta(normalized_provider)
    if meta.url_style == "openai_like":
        return _resolve_openai_like_base_url_candidates(
            base_url,
            default_base_url=meta.default_base_url,
            allow_root_fallback=normalized_provider == "custom_proxy",
            allow_root_fallback_for_v1=allow_runtime_probe_fallback and normalized_provider == "custom_proxy",
            allow_root_fallback_for_custom_path=allow_runtime_probe_fallback and normalized_provider == "custom_proxy",
        )
    if meta.url_style == "ollama":
        return _resolve_ollama_base_url_candidates(base_url, default_base_url=meta.default_base_url)
    return []


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


def _build_model_request_headers(
    *,
    api_key: str = "",
    include_accept: bool = True,
    include_content_type: bool = False,
) -> dict[str, str]:
    headers = {
        "Accept-Language": DEFAULT_OPENAI_COMPAT_ACCEPT_LANGUAGE,
        "User-Agent": DEFAULT_OPENAI_COMPAT_USER_AGENT,
        "X-Client-Name": DEFAULT_MODEL_REQUEST_CLIENT_NAME,
    }
    if include_accept:
        headers["Accept"] = "application/json"
    if include_content_type:
        headers["Content-Type"] = "application/json"
    normalized_api_key = str(api_key or "").strip()
    if normalized_api_key:
        headers["Authorization"] = f"Bearer {normalized_api_key}"
    return headers


def _should_retry_with_alternate_base_url(exc: Exception) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in {404, 405, 422}
    if isinstance(exc, ValueError):
        message = str(exc)
        return "页面内容" in message or "非 JSON" in message
    return False


def _normalize_message_role(role: str | None) -> str:
    normalized = str(role or "user").strip().lower() or "user"
    if normalized not in {"system", "user", "assistant"}:
        return "user"
    return normalized


def _openai_message_text(message: LLMMessage) -> str:
    return message.text_content()


def _build_openai_chat_messages(request: LLMRequest) -> list[dict[str, str]]:
    messages: list[dict[str, str]] = []
    instructions = request.system_instructions()
    if instructions:
        messages.append({"role": "system", "content": instructions})
    for item in request.conversation_messages():
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


def _extract_text_parts_from_blocks(
    blocks: Any,
    *,
    allowed_types: set[str] | None = None,
) -> list[str]:
    if not isinstance(blocks, list):
        return []
    normalized_allowed_types = allowed_types or {"text", "output_text", "input_text"}
    parts: list[str] = []
    for item in blocks:
        if isinstance(item, str):
            text = item.strip()
            if text:
                parts.append(text)
            continue
        if not isinstance(item, dict):
            continue
        item_type = str(item.get("type") or "").strip().lower()
        if item_type and item_type not in normalized_allowed_types:
            continue
        text = item.get("text")
        if isinstance(text, str) and text.strip():
            parts.append(text.strip())
            continue
        value = item.get("value")
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    return parts


def _extract_payload_error_detail(payload: dict[str, Any]) -> str:
    for key in ("error", "detail", "message"):
        value = payload.get(key)
        if isinstance(value, dict):
            for nested_key in ("message", "detail", "error"):
                nested_value = value.get(nested_key)
                if isinstance(nested_value, str) and nested_value.strip():
                    return nested_value.strip()
        elif isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _extract_fallback_text_content(payload: dict[str, Any]) -> str:
    content = payload.get("content")
    if isinstance(content, str) and content.strip():
        return content.strip()
    parts = _extract_text_parts_from_blocks(content)
    if parts:
        return "\n".join(parts)

    for key in ("output_text", "completion", "text", "response"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    message = payload.get("message")
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()
        parts = _extract_text_parts_from_blocks(content)
        if parts:
            return "\n".join(parts)
        text = message.get("text")
        if isinstance(text, str) and text.strip():
            return text.strip()

    return ""


def _extract_openai_content(payload: dict[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        message = choices[0].get("message") or {}
        content = message.get("content")
        if isinstance(content, str):
            return content.strip()
        parts = _extract_text_parts_from_blocks(content, allowed_types={"text"})
        if parts:
            return "\n".join(parts)

    fallback_text = _extract_fallback_text_content(payload)
    if fallback_text:
        return fallback_text

    error_detail = _extract_payload_error_detail(payload)
    if error_detail:
        raise ValueError(f"上游返回错误：{error_detail}")

    raise ValueError("模型返回格式不兼容，缺少可读取内容")


def _extract_openai_responses_content(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    output = payload.get("output")
    if not isinstance(output, list) or not output:
        fallback_text = _extract_fallback_text_content(payload)
        if fallback_text:
            return fallback_text
        error_detail = _extract_payload_error_detail(payload)
        if error_detail:
            raise ValueError(f"上游返回错误：{error_detail}")
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
    fallback_text = _extract_fallback_text_content(payload)
    if fallback_text:
        return fallback_text
    error_detail = _extract_payload_error_detail(payload)
    if error_detail:
        raise ValueError(f"上游返回错误：{error_detail}")
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
        base_url_candidates: list[str] | None = None,
        timeout_seconds: int,
        api_key: str = "",
        wire_api: str = "responses",
        chat_json_mode: bool = False,
        provider_label: str = "OpenAI 兼容接口",
    ) -> None:
        normalized_candidates: list[str] = []
        for item in base_url_candidates or [base_url]:
            _append_unique_candidate(normalized_candidates, str(item or "").strip().rstrip("/"))
        if not normalized_candidates:
            _append_unique_candidate(normalized_candidates, str(base_url or "").strip().rstrip("/"))
        self.model = model
        self.base_url_candidates = normalized_candidates
        self._active_base_url_index = 0
        self.base_url = normalized_candidates[0] if normalized_candidates else str(base_url or "").strip().rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key
        self.wire_api = str(wire_api or "responses").strip().lower() or "responses"
        self.chat_json_mode = bool(chat_json_mode)
        self.provider_label = provider_label
        self.max_attempts = DEFAULT_TRANSIENT_RETRY_ATTEMPTS

    def _cached_auto_wire_api(self) -> str:
        if self.wire_api != "auto":
            return ""
        return get_cached_auto_wire_api(self.base_url)

    def _remember_auto_wire_api(self, wire_api: str) -> None:
        if self.wire_api != "auto":
            return
        set_cached_auto_wire_api(self.base_url, wire_api)

    def _build_headers(self) -> dict[str, str]:
        return _build_model_request_headers(
            api_key=self.api_key,
            include_accept=True,
            include_content_type=True,
        )

    def _set_active_base_url_index(self, candidate_index: int) -> None:
        if not self.base_url_candidates:
            return
        self._active_base_url_index = candidate_index
        self.base_url = self.base_url_candidates[candidate_index]

    def _candidate_attempt_indices(self) -> list[int]:
        if not self.base_url_candidates:
            return [0]
        ordered = [self._active_base_url_index]
        for index in range(len(self.base_url_candidates)):
            if index != self._active_base_url_index:
                ordered.append(index)
        return ordered

    def _run_with_base_url_fallback(self, operation):  # type: ignore[no-untyped-def]
        original_index = self._active_base_url_index
        last_exc: Exception | None = None
        attempt_indices = self._candidate_attempt_indices()
        for attempt_position, candidate_index in enumerate(attempt_indices):
            self._set_active_base_url_index(candidate_index)
            try:
                return operation()
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt_position == len(attempt_indices) - 1 or not _should_retry_with_alternate_base_url(exc):
                    self._set_active_base_url_index(original_index)
                    raise
        self._set_active_base_url_index(original_index)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("AI 请求失败")

    def _stream_with_base_url_fallback(self, operation):  # type: ignore[no-untyped-def]
        original_index = self._active_base_url_index
        last_exc: Exception | None = None
        attempt_indices = self._candidate_attempt_indices()
        for attempt_position, candidate_index in enumerate(attempt_indices):
            emitted_any = False
            self._set_active_base_url_index(candidate_index)
            try:
                for chunk in operation():
                    emitted_any = True
                    yield chunk
                return
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if emitted_any:
                    raise
                if attempt_position == len(attempt_indices) - 1 or not _should_retry_with_alternate_base_url(exc):
                    self._set_active_base_url_index(original_index)
                    raise
        self._set_active_base_url_index(original_index)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("AI 请求失败")

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

    def _should_retry_chat_without_json_mode(self, exc: httpx.HTTPStatusError) -> bool:
        if exc.response.status_code not in {400, 422}:
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
        if not combined_message:
            return True

        retry_markers = (
            "response_format",
            "json_object",
            "json schema",
            "json_schema",
            "unsupported parameter",
            "unrecognized request argument",
            "extra inputs are not permitted",
            "unknown field",
        )
        return any(marker in combined_message for marker in retry_markers)

    def _generate_chat_completions(self, request: LLMRequest) -> str:
        payload = {
            "model": self.model,
            "messages": _build_openai_chat_messages(request),
            "temperature": 0.2,
        }
        if self.chat_json_mode:
            try:
                response = self._post_with_retry(
                    endpoint="/chat/completions",
                    payload={
                        **payload,
                        "response_format": {"type": "json_object"},
                    },
                )
            except httpx.HTTPStatusError as exc:
                if not self._should_retry_chat_without_json_mode(exc):
                    raise
                response = self._post_with_retry(
                    endpoint="/chat/completions",
                    payload=payload,
                )
        else:
            response = self._post_with_retry(
                endpoint="/chat/completions",
                payload=payload,
            )
        return _extract_openai_content(_parse_json_response(response))

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
            content_type = str(response.headers.get("content-type") or "").lower()
            if "text/html" in content_type:
                raise ValueError("上游返回页面内容，请检查 Base URL 是否指向 API 根地址")
            emitted_any = False
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
                    emitted_any = True
                    yield content
                    continue
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            text = item.get("text")
                            if isinstance(text, str) and text:
                                emitted_any = True
                                yield text
            if not emitted_any:
                raise ValueError("上游返回非 JSON 响应，请检查 Base URL 是否正确")

    def _generate_responses(self, request: LLMRequest) -> str:
        response = self._post_with_retry(
            endpoint="/responses",
            payload={
                "model": self.model,
                "instructions": request.system_instructions(),
                "input": _build_openai_responses_input(request),
            },
        )
        return _extract_openai_responses_content(_parse_json_response(response))

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
            content_type = str(response.headers.get("content-type") or "").lower()
            if "text/html" in content_type:
                raise ValueError("上游返回页面内容，请检查 Base URL 是否指向 API 根地址")
            emitted_any = False
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
                        emitted_any = True
                        yield delta
                    continue
                if event_type in {"response.output_text.done", "output_text.done"}:
                    text = payload.get("text")
                    if isinstance(text, str) and text:
                        emitted_any = True
                        yield text
            if not emitted_any:
                raise ValueError("上游返回非 JSON 响应，请检查 Base URL 是否正确")

    def generate(self, request: LLMRequest) -> str:
        def _generate() -> str:
            cached_wire_api = self._cached_auto_wire_api()
            if self.wire_api == "responses":
                return self._generate_responses(request)
            if self.wire_api == "chat_completions":
                return self._generate_chat_completions(request)
            if cached_wire_api == "responses":
                result = self._generate_responses(request)
                self._remember_auto_wire_api("responses")
                return result
            if cached_wire_api == "chat_completions":
                result = self._generate_chat_completions(request)
                self._remember_auto_wire_api("chat_completions")
                return result
            try:
                result = self._generate_responses(request)
                self._remember_auto_wire_api("responses")
                return result
            except httpx.HTTPStatusError as exc:
                if not self._should_retry_with_chat_completions(exc):
                    raise
            result = self._generate_chat_completions(request)
            self._remember_auto_wire_api("chat_completions")
            return result

        return self._run_with_base_url_fallback(_generate)

    def stream_generate(self, request: LLMRequest) -> Iterator[str]:
        emitted_any = False
        try:
            cached_wire_api = self._cached_auto_wire_api()
            if self.wire_api == "responses":
                for chunk in self._stream_with_base_url_fallback(lambda: self._stream_responses(request)):
                    emitted_any = True
                    yield chunk
                return
            if self.wire_api == "chat_completions":
                for chunk in self._stream_with_base_url_fallback(lambda: self._stream_chat_completions(request)):
                    emitted_any = True
                    yield chunk
                return
            if cached_wire_api == "responses":
                for chunk in self._stream_with_base_url_fallback(lambda: self._stream_responses(request)):
                    emitted_any = True
                    yield chunk
                self._remember_auto_wire_api("responses")
                return
            if cached_wire_api == "chat_completions":
                for chunk in self._stream_with_base_url_fallback(lambda: self._stream_chat_completions(request)):
                    emitted_any = True
                    yield chunk
                self._remember_auto_wire_api("chat_completions")
                return

            def _stream_auto() -> Iterator[str]:
                responses_emitted = False
                try:
                    for chunk in self._stream_responses(request):
                        responses_emitted = True
                        yield chunk
                    if responses_emitted:
                        self._remember_auto_wire_api("responses")
                    return
                except httpx.HTTPStatusError as exc:
                    if responses_emitted or not self._should_retry_with_chat_completions(exc):
                        raise
                chat_emitted = False
                for chunk in self._stream_chat_completions(request):
                    chat_emitted = True
                    yield chunk
                if chat_emitted:
                    self._remember_auto_wire_api("chat_completions")

            for chunk in self._stream_with_base_url_fallback(_stream_auto):
                emitted_any = True
                yield chunk
        except Exception:
            if emitted_any:
                raise
            yield from super().stream_generate(request)


class OpenAIProvider(OpenAICompatibleProvider):
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: int,
        base_url: str = DEFAULT_OPENAI_BASE_URL,
        wire_api: str = "responses",
        chat_json_mode: bool = False,
    ) -> None:
        super().__init__(
            api_key=api_key,
            model=model,
            base_url=base_url or DEFAULT_OPENAI_BASE_URL,
            timeout_seconds=timeout_seconds,
            wire_api=wire_api,
            chat_json_mode=chat_json_mode,
            provider_label="OpenAI",
        )


class OllamaRemoteProvider(BaseProvider):
    def __init__(self, *, model: str, base_url: str, timeout_seconds: int, api_key: str = "") -> None:
        self.model = model
        self.base_url = base_url or DEFAULT_OLLAMA_BASE_URL
        self.timeout_seconds = timeout_seconds
        self.api_key = api_key

    def generate(self, request: LLMRequest) -> str:
        response = httpx.post(
            _join_endpoint(self.base_url, "/api/generate"),
            headers=_build_model_request_headers(
                api_key=self.api_key,
                include_accept=True,
                include_content_type=True,
            ),
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
        emitted_any = False
        try:
            with httpx.stream(
                "POST",
                _join_endpoint(self.base_url, "/api/generate"),
                headers=_build_model_request_headers(
                    api_key=self.api_key,
                    include_accept=True,
                    include_content_type=True,
                ),
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
    candidates = resolve_provider_base_url_candidates(provider_name, base_url)
    return candidates[0] if candidates else ""


def resolve_provider_saved_base_url(provider_name: str, base_url: str = "") -> str:
    normalized_provider = normalize_provider_name(provider_name)
    if normalized_provider == "custom_proxy":
        explicit_root = _resolve_explicit_custom_proxy_root_base_url(base_url)
        if explicit_root:
            return explicit_root
    return resolve_provider_base_url(normalized_provider, base_url)


def resolve_provider_models_base_url(provider_name: str, base_url: str = "") -> str:
    candidates = resolve_provider_models_base_url_candidates(provider_name, base_url)
    return candidates[0] if candidates else ""


def resolve_provider_models_base_url_candidates(
    provider_name: str,
    base_url: str = "",
    *,
    allow_runtime_probe_fallback: bool = False,
) -> list[str]:
    normalized_provider = normalize_provider_name(provider_name)
    resolved_candidates = resolve_provider_base_url_candidates(
        normalized_provider,
        base_url,
        allow_runtime_probe_fallback=allow_runtime_probe_fallback,
    )
    if normalized_provider in {"openai", "minimax", "custom_proxy"}:
        normalized_candidates: list[str] = []
        for candidate in resolved_candidates:
            _append_unique_candidate(normalized_candidates, _strip_endpoint_suffix(candidate, OPENAI_STYLE_ENDPOINT_SUFFIXES))
        return normalized_candidates
    if normalized_provider == "ollama_remote":
        normalized_candidates = []
        for candidate in resolved_candidates:
            _append_unique_candidate(normalized_candidates, _strip_endpoint_suffix(candidate, OLLAMA_ENDPOINT_SUFFIXES))
        return normalized_candidates
    return resolved_candidates


def list_remote_models(
    *,
    provider_name: str,
    base_url: str = "",
    api_key: str = "",
    timeout_seconds: int = 60,
) -> tuple[str, list[RemoteModelOption]]:
    normalized_provider = normalize_provider_name(provider_name)
    normalized_api_key = str(api_key or "").strip()
    normalized_timeout = max(int(timeout_seconds or 60), 1)

    if normalized_provider == "mock":
        return "", [RemoteModelOption(id="gpt-4o-mini", display_name="Mock 默认模型")]

    if provider_requires_api_key(normalized_provider) and not normalized_api_key:
        raise ValueError("当前模型接入方式必须填写 API Key")

    if normalized_provider in {"openai", "minimax", "custom_proxy"}:
        resolved_base_urls = resolve_provider_models_base_url_candidates(
            normalized_provider,
            base_url,
            allow_runtime_probe_fallback=True,
        )
        if not resolved_base_urls:
            raise ValueError("当前模型接入方式必须填写 Base URL")
        last_exc: Exception | None = None
        for attempt_position, resolved_base_url in enumerate(resolved_base_urls):
            try:
                response = httpx.get(
                    _join_endpoint(resolved_base_url, "/models"),
                    headers=_build_model_request_headers(
                        api_key=normalized_api_key,
                        include_accept=True,
                        include_content_type=False,
                    ),
                    timeout=normalized_timeout,
                )
                response.raise_for_status()
                payload = _parse_json_response(response)
                return resolved_base_url, _extract_openai_models(payload)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if attempt_position == len(resolved_base_urls) - 1 or not _should_retry_with_alternate_base_url(exc):
                    raise
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("获取模型列表失败")

    if normalized_provider == "ollama_remote":
        resolved_base_urls = resolve_provider_models_base_url_candidates(normalized_provider, base_url)
        if not resolved_base_urls:
            raise ValueError("当前模型接入方式必须填写 Base URL")
        resolved_base_url = resolved_base_urls[0]
        response = httpx.get(
            _join_endpoint(resolved_base_url, "/api/tags"),
            headers=_build_model_request_headers(
                api_key=normalized_api_key,
                include_accept=True,
                include_content_type=False,
            ),
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
    wire_api: str = "",
    timeout_seconds: int = 60,
    api_key: str = "",
    chat_json_mode: bool = False,
    fallback_to_mock: bool = False,
) -> ProviderBuildResult:
    normalized_provider = normalize_provider_name(provider_name)
    normalized_model = str(model or "").strip() or "gpt-4o-mini"
    normalized_base_url_candidates = resolve_provider_base_url_candidates(
        normalized_provider,
        base_url,
        allow_runtime_probe_fallback=normalized_provider == "custom_proxy",
    )
    normalized_base_url = normalized_base_url_candidates[0] if normalized_base_url_candidates else ""
    normalized_wire_api = str(wire_api or resolve_provider_default_wire_api(normalized_provider)).strip().lower() or resolve_provider_default_wire_api(normalized_provider)
    normalized_api_key = str(api_key or "").strip()
    normalized_timeout = max(int(timeout_seconds or 60), 1)

    if normalized_provider not in PROVIDER_META:
        raise ValueError("当前模型接入方式不受支持")

    if normalized_provider == "mock":
        return ProviderBuildResult(
            provider_name="mock",
            model=normalized_model,
            resolved_base_url="",
            provider=MockProvider(),
        )

    if provider_requires_api_key(normalized_provider) and not normalized_api_key:
        provider_labels = {
            "openai": "OpenAI Provider",
            "minimax": "MiniMax",
            "custom_proxy": "自定义中转",
        }
        if fallback_to_mock:
            label = provider_labels.get(normalized_provider, "当前模型接入方式")
            return ProviderBuildResult(
                provider_name="mock",
                model=normalized_model,
                resolved_base_url="",
                provider=MockProvider(f"{label} 未配置 API Key，已回退到模板摘要。"),
            )
        raise ValueError("当前模型接入方式必须填写 API Key")

    if normalized_provider == "openai":
        resolved_base_url = normalized_base_url or DEFAULT_OPENAI_BASE_URL
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
                chat_json_mode=chat_json_mode,
            ),
        )

    if normalized_provider == "minimax":
        resolved_base_url = normalized_base_url or DEFAULT_MINIMAX_BASE_URL
        return ProviderBuildResult(
            provider_name="minimax",
            model=normalized_model,
            resolved_base_url=resolved_base_url,
            provider=OpenAICompatibleProvider(
                api_key=normalized_api_key,
                model=normalized_model,
                base_url=resolved_base_url,
                base_url_candidates=[resolved_base_url],
                timeout_seconds=normalized_timeout,
                wire_api=normalized_wire_api,
                chat_json_mode=chat_json_mode,
                provider_label="MiniMax",
            ),
        )

    if normalized_provider == "custom_proxy":
        if not normalized_base_url:
            if fallback_to_mock:
                return ProviderBuildResult(
                    provider_name="mock",
                    model=normalized_model,
                    resolved_base_url="",
                    provider=MockProvider("自定义中转未配置 Base URL，已回退到模板摘要。"),
                )
            raise ValueError("当前模型接入方式必须填写 Base URL")
        return ProviderBuildResult(
            provider_name="custom_proxy",
            model=normalized_model,
            resolved_base_url=normalized_base_url,
            provider=OpenAICompatibleProvider(
                api_key=normalized_api_key,
                model=normalized_model,
                base_url=normalized_base_url,
                base_url_candidates=normalized_base_url_candidates,
                timeout_seconds=normalized_timeout,
                wire_api=normalized_wire_api,
                chat_json_mode=chat_json_mode,
                provider_label="自定义中转",
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

    raise ValueError("当前模型接入方式不受支持")
