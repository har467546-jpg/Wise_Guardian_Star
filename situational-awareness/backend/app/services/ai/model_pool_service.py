from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator, Literal

import httpx
from redis import Redis

from app.core.config import read_runtime_env_value, settings
from app.services.ai import model_router_service
from app.services.ai.providers import LLMRequest, ProviderBuildResult, build_provider, normalize_provider_name
from app.utils.sanitize import sanitize_text

ModelPoolCapability = Literal["json_mode", "streaming", "any"]
ModelPoolPurpose = Literal["agent_decision", "streaming_reply", "general", "probe"]

DEFAULT_POOL_METRICS_WINDOW = 100
DEFAULT_SOFT_FAILURE_THRESHOLD = 3
DEFAULT_SOFT_CIRCUIT_SECONDS = 300
HARD_FAILURE_STATUS_CODES = {401, 402, 403}
SOFT_FAILURE_STATUS_CODES = {408, 409, 429, 500, 502, 503, 504}


@dataclass(frozen=True, slots=True)
class ModelPoolNode:
    id: str
    provider_name: str
    model: str
    base_url: str = ""
    api_key: str = ""
    wire_api: str = ""
    timeout_seconds: int = 60
    priority: int = 100
    weight: float = 1.0
    supports_json_mode: bool = False
    supports_streaming: bool = False
    enabled: bool = True
    cost_tier: str = "standard"
    quality_tier: str = "standard"
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_mock(self) -> bool:
        return normalize_provider_name(self.provider_name) == "mock"


@dataclass(frozen=True, slots=True)
class ModelPoolCallRecord:
    node_id: str
    provider_name: str
    model: str
    latency_ms: int
    success: bool
    error: str = ""
    status_code: int | None = None
    purpose: str = "general"
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class ModelPoolNodeSnapshot:
    node: ModelPoolNode
    healthy: bool
    state: str
    average_latency_ms: int | None
    success_count: int
    error_count: int
    consecutive_failures: int
    circuit_open_until: float
    last_error: str
    last_status_code: int | None
    last_seen_at: float | None


@dataclass(frozen=True, slots=True)
class ModelPoolCallResult:
    node: ModelPoolNode
    provider_result: ProviderBuildResult
    content: str
    latency_ms: int
    attempts: list[ModelPoolCallRecord]


@dataclass(frozen=True, slots=True)
class ModelPoolStreamResult:
    node: ModelPoolNode
    provider_result: ProviderBuildResult
    chunks: Iterator[str]
    attempts: list[ModelPoolCallRecord]


@dataclass(frozen=True, slots=True)
class ModelPoolProviderCandidate:
    node: ModelPoolNode
    provider_result: ProviderBuildResult


_local_lock = threading.Lock()
_local_records: dict[str, list[dict[str, Any]]] = {}
_local_circuits: dict[str, dict[str, Any]] = {}


def model_pool_enabled() -> bool:
    if model_router_service.gateway_channels_configured():
        return True
    raw_pool = read_runtime_env_value("LLM_MODEL_POOL", str(getattr(settings, "LLM_MODEL_POOL", "") or ""))
    return bool(_parse_model_pool_nodes(raw_pool))


def read_model_pool_nodes(*, include_disabled: bool = False) -> list[ModelPoolNode]:
    if model_router_service.gateway_channels_configured():
        return [
            _node_from_gateway_channel(channel)
            for channel in model_router_service.read_gateway_channels(include_disabled=include_disabled)
        ]
    raw_pool = read_runtime_env_value("LLM_MODEL_POOL", str(getattr(settings, "LLM_MODEL_POOL", "") or ""))
    nodes = _parse_model_pool_nodes(raw_pool)
    if not nodes:
        nodes = [_legacy_single_node()]
    if not include_disabled:
        nodes = [node for node in nodes if node.enabled]
    return sorted(nodes, key=lambda item: (item.priority, item.id))


def select_model_pool_nodes(
    *,
    capability: ModelPoolCapability = "any",
    purpose: ModelPoolPurpose = "general",
    include_unhealthy: bool = False,
) -> list[ModelPoolNode]:
    if model_router_service.gateway_channels_configured():
        return [
            _node_from_gateway_channel(channel)
            for channel in model_router_service.select_gateway_channels(
                capability=capability,
                purpose=purpose,
                include_unhealthy=include_unhealthy,
            )
        ]
    candidates = [
        node
        for node in read_model_pool_nodes(include_disabled=False)
        if _node_supports_capability(node, capability)
    ]
    if not include_unhealthy:
        healthy = [node for node in candidates if _node_snapshot(node).healthy]
        if healthy:
            candidates = healthy
    return _ordered_candidates(candidates, purpose=purpose)


def build_model_pool_provider(
    *,
    node: ModelPoolNode,
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
    fallback_to_mock: bool = False,
) -> ProviderBuildResult:
    gateway_channel = _gateway_channel_from_node(node)
    if gateway_channel is not None:
        return model_router_service.build_gateway_provider(
            channel=gateway_channel,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
            fallback_to_mock=fallback_to_mock,
        )
    return build_provider(
        provider_name=node.provider_name,
        model=node.model,
        base_url=node.base_url,
        wire_api=wire_api_override or node.wire_api,
        timeout_seconds=node.timeout_seconds,
        api_key=node.api_key,
        chat_json_mode=node.supports_json_mode if chat_json_mode is None else bool(chat_json_mode),
        fallback_to_mock=fallback_to_mock,
    )


def first_provider_candidate(
    *,
    capability: ModelPoolCapability,
    purpose: ModelPoolPurpose,
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
) -> ModelPoolProviderCandidate:
    nodes = select_model_pool_nodes(capability=capability, purpose=purpose)
    if not nodes:
        raise RuntimeError("模型池中没有满足当前能力要求的可用模型")
    node = nodes[0]
    return ModelPoolProviderCandidate(
        node=node,
        provider_result=build_model_pool_provider(
            node=node,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
            fallback_to_mock=False,
        ),
    )


def generate_with_model_pool(
    request: LLMRequest,
    *,
    capability: ModelPoolCapability = "any",
    purpose: ModelPoolPurpose = "general",
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
) -> ModelPoolCallResult:
    if model_router_service.gateway_channels_configured():
        result = model_router_service.generate_with_gateway(
            request,
            capability=capability,
            purpose=purpose,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
        )
        return ModelPoolCallResult(
            node=_node_from_gateway_channel(result.channel),
            provider_result=result.provider_result,
            content=result.content,
            latency_ms=result.latency_ms,
            attempts=[_record_from_gateway_record(record) for record in result.attempts],
        )
    nodes = select_model_pool_nodes(capability=capability, purpose=purpose)
    if not nodes:
        raise RuntimeError("模型池中没有满足当前能力要求的可用模型")
    attempts: list[ModelPoolCallRecord] = []
    last_exc: Exception | None = None
    for node in nodes:
        provider_result = build_model_pool_provider(
            node=node,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
            fallback_to_mock=False,
        )
        started_at = time.perf_counter()
        try:
            content = provider_result.provider.generate(request)
            latency_ms = _elapsed_ms(started_at)
            record = _record_call(
                node=node,
                latency_ms=latency_ms,
                success=True,
                purpose=purpose,
            )
            attempts.append(record)
            return ModelPoolCallResult(
                node=node,
                provider_result=provider_result,
                content=content,
                latency_ms=latency_ms,
                attempts=attempts,
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            latency_ms = _elapsed_ms(started_at)
            record = _record_call(
                node=node,
                latency_ms=latency_ms,
                success=False,
                error=_humanize_error(exc),
                status_code=_extract_status_code(exc),
                purpose=purpose,
            )
            attempts.append(record)
            if not _can_fallback_after_error(exc):
                raise
    if last_exc is not None:
        raise last_exc
    raise RuntimeError("模型池调用失败")


def stream_with_model_pool(
    request: LLMRequest,
    *,
    capability: ModelPoolCapability = "streaming",
    purpose: ModelPoolPurpose = "streaming_reply",
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
) -> ModelPoolStreamResult:
    if model_router_service.gateway_channels_configured():
        gateway_result = model_router_service.stream_with_gateway(
            request,
            capability=capability,
            purpose=purpose,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
        )
        attempts: list[ModelPoolCallRecord] = []

        def _iter_gateway_stream() -> Iterator[str]:
            try:
                yield from gateway_result.chunks
            finally:
                attempts[:] = [_record_from_gateway_record(record) for record in gateway_result.attempts]

        return ModelPoolStreamResult(
            node=_node_from_gateway_channel(gateway_result.channel),
            provider_result=gateway_result.provider_result,
            chunks=_iter_gateway_stream(),
            attempts=attempts,
        )
    nodes = select_model_pool_nodes(capability=capability, purpose=purpose)
    if not nodes:
        raise RuntimeError("模型池中没有满足当前能力要求的可用模型")
    attempts: list[ModelPoolCallRecord] = []

    def _iter_stream() -> Iterator[str]:
        last_exc: Exception | None = None
        for node in nodes:
            provider_result = build_model_pool_provider(
                node=node,
                wire_api_override=wire_api_override,
                chat_json_mode=chat_json_mode,
                fallback_to_mock=False,
            )
            started_at = time.perf_counter()
            emitted_any = False
            try:
                for chunk in provider_result.provider.stream_generate(request):
                    emitted_any = True
                    yield chunk
                record = _record_call(
                    node=node,
                    latency_ms=_elapsed_ms(started_at),
                    success=True,
                    purpose=purpose,
                )
                attempts.append(record)
                return
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                record = _record_call(
                    node=node,
                    latency_ms=_elapsed_ms(started_at),
                    success=False,
                    error=_humanize_error(exc),
                    status_code=_extract_status_code(exc),
                    purpose=purpose,
                )
                attempts.append(record)
                if emitted_any or not _can_fallback_after_error(exc):
                    raise
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("模型池流式调用失败")

    first = first_provider_candidate(
        capability=capability,
        purpose=purpose,
        wire_api_override=wire_api_override,
        chat_json_mode=chat_json_mode,
    )
    return ModelPoolStreamResult(
        node=first.node,
        provider_result=first.provider_result,
        chunks=_iter_stream(),
        attempts=attempts,
    )


def probe_model_pool_node(node_id: str) -> ModelPoolCallRecord | None:
    if model_router_service.gateway_channels_configured():
        record = model_router_service.probe_gateway_channel(node_id, include_disabled=False)
        return _record_from_gateway_record(record) if record is not None else None
    node = next((item for item in read_model_pool_nodes(include_disabled=True) if item.id == node_id), None)
    if node is None or not node.enabled or node.is_mock:
        return None
    request = LLMRequest.from_text(
        "1+1=",
        system_prompt="你是连通性探针。请只返回一个字符：2。",
    )
    started_at = time.perf_counter()
    try:
        provider_result = build_model_pool_provider(node=node, fallback_to_mock=False)
        provider_result.provider.generate(request)
        return _record_call(node=node, latency_ms=_elapsed_ms(started_at), success=True, purpose="probe")
    except Exception as exc:  # noqa: BLE001
        return _record_call(
            node=node,
            latency_ms=_elapsed_ms(started_at),
            success=False,
            error=_humanize_error(exc),
            status_code=_extract_status_code(exc),
            purpose="probe",
        )


def probe_unhealthy_model_pool_nodes() -> dict[str, Any]:
    if model_router_service.gateway_channels_configured():
        return model_router_service.check_cooldown_channels()
    results: list[dict[str, Any]] = []
    for node in read_model_pool_nodes(include_disabled=False):
        snapshot = _node_snapshot(node)
        if snapshot.healthy and snapshot.state != "half_open":
            continue
        record = probe_model_pool_node(node.id)
        if record is None:
            continue
        results.append(_record_to_payload(record))
    return {"probed": len(results), "results": results}


def get_model_pool_status() -> dict[str, Any]:
    if model_router_service.gateway_channels_configured():
        return model_router_service.get_gateway_status()
    nodes = read_model_pool_nodes(include_disabled=True)
    snapshots = [_node_snapshot(node) for node in nodes]
    return {
        "enabled": bool(nodes),
        "nodes": [_snapshot_to_payload(snapshot) for snapshot in snapshots],
        "routing": {
            "agent_decision": [node.id for node in select_model_pool_nodes(capability="json_mode", purpose="agent_decision", include_unhealthy=True)],
            "streaming_reply": [node.id for node in select_model_pool_nodes(capability="streaming", purpose="streaming_reply", include_unhealthy=True)],
        },
    }


def reset_local_model_pool_state() -> None:
    with _local_lock:
        _local_records.clear()
        _local_circuits.clear()
    model_router_service.reset_local_gateway_state()


def _parse_model_pool_nodes(raw_value: str) -> list[ModelPoolNode]:
    normalized = str(raw_value or "").strip()
    if not normalized:
        return []
    try:
        payload = json.loads(normalized)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        raw_nodes = payload.get("nodes")
    else:
        raw_nodes = payload
    if not isinstance(raw_nodes, list):
        return []
    nodes: list[ModelPoolNode] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw_nodes):
        if not isinstance(item, dict):
            continue
        node = _parse_model_pool_node(item, index=index)
        if node is None or node.id in seen_ids:
            continue
        seen_ids.add(node.id)
        nodes.append(node)
    return nodes


def _parse_model_pool_node(item: dict[str, Any], *, index: int) -> ModelPoolNode | None:
    provider_name = normalize_provider_name(str(item.get("provider") or item.get("provider_name") or "custom_proxy"))
    model = str(item.get("model") or "").strip()
    if not model:
        return None
    base_url = str(item.get("base_url") or "").strip()
    api_key = str(item.get("api_key") or "").strip()
    if api_key.startswith("env:"):
        api_key = read_runtime_env_value(api_key[4:].strip(), "")
    node_id = str(item.get("id") or f"{provider_name}:{model}:{base_url or index}").strip()
    return ModelPoolNode(
        id=node_id,
        provider_name=provider_name,
        model=model,
        base_url=base_url,
        api_key=api_key,
        wire_api=str(item.get("wire_api") or "").strip(),
        timeout_seconds=_safe_int(item.get("timeout_seconds"), default=int(settings.LLM_TIMEOUT_SECONDS or 60), minimum=1),
        priority=_safe_int(item.get("priority"), default=100, minimum=0),
        weight=max(float(item.get("weight") or 1.0), 0.01),
        supports_json_mode=bool(item.get("supports_json_mode", provider_name in {"openai", "minimax", "custom_proxy"})),
        supports_streaming=bool(item.get("supports_streaming", provider_name in {"openai", "minimax", "custom_proxy", "ollama_remote"})),
        enabled=bool(item.get("enabled", True)),
        cost_tier=str(item.get("cost_tier") or "standard").strip().lower() or "standard",
        quality_tier=str(item.get("quality_tier") or "standard").strip().lower() or "standard",
        tags=tuple(str(tag).strip() for tag in item.get("tags", []) if str(tag).strip()) if isinstance(item.get("tags"), list) else (),
    )


def _legacy_single_node() -> ModelPoolNode:
    provider_name = normalize_provider_name(read_runtime_env_value("LLM_PROVIDER", str(settings.LLM_PROVIDER or "mock")))
    return ModelPoolNode(
        id=f"legacy-{provider_name}",
        provider_name=provider_name,
        model=read_runtime_env_value("LLM_MODEL", str(settings.LLM_MODEL or "gpt-4o-mini")),
        base_url=read_runtime_env_value("LLM_BASE_URL", str(settings.LLM_BASE_URL or "")),
        api_key=read_runtime_env_value("LLM_API_KEY", str(settings.LLM_API_KEY or "")),
        wire_api=read_runtime_env_value("LLM_WIRE_API", str(settings.LLM_WIRE_API or "responses")),
        timeout_seconds=_safe_int(read_runtime_env_value("LLM_TIMEOUT_SECONDS", str(settings.LLM_TIMEOUT_SECONDS or 60)), default=60, minimum=1),
        priority=100,
        supports_json_mode=provider_name in {"openai", "minimax", "custom_proxy"},
        supports_streaming=provider_name in {"openai", "minimax", "custom_proxy", "ollama_remote"},
        cost_tier="standard",
        quality_tier="standard",
    )


def _node_from_gateway_channel(channel: model_router_service.GatewayChannel) -> ModelPoolNode:
    return ModelPoolNode(
        id=f"channel-{channel.id}",
        provider_name=channel.provider_name,
        model=channel.model_name,
        base_url=channel.api_base,
        api_key=channel.api_key,
        wire_api=channel.wire_api,
        timeout_seconds=channel.timeout_seconds,
        priority=channel.priority,
        weight=channel.weight,
        supports_json_mode=channel.supports_json_mode,
        supports_streaming=channel.supports_streaming,
        enabled=channel.enabled,
        cost_tier="local" if channel.provider in {"ollama"} or "local" in channel.tags else "standard",
        quality_tier="standard",
        tags=channel.tags,
    )


def _gateway_channel_from_node(node: ModelPoolNode) -> model_router_service.GatewayChannel | None:
    if not str(node.id).startswith("channel-"):
        return None
    return next(
        (
            channel
            for channel in model_router_service.read_gateway_channels(include_disabled=True)
            if f"channel-{channel.id}" == node.id
        ),
        None,
    )


def _record_from_gateway_record(record: model_router_service.GatewayCallRecord) -> ModelPoolCallRecord:
    return ModelPoolCallRecord(
        node_id=f"channel-{record.channel_id}",
        provider_name=record.provider_name,
        model=record.model,
        latency_ms=record.latency_ms,
        success=record.success,
        error=record.error,
        status_code=record.status_code,
        purpose=record.purpose,
        timestamp=record.timestamp,
    )


def _node_supports_capability(node: ModelPoolNode, capability: ModelPoolCapability) -> bool:
    if capability == "json_mode":
        return node.supports_json_mode
    if capability == "streaming":
        return node.supports_streaming
    return True


def _ordered_candidates(nodes: list[ModelPoolNode], *, purpose: ModelPoolPurpose) -> list[ModelPoolNode]:
    ranked = list(nodes)
    if purpose == "agent_decision":
        ranked.sort(key=lambda item: (item.priority, _quality_rank(item.quality_tier), -_dynamic_weight(item), item.id))
        return ranked
    if purpose == "streaming_reply":
        ranked.sort(key=lambda item: (item.priority, -_dynamic_weight(item), _cost_rank(item.cost_tier), item.id))
        return ranked
    ranked.sort(key=lambda item: (item.priority, -_dynamic_weight(item), item.id))
    return ranked


def _dynamic_weight(node: ModelPoolNode) -> float:
    snapshot = _node_snapshot(node)
    latency = snapshot.average_latency_ms or 1000
    latency_weight = 1000.0 / max(float(latency), 1.0)
    health_weight = 0.2 if not snapshot.healthy else 1.0
    jitter = random.random() * 0.001
    return max(node.weight, 0.01) * latency_weight * health_weight + jitter


def _quality_rank(value: str) -> int:
    normalized = str(value or "").lower()
    if normalized in {"high", "premium", "reasoning"}:
        return 0
    if normalized in {"standard", "balanced"}:
        return 1
    return 2


def _cost_rank(value: str) -> int:
    normalized = str(value or "").lower()
    if normalized in {"local", "low", "cheap"}:
        return 0
    if normalized in {"standard", "balanced"}:
        return 1
    return 2


def _record_call(
    *,
    node: ModelPoolNode,
    latency_ms: int,
    success: bool,
    purpose: ModelPoolPurpose,
    error: str = "",
    status_code: int | None = None,
) -> ModelPoolCallRecord:
    record = ModelPoolCallRecord(
        node_id=node.id,
        provider_name=node.provider_name,
        model=node.model,
        latency_ms=latency_ms,
        success=success,
        error=sanitize_text(error, max_length=300) or "",
        status_code=status_code,
        purpose=purpose,
    )
    _persist_call_record(node, record)
    _update_circuit_state(node, record)
    return record


def _persist_call_record(node: ModelPoolNode, record: ModelPoolCallRecord) -> None:
    payload = json.dumps(_record_to_payload(record), ensure_ascii=False)
    try:
        client = _redis_client()
        key = _records_key(node.id)
        pipe = client.pipeline()
        pipe.lpush(key, payload)
        pipe.ltrim(key, 0, DEFAULT_POOL_METRICS_WINDOW - 1)
        pipe.expire(key, 86400)
        pipe.execute()
        client.close()
        return
    except Exception:
        pass
    with _local_lock:
        records = _local_records.setdefault(node.id, [])
        records.insert(0, _record_to_payload(record))
        del records[DEFAULT_POOL_METRICS_WINDOW:]


def _update_circuit_state(node: ModelPoolNode, record: ModelPoolCallRecord) -> None:
    now = time.time()
    state = _load_circuit_state(node.id)
    if record.success:
        updated = {
            "consecutive_failures": 0,
            "circuit_open_until": 0,
            "hard_isolated": False,
            "last_error": "",
            "last_status_code": None,
            "last_seen_at": now,
        }
        _save_circuit_state(node.id, updated)
        return

    consecutive_failures = int(state.get("consecutive_failures") or 0) + 1
    hard_isolated = record.status_code in HARD_FAILURE_STATUS_CODES
    circuit_open_until = 0 if not hard_isolated else now + 86400
    if not hard_isolated and (consecutive_failures >= DEFAULT_SOFT_FAILURE_THRESHOLD or record.status_code in SOFT_FAILURE_STATUS_CODES):
        circuit_open_until = now + DEFAULT_SOFT_CIRCUIT_SECONDS
    updated = {
        "consecutive_failures": consecutive_failures,
        "circuit_open_until": circuit_open_until,
        "hard_isolated": hard_isolated,
        "last_error": record.error,
        "last_status_code": record.status_code,
        "last_seen_at": now,
    }
    _save_circuit_state(node.id, updated)


def _node_snapshot(node: ModelPoolNode) -> ModelPoolNodeSnapshot:
    records = _load_records(node.id)
    state = _load_circuit_state(node.id)
    now = time.time()
    circuit_open_until = float(state.get("circuit_open_until") or 0)
    hard_isolated = bool(state.get("hard_isolated"))
    healthy = node.enabled and not hard_isolated and circuit_open_until <= now
    state_label = "healthy"
    if hard_isolated:
        state_label = "isolated"
    elif circuit_open_until > now:
        state_label = "open"
    elif int(state.get("consecutive_failures") or 0) > 0:
        state_label = "half_open"
    successes = [item for item in records if bool(item.get("success"))]
    latency_values = [int(item.get("latency_ms") or 0) for item in successes if int(item.get("latency_ms") or 0) > 0]
    avg_latency = int(sum(latency_values) / len(latency_values)) if latency_values else None
    return ModelPoolNodeSnapshot(
        node=node,
        healthy=healthy,
        state=state_label,
        average_latency_ms=avg_latency,
        success_count=len(successes),
        error_count=len(records) - len(successes),
        consecutive_failures=int(state.get("consecutive_failures") or 0),
        circuit_open_until=circuit_open_until,
        last_error=str(state.get("last_error") or ""),
        last_status_code=state.get("last_status_code") if isinstance(state.get("last_status_code"), int) else None,
        last_seen_at=float(state.get("last_seen_at") or 0) or None,
    )


def _load_records(node_id: str) -> list[dict[str, Any]]:
    try:
        client = _redis_client()
        rows = client.lrange(_records_key(node_id), 0, DEFAULT_POOL_METRICS_WINDOW - 1)
        client.close()
        records: list[dict[str, Any]] = []
        for row in rows:
            try:
                item = json.loads(row)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                records.append(item)
        return records
    except Exception:
        pass
    with _local_lock:
        return list(_local_records.get(node_id, []))


def _load_circuit_state(node_id: str) -> dict[str, Any]:
    try:
        client = _redis_client()
        raw_payload = client.get(_circuit_key(node_id))
        client.close()
        if raw_payload:
            payload = json.loads(raw_payload)
            if isinstance(payload, dict):
                return payload
    except Exception:
        pass
    with _local_lock:
        return dict(_local_circuits.get(node_id, {}))


def _save_circuit_state(node_id: str, payload: dict[str, Any]) -> None:
    try:
        client = _redis_client()
        client.set(_circuit_key(node_id), json.dumps(payload, ensure_ascii=False), ex=86400)
        client.close()
        return
    except Exception:
        pass
    with _local_lock:
        _local_circuits[node_id] = dict(payload)


def _can_fallback_after_error(exc: Exception) -> bool:
    status_code = _extract_status_code(exc)
    if status_code in HARD_FAILURE_STATUS_CODES:
        return True
    if status_code is None:
        return True
    return status_code in SOFT_FAILURE_STATUS_CODES or status_code >= 500


def _extract_status_code(exc: Exception) -> int | None:
    if isinstance(exc, httpx.HTTPStatusError):
        return int(exc.response.status_code)
    return None


def _humanize_error(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http_{exc.response.status_code}"
    if isinstance(exc, httpx.RequestError):
        return "request_error"
    return sanitize_text(str(exc), max_length=300) or exc.__class__.__name__


def _safe_int(value: Any, *, default: int, minimum: int) -> int:
    try:
        return max(int(value), minimum)
    except (TypeError, ValueError):
        return max(default, minimum)


def _elapsed_ms(started_at: float) -> int:
    return max(0, int((time.perf_counter() - started_at) * 1000))


def _redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def _records_key(node_id: str) -> str:
    return f"{_redis_prefix()}:records:{node_id}"


def _circuit_key(node_id: str) -> str:
    return f"{_redis_prefix()}:circuit:{node_id}"


def _redis_prefix() -> str:
    return str(getattr(settings, "LLM_MODEL_POOL_REDIS_PREFIX", "sa:model_pool") or "sa:model_pool").strip() or "sa:model_pool"


def _record_to_payload(record: ModelPoolCallRecord) -> dict[str, Any]:
    return {
        "node_id": record.node_id,
        "provider_name": record.provider_name,
        "model": record.model,
        "latency_ms": record.latency_ms,
        "success": record.success,
        "error": record.error,
        "status_code": record.status_code,
        "purpose": record.purpose,
        "timestamp": record.timestamp,
    }


def _snapshot_to_payload(snapshot: ModelPoolNodeSnapshot) -> dict[str, Any]:
    node = snapshot.node
    return {
        "id": node.id,
        "provider_name": node.provider_name,
        "model": node.model,
        "base_url": node.base_url,
        "priority": node.priority,
        "weight": node.weight,
        "supports_json_mode": node.supports_json_mode,
        "supports_streaming": node.supports_streaming,
        "enabled": node.enabled,
        "cost_tier": node.cost_tier,
        "quality_tier": node.quality_tier,
        "healthy": snapshot.healthy,
        "state": snapshot.state,
        "average_latency_ms": snapshot.average_latency_ms,
        "success_count": snapshot.success_count,
        "error_count": snapshot.error_count,
        "consecutive_failures": snapshot.consecutive_failures,
        "circuit_open_until": snapshot.circuit_open_until,
        "last_error": snapshot.last_error,
        "last_status_code": snapshot.last_status_code,
        "last_seen_at": snapshot.last_seen_at,
    }
