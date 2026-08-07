from __future__ import annotations

import json
import logging
import math
import random
import threading
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

import httpx
from redis import Redis
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import decrypt_text, encrypt_text
from app.db.models.ai_channel import AIChannel
from app.db.session import SessionLocal
from app.services.ai.providers import LLMRequest, ProviderBuildResult, build_provider, normalize_provider_name
from app.utils.sanitize import sanitize_text

logger = logging.getLogger(__name__)

GatewayCapability = Literal["json_mode", "streaming", "any"]
GatewayPurpose = Literal["agent_decision", "streaming_reply", "general", "probe"]

CONFIG_UPDATED_CHANNEL = "channel:config:updated"
DEFAULT_GATEWAY_REDIS_PREFIX = "ai_pool"
METRICS_WINDOW_SECONDS = 30 * 60
MONITOR_WINDOW_SECONDS = 10 * 60
RATE_LIMIT_COOLDOWN_SECONDS = 60
SERVER_ERROR_COOLDOWN_SECONDS = 300
CONSECUTIVE_FAILURE_THRESHOLD = 3
FAILURE_COUNTER_TTL_SECONDS = 10 * 60
AUTH_FAILURE_STATUS_CODES = {401, 403}
RETRYABLE_STATUS_CODES = {408, 409, 429, 500, 502, 503, 504}
SUPPORTED_CHANNEL_STATUSES = {"active", "disabled"}


@dataclass(frozen=True, slots=True)
class GatewayChannel:
    id: int
    name: str
    provider: str
    provider_name: str
    api_base: str
    api_key: str
    model_name: str
    priority: int
    status: str
    wire_api: str = ""
    timeout_seconds: int = 60
    supports_json_mode: bool = True
    supports_streaming: bool = True
    weight: float = 1.0
    tags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def enabled(self) -> bool:
        return self.status == "active"


@dataclass(frozen=True, slots=True)
class GatewayCallRecord:
    channel_id: int
    provider: str
    provider_name: str
    model: str
    latency_ms: int
    success: bool
    status_code: int | None = None
    error: str = ""
    purpose: str = "general"
    timestamp: float = field(default_factory=time.time)


@dataclass(frozen=True, slots=True)
class GatewayChannelSnapshot:
    channel: GatewayChannel
    health_status: str
    cooldown_ttl_seconds: int
    healthy: bool
    request_count: int
    success_count: int
    error_count: int
    success_rate: float | None
    average_latency_ms: int | None
    tp90_latency_ms: int | None
    consecutive_failures: int
    last_error: str
    last_status_code: int | None
    last_seen_at: float | None


@dataclass(frozen=True, slots=True)
class GatewayCallResult:
    channel: GatewayChannel
    provider_result: ProviderBuildResult
    content: str
    latency_ms: int
    attempts: list[GatewayCallRecord]


@dataclass(frozen=True, slots=True)
class GatewayStreamResult:
    channel: GatewayChannel
    provider_result: ProviderBuildResult
    chunks: Iterator[str]
    attempts: list[GatewayCallRecord]


class GatewayError(Exception):
    pass


class RetryableGatewayError(GatewayError):
    pass


class NoAvailableGatewayChannelError(GatewayError):
    pass


_cache_lock = threading.RLock()
_channel_cache: list[GatewayChannel] | None = None
_channel_cache_loaded_at = 0.0
_channel_cache_ttl_seconds = 30.0

_local_lock = threading.Lock()
_local_cooldowns: dict[int, float] = {}
_local_failures: dict[int, int] = {}
_local_records: dict[int, list[dict[str, Any]]] = {}
_subscriber_lock = threading.Lock()
_subscriber_thread: threading.Thread | None = None
_subscriber_stop_event: threading.Event | None = None


def gateway_channels_configured() -> bool:
    try:
        return bool(read_gateway_channels(include_disabled=True))
    except Exception:
        return False


def read_gateway_channels(*, include_disabled: bool = False, force_reload: bool = False) -> list[GatewayChannel]:
    now = time.time()
    global _channel_cache, _channel_cache_loaded_at
    with _cache_lock:
        if force_reload or _channel_cache is None or now - _channel_cache_loaded_at > _channel_cache_ttl_seconds:
            _channel_cache = _load_channels_from_db()
            _channel_cache_loaded_at = now
        channels = list(_channel_cache)
    if not include_disabled:
        channels = [channel for channel in channels if channel.enabled]
    return sorted(channels, key=lambda item: (-item.priority, item.id))


def refresh_gateway_channel_cache() -> list[GatewayChannel]:
    return read_gateway_channels(include_disabled=True, force_reload=True)


def invalidate_gateway_channel_cache() -> None:
    global _channel_cache, _channel_cache_loaded_at
    with _cache_lock:
        _channel_cache = None
        _channel_cache_loaded_at = 0.0


def publish_gateway_config_updated(*, reason: str = "manual") -> None:
    invalidate_gateway_channel_cache()
    payload = json.dumps({"event": "config_updated", "reason": reason, "timestamp": time.time()}, ensure_ascii=False)
    try:
        client = _redis_client()
        client.publish(CONFIG_UPDATED_CHANNEL, payload)
        client.close()
    except Exception as exc:
        logger.debug("Failed to publish AI gateway config update: %s", exc)


def start_gateway_config_subscriber(*, service_name: str = "backend") -> None:
    global _subscriber_thread, _subscriber_stop_event
    with _subscriber_lock:
        if _subscriber_thread is not None and _subscriber_thread.is_alive():
            return
        stop_event = threading.Event()
        thread = threading.Thread(
            target=_config_subscriber_loop,
            kwargs={"stop_event": stop_event, "service_name": service_name},
            name=f"ai-gateway-config-subscriber-{service_name}",
            daemon=True,
        )
        _subscriber_stop_event = stop_event
        _subscriber_thread = thread
        thread.start()


def stop_gateway_config_subscriber() -> None:
    global _subscriber_thread, _subscriber_stop_event
    with _subscriber_lock:
        stop_event = _subscriber_stop_event
        thread = _subscriber_thread
        _subscriber_stop_event = None
        _subscriber_thread = None
    if stop_event is not None:
        stop_event.set()
    if thread is not None and thread.is_alive():
        thread.join(timeout=2.0)


def select_gateway_channels(
    *,
    capability: GatewayCapability = "any",
    purpose: GatewayPurpose = "general",
    task_type: str = "general",
    include_unhealthy: bool = False,
) -> list[GatewayChannel]:
    channels = [
        channel
        for channel in read_gateway_channels(include_disabled=False)
        if _channel_supports_capability(channel, capability)
    ]
    if str(task_type or "").strip().lower() == "secure_ssh":
        channels = [channel for channel in channels if _is_secure_local_channel(channel)]
    if not include_unhealthy:
        healthy = [channel for channel in channels if get_channel_health(channel.id).get("health_status") == "healthy"]
        if healthy:
            channels = healthy
    return _ordered_channels(channels, purpose=purpose)


def build_gateway_provider(
    *,
    channel: GatewayChannel,
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
    fallback_to_mock: bool = False,
) -> ProviderBuildResult:
    return build_provider(
        provider_name=channel.provider_name,
        model=channel.model_name,
        base_url=channel.api_base,
        wire_api=wire_api_override or channel.wire_api,
        timeout_seconds=channel.timeout_seconds,
        api_key=channel.api_key,
        chat_json_mode=channel.supports_json_mode if chat_json_mode is None else bool(chat_json_mode),
        fallback_to_mock=fallback_to_mock,
    )


def generate_with_gateway(
    request: LLMRequest,
    *,
    capability: GatewayCapability = "any",
    purpose: GatewayPurpose = "general",
    task_type: str = "general",
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
) -> GatewayCallResult:
    channels = select_gateway_channels(capability=capability, purpose=purpose, task_type=task_type)
    if not channels:
        raise NoAvailableGatewayChannelError("AI Gateway 没有满足当前要求的可用通道")
    attempts: list[GatewayCallRecord] = []
    last_exc: Exception | None = None
    for channel in channels:
        provider_result = build_gateway_provider(
            channel=channel,
            wire_api_override=wire_api_override,
            chat_json_mode=chat_json_mode,
            fallback_to_mock=False,
        )
        try:
            content, latency_ms, record = execute_request_with_monitor(
                channel=channel,
                purpose=purpose,
                operation=lambda: provider_result.provider.generate(request),
            )
            attempts.append(record)
            return GatewayCallResult(
                channel=channel,
                provider_result=provider_result,
                content=content,
                latency_ms=latency_ms,
                attempts=attempts,
            )
        except RetryableGatewayError as exc:
            last_exc = exc
            if exc.__cause__ is not None:
                last_exc = exc.__cause__
            logger.warning("AI Gateway channel %s failed; trying fallback: %s", channel.name, exc)
            attempts.extend(_records_from_gateway_error(exc))
            continue
        except Exception as exc:
            last_exc = exc
            logger.warning("AI Gateway channel %s failed; trying fallback: %s", channel.name, exc)
            continue
    if last_exc is not None:
        raise last_exc
    raise NoAvailableGatewayChannelError("所有 AI Gateway 通道均不可用")


def stream_with_gateway(
    request: LLMRequest,
    *,
    capability: GatewayCapability = "streaming",
    purpose: GatewayPurpose = "streaming_reply",
    task_type: str = "general",
    wire_api_override: str | None = None,
    chat_json_mode: bool | None = None,
) -> GatewayStreamResult:
    channels = select_gateway_channels(capability=capability, purpose=purpose, task_type=task_type)
    if not channels:
        raise NoAvailableGatewayChannelError("AI Gateway 没有满足当前要求的可用流式通道")
    attempts: list[GatewayCallRecord] = []
    first_provider_result = build_gateway_provider(
        channel=channels[0],
        wire_api_override=wire_api_override,
        chat_json_mode=chat_json_mode,
        fallback_to_mock=False,
    )

    def _iter_stream() -> Iterator[str]:
        last_exc: Exception | None = None
        for channel in channels:
            provider_result = build_gateway_provider(
                channel=channel,
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
                record = record_gateway_success(channel=channel, latency_ms=_elapsed_ms(started_at), purpose=purpose)
                attempts.append(record)
                return
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                latency_ms = _elapsed_ms(started_at)
                record = record_gateway_failure(
                    channel=channel,
                    latency_ms=latency_ms,
                    purpose=purpose,
                    exc=exc,
                )
                attempts.append(record)
                if emitted_any or not _can_failover_after_exception(exc):
                    raise
                logger.warning("AI Gateway stream channel %s failed; trying fallback: %s", channel.name, exc)
        if last_exc is not None:
            raise last_exc
        raise NoAvailableGatewayChannelError("所有 AI Gateway 流式通道均不可用")

    return GatewayStreamResult(
        channel=channels[0],
        provider_result=first_provider_result,
        chunks=_iter_stream(),
        attempts=attempts,
    )


def execute_request_with_monitor(
    *,
    channel: GatewayChannel,
    purpose: GatewayPurpose,
    operation,
) -> tuple[str, int, GatewayCallRecord]:  # type: ignore[no-untyped-def]
    started_at = time.perf_counter()
    try:
        content = operation()
        latency_ms = _elapsed_ms(started_at)
        record = record_gateway_success(channel=channel, latency_ms=latency_ms, purpose=purpose)
        return str(content or ""), latency_ms, record
    except Exception as exc:  # noqa: BLE001
        latency_ms = _elapsed_ms(started_at)
        record = record_gateway_failure(channel=channel, latency_ms=latency_ms, purpose=purpose, exc=exc)
        wrapped = RetryableGatewayError(_humanize_error(exc))
        setattr(wrapped, "_gateway_records", [record])
        raise wrapped from exc


def record_gateway_success(*, channel: GatewayChannel, latency_ms: int, purpose: GatewayPurpose) -> GatewayCallRecord:
    record = GatewayCallRecord(
        channel_id=channel.id,
        provider=channel.provider,
        provider_name=channel.provider_name,
        model=channel.model_name,
        latency_ms=latency_ms,
        success=True,
        status_code=200,
        purpose=purpose,
    )
    _record_metric(record)
    _clear_failure_state(channel.id)
    _clear_cooldown(channel.id)
    aggregate_channel_metrics(channel.id)
    return record


def record_gateway_failure(
    *,
    channel: GatewayChannel,
    latency_ms: int,
    purpose: GatewayPurpose,
    exc: Exception,
) -> GatewayCallRecord:
    status_code = _extract_status_code(exc)
    error = _humanize_error(exc)
    record = GatewayCallRecord(
        channel_id=channel.id,
        provider=channel.provider,
        provider_name=channel.provider_name,
        model=channel.model_name,
        latency_ms=latency_ms,
        success=False,
        status_code=status_code,
        error=error,
        purpose=purpose,
    )
    _record_metric(record)
    if status_code in AUTH_FAILURE_STATUS_CODES:
        disable_gateway_channel(channel.id, reason="auth_failed")
    elif status_code == 429:
        cooldown_gateway_channel(channel.id, ttl_seconds=RATE_LIMIT_COOLDOWN_SECONDS, reason="rate_limited")
    else:
        failure_count = _increment_failure_count(channel.id)
        if status_code is None or status_code >= 500 or failure_count >= CONSECUTIVE_FAILURE_THRESHOLD:
            cooldown_gateway_channel(channel.id, ttl_seconds=SERVER_ERROR_COOLDOWN_SECONDS, reason="server_or_network_error")
    aggregate_channel_metrics(channel.id)
    return record


def probe_gateway_channel(channel_id: int | str, *, include_disabled: bool = True) -> GatewayCallRecord | None:
    channel = _find_channel(channel_id, include_disabled=include_disabled)
    if channel is None:
        return None
    request = LLMRequest.from_text(
        "hi",
        system_prompt="你是 AI Gateway 连通性探针。请只返回 OK。",
    )
    started_at = time.perf_counter()
    try:
        provider_result = build_gateway_provider(channel=channel, fallback_to_mock=False)
        provider_result.provider.generate(request)
        return record_gateway_success(channel=channel, latency_ms=_elapsed_ms(started_at), purpose="probe")
    except Exception as exc:  # noqa: BLE001
        return record_gateway_failure(
            channel=channel,
            latency_ms=_elapsed_ms(started_at),
            purpose="probe",
            exc=exc,
        )


def check_cooldown_channels() -> dict[str, Any]:
    cooldown_ids = sorted(_cooldown_channel_ids())
    results: list[dict[str, Any]] = []
    for channel_id in cooldown_ids:
        record = probe_gateway_channel(channel_id, include_disabled=False)
        if record is None:
            continue
        payload = _record_to_payload(record)
        results.append(payload)
        if record.success:
            logger.info("[Recovery] AI Gateway channel %s recovered", channel_id)
    return {"probed": len(results), "results": results}


def aggregate_gateway_metrics() -> dict[str, Any]:
    channels = read_gateway_channels(include_disabled=True)
    snapshots = [aggregate_channel_metrics(channel.id) for channel in channels]
    return {"channels": len(snapshots), "snapshots": snapshots}


def aggregate_channel_metrics(channel_id: int | str) -> dict[str, Any]:
    normalized_id = _normalize_channel_id(channel_id)
    records = _load_metric_records(normalized_id, window_seconds=MONITOR_WINDOW_SECONDS)
    successes = [record for record in records if bool(record.get("success"))]
    latency_values = sorted(int(record.get("latency_ms") or 0) for record in successes if int(record.get("latency_ms") or 0) > 0)
    request_count = len(records)
    success_count = len(successes)
    error_count = request_count - success_count
    success_rate = round(success_count / request_count, 4) if request_count else None
    average_latency_ms = int(sum(latency_values) / len(latency_values)) if latency_values else None
    tp90_latency_ms = _percentile(latency_values, 0.9)
    last_record = max(records, key=lambda item: float(item.get("timestamp") or 0), default={})
    health = get_channel_health(normalized_id)
    payload = {
        "channel_id": normalized_id,
        "health_status": health["health_status"],
        "cooldown_ttl_seconds": health["cooldown_ttl_seconds"],
        "request_count": request_count,
        "success_count": success_count,
        "error_count": error_count,
        "success_rate": success_rate,
        "average_latency_ms": average_latency_ms,
        "tp90_latency_ms": tp90_latency_ms,
        "consecutive_failures": _get_failure_count(normalized_id),
        "last_error": str(last_record.get("error") or ""),
        "last_status_code": last_record.get("status_code") if isinstance(last_record.get("status_code"), int) else None,
        "last_seen_at": float(last_record.get("timestamp") or 0) or None,
        "updated_at": time.time(),
    }
    _save_aggregate_payload(normalized_id, payload)
    return payload


def get_gateway_status() -> dict[str, Any]:
    channels = read_gateway_channels(include_disabled=True)
    snapshots = [build_channel_snapshot(channel) for channel in channels]
    return {
        "enabled": any(snapshot.channel.enabled for snapshot in snapshots),
        "nodes": [_snapshot_to_payload(snapshot) for snapshot in snapshots],
        "routing": {
            "agent_decision": [channel.id for channel in select_gateway_channels(capability="json_mode", purpose="agent_decision", include_unhealthy=True)],
            "streaming_reply": [channel.id for channel in select_gateway_channels(capability="streaming", purpose="streaming_reply", include_unhealthy=True)],
        },
    }


def get_gateway_channels_payload() -> list[dict[str, Any]]:
    return [_snapshot_to_payload(build_channel_snapshot(channel)) for channel in read_gateway_channels(include_disabled=True)]


def get_gateway_traffic_payload(*, minutes: int = 30) -> dict[str, Any]:
    window_seconds = max(1, min(int(minutes or 30), 120)) * 60
    channels = read_gateway_channels(include_disabled=True)
    per_channel: list[dict[str, Any]] = []
    merged_buckets: dict[int, list[dict[str, Any]]] = {}
    for channel in channels:
        records = _load_metric_records(channel.id, window_seconds=window_seconds)
        buckets = _bucket_records(records)
        for bucket_start, bucket_records in buckets.items():
            merged_buckets.setdefault(bucket_start, []).extend(bucket_records)
        per_channel.append(
            {
                "channel_id": channel.id,
                "name": channel.name,
                "provider": channel.provider,
                "points": [_traffic_point_payload(bucket_start, bucket_records) for bucket_start, bucket_records in sorted(buckets.items())],
            }
        )
    return {
        "window_minutes": int(window_seconds / 60),
        "points": [_traffic_point_payload(bucket_start, bucket_records) for bucket_start, bucket_records in sorted(merged_buckets.items())],
        "channels": per_channel,
    }


def build_channel_snapshot(channel: GatewayChannel) -> GatewayChannelSnapshot:
    aggregate = _load_aggregate_payload(channel.id) or aggregate_channel_metrics(channel.id)
    health = get_channel_health(channel.id)
    return GatewayChannelSnapshot(
        channel=channel,
        health_status=str(health.get("health_status") or "healthy"),
        cooldown_ttl_seconds=int(health.get("cooldown_ttl_seconds") or 0),
        healthy=channel.enabled and str(health.get("health_status") or "healthy") == "healthy",
        request_count=int(aggregate.get("request_count") or 0),
        success_count=int(aggregate.get("success_count") or 0),
        error_count=int(aggregate.get("error_count") or 0),
        success_rate=aggregate.get("success_rate") if isinstance(aggregate.get("success_rate"), float) else None,
        average_latency_ms=aggregate.get("average_latency_ms") if isinstance(aggregate.get("average_latency_ms"), int) else None,
        tp90_latency_ms=aggregate.get("tp90_latency_ms") if isinstance(aggregate.get("tp90_latency_ms"), int) else None,
        consecutive_failures=int(aggregate.get("consecutive_failures") or _get_failure_count(channel.id)),
        last_error=str(aggregate.get("last_error") or ""),
        last_status_code=aggregate.get("last_status_code") if isinstance(aggregate.get("last_status_code"), int) else None,
        last_seen_at=float(aggregate.get("last_seen_at") or 0) or None,
    )


def get_channel_health(channel_id: int | str) -> dict[str, Any]:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        ttl = int(client.ttl(_status_key(normalized_id)) or 0)
        value = client.get(_status_key(normalized_id))
        client.close()
        if value == "cooldown" and ttl != 0:
            return {"health_status": "cooldown", "cooldown_ttl_seconds": max(ttl, 0)}
    except Exception:
        pass
    with _local_lock:
        until = float(_local_cooldowns.get(normalized_id) or 0)
        if until > time.time():
            return {"health_status": "cooldown", "cooldown_ttl_seconds": max(0, int(until - time.time()))}
        _local_cooldowns.pop(normalized_id, None)
    return {"health_status": "healthy", "cooldown_ttl_seconds": 0}


def cooldown_gateway_channel(channel_id: int | str, *, ttl_seconds: int, reason: str = "") -> None:
    normalized_id = _normalize_channel_id(channel_id)
    ttl = max(int(ttl_seconds or 1), 1)
    try:
        client = _redis_client()
        client.set(_status_key(normalized_id), "cooldown", ex=ttl)
        client.close()
    except Exception:
        pass
    with _local_lock:
        _local_cooldowns[normalized_id] = time.time() + ttl
    logger.warning("AI Gateway channel %s entered cooldown for %ss: %s", normalized_id, ttl, reason)


def disable_gateway_channel(channel_id: int | str, *, reason: str = "") -> None:
    normalized_id = _normalize_channel_id(channel_id)
    with SessionLocal() as db:
        try:
            channel = db.get(AIChannel, normalized_id)
            if channel is None:
                return
            channel.status = "disabled"
            db.commit()
        except Exception:
            db.rollback()
            raise
    publish_gateway_config_updated(reason=reason or "channel_disabled")
    logger.error("AI Gateway channel %s disabled: %s", normalized_id, reason)


def create_gateway_channel(db: Session, payload: Mapping[str, Any]) -> AIChannel:
    normalized = _normalize_channel_payload(payload, existing=None)
    channel = AIChannel(
        name=normalized["name"],
        provider=normalized["provider"],
        api_base=normalized["api_base"],
        api_key_ciphertext=encrypt_text(normalized["api_key"]) if normalized["api_key"] else None,
        model_name=normalized["model_name"],
        priority=normalized["priority"],
        status=normalized["status"],
        config_json=normalized["config_json"],
    )
    db.add(channel)
    db.flush()
    return channel


def update_gateway_channel(db: Session, channel_id: int | str, payload: Mapping[str, Any]) -> AIChannel:
    channel = db.get(AIChannel, _normalize_channel_id(channel_id))
    if channel is None:
        raise LookupError("AI 通道不存在")
    normalized = _normalize_channel_payload(payload, existing=channel)
    channel.name = normalized["name"]
    channel.provider = normalized["provider"]
    channel.api_base = normalized["api_base"]
    channel.model_name = normalized["model_name"]
    channel.priority = normalized["priority"]
    channel.status = normalized["status"]
    channel.config_json = normalized["config_json"]
    if normalized["clear_api_key"]:
        channel.api_key_ciphertext = None
    elif normalized["api_key"]:
        channel.api_key_ciphertext = encrypt_text(normalized["api_key"])
    db.flush()
    return channel


def delete_gateway_channel(db: Session, channel_id: int | str) -> None:
    channel = db.get(AIChannel, _normalize_channel_id(channel_id))
    if channel is None:
        raise LookupError("AI 通道不存在")
    db.delete(channel)
    db.flush()


def reset_local_gateway_state() -> None:
    invalidate_gateway_channel_cache()
    with _local_lock:
        _local_cooldowns.clear()
        _local_failures.clear()
        _local_records.clear()


def _load_channels_from_db() -> list[GatewayChannel]:
    try:
        with SessionLocal() as db:
            rows = list(db.scalars(select(AIChannel).order_by(AIChannel.priority.desc(), AIChannel.id.asc())))
            return [_channel_from_model(row) for row in rows]
    except SQLAlchemyError as exc:
        logger.debug("AI Gateway channel table unavailable: %s", exc)
        return []
    except Exception as exc:
        logger.warning("Failed to load AI Gateway channels: %s", exc)
        return []


def _channel_from_model(row: AIChannel) -> GatewayChannel:
    config = row.config_json if isinstance(row.config_json, dict) else {}
    provider = _normalize_external_provider(row.provider)
    provider_name = _provider_name_for_build(provider)
    api_key = _decrypt_optional_secret(row.api_key_ciphertext)
    tags = tuple(str(item).strip() for item in config.get("tags", []) if str(item).strip()) if isinstance(config.get("tags"), list) else ()
    return GatewayChannel(
        id=int(row.id),
        name=sanitize_text(str(row.name or f"AI Channel {row.id}"), max_length=128, single_line=True) or f"AI Channel {row.id}",
        provider=provider,
        provider_name=provider_name,
        api_base=str(row.api_base or "").strip(),
        api_key=api_key,
        model_name=str(row.model_name or "").strip() or "gpt-4o-mini",
        priority=max(1, min(int(row.priority or 100), 100)),
        status=_normalize_channel_status(row.status),
        wire_api=str(config.get("wire_api") or _default_wire_api(provider)).strip(),
        timeout_seconds=max(int(config.get("timeout_seconds") or getattr(settings, "LLM_TIMEOUT_SECONDS", 60) or 60), 1),
        supports_json_mode=bool(config.get("supports_json_mode", provider_name in {"openai", "minimax", "custom_proxy"})),
        supports_streaming=bool(config.get("supports_streaming", provider_name in {"openai", "minimax", "custom_proxy", "ollama_remote"})),
        weight=max(float(config.get("weight") or 1.0), 0.01),
        tags=tags,
    )


def _normalize_channel_payload(payload: Mapping[str, Any], *, existing: AIChannel | None) -> dict[str, Any]:
    raw_config = payload.get("config_json")
    config_json = dict(raw_config) if isinstance(raw_config, Mapping) else dict(existing.config_json or {}) if existing is not None and isinstance(existing.config_json, dict) else {}
    wire_api = str(payload.get("wire_api") or config_json.get("wire_api") or "").strip()
    if wire_api:
        config_json["wire_api"] = wire_api
    timeout_seconds = payload.get("timeout_seconds", config_json.get("timeout_seconds"))
    if timeout_seconds is not None:
        config_json["timeout_seconds"] = max(int(timeout_seconds), 1)
    if "supports_json_mode" in payload:
        config_json["supports_json_mode"] = bool(payload.get("supports_json_mode"))
    if "supports_streaming" in payload:
        config_json["supports_streaming"] = bool(payload.get("supports_streaming"))
    if "weight" in payload and payload.get("weight") is not None:
        config_json["weight"] = max(float(payload.get("weight") or 1.0), 0.01)
    if "tags" in payload and isinstance(payload.get("tags"), list):
        tags: list[str] = []
        seen_tags: set[str] = set()
        for item in payload.get("tags") or []:
            tag = str(item or "").strip().lower()
            if not tag or tag in seen_tags:
                continue
            seen_tags.add(tag)
            tags.append(tag)
        config_json["tags"] = tags
    provider = _normalize_external_provider(str(payload.get("provider") or getattr(existing, "provider", "") or "custom_proxy"))
    model_name = str(payload.get("model_name") or getattr(existing, "model_name", "") or "").strip()
    api_base = str(payload.get("api_base") if payload.get("api_base") is not None else getattr(existing, "api_base", "") or "").strip()
    api_key = str(payload.get("api_key") or "").strip()
    clear_api_key = bool(payload.get("clear_api_key", False))
    has_existing_api_key = bool(getattr(existing, "api_key_ciphertext", None))
    if clear_api_key and api_key:
        raise ValueError("清空 API Key 时不能同时提交新的 API Key")
    if not model_name:
        raise ValueError("模型名称不能为空")
    if _provider_requires_base_url(provider) and not api_base:
        raise ValueError("当前通道类型必须填写 API Base")
    if _provider_requires_api_key(provider) and not api_key and not has_existing_api_key and not clear_api_key:
        raise ValueError("当前通道类型必须填写 API Key")
    return {
        "name": sanitize_text(str(payload.get("name") or getattr(existing, "name", "") or model_name), max_length=128, single_line=True) or model_name,
        "provider": provider,
        "api_base": api_base,
        "api_key": api_key,
        "clear_api_key": clear_api_key,
        "model_name": model_name,
        "priority": max(1, min(int(payload.get("priority") or getattr(existing, "priority", 100) or 100), 100)),
        "status": _normalize_channel_status(str(payload.get("status") or getattr(existing, "status", "active") or "active")),
        "config_json": config_json,
    }


def _config_subscriber_loop(*, stop_event: threading.Event, service_name: str) -> None:
    while not stop_event.is_set():
        client: Redis | None = None
        pubsub = None
        try:
            client = _redis_client()
            pubsub = client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(CONFIG_UPDATED_CHANNEL)
            logger.info("Subscribed AI Gateway config updates on %s (%s)", CONFIG_UPDATED_CHANNEL, service_name)
            while not stop_event.is_set():
                message = pubsub.get_message(timeout=1.0)
                if not isinstance(message, dict) or message.get("type") != "message":
                    continue
                invalidate_gateway_channel_cache()
                refresh_gateway_channel_cache()
        except Exception as exc:
            if not stop_event.is_set():
                logger.warning("AI Gateway config subscriber disconnected, retrying: %s", exc)
                stop_event.wait(3.0)
        finally:
            try:
                if pubsub is not None:
                    pubsub.close()
            except Exception:
                pass
            try:
                if client is not None:
                    client.close()
            except Exception:
                pass


def _ordered_channels(channels: list[GatewayChannel], *, purpose: GatewayPurpose) -> list[GatewayChannel]:
    ranked = list(channels)
    if purpose == "agent_decision":
        ranked.sort(key=lambda item: (-item.priority, -_dynamic_weight(item), item.id))
        return ranked
    ranked.sort(key=lambda item: (-item.priority, -_dynamic_weight(item), item.id))
    return ranked


def _dynamic_weight(channel: GatewayChannel) -> float:
    aggregate = _load_aggregate_payload(channel.id) or {}
    latency = int(aggregate.get("average_latency_ms") or 1000)
    success_rate = aggregate.get("success_rate")
    success_weight = float(success_rate) if isinstance(success_rate, float) else 1.0
    latency_weight = 1000.0 / max(float(latency), 1.0)
    jitter = random.random() * 0.001
    return channel.weight * latency_weight * max(success_weight, 0.1) + jitter


def _channel_supports_capability(channel: GatewayChannel, capability: GatewayCapability) -> bool:
    if capability == "json_mode":
        return channel.supports_json_mode
    if capability == "streaming":
        return channel.supports_streaming
    return True


def _is_secure_local_channel(channel: GatewayChannel) -> bool:
    values = {channel.provider, channel.provider_name, *channel.tags}
    return bool(values & {"ollama", "ollama_remote", "local", "secure"})


def _find_channel(channel_id: int | str, *, include_disabled: bool = True) -> GatewayChannel | None:
    normalized_id = _normalize_channel_id(channel_id)
    return next((channel for channel in read_gateway_channels(include_disabled=include_disabled) if channel.id == normalized_id), None)


def _record_metric(record: GatewayCallRecord) -> None:
    payload = _record_to_payload(record)
    payload["request_id"] = uuid4().hex
    member = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    min_score = record.timestamp - METRICS_WINDOW_SECONDS
    try:
        client = _redis_client()
        key = _metrics_key(record.channel_id)
        pipe = client.pipeline()
        pipe.zadd(key, {member: record.timestamp})
        pipe.zremrangebyscore(key, 0, min_score)
        pipe.expire(key, METRICS_WINDOW_SECONDS + 300)
        pipe.execute()
        client.close()
        return
    except Exception:
        pass
    with _local_lock:
        records = _local_records.setdefault(record.channel_id, [])
        records.append(payload)
        _local_records[record.channel_id] = [item for item in records if float(item.get("timestamp") or 0) >= min_score]


def _load_metric_records(channel_id: int | str, *, window_seconds: int) -> list[dict[str, Any]]:
    normalized_id = _normalize_channel_id(channel_id)
    since = time.time() - max(int(window_seconds or MONITOR_WINDOW_SECONDS), 1)
    try:
        client = _redis_client()
        rows = client.zrangebyscore(_metrics_key(normalized_id), since, "+inf")
        client.close()
        records: list[dict[str, Any]] = []
        for row in rows:
            try:
                item = json.loads(row)
            except Exception:
                continue
            if isinstance(item, dict):
                records.append(item)
        return records
    except Exception:
        pass
    with _local_lock:
        return [dict(item) for item in _local_records.get(normalized_id, []) if float(item.get("timestamp") or 0) >= since]


def _save_aggregate_payload(channel_id: int | str, payload: Mapping[str, Any]) -> None:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        client.hset(_aggregate_key(normalized_id), mapping={key: json.dumps(value, ensure_ascii=False) for key, value in payload.items()})
        client.expire(_aggregate_key(normalized_id), METRICS_WINDOW_SECONDS + 300)
        client.close()
    except Exception:
        return


def _load_aggregate_payload(channel_id: int | str) -> dict[str, Any] | None:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        raw = client.hgetall(_aggregate_key(normalized_id))
        client.close()
        if not raw:
            return None
        payload: dict[str, Any] = {}
        for key, value in raw.items():
            try:
                payload[key] = json.loads(value)
            except Exception:
                payload[key] = value
        return payload
    except Exception:
        return None


def _increment_failure_count(channel_id: int | str) -> int:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        count = int(client.incr(_failures_key(normalized_id)) or 0)
        client.expire(_failures_key(normalized_id), FAILURE_COUNTER_TTL_SECONDS)
        client.close()
        return count
    except Exception:
        pass
    with _local_lock:
        _local_failures[normalized_id] = int(_local_failures.get(normalized_id) or 0) + 1
        return _local_failures[normalized_id]


def _get_failure_count(channel_id: int | str) -> int:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        value = int(client.get(_failures_key(normalized_id)) or 0)
        client.close()
        return value
    except Exception:
        pass
    with _local_lock:
        return int(_local_failures.get(normalized_id) or 0)


def _clear_failure_state(channel_id: int | str) -> None:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        client.delete(_failures_key(normalized_id))
        client.close()
    except Exception:
        pass
    with _local_lock:
        _local_failures.pop(normalized_id, None)


def _clear_cooldown(channel_id: int | str) -> None:
    normalized_id = _normalize_channel_id(channel_id)
    try:
        client = _redis_client()
        client.delete(_status_key(normalized_id))
        client.close()
    except Exception:
        pass
    with _local_lock:
        _local_cooldowns.pop(normalized_id, None)


def _cooldown_channel_ids() -> set[int]:
    ids: set[int] = set()
    try:
        client = _redis_client()
        for key in client.scan_iter(match=f"{_redis_prefix()}:status:*"):
            value = client.get(key)
            if value != "cooldown":
                continue
            ids.add(_normalize_channel_id(str(key).rsplit(":", 1)[-1]))
        client.close()
    except Exception:
        pass
    with _local_lock:
        now = time.time()
        ids.update(channel_id for channel_id, until in _local_cooldowns.items() if until > now)
    return ids


def _bucket_records(records: list[dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    buckets: dict[int, list[dict[str, Any]]] = {}
    for record in records:
        timestamp = int(float(record.get("timestamp") or 0))
        if timestamp <= 0:
            continue
        bucket_start = timestamp - (timestamp % 60)
        buckets.setdefault(bucket_start, []).append(record)
    return buckets


def _traffic_point_payload(bucket_start: int, records: list[dict[str, Any]]) -> dict[str, Any]:
    successes = [item for item in records if bool(item.get("success"))]
    latencies = sorted(int(item.get("latency_ms") or 0) for item in successes if int(item.get("latency_ms") or 0) > 0)
    count = len(records)
    return {
        "timestamp": bucket_start,
        "datetime": datetime.fromtimestamp(bucket_start, timezone.utc).isoformat(),
        "request_count": count,
        "success_count": len(successes),
        "error_count": count - len(successes),
        "success_rate": round(len(successes) / count, 4) if count else None,
        "average_latency_ms": int(sum(latencies) / len(latencies)) if latencies else None,
        "tp90_latency_ms": _percentile(latencies, 0.9),
    }


def _record_to_payload(record: GatewayCallRecord) -> dict[str, Any]:
    return {
        "channel_id": record.channel_id,
        "provider": record.provider,
        "provider_name": record.provider_name,
        "model": record.model,
        "latency_ms": record.latency_ms,
        "success": record.success,
        "status_code": record.status_code,
        "error": record.error,
        "purpose": record.purpose,
        "timestamp": record.timestamp,
    }


def _snapshot_to_payload(snapshot: GatewayChannelSnapshot) -> dict[str, Any]:
    channel = snapshot.channel
    return {
        "id": channel.id,
        "name": channel.name,
        "provider": channel.provider,
        "provider_name": channel.provider_name,
        "api_base": channel.api_base,
        "api_key": {
            "configured": bool(channel.api_key),
            "masked_value": _mask_secret(channel.api_key),
            "editable": True,
        },
        "model_name": channel.model_name,
        "priority": channel.priority,
        "status": channel.status,
        "wire_api": channel.wire_api,
        "timeout_seconds": channel.timeout_seconds,
        "supports_json_mode": channel.supports_json_mode,
        "supports_streaming": channel.supports_streaming,
        "tags": list(channel.tags),
        "healthy": snapshot.healthy,
        "health_status": snapshot.health_status,
        "cooldown_ttl_seconds": snapshot.cooldown_ttl_seconds,
        "request_count": snapshot.request_count,
        "success_count": snapshot.success_count,
        "error_count": snapshot.error_count,
        "success_rate": snapshot.success_rate,
        "average_latency_ms": snapshot.average_latency_ms,
        "tp90_latency_ms": snapshot.tp90_latency_ms,
        "consecutive_failures": snapshot.consecutive_failures,
        "last_error": snapshot.last_error,
        "last_status_code": snapshot.last_status_code,
        "last_seen_at": snapshot.last_seen_at,
    }


def _records_from_gateway_error(exc: Exception) -> list[GatewayCallRecord]:
    records = getattr(exc, "_gateway_records", None)
    if isinstance(records, list):
        return [item for item in records if isinstance(item, GatewayCallRecord)]
    return []


def _can_failover_after_exception(exc: Exception) -> bool:
    status_code = _extract_status_code(exc)
    if status_code is None:
        return True
    return status_code in AUTH_FAILURE_STATUS_CODES or status_code in RETRYABLE_STATUS_CODES or status_code >= 500


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
    return sanitize_text(str(exc), max_length=300, single_line=True) or exc.__class__.__name__


def _elapsed_ms(started_at: float) -> int:
    return max(0, int((time.perf_counter() - started_at) * 1000))


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    rank = max(0, min(len(values) - 1, math.ceil(len(values) * percentile) - 1))
    return values[rank]


def _normalize_channel_id(value: int | str) -> int:
    try:
        return int(str(value).replace("channel-", "").strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("通道 ID 不合法") from exc


def _normalize_channel_status(value: str | None) -> str:
    normalized = str(value or "active").strip().lower()
    if normalized not in SUPPORTED_CHANNEL_STATUSES:
        return "active"
    return normalized


def _normalize_external_provider(provider: str) -> str:
    normalized = normalize_provider_name(provider)
    if normalized == "ollama_remote":
        return "ollama"
    if normalized in {"openai", "minimax", "custom_proxy", "mock"}:
        return normalized
    if normalized == "anthropic":
        return "anthropic"
    return normalized


def _provider_name_for_build(provider: str) -> str:
    normalized = _normalize_external_provider(provider)
    if normalized == "ollama":
        return "ollama_remote"
    if normalized == "anthropic":
        return "custom_proxy"
    return normalized


def _default_wire_api(provider: str) -> str:
    if provider in {"custom_proxy", "anthropic"}:
        return "auto"
    if provider == "minimax":
        return "chat_completions"
    return ""


def _provider_requires_base_url(provider: str) -> bool:
    return _provider_name_for_build(provider) in {"custom_proxy", "ollama_remote"}


def _provider_requires_api_key(provider: str) -> bool:
    return _provider_name_for_build(provider) in {"openai", "minimax", "custom_proxy"}


def _decrypt_optional_secret(value: str | None) -> str:
    if not value:
        return ""
    try:
        return decrypt_text(value)
    except Exception:
        return ""


def _mask_secret(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        return None
    if len(normalized) <= 6:
        return f"{normalized[:2]}***"
    return f"{normalized[:3]}***{normalized[-3:]}"


def _redis_client() -> Redis:
    return Redis.from_url(settings.REDIS_URL, decode_responses=True)


def _redis_prefix() -> str:
    return str(getattr(settings, "AI_GATEWAY_REDIS_PREFIX", DEFAULT_GATEWAY_REDIS_PREFIX) or DEFAULT_GATEWAY_REDIS_PREFIX).strip() or DEFAULT_GATEWAY_REDIS_PREFIX


def _status_key(channel_id: int | str) -> str:
    return f"{_redis_prefix()}:status:{_normalize_channel_id(channel_id)}"


def _metrics_key(channel_id: int | str) -> str:
    return f"{_redis_prefix()}:metrics:{_normalize_channel_id(channel_id)}"


def _aggregate_key(channel_id: int | str) -> str:
    return f"{_redis_prefix()}:aggregate:{_normalize_channel_id(channel_id)}"


def _failures_key(channel_id: int | str) -> str:
    return f"{_redis_prefix()}:failures:{_normalize_channel_id(channel_id)}"
