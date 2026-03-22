from __future__ import annotations

import asyncio
import json
import logging
import threading
from collections import defaultdict

from fastapi import WebSocket
from redis import Redis
from redis.asyncio import Redis as AsyncRedis

from app.core.config import settings
from app.schemas.device_alert import DeviceAbnormalAlertEvent

logger = logging.getLogger(__name__)

_sync_redis_lock = threading.Lock()
_sync_redis_client: Redis | None = None


def publish_device_abnormal_alert(event: DeviceAbnormalAlertEvent) -> None:
    try:
        _get_sync_redis_client().publish(
            settings.DEVICE_ALERTS_REDIS_CHANNEL,
            event.model_dump_json(),
        )
    except Exception as exc:  # pragma: no cover - defensive logging only
        logger.warning("Failed to publish device abnormal alert: %s", exc)


def _get_sync_redis_client() -> Redis:
    global _sync_redis_client
    with _sync_redis_lock:
        if _sync_redis_client is None:
            _sync_redis_client = Redis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
            )
    return _sync_redis_client


class DeviceAlertHub:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        self._connection_lock = asyncio.Lock()
        self._listener_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if self._listener_task is not None and not self._listener_task.done():
            return
        self._listener_task = asyncio.create_task(self._listen_forever())

    async def stop(self) -> None:
        if self._listener_task is None:
            return
        self._listener_task.cancel()
        try:
            await self._listener_task
        except asyncio.CancelledError:
            pass
        self._listener_task = None

    async def connect(self, *, user_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._connection_lock:
            self._connections[user_id].add(websocket)

    async def disconnect(self, *, user_id: str, websocket: WebSocket) -> None:
        async with self._connection_lock:
            sockets = self._connections.get(user_id)
            if sockets is None:
                return
            sockets.discard(websocket)
            if not sockets:
                self._connections.pop(user_id, None)

    async def _listen_forever(self) -> None:
        while True:
            redis_client: AsyncRedis | None = None
            pubsub = None
            try:
                redis_client = AsyncRedis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                )
                pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
                await pubsub.subscribe(settings.DEVICE_ALERTS_REDIS_CHANNEL)
                logger.info(
                    "Subscribed device alert stream on Redis channel %s",
                    settings.DEVICE_ALERTS_REDIS_CHANNEL,
                )
                while True:
                    message = await pubsub.get_message(timeout=1.0)
                    if not isinstance(message, dict) or message.get("type") != "message":
                        continue
                    event = _parse_device_alert_event(message.get("data"))
                    if event is None:
                        continue
                    await self._broadcast(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - integration behavior
                logger.warning("Device alert subscriber disconnected, retrying: %s", exc)
                await asyncio.sleep(3)
            finally:
                if pubsub is not None:
                    await pubsub.close()
                if redis_client is not None:
                    await redis_client.aclose()

    async def _broadcast(self, event: DeviceAbnormalAlertEvent) -> None:
        async with self._connection_lock:
            connection_pairs = [
                (user_id, socket)
                for user_id, sockets in self._connections.items()
                for socket in sockets
            ]

        stale_connections: list[tuple[str, WebSocket]] = []
        payload = {
            "type": event.type,
            "event": event.model_dump(mode="json"),
        }
        for user_id, socket in connection_pairs:
            try:
                await socket.send_json(payload)
            except Exception:
                stale_connections.append((user_id, socket))

        for user_id, socket in stale_connections:
            await self.disconnect(user_id=user_id, websocket=socket)


def _parse_device_alert_event(raw: object) -> DeviceAbnormalAlertEvent | None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="ignore")
    if isinstance(raw, str):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            logger.debug("Ignored malformed device alert payload")
            return None
    elif isinstance(raw, dict):
        payload = raw
    else:
        return None

    try:
        return DeviceAbnormalAlertEvent.model_validate(payload)
    except Exception:
        logger.debug("Ignored invalid device alert event payload")
        return None


device_alert_hub = DeviceAlertHub()
