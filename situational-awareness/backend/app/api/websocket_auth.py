from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TypeVar

from fastapi import WebSocket, WebSocketDisconnect

ResolvedActor = TypeVar("ResolvedActor")
AUTH_FRAME_TIMEOUT_SECONDS = 5


async def authenticate_websocket(
    websocket: WebSocket,
    *,
    resolve_actor: Callable[[str], ResolvedActor | None],
) -> ResolvedActor | None:
    token = str(websocket.query_params.get("token") or "").strip()
    await websocket.accept()
    if token:
        actor = resolve_actor(token)
        if actor is not None:
            return actor
        await websocket.close(code=1008, reason="unauthorized")
        return None

    try:
        frame = await asyncio.wait_for(websocket.receive_json(), timeout=AUTH_FRAME_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        await websocket.close(code=1008, reason="missing auth frame")
        return None
    except WebSocketDisconnect:
        return None
    except Exception:
        await websocket.close(code=1008, reason="invalid auth frame")
        return None

    if not isinstance(frame, dict) or str(frame.get("type") or "").strip().lower() != "auth":
        await websocket.close(code=1008, reason="missing auth frame")
        return None

    token = str(frame.get("token") or "").strip()
    if not token:
        await websocket.close(code=1008, reason="missing token")
        return None

    actor = resolve_actor(token)
    if actor is None:
        await websocket.close(code=1008, reason="unauthorized")
        return None
    return actor
