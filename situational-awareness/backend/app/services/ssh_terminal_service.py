from __future__ import annotations

import asyncio
import inspect
import json
from dataclasses import dataclass
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.collector.ssh_collector import (
    SSHCollectOptions,
    SSHCollectProfile,
    _build_connect_kwargs,
    _connect_with_legacy_hostkey_fallback,
    _load_asyncssh,
)
from app.core.crypto import decrypt_text
from app.db.models.asset import Asset
from app.db.models.credential import SSHCredential
from app.db.models.enums import CredentialAuthType
from app.services.remediation_service import get_manual_credential

DEFAULT_TERMINAL_COLS = 100
DEFAULT_TERMINAL_ROWS = 28
MIN_TERMINAL_COLS = 20
MAX_TERMINAL_COLS = 240
MIN_TERMINAL_ROWS = 8
MAX_TERMINAL_ROWS = 80
TERMINAL_CONNECT_TIMEOUT_SECONDS = 10.0
TERMINAL_CLOSE_TIMEOUT_SECONDS = 3.0


class SSHTerminalError(RuntimeError):
    pass


@dataclass(slots=True)
class SSHTerminalProfile:
    asset_id: str
    ip: str
    hostname: str | None
    username: str
    privilege: str
    collect_profile: SSHCollectProfile


def build_ssh_terminal_profile(db: Session, asset_id: str) -> SSHTerminalProfile:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise SSHTerminalError("资产不存在")
    credential = get_manual_credential(db, asset_id)
    if credential is None:
        raise SSHTerminalError("当前资产未配置 SSH 管理员凭据")
    _ensure_terminal_authorized(credential)
    collect_profile = _build_collect_profile(asset, credential)
    return SSHTerminalProfile(
        asset_id=asset.id,
        ip=str(asset.ip),
        hostname=asset.hostname,
        username=credential.username,
        privilege=str(credential.last_effective_privilege or "").strip().lower(),
        collect_profile=collect_profile,
    )


async def run_ssh_terminal(
    websocket: WebSocket,
    profile: SSHTerminalProfile,
    *,
    cols: int = DEFAULT_TERMINAL_COLS,
    rows: int = DEFAULT_TERMINAL_ROWS,
) -> bool:
    terminal_cols = clamp_terminal_cols(cols)
    terminal_rows = clamp_terminal_rows(rows)
    asyncssh = _load_asyncssh()
    options = SSHCollectOptions(connect_timeout=TERMINAL_CONNECT_TIMEOUT_SECONDS)
    connect_kwargs = _build_connect_kwargs(asyncssh=asyncssh, profile=profile.collect_profile, options=options)
    if connect_kwargs is None:
        await _send_terminal_error(websocket, "SSH 私钥无效，请重新保存凭据")
        return False

    session_started = False
    try:
        async with _connect_with_legacy_hostkey_fallback(asyncssh=asyncssh, connect_kwargs=connect_kwargs) as connection:
            process = await connection.create_process(
                term_type="xterm-256color",
                term_size=(terminal_cols, terminal_rows),
            )
            session_started = True
            await websocket.send_json(
                {
                    "type": "ready",
                    "asset_id": profile.asset_id,
                    "ip": profile.ip,
                    "hostname": profile.hostname,
                    "username": profile.username,
                    "privilege": profile.privilege,
                    "cols": terminal_cols,
                    "rows": terminal_rows,
                }
            )
            output_task = asyncio.create_task(_relay_process_output(websocket, process))
            input_task = asyncio.create_task(_relay_websocket_input(websocket, process))
            pending: set[asyncio.Task[None]] = set()
            try:
                done, pending = await asyncio.wait(
                    {output_task, input_task},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    task.result()
            finally:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                await _close_process(process)
            return True
    except WebSocketDisconnect:
        return session_started
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        await _send_terminal_error(websocket, f"SSH 终端连接失败：{exc}")
        return session_started


def clamp_terminal_cols(value: int | str | None) -> int:
    return _clamp_int(value, default=DEFAULT_TERMINAL_COLS, lower=MIN_TERMINAL_COLS, upper=MAX_TERMINAL_COLS)


def clamp_terminal_rows(value: int | str | None) -> int:
    return _clamp_int(value, default=DEFAULT_TERMINAL_ROWS, lower=MIN_TERMINAL_ROWS, upper=MAX_TERMINAL_ROWS)


async def _relay_process_output(websocket: WebSocket, process: Any) -> None:
    try:
        while True:
            chunk = await process.stdout.read(4096)
            if not chunk:
                break
            if isinstance(chunk, bytes):
                chunk = chunk.decode(errors="replace")
            await websocket.send_json({"type": "output", "data": chunk})
        await process.wait()
        await websocket.send_json({"type": "exit", "status": getattr(process, "exit_status", None)})
    except WebSocketDisconnect:
        return


async def _relay_websocket_input(websocket: WebSocket, process: Any) -> None:
    while True:
        raw_message = await websocket.receive_text()
        try:
            message = json.loads(raw_message)
        except json.JSONDecodeError:
            await websocket.send_json({"type": "error", "message": "终端消息格式无效"})
            continue
        if not isinstance(message, dict):
            continue
        message_type = str(message.get("type") or "").strip().lower()
        if message_type == "input":
            data = message.get("data")
            if isinstance(data, str) and data:
                process.stdin.write(data)
                drain = getattr(process.stdin, "drain", None)
                if callable(drain):
                    await _maybe_await(drain())
        elif message_type == "resize":
            cols = clamp_terminal_cols(message.get("cols"))
            rows = clamp_terminal_rows(message.get("rows"))
            await _maybe_await(process.change_terminal_size(cols, rows))
        elif message_type == "ping":
            await websocket.send_json({"type": "pong"})
        elif message_type == "close":
            break


async def _close_process(process: Any) -> None:
    try:
        if getattr(process, "returncode", None) is None:
            process.terminate()
        await asyncio.wait_for(process.wait(), timeout=TERMINAL_CLOSE_TIMEOUT_SECONDS)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


async def _send_terminal_error(websocket: WebSocket, message: str) -> None:
    try:
        await websocket.send_json({"type": "error", "message": message})
    except RuntimeError:
        pass
    except WebSocketDisconnect:
        pass


async def _maybe_await(value: Any) -> None:
    if inspect.isawaitable(value):
        await value


def _ensure_terminal_authorized(credential: SSHCredential) -> None:
    if not credential.admin_authorized:
        raise SSHTerminalError("当前 SSH 凭据尚未确认管理员授权")
    if str(credential.last_verification_status or "").strip().lower() != "success":
        raise SSHTerminalError("当前 SSH 凭据尚未完成管理员权限验证")
    privilege = str(credential.last_effective_privilege or "").strip().lower()
    if privilege not in {"root", "sudo"}:
        raise SSHTerminalError("当前 SSH 凭据未验证到管理员权限")


def _build_collect_profile(asset: Asset, credential: SSHCredential) -> SSHCollectProfile:
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    if credential.auth_type == CredentialAuthType.PASSWORD:
        if not credential.secret_ciphertext:
            raise SSHTerminalError("凭据中的密码为空，请重新保存")
        password = decrypt_text(credential.secret_ciphertext)
    elif credential.auth_type == CredentialAuthType.KEY:
        if not credential.key_ciphertext:
            raise SSHTerminalError("凭据中的私钥为空，请重新保存")
        private_key = decrypt_text(credential.key_ciphertext)
    else:
        raise SSHTerminalError(f"不支持的凭据认证方式：{credential.auth_type}")
    if credential.sudo_secret_ciphertext:
        sudo_password = decrypt_text(credential.sudo_secret_ciphertext)
    return SSHCollectProfile(
        asset_id=asset.id,
        ip=str(asset.ip),
        username=credential.username,
        password=password,
        private_key=private_key,
        sudo_password=sudo_password,
    )


def _clamp_int(value: int | str | None, *, default: int, lower: int, upper: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError):
        parsed = default
    return max(lower, min(upper, parsed))
