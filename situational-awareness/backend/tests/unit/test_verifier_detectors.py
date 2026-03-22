from __future__ import annotations

import asyncio
import base64
import re
import struct

import pytest

from app.db.models.asset import Asset, AssetPort
from app.rules.rule_matcher import ActiveCheckDefinition, RuleDefinition
from app.verifiers import detectors
from app.verifiers.base import VerificationContext


def _build_context(
    detector: str,
    port: int,
    service_name: str,
    *,
    trigger: str,
    params: dict | None = None,
    connect_timeout_seconds: int = 1,
    read_timeout_seconds: int = 1,
) -> VerificationContext:
    asset = Asset(id="asset-1", ip="127.0.0.1")
    asset_port = AssetPort(
        id=f"port-{port}",
        asset_id=asset.id,
        port=port,
        protocol="tcp",
        service_name=service_name,
        service_version="test-version",
        state="open",
    )
    rule = RuleDefinition(
        rule_id=f"{detector}.rule",
        enabled=True,
        service=service_name,
        severity="high",
        description="test rule",
        active_check=ActiveCheckDefinition(
            detector=detector,
            trigger=trigger,
            timeout_seconds=max(connect_timeout_seconds, read_timeout_seconds),
            params=params or {},
        ),
    )
    return VerificationContext(
        asset=asset,
        port=asset_port,
        service_name=service_name,
        service_version=asset_port.service_version,
        banner=None,
        fingerprint={},
        config={},
        latest_snapshot=None,
        rule=rule,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
    )


@pytest.mark.parametrize(
    ("allow_login", "expected_status"),
    [
        (True, "confirmed"),
        (False, "rejected"),
    ],
)
def test_verify_ftp_anonymous_login_returns_expected_status(allow_login: bool, expected_status: str) -> None:
    async def _scenario() -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"220 FTP ready\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"331 Please specify the password.\r\n")
            await writer.drain()
            await reader.readline()
            if allow_login:
                writer.write(b"230 Login successful.\r\n")
            else:
                writer.write(b"530 Login incorrect.\r\n")
            await writer.drain()
            await reader.readline()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("ftp_anonymous_login", port, "ftp", trigger="on_service_present")
            result = await detectors.verify_ftp_anonymous_login(context)
            assert result.status == expected_status
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_ftp_anonymous_login_times_out() -> None:
    async def _scenario() -> None:
        async def _handler(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await asyncio.sleep(2)
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context(
                "ftp_anonymous_login",
                port,
                "ftp",
                trigger="on_service_present",
                connect_timeout_seconds=1,
                read_timeout_seconds=1,
            )
            result = await detectors.verify_ftp_anonymous_login(context)
            assert result.status == "error"
            assert "超时" in result.summary
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_tomcat_manager_default_creds_uses_credentials_and_confirms() -> None:
    async def _scenario() -> None:
        expected_auth = "Basic " + base64.b64encode(b"sa-admin:sa-admin").decode("ascii")

        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                request += chunk
            request_text = request.decode("utf-8", errors="ignore")
            if f"Authorization: {expected_auth}" in request_text:
                body = "Apache Tomcat Manager"
                response = (
                    f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nContent-Type: text/html\r\n\r\n{body}"
                ).encode("utf-8")
            else:
                body = "Unauthorized"
                response = (
                    f"HTTP/1.1 401 Unauthorized\r\nContent-Length: {len(body)}\r\nContent-Type: text/plain\r\n\r\n{body}"
                ).encode("utf-8")
            writer.write(response)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context(
                "tomcat_manager_default_creds",
                port,
                "tomcat",
                trigger="on_service_present",
                params={"credentials": [{"username": "sa-admin", "password": "sa-admin"}]},
            )
            result = await detectors.verify_tomcat_manager_default_creds(context)
            assert result.status == "confirmed"
            assert result.evidence["username"] == "sa-admin"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_tomcat_manager_default_creds_reports_protocol_error() -> None:
    async def _scenario() -> None:
        async def _handler(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"not-http\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("tomcat_manager_default_creds", port, "tomcat", trigger="on_service_present")
            result = await detectors.verify_tomcat_manager_default_creds(context)
            assert result.status == "error"
            assert "探测失败" in result.summary
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_redis_unauth_info_probe_confirms_when_info_is_readable() -> None:
    async def _scenario() -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await reader.readuntil(b"\r\n")
            await reader.readuntil(b"\r\n")
            await reader.readuntil(b"\r\n")
            writer.write(b"+PONG\r\n")
            await writer.drain()
            await reader.readuntil(b"\r\n")
            await reader.readuntil(b"\r\n")
            await reader.readuntil(b"\r\n")
            body = b"# Server\r\nredis_version:7.0.0\r\n"
            writer.write(f"${len(body)}\r\n".encode("utf-8") + body + b"\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("redis_unauth_info_probe", port, "redis", trigger="on_service_present")
            result = await detectors.verify_redis_unauth_info_probe(context)
            assert result.status == "confirmed"
            assert "redis_version:7.0.0" in result.evidence["info_response_sample"]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_http_risky_methods_probe_confirms_put_from_options() -> None:
    async def _scenario() -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                request += chunk
            request_text = request.decode("utf-8", errors="ignore")
            if request_text.startswith("OPTIONS"):
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Allow: GET, HEAD, POST, OPTIONS, PUT, DELETE\r\n"
                    "Content-Length: 0\r\n\r\n"
                ).encode("utf-8")
            else:
                response = b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
            writer.write(response)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("http_risky_methods_probe", port, "apache", trigger="on_passive_match")
            result = await detectors.verify_http_risky_methods_probe(context)
            assert result.status == "confirmed"
            assert result.evidence["confirmed_methods"] == ["DELETE", "PUT"]
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_distccd_rce_probe_confirms_marker() -> None:
    async def _scenario() -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            payload_length = struct.unpack(">I", await reader.readexactly(4))[0]
            payload = (await reader.readexactly(payload_length)).decode("utf-8", errors="ignore")
            match = re.search(r"echo (SA_ACTIVE_VERIFY_OK_[0-9a-f]+)", payload)
            writer.write((match.group(1) if match else "missing-marker").encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("distccd_rce_probe", port, "distccd", trigger="on_passive_match")
            result = await detectors.verify_distccd_rce_probe(context)
            assert result.status == "confirmed"
            assert result.evidence["marker"].startswith("SA_ACTIVE_VERIFY_OK_")
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_unrealircd_backdoor_probe_returns_inconclusive_without_marker() -> None:
    async def _scenario() -> None:
        async def _handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b":server NOTICE AUTH :Welcome to UnrealIRCd\r\n")
            await writer.drain()
            await reader.read(1024)
            writer.write(b":server NOTICE AUTH :command received\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            context = _build_context("unrealircd_backdoor_probe", port, "unrealircd", trigger="on_passive_match")
            result = await detectors.verify_unrealircd_backdoor_probe(context)
            assert result.status == "inconclusive"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_scenario())


def test_verify_vsftpd_smiley_backdoor_confirms_when_backdoor_port_is_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _scenario() -> None:
        async def _ftp_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"220 (vsFTPd 2.3.4)\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"331 Please specify the password.\r\n")
            await writer.drain()
            await reader.readline()
            writer.write(b"230 Login successful.\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def _backdoor_handler(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.write(b"uid=0(root) gid=0(root)\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        ftp_server = await asyncio.start_server(_ftp_handler, "127.0.0.1", 0)
        backdoor_server = await asyncio.start_server(_backdoor_handler, "127.0.0.1", 0)
        ftp_port = ftp_server.sockets[0].getsockname()[1]
        backdoor_port = backdoor_server.sockets[0].getsockname()[1]
        original_open_connection = detectors.asyncio.open_connection

        async def _patched_open_connection(host: str, port: int, *args, **kwargs):
            redirected_port = backdoor_port if int(port) == 6200 else port
            return await original_open_connection(host, redirected_port, *args, **kwargs)

        monkeypatch.setattr(detectors.asyncio, "open_connection", _patched_open_connection)
        try:
            context = _build_context("vsftpd_smiley_backdoor", ftp_port, "vsftpd", trigger="on_passive_match")
            result = await detectors.verify_vsftpd_smiley_backdoor(context)
            assert result.status == "confirmed"
            assert result.evidence["backdoor_port"] == 6200
        finally:
            ftp_server.close()
            backdoor_server.close()
            await ftp_server.wait_closed()
            await backdoor_server.wait_closed()

    asyncio.run(_scenario())
