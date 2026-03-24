from __future__ import annotations

import json
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib import request


HOST = os.getenv("SETTINGS_HELPER_BIND", "0.0.0.0")
PORT = int(os.getenv("SETTINGS_HELPER_PORT", "8091"))
TOKEN = os.getenv("SETTINGS_HELPER_TOKEN", "")
CALLBACK_TOKEN = os.getenv("SETTINGS_HELPER_TOKEN", "")
HEALTH_TIMEOUT_SECONDS = int(os.getenv("SETTINGS_HELPER_HEALTH_TIMEOUT_SECONDS", "180"))
RUNTIME_SYNC_TIMEOUT_SECONDS = int(os.getenv("SETTINGS_HELPER_RUNTIME_SYNC_TIMEOUT_SECONDS", "90"))
RUNTIME_SYNC_POLL_INTERVAL_SECONDS = float(os.getenv("SETTINGS_HELPER_RUNTIME_SYNC_POLL_INTERVAL_SECONDS", "2"))
WORKSPACE_ROOT = Path(os.getenv("SETTINGS_HELPER_WORKSPACE_ROOT", "/workspace")).resolve()
HOST_WORKSPACE_ROOT_OVERRIDE = os.getenv("SETTINGS_HELPER_HOST_WORKSPACE_ROOT", "").strip()
RUNTIME_SNAPSHOT_SCRIPT = (
    "import json, sys\n"
    "from app.core.config import read_runtime_env_value\n"
    "keys = json.loads(sys.argv[1])\n"
    "print(json.dumps({key: read_runtime_env_value(key, '') for key in keys}, ensure_ascii=False))\n"
)


class EffectiveComposeContext:
    def __init__(
        self,
        *,
        compose_file: Path,
        compose_dir: Path,
        cleanup_path: Path | None = None,
        metadata: dict | None = None,
    ) -> None:
        self.compose_file = compose_file
        self.compose_dir = compose_dir
        self.cleanup_path = cleanup_path
        self.metadata = metadata


def _json_response(handler: BaseHTTPRequestHandler, status_code: int, payload: dict) -> None:
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status_code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _stage_event(stage_code: str, stage_name: str, message: str, progress: int, *, event_type: str = "stage", level: str = "info", payload: dict | None = None) -> dict:
    return {
        "event_type": event_type,
        "level": level,
        "stage_code": stage_code,
        "stage_name": stage_name,
        "message": message,
        "progress": progress,
        "payload_json": payload or {},
    }


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent) as handle:
        handle.write(content)
        temp_name = handle.name
    Path(temp_name).replace(path)


def _parse_env_content(content: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for raw_line in str(content or "").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _resolve_verification_keys(changed_keys: list[str], expected_env: dict[str, str]) -> list[str]:
    keys: list[str] = []
    seen: set[str] = set()
    for item in changed_keys:
        key = str(item or "").strip()
        if not key or key in seen or key not in expected_env:
            continue
        seen.add(key)
        keys.append(key)
    return keys


def _compose_base_command(compose_file: Path) -> list[str]:
    return ["docker", "compose", "-f", str(compose_file)]


def _relative_to(path: Path, root: Path) -> Path | None:
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return None


def _read_container_id() -> str:
    hostname = os.getenv("HOSTNAME", "").strip()
    if hostname:
        return hostname
    try:
        return Path("/etc/hostname").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _detect_host_workspace_root(workspace_root: Path) -> Path | None:
    override = HOST_WORKSPACE_ROOT_OVERRIDE.strip()
    if override:
        return Path(override)

    container_id = _read_container_id()
    if not container_id:
        return None

    result = subprocess.run(
        ["docker", "inspect", container_id],
        cwd="/app",
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, list) or not payload:
        return None
    container_info = payload[0] if isinstance(payload[0], dict) else {}
    mounts = container_info.get("Mounts", []) if isinstance(container_info, dict) else []
    for mount in mounts:
        if not isinstance(mount, dict):
            continue
        if str(mount.get("Destination") or "").strip() != str(workspace_root):
            continue
        source = str(mount.get("Source") or "").strip()
        if source:
            return Path(source)
    return None


def _translate_workspace_bind_source(source: str, *, workspace_root: Path, host_workspace_root: Path) -> str:
    source_path = Path(str(source or "").strip())
    relative = _relative_to(source_path, workspace_root)
    if relative is None:
        return str(source)
    return str((host_workspace_root / relative).resolve())


def _prepare_effective_compose_context(*, compose_file: Path, compose_dir: Path) -> EffectiveComposeContext:
    if _relative_to(compose_file, WORKSPACE_ROOT) is None:
        return EffectiveComposeContext(
            compose_file=compose_file,
            compose_dir=compose_dir,
            metadata={"mode": "direct", "workspace_root": str(WORKSPACE_ROOT)},
        )

    host_workspace_root = _detect_host_workspace_root(WORKSPACE_ROOT)
    if host_workspace_root is None:
        raise RuntimeError(f"无法解析 settings-helper 宿主机工作区路径: {WORKSPACE_ROOT}")

    config_result = subprocess.run(
        [*_compose_base_command(compose_file), "config", "--format", "json"],
        cwd=str(compose_dir),
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if config_result.returncode != 0:
        stderr = config_result.stderr.strip()
        stdout = config_result.stdout.strip()
        raise RuntimeError(stderr or stdout or "docker compose config 执行失败")
    try:
        compose_config = json.loads(config_result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"docker compose config 返回了无效的 JSON: {exc}") from exc

    translated_bind_mounts = 0
    services = compose_config.get("services", {}) if isinstance(compose_config, dict) else {}
    if isinstance(services, dict):
        for service in services.values():
            if not isinstance(service, dict):
                continue
            volumes = service.get("volumes", [])
            if not isinstance(volumes, list):
                continue
            for volume in volumes:
                if not isinstance(volume, dict) or str(volume.get("type") or "") != "bind":
                    continue
                source = str(volume.get("source") or "").strip()
                translated = _translate_workspace_bind_source(
                    source,
                    workspace_root=WORKSPACE_ROOT,
                    host_workspace_root=host_workspace_root,
                )
                if translated == source:
                    continue
                volume["source"] = translated
                translated_bind_mounts += 1

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
        json.dump(compose_config, handle, ensure_ascii=False)
        handle.write("\n")
        temp_path = Path(handle.name)

    return EffectiveComposeContext(
        compose_file=temp_path,
        compose_dir=compose_dir,
        cleanup_path=temp_path,
        metadata={
            "mode": "translated",
            "workspace_root": str(WORKSPACE_ROOT),
            "host_workspace_root": str(host_workspace_root),
            "source_compose_file": str(compose_file),
            "translated_bind_mounts": translated_bind_mounts,
        },
    )


def _run_compose_exec_snapshot(
    *,
    compose_file: Path,
    compose_dir: Path,
    service: str,
    verification_keys: list[str],
) -> tuple[dict[str, str], str | None]:
    command = [
        *_compose_base_command(compose_file),
        "exec",
        "-T",
        service,
        "python",
        "-c",
        RUNTIME_SNAPSHOT_SCRIPT,
        json.dumps(verification_keys, ensure_ascii=False),
    ]
    try:
        result = subprocess.run(
            command,
            cwd=str(compose_dir),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        return {}, f"runtime snapshot timeout: {exc}"
    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        return {}, stderr or stdout or f"docker compose exec failed with code {result.returncode}"
    raw_output = result.stdout.strip()
    if not raw_output:
        return {}, "runtime snapshot returned empty output"
    try:
        payload = json.loads(raw_output.splitlines()[-1])
    except json.JSONDecodeError as exc:
        return {}, f"runtime snapshot returned invalid json: {exc}"
    if not isinstance(payload, dict):
        return {}, "runtime snapshot payload is not an object"
    return {str(key): str(value or "") for key, value in payload.items()}, None


def _verify_service_runtime_sync(
    *,
    compose_file: Path,
    compose_dir: Path,
    service: str,
    verification_keys: list[str],
    expected_values: dict[str, str],
) -> dict:
    if not verification_keys:
        return {
            "ok": True,
            "skipped": True,
            "attempts": 0,
            "actual_values": {},
            "mismatches": {},
            "exec_error": None,
        }
    deadline = time.time() + RUNTIME_SYNC_TIMEOUT_SECONDS
    attempts = 0
    last_actual_values: dict[str, str] = {}
    last_mismatches: dict[str, dict[str, str]] = {}
    last_exec_error: str | None = None
    while True:
        attempts += 1
        actual_values, exec_error = _run_compose_exec_snapshot(
            compose_file=compose_file,
            compose_dir=compose_dir,
            service=service,
            verification_keys=verification_keys,
        )
        mismatches: dict[str, dict[str, str]] = {}
        if exec_error is None:
            for key in verification_keys:
                expected = str(expected_values.get(key, ""))
                if key not in actual_values:
                    mismatches[key] = {"expected": expected, "actual": ""}
                    continue
                actual = str(actual_values.get(key, ""))
                if actual != expected:
                    mismatches[key] = {"expected": expected, "actual": actual}
        last_actual_values = actual_values
        last_mismatches = mismatches
        last_exec_error = exec_error
        if exec_error is None and not mismatches:
            return {
                "ok": True,
                "skipped": False,
                "attempts": attempts,
                "actual_values": actual_values,
                "mismatches": {},
                "exec_error": None,
            }
        if time.time() >= deadline:
            return {
                "ok": False,
                "skipped": False,
                "attempts": attempts,
                "actual_values": last_actual_values,
                "mismatches": last_mismatches,
                "exec_error": last_exec_error,
            }
        time.sleep(RUNTIME_SYNC_POLL_INTERVAL_SECONDS)


def _runtime_sync_failure_message(service: str, verification: dict) -> str:
    if verification.get("exec_error"):
        return f"{service} 运行时配置校验失败：{verification['exec_error']}"
    mismatches = verification.get("mismatches") if isinstance(verification.get("mismatches"), dict) else {}
    if mismatches:
        mismatch_keys = ", ".join(sorted(str(key) for key in mismatches))
        return f"{service} 运行时配置未同步：{mismatch_keys}"
    return f"{service} 运行时配置校验失败"


def _wait_for_health(url: str) -> tuple[bool, int, str | None]:
    deadline = time.time() + HEALTH_TIMEOUT_SECONDS
    attempts = 0
    last_error: str | None = None
    while time.time() < deadline:
        attempts += 1
        try:
            with request.urlopen(url, timeout=5) as response:
                body = response.read().decode("utf-8", errors="ignore")
                if response.status == 200 and "\"ok\"" in body:
                    return True, attempts, None
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        time.sleep(2)
    return False, attempts, last_error


def _post_callback(url: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Settings-Helper-Token": CALLBACK_TOKEN,
        },
    )
    attempts = 0
    last_error: str | None = None
    while attempts < 20:
        attempts += 1
        try:
            with request.urlopen(req, timeout=10) as response:
                if 200 <= response.status < 300:
                    return
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(3)
    raise RuntimeError(last_error or "callback failed")


def _run_apply(payload: dict) -> None:
    task_id = str(payload.get("task_id") or "").strip()
    runtime_env_path = Path(str(payload.get("runtime_env_path") or "").strip() or "/workspace/backend/.env.runtime")
    compose_dir = Path(str(payload.get("compose_dir") or "").strip() or "/workspace/infra")
    compose_file = Path(str(payload.get("compose_file") or "").strip() or str(compose_dir / "docker-compose.yml"))
    callback_url = str(payload.get("callback_url") or "").strip()
    health_url = str(payload.get("health_url") or "").strip() or "http://backend:8000/health"
    restart_targets = [str(item).strip() for item in payload.get("restart_targets", []) if str(item).strip()] or ["backend", "worker"]
    changed_keys = [str(item).strip() for item in payload.get("changed_keys", []) if str(item).strip()]
    env_content = str(payload.get("env_content") or "")
    expected_env = _parse_env_content(env_content)
    verification_keys = _resolve_verification_keys(changed_keys, expected_env)
    stage_events: list[dict] = []
    result_json = {
        "changed_keys": changed_keys,
        "restart_targets": restart_targets,
        "runtime_env_path": "backend/.env.runtime",
        "helper_result": {
            "runtime_sync": {
                "verification_keys": verification_keys,
                "backend": {},
                "worker": {},
            }
        },
        "applied_at": None,
    }
    effective_compose = EffectiveComposeContext(compose_file=compose_file, compose_dir=compose_dir, metadata={"mode": "direct"})
    try:
        _atomic_write(runtime_env_path, env_content)
        stage_events.append(
            _stage_event(
                "write_runtime_env",
                "写入运行时环境",
                "运行时环境文件已写入",
                45,
                payload={"runtime_env_path": str(runtime_env_path)},
            )
        )

        effective_compose = _prepare_effective_compose_context(compose_file=compose_file, compose_dir=compose_dir)
        result_json["helper_result"]["compose_context"] = effective_compose.metadata or {}

        command = [*_compose_base_command(effective_compose.compose_file), "up", "-d", "--force-recreate", *restart_targets]
        compose_result = subprocess.run(
            command,
            cwd=str(effective_compose.compose_dir),
            check=False,
            capture_output=True,
            text=True,
            timeout=900,
        )
        result_json["helper_result"]["compose_command"] = command
        result_json["helper_result"]["compose_stdout"] = compose_result.stdout[-4000:]
        result_json["helper_result"]["compose_stderr"] = compose_result.stderr[-4000:]
        stage_events.append(
            _stage_event(
                "restart_services",
                "重启服务",
                "backend 与 worker 已提交重建",
                70,
                payload={"restart_targets": restart_targets, "return_code": compose_result.returncode},
            )
        )
        if compose_result.returncode != 0:
            raise RuntimeError(compose_result.stderr.strip() or compose_result.stdout.strip() or "docker compose up 执行失败")

        health_ok, attempts, last_error = _wait_for_health(health_url)
        result_json["helper_result"]["health_url"] = health_url
        result_json["helper_result"]["health_attempts"] = attempts
        if last_error:
            result_json["helper_result"]["health_last_error"] = last_error
        stage_events.append(
            _stage_event(
                "wait_backend_health",
                "等待后端恢复",
                "backend 健康检查已恢复" if health_ok else "backend 健康检查超时",
                88 if health_ok else 95,
                level="info" if health_ok else "warning",
                event_type="stage" if health_ok else "warning",
                payload={"health_ok": health_ok, "attempts": attempts, "health_url": health_url},
            )
        )
        if not health_ok:
            raise RuntimeError(f"后端健康检查超时: {last_error or health_url}")

        runtime_sync = result_json["helper_result"]["runtime_sync"]
        verification_failures: list[str] = []
        for service, stage_code, stage_name, progress in (
            ("backend", "verify_backend_runtime", "校验 backend 配置", 92),
            ("worker", "verify_worker_runtime", "校验 worker 配置", 96),
        ):
            verification = _verify_service_runtime_sync(
                compose_file=effective_compose.compose_file,
                compose_dir=effective_compose.compose_dir,
                service=service,
                verification_keys=verification_keys,
                expected_values=expected_env,
            )
            runtime_sync[service] = verification
            if verification["ok"]:
                message = (
                    f"{service} 已加载最新运行时配置"
                    if verification_keys
                    else f"{service} 当前无需要校验的运行时变更键"
                )
                stage_events.append(
                    _stage_event(
                        stage_code,
                        stage_name,
                        message,
                        progress,
                        payload=verification,
                    )
                )
                continue
            failure_message = _runtime_sync_failure_message(service, verification)
            verification_failures.append(failure_message)
            stage_events.append(
                _stage_event(
                    stage_code,
                    stage_name,
                    failure_message,
                    progress,
                    event_type="failure",
                    level="error",
                    payload=verification,
                )
            )
        if verification_failures:
            raise RuntimeError("；".join(verification_failures))

        result_json["applied_at"] = datetime.now(timezone.utc).isoformat()
        result_json["helper_result"]["task_id"] = task_id
        _post_callback(
            callback_url,
            {
                "status": "success",
                "message": "系统设置已应用，backend/worker 已加载最新运行时配置",
                "result_json": result_json,
                "error_json": {},
                "stage_events": stage_events,
            },
        )
    except Exception as exc:  # noqa: BLE001
        result_json["helper_result"]["task_id"] = task_id
        result_json["helper_result"]["error"] = str(exc)
        try:
            _post_callback(
                callback_url,
                {
                    "status": "failure",
                    "message": "系统设置应用失败",
                    "result_json": result_json,
                    "error_json": {"error": str(exc)},
                    "stage_events": stage_events,
                },
            )
        except Exception as callback_exc:  # noqa: BLE001
            print(json.dumps({"task_id": task_id, "error": str(exc), "callback_error": str(callback_exc)}, ensure_ascii=False), flush=True)
    finally:
        if effective_compose.cleanup_path is not None:
            try:
                effective_compose.cleanup_path.unlink(missing_ok=True)
            except OSError:
                pass


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            _json_response(self, 200, {"status": "ok"})
            return
        _json_response(self, 404, {"detail": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/internal/apply":
            _json_response(self, 404, {"detail": "not found"})
            return
        if self.headers.get("X-Settings-Helper-Token", "") != TOKEN:
            _json_response(self, 403, {"detail": "forbidden"})
            return
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        try:
            payload = json.loads(self.rfile.read(content_length).decode("utf-8") or "{}")
        except json.JSONDecodeError:
            _json_response(self, 400, {"detail": "invalid json"})
            return
        threading.Thread(target=_run_apply, args=(payload,), daemon=True).start()
        _json_response(self, 202, {"accepted": True, "task_id": payload.get("task_id")})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(json.dumps({"status": "starting", "host": HOST, "port": PORT}, ensure_ascii=False), flush=True)
    server.serve_forever()
