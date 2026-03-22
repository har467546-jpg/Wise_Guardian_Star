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
    callback_url = str(payload.get("callback_url") or "").strip()
    health_url = str(payload.get("health_url") or "").strip() or "http://backend:8000/health"
    restart_targets = [str(item).strip() for item in payload.get("restart_targets", []) if str(item).strip()] or ["backend", "worker"]
    changed_keys = [str(item).strip() for item in payload.get("changed_keys", []) if str(item).strip()]
    env_content = str(payload.get("env_content") or "")
    stage_events: list[dict] = []
    result_json = {
        "changed_keys": changed_keys,
        "restart_targets": restart_targets,
        "runtime_env_path": "backend/.env.runtime",
        "helper_result": {},
        "applied_at": None,
    }
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

        command = ["docker", "compose", "up", "-d", "--force-recreate", *restart_targets]
        compose_result = subprocess.run(
            command,
            cwd=str(compose_dir),
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

        result_json["applied_at"] = datetime.now(timezone.utc).isoformat()
        result_json["helper_result"]["task_id"] = task_id
        _post_callback(
            callback_url,
            {
                "status": "success",
                "message": "系统设置已应用并完成服务重启",
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
