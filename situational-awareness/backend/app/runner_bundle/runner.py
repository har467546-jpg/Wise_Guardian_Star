#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def write_json_file(path: str, payload: Dict[str, Any]) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".sa-runner-", dir=parent or None)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


def request_json(
    *,
    base_url: str,
    path: str,
    method: str,
    payload: Optional[Dict[str, Any]] = None,
    runner_token: Optional[str] = None,
    timeout: int = 20,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method=method.upper())
    request.add_header("Content-Type", "application/json")
    if runner_token:
        request.add_header("X-Runner-Token", runner_token)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read().decode("utf-8")
    if not raw:
        return {}
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


def register_runner(config: Dict[str, Any], state_path: str) -> Dict[str, Any]:
    payload = {
        "registration_token": config.get("registration_token"),
        "asset_id": config.get("asset_id"),
        "version": config.get("runner_version") or "1.0.0",
        "capabilities": {
            "transport": "poll",
            "executor": "local-shell",
            "python": sys.version.split()[0],
        },
    }
    response = request_json(
        base_url=str(config["platform_url"]),
        path="/api/v1/runner/register",
        method="POST",
        payload=payload,
        timeout=20,
    )
    state = load_json_file(state_path)
    state["runner_id"] = response.get("runner_id")
    state["runner_token"] = response.get("runner_token")
    state["poll_interval_seconds"] = response.get("poll_interval_seconds", 10)
    write_json_file(state_path, state)
    return state


def heartbeat(config: Dict[str, Any], state: Dict[str, Any], *, status: str, last_error: Optional[str] = None) -> None:
    request_json(
        base_url=str(config["platform_url"]),
        path="/api/v1/runner/heartbeat",
        method="POST",
        runner_token=str(state["runner_token"]),
        payload={
            "version": config.get("runner_version") or "1.0.0",
            "status": status,
            "last_error": last_error,
            "capabilities": {
                "transport": "poll",
                "executor": "local-shell",
            },
        },
        timeout=15,
    )


def poll_assignments(config: Dict[str, Any], state: Dict[str, Any]) -> List[Dict[str, Any]]:
    response = request_json(
        base_url=str(config["platform_url"]),
        path="/api/v1/runner/poll",
        method="POST",
        runner_token=str(state["runner_token"]),
        payload={"max_tasks": 1},
        timeout=20,
    )
    assignments = response.get("assignments")
    return assignments if isinstance(assignments, list) else []


def post_task_events(config: Dict[str, Any], state: Dict[str, Any], task_id: str, events: List[Dict[str, Any]]) -> None:
    if not events:
        return
    request_json(
        base_url=str(config["platform_url"]),
        path=f"/api/v1/runner/tasks/{task_id}/events",
        method="POST",
        runner_token=str(state["runner_token"]),
        payload={"events": events},
        timeout=20,
    )


def post_task_complete(config: Dict[str, Any], state: Dict[str, Any], task_id: str, payload: Dict[str, Any]) -> None:
    request_json(
        base_url=str(config["platform_url"]),
        path=f"/api/v1/runner/tasks/{task_id}/complete",
        method="POST",
        runner_token=str(state["runner_token"]),
        payload=payload,
        timeout=30,
    )


def backup_target(target: str) -> Optional[str]:
    if not os.path.exists(target):
        return None
    backup_path = f"{target}.bak.sa.{time.strftime('%Y%m%d%H%M%S')}"
    shutil.copy2(target, backup_path)
    return backup_path


def snapshot_permissions(target: str) -> Optional[str]:
    if not os.path.exists(target):
        return None
    stat_result = os.stat(target)
    return f"{target}|{oct(stat_result.st_mode & 0o777)}|{stat_result.st_uid}|{stat_result.st_gid}"


def prepare_backups(backup_plan: Optional[Dict[str, Any]]) -> List[str]:
    if not isinstance(backup_plan, dict):
        return []
    kind = str(backup_plan.get("kind") or "").strip().lower()
    targets = [str(item).strip() for item in backup_plan.get("targets", []) if str(item).strip()]
    if not kind or not targets:
        return []
    results: List[str] = []
    if kind == "file_copy":
        for target in targets:
            backup_path = backup_target(target)
            if backup_path:
                results.append(backup_path)
        return results
    if kind == "permission_snapshot":
        for target in targets:
            snapshot = snapshot_permissions(target)
            if snapshot:
                results.append(snapshot)
        return results
    return results


def stream_command(task_id: str, config: Dict[str, Any], state: Dict[str, Any], step_id: str, command: str) -> Tuple[int, List[str]]:
    process = subprocess.Popen(
        ["/bin/sh", "-lc", command],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    output_tail: List[str] = []
    event_buffer: List[Dict[str, Any]] = []
    assert process.stdout is not None
    for raw_line in process.stdout:
        text = raw_line.rstrip("\n")
        if text:
            if len(output_tail) >= 60:
                output_tail.pop(0)
            output_tail.append(text[:800])
        event_buffer.append(
            {
                "event_type": "stream",
                "stage_code": "execute_steps",
                "stage_name": "Runner 执行步骤",
                "message": text[:255],
                "payload_json": {"step_id": step_id, "stream": "stdout", "text": text[:800]},
            }
        )
        if len(event_buffer) >= 10:
            post_task_events(config, state, task_id, event_buffer)
            event_buffer = []
    if event_buffer:
        post_task_events(config, state, task_id, event_buffer)
    process.wait()
    return int(process.returncode or 0), output_tail


def execute_assignment(config: Dict[str, Any], state: Dict[str, Any], assignment: Dict[str, Any]) -> None:
    task_id = str(assignment.get("task_id") or "")
    steps = assignment.get("steps")
    if not task_id or not isinstance(steps, list):
        return

    post_task_events(
        config,
        state,
        task_id,
        [
            {
                "event_type": "stage",
                "stage_code": "execute_steps",
                "stage_name": "Runner 执行步骤",
                "message": "Host Runner 已开始执行整机修复计划",
                "progress": 10,
                "payload_json": {"assignment": assignment.get("summary")},
            }
        ],
    )

    step_results: List[Dict[str, Any]] = []
    backup_map: Dict[str, List[str]] = {}
    executed_count = 0
    success_count = 0
    final_status = "success"

    for index, raw_step in enumerate(steps, start=1):
        step = raw_step if isinstance(raw_step, dict) else {}
        step_id = str(step.get("step_id") or f"step-{index}")
        title = str(step.get("title") or step_id)
        generated_command = str(step.get("generated_command") or "").strip()
        execution_state = str(step.get("execution_state") or "").strip().lower()
        started_at = utc_now()

        if execution_state == "blocked":
            step_results.append(
                {
                    "step_id": step_id,
                    "title": title,
                    "status": "blocked",
                    "generated_command": generated_command or None,
                    "exit_status": None,
                    "backup_paths": [],
                    "output_tail": [],
                    "started_at": started_at,
                    "finished_at": utc_now(),
                    "error": str(step.get("blocked_reason") or "步骤被阻塞"),
                }
            )
            final_status = "failure"
            continue

        if not generated_command:
            step_results.append(
                {
                    "step_id": step_id,
                    "title": title,
                    "status": "skipped",
                    "generated_command": None,
                    "exit_status": None,
                    "backup_paths": [],
                    "output_tail": [],
                    "started_at": started_at,
                    "finished_at": utc_now(),
                    "error": None,
                }
            )
            continue

        post_task_events(
            config,
            state,
            task_id,
            [
                {
                    "event_type": "command",
                    "stage_code": "execute_steps",
                    "stage_name": "Runner 执行步骤",
                    "message": f"执行步骤 {index}: {title}",
                    "progress": min(90, 10 + index * 8),
                    "payload_json": {
                        "step_id": step_id,
                        "title": title,
                        "generated_command": generated_command,
                        "submitted_command": generated_command,
                    },
                }
            ],
        )

        backup_paths = prepare_backups(step.get("backup_plan") if isinstance(step.get("backup_plan"), dict) else None)
        if backup_paths:
            backup_map[step_id] = backup_paths

        exit_status, output_tail = stream_command(task_id, config, state, step_id, generated_command)
        executed_count += 1
        finished_at = utc_now()
        if exit_status == 0:
            success_count += 1
            step_results.append(
                {
                    "step_id": step_id,
                    "title": title,
                    "status": "success",
                    "generated_command": generated_command,
                    "exit_status": 0,
                    "backup_paths": backup_paths,
                    "output_tail": output_tail,
                    "started_at": started_at,
                    "finished_at": finished_at,
                    "error": None,
                }
            )
            post_task_events(
                config,
                state,
                task_id,
                [
                    {
                        "event_type": "success",
                        "stage_code": "execute_steps",
                        "stage_name": "Runner 执行步骤",
                        "message": f"步骤完成: {title}",
                        "payload_json": {"step_id": step_id, "status": "success"},
                    }
                ],
            )
            continue

        final_status = "failure"
        step_results.append(
            {
                "step_id": step_id,
                "title": title,
                "status": "failed",
                "generated_command": generated_command,
                "exit_status": exit_status,
                "backup_paths": backup_paths,
                "output_tail": output_tail,
                "started_at": started_at,
                "finished_at": finished_at,
                "error": output_tail[-1] if output_tail else f"退出状态码 {exit_status}",
            }
        )
        post_task_events(
            config,
            state,
            task_id,
            [
                {
                    "event_type": "failure",
                    "level": "error",
                    "stage_code": "execute_steps",
                    "stage_name": "Runner 执行步骤",
                    "message": f"步骤失败: {title}",
                    "payload_json": {"step_id": step_id, "status": "failed", "exit_status": exit_status},
                }
            ],
        )
        break

    execution = {
        "execution_boundary": "runner_dispatch",
        "step_results": step_results,
        "success_count": success_count,
        "executed_count": executed_count,
        "backup_map": backup_map,
    }
    post_task_complete(
        config,
        state,
        task_id,
        {
            "status": final_status,
            "message": "Host Runner 已完成当前阶段执行" if final_status == "success" else "Host Runner 执行失败",
            "execution": execution,
            "backups": backup_map,
            "step_results": step_results,
        },
    )


def run_loop(config_path: str) -> int:
    config = load_json_file(config_path)
    if not config:
        raise RuntimeError("runner config missing")
    state_path = str(config.get("state_path") or "/var/lib/sa-runner/state.json")
    state = load_json_file(state_path)
    if not state.get("runner_token"):
        state = register_runner(config, state_path)

    poll_interval = int(state.get("poll_interval_seconds") or config.get("poll_interval_seconds") or 10)
    while True:
        try:
            heartbeat(config, state, status="online")
            assignments = poll_assignments(config, state)
            if assignments:
                heartbeat(config, state, status="busy")
                for assignment in assignments:
                    execute_assignment(config, state, assignment if isinstance(assignment, dict) else {})
                heartbeat(config, state, status="online")
            time.sleep(max(5, poll_interval))
        except urllib.error.HTTPError as exc:
            heartbeat(config, state, status="error", last_error=f"http {exc.code}")
            time.sleep(max(5, poll_interval))
        except Exception as exc:  # pragma: no cover - host runtime dependent
            try:
                heartbeat(config, state, status="error", last_error=str(exc))
            except Exception:
                pass
            time.sleep(max(5, poll_interval))


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Asset platform host remediation runner")
    parser.add_argument("--config", default="/opt/sa-runner/bootstrap.json")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    return run_loop(args.config)


if __name__ == "__main__":
    raise SystemExit(main())
