from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


HELPER_APP_PATH = Path(__file__).resolve().parents[3] / "infra/settings-helper/app.py"


def _load_helper_module():
    spec = importlib.util.spec_from_file_location("settings_helper_app", HELPER_APP_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _apply_payload(runtime_env_path: Path, compose_file: Path, *, env_content: str, changed_keys: list[str]) -> dict:
    return {
        "task_id": "task-1",
        "runtime_env_path": str(runtime_env_path),
        "compose_dir": str(compose_file.parent),
        "compose_file": str(compose_file),
        "callback_url": "http://backend.test/internal/callback",
        "health_url": "http://backend.test/health",
        "restart_targets": ["backend", "worker"],
        "changed_keys": changed_keys,
        "env_content": env_content,
    }


def test_run_apply_verifies_backend_and_worker_runtime_sync_success(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "RUNTIME_SYNC_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(helper, "RUNTIME_SYNC_POLL_INTERVAL_SECONDS", 0)
    runtime_env_path = tmp_path / ".env.runtime"
    compose_file = tmp_path / "infra/docker-compose.yml"
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text("services: {}\n", encoding="utf-8")
    callback_payloads: list[dict] = []
    commands: list[list[str]] = []
    env_content = (
        "LLM_MODEL=MiniMax-M2.5\n"
        "LLM_BASE_URL=http://120.24.86.32:3000/anthropic\n"
        "LLM_API_KEY=\n"
    )
    expected_values = {
        "LLM_MODEL": "MiniMax-M2.5",
        "LLM_BASE_URL": "http://120.24.86.32:3000/anthropic",
        "LLM_API_KEY": "",
    }

    monkeypatch.setattr(helper, "_wait_for_health", lambda _url: (True, 2, None))
    monkeypatch.setattr(helper, "_post_callback", lambda _url, payload: callback_payloads.append(payload))

    def _fake_run(command, cwd, check, capture_output, text, timeout):  # type: ignore[no-untyped-def]
        commands.append(command)
        assert cwd == str(compose_file.parent)
        if command[4] == "up":
            return subprocess.CompletedProcess(command, 0, "compose ok", "")
        if command[4] == "exec":
            return subprocess.CompletedProcess(command, 0, json.dumps(expected_values, ensure_ascii=False), "")
        raise AssertionError(command)

    monkeypatch.setattr(helper.subprocess, "run", _fake_run)

    helper._run_apply(
        _apply_payload(
            runtime_env_path,
            compose_file,
            env_content=env_content,
            changed_keys=["LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"],
        )
    )

    assert runtime_env_path.read_text(encoding="utf-8") == env_content
    assert commands[0] == [
        "docker",
        "compose",
        "-f",
        str(compose_file),
        "up",
        "-d",
        "--force-recreate",
        "backend",
        "worker",
    ]
    assert callback_payloads[-1]["status"] == "success"
    helper_result = callback_payloads[-1]["result_json"]["helper_result"]
    assert helper_result["runtime_sync"]["verification_keys"] == ["LLM_MODEL", "LLM_BASE_URL", "LLM_API_KEY"]
    assert helper_result["runtime_sync"]["backend"]["ok"] is True
    assert helper_result["runtime_sync"]["worker"]["ok"] is True
    assert helper_result["runtime_sync"]["backend"]["actual_values"]["LLM_API_KEY"] == ""
    stage_codes = [event.get("stage_code") for event in callback_payloads[-1]["stage_events"]]
    assert stage_codes == [
        "write_runtime_env",
        "restart_services",
        "wait_backend_health",
        "verify_backend_runtime",
        "verify_worker_runtime",
    ]


@pytest.mark.parametrize("service_name", ["backend", "worker"])
def test_run_apply_fails_when_runtime_values_do_not_match(monkeypatch, tmp_path, service_name: str) -> None:  # type: ignore[no-untyped-def]
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "RUNTIME_SYNC_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(helper, "RUNTIME_SYNC_POLL_INTERVAL_SECONDS", 0)
    runtime_env_path = tmp_path / ".env.runtime"
    compose_file = tmp_path / "infra/docker-compose.yml"
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text("services: {}\n", encoding="utf-8")
    callback_payloads: list[dict] = []
    env_content = "LLM_MODEL=MiniMax-M2.5\nLLM_BASE_URL=http://120.24.86.32:3000/anthropic\n"
    expected_values = {
        "LLM_MODEL": "MiniMax-M2.5",
        "LLM_BASE_URL": "http://120.24.86.32:3000/anthropic",
    }

    monkeypatch.setattr(helper, "_wait_for_health", lambda _url: (True, 1, None))
    monkeypatch.setattr(helper, "_post_callback", lambda _url, payload: callback_payloads.append(payload))

    def _fake_run(command, cwd, check, capture_output, text, timeout):  # type: ignore[no-untyped-def]
        if command[4] == "up":
            return subprocess.CompletedProcess(command, 0, "compose ok", "")
        if command[4] == "exec":
            service = command[6]
            payload = dict(expected_values)
            if service == service_name:
                payload["LLM_MODEL"] = "gpt-old"
            return subprocess.CompletedProcess(command, 0, json.dumps(payload, ensure_ascii=False), "")
        raise AssertionError(command)

    monkeypatch.setattr(helper.subprocess, "run", _fake_run)

    helper._run_apply(
        _apply_payload(
            runtime_env_path,
            compose_file,
            env_content=env_content,
            changed_keys=["LLM_MODEL", "LLM_BASE_URL"],
        )
    )

    assert callback_payloads[-1]["status"] == "failure"
    runtime_sync = callback_payloads[-1]["result_json"]["helper_result"]["runtime_sync"]
    assert runtime_sync[service_name]["ok"] is False
    assert runtime_sync[service_name]["mismatches"]["LLM_MODEL"] == {"expected": "MiniMax-M2.5", "actual": "gpt-old"}


def test_run_apply_fails_when_runtime_exec_errors(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "RUNTIME_SYNC_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(helper, "RUNTIME_SYNC_POLL_INTERVAL_SECONDS", 0)
    runtime_env_path = tmp_path / ".env.runtime"
    compose_file = tmp_path / "infra/docker-compose.yml"
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text("services: {}\n", encoding="utf-8")
    callback_payloads: list[dict] = []

    monkeypatch.setattr(helper, "_wait_for_health", lambda _url: (True, 1, None))
    monkeypatch.setattr(helper, "_post_callback", lambda _url, payload: callback_payloads.append(payload))

    def _fake_run(command, cwd, check, capture_output, text, timeout):  # type: ignore[no-untyped-def]
        if command[4] == "up":
            return subprocess.CompletedProcess(command, 0, "compose ok", "")
        if command[4] == "exec" and command[6] == "worker":
            return subprocess.CompletedProcess(command, 1, "", "worker exec failed")
        if command[4] == "exec":
            return subprocess.CompletedProcess(command, 0, json.dumps({"LLM_MODEL": "MiniMax-M2.5"}, ensure_ascii=False), "")
        raise AssertionError(command)

    monkeypatch.setattr(helper.subprocess, "run", _fake_run)

    helper._run_apply(
        _apply_payload(
            runtime_env_path,
            compose_file,
            env_content="LLM_MODEL=MiniMax-M2.5\n",
            changed_keys=["LLM_MODEL"],
        )
    )

    assert callback_payloads[-1]["status"] == "failure"
    runtime_sync = callback_payloads[-1]["result_json"]["helper_result"]["runtime_sync"]
    assert runtime_sync["worker"]["ok"] is False
    assert runtime_sync["worker"]["exec_error"] == "worker exec failed"


def test_run_apply_translates_workspace_bind_sources_to_host_paths(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    helper = _load_helper_module()
    monkeypatch.setattr(helper, "RUNTIME_SYNC_TIMEOUT_SECONDS", 0)
    monkeypatch.setattr(helper, "RUNTIME_SYNC_POLL_INTERVAL_SECONDS", 0)

    workspace_root = tmp_path / "workspace"
    host_workspace_root = tmp_path / "host-project"
    runtime_env_path = workspace_root / "backend/.env.runtime"
    compose_file = workspace_root / "infra/docker-compose.yml"
    runtime_env_path.parent.mkdir(parents=True, exist_ok=True)
    compose_file.parent.mkdir(parents=True, exist_ok=True)
    compose_file.write_text("services: {}\n", encoding="utf-8")

    monkeypatch.setattr(helper, "WORKSPACE_ROOT", workspace_root)
    monkeypatch.setattr(helper, "HOST_WORKSPACE_ROOT_OVERRIDE", str(host_workspace_root))

    callback_payloads: list[dict] = []
    commands: list[list[str]] = []
    generated_compose_files: list[Path] = []
    compose_config = {
        "name": "infra",
        "services": {
            "backend": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(workspace_root / "backend"),
                        "target": "/app",
                    }
                ]
            },
            "worker": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(workspace_root / "backend"),
                        "target": "/app",
                    }
                ]
            },
            "postgres": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(workspace_root / "infra/postgres/init.sql"),
                        "target": "/docker-entrypoint-initdb.d/init.sql",
                    }
                ]
            },
        },
    }

    monkeypatch.setattr(helper, "_wait_for_health", lambda _url: (True, 1, None))
    monkeypatch.setattr(helper, "_post_callback", lambda _url, payload: callback_payloads.append(payload))

    def _fake_run(command, cwd, check, capture_output, text, timeout):  # type: ignore[no-untyped-def]
        commands.append(command)
        assert cwd == str(compose_file.parent)
        if command[4] == "config":
            assert command[:4] == ["docker", "compose", "-f", str(compose_file)]
            return subprocess.CompletedProcess(command, 0, json.dumps(compose_config, ensure_ascii=False), "")
        if command[4] == "up":
            generated_file = Path(command[3])
            generated_compose_files.append(generated_file)
            generated_json = json.loads(generated_file.read_text(encoding="utf-8"))
            assert generated_json["services"]["backend"]["volumes"][0]["source"] == str(host_workspace_root / "backend")
            assert generated_json["services"]["worker"]["volumes"][0]["source"] == str(host_workspace_root / "backend")
            assert generated_json["services"]["postgres"]["volumes"][0]["source"] == str(host_workspace_root / "infra/postgres/init.sql")
            return subprocess.CompletedProcess(command, 0, "compose ok", "")
        if command[4] == "exec":
            assert command[3] == str(generated_compose_files[-1])
            return subprocess.CompletedProcess(command, 0, json.dumps({"LLM_MODEL": "MiniMax-M2.5"}, ensure_ascii=False), "")
        raise AssertionError(command)

    monkeypatch.setattr(helper.subprocess, "run", _fake_run)

    helper._run_apply(
        _apply_payload(
            runtime_env_path,
            compose_file,
            env_content="LLM_MODEL=MiniMax-M2.5\n",
            changed_keys=["LLM_MODEL"],
        )
    )

    assert callback_payloads[-1]["status"] == "success"
    helper_result = callback_payloads[-1]["result_json"]["helper_result"]
    compose_context = helper_result["compose_context"]
    assert compose_context["mode"] == "translated"
    assert compose_context["host_workspace_root"] == str(host_workspace_root)
    assert compose_context["translated_bind_mounts"] == 3
    assert len(generated_compose_files) == 1
    assert not generated_compose_files[0].exists()
