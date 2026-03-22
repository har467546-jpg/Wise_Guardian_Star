import asyncio
import json
import os
import subprocess
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.runner_service import (
    RunnerInstallProbe,
    RunnerInstallError,
    _build_assignment_execution_script,
    _build_runner_bootstrap_packages,
    _bootstrap_runner_prereqs,
    _normalize_runtime_kind,
    _probe_remote_runner_install,
    _validate_runner_install_probe,
    _validate_runner_install_probe_minimal,
)
from app.schemas.remediation import RunnerTaskCompleteRequest, RunnerTaskStepRead


class _FakeConnection:
    def __init__(self, *, stdout: str, stderr: str = "", exit_status: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status

    async def run(self, command: str, check: bool = False):
        return SimpleNamespace(stdout=self.stdout, stderr=self.stderr, exit_status=self.exit_status)


def _probe_output(**overrides: str) -> str:
    data = {
        "detected_os": "Linux",
        "detected_arch": "x86_64",
        "os_release_like": "ubuntu",
        "is_root": "0",
        "has_sudo": "1",
        "sudo_nopasswd": "1",
        "sudo_password_works": "0",
        "has_systemd": "1",
        "has_sysvinit": "1",
        "has_crontab": "1",
        "has_user_systemd": "1",
        "has_bash": "1",
        "has_sh": "1",
        "has_tar": "1",
        "has_mktemp": "1",
        "package_manager": "apt",
        "http_tool": "curl",
        "platform_ok": "1",
    }
    data.update(overrides)
    return "\n".join(f"{key}={value}" for key, value in data.items()) + "\n"


def _ready_probe(**overrides) -> RunnerInstallProbe:
    base = RunnerInstallProbe(
        detected_os="linux",
        detected_arch="x86_64",
        can_system_install=True,
        has_sudo=True,
        sudo_nopasswd=True,
        sudo_password_works=False,
        has_systemd=True,
        has_sysvinit=True,
        has_crontab=True,
        has_user_systemd=True,
        has_bash=True,
        has_sh=True,
        has_tar=True,
        has_mktemp=True,
        http_tool="curl",
        platform_ok=True,
        package_manager="apt",
        os_release_like="ubuntu",
        missing_tools=[],
        bootstrap_needed=False,
        bootstrap_supported=False,
        bootstrap_status="not_needed",
        compatibility_issues=[],
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    if "missing_tools" not in overrides:
        missing_tools: list[str] = []
        if not base.has_bash:
            missing_tools.append("bash")
        if not base.has_tar:
            missing_tools.append("tar")
        if not base.has_mktemp:
            missing_tools.append("mktemp")
        if base.http_tool == "none":
            missing_tools.append("curl/wget")
        base.missing_tools = missing_tools
    if "bootstrap_needed" not in overrides:
        base.bootstrap_needed = bool(base.missing_tools)
    if "bootstrap_supported" not in overrides:
        base.bootstrap_supported = base.bootstrap_needed and base.package_manager == "apt"
    if "bootstrap_status" not in overrides:
        base.bootstrap_status = "pending" if base.bootstrap_supported else ("unsupported" if base.bootstrap_needed else "not_needed")
    return base


def test_normalize_runtime_kind_accepts_shell_bundle_and_legacy_binary() -> None:
    assert _normalize_runtime_kind("shell_bundle") == "shell_bundle"
    assert _normalize_runtime_kind("shell-bundle") == "shell_bundle"
    assert _normalize_runtime_kind("bundled_binary") == "shell_bundle"
    assert _normalize_runtime_kind("python_script") == "python_script"


def test_probe_remote_runner_install_allows_i686_shell_bundle_path() -> None:
    probe = asyncio.run(
        _probe_remote_runner_install(
            _FakeConnection(stdout=_probe_output(detected_arch="i686", has_systemd="0")),
            platform_url="http://192.168.10.131:8000",
            sudo_password=None,
        )
    )

    assert probe.detected_arch == "i686"
    assert any("i686" in item for item in probe.compatibility_issues)
    _validate_runner_install_probe(probe, platform_url="http://192.168.10.131:8000")


def test_probe_remote_runner_install_allows_unknown_linux_arch() -> None:
    probe = asyncio.run(
        _probe_remote_runner_install(
            _FakeConnection(stdout=_probe_output(detected_arch="mips64")),
            platform_url="http://192.168.10.131:8000",
            sudo_password=None,
        )
    )

    assert probe.detected_arch == "mips64"
    assert any("mips64" in item for item in probe.compatibility_issues)
    _validate_runner_install_probe(probe, platform_url="http://192.168.10.131:8000")


def test_probe_remote_runner_install_rejects_invalid_sudo_password_for_system_mode() -> None:
    probe = asyncio.run(
        _probe_remote_runner_install(
            _FakeConnection(stdout=_probe_output(sudo_nopasswd="0", sudo_password_works="0")),
            platform_url="http://192.168.10.131:8000",
            sudo_password="secret",
        )
    )

    assert probe.has_sudo is True
    assert probe.sudo_nopasswd is False
    assert probe.sudo_password_works is False
    assert probe.can_system_install is False
    assert any("sudo 凭据不可用" in item for item in probe.compatibility_issues)


def test_probe_remote_runner_install_marks_missing_dependencies_for_bootstrap() -> None:
    probe = asyncio.run(
        _probe_remote_runner_install(
            _FakeConnection(stdout=_probe_output(has_bash="0", has_mktemp="0", http_tool="none", platform_ok="0")),
            platform_url="http://192.168.10.131:8000",
            sudo_password=None,
        )
    )

    assert probe.missing_tools == ["bash", "mktemp", "curl/wget"]
    assert probe.package_manager == "apt"
    assert probe.bootstrap_needed is True
    assert probe.bootstrap_supported is True
    assert probe.bootstrap_status == "pending"


def test_validate_runner_install_probe_rejects_non_linux() -> None:
    probe = _ready_probe(detected_os="freebsd")

    with pytest.raises(RuntimeError, match="仅支持 Linux"):
        _validate_runner_install_probe(probe, platform_url="http://192.168.10.131:8000")


def test_validate_runner_install_probe_minimal_rejects_missing_dependencies_without_admin() -> None:
    probe = _ready_probe(
        has_bash=False,
        has_sudo=False,
        sudo_nopasswd=False,
        sudo_password_works=False,
        can_system_install=False,
    )

    with pytest.raises(RuntimeError, match="没有已验证的管理员权限"):
        _validate_runner_install_probe_minimal(probe)


def test_validate_runner_install_probe_minimal_rejects_non_apt_bootstrap() -> None:
    probe = _ready_probe(has_bash=False, package_manager="yum")

    with pytest.raises(RuntimeError, match="当前发行版不支持自动预引导"):
        _validate_runner_install_probe_minimal(probe)


def test_validate_runner_install_probe_rejects_missing_dependencies_after_bootstrap_failure() -> None:
    probe = _ready_probe(has_bash=False, bootstrap_status="failed")

    with pytest.raises(RuntimeError, match="已尝试自动补齐但失败"):
        _validate_runner_install_probe(probe, platform_url="http://192.168.10.131:8000")


def test_validate_runner_install_probe_requires_platform_reachability() -> None:
    probe = _ready_probe(platform_ok=False)

    with pytest.raises(RuntimeError, match="无法访问平台地址"):
        _validate_runner_install_probe(probe, platform_url="http://192.168.10.131:8000")


def test_build_runner_bootstrap_packages_maps_missing_tools_to_apt_packages() -> None:
    packages = _build_runner_bootstrap_packages(["bash", "mktemp", "curl/wget", "tar"])

    assert packages == ["bash", "coreutils", "ca-certificates", "curl", "wget", "tar"]


def test_bootstrap_runner_prereqs_raises_clear_error_when_apt_install_fails() -> None:
    probe = _ready_probe(has_bash=False)

    with pytest.raises(RunnerInstallError, match="已尝试自动补齐但失败"):
        asyncio.run(
            _bootstrap_runner_prereqs(
                _FakeConnection(stderr="apt-get install failed", exit_status=1, stdout=""),
                probe=probe,
                sudo_password="secret",
            )
        )

    assert probe.bootstrap_status == "failed"
    assert any("apt-get install failed" in item for item in probe.compatibility_issues)


def test_assignment_execution_script_includes_step_timeout_guard() -> None:
    script = _build_assignment_execution_script(
        task_id="task-1",
        summary="执行 ssh 配置重载",
        steps=[
            RunnerTaskStepRead(
                step_id="step-1",
                title="重载服务配置：ssh",
                action_type="reload_service",
                generated_command="service ssh reload",
                execution_state="ready",
                blocked_reason=None,
                backup_plan=None,
            )
        ],
    )

    assert 'STEP_TIMEOUT_SECONDS="${SA_RUNNER_STEP_TIMEOUT_SECONDS:-180}"' in script
    assert 'run_command_with_timeout() {' in script
    assert 'return 124' in script
    assert 'run_command_with_timeout "$command_text" "$output_file" "$STEP_TIMEOUT_SECONDS"' in script
    assert 'output_tail_json="$(json_array_from_file_tail "$output_file")"' in script
    assert '命令执行超时，已超过 ${STEP_TIMEOUT_SECONDS}s' in script
    assert 'JSON_PYTHON_BIN=""' in script
    assert 'resolve_json_python() {' in script
    assert 'json_escape_fallback() {' in script
    assert 'if python3 -c "import json" >/dev/null 2>&1; then' in script
    assert 'if python -c "import json" >/dev/null 2>&1; then' in script
    assert "LC_ALL=C tr -d '\\000-\\010\\013\\014\\016-\\037'" in script
    assert "sed ':a;N;$!ba;" in script
    assert 's/\\\\/\\\\\\\\/g' in script
    assert 's/"/\\\\\\"/g' in script
    assert 's/\\n/\\\\n/g' in script
    assert '"$JSON_PYTHON_BIN" -c' in script
    assert 'STEP_RESULTS_PAYLOAD="[$STEP_RESULTS_JSON]"' in script
    assert '"step_results":%s' in script
    assert '"generated_command":%s' in script
    assert '"output_tail":%s' in script
    assert 'final_message="Host Runner 执行失败：$LAST_FAILURE_TITLE"' in script


def test_assignment_execution_script_posts_valid_completion_payload_for_multiline_command(tmp_path: Path) -> None:
    capture_dir = tmp_path / "capture"
    capture_dir.mkdir()
    curl_path = tmp_path / "curl"
    curl_path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            set -eu
            body=""
            url=""
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --data)
                  body="$2"
                  shift 2
                  ;;
                http://*|https://*)
                  url="$1"
                  shift
                  ;;
                *)
                  shift
                  ;;
              esac
            done
            if printf "%s" "$url" | grep -q '/complete$'; then
              printf "%s" "$body" >"$SA_CAPTURE_DIR/complete.json"
            fi
            printf '{}'
            """
        ),
        encoding="utf-8",
    )
    curl_path.chmod(0o755)

    script = _build_assignment_execution_script(
        task_id="task-1",
        summary="执行 ssh 配置重载",
        steps=[
            RunnerTaskStepRead(
                step_id="step-1",
                title="重载服务配置：ssh",
                action_type="reload_service",
                generated_command=(
                    "cat <<'EOF'\n"
                    'quote " backslash \\\\ percent %s\n'
                    "EOF\n"
                    "python3 - <<'PY'\n"
                    "import sys\n"
                    'sys.stdout.write("ansi:\\x1b[31mred\\x1b[0m\\\\n")\n'
                    'sys.stdout.write("formfeed:\\\\f\\\\n")\n'
                    'sys.stdout.write("backspace:\\\\b\\\\n")\n'
                    "PY\n"
                ),
                execution_state="ready",
                blocked_reason=None,
                backup_plan=None,
            )
        ],
    )

    script_path = tmp_path / "assignment.sh"
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{tmp_path}:{env['PATH']}"
    env["SA_CAPTURE_DIR"] = str(capture_dir)
    env["SA_RUNNER_PLATFORM_URL"] = "http://example.invalid"
    env["SA_RUNNER_TOKEN"] = "runner-token"
    env["SA_RUNNER_HTTP_TOOL"] = "curl"
    subprocess.run(
        ["/bin/sh", str(script_path)],
        check=True,
        cwd=str(tmp_path),
        env=env,
    )

    complete_payload = (capture_dir / "complete.json").read_text(encoding="utf-8")
    payload = json.loads(complete_payload)
    validated = RunnerTaskCompleteRequest.model_validate(payload)

    assert validated.status == "success"
    assert len(validated.step_results) == 1
    step_result = validated.step_results[0]
    assert step_result.generated_command is not None
    assert 'quote " backslash \\\\ percent %s' in step_result.generated_command
    assert any("\x1b[31mred\x1b[0m" in item for item in step_result.output_tail)
    assert any("formfeed:" in item for item in step_result.output_tail)
    assert any("backspace:" in item for item in step_result.output_tail)


def test_assignment_execution_script_falls_back_when_python_json_module_is_unavailable(tmp_path: Path) -> None:
    capture_dir = tmp_path / "capture"
    capture_dir.mkdir()
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()

    for name in ("python", "python3"):
        path = fake_bin / name
        path.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                echo "ImportError: No module named json" >&2
                exit 1
                """
            ),
            encoding="utf-8",
        )
        path.chmod(0o755)

    curl_path = fake_bin / "curl"
    curl_path.write_text(
        textwrap.dedent(
            """\
            #!/bin/sh
            set -eu
            body=""
            url=""
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --data)
                  body="$2"
                  shift 2
                  ;;
                http://*|https://*)
                  url="$1"
                  shift
                  ;;
                *)
                  shift
                  ;;
              esac
            done
            if printf "%s" "$url" | grep -q '/complete$'; then
              printf "%s" "$body" >"$SA_CAPTURE_DIR/complete.json"
            fi
            printf '{}'
            """
        ),
        encoding="utf-8",
    )
    curl_path.chmod(0o755)

    script = _build_assignment_execution_script(
        task_id="task-1",
        summary="回调验证",
        steps=[
            RunnerTaskStepRead(
                step_id="step-1",
                title="Runner 回调验证",
                action_type="shell_command",
                generated_command=(
                    "cat <<'EOF'\n"
                    "pattern = re.compile('\\\\bDemo\\\\s+Rule\\\\b')\n"
                    "EOF\n"
                ),
                execution_state="ready",
                blocked_reason=None,
                backup_plan=None,
            )
        ],
    )

    script_path = tmp_path / "assignment.sh"
    script_path.write_text(script, encoding="utf-8")
    script_path.chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["SA_CAPTURE_DIR"] = str(capture_dir)
    env["SA_RUNNER_PLATFORM_URL"] = "http://example.invalid"
    env["SA_RUNNER_TOKEN"] = "runner-token"
    env["SA_RUNNER_HTTP_TOOL"] = "curl"
    subprocess.run(
        ["/bin/sh", str(script_path)],
        check=True,
        cwd=str(tmp_path),
        env=env,
    )

    payload = json.loads((capture_dir / "complete.json").read_text(encoding="utf-8"))
    validated = RunnerTaskCompleteRequest.model_validate(payload)

    assert validated.status == "success"
    assert validated.step_results[0].generated_command == "cat <<'EOF'\npattern = re.compile('\\\\bDemo\\\\s+Rule\\\\b')\nEOF"
