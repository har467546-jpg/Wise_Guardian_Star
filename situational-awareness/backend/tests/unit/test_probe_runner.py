import asyncio

from app.collector.probe_runner import AsyncSSHProbeRunner, ProbeCommandExecution, _build_structured_probe_payload, _normalize_connect_error
from app.collector.ssh_collector import SSHCollectProfile


def test_probe_runner_invalid_preset_fails_fast() -> None:
    runner = AsyncSSHProbeRunner()
    profile = SSHCollectProfile(asset_id="a1", ip="10.0.0.1", username="root")
    result = asyncio.run(runner.run(profile, preset="invalid-preset"))
    assert result.status == "failed"
    assert result.errors


def test_probe_structured_payload_extracts_baseline_fields() -> None:
    executions = [
        ProbeCommandExecution(name="hostname", command="hostname", success=True, exit_status=0, stdout="web-01\n"),
        ProbeCommandExecution(
            name="os_release",
            command="cat /etc/os-release",
            success=True,
            exit_status=0,
            stdout='NAME="Ubuntu"\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n',
        ),
        ProbeCommandExecution(name="kernel", command="uname -a", success=True, exit_status=0, stdout="Linux host 5.15.0 test\n"),
        ProbeCommandExecution(name="uptime", command="uptime", success=True, exit_status=0, stdout=" 10:00 up 12 days,  3 users\n"),
        ProbeCommandExecution(
            name="listening_ports",
            command="ss -tulpen",
            success=True,
            exit_status=0,
            stdout="tcp LISTEN 0 128 0.0.0.0:22\n"
            "tcp LISTEN 0 128 0.0.0.0:443\n"
            "tcp LISTEN 0 128 [::]:8080\n",
        ),
    ]

    summary, detail, friendly = _build_structured_probe_payload(executions)

    assert summary["hostname"] == "web-01"
    assert summary["os"] == "Ubuntu 22.04.4 LTS"
    assert summary["listening_ports"] == [22, 443, 8080]
    assert summary["external_listening_ports"] == [22, 443, 8080]
    assert detail["command_health"]["failed"] == 0
    assert len(detail["listening_entries"]) == 3
    assert friendly


def test_probe_structured_payload_falls_back_to_kernel_for_legacy_os() -> None:
    executions = [
        ProbeCommandExecution(name="hostname", command="hostname", success=True, exit_status=0, stdout="legacy-node\n"),
        ProbeCommandExecution(name="os_release", command="cat /etc/os-release", success=True, exit_status=0, stdout=""),
        ProbeCommandExecution(
            name="kernel",
            command="uname -a",
            success=True,
            exit_status=0,
            stdout="Linux legacy-node 2.6.24 i686 GNU/Linux\n",
        ),
        ProbeCommandExecution(name="uptime", command="uptime", success=True, exit_status=0, stdout="up 1 day\n"),
        ProbeCommandExecution(name="listening_ports", command="ss -tulpen", success=True, exit_status=0, stdout=""),
    ]

    summary, _, _ = _build_structured_probe_payload(executions)

    assert summary["os"] == "Linux（未识别发行版）"


def test_probe_structured_payload_does_not_parse_pid_as_port() -> None:
    executions = [
        ProbeCommandExecution(name="hostname", command="hostname", success=True, exit_status=0, stdout="node\n"),
        ProbeCommandExecution(name="os_release", command="cat /etc/os-release", success=True, exit_status=0, stdout='PRETTY_NAME=\"Debian\"\\n'),
        ProbeCommandExecution(name="kernel", command="uname -a", success=True, exit_status=0, stdout="Linux node\n"),
        ProbeCommandExecution(name="uptime", command="uptime", success=True, exit_status=0, stdout="up 1 day\n"),
        ProbeCommandExecution(
            name="listening_ports",
            command="ss -tulpen",
            success=True,
            exit_status=0,
            stdout=(
                "tcp 0 64 *:512 *:* users:((\"xinetd\",5115,11)) ino:12836 sk:dd5c7300\n"
                "tcp 0 128 :::22 :::* users:((\"sshd\",4761,3)) ino:11978 sk:df4c0a80\n"
            ),
        ),
    ]

    summary, _, _ = _build_structured_probe_payload(executions)

    assert summary["listening_ports"] == [22, 512]


def test_probe_structured_payload_marks_loopback_and_external() -> None:
    executions = [
        ProbeCommandExecution(name="hostname", command="hostname", success=True, exit_status=0, stdout="node\n"),
        ProbeCommandExecution(name="os_release", command="cat /etc/os-release", success=True, exit_status=0, stdout=""),
        ProbeCommandExecution(name="kernel", command="uname -a", success=True, exit_status=0, stdout="Linux node\n"),
        ProbeCommandExecution(name="uptime", command="uptime", success=True, exit_status=0, stdout="up 1 day\n"),
        ProbeCommandExecution(
            name="listening_ports",
            command="ss -tulpen",
            success=True,
            exit_status=0,
            stdout=(
                "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",100,3))\n"
                "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:((\"postgres\",200,5))\n"
                "tcp LISTEN 0 128 [::]:8080 [::]:* users:((\"nginx\",300,7))\n"
            ),
        ),
    ]

    summary, detail, _ = _build_structured_probe_payload(executions)

    assert summary["listening_ports"] == [22, 5432, 8080]
    assert summary["external_listening_ports"] == [22, 8080]
    entries = detail["listening_entries"]
    assert len(entries) == 3
    assert {item["scope"] for item in entries} == {"external", "loopback"}
    assert any(item["process_name"] == "sshd" for item in entries)


def test_normalize_connect_error_timeout() -> None:
    message = _normalize_connect_error(asyncio.TimeoutError(), connect_timeout=20)
    assert "超时" in message


def test_normalize_connect_error_permission_denied() -> None:
    PermissionDenied = type("PermissionDenied", (Exception,), {})
    message = _normalize_connect_error(PermissionDenied("Permission denied"), connect_timeout=20)
    assert "认证失败" in message
