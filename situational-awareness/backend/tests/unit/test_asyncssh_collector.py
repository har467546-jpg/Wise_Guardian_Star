import asyncio

from app.collector.host_security import (
    CAPABILITIES_COMMAND,
    CRON_LOCAL_COMMAND,
    DOCKER_DAEMON_LOCAL_COMMAND,
    DOCKER_LOCAL_COMMAND,
    LOGROTATE_LOCAL_COMMAND,
    NMAP_LOCAL_COMMAND,
    POLKIT_LOCAL_COMMAND,
    POLKIT_RULES_LOCAL_COMMAND,
    SCREEN_LOCAL_COMMAND,
    SUDO_LOCAL_COMMAND,
    SUDOERS_COMMAND,
    SUDO_LIST_COMMAND,
    SUID_SGID_COMMAND,
    SYSTEMD_LOCAL_COMMAND,
    WORLD_WRITABLE_COMMAND,
)
from app.collector.ssh_collector import AsyncSSHCollector, SSHCollectOptions, SSHCollectProfile
from app.collector.service_config import SERVICE_CONFIG_COLLECTION_PLANS
from app.collector.system_info import CPU_COMMAND, HOSTNAME_COMMAND, KERNEL_COMMAND, MEMORY_COMMAND, OS_COMMAND, SERVICES_COMMAND


class _FakeResult:
    def __init__(self, stdout: str = "", stderr: str = "", exit_status: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.exit_status = exit_status


class _FakeConnection:
    def __init__(self, responses: dict[str, _FakeResult | Exception]) -> None:
        self.responses = responses

    async def run(self, command: str, check: bool = False, input: str | None = None) -> _FakeResult:
        response = self.responses.get(command, _FakeResult(stdout="", exit_status=0))
        if isinstance(response, Exception):
            raise response
        return response


class _FakeConnectContext:
    def __init__(self, responses: dict[str, _FakeResult | Exception], error: Exception | None = None) -> None:
        self.responses = responses
        self.error = error

    async def __aenter__(self) -> _FakeConnection:
        if self.error is not None:
            raise self.error
        return _FakeConnection(self.responses)

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeAsyncSSH:
    def __init__(self, responses: dict[str, _FakeResult | Exception], error: Exception | None = None) -> None:
        self.responses = responses
        self.error = error

    def import_private_key(self, raw: str) -> str:
        return f"imported:{raw}"

    def connect(self, **kwargs) -> _FakeConnectContext:
        return _FakeConnectContext(self.responses, self.error)


class _LegacyFallbackAsyncSSH:
    def __init__(self, responses: dict[str, _FakeResult | Exception]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def import_private_key(self, raw: str) -> str:
        return f"imported:{raw}"

    def connect(self, **kwargs) -> _FakeConnectContext:
        self.calls.append(dict(kwargs))
        if "server_host_key_algs" not in kwargs:
            return _FakeConnectContext({}, error=RuntimeError("Unable to negotiate with 192.168.10.230 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss"))
        return _FakeConnectContext(self.responses)


def test_collect_one_success(monkeypatch) -> None:
    responses = {
        "whoami": _FakeResult(stdout="root\n"),
        "id -u": _FakeResult(stdout="0\n"),
        HOSTNAME_COMMAND: _FakeResult(stdout="app01\n"),
        OS_COMMAND: _FakeResult(stdout='NAME="Ubuntu"\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04 LTS"\n'),
        KERNEL_COMMAND: _FakeResult(stdout="6.8.0-59-generic\n#1 SMP PREEMPT_DYNAMIC\n"),
        CPU_COMMAND: _FakeResult(stdout="Architecture: x86_64\nCPU(s): 4\nModel name: Test CPU\nSocket(s): 1\nCore(s) per socket: 2\n"),
        MEMORY_COMMAND: _FakeResult(
            stdout="              total        used        free      shared  buff/cache   available\nMem:      1024        128        256        0        640        800\n"
        ),
        SERVICES_COMMAND: _FakeResult(
            stdout="sshd.service loaded active running OpenSSH server\nmysqld.service loaded active running MySQL server\n"
        ),
        "command -v dpkg-query >/dev/null 2>&1": _FakeResult(stdout="", exit_status=0),
        "dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'": _FakeResult(
            stdout=(
                "bash\t5.2\tamd64\n"
                "mysql-server\t8.0.36-0ubuntu0.22.04.1\tamd64\n"
                "nmap\t1:5.20-1ubuntu1\tamd64\n"
                "screen\t4.5.0-1\tamd64\n"
                "sudo\t1:1.8.31-1ubuntu1.1\tamd64\n"
                "policykit-1\t0.105-26ubuntu1.1\tamd64\n"
            )
        ),
        SERVICE_CONFIG_COLLECTION_PLANS["ssh"].command: _FakeResult(
            stdout="PasswordAuthentication yes\nPermitRootLogin yes\nPermitEmptyPasswords yes\n"
        ),
        SERVICE_CONFIG_COLLECTION_PLANS["mysql"].command: _FakeResult(
            stdout="skip-grant-tables\nlocal_infile = ON\nbind-address = 0.0.0.0\n"
        ),
        SUDO_LIST_COMMAND: _FakeResult(stdout="User root may run the following commands on host:\n    (ALL : ALL) ALL\n"),
        SUDOERS_COMMAND: _FakeResult(
            stdout='Defaults env_keep += "LD_PRELOAD PATH"\nroot ALL=(ALL:ALL) SETENV: ALL\n'
        ),
        SUDO_LOCAL_COMMAND: _FakeResult(stdout="path=/usr/bin/sudo\nmode=755|owner=root|group=root\n"),
        SUID_SGID_COMMAND: _FakeResult(stdout="/usr/bin/passwd\n/usr/bin/find\n"),
        CAPABILITIES_COMMAND: _FakeResult(stdout="/usr/bin/ping cap_net_raw=ep\n"),
        WORLD_WRITABLE_COMMAND: _FakeResult(stdout="/opt/test.sh\n"),
        NMAP_LOCAL_COMMAND: _FakeResult(stdout="path=/usr/bin/nmap\nmode=4755|owner=root|group=root\nsuid=true\n"),
        SCREEN_LOCAL_COMMAND: _FakeResult(stdout="path=/usr/bin/screen\nmode=4755|owner=root|group=root\nsuid=true\n"),
        DOCKER_LOCAL_COMMAND: _FakeResult(stdout="socket=/var/run/docker.sock|660|root|docker\ngroup=docker\n"),
        DOCKER_DAEMON_LOCAL_COMMAND: _FakeResult(
            stdout='source=daemon_json\n{"hosts":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"],"tlsverify": false}\n'
        ),
        POLKIT_LOCAL_COMMAND: _FakeResult(stdout="pkexec_path=/usr/bin/pkexec\npkexec_suid=true\npath=/usr/bin/pkcheck\n"),
        POLKIT_RULES_LOCAL_COMMAND: _FakeResult(stdout="writable_path=/etc/polkit-1/rules.d/49-demo.rules\n"),
        SYSTEMD_LOCAL_COMMAND: _FakeResult(
            stdout="unit=/etc/systemd/system/demo.service|exec=/usr/local/bin/demo|unit_writable=true|exec_writable=true\n"
        ),
        CRON_LOCAL_COMMAND: _FakeResult(stdout="path=/etc/cron.d/demo|kind=direct\n"),
        LOGROTATE_LOCAL_COMMAND: _FakeResult(stdout="action=/etc/logrotate.d/demo\nwritable_action=/etc/logrotate.d/demo\n"),
    }
    collector = AsyncSSHCollector()
    monkeypatch.setattr("app.collector.ssh_collector._load_asyncssh", lambda: _FakeAsyncSSH(responses))

    result = asyncio.run(
        collector.collect_one(
            SSHCollectProfile(asset_id="asset-1", ip="10.0.0.10", username="root", password="secret"),
            SSHCollectOptions(),
        )
    )

    assert result.status == "success"
    assert result.hostname == "app01"
    assert result.os["pretty_name"] == "Ubuntu 20.04 LTS"
    assert result.kernel["release"] == "6.8.0-59-generic"
    assert result.packages[0]["name"] == "bash"
    assert result.services[0]["name"] == "sshd"
    assert result.authorization["effective_privilege"] == "root"
    assert result.host_checks["sudoers"]["line_count"] == 2
    assert result.service_configs["sudo"]["full_privilege_rule"] is True
    assert result.service_configs["sudo"]["setenv_present"] is True
    assert result.service_configs["sudo"]["dangerous_env_keep_present"] is True
    assert result.service_configs["sudo"]["dangerous_env_keep_tokens"] == ["LD_PRELOAD", "PATH"]
    assert result.service_configs["ssh"]["permit_empty_passwords"] is True
    assert result.service_configs["mysql"]["skip_grant_tables"] is True
    assert result.service_configs["mysql"]["local_infile"] is True
    assert result.service_configs["mysql"]["bind_all_interfaces"] is True
    assert result.host_checks["sudo_local"]["package_name"] == "sudo"
    assert result.service_configs["sudo"]["distro_aware_exposed"] is True
    assert result.host_checks["nmap_local"]["normalized_version"] == "5.20"
    assert result.service_configs["nmap"]["legacy_interactive_privesc_exposed"] is True
    assert result.service_configs["screen"]["legacy_setuid_privesc_exposed"] is True
    assert result.service_configs["docker"]["socket_present"] is True
    assert result.service_configs["docker"]["tcp_listener_without_tlsverify"] is True
    assert result.host_checks["polkit_local"]["pkexec_present"] is True
    assert result.host_checks["polkit_rules_local"]["writable_rules_path_present"] is True
    assert result.service_configs["polkit"]["pkexec_suid_present"] is True
    assert result.service_configs["polkit"]["writable_rules_path_present"] is True
    assert result.service_configs["polkit"]["distro_aware_exposed"] is True
    assert result.service_configs["systemd"]["writable_unit_chain_present"] is True


def test_collect_one_connection_failure(monkeypatch) -> None:
    collector = AsyncSSHCollector()
    monkeypatch.setattr(
        "app.collector.ssh_collector._load_asyncssh",
        lambda: _FakeAsyncSSH({}, error=RuntimeError("auth failed")),
    )

    result = asyncio.run(
        collector.collect_one(
            SSHCollectProfile(asset_id="asset-2", ip="10.0.0.20", username="root", password="bad"),
            SSHCollectOptions(),
        )
    )

    assert result.status == "failed"
    assert result.errors[0].stage == "connect"


def test_verify_authorization_confirms_sudo_user(monkeypatch) -> None:
    responses = {
        "whoami": _FakeResult(stdout="admin\n"),
        "id -u": _FakeResult(stdout="1000\n"),
        "printf '%s\\n' secret | sudo -S -p '' sh -lc 'id -u'": _FakeResult(stdout="0\n"),
    }
    collector = AsyncSSHCollector()
    monkeypatch.setattr("app.collector.ssh_collector._load_asyncssh", lambda: _FakeAsyncSSH(responses))

    result = asyncio.run(
        collector.verify_authorization(
            SSHCollectProfile(asset_id="asset-verify", ip="10.0.0.30", username="admin", password="secret", sudo_password="secret"),
            SSHCollectOptions(),
        )
    )

    assert result.status == "success"
    assert result.effective_privilege == "sudo"


def test_verify_authorization_retries_legacy_host_key_algorithms(monkeypatch) -> None:
    responses = {
        "whoami": _FakeResult(stdout="root\n"),
        "id -u": _FakeResult(stdout="0\n"),
    }
    fake_asyncssh = _LegacyFallbackAsyncSSH(responses)
    collector = AsyncSSHCollector()
    monkeypatch.setattr("app.collector.ssh_collector._load_asyncssh", lambda: fake_asyncssh)

    result = asyncio.run(
        collector.verify_authorization(
            SSHCollectProfile(asset_id="asset-legacy", ip="192.168.10.230", username="root", password="msfadmin"),
            SSHCollectOptions(),
        )
    )

    assert result.status == "success"
    assert len(fake_asyncssh.calls) == 2
    assert "server_host_key_algs" not in fake_asyncssh.calls[0]
    assert fake_asyncssh.calls[1]["server_host_key_algs"] == ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa", "ssh-dss"]


def test_verify_authorization_does_not_retry_non_legacy_errors(monkeypatch) -> None:
    collector = AsyncSSHCollector()
    monkeypatch.setattr(
        "app.collector.ssh_collector._load_asyncssh",
        lambda: _FakeAsyncSSH({}, error=RuntimeError("connection refused")),
    )

    result = asyncio.run(
        collector.verify_authorization(
            SSHCollectProfile(asset_id="asset-no-retry", ip="10.0.0.40", username="root", password="bad"),
            SSHCollectOptions(),
        )
    )

    assert result.status == "failed"
    assert "connection refused" in result.summary


def test_collect_many_continues_after_failure(monkeypatch) -> None:
    collector = AsyncSSHCollector()

    async def side_effect(profile: SSHCollectProfile, options: SSHCollectOptions | None = None):
        if profile.asset_id == "broken":
            from app.collector.ssh_collector import SSHCollectResult

            return SSHCollectResult.failed(profile.asset_id, profile.ip, "connect", "failed")
        from app.collector.ssh_collector import SSHCollectResult

        return SSHCollectResult(
            asset_id=profile.asset_id,
            ip=profile.ip,
            status="success",
            hostname="ok",
            os={"name": "Ubuntu", "version": "22.04", "pretty_name": "Ubuntu 22.04"},
            kernel={"release": "6.8", "version": "#1"},
            cpu={"model": "CPU", "architecture": "x86_64", "cores": 2, "threads": 4},
            memory={"total_bytes": 1, "available_bytes": 1},
            packages=[],
            services=[],
        )

    monkeypatch.setattr(collector, "collect_one", side_effect)
    results = asyncio.run(
        collector.collect_many(
            [
                SSHCollectProfile(asset_id="ok", ip="10.0.0.1", username="root", password="x"),
                SSHCollectProfile(asset_id="broken", ip="10.0.0.2", username="root", password="x"),
            ],
            concurrency=2,
        )
    )

    assert [result.status for result in results] == ["success", "failed"]
