from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import remediation as remediation_endpoint
from app.api.v1.endpoints import risks
from app.core.config import settings
from app.core.security import create_access_token
from app.db.base import Base
from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import AssetCredentialBinding, SSHCredential
from app.db.models.enums import AssetStatus, CredentialAuthType, FindingStatus, RiskSeverity, TaskExecutionStatus, TaskType, UserRole
from app.db.models.host_runner import HostRunner
from app.db.models.risk_finding import RiskFinding
from app.db.models.remediation_session import RemediationSession
from app.db.models.snapshot import HostSnapshot
from app.db.models.task_run import TaskRun
from app.db.models.user import User
from app.db.session import SessionLocal, engine
from app.main import create_app
from app.rules.rule_store import RuleStore
from app.services.remediation_session_service import process_remediation_session_ai_generation


def _override_user(role: UserRole):
    def _resolver():
        return SimpleNamespace(id="user-1", role=role, is_active=True)

    return _resolver


def _unique_ip() -> str:
    seed = uuid4().int
    return f"10.240.{seed % 250 + 1}.{(seed // 256) % 250 + 1}"


def _admin_ws_token() -> str:
    return create_access_token(subject="user-1", extra={"role": UserRole.ADMIN.value})


def _run_session_ai(session_id: str, *, reason: str | None = None, force: bool = False) -> None:
    with SessionLocal() as db:
        process_remediation_session_ai_generation(db, session_id=session_id, reason=reason, force=force)


def _build_client(tmp_path, role: UserRole = UserRole.ADMIN) -> TestClient:
    Base.metadata.create_all(bind=engine)
    settings.LLM_PROVIDER = "mock"
    rule_path = tmp_path / "risk_rules.yaml"
    rule_path.write_text(
        """rules:
  - id: ssh.password_authentication.enabled
    name: SSH 允许密码登录
    enabled: true
    service: ssh
    severity: high
    description: ssh password authentication enabled
    match:
      config:
        password_authentication:
          eq: true
    remediation:
      summary: 关闭 ssh 密码登录
      automation_level: callable
      impact_summary: 会收紧 SSH 登录入口，可能影响当前依赖密码登录的运维方式
      precheck_items:
        - 确认当前主机至少保留一种可用的 SSH 密钥登录方式
      verify_items:
        - 确认 PasswordAuthentication 已关闭且 SSH 连接仍可用
      rollback_notes:
        - 如误锁定入口，可回滚 sshd_config 备份并重载 ssh 服务
      actions:
        - action_type: toggle_feature
          title: 关闭密码登录
          params:
            service_name: ssh
            config_key: password_authentication
            desired_state: false
          target_files:
            - /etc/ssh/sshd_config
          target_services:
            - ssh
          verify_items:
            - 确认 PasswordAuthentication no 已生效
  - id: sudo.full_privilege_rule.enabled
    name: sudo 存在全量管理员授权
    enabled: true
    service: sudo
    severity: critical
    description: sudo full privilege rule enabled
    match:
      config:
        full_privilege_rule:
          eq: true
    remediation:
      summary: 收紧 sudo 全量管理员授权
      automation_level: callable
      actions:
        - action_type: set_config
          title: 收紧 sudo 全量管理员授权
          params:
            service_name: sudo
            config_key: full_privilege_rule
          target_files:
            - /etc/sudoers
          target_services:
            - sudo
""",
        encoding="utf-8",
    )
    risks.RULE_STORE = RuleStore(rule_path)
    with SessionLocal() as db:
        existing_user = db.get(User, "user-1")
        if existing_user is None:
            db.add(
                User(
                    id="user-1",
                    username="tester-admin",
                    email="tester-admin@example.com",
                    password_hash="not-used",
                    role=role,
                    is_active=True,
                )
            )
        else:
            existing_user.role = role
            existing_user.is_active = True
            db.add(existing_user)
        db.commit()

    app = create_app()
    app.dependency_overrides[get_current_user] = _override_user(role)
    return TestClient(app)


def _create_asset_context(
    *,
    hostname: str = "srv-01",
    os_name: str = "Ubuntu 22.04",
    credential_status: str = "success",
    effective_privilege: str | None = "root",
    include_snapshot: bool = True,
    include_open_finding: bool = True,
    finding_severity: RiskSeverity = RiskSeverity.HIGH,
    port_state: str = "open",
) -> tuple[str, str]:
    asset_id = str(uuid4())
    port_id = str(uuid4())
    finding_id = str(uuid4())
    asset = Asset(id=asset_id, ip=_unique_ip(), status=AssetStatus.ONLINE, hostname=hostname, os_name=os_name)
    port = AssetPort(
        id=port_id,
        asset_id=asset.id,
        port=22,
        protocol="tcp",
        service_name="ssh",
        service_version="OpenSSH_8.9",
        fingerprint_json={"service_aliases": ["ssh"]},
        state=port_state,
    )
    finding = RiskFinding(
        id=finding_id,
        asset_id=asset.id,
        asset_port_id=port.id,
        severity=finding_severity,
        status=FindingStatus.OPEN if include_open_finding else FindingStatus.IGNORED,
        title="SSH 允许密码登录",
        description="PasswordAuthentication yes",
        evidence_json={
            "yaml_rule_id": "ssh.password_authentication.enabled",
            "service_name": "ssh",
            "service_version": "OpenSSH_8.9",
            "port": 22,
        },
    )
    credential = SSHCredential(
        id=str(uuid4()),
        name=f"manual-asset-{asset.id}",
        username="root",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        admin_authorized=True,
        last_verification_status=credential_status,
        last_effective_privilege=effective_privilege,
    )
    binding = AssetCredentialBinding(asset_id=asset.id, credential_id=credential.id, priority=-100)
    snapshot = HostSnapshot(
        asset_id=asset.id,
        hostname="srv-01",
        os_release="Ubuntu 22.04",
        kernel_version="5.15.0",
        cpu_json={},
        memory_json={},
        software_json={
            "packages": [{"name": "openssh-server", "version": "1:8.9p1-3", "manager": "dpkg", "arch": "amd64"}],
            "host_checks": {
                "nmap_local": {"binary_path": "/usr/bin/nmap"},
                "screen_local": {"binary_path": "/usr/bin/screen"},
            },
            "summary_json": {"authorization_status": "success"},
            "detail_json": {},
        },
        services_json={
            "services": [{"name": "sshd", "state": "running"}],
            "config_by_service": {
                "ssh": {
                    "password_authentication": True,
                    "source_files": ["/etc/ssh/sshd_config"],
                }
            },
            "nse_by_port": {},
            "nse_summary": {},
        },
        error_json={},
        collection_status="success",
    )
    with SessionLocal() as db:
        db.add(asset)
        db.add(port)
        db.add(credential)
        db.add(binding)
        if include_open_finding:
            db.add(finding)
        if include_snapshot:
            db.add(snapshot)
        db.commit()
    return asset_id, finding_id


def _create_sudo_self_lock_context() -> tuple[str, str]:
    asset_id = str(uuid4())
    port_id = str(uuid4())
    finding_id = str(uuid4())
    asset = Asset(id=asset_id, ip=_unique_ip(), status=AssetStatus.ONLINE, hostname="sudo-host", os_name="Ubuntu 22.04")
    port = AssetPort(
        id=port_id,
        asset_id=asset.id,
        port=22,
        protocol="tcp",
        service_name="ssh",
        service_version="OpenSSH_8.9",
        fingerprint_json={"service_aliases": ["ssh"]},
        state="open",
    )
    finding = RiskFinding(
        id=finding_id,
        asset_id=asset.id,
        asset_port_id=port.id,
        severity=RiskSeverity.CRITICAL,
        status=FindingStatus.OPEN,
        title="sudo 存在全量管理员授权",
        description="sudoers contains ALL=(ALL) ALL",
        evidence_json={
            "yaml_rule_id": "sudo.full_privilege_rule.enabled",
            "service_name": "sudo",
        },
    )
    credential = SSHCredential(
        id=str(uuid4()),
        name=f"manual-asset-{asset.id}",
        username="msfadmin",
        auth_type=CredentialAuthType.PASSWORD,
        secret_ciphertext="cipher",
        sudo_secret_ciphertext="sudo-cipher",
        admin_authorized=True,
        last_verification_status="success",
        last_effective_privilege="sudo",
    )
    binding = AssetCredentialBinding(asset_id=asset.id, credential_id=credential.id, priority=-100)
    snapshot = HostSnapshot(
        asset_id=asset.id,
        hostname="sudo-host",
        os_release="Ubuntu 22.04",
        kernel_version="5.15.0",
        cpu_json={},
        memory_json={},
        software_json={
            "packages": [{"name": "sudo", "version": "1:1.9.9", "manager": "dpkg", "arch": "amd64"}],
            "host_checks": {},
            "summary_json": {"authorization_status": "success"},
            "detail_json": {},
        },
        services_json={
            "services": [{"name": "sudo", "state": "installed"}],
            "config_by_service": {
                "sudo": {
                    "source_files": ["/etc/sudoers"],
                    "full_privilege_rule": True,
                }
            },
            "nse_by_port": {},
            "nse_summary": {},
        },
        error_json={},
        collection_status="success",
    )
    with SessionLocal() as db:
        db.add(asset)
        db.add(port)
        db.add(credential)
        db.add(binding)
        db.add(finding)
        db.add(snapshot)
        db.commit()
    return asset_id, finding_id


def test_remediation_workspace_requires_admin(tmp_path) -> None:
    client = _build_client(tmp_path, role=UserRole.ANALYST)
    asset_id, _ = _create_asset_context()

    response = client.get(f"/api/v1/remediation/assets/{asset_id}/workspace")

    assert response.status_code == 403


def test_remediation_plan_renders_supported_config_step(tmp_path) -> None:
    client = _build_client(tmp_path)
    _, finding_id = _create_asset_context()

    response = client.get(f"/api/v1/remediation/findings/{finding_id}/plan")

    assert response.status_code == 200
    body = response.json()
    assert body["execution_ready"] is True
    assert body["impact_summary"]
    assert body["precheck_items"]
    assert body["verify_items"]
    assert body["rollback_notes"]
    assert body["steps"][0]["supported"] is True
    assert "/etc/ssh/sshd_config" in body["steps"][0]["generated_command"]
    assert "PasswordAuthentication" in body["steps"][0]["generated_command"]
    assert body["steps"][0]["backup_plan"]["targets"] == ["/etc/ssh/sshd_config"]
    assert body["steps"][0]["target_files"] == ["/etc/ssh/sshd_config"]
    assert body["steps"][0]["target_services"] == ["ssh"]
    assert body["steps"][0]["verify_items"] == ["确认 PasswordAuthentication no 已生效"]


def test_remediation_assets_endpoint_returns_only_ready_assets_sorted(tmp_path) -> None:
    client = _build_client(tmp_path)
    candidate_asset_id, candidate_finding_id = _create_asset_context(
        hostname="rem-candidate-alpha",
        finding_severity=RiskSeverity.CRITICAL,
    )
    excluded_failed_asset_id, _ = _create_asset_context(
        hostname="rem-excluded-failed-auth",
        credential_status="failed",
        effective_privilege=None,
    )
    excluded_no_snapshot_asset_id, _ = _create_asset_context(
        hostname="rem-excluded-no-snapshot",
        include_snapshot=False,
    )
    excluded_no_open_risk_asset_id, _ = _create_asset_context(
        hostname="rem-excluded-no-open-risk",
        include_open_finding=False,
    )
    excluded_closed_port_asset_id, _ = _create_asset_context(
        hostname="rem-excluded-closed-port",
        port_state="closed",
    )

    response = client.get("/api/v1/remediation/assets?page=1&page_size=24&keyword=alpha")

    assert response.status_code == 200
    body = response.json()
    asset_ids = {item["asset_id"] for item in body["items"]}
    assert candidate_asset_id in asset_ids
    assert excluded_failed_asset_id not in asset_ids
    assert excluded_no_snapshot_asset_id not in asset_ids
    assert excluded_no_open_risk_asset_id not in asset_ids
    assert excluded_closed_port_asset_id not in asset_ids
    candidate = next(item for item in body["items"] if item["asset_id"] == candidate_asset_id)
    assert candidate["recommended_finding_id"] == candidate_finding_id
    assert candidate["highest_severity"] == "critical"
    assert candidate["effective_privilege"] == "root"


def test_remediation_assets_endpoint_requires_admin(tmp_path) -> None:
    client = _build_client(tmp_path, role=UserRole.ANALYST)

    response = client.get("/api/v1/remediation/assets")

    assert response.status_code == 403


def test_remediation_asset_detail_returns_runner_summary(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
            )
        )
        db.add(
            RemediationSession(
                asset_id=asset_id,
                status="draft",
                summary_json={"summary_text": "ready"},
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/assets/{asset_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["runner"]["status"] in {"online", "offline"}
    assert body["runner"]["install_status"] == "installed"
    assert body["active_session_status"] == "draft"


def test_remediation_asset_detail_returns_runner_runtime_metadata(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                capabilities_json={
                    "runtime_kind": "bundled_binary",
                    "install_mode": "user",
                    "service_mode": "crontab",
                    "host_facts": {"os": "linux", "arch": "amd64"},
                    "compatibility_issues": ["当前未检测到可用的 root/sudo，已改用用户态安装"],
                },
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/assets/{asset_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["runner"]["runtime_kind"] == "shell_bundle"
    assert body["runner"]["install_mode"] == "user"
    assert body["runner"]["service_mode"] == "crontab"
    assert body["runner"]["detected_os"] == "linux"
    assert body["runner"]["detected_arch"] == "amd64"
    assert body["runner"]["compatibility_issues"]


def test_asset_runner_endpoint_corrects_stale_installing_state(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    task_id = str(uuid4())
    stale_time = datetime.now(timezone.utc) - timedelta(minutes=20)
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="offline",
                install_status="installing",
                platform_url="http://192.168.10.131:3000",
            )
        )
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.RUNNER_INSTALL,
                status=TaskExecutionStatus.RUNNING,
                scope_type="asset",
                scope_id=asset_id,
                progress=60,
                message="通过 SSH 上传并安装 Host Runner",
                created_at=stale_time,
                started_at=stale_time,
                updated_at=stale_time,
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/assets/{asset_id}/runner")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "offline"
    assert body["install_status"] == "failed"
    assert "长时间未完成平台注册" in (body["last_error"] or "")
    with SessionLocal() as db:
        task = db.get(TaskRun, task_id)
        assert task is not None
        assert task.status == TaskExecutionStatus.FAILURE


def test_remediation_session_endpoint_builds_host_plan(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    response = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})

    assert response.status_code == 200
    body = response.json()
    assert body["asset_id"] == asset_id
    assert body["status"] == "ready"
    assert body["plan"]["findings_covered_count"] == 1
    assert body["plan"]["ready_step_count"] >= 1
    assert body["plan"]["impact_summary"]
    assert body["plan"]["precheck_items"]
    assert body["plan"]["verify_items"]
    assert body["plan"]["rollback_notes"]
    assert body["plan"]["plan_mode"] == "ready"
    assert body["plan"]["stages"]
    assert body["plan"]["stages"][0]["gate_status"] == "ready"
    assert body["plan"]["steps"][0]["target_files"] == ["/etc/ssh/sshd_config"]
    assert body["plan"]["steps"][0]["target_services"] == ["ssh"]
    assert body["messages"] == []


def test_remediation_session_refresh_ai_appends_new_ai_plan_summary(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    session_id = created.json()["session_id"]
    assert created.json()["messages"] == []

    refreshed = client.post(
        f"/api/v1/remediation/sessions/{session_id}/messages",
        json={"intent": "refresh_ai"},
    )

    assert refreshed.status_code == 200
    interim = refreshed.json()
    assert interim["messages"][-1]["message_type"] == "intent"

    _run_session_ai(session_id, reason="refresh_ai", force=True)
    body = client.get(f"/api/v1/remediation/sessions/{session_id}").json()
    assert body["messages"][-2]["message_type"] == "intent"
    assert body["messages"][-1]["message_type"] == "ai_plan_summary"
    assert sum(1 for item in body["messages"] if item["message_type"] == "ai_plan_summary") == 1


def test_remediation_session_explain_blockers_appends_ai_blocker_analysis(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})

    assert created.status_code == 200
    created_body = created.json()
    assert created_body["status"] == "draft"
    initial_message_count = len(created_body["messages"])

    explained = client.post(
        f"/api/v1/remediation/sessions/{created_body['session_id']}/messages",
        json={"intent": "explain_blockers"},
    )

    assert explained.status_code == 200
    assert len(explained.json()["messages"]) == initial_message_count + 1

    _run_session_ai(created_body["session_id"], reason="explain_blockers", force=True)
    body = client.get(f"/api/v1/remediation/sessions/{created_body['session_id']}").json()
    assert len(body["messages"]) == initial_message_count + 3
    assert body["messages"][-3]["message_type"] == "intent"
    assert body["messages"][-2]["message_type"] == "ai_plan_summary"
    assert body["messages"][-1]["message_type"] == "ai_blocker_analysis"


def test_remediation_session_stream_emits_snapshot_and_ai_updates(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    session_id = created.json()["session_id"]
    token = _admin_ws_token()

    with client.websocket_connect(f"/api/v1/remediation/sessions/{session_id}/stream?token={token}") as websocket:
        initial = websocket.receive_json()
        assert initial["type"] == "session_snapshot"
        assert initial["session"]["session_id"] == session_id

        with SessionLocal() as db:
            session = db.get(RemediationSession, session_id)
            assert session is not None
            summary_json = dict(session.summary_json or {})
            summary_json.update(
                ai_generation_status="queued",
                pending_ai_reason="initial",
                pending_ai_digest="pending-test-digest",
            )
            session.summary_json = summary_json
            db.add(session)
            db.commit()

        started = websocket.receive_json()
        assert started["type"] == "ai_generation_started"
        assert started["reason"] == "initial"

        _run_session_ai(session_id, reason="initial", force=False)

        added = None
        snapshot = None
        for _ in range(6):
            event = websocket.receive_json()
            if event["type"] == "session_message_added" and event["message"]["message_type"] == "ai_plan_summary":
                added = event
            if event["type"] == "session_snapshot":
                snapshot = event
            if added and snapshot:
                break

        assert added is not None
        assert snapshot is not None

    reread = client.get(f"/api/v1/remediation/sessions/{session_id}")
    assert reread.status_code == 200
    assert any(item["message_type"] == "ai_plan_summary" for item in reread.json()["messages"])


def test_get_remediation_session_does_not_duplicate_unchanged_ai_messages(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    session_id = created.json()["session_id"]
    _run_session_ai(session_id, reason="initial", force=False)
    first_read = client.get(f"/api/v1/remediation/sessions/{session_id}")
    assert first_read.status_code == 200
    initial_message_count = len(first_read.json()["messages"])

    reread = client.get(f"/api/v1/remediation/sessions/{session_id}")

    assert reread.status_code == 200
    assert len(reread.json()["messages"]) == initial_message_count


def test_remediation_asset_detail_clears_stale_terminal_active_session(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    task_id = str(uuid4())
    session_id = str(uuid4())
    with SessionLocal() as db:
        db.add(HostRunner(asset_id=asset_id, status="online", install_status="installed"))
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.REMEDIATION_EXECUTE,
                status=TaskExecutionStatus.SUCCESS,
                scope_type="asset",
                scope_id=asset_id,
                progress=100,
                message="Host Runner 已完成整机修复计划",
                result_json={
                    "context": {"asset_id": asset_id, "stage_code": "remove_exposure", "stage_name": "暴露面收敛"},
                    "execution": {"execution_boundary": "runner_dispatch"},
                },
            )
        )
        db.add(
            RemediationSession(
                id=session_id,
                asset_id=asset_id,
                status="running",
                last_task_id=task_id,
                summary_json={"summary_text": "stale", "running_stage_code": "remove_exposure"},
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/assets/{asset_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["active_session_id"] is None
    assert body["active_session_status"] is None


def test_get_remediation_session_corrects_status_from_task_state(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    task_id = str(uuid4())
    session_id = str(uuid4())
    with SessionLocal() as db:
        db.add(HostRunner(asset_id=asset_id, status="online", install_status="installed"))
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.REMEDIATION_EXECUTE,
                status=TaskExecutionStatus.SUCCESS,
                scope_type="asset",
                scope_id=asset_id,
                progress=100,
                message="Host Runner 已完成整机修复计划",
                result_json={
                    "context": {"asset_id": asset_id, "stage_code": "remove_exposure", "stage_name": "暴露面收敛"},
                    "execution": {"execution_boundary": "runner_dispatch"},
                },
            )
        )
        db.add(
            RemediationSession(
                id=session_id,
                asset_id=asset_id,
                status="running",
                last_task_id=task_id,
                summary_json={"summary_text": "running", "running_stage_code": "remove_exposure"},
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/sessions/{session_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert any(item["message_type"] == "audit" for item in body["messages"])


def test_get_remediation_session_appends_ai_task_failure_message(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    task_id = str(uuid4())
    session_id = str(uuid4())
    with SessionLocal() as db:
        db.add(HostRunner(asset_id=asset_id, status="online", install_status="installed"))
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.REMEDIATION_EXECUTE,
                status=TaskExecutionStatus.FAILURE,
                scope_type="asset",
                scope_id=asset_id,
                progress=100,
                message="sshd 配置校验失败",
                result_json={
                    "context": {"asset_id": asset_id, "stage_code": "remove_exposure", "stage_name": "暴露面收敛"},
                    "execution": {
                        "execution_boundary": "runner_dispatch",
                        "step_results": [
                            {
                                "step_id": "step-1",
                                "title": "关闭密码登录",
                                "status": "failed",
                                "output_tail": ["line 1", "sshd: bad configuration option"],
                            }
                        ],
                    }
                },
            )
        )
        db.add(
            RemediationSession(
                id=session_id,
                asset_id=asset_id,
                status="running",
                last_task_id=task_id,
                summary_json={"summary_text": "running", "running_stage_code": "remove_exposure"},
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/sessions/{session_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert all(item["message_type"] != "ai_task_failure" for item in body["messages"])

    _run_session_ai(session_id, reason="auto", force=False)
    reread = client.get(f"/api/v1/remediation/sessions/{session_id}")
    assert reread.status_code == 200
    assert any(item["message_type"] == "ai_task_failure" for item in reread.json()["messages"])
    ai_failure = next(item for item in reread.json()["messages"] if item["message_type"] == "ai_task_failure")
    assert "失败诊断" in ai_failure["content"]


def test_get_remediation_session_rebuilds_stale_cached_plan_when_runner_state_changes(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, finding_id = _create_asset_context()
    session_id = str(uuid4())
    with SessionLocal() as db:
        snapshot = db.scalar(
            db.query(HostSnapshot)
            .filter(HostSnapshot.asset_id == asset_id)
            .order_by(HostSnapshot.collected_at.desc())
            .statement
        )
        assert snapshot is not None
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            RemediationSession(
                id=session_id,
                asset_id=asset_id,
                status="draft",
                plan_json={
                    "execution_ready": False,
                    "blocked_reasons": ["Host Runner 当前离线，无法拉取整机修复计划"],
                    "findings_covered_count": 1,
                    "service_count": 1,
                    "impacted_services": ["ssh"],
                    "phase_count": 1,
                    "ready_step_count": 0,
                    "blocked_step_count": 1,
                    "summary_text": "stale plan",
                    "phases": [],
                    "steps": [],
                },
                finding_snapshot_json={
                    "findings": [
                        {
                            "finding_id": finding_id,
                            "rule_id": "ssh.password_authentication.enabled",
                            "title": "SSH 允许密码登录",
                            "severity": "high",
                            "status": "open",
                            "service_name": "ssh",
                            "detected_at": datetime.now(timezone.utc).isoformat(),
                            "has_template": True,
                        }
                    ],
                    "latest_collection_at": snapshot.collected_at.isoformat(),
                },
                summary_json={
                    "summary_text": "stale plan",
                    "ready_step_count": 0,
                    "blocked_step_count": 1,
                    "runner_status": "offline",
                    "runner_install_status": "installed",
                },
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/sessions/{session_id}")

    assert response.status_code == 200
    body = response.json()
    assert "Host Runner 当前离线，无法拉取整机修复计划" not in body["plan"]["blocked_reasons"]
    assert body["plan"]["ready_step_count"] >= 1


def test_approve_remediation_session_sets_session_running(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    session_id = created.json()["session_id"]

    response = client.post(f"/api/v1/remediation/sessions/{session_id}/approve")

    assert response.status_code == 202
    body = response.json()
    session_response = client.get(f"/api/v1/remediation/sessions/{session_id}")
    assert session_response.status_code == 200
    assert session_response.json()["status"] == "running"
    assert session_response.json()["last_task_id"] == body["task_id"]


def test_remediation_session_blocks_execution_when_runner_only_has_user_mode_without_sudo(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
                capabilities_json={
                    "runtime_kind": "shell_bundle",
                    "install_mode": "user",
                    "service_mode": "crontab",
                    "probe": {
                        "can_system_install": False,
                    },
                },
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    body = created.json()
    assert any("root/sudo" in item for item in body["plan"]["blocked_reasons"])

    approve = client.post(f"/api/v1/remediation/sessions/{body['session_id']}/approve")
    assert approve.status_code == 400
    assert "root/sudo" in approve.json()["detail"]


def test_remediation_session_blocks_sudo_self_lock_steps(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_sudo_self_lock_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})

    assert created.status_code == 200
    body = created.json()
    assert any("sudo 管理链路" in item for item in body["plan"]["blocked_reasons"])
    assert any(
        "sudo 管理链路" in str(step.get("blocked_reason") or "")
        for stage in body["plan"]["stages"]
        for step in stage["steps"]
    )

    approve = client.post(f"/api/v1/remediation/sessions/{body['session_id']}/approve")

    assert approve.status_code == 400
    assert "sudo 管理链路" in approve.json()["detail"]


def test_remediation_task_endpoint_accepts_runner_dispatch_boundary(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    task_id = str(uuid4())
    with SessionLocal() as db:
        db.add(
            TaskRun(
                id=task_id,
                task_type=TaskType.REMEDIATION_EXECUTE,
                status=TaskExecutionStatus.RUNNING,
                scope_type="asset",
                scope_id=asset_id,
                progress=55,
                message="等待 Runner 接单",
                result_json={
                    "context": {"asset_id": asset_id},
                    "execution": {"execution_boundary": "runner_dispatch", "execution_status": "succeeded", "business_status": "verified_partial"},
                    "execution_status": "succeeded",
                    "business_status": "verified_partial",
                    "reverify_task_id": "reverify-task-1",
                    "reverify_summary": {"open_target_count": 1, "closed_target_count": 0},
                    "targeted_finding_outcomes": [{"rule_id": "apache.webdav.enabled", "status": "open"}],
                },
            )
        )
        db.commit()

    response = client.get(f"/api/v1/remediation/tasks/{task_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["execution_boundary"] == "runner_dispatch"
    assert body["execution_status"] == "succeeded"
    assert body["business_status"] == "verified_partial"
    assert body["reverify_task_id"] == "reverify-task-1"
    assert body["reverify_summary"]["open_target_count"] == 1
    assert body["targeted_finding_outcomes"][0]["status"] == "open"


def test_runner_install_endpoint_queues_task(monkeypatch, tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()

    monkeypatch.setattr(
        remediation_endpoint.run_runner_install_task,
        "delay",
        lambda *args, **kwargs: SimpleNamespace(id="celery-runner-install-1"),
        raising=False,
    )

    response = client.post(f"/api/v1/remediation/assets/{asset_id}/runner/install")

    assert response.status_code == 202
    body = response.json()
    assert body["stream_url"].endswith(f"/api/v1/remediation/tasks/{body['task_id']}/stream")
    with SessionLocal() as db:
        task = db.get(TaskRun, body["task_id"])
        assert task is not None
        assert task.task_type == TaskType.RUNNER_INSTALL


def test_runner_install_endpoint_allows_user_mode_fallback(monkeypatch, tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context(credential_status="failed", effective_privilege=None)

    monkeypatch.setattr(
        remediation_endpoint.run_runner_install_task,
        "delay",
        lambda *args, **kwargs: SimpleNamespace(id="celery-runner-install-user-mode"),
        raising=False,
    )

    response = client.post(f"/api/v1/remediation/assets/{asset_id}/runner/install")

    assert response.status_code == 202


def test_runner_install_endpoint_prefers_public_base_url(monkeypatch, tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()

    monkeypatch.setattr(settings, "RUNNER_PUBLIC_BASE_URL", "http://192.168.10.131:3000")
    monkeypatch.setattr(
        remediation_endpoint.run_runner_install_task,
        "delay",
        lambda *args, **kwargs: SimpleNamespace(id="celery-runner-install-public-url"),
        raising=False,
    )

    response = client.post(f"/api/v1/remediation/assets/{asset_id}/runner/install")

    assert response.status_code == 202
    with SessionLocal() as db:
        runner = db.scalar(db.query(HostRunner).filter(HostRunner.asset_id == asset_id).statement)
        assert runner is not None
        assert runner.platform_url == "http://192.168.10.131:3000"


def test_remediation_execute_endpoint_queues_task_in_apply_mode(monkeypatch, tmp_path) -> None:
    client = _build_client(tmp_path)
    _, finding_id = _create_asset_context()

    monkeypatch.setattr(
        remediation_endpoint.run_remediation_execute_task,
        "delay",
        lambda *args, **kwargs: SimpleNamespace(id="celery-remediation-1"),
        raising=False,
    )

    response = client.post(
        f"/api/v1/remediation/findings/{finding_id}/execute",
        json={"steps": [], "execution_mode": "apply"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["execution_mode"] == "apply"
    assert body["stream_url"].endswith(f"/api/v1/remediation/tasks/{body['task_id']}/stream")
    with SessionLocal() as db:
        task = db.get(TaskRun, body["task_id"])
        assert task is not None
        assert task.task_type == TaskType.REMEDIATION_EXECUTE


def test_remediation_execute_endpoint_defaults_to_dry_run_and_exposes_evidence(tmp_path) -> None:
    client = _build_client(tmp_path)
    _, finding_id = _create_asset_context()

    response = client.post(
        f"/api/v1/remediation/findings/{finding_id}/execute",
        json={"steps": []},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["execution_mode"] == "dry_run"

    task_response = client.get(f"/api/v1/remediation/tasks/{body['task_id']}")
    assert task_response.status_code == 200
    assert task_response.json()["status"] == "success"
    assert task_response.json()["execution_mode"] == "dry_run"

    evidence_response = client.get(f"/api/v1/remediation/tasks/{body['task_id']}/evidence")
    assert evidence_response.status_code == 200
    evidence_body = evidence_response.json()
    assert evidence_body["execution_mode"] == "dry_run"
    assert evidence_body["item_count"] >= 1


def test_remediation_session_approve_supports_dry_run_preview(tmp_path) -> None:
    client = _build_client(tmp_path)
    asset_id, _ = _create_asset_context()
    with SessionLocal() as db:
        db.add(
            HostRunner(
                asset_id=asset_id,
                status="online",
                install_status="installed",
                last_seen_at=datetime.now(timezone.utc),
            )
        )
        db.commit()

    created = client.post(f"/api/v1/remediation/assets/{asset_id}/sessions", json={})
    assert created.status_code == 200
    session_id = created.json()["session_id"]

    response = client.post(
        f"/api/v1/remediation/sessions/{session_id}/approve",
        json={"execution_mode": "dry_run"},
    )

    assert response.status_code == 202
    body = response.json()
    assert body["execution_mode"] == "dry_run"
    session_response = client.get(f"/api/v1/remediation/sessions/{session_id}")
    assert session_response.status_code == 200
    assert session_response.json()["last_task_id"] == body["task_id"]
    task_response = client.get(f"/api/v1/remediation/tasks/{body['task_id']}")
    assert task_response.status_code == 200
    assert task_response.json()["execution_mode"] == "dry_run"


def test_remediation_execute_endpoint_rejects_sudo_self_lock_step(tmp_path) -> None:
    client = _build_client(tmp_path)
    _, finding_id = _create_sudo_self_lock_context()

    response = client.post(
        f"/api/v1/remediation/findings/{finding_id}/execute",
        json={"steps": []},
    )

    assert response.status_code == 400
    assert "sudo 管理链路" in response.json()["detail"]
