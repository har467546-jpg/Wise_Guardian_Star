import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_current_user, get_db_session
from app.api.v1.endpoints import vuln_library
from app.db.base import Base
from app.db.models.enums import TaskType, UserRole
from app.db.models.task_run import TaskRun
from app.db.models.vuln_rule_index import VulnRuleIndex
from app.main import create_app
from app.rules.rule_store import RuleStore
from app.services.vuln_library_service import VulnLibraryService
from app.tasks import vuln_intel_tasks


@compiles(JSONB, "sqlite")
def _compile_jsonb_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "JSON"


@compiles(INET, "sqlite")
def _compile_inet_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


@compiles(CIDR, "sqlite")
def _compile_cidr_for_sqlite(_type, _compiler, **_kw):  # type: ignore[no-untyped-def]
    return "TEXT"


engine = create_engine(
    "sqlite+pysqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
    class_=Session,
)


def _override_user(role: UserRole):
    def _resolver():
        return SimpleNamespace(id="user-1", role=role, is_active=True)

    return _resolver


def _reset_index_table() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        db.query(VulnRuleIndex).delete()
        db.commit()


def _build_service(tmp_path, content: str) -> VulnLibraryService:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(content, encoding="utf-8")
    return VulnLibraryService(RuleStore(path), SessionLocal)


def _build_client(tmp_path, role: UserRole, content: str = "rules: []\n") -> tuple[TestClient, VulnLibraryService]:
    _reset_index_table()
    service = _build_service(tmp_path, content)
    app = create_app()
    app.dependency_overrides[get_current_user] = _override_user(role)

    def _override_db():
        with SessionLocal() as db:
            yield db

    app.dependency_overrides[get_db_session] = _override_db
    vuln_library.RULE_SERVICE = service
    return TestClient(app), service


def test_vuln_library_write_requires_admin(tmp_path) -> None:
    client, _ = _build_client(tmp_path, UserRole.ANALYST)

    response = client.post(
        "/api/v1/vuln-library/rules",
        json={
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
            "mitigations": ["upgrade apache"],
        },
    )

    assert response.status_code == 403


def test_vuln_library_admin_can_create_and_list_rules(tmp_path) -> None:
    client, _ = _build_client(tmp_path, UserRole.ADMIN)

    create_response = client.post(
        "/api/v1/vuln-library/rules",
        json={
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9", "nse": {"http-headers.hit": {"eq": True}}},
            "active_check": {
                "detector": "distccd_rce_probe",
                "trigger": "on_passive_match",
                "timeout_seconds": 5,
                "params": {},
            },
            "cve_ids": ["CVE-2007-6388"],
            "mitigations": ["upgrade apache"],
        },
    )
    list_response = client.get("/api/v1/vuln-library/rules")

    assert create_response.status_code == 201
    assert create_response.json()["id"] == "apache.httpd.lt_2_2_9"
    assert create_response.json()["active_check"]["detector"] == "distccd_rce_probe"
    assert create_response.json()["match"]["nse"]["http-headers.hit"]["eq"] is True
    assert list_response.status_code == 200
    assert list_response.json()["meta"]["total"] == 1


def test_vuln_library_batch_import_and_export_require_admin(tmp_path) -> None:
    client, _ = _build_client(tmp_path, UserRole.ANALYST)

    batch_response = client.post(
        "/api/v1/vuln-library/rules/batch/status",
        json={"rule_ids": ["apache.httpd.lt_2_2_9"], "enabled": False},
    )
    export_response = client.get("/api/v1/vuln-library/rules/export")
    import_response = client.post(
        "/api/v1/vuln-library/rules/import",
        data={"mode": "skip_existing", "dry_run": "true"},
        files={"file": ("rules.yaml", "rules: []\n", "application/yaml")},
    )

    assert batch_response.status_code == 403
    assert export_response.status_code == 403
    assert import_response.status_code == 403


def test_vuln_library_status_returns_index_health(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
""",
    )

    response = client.get("/api/v1/vuln-library/status")

    assert response.status_code == 200
    assert response.json()["rule_count"] == 1
    assert response.json()["schema_ready"] is True
    assert response.json()["schema_error"] is None
    assert response.json()["indexed_rule_count"] == 1
    assert response.json()["index_in_sync"] is True


def test_vuln_library_intel_status_endpoint_returns_summary(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
    cve_ids:
      - CVE-2007-6388
""",
    )

    response = client.get("/api/v1/vuln-library/intel/status")

    assert response.status_code == 200
    body = response.json()
    assert body["tracked_rule_cves"] == 1
    assert body["synced_cves"] == 0
    assert body["stale"] is True
    assert body["updated_cves"] == 0


def test_vuln_library_intel_status_auto_queues_stale_sync(monkeypatch) -> None:
    _reset_index_table()
    status_payload = SimpleNamespace(
        total_cves=0,
        tracked_rule_cves=1,
        synced_cves=0,
        stale=True,
        stale_count=1,
        last_synced_at=None,
        sources=["cve_project", "osv", "kev", "epss"],
        updated_cves=0,
    )
    monkeypatch.setattr(vuln_library, "_last_auto_sync_queued_at", None)
    monkeypatch.setattr(vuln_library, "_last_auto_sync_task_id", None)
    monkeypatch.setattr(
        vuln_library,
        "RULE_SERVICE",
        SimpleNamespace(get_status=lambda: SimpleNamespace(schema_ready=True)),
    )
    monkeypatch.setattr(vuln_library.sync_vuln_intel_task, "delay", lambda task_run_id: SimpleNamespace(id=f"celery-{task_run_id}"))

    with SessionLocal() as db:
        auto_sync = vuln_library._queue_auto_intel_sync_if_needed(status_payload, db=db)
    body = vuln_library._to_intel_status_read(status_payload, auto_sync=auto_sync).model_dump(mode="json")

    assert body["sync_status"] == "queued"
    assert body["sync_task_id"]
    assert body["auto_sync_queued"] is True
    with SessionLocal() as db:
        task = db.get(TaskRun, body["sync_task_id"])
        assert task is not None
        assert task.task_type == TaskType.VULN_INTEL_SYNC


def test_vuln_library_intel_sync_queues_background_task(monkeypatch) -> None:
    _reset_index_table()
    status_payload = SimpleNamespace(
        total_cves=0,
        tracked_rule_cves=1,
        synced_cves=0,
        stale=False,
        stale_count=0,
        last_synced_at=None,
        sources=["cve_project", "osv", "kev", "epss"],
        updated_cves=0,
    )
    monkeypatch.setattr(vuln_library, "_last_auto_sync_queued_at", None)
    monkeypatch.setattr(vuln_library, "_last_auto_sync_task_id", None)
    monkeypatch.setattr(
        vuln_library,
        "RULE_SERVICE",
        SimpleNamespace(
            get_status=lambda: SimpleNamespace(schema_ready=True, schema_error=None),
            get_intel_status=lambda: status_payload,
        ),
    )
    monkeypatch.setattr(vuln_library.sync_vuln_intel_task, "delay", lambda task_run_id: SimpleNamespace(id=f"celery-{task_run_id}"))

    with SessionLocal() as db:
        response = vuln_library.sync_vuln_intel_catalog(SimpleNamespace(id="user-1", role=UserRole.ADMIN), db)

    body = response.model_dump(mode="json")
    assert body["sync_status"] == "queued"
    assert body["sync_task_id"]
    assert body["auto_sync_queued"] is True
    with SessionLocal() as db:
        task = db.get(TaskRun, body["sync_task_id"])
        assert task is not None
        assert task.task_type == TaskType.VULN_INTEL_SYNC


def test_scheduled_vuln_intel_sync_creates_task_run(monkeypatch) -> None:
    _reset_index_table()
    monkeypatch.setattr(vuln_intel_tasks, "SessionLocal", SessionLocal)
    monkeypatch.setattr(vuln_intel_tasks, "_acquire_sync_lock", lambda token, *, task_run_id: True)
    monkeypatch.setattr(vuln_intel_tasks, "_release_sync_lock", lambda token: None)
    monkeypatch.setattr(
        vuln_intel_tasks,
        "_sync_intel_payload",
        lambda task_run_id=None: {
            "tracked_rule_cves": 1,
            "synced_cves": 1,
            "updated_cves": 1,
            "stale": False,
            "stale_count": 0,
            "last_synced_at": None,
        },
    )

    result = vuln_intel_tasks.sync_vuln_intel_task.run()

    assert result["tracked_rule_cves"] == 1
    with SessionLocal() as db:
        tasks = db.query(TaskRun).all()
        assert len(tasks) == 1
        assert tasks[0].task_type == TaskType.VULN_INTEL_SYNC
        assert tasks[0].message == "漏洞情报同步任务已入队"


def test_scheduled_vuln_intel_sync_reuses_active_task(monkeypatch) -> None:
    _reset_index_table()
    monkeypatch.setattr(vuln_intel_tasks, "SessionLocal", SessionLocal)
    with SessionLocal() as db:
        existing = vuln_library._create_vuln_intel_task_run(db)

    result = vuln_intel_tasks.sync_vuln_intel_task.run()

    assert result["skipped"] is True
    assert result["task_run_id"] == existing
    with SessionLocal() as db:
        tasks = db.query(TaskRun).all()
        assert len(tasks) == 1
        assert tasks[0].id == existing


def test_vuln_library_intel_sync_returns_409_when_schema_not_ready(monkeypatch) -> None:
    monkeypatch.setattr(
        vuln_library,
        "RULE_SERVICE",
        SimpleNamespace(get_status=lambda: SimpleNamespace(schema_ready=False, schema_error="数据库结构未升级，请先执行 alembic upgrade head")),
    )

    with SessionLocal() as db, pytest.raises(HTTPException) as exc_info:
        vuln_library.sync_vuln_intel_catalog(SimpleNamespace(id="user-1", role=UserRole.ADMIN), db)

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "数据库结构未升级，请先执行 alembic upgrade head"


def test_vuln_library_export_supports_selected_ids_and_filters(tmp_path) -> None:
    client, service = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
  - id: nginx.http.autoindex.enabled
    name: Nginx autoindex enabled
    enabled: false
    service: nginx
    severity: medium
    description: Autoindex is enabled
    match:
      config:
        autoindex:
          eq: on
""",
    )
    service.rebuild_index()

    selected_response = client.get("/api/v1/vuln-library/rules/export", params=[("rule_ids", "nginx.http.autoindex.enabled")])
    filtered_response = client.get("/api/v1/vuln-library/rules/export", params={"format": "json", "service": "apache"})

    selected_body = selected_response.content.decode("utf-8")
    filtered_body = json.loads(filtered_response.content.decode("utf-8"))

    assert selected_response.status_code == 200
    assert "nginx.http.autoindex.enabled" in selected_body
    assert "apache.httpd.lt_2_2_9" not in selected_body
    assert filtered_response.status_code == 200
    assert filtered_body["rules"][0]["id"] == "apache.httpd.lt_2_2_9"
    assert len(filtered_body["rules"]) == 1
    assert filtered_body["rules"][0]["remediation"]["actions"][0]["action_type"] == "upgrade_package"


def test_vuln_library_catalog_view_defaults_to_non_legacy(tmp_path) -> None:
    client, service = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: legacy.rule
    name: Legacy rule
    enabled: true
    service: nginx
    severity: high
    description: legacy rule
    match:
      version: <1.18
    tags:
      - legacy
      - legacy-exposure
  - id: high.value.rule
    name: High value rule
    enabled: true
    service: apache
    severity: critical
    description: high value rule
    match:
      nse:
        http-shellshock.vulnerable:
          eq: true
    tags:
      - high-value
""",
    )
    service.rebuild_index()

    default_response = client.get("/api/v1/vuln-library/rules")
    legacy_response = client.get("/api/v1/vuln-library/rules", params={"catalog_view": "legacy"})
    export_response = client.get("/api/v1/vuln-library/rules/export", params={"format": "json"})

    assert default_response.status_code == 200
    assert [item["id"] for item in default_response.json()["items"]] == ["high.value.rule"]
    assert legacy_response.status_code == 200
    assert [item["id"] for item in legacy_response.json()["items"]] == ["legacy.rule"]
    exported_ids = [item["id"] for item in json.loads(export_response.content.decode("utf-8"))["rules"]]
    assert exported_ids == ["high.value.rule"]


def test_vuln_library_returns_package_match_and_remediation(tmp_path) -> None:
    client, _ = _build_client(tmp_path, UserRole.ADMIN)

    create_response = client.post(
        "/api/v1/vuln-library/rules",
        json={
            "id": "sudo.baron_samedit.cve_2021_3156.exposed",
            "name": "Sudo Baron Samedit",
            "enabled": True,
            "service": "sudo",
            "severity": "critical",
            "description": "distro aware sudo package rule",
            "match": {
                "package": {
                    "manager": "dpkg",
                    "name": "sudo",
                    "compare": "lt_fixed",
                    "fixed_versions": {"ubuntu": {"20.04": "1.8.31-1ubuntu1.2"}},
                }
            },
        },
    )

    assert create_response.status_code == 201
    assert create_response.json()["match"]["package"]["name"] == "sudo"
    assert create_response.json()["remediation"]["summary"]
    assert create_response.json()["remediation"]["actions"][0]["action_type"] == "upgrade_package"


def test_vuln_library_import_preview_and_apply(tmp_path) -> None:
    client, _ = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
""",
    )

    file_payload = {
        "rules": [
            {
                "id": "apache.httpd.lt_2_2_9",
                "name": "Apache legacy exposure updated",
                "enabled": False,
                "service": "apache",
                "severity": "medium",
                "description": "Apache version is older than 2.2.9",
                "match": {"version": "<2.2.9"},
            },
            {
                "id": "redis.auth.disabled",
                "name": "Redis auth disabled",
                "enabled": True,
                "service": "redis",
                "severity": "high",
                "description": "Redis does not require authentication",
                "match": {"config": {"requirepass": {"exists": False}}},
                "active_check": {
                    "detector": "ftp_anonymous_login",
                    "trigger": "on_service_present",
                    "timeout_seconds": 5,
                    "params": {},
                },
            },
        ]
    }

    preview = client.post(
        "/api/v1/vuln-library/rules/import",
        data={"mode": "upsert", "dry_run": "true"},
        files={"file": ("rules.json", json.dumps(file_payload), "application/json")},
    )
    applied = client.post(
        "/api/v1/vuln-library/rules/import",
        data={"mode": "upsert", "dry_run": "false"},
        files={"file": ("rules.json", json.dumps(file_payload), "application/json")},
    )

    assert preview.status_code == 200
    assert preview.json()["created"] == 1
    assert preview.json()["updated"] == 1
    assert applied.status_code == 200
    assert applied.json()["created"] == 1
    assert applied.json()["updated"] == 1


def test_vuln_library_rejects_invalid_active_check(tmp_path) -> None:
    client, _ = _build_client(tmp_path, UserRole.ADMIN)

    response = client.post(
        "/api/v1/vuln-library/rules",
        json={
            "id": "invalid.rule",
            "name": "Invalid active check",
            "enabled": True,
            "service": "ftp",
            "severity": "high",
            "description": "invalid detector",
            "match": {"version": "==1.0"},
            "active_check": {
                "detector": "unknown_detector",
                "trigger": "on_passive_match",
                "timeout_seconds": 5,
                "params": {},
            },
        },
    )

    assert response.status_code == 400
    assert "active_check.detector 不受支持" in response.json()["detail"]


def test_vuln_library_batch_status_and_rebuild_index(tmp_path) -> None:
    client, service = _build_client(
        tmp_path,
        UserRole.ADMIN,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
""",
    )
    service.rebuild_index()

    batch_response = client.post(
        "/api/v1/vuln-library/rules/batch/status",
        json={"rule_ids": ["apache.httpd.lt_2_2_9"], "enabled": False},
    )
    _reset_index_table()
    rebuild_response = client.post("/api/v1/vuln-library/index/rebuild")

    assert batch_response.status_code == 200
    assert batch_response.json()["updated"] == 1
    assert rebuild_response.status_code == 200
    assert rebuild_response.json()["index_in_sync"] is True
    assert rebuild_response.json()["indexed_rule_count"] == 1
