import json
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import delete, text

from app.api.deps import get_current_user
from app.api.v1.endpoints import vuln_library
from app.db.base import Base
from app.db.models.enums import UserRole
from app.db.models.vuln_rule_index import VulnRuleIndex
from app.db.session import SessionLocal, engine
from app.main import create_app
from app.rules.rule_store import RuleStore
from app.services.vuln_library_service import VulnLibraryService


def _override_user(role: UserRole):
    def _resolver():
        return SimpleNamespace(id="user-1", role=role, is_active=True)

    return _resolver


def _reset_index_table() -> None:
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE vuln_rule_index ADD COLUMN IF NOT EXISTS has_active_check BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE vuln_rule_index ADD COLUMN IF NOT EXISTS active_detector VARCHAR(64)"))
        conn.execute(text("ALTER TABLE vuln_rule_index ADD COLUMN IF NOT EXISTS active_trigger VARCHAR(32)"))
        conn.execute(text("ALTER TABLE vuln_rule_index ADD COLUMN IF NOT EXISTS has_nse_match BOOLEAN NOT NULL DEFAULT false"))
        conn.execute(text("ALTER TABLE vuln_rule_index ADD COLUMN IF NOT EXISTS nse_scripts JSONB NOT NULL DEFAULT '[]'::jsonb"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_rule_index_has_active_check ON vuln_rule_index (has_active_check)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_rule_index_active_detector ON vuln_rule_index (active_detector)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_vuln_rule_index_has_nse_match ON vuln_rule_index (has_nse_match)"))
    with SessionLocal() as db:
        db.execute(delete(VulnRuleIndex))
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
    assert response.json()["indexed_rule_count"] == 1
    assert response.json()["index_in_sync"] is True


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
