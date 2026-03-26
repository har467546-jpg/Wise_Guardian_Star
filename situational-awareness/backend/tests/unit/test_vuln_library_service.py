import json

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models.vuln_rule_index import VulnRuleIndex
from app.rules.rule_store import RuleStore
from app.services.vuln_library_service import (
    VulnLibrarySchemaNotReadyError,
    VulnLibrarySchemaStatus,
    VulnLibraryService,
)


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


def _build_service_without_index(tmp_path, content: str) -> VulnLibraryService:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(content, encoding="utf-8")
    return VulnLibraryService(RuleStore(path), lambda: None)


def test_vuln_library_service_rebuilds_index_from_yaml(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
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

    status = service.get_status()

    with SessionLocal() as db:
        rows = db.execute(select(VulnRuleIndex).order_by(VulnRuleIndex.rule_id.asc())).scalars().all()

    assert status.rule_count == 2
    assert status.indexed_rule_count == 2
    assert status.index_in_sync is True
    assert len(rows) == 2
    assert rows[0].rule_id == "apache.httpd.lt_2_2_9"
    assert rows[0].source_hash == rows[1].source_hash
    assert rows[0].has_active_check is False


def test_vuln_library_service_write_operations_refresh_index(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(tmp_path, "rules: []\n")

    created = service.create_rule(
        {
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
        }
    )
    service.batch_update_status([created.rule_id], enabled=False)
    service.delete_rule(created.rule_id)
    status = service.get_status()

    with SessionLocal() as db:
        rows = db.execute(select(VulnRuleIndex)).scalars().all()

    assert status.rule_count == 0
    assert status.indexed_rule_count == 0
    assert status.index_in_sync is True
    assert rows == []


def test_vuln_library_service_get_status_reports_schema_not_ready_without_touching_index(tmp_path, monkeypatch) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
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
    monkeypatch.setattr(
        service,
        "_get_schema_status",
        lambda: VulnLibrarySchemaStatus(
            ready=False,
            error="数据库结构未升级，请先执行 alembic upgrade head",
        ),
    )

    def _unexpected_index_refresh(*args, **kwargs):
        raise AssertionError("schema 未就绪时不应刷新索引")

    monkeypatch.setattr(service, "_ensure_index_current", _unexpected_index_refresh)

    status = service.get_status()

    assert status.rule_count == 1
    assert status.schema_ready is False
    assert status.schema_error == "数据库结构未升级，请先执行 alembic upgrade head"
    assert status.index_in_sync is False
    assert status.index_last_error == "数据库结构未升级，请先执行 alembic upgrade head"


def test_vuln_library_service_sync_intel_fails_fast_when_schema_not_ready(tmp_path, monkeypatch) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
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
    monkeypatch.setattr(
        service,
        "_get_schema_status",
        lambda: VulnLibrarySchemaStatus(
            ready=False,
            error="数据库结构未升级，请先执行 alembic upgrade head",
        ),
    )

    with pytest.raises(VulnLibrarySchemaNotReadyError, match="alembic upgrade head"):
        service.sync_intel()


def test_vuln_library_service_indexes_active_check_metadata(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: ftp.anonymous.enabled
    name: FTP anonymous enabled
    enabled: true
    service: vsftpd
    severity: high
    description: Anonymous FTP access is enabled
    match:
      config:
        anonymous_enabled:
          eq: true
    active_check:
      detector: ftp_anonymous_login
      trigger: on_service_present
      timeout_seconds: 5
      params: {}
""",
    )

    status = service.get_status()

    with SessionLocal() as db:
        row = db.scalar(select(VulnRuleIndex).where(VulnRuleIndex.rule_id == "ftp.anonymous.enabled"))

    assert status.index_in_sync is True
    assert row is not None
    assert row.has_active_check is True
    assert row.active_detector == "ftp_anonymous_login"
    assert row.active_trigger == "on_service_present"


def test_vuln_library_service_indexes_nse_metadata(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: ftp.anonymous.nse.enabled
    name: FTP anonymous enabled by NSE
    enabled: true
    service: vsftpd
    severity: high
    description: Anonymous FTP access is enabled
    match:
      nse:
        ftp-anon.hit:
          eq: true
        ftp-anon.writable_entries:
          contains: incoming
""",
    )

    status = service.get_status()

    with SessionLocal() as db:
        row = db.scalar(select(VulnRuleIndex).where(VulnRuleIndex.rule_id == "ftp.anonymous.nse.enabled"))

    assert status.index_in_sync is True
    assert row is not None
    assert row.has_nse_match is True
    assert row.nse_scripts == ["ftp-anon"]
    assert row.match_type == "nse"


def test_vuln_library_service_indexes_package_metadata(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: sudo.baron_samedit.cve_2021_3156.exposed
    name: Sudo Baron Samedit
    enabled: true
    service: sudo
    severity: critical
    description: distro aware sudo package rule
    match:
      package:
        manager: dpkg
        name: sudo
        compare: lt_fixed
        fixed_versions:
          ubuntu:
            "20.04": "1.8.31-1ubuntu1.2"
""",
    )

    status = service.get_status()

    with SessionLocal() as db:
        row = db.scalar(select(VulnRuleIndex).where(VulnRuleIndex.rule_id == "sudo.baron_samedit.cve_2021_3156.exposed"))

    assert status.index_in_sync is True
    assert row is not None
    assert row.match_type == "package"
    assert row.has_nse_match is False


def test_vuln_library_service_normalizes_legacy_remediation_payload() -> None:
    payload, total = VulnLibraryService._normalize_import_payload(
        {
            "rules": [
                {
                    "id": "apache.httpd.lt_2_2_9",
                    "name": "Apache legacy exposure",
                    "enabled": True,
                    "service": "apache",
                    "severity": "high",
                    "description": "Apache version is older than 2.2.9",
                    "match": {"version": "<2.2.9"},
                    "remediation": {
                        "summary": "旧模板",
                        "automation_level": "assisted",
                        "actions": [
                            {
                                "action_type": "manual_step",
                                "title": "人工处理",
                                "params": {},
                            }
                        ],
                    },
                }
            ]
        }
    )

    assert total == 1
    assert "remediation" not in payload["rules"][0]


def test_vuln_library_service_catalog_view_filters_legacy_rules(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: legacy.rule
    name: Legacy rule
    enabled: true
    service: nginx
    severity: high
    description: legacy only
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
    description: high value
    match:
      nse:
        http-shellshock.vulnerable:
          eq: true
    tags:
      - high-value
      - rce
  - id: regular.rule
    name: Regular rule
    enabled: true
    service: redis
    severity: high
    description: regular
    match:
      config:
        protected_mode:
          eq: false
""",
    )

    default_rules, default_total = service.list_rules(page=1, page_size=20, catalog_view="default")
    legacy_rules, legacy_total = service.list_rules(page=1, page_size=20, catalog_view="legacy")
    all_rules, all_total = service.list_rules(page=1, page_size=20, catalog_view="all")

    assert default_total == 2
    assert [rule.rule_id for rule in default_rules] == ["high.value.rule", "regular.rule"]
    assert legacy_total == 1
    assert [rule.rule_id for rule in legacy_rules] == ["legacy.rule"]
    assert all_total == 3


def test_vuln_library_service_export_includes_resolved_remediation(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
    mitigations:
      - upgrade apache
""",
    )

    export_payload = service.export_rules(format_name="json", catalog_view="all")
    exported = json.loads(export_payload.content.decode("utf-8"))

    assert exported["rules"][0]["id"] == "apache.httpd.lt_2_2_9"
    assert exported["rules"][0]["remediation"]["actions"][0]["action_type"] == "upgrade_package"


def test_vuln_library_service_import_preview_and_apply(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
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
    payload = {
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

    preview = service.import_rules_from_bytes(
        content=json.dumps(payload).encode("utf-8"),
        filename="rules.json",
        format_name="auto",
        mode="upsert",
        dry_run=True,
    )
    applied = service.import_rules_from_bytes(
        content=json.dumps(payload).encode("utf-8"),
        filename="rules.json",
        format_name="auto",
        mode="upsert",
        dry_run=False,
    )
    updated_rule = service.get_rule("apache.httpd.lt_2_2_9")
    created_rule = service.get_rule("redis.auth.disabled")

    assert preview.detected_format == "json"
    assert preview.created_ids == ["redis.auth.disabled"]
    assert preview.updated_ids == ["apache.httpd.lt_2_2_9"]
    assert preview.skipped_ids == []
    assert applied.created_ids == ["redis.auth.disabled"]
    assert applied.updated_ids == ["apache.httpd.lt_2_2_9"]
    assert updated_rule is not None and updated_rule.enabled is False
    assert created_rule is not None and created_rule.service == "redis"
    assert created_rule.active_check is not None
    assert created_rule.active_check.detector == "ftp_anonymous_login"


def test_vuln_library_service_invalid_import_returns_errors_without_writing(tmp_path) -> None:
    _reset_index_table()
    service = _build_service(tmp_path, "rules: []\n")

    result = service.import_rules_from_bytes(
        content=b'{"rules":[{"id":"broken"}]}',
        filename="broken.json",
        format_name="auto",
        mode="skip_existing",
        dry_run=False,
    )
    status = service.get_status()

    assert result.error_count == 1
    assert result.created == 0
    assert "service 必须是非空字符串" in result.errors[0].message
    assert status.rule_count == 0
    assert status.indexed_rule_count == 0


def test_vuln_library_service_recovers_from_concurrent_rebuild_conflict(tmp_path, monkeypatch) -> None:
    _reset_index_table()
    service = _build_service(
        tmp_path,
        """rules:
  - id: nginx.version.lt_1_18
    name: nginx legacy exposure
    enabled: true
    service: nginx
    severity: high
    description: nginx version is older than 1.18
    match:
      version: <1.18
""",
    )

    original_rebuild = service._rebuild_index_in_session
    triggered = {"value": False}

    def _simulate_concurrent_rebuild(db, rules, expected_hash):
        if not triggered["value"]:
            triggered["value"] = True
            with SessionLocal() as other_db:
                original_rebuild(other_db, rules, expected_hash)
            raise IntegrityError(
                "INSERT INTO vuln_rule_index (...) VALUES (...)",
                {},
                Exception("duplicate key value violates unique constraint"),
            )
        return original_rebuild(db, rules, expected_hash)

    monkeypatch.setattr(service, "_rebuild_index_in_session", _simulate_concurrent_rebuild)

    status = service.get_status()

    with SessionLocal() as db:
        rows = db.execute(select(VulnRuleIndex)).scalars().all()

    assert status.rule_count == 1
    assert status.indexed_rule_count == 1
    assert status.index_in_sync is True
    assert status.index_last_error is None
    assert len(rows) == 1
    assert rows[0].rule_id == "nginx.version.lt_1_18"
