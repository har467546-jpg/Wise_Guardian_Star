import time

from app.rules.rule_store import RuleNotFoundError, RuleStore


def test_rule_store_create_update_delete_roundtrip(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    created = store.create_rule(
        {
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
            "mitigations": ["upgrade apache"],
        }
    )

    assert created.rule_id == "apache.httpd.lt_2_2_9"
    assert created.name == "Apache legacy exposure"

    updated = store.update_rule(
        "apache.httpd.lt_2_2_9",
        {
            "name": "Apache HTTPD legacy exposure",
            "enabled": False,
            "service": "apache",
            "severity": "medium",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
            "mitigations": ["upgrade apache now"],
        },
    )

    assert updated.name == "Apache HTTPD legacy exposure"
    assert updated.enabled is False
    assert updated.severity == "medium"

    store.delete_rule("apache.httpd.lt_2_2_9")

    assert store.get_rule("apache.httpd.lt_2_2_9") is None


def test_rule_store_bootstrap_is_idempotent(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)
    bootstrap_rules = [
        {
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
            "tags": ["high-value"],
        },
        {
            "id": "nginx.http.autoindex.enabled",
            "name": "Nginx autoindex enabled",
            "enabled": True,
            "service": "nginx",
            "severity": "medium",
            "description": "Autoindex is enabled",
            "match": {"config": {"autoindex": {"eq": "on"}}},
            "tags": ["lab-baseline"],
        },
        {
            "id": "redis.auth.disabled",
            "name": "Redis auth disabled",
            "enabled": True,
            "service": "redis",
            "severity": "high",
            "description": "Redis does not require authentication",
            "match": {"config": {"requirepass": {"exists": False}}},
            "tags": ["lab-baseline"],
        },
    ]

    created_rules, skipped_ids = store.bootstrap_rules(bootstrap_rules)
    created_rules_second, skipped_ids_second = store.bootstrap_rules(bootstrap_rules)

    assert len(created_rules) == 3
    assert skipped_ids == []
    assert created_rules_second == []
    assert len(skipped_ids_second) == 3


def test_rule_store_reuses_cached_rules_until_file_changes(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
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
        encoding="utf-8",
    )
    store = RuleStore(path)

    first = store.get_rule("apache.httpd.lt_2_2_9")
    first_loaded_at = store.loader._rule_set.loaded_at
    second = store.get_rule("apache.httpd.lt_2_2_9")
    second_loaded_at = store.loader._rule_set.loaded_at

    assert first is not None
    assert second is not None
    assert first_loaded_at == second_loaded_at

    time.sleep(0.02)
    path.write_text(
        """rules:
  - id: apache.httpd.lt_2_2_9
    name: Apache legacy exposure updated
    enabled: true
    service: apache
    severity: high
    description: Apache version is older than 2.2.9
    match:
      version: <2.2.9
""",
        encoding="utf-8",
    )

    updated = store.get_rule("apache.httpd.lt_2_2_9")

    assert updated is not None
    assert updated.name == "Apache legacy exposure updated"
    assert store.loader._rule_set.loaded_at != second_loaded_at


def test_rule_store_delete_missing_rule_raises(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    try:
        store.delete_rule("missing")
    except RuleNotFoundError:
        assert True
    else:
        assert False, "expected RuleNotFoundError"


def test_rule_store_import_rules_supports_skip_existing_and_upsert(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
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
        encoding="utf-8",
    )
    store = RuleStore(path)

    skip_result = store.import_rules(
        [
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
                "id": "nginx.http.autoindex.enabled",
                "name": "Nginx autoindex enabled",
                "enabled": True,
                "service": "nginx",
                "severity": "medium",
                "description": "Autoindex is enabled",
                "match": {"config": {"autoindex": {"eq": "on"}}},
            },
        ],
        mode="skip_existing",
    )

    assert skip_result.created_ids == ["nginx.http.autoindex.enabled"]
    assert skip_result.updated_ids == []
    assert skip_result.skipped_ids == ["apache.httpd.lt_2_2_9"]

    upsert_result = store.import_rules(
        [
            {
                "id": "apache.httpd.lt_2_2_9",
                "name": "Apache legacy exposure updated",
                "enabled": False,
                "service": "apache",
                "severity": "medium",
                "description": "Apache version is older than 2.2.9",
                "match": {"version": "<2.2.9"},
            }
        ],
        mode="upsert",
    )

    updated = store.get_rule("apache.httpd.lt_2_2_9")
    assert upsert_result.created_ids == []
    assert upsert_result.updated_ids == ["apache.httpd.lt_2_2_9"]
    assert upsert_result.skipped_ids == []
    assert updated is not None
    assert updated.enabled is False
    assert updated.severity == "medium"


def test_rule_store_set_rules_enabled_updates_only_target_rules(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
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
        encoding="utf-8",
    )
    store = RuleStore(path)

    result = store.set_rules_enabled(
        [
            "apache.httpd.lt_2_2_9",
            "nginx.http.autoindex.enabled",
            "missing.rule",
        ],
        enabled=False,
    )

    apache_rule = store.get_rule("apache.httpd.lt_2_2_9")
    nginx_rule = store.get_rule("nginx.http.autoindex.enabled")
    assert result.updated_ids == ["apache.httpd.lt_2_2_9"]
    assert result.unchanged_ids == ["nginx.http.autoindex.enabled"]
    assert result.missing_ids == ["missing.rule"]
    assert apache_rule is not None and apache_rule.enabled is False
    assert nginx_rule is not None and nginx_rule.enabled is False


def test_rule_store_preserves_nse_match_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    created = store.create_rule(
        {
            "id": "ftp.anonymous.nse.enabled",
            "name": "FTP 匿名访问（NSE）",
            "enabled": True,
            "service": "vsftpd",
            "severity": "high",
            "description": "通过 NSE 识别匿名 FTP",
            "match": {
                "nse": {
                    "ftp-anon.hit": {"eq": True},
                    "ftp-anon.writable_entries": {"contains": "incoming"},
                }
            },
        }
    )

    serialized = store.serialize_rule(created)

    assert created.nse_conditions == {
        "ftp-anon.hit": {"eq": True},
        "ftp-anon.writable_entries": {"contains": "incoming"},
    }
    assert serialized["match"]["nse"]["ftp-anon.hit"]["eq"] is True


def test_rule_store_preserves_package_match_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    created = store.create_rule(
        {
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
                    "fixed_versions": {
                        "ubuntu": {"20.04": "1.8.31-1ubuntu1.2"},
                        "debian": {"11": "1.9.5p2-3+deb11u1"},
                    },
                }
            },
        }
    )

    serialized = store.serialize_rule(created)

    assert created.package_conditions is not None
    assert created.package_conditions.manager == "dpkg"
    assert serialized["match"]["package"]["name"] == "sudo"
    assert serialized["match"]["package"]["fixed_versions"]["debian"]["11"] == "1.9.5p2-3+deb11u1"


def test_rule_store_preserves_explicit_remediation(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    created = store.create_rule(
        {
            "id": "nginx.version.lt_1_18",
            "name": "nginx legacy exposure",
            "enabled": True,
            "service": "nginx",
            "severity": "high",
            "description": "nginx version is older than 1.18",
            "match": {"version": "<1.18"},
            "remediation": {
                "summary": "升级 nginx 并重载服务",
                "automation_level": "callable",
                "actions": [
                    {
                        "action_type": "upgrade_package",
                        "title": "升级 nginx",
                        "params": {"package_name": "nginx"},
                    }
                ],
            },
        }
    )

    serialized = store.serialize_rule(created)

    assert created.remediation is not None
    assert serialized["remediation"]["summary"] == "升级 nginx 并重载服务"
    assert serialized["remediation"]["actions"][0]["action_type"] == "upgrade_package"


def test_rule_store_can_serialize_resolved_remediation_for_legacy_rules(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    created = store.create_rule(
        {
            "id": "apache.httpd.lt_2_2_9",
            "name": "Apache legacy exposure",
            "enabled": True,
            "service": "apache",
            "severity": "high",
            "description": "Apache version is older than 2.2.9",
            "match": {"version": "<2.2.9"},
            "mitigations": ["upgrade apache"],
        }
    )

    serialized = store.serialize_rule(created)

    assert "remediation" in serialized
    assert serialized["remediation"]["actions"][0]["action_type"] == "upgrade_package"


def test_rule_store_writes_unicode_text_without_yaml_escape_sequences(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text("rules: []\n", encoding="utf-8")
    store = RuleStore(path)

    store.create_rule(
        {
            "id": "ssh.permit_empty_passwords.enabled",
            "name": "SSH 允许空密码",
            "enabled": True,
            "service": "ssh",
            "severity": "high",
            "description": "检查管理后台用户配置",
            "match": {"config": {"permit_empty_passwords": {"eq": True}}},
            "verify_playbook": ["确认默认凭据已移除且管理路径已受限"],
        }
    )

    content = path.read_text(encoding="utf-8")

    assert "SSH 允许空密码" in content
    assert "检查管理后台用户配置" in content
    assert "确认默认凭据已移除且管理路径已受限" in content
    assert "\\u68C0\\u67E5" not in content
