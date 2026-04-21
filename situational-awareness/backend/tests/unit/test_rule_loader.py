import time
from pathlib import Path

from app.rules.rule_loader import RuleLoader


VALID_RULES = """
rules:
  - id: nginx.version.lt_1_18
    name: nginx legacy exposure
    enabled: true
    service: nginx
    severity: high
    description: nginx version is older than 1.18
    match:
      version: "<1.18"
    cve_ids:
      - CVE-2021-23017
    mitigations:
      - upgrade nginx
"""


INVALID_RULES = """
rules:
  - id: duplicate
    enabled: true
    service: ssh
    severity: medium
    description: test
    match:
      config:
        password_authentication:
          unknown: true
"""


BAD_YAML = "rules: ["
INVALID_VERSION_RULES = """
rules:
  - id: invalid.version
    enabled: true
    service: nginx
    severity: high
    description: invalid version rule
    match:
      version: "legacy"
"""
INVALID_PACKAGE_RULES = """
rules:
  - id: invalid.package
    enabled: true
    service: sudo
    severity: high
    description: invalid package rule
    match:
      package:
        manager: dpkg
        name: sudo
        compare: gte_fixed
        fixed_versions:
          ubuntu:
            "20.04": 1.8.31-1ubuntu1.2
"""
VALID_REMEDIATION_RULES = """
rules:
  - id: nginx.version.lt_1_18
    name: nginx legacy exposure
    enabled: true
    service: nginx
    severity: high
    description: nginx version is older than 1.18
    match:
      version: "<1.18"
    remediation:
      summary: 升级 nginx 并重载服务
      automation_level: callable
      impact_summary: 可能影响 nginx 短暂重载
      precheck_items:
        - 确认配置已备份
      verify_items:
        - 确认健康检查通过
      rollback_notes:
        - 保留升级前版本用于回滚
      actions:
        - action_type: upgrade_package
          title: 升级 nginx
          params:
            package_name: nginx
          target_services:
            - nginx
          verify_items:
            - 确认软件包已升级
        - action_type: reload_service
          title: 重载 nginx
          params:
            service_name: nginx
"""
INVALID_REMEDIATION_RULES = """
rules:
  - id: invalid.remediation
    enabled: true
    service: nginx
    severity: high
    description: invalid remediation rule
    match:
      version: "<1.18"
    remediation:
      summary: bad remediation
      automation_level: callable
      actions:
        - action_type: run_shell
          title: invalid
          params: {}
"""


def test_rule_loader_loads_valid_yaml(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(VALID_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert len(ruleset.rules) == 1
    assert ruleset.rules[0].rule_id == "nginx.version.lt_1_18"
    assert ruleset.rules[0].name == "nginx legacy exposure"
    assert ruleset.rules[0].cve_ids == ["CVE-2021-23017"]
    assert ruleset.rules[0].mitigations == ["upgrade nginx"]
    assert ruleset.last_error is None


def test_rule_loader_preserves_previous_rules_when_reload_fails(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(VALID_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    first = loader.load(force=True)
    assert len(first.rules) == 1

    time.sleep(1.1)
    path.write_text(BAD_YAML, encoding="utf-8")

    second = loader.maybe_reload()
    assert len(second.rules) == 1
    assert second.last_error is not None


def test_rule_loader_rejects_unsupported_config_operator(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(INVALID_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.rules == []
    assert "不支持的 config 操作符" in (ruleset.last_error or "")


def test_rule_loader_rejects_invalid_version_specifier(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(INVALID_VERSION_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.rules == []
    assert "版本约束无效" in (ruleset.last_error or "")


def test_rule_loader_loads_project_risk_rules_with_active_checks() -> None:
    path = Path(__file__).resolve().parents[2] / "app" / "rules" / "risk_rules.yaml"

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)
    rules_by_id = {rule.rule_id: rule for rule in ruleset.rules}

    assert ruleset.last_error is None
    assert "apache.directory_listing.enabled" in rules_by_id
    assert "redis.bind_all_interfaces.enabled" in rules_by_id
    assert "postgresql.listen_all_interfaces.enabled" in rules_by_id
    assert "ftp.vsftpd_backdoor.nse.confirmed" in rules_by_id
    assert "php.cgi.cve_2012_1823.apache" in rules_by_id
    assert "tls.heartbleed.https" in rules_by_id
    assert "redis.unauthorized.info.confirmed" in rules_by_id
    assert "struts2.cve_2017_5638.tomcat" in rules_by_id
    assert "phpmyadmin.path.exposed.apache" in rules_by_id
    assert "twiki.path.exposed.twiki" in rules_by_id
    assert rules_by_id["vsftpd.backdoor.2_3_4"].active_check is not None
    assert rules_by_id["vsftpd.backdoor.2_3_4"].active_check.detector == "vsftpd_smiley_backdoor"
    assert rules_by_id["ftp.anonymous.enabled"].active_check is not None
    assert rules_by_id["ftp.anonymous.enabled"].active_check.trigger == "on_service_present"
    assert rules_by_id["tomcat.manager.default_creds"].active_check is not None
    assert rules_by_id["tomcat.manager.default_creds"].active_check.params["paths"] == ["/manager/html", "/manager/status"]
    assert rules_by_id["redis.unauthorized.info.confirmed"].active_check is not None
    assert rules_by_id["redis.unauthorized.info.confirmed"].active_check.detector == "redis_unauth_info_probe"
    assert rules_by_id["apache.webdav.risky_methods.confirmed"].active_check is not None
    assert rules_by_id["apache.webdav.risky_methods.confirmed"].active_check.detector == "http_risky_methods_probe"
    assert rules_by_id["ftp.vsftpd_backdoor.nse.confirmed"].nse_conditions == {
        "ftp-vsftpd-backdoor.vulnerable": {"eq": True}
    }
    assert rules_by_id["tls.heartbleed.https"].nse_conditions == {
        "ssl-heartbleed.vulnerable": {"eq": True}
    }
    assert rules_by_id["struts2.cve_2017_5638.tomcat"].nse_conditions == {
        "http-vuln-cve2017-5638.vulnerable": {"eq": True}
    }


def test_rule_loader_project_rules_use_v2_remediation_shape() -> None:
    path = Path(__file__).resolve().parents[2] / "app" / "rules" / "risk_rules.yaml"

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert len(ruleset.rules) == 129
    assert all(rule.remediation is not None for rule in ruleset.rules)
    assert all(rule.remediation and rule.remediation.impact_summary for rule in ruleset.rules)
    assert all(rule.remediation and rule.remediation.precheck_items for rule in ruleset.rules)
    assert all(rule.remediation and rule.remediation.verify_items for rule in ruleset.rules)
    assert all(rule.remediation and rule.remediation.rollback_notes for rule in ruleset.rules)
    assert all(
        rule.remediation
        and all(action.verify_items for action in rule.remediation.actions)
        for rule in ruleset.rules
    )
    assert all(
        rule.remediation
        and all(
            action.target_files or action.target_services or action.target_paths
            for action in rule.remediation.actions
        )
        for rule in ruleset.rules
    )
    canonical_action_count = sum(
        1
        for rule in ruleset.rules
        if rule.remediation is not None
        for action in rule.remediation.actions
        if action.action_type in {"toggle_feature", "set_bind_scope", "set_access_policy", "remove_path", "set_path_permission"}
    )
    assert canonical_action_count >= 100


def test_rule_loader_accepts_nse_match_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ftp.anonymous.nse.enabled
    name: FTP anonymous enabled via NSE
    enabled: true
    service: vsftpd
    severity: high
    description: ftp anon
    match:
      nse:
        ftp-anon.hit:
          eq: true
        http-methods.risky_methods:
          contains: PUT
""",
        encoding="utf-8",
    )

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].nse_conditions == {
        "ftp-anon.hit": {"eq": True},
        "http-methods.risky_methods": {"contains": "PUT"},
    }


def test_rule_loader_accepts_package_match_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: sudo.baron_samedit.cve_2021_3156.exposed
    name: Sudo Baron Samedit
    enabled: true
    service: sudo
    severity: critical
    description: sudo vulnerable package
    match:
      package:
        manager: dpkg
        name: sudo
        compare: lt_fixed
        fixed_versions:
          ubuntu:
            "20.04": "1.8.31-1ubuntu1.2"
          debian:
            "11": "1.9.5p2-3+deb11u1"
""",
        encoding="utf-8",
    )

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].package_conditions is not None
    assert ruleset.rules[0].package_conditions.name == "sudo"
    assert ruleset.rules[0].package_conditions.fixed_versions["ubuntu"]["20.04"] == "1.8.31-1ubuntu1.2"


def test_rule_loader_accepts_rpm_package_match_conditions(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: ssh.openssh.rpm.outdated
    name: OpenSSH RPM outdated
    enabled: true
    service: ssh
    severity: high
    description: openssh rpm vulnerable
    match:
      package:
        manager: dnf
        name: openssh-server
        compare: lt_fixed
        fixed_versions:
          Rocky Linux:
            "9": "1:8.7p1-40.el9"
""",
        encoding="utf-8",
    )

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].package_conditions is not None
    assert ruleset.rules[0].package_conditions.manager == "rpm"
    assert ruleset.rules[0].package_conditions.fixed_versions["rocky"]["9"] == "1:8.7p1-40.el9"


def test_rule_loader_accepts_remediation_definition(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(VALID_REMEDIATION_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].remediation is not None
    assert ruleset.rules[0].remediation.summary == "升级 nginx 并重载服务"
    assert ruleset.rules[0].remediation.impact_summary == "可能影响 nginx 短暂重载"
    assert ruleset.rules[0].remediation.precheck_items == ["确认配置已备份"]
    assert ruleset.rules[0].remediation.actions[0].action_type == "upgrade_package"
    assert ruleset.rules[0].remediation.actions[0].target_services == ["nginx"]


def test_rule_loader_accepts_new_canonical_remediation_action_types(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: tomcat.manager.exposed
    enabled: true
    service: tomcat
    severity: high
    description: manager exposed
    match:
      nse:
        http-title.title:
          contains: Tomcat
    remediation:
      summary: 下线 tomcat manager
      automation_level: callable
      actions:
        - action_type: remove_path
          title: 移除 manager 暴露路径
          params:
            service_name: tomcat
            rule_id: tomcat.manager.exposed
          target_paths:
            - /manager
        - action_type: set_bind_scope
          title: 收敛监听来源
          params:
            service_name: tomcat
            target_scope: admin_segment_only
""",
        encoding="utf-8",
    )

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].remediation is not None
    assert ruleset.rules[0].remediation.actions[0].action_type == "remove_path"
    assert ruleset.rules[0].remediation.actions[1].action_type == "set_bind_scope"


def test_rule_loader_rejects_invalid_remediation_action_type(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(INVALID_REMEDIATION_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.rules == []
    assert "remediation.actions[1].action_type 不受支持" in (ruleset.last_error or "")


def test_rule_loader_decodes_literal_unicode_escape_sequences_in_text_fields(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(
        """rules:
  - id: tomcat.manager.default_creds
    name: Tomcat 管理后台默认凭据风险
    enabled: true
    service: tomcat
    severity: critical
    description: Tomcat \\u7BA1\\u7406\\u540E\\u53F0\\u82E5\\u4FDD\\u7559\\u9ED8\\u8BA4\\u51ED\\u636E
    match:
      config:
        default_credentials:
          eq: true
    verify_playbook:
      - \\u68C0\\u67E5\\u7BA1\\u7406\\u540E\\u53F0\\u7528\\u6237\\u914D\\u7F6E
    mitigations:
      - \\u79FB\\u9664\\u9ED8\\u8BA4\\u51ED\\u636E
""",
        encoding="utf-8",
    )

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.last_error is None
    assert ruleset.rules[0].description == "Tomcat 管理后台若保留默认凭据"
    assert ruleset.rules[0].verify_playbook == ["检查管理后台用户配置"]
    assert ruleset.rules[0].mitigations == ["移除默认凭据"]


def test_rule_loader_rejects_invalid_package_compare(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(INVALID_PACKAGE_RULES, encoding="utf-8")

    loader = RuleLoader(path)
    ruleset = loader.load(force=True)

    assert ruleset.rules == []
    assert "match.package.compare 不受支持" in (ruleset.last_error or "")
