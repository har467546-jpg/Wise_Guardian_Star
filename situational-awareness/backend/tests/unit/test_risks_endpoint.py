from types import SimpleNamespace
from uuid import uuid4

from fastapi.testclient import TestClient

from app.api.deps import get_current_user
from app.api.v1.endpoints import risks
from app.db.base import Base
from app.db.models.asset import Asset, AssetPort
from app.db.models.enums import AssetStatus, FindingStatus, RiskSeverity, UserRole
from app.db.models.risk_finding import RiskFinding
from app.db.session import SessionLocal, engine
from app.main import create_app
from app.rules.rule_store import RuleStore


def _override_user(role: UserRole):
    def _resolver():
        return SimpleNamespace(id="user-1", role=role, is_active=True)

    return _resolver


def _unique_ip() -> str:
    seed = uuid4().int
    octet_3 = (seed // 256) % 250 + 1
    octet_4 = seed % 250 + 1
    return f"10.250.{octet_3}.{octet_4}"


def _build_client(tmp_path, rule_content: str) -> TestClient:
    Base.metadata.create_all(bind=engine)
    rule_path = tmp_path / "risk_rules.yaml"
    rule_path.write_text(rule_content, encoding="utf-8")
    risks.RULE_STORE = RuleStore(rule_path)

    app = create_app()
    app.dependency_overrides[get_current_user] = _override_user(UserRole.ADMIN)
    return TestClient(app)


def _create_finding(*, evidence_json: dict, service_name: str = "apache", service_version: str = "2.2.8", port: int = 80) -> RiskFinding:
    asset = Asset(id=str(uuid4()), ip=_unique_ip(), status=AssetStatus.ONLINE)
    asset_port = AssetPort(
        id=str(uuid4()),
        asset_id=asset.id,
        port=port,
        protocol="tcp",
        service_name=service_name,
        service_version=service_version,
        fingerprint_json={},
        state="open",
    )
    finding = RiskFinding(
        id=str(uuid4()),
        asset_id=asset.id,
        asset_port_id=asset_port.id,
        severity=RiskSeverity.HIGH,
        status=FindingStatus.OPEN,
        title="测试风险",
        description="测试风险描述",
        evidence_json=evidence_json,
    )
    with SessionLocal() as db:
        db.add(asset)
        db.add(asset_port)
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding


def test_risk_remediation_template_endpoint_renders_rule_context(tmp_path) -> None:
    client = _build_client(
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
    remediation:
      summary: 升级 {{ service_name }} 并在 {{ port }} 端口复测
      automation_level: callable
      impact_summary: 可能触发 apache 短暂重载
      precheck_items:
        - 确认配置文件已备份
      verify_items:
        - 确认 80 端口响应恢复正常
      rollback_notes:
        - 保留升级前软件包版本用于回滚
      actions:
        - action_type: upgrade_package
          title: 升级 {{ service_name }}
          params:
            package_name: "{{ service_name }}"
            port: "{{ port }}"
          target_services:
            - apache
          verify_items:
            - 确认 apache 已升级到安全版本
""",
    )
    finding = _create_finding(
        evidence_json={
            "yaml_rule_id": "apache.httpd.lt_2_2_9",
            "service_name": "apache",
            "service_version": "2.2.8",
            "port": 80,
        }
    )

    response = client.get(f"/api/v1/risks/{finding.id}/remediation-template")

    assert response.status_code == 200
    body = response.json()
    assert body["rule_id"] == "apache.httpd.lt_2_2_9"
    assert body["summary"] == "升级 apache 并在 80 端口复测"
    assert body["impact_summary"] == "可能触发 apache 短暂重载"
    assert body["precheck_items"] == ["确认配置文件已备份"]
    assert body["verify_items"] == ["确认 80 端口响应恢复正常"]
    assert body["rollback_notes"] == ["保留升级前软件包版本用于回滚"]
    assert body["actions"][0]["title"] == "升级 apache"
    assert body["actions"][0]["params"]["port"] == 80
    assert body["actions"][0]["target_services"] == ["apache"]
    assert body["actions"][0]["verify_items"] == ["确认 apache 已升级到安全版本"]
    assert body["source_refs"]["generated"] is False


def test_risk_remediation_template_endpoint_generates_fallback_for_legacy_rule(tmp_path) -> None:
    client = _build_client(
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
    finding = _create_finding(
        evidence_json={
            "yaml_rule_id": "apache.httpd.lt_2_2_9",
            "service_name": "apache",
            "service_version": "2.2.8",
            "port": 80,
        }
    )

    response = client.get(f"/api/v1/risks/{finding.id}/remediation-template")

    assert response.status_code == 200
    body = response.json()
    assert body["source_refs"]["generated"] is True
    assert body["automation_level"] == "callable"
    assert body["actions"][0]["action_type"] == "upgrade_package"
    assert body["impact_summary"]
    assert body["precheck_items"]
    assert body["verify_items"]
    assert body["rollback_notes"]


def test_risk_remediation_template_endpoint_rejects_finding_without_yaml_rule(tmp_path) -> None:
    client = _build_client(tmp_path, "rules: []\n")
    finding = _create_finding(evidence_json={"service_name": "apache"})

    response = client.get(f"/api/v1/risks/{finding.id}/remediation-template")

    assert response.status_code == 404
    assert response.json()["detail"] == "风险发现未关联 YAML 规则"
