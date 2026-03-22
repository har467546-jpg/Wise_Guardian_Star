from datetime import datetime, timezone

from app.ai.risk_summary import RiskSummaryService
from app.db.models.asset import Asset, AssetPort
from app.db.models.enums import FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding
from app.db.models.snapshot import HostSnapshot


def _finding(severity: RiskSeverity, description: str, port: int = 22):
    return RiskFinding(
        severity=severity,
        status=FindingStatus.OPEN,
        description=description,
        title=description,
        evidence_json={"rule_id": "ssh.password_login.enabled", "service_name": "ssh", "port": port},
    )


def test_usage_hypothesis_identifies_web_node() -> None:
    service = RiskSummaryService()
    asset = Asset(id="asset-1", ip="10.0.0.10", hostname="web-01", os_name="Ubuntu")
    asset.ports = [
        AssetPort(port=80, protocol="tcp", service_name="http", service_version="nginx/1.17.10", state="open"),
        AssetPort(port=443, protocol="tcp", service_name="https", service_version="nginx/1.17.10", state="open"),
    ]
    asset.findings = []
    asset.snapshots = []

    usage = service._usage_hypothesis(asset)

    assert usage["purpose"] == "Web service node"
    assert usage["confidence"] in {"high", "medium"}


def test_priority_scoring_and_asset_summary() -> None:
    service = RiskSummaryService()
    asset = Asset(id="asset-2", ip="10.0.0.20", hostname="db-01", os_name="Rocky")
    asset.ports = [AssetPort(port=22, protocol="tcp", service_name="ssh", service_version="OpenSSH_7.4", state="open")]
    asset.findings = [
        _finding(RiskSeverity.HIGH, "ssh password login is enabled"),
        _finding(RiskSeverity.MEDIUM, "old ssh version"),
    ]
    asset.snapshots = [HostSnapshot(asset_id="asset-2", collected_at=datetime.now(timezone.utc))]

    analysis = service._asset_analysis(service._build_asset_context(asset))

    assert analysis["risk_summary"]["highest_severity"] == "high"
    assert analysis["risk_priority"]["level"] == "P2"
    assert analysis["risk_priority"]["score"] == 50
    assert analysis["recommendations"]
