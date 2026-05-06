from datetime import datetime, timezone

from app.ai.report_renderer import VulnerabilityReportRenderer
from app.db.models.enums import ReportScope


def test_report_renderer_outputs_fixed_html_sections() -> None:
    renderer = VulnerabilityReportRenderer()
    filename, html = renderer.render_html(
        scope=ReportScope.ASSET,
        scope_id="asset-1",
        report_id="report-1",
        created_at=datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc),
        analysis={
            "asset": {
                "id": "asset-1",
                "ip": "10.0.0.10",
                "hostname": "web-01",
                "os_name": "Ubuntu 22.04",
                "status": "online",
            },
            "services": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "service_name": "nginx",
                    "service_version": "1.16.1",
                    "state": "open",
                    "fingerprint_json": {},
                }
            ],
            "findings": [
                {
                    "id": "finding-1",
                    "asset_id": "asset-1",
                    "yaml_rule_id": "apache.httpd.path_traversal.2_4_49",
                    "severity": "high",
                    "status": "open",
                    "title": "Apache HTTPD 2.4.49 路径穿越风险",
                    "description": "HTTP 服务存在路径穿越风险。",
                    "port": 80,
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_version": "Apache 2.4.49",
                    "verification_status": "confirmed",
                    "match_source": "active",
                    "evidence_scope": "network",
                    "evidence_json": {"nse_scripts": ["http-enum"]},
                }
            ],
            "risk_summary": {
                "highest_severity": "high",
                "open_findings": 1,
                "severity_counts": {"low": 0, "medium": 0, "high": 1, "critical": 0},
            },
            "risk_priority": {"level": "P2", "score": 40, "reasons": ["1 high findings"]},
            "recommendations": [
                {
                    "id": "rec-nginx-upgrade",
                    "priority": "high",
                    "target": "nginx",
                    "action": "Upgrade nginx",
                    "rationale": "Reduce exposure",
                }
            ],
            "usage_hypothesis": {"purpose": "Web service node", "confidence": "high", "evidence": ["port 80 exposed"]},
        },
    )

    assert filename.endswith(".html")
    assert "1 检测结果综述" in html
    assert "2.1 资产基本信息" in html
    assert "5.2 WEB漏洞详情" in html
    assert "7.2 资产风险等级评定标准" in html
    assert 'href="#section-5-2"' in html
    assert "下载 PDF 报告" not in html


def test_report_renderer_keeps_empty_sections_for_missing_categories() -> None:
    renderer = VulnerabilityReportRenderer()
    _, html = renderer.render_html(
        scope=ReportScope.ASSET,
        scope_id="asset-empty",
        report_id="report-empty",
        created_at=datetime(2026, 4, 22, 12, 0, tzinfo=timezone.utc),
        analysis={
            "asset": {"id": "asset-empty", "ip": "10.0.0.11", "hostname": "", "os_name": "", "status": "unknown"},
            "services": [],
            "findings": [],
            "risk_summary": {
                "highest_severity": None,
                "open_findings": 0,
                "severity_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0},
            },
            "risk_priority": {"level": "P5", "score": 0, "reasons": ["no open findings detected"]},
            "recommendations": [],
            "usage_hypothesis": {"purpose": "Unknown asset role", "confidence": "low", "evidence": []},
        },
    )

    assert 'id="section-6"' in html
    assert 'id="section-7-1"' in html
    assert 'id="section-8"' in html
