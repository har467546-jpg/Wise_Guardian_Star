from app.ai.report_generator import ReportGenerator


def test_report_generator_builds_asset_markdown() -> None:
    generator = ReportGenerator()
    analysis = {
        "asset": {"id": "asset-1", "ip": "10.0.0.10", "hostname": "web-01", "os_name": "Ubuntu"},
        "services": [{"port": 80, "service_name": "http", "service_version": "nginx/1.17.10", "state": "open"}],
        "risk_summary": {
            "highest_severity": "high",
            "open_findings": 1,
            "severity_counts": {"low": 0, "medium": 0, "high": 1, "critical": 0},
            "key_findings": ["nginx version is older than 1.18"],
        },
        "risk_priority": {"level": "P2", "score": 40, "reasons": ["1 high findings"]},
        "recommendations": [{"id": "rec-nginx-upgrade", "priority": "high", "target": "nginx", "action": "Upgrade nginx", "rationale": "Reduce risk"}],
        "usage_hypothesis": {"purpose": "Web service node", "confidence": "high", "evidence": ["ports 80 exposed"]},
    }

    analysis_json, overview, markdown = generator.build_asset_report(analysis)

    assert analysis_json["asset"]["ip"] == "10.0.0.10"
    assert overview["high"] == 1
    assert "## 风险总结" in markdown
    assert "## 修复建议" in markdown


def test_report_generator_builds_job_markdown() -> None:
    generator = ReportGenerator()
    analysis = {
        "job": {"id": "job-1", "cidr": "10.0.0.0/24", "label": "test", "asset_count": 2},
        "risk_summary": {
            "highest_severity": "critical",
            "total_findings": 2,
            "severity_counts": {"low": 0, "medium": 0, "high": 1, "critical": 1},
            "top_assets": [{"ip": "10.0.0.10", "hostname": "db-01", "priority": "P1", "score": 140, "highest_severity": "critical", "open_findings": 2}],
        },
        "risk_priority": {"level": "P1", "score": 140, "reasons": ["1 critical findings"]},
        "recommendations": [],
        "asset_summaries": [],
    }

    _, overview, markdown = generator.build_job_report(analysis)

    assert overview["critical"] == 1
    assert "## 重点资产" in markdown
