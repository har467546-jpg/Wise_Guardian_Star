from app.db.models.enums import ReportScope
from app.tasks import report_tasks


class _FakeDB:
    def __init__(self) -> None:
        self.added = []
        self.committed = False
        self.refreshed = False

    def add(self, item):
        item.id = "report-1"
        self.added.append(item)

    def commit(self):
        self.committed = True

    def refresh(self, item):
        self.refreshed = True


class _FakeSessionLocal:
    def __init__(self, db):
        self.db = db

    def __call__(self):
        return self

    def __enter__(self):
        return self.db

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeSummary:
    def summarize_job(self, db, job_id):
        return {"job": {"id": job_id}, "risk_summary": {"severity_counts": {"low": 0, "medium": 0, "high": 1, "critical": 0}}, "risk_priority": {"level": "P2", "score": 40, "reasons": []}, "recommendations": [], "asset_summaries": []}

    def summarize_asset(self, db, asset_id):
        return {"asset": {"id": asset_id, "ip": "10.0.0.10", "hostname": None, "os_name": None}, "services": [], "risk_summary": {"highest_severity": None, "open_findings": 0, "severity_counts": {"low": 0, "medium": 0, "high": 0, "critical": 0}, "key_findings": []}, "risk_priority": {"level": "P5", "score": 0, "reasons": []}, "recommendations": [], "usage_hypothesis": {"purpose": "Unknown asset role", "confidence": "low", "evidence": []}}


class _FakeGenerator:
    def build_job_report(self, analysis):
        return analysis, analysis["risk_summary"]["severity_counts"], "# job"

    def build_asset_report(self, analysis):
        return analysis, analysis["risk_summary"]["severity_counts"], "# asset"


def test_generate_job_report_persists_analysis(monkeypatch) -> None:
    db = _FakeDB()
    monkeypatch.setattr(report_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(report_tasks, "RiskSummaryService", lambda: _FakeSummary())
    monkeypatch.setattr(report_tasks, "ReportGenerator", lambda: _FakeGenerator())

    report_id = report_tasks.generate_job_report("job-1")

    assert report_id == "report-1"
    assert db.committed is True
    assert db.added[0].scope == ReportScope.JOB
    assert db.added[0].analysis_json["job"]["id"] == "job-1"


def test_generate_asset_report_persists_analysis(monkeypatch) -> None:
    db = _FakeDB()
    monkeypatch.setattr(report_tasks, "SessionLocal", _FakeSessionLocal(db))
    monkeypatch.setattr(report_tasks, "RiskSummaryService", lambda: _FakeSummary())
    monkeypatch.setattr(report_tasks, "ReportGenerator", lambda: _FakeGenerator())

    report_id = report_tasks.generate_asset_report("asset-1")

    assert report_id == "report-1"
    assert db.added[0].scope == ReportScope.ASSET
    assert db.added[0].summary_md == "# asset"
