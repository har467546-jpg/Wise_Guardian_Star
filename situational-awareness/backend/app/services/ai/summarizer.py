from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.risk_finding import RiskFinding
from app.services.ai.gateway import LLMGateway


class RiskSummarizer:
    def __init__(self, gateway: LLMGateway | None = None) -> None:
        self.gateway = gateway or LLMGateway()

    def summarize_job(self, db: Session, job_id: str) -> tuple[str, dict]:
        severity_count = {}
        rows = db.execute(
            select(RiskFinding.severity, func.count(RiskFinding.id)).group_by(RiskFinding.severity)
        ).all()
        for severity, count in rows:
            severity_count[severity.value] = count

        prompt = (
            f"Job {job_id} risk overview:\n"
            f"- low: {severity_count.get('low', 0)}\n"
            f"- medium: {severity_count.get('medium', 0)}\n"
            f"- high: {severity_count.get('high', 0)}\n"
            f"- critical: {severity_count.get('critical', 0)}\n"
            "请给出风险摘要与优先处置建议。"
        )
        summary = self.gateway.summarize(prompt)
        return summary, severity_count
