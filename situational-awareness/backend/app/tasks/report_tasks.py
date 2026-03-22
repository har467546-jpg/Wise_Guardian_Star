from celery import Task

from app.ai.report_generator import ReportGenerator
from app.ai.risk_summary import RiskSummaryService
from app.core.celery_app import celery_app
from app.db.models.report import AIReport
from app.db.models.enums import ReportScope
from app.db.session import SessionLocal
from app.tasks.task_runtime import (
    TaskCanceledError,
    ensure_task_not_canceled,
    set_task_failure,
    set_task_progress,
    set_task_retry,
    set_task_success,
    tracked_task,
)


@celery_app.task(bind=True, name="app.tasks.report_tasks.generate_job_report", max_retries=3)
def generate_job_report(self: Task, job_id: str, task_run_id: str | None = None) -> str:
    try:
        if task_run_id:
            with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
                ensure_task_not_canceled(task_run_id)
                set_task_progress(task_run_id, 20, "正在生成任务报告", {"job_id": job_id}, stage_code="generate_report", stage_name="报告生成")
                report_id = _create_job_report(job_id)
                ensure_task_not_canceled(task_run_id)
                set_task_success(task_run_id, "任务报告已生成", {"job_id": job_id, "report_id": report_id})
                return report_id
        return _create_job_report(job_id)
    except TaskCanceledError:
        return task_run_id or job_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            if task_run_id:
                set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        if task_run_id:
            set_task_failure(task_run_id, self.request.retries, str(exc))
        raise


@celery_app.task(bind=True, name="app.tasks.report_tasks.generate_asset_report", max_retries=3)
def generate_asset_report(self: Task, asset_id: str, task_run_id: str | None = None) -> str:
    try:
        if task_run_id:
            with tracked_task(task_run_id, celery_task_id=self.request.id, retry_count=self.request.retries):
                ensure_task_not_canceled(task_run_id)
                set_task_progress(task_run_id, 20, "正在生成资产报告", {"asset_id": asset_id}, stage_code="generate_report", stage_name="报告生成")
                report_id = _create_asset_report(asset_id)
                ensure_task_not_canceled(task_run_id)
                set_task_success(task_run_id, "资产报告已生成", {"asset_id": asset_id, "report_id": report_id})
                return report_id
        return _create_asset_report(asset_id)
    except TaskCanceledError:
        return task_run_id or asset_id
    except Exception as exc:
        if self.request.retries < self.max_retries:
            if task_run_id:
                set_task_retry(task_run_id, self.request.retries + 1, str(exc))
            raise self.retry(exc=exc, countdown=2 ** (self.request.retries + 1))
        if task_run_id:
            set_task_failure(task_run_id, self.request.retries, str(exc))
        raise


def _create_job_report(job_id: str) -> str:
    with SessionLocal() as db:
        analysis = RiskSummaryService().summarize_job(db, job_id)
        analysis_json, overview, summary_md = ReportGenerator().build_job_report(analysis)

        report = AIReport(
            scope=ReportScope.JOB,
            scope_id=job_id,
            summary_md=summary_md,
            risk_overview_json=overview,
            analysis_json=analysis_json,
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report.id


def _create_asset_report(asset_id: str) -> str:
    with SessionLocal() as db:
        analysis = RiskSummaryService().summarize_asset(db, asset_id)
        analysis_json, overview, summary_md = ReportGenerator().build_asset_report(analysis)

        report = AIReport(
            scope=ReportScope.ASSET,
            scope_id=asset_id,
            summary_md=summary_md,
            risk_overview_json=overview,
            analysis_json=analysis_json,
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report.id
