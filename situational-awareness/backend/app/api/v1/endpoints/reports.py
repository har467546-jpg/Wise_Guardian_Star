from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.ai.report_renderer import VulnerabilityReportRenderer
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import ReportScope, TaskExecutionStatus, TaskType
from app.db.models.report import AIReport
from app.db.models.task_run import TaskRun
from app.db.models.user import User
from app.repositories.task_repo import create_task_run, update_task_run
from app.schemas.report import GenerateReportResponse, ReportRead
from app.tasks.report_tasks import generate_asset_report, generate_job_report

router = APIRouter()


def _latest_report(db: Session, *, scope: ReportScope, scope_id: str) -> AIReport | None:
    return db.scalars(
        select(AIReport)
        .where(AIReport.scope == scope, AIReport.scope_id == scope_id)
        .order_by(AIReport.created_at.desc())
        .limit(1)
    ).first()


def _latest_successful_report_task_id(db: Session, *, scope: ReportScope, scope_id: str) -> str | None:
    scope_type = "asset" if scope == ReportScope.ASSET else "job"
    task = db.scalars(
        select(TaskRun)
        .where(
            TaskRun.task_type == TaskType.REPORT_GENERATE,
            TaskRun.scope_type == scope_type,
            TaskRun.scope_id == scope_id,
            TaskRun.status == TaskExecutionStatus.SUCCESS,
        )
        .order_by(TaskRun.created_at.desc())
        .limit(1)
    ).first()
    return task.id if task else None


@router.post("/jobs/{job_id}/generate", response_model=GenerateReportResponse, status_code=status.HTTP_202_ACCEPTED)
def generate_job_scope_report(
    job_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> GenerateReportResponse:
    if not db.get(DiscoveryJob, job_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="发现任务不存在")
    task_run = create_task_run(db, task_type=TaskType.REPORT_GENERATE, scope_type="job", scope_id=job_id, message="任务报告已入队")
    task = generate_job_report.delay(job_id, task_run.id)
    update_task_run(db, task_run, celery_task_id=task.id)
    return GenerateReportResponse(task_id=task_run.id, status="pending")


@router.post("/assets/{asset_id}/generate", response_model=GenerateReportResponse, status_code=status.HTTP_202_ACCEPTED)
def generate_asset_scope_report(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> GenerateReportResponse:
    if not db.get(Asset, asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    task_run = create_task_run(db, task_type=TaskType.REPORT_GENERATE, scope_type="asset", scope_id=asset_id, message="资产报告已入队")
    task = generate_asset_report.delay(asset_id, task_run.id)
    update_task_run(db, task_run, celery_task_id=task.id)
    return GenerateReportResponse(task_id=task_run.id, status="pending")


@router.get("/jobs/{job_id}/latest", response_model=ReportRead)
def get_latest_job_report(
    job_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> ReportRead:
    if not db.get(DiscoveryJob, job_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="发现任务不存在")
    report = _latest_report(db, scope=ReportScope.JOB, scope_id=job_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    return ReportRead.model_validate(report)


@router.get("/assets/{asset_id}/latest", response_model=ReportRead)
def get_latest_asset_report(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> ReportRead:
    if not db.get(Asset, asset_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    report = _latest_report(db, scope=ReportScope.ASSET, scope_id=asset_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    return ReportRead.model_validate(report)


@router.get("/{report_id}", response_model=ReportRead)
def get_report(
    report_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> ReportRead:
    report = db.get(AIReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    return ReportRead.model_validate(report)


@router.get("/{report_id}/download/html", response_class=HTMLResponse)
def download_report_html(
    report_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> HTMLResponse:
    report = db.get(AIReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    analysis = dict(report.analysis_json) if isinstance(report.analysis_json, dict) else {}
    report_task_id = _latest_successful_report_task_id(db, scope=report.scope, scope_id=report.scope_id)
    if report.scope == ReportScope.JOB and report_task_id:
        analysis.setdefault("task_id", report_task_id)
    filename, html = VulnerabilityReportRenderer().render_html(
        scope=report.scope,
        scope_id=report.scope_id,
        analysis=analysis,
        report_id=report.id,
        created_at=report.created_at,
    )
    return HTMLResponse(
        content=html,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{report_id}/download/pdf")
def download_report_pdf(
    report_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> Response:
    report = db.get(AIReport, report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="报告不存在")
    try:
        analysis = dict(report.analysis_json) if isinstance(report.analysis_json, dict) else {}
        report_task_id = _latest_successful_report_task_id(db, scope=report.scope, scope_id=report.scope_id)
        if report.scope == ReportScope.JOB and report_task_id:
            analysis.setdefault("task_id", report_task_id)
        filename, pdf_bytes = VulnerabilityReportRenderer().render_pdf(
            scope=report.scope,
            scope_id=report.scope_id,
            analysis=analysis,
            report_id=report.id,
            created_at=report.created_at,
        )
    except ModuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="PDF 导出依赖未安装") from exc
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
