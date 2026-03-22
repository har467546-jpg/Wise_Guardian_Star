from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import TaskType
from app.db.models.report import AIReport
from app.db.models.user import User
from app.repositories.task_repo import create_task_run, update_task_run
from app.schemas.report import GenerateReportResponse, ReportRead
from app.tasks.report_tasks import generate_asset_report, generate_job_report

router = APIRouter()


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
