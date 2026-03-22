from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.db.models.enums import DiscoveryJobStatus, TaskExecutionStatus, TaskType
from app.db.models.user import User
from app.repositories.discovery_repo import create_job, get_active_job_by_cidr, get_job, list_jobs
from app.repositories.task_repo import create_task_run, get_latest_task_run_for_scope, update_task_run
from app.schemas.common import PageMeta
from app.schemas.discovery import DiscoveryJobCreate, DiscoveryJobCreateResponse, DiscoveryJobListResponse, DiscoveryJobRead
from app.tasks.scan_tasks import run_asset_scan_task

router = APIRouter()


@router.post("/jobs", response_model=DiscoveryJobCreateResponse, status_code=status.HTTP_201_CREATED)
def create_discovery_job(
    payload: DiscoveryJobCreate,
    response: Response,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> DiscoveryJobCreateResponse:
    def ensure_scan_task(job_id: str, *, message: str = "扫描任务已入队"):
        existing = get_latest_task_run_for_scope(
            db,
            scope_type="discovery_job",
            scope_id=job_id,
            task_type=TaskType.ASSET_SCAN,
            statuses=[TaskExecutionStatus.PENDING, TaskExecutionStatus.RUNNING, TaskExecutionStatus.RETRY],
        )
        if existing:
            return existing
        created = create_task_run(db, task_type=TaskType.ASSET_SCAN, scope_type="discovery_job", scope_id=job_id, message=message)
        celery_task = run_asset_scan_task.delay(created.id, job_id)
        return update_task_run(db, created, celery_task_id=celery_task.id)

    cidr_text = str(payload.cidr)
    active_job = get_active_job_by_cidr(db, cidr_text)
    if active_job:
        existing_task = ensure_scan_task(active_job.id, message="已复用已有扫描任务")
        response.status_code = status.HTTP_200_OK
        return DiscoveryJobCreateResponse(
            job=DiscoveryJobRead.model_validate(active_job),
            task_id=existing_task.id,
            status="reused",
            reused=True,
        )

    try:
        job = create_job(db=db, cidr=cidr_text, label=payload.label, created_by=current_user.id)
    except IntegrityError:
        db.rollback()
        active_job = get_active_job_by_cidr(db, cidr_text)
        if not active_job:
            raise
        existing_task = ensure_scan_task(active_job.id, message="检测到并发冲突，已复用已有扫描任务")
        response.status_code = status.HTTP_200_OK
        return DiscoveryJobCreateResponse(
            job=DiscoveryJobRead.model_validate(active_job),
            task_id=existing_task.id,
            status="reused",
            reused=True,
        )

    task_run = ensure_scan_task(job.id)
    response.status_code = status.HTTP_201_CREATED
    return DiscoveryJobCreateResponse(job=DiscoveryJobRead.model_validate(job), task_id=task_run.id, status="pending", reused=False)


@router.get("/jobs", response_model=DiscoveryJobListResponse)
def get_discovery_jobs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    status: DiscoveryJobStatus | None = None,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> DiscoveryJobListResponse:
    items, total = list_jobs(db, page=page, page_size=page_size, status=status)
    return DiscoveryJobListResponse(
        items=[DiscoveryJobRead.model_validate(item) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/jobs/{job_id}", response_model=DiscoveryJobRead)
def get_discovery_job(job_id: str, db: Session = Depends(get_db_session), _: User = Depends(get_current_user)) -> DiscoveryJobRead:
    job = get_job(db, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="发现任务不存在")
    return DiscoveryJobRead.model_validate(job)
