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
from app.services.runner_service import resolve_runner_by_asset_for_read
from app.tasks.scan_tasks import run_asset_scan_task
from app.utils.net import normalize_cidr

router = APIRouter()


@router.post("/jobs", response_model=DiscoveryJobCreateResponse, status_code=status.HTTP_201_CREATED)
def create_discovery_job(
    payload: DiscoveryJobCreate,
    response: Response,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> DiscoveryJobCreateResponse:
    def ensure_scan_task(job_id: str, *, message: str = "扫描任务已入队", runner_asset_id: str | None = None):
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
        result_json = {
            "context": {
                "job_id": job_id,
                "runner_asset_id": str(runner_asset_id or "").strip() or None,
                "execution_boundary": "runner_dispatch" if runner_asset_id else "local",
            }
        }
        if runner_asset_id:
            return update_task_run(db, created, result_json=result_json, message="等待扫描节点接单")
        celery_task = run_asset_scan_task.delay(created.id, job_id)
        return update_task_run(db, created, celery_task_id=celery_task.id, result_json=result_json)

    cidr_text = normalize_cidr(str(payload.cidr))
    runner_asset_id = str(getattr(payload, "runner_asset_id", "") or "").strip() or None
    if runner_asset_id:
        runner = resolve_runner_by_asset_for_read(db, runner_asset_id)
        if runner is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="指定的扫描节点不存在")
        if runner.install_status != "installed":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="指定的扫描节点尚未完成 Runner 安装")
        if runner.status not in {"online", "busy"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="指定的扫描节点当前离线")
    active_job = get_active_job_by_cidr(db, cidr_text)
    if active_job:
        existing_task = ensure_scan_task(active_job.id, message="已复用已有扫描任务", runner_asset_id=runner_asset_id)
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
        existing_task = ensure_scan_task(active_job.id, message="检测到并发冲突，已复用已有扫描任务", runner_asset_id=runner_asset_id)
        response.status_code = status.HTTP_200_OK
        return DiscoveryJobCreateResponse(
            job=DiscoveryJobRead.model_validate(active_job),
            task_id=existing_task.id,
            status="reused",
            reused=True,
        )

    job.summary_json = {
        **(job.summary_json if isinstance(job.summary_json, dict) else {}),
        "request": {
            "runner_asset_id": runner_asset_id,
            "execution_boundary": "runner_dispatch" if runner_asset_id else "local",
        },
    }
    db.add(job)
    db.commit()
    db.refresh(job)
    task_run = ensure_scan_task(job.id, runner_asset_id=runner_asset_id)
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
