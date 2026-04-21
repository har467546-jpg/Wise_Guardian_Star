from datetime import datetime, timezone

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import DiscoveryJobStatus
from app.utils.net import normalize_cidr


def create_job(
    db: Session,
    cidr: str,
    label: str | None,
    created_by: str | None,
    scanner_zone_id: str | None = None,
) -> DiscoveryJob:
    normalized_cidr = normalize_cidr(cidr)
    job = DiscoveryJob(cidr=normalized_cidr, label=label, created_by=created_by, scanner_zone_id=scanner_zone_id)
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_job(db: Session, job_id: str) -> DiscoveryJob | None:
    return db.get(DiscoveryJob, job_id)


def list_jobs(
    db: Session,
    *,
    page: int,
    page_size: int,
    status: DiscoveryJobStatus | None = None,
) -> tuple[list[DiscoveryJob], int]:
    stmt: Select[tuple[DiscoveryJob]] = select(DiscoveryJob)
    count_stmt = select(func.count(DiscoveryJob.id))

    if status is not None:
        stmt = stmt.where(DiscoveryJob.status == status)
        count_stmt = count_stmt.where(DiscoveryJob.status == status)

    total = int(db.scalar(count_stmt) or 0)
    items = db.scalars(
        stmt.order_by(DiscoveryJob.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return items, total


def get_active_job_by_cidr(db: Session, cidr: str) -> DiscoveryJob | None:
    normalized_cidr = normalize_cidr(cidr)
    stmt = (
        select(DiscoveryJob)
        .where(
            DiscoveryJob.cidr == normalized_cidr,
            DiscoveryJob.status.in_([DiscoveryJobStatus.PENDING, DiscoveryJobStatus.RUNNING]),
        )
        .order_by(DiscoveryJob.created_at.desc())
    )
    return db.scalar(stmt)


def set_job_status(db: Session, job: DiscoveryJob, status: DiscoveryJobStatus, summary: dict | None = None) -> DiscoveryJob:
    job.status = status
    if status == DiscoveryJobStatus.RUNNING:
        job.started_at = datetime.now(timezone.utc)
    if status in {DiscoveryJobStatus.COMPLETED, DiscoveryJobStatus.FAILED}:
        job.finished_at = datetime.now(timezone.utc)
    if summary is not None:
        job.summary_json = summary
    db.add(job)
    db.commit()
    db.refresh(job)
    return job
