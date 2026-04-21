from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_db_session
from app.db.models.asset import Asset
from app.db.models.campus_data_source import CampusDataSource
from app.db.models.discovery_job_execution import DiscoveryJobExecution
from app.db.models.host_runner import HostRunner
from app.db.models.scanner_node_assignment import ScannerNodeAssignment
from app.db.models.scanner_zone import ScannerZone
from app.db.models.user import User
from app.schemas.campus import (
    CampusDataSourceRead,
    CampusDataSourceTestResponse,
    CampusDataSourceWrite,
    DiscoveryJobExecutionListResponse,
    DiscoveryJobExecutionRead,
    ScannerNodeAssignmentRead,
    ScannerNodeAssignmentWrite,
    ScannerZoneListResponse,
    ScannerZoneRead,
    ScannerZoneWrite,
)
from app.schemas.common import PageMeta
from app.services.campus_data_source_service import sync_campus_data_source, test_campus_data_source, upsert_campus_data_source
from app.services.campus_asset_association_service import upsert_asset_from_observation
from app.services.campus_zone_service import (
    get_scanner_zone,
    list_campus_data_sources,
    list_discovery_job_executions,
    list_scanner_node_assignments,
    list_scanner_zones,
)

router = APIRouter()


@router.get("/zones", response_model=ScannerZoneListResponse)
def get_scanner_zones(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> ScannerZoneListResponse:
    items, total = list_scanner_zones(db, page=page, page_size=page_size)
    return ScannerZoneListResponse(
        items=[ScannerZoneRead.model_validate(item) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.post("/zones", response_model=ScannerZoneRead, status_code=status.HTTP_201_CREATED)
def create_scanner_zone(
    payload: ScannerZoneWrite,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> ScannerZoneRead:
    zone = ScannerZone(**payload.model_dump())
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return ScannerZoneRead.model_validate(zone)


@router.patch("/zones/{zone_id}", response_model=ScannerZoneRead)
def update_scanner_zone(
    zone_id: str,
    payload: ScannerZoneWrite,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> ScannerZoneRead:
    zone = get_scanner_zone(db, zone_id)
    if zone is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="扫描分区不存在")
    for key, value in payload.model_dump().items():
        setattr(zone, key, value)
    db.add(zone)
    db.commit()
    db.refresh(zone)
    return ScannerZoneRead.model_validate(zone)


@router.delete("/zones/{zone_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scanner_zone(
    zone_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> None:
    zone = get_scanner_zone(db, zone_id)
    if zone is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="扫描分区不存在")
    db.delete(zone)
    db.commit()


@router.get("/zones/{zone_id}/nodes", response_model=list[ScannerNodeAssignmentRead])
def get_zone_nodes(
    zone_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> list[ScannerNodeAssignmentRead]:
    if get_scanner_zone(db, zone_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="扫描分区不存在")
    return [ScannerNodeAssignmentRead.model_validate(item) for item in list_scanner_node_assignments(db, zone_id=zone_id)]


@router.post("/zones/{zone_id}/nodes", response_model=ScannerNodeAssignmentRead, status_code=status.HTTP_201_CREATED)
def create_zone_node(
    zone_id: str,
    payload: ScannerNodeAssignmentWrite,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> ScannerNodeAssignmentRead:
    if get_scanner_zone(db, zone_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="扫描分区不存在")
    asset = db.get(Asset, payload.asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="扫描节点资产不存在")
    assignment = ScannerNodeAssignment(scanner_zone_id=zone_id, **payload.model_dump())
    db.add(assignment)
    db.commit()
    db.refresh(assignment)
    host_runner = asset.host_runner
    if host_runner is not None:
        host_runner.scanner_zone_id = zone_id
        host_runner.visible_cidrs_json = payload.visible_cidrs_json
        host_runner.max_concurrent_jobs = payload.max_concurrent_jobs
        db.add(host_runner)
        db.commit()
    return ScannerNodeAssignmentRead.model_validate(assignment)


@router.get("/data-sources", response_model=list[CampusDataSourceRead])
def get_campus_data_sources(
    zone_id: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> list[CampusDataSourceRead]:
    return [CampusDataSourceRead.model_validate(item) for item in list_campus_data_sources(db, zone_id=zone_id)]


@router.post("/data-sources", response_model=CampusDataSourceRead, status_code=status.HTTP_201_CREATED)
def create_campus_data_source(
    payload: CampusDataSourceWrite,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> CampusDataSourceRead:
    if get_scanner_zone(db, payload.scanner_zone_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="扫描分区不存在")
    source = upsert_campus_data_source(
        db,
        None,
        scanner_zone_id=payload.scanner_zone_id,
        asset_id=payload.asset_id,
        name=payload.name,
        source_type=payload.source_type,
        enabled=payload.enabled,
        collection_interval_seconds=payload.collection_interval_seconds,
        config_json=payload.config_json,
        secret_plaintext=payload.secret_plaintext,
    )
    return CampusDataSourceRead.model_validate(source)


@router.patch("/data-sources/{source_id}", response_model=CampusDataSourceRead)
def update_campus_data_source(
    source_id: str,
    payload: CampusDataSourceWrite,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> CampusDataSourceRead:
    source = db.get(CampusDataSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="校园数据源不存在")
    source = upsert_campus_data_source(
        db,
        source,
        scanner_zone_id=payload.scanner_zone_id,
        asset_id=payload.asset_id,
        name=payload.name,
        source_type=payload.source_type,
        enabled=payload.enabled,
        collection_interval_seconds=payload.collection_interval_seconds,
        config_json=payload.config_json,
        secret_plaintext=payload.secret_plaintext,
    )
    return CampusDataSourceRead.model_validate(source)


@router.delete("/data-sources/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_campus_data_source(
    source_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> None:
    source = db.get(CampusDataSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="校园数据源不存在")
    db.delete(source)
    db.commit()


@router.post("/data-sources/{source_id}/test", response_model=CampusDataSourceTestResponse)
def test_campus_data_source_endpoint(
    source_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> CampusDataSourceTestResponse:
    source = db.get(CampusDataSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="校园数据源不存在")
    ok, message, summary = test_campus_data_source(source)
    return CampusDataSourceTestResponse(ok=ok, source_type=source.source_type, message=message, summary_json=summary)


@router.post("/data-sources/{source_id}/collect", response_model=CampusDataSourceTestResponse)
def collect_campus_data_source_endpoint(
    source_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> CampusDataSourceTestResponse:
    source = db.get(CampusDataSource, source_id)
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="校园数据源不存在")
    observations, summary = sync_campus_data_source(db, source)
    matched_count = 0
    created_count = 0
    for observation in observations:
        asset, decision = upsert_asset_from_observation(db, observation, identity_source=source.source_type)
        if decision.asset is None:
            created_count += 1
        else:
            matched_count += 1
        db.add(asset)
    db.commit()
    return CampusDataSourceTestResponse(
        ok=True,
        source_type=source.source_type,
        message=f"采集成功，共 {len(observations)} 条观测",
        summary_json={**summary, "matched_count": matched_count, "created_count": created_count},
    )


@router.get("/discovery-jobs/{job_id}/executions", response_model=DiscoveryJobExecutionListResponse)
def get_discovery_job_execution_list(
    job_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_admin_user),
) -> DiscoveryJobExecutionListResponse:
    items = list_discovery_job_executions(db, job_id=job_id)
    sliced = items[(page - 1) * page_size : page * page_size]
    return DiscoveryJobExecutionListResponse(
        items=[DiscoveryJobExecutionRead.model_validate(item) for item in sliced],
        meta=PageMeta(total=len(items), page=page, page_size=page_size),
    )
