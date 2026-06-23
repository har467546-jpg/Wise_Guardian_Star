from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_admin_user, get_current_user, get_db_session
from app.db.models.enums import TaskType
from app.db.models.task_run import TaskRun
from app.db.models.user import User
from app.db.session import SessionLocal
from app.repositories.task_repo import ACTIVE_TASK_STATUSES, create_task_run, get_latest_task_run_for_scope, update_task_run
from app.rules import RuleConflictError, RuleDefinition, RuleNotFoundError, RuleStore
from app.schemas.common import PageMeta
from app.schemas.vuln_library import (
    RuleImportImpactPreviewRead,
    RuleEngineStatusRead,
    VulnIntelStatusRead,
    VulnRuleBatchStatusRequest,
    VulnRuleBatchStatusResponse,
    VulnRuleCreate,
    VulnRuleImportResponse,
    VulnRuleIndexRebuildResponse,
    VulnRuleListResponse,
    VulnRuleRead,
    VulnRuleUpdate,
)
from app.services.vuln_library_service import (
    RuleCatalogMetadata,
    VulnLibraryService,
    VulnRuleImportResult,
)
from app.tasks.vuln_intel_tasks import sync_vuln_intel_task

router = APIRouter()
logger = logging.getLogger(__name__)

RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "risk_rules.yaml"
RULE_STORE = RuleStore(RULES_PATH)
RULE_SERVICE = VulnLibraryService(RULE_STORE)
AUTO_INTEL_SYNC_COOLDOWN_SECONDS = 300
_last_auto_sync_queued_at: datetime | None = None
_last_auto_sync_task_id: str | None = None


@router.get("/status", response_model=RuleEngineStatusRead)
def get_vuln_library_status(_: User = Depends(get_current_user)) -> RuleEngineStatusRead:
    status_payload = RULE_SERVICE.get_status()
    return RuleEngineStatusRead(
        path=status_payload.path,
        loaded_at=status_payload.loaded_at,
        source_mtime=status_payload.source_mtime,
        rule_count=status_payload.rule_count,
        last_error=status_payload.last_error,
        schema_ready=status_payload.schema_ready,
        schema_error=status_payload.schema_error,
        indexed_rule_count=status_payload.indexed_rule_count,
        index_synced_at=status_payload.index_synced_at,
        index_in_sync=status_payload.index_in_sync,
        index_last_error=status_payload.index_last_error,
    )


@router.get("/intel/status", response_model=VulnIntelStatusRead)
def get_vuln_intel_status(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db_session),
) -> VulnIntelStatusRead:
    status_payload = RULE_SERVICE.get_intel_status()
    return _to_intel_status_read(
        status_payload,
        auto_sync=_queue_auto_intel_sync_if_needed(status_payload, db=db),
    )


@router.post("/intel/sync", response_model=VulnIntelStatusRead)
def sync_vuln_intel_catalog(
    _: User = Depends(get_admin_user),
    db: Session = Depends(get_db_session),
) -> VulnIntelStatusRead:
    library_status = RULE_SERVICE.get_status()
    if not library_status.schema_ready:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=library_status.schema_error or "数据库结构未升级，请先执行 alembic upgrade head",
        )
    status_payload = RULE_SERVICE.get_intel_status()
    auto_sync = _queue_intel_sync(status_payload, force=True, db=db)
    if auto_sync.get("sync_status") == "stale":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="后台同步任务提交失败，请稍后重试")
    return _to_intel_status_read(status_payload, auto_sync=auto_sync)


@router.get("/rules", response_model=VulnRuleListResponse)
def list_vuln_rules(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    keyword: str | None = Query(default=None),
    service: str | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    enabled: bool | None = Query(default=None),
    catalog_view: str = Query(default="default", pattern="^(default|all|legacy)$"),
    _: User = Depends(get_current_user),
) -> VulnRuleListResponse:
    items, total = RULE_SERVICE.list_rules(
        page=page,
        page_size=page_size,
        keyword=keyword,
        service=service,
        severity=severity,
        enabled=enabled,
        catalog_view=catalog_view,
    )
    metadata_map = RULE_SERVICE.get_rule_catalog_metadata(items)
    return VulnRuleListResponse(
        items=[_to_read_model(item, metadata_map.get(item.rule_id)) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/rules/export")
def export_vuln_rules(
    format: str = Query(default="yaml", pattern="^(yaml|json)$"),
    rule_ids: list[str] | None = Query(default=None),
    keyword: str | None = Query(default=None),
    service: str | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    enabled: bool | None = Query(default=None),
    catalog_view: str = Query(default="default", pattern="^(default|all|legacy)$"),
    _: User = Depends(get_admin_user),
) -> Response:
    export_payload = RULE_SERVICE.export_rules(
        format_name=format,
        rule_ids=rule_ids,
        keyword=keyword,
        service=service,
        severity=severity,
        enabled=enabled,
        catalog_view=catalog_view,
    )
    return Response(
        content=export_payload.content,
        media_type=export_payload.media_type,
        headers={"Content-Disposition": f'attachment; filename="{export_payload.filename}"'},
    )


@router.post("/rules/import", response_model=VulnRuleImportResponse)
async def import_vuln_rules(
    file: UploadFile = File(...),
    format: Annotated[str, Form(pattern="^(auto|yaml|json)$")] = "auto",
    mode: Annotated[str, Form(pattern="^(skip_existing|upsert)$")] = "skip_existing",
    dry_run: Annotated[bool, Form()] = False,
    _: User = Depends(get_admin_user),
) -> VulnRuleImportResponse:
    result = RULE_SERVICE.import_rules_from_bytes(
        content=await file.read(),
        filename=file.filename,
        format_name=format,
        mode=mode,
        dry_run=dry_run,
    )
    return _to_import_response(result)


@router.post("/rules/batch/status", response_model=VulnRuleBatchStatusResponse)
def batch_update_vuln_rule_status(
    payload: VulnRuleBatchStatusRequest,
    _: User = Depends(get_admin_user),
) -> VulnRuleBatchStatusResponse:
    result = RULE_SERVICE.batch_update_status(payload.rule_ids, enabled=payload.enabled)
    return VulnRuleBatchStatusResponse(
        enabled=result.enabled,
        updated=len(result.updated_ids),
        unchanged=len(result.unchanged_ids),
        missing=len(result.missing_ids),
        updated_ids=result.updated_ids,
        unchanged_ids=result.unchanged_ids,
        missing_ids=result.missing_ids,
    )


@router.get("/rules/{rule_id}", response_model=VulnRuleRead)
def get_vuln_rule(rule_id: str, _: User = Depends(get_current_user)) -> VulnRuleRead:
    rule = RULE_SERVICE.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="规则不存在")
    return _to_read_model(rule, RULE_SERVICE.get_rule_catalog_metadata([rule]).get(rule.rule_id))


@router.post("/rules", response_model=VulnRuleRead, status_code=status.HTTP_201_CREATED)
def create_vuln_rule(payload: VulnRuleCreate, _: User = Depends(get_admin_user)) -> VulnRuleRead:
    try:
        rule = RULE_SERVICE.create_rule(payload.model_dump(mode="python"))
    except RuleConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _to_read_model(rule, RULE_SERVICE.get_rule_catalog_metadata([rule]).get(rule.rule_id))


@router.put("/rules/{rule_id}", response_model=VulnRuleRead)
def update_vuln_rule(rule_id: str, payload: VulnRuleUpdate, _: User = Depends(get_admin_user)) -> VulnRuleRead:
    try:
        rule = RULE_SERVICE.update_rule(rule_id, payload.model_dump(mode="python"))
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _to_read_model(rule, RULE_SERVICE.get_rule_catalog_metadata([rule]).get(rule.rule_id))


@router.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vuln_rule(rule_id: str, _: User = Depends(get_admin_user)) -> None:
    try:
        RULE_SERVICE.delete_rule(rule_id)
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/index/rebuild", response_model=VulnRuleIndexRebuildResponse)
def rebuild_vuln_rule_index(_: User = Depends(get_admin_user)) -> VulnRuleIndexRebuildResponse:
    result = RULE_SERVICE.rebuild_index()
    return VulnRuleIndexRebuildResponse(
        indexed_rule_count=result.indexed_rule_count,
        index_synced_at=result.index_synced_at,
        index_in_sync=result.index_in_sync,
        source_hash=result.source_hash,
        index_last_error=result.index_last_error,
    )


def _to_read_model(rule: RuleDefinition, metadata: RuleCatalogMetadata | None = None) -> VulnRuleRead:
    payload = RuleStore.serialize_rule(rule)
    payload.setdefault("cve_ids", [])
    payload.setdefault("cwe_ids", [])
    payload.setdefault("affected_versions_text", None)
    payload.setdefault("exploit_module", None)
    payload.setdefault("preconditions", [])
    payload.setdefault("verify_playbook", [])
    payload.setdefault("mitigations", [])
    payload.setdefault("remediation", None)
    payload.setdefault("references", [])
    payload.setdefault("tags", [])
    payload.setdefault("active_check", None)
    payload.setdefault("created_at", None)
    payload.setdefault("updated_at", None)
    payload["intel_summary"] = {
        "cve_count": metadata.intel_summary.cve_count if metadata else len(payload["cve_ids"]),
        "max_cvss": metadata.intel_summary.max_cvss if metadata else None,
        "max_epss": metadata.intel_summary.max_epss if metadata else None,
        "kev_flag": metadata.intel_summary.kev_flag if metadata else False,
        "exploit_maturity": metadata.intel_summary.exploit_maturity if metadata else None,
        "intel_synced_at": metadata.intel_summary.intel_synced_at if metadata else None,
        "stale": metadata.intel_summary.stale if metadata else False,
    }
    payload["governance"] = {
        "owner_id": metadata.owner_id if metadata else None,
        "review_status": metadata.review_status if metadata else "published",
        "change_ticket": metadata.change_ticket if metadata else None,
        "last_validated_at": metadata.last_validated_at if metadata else None,
        "last_preview_at": metadata.last_preview_at if metadata else None,
        "updated_at": metadata.updated_at if metadata else None,
    }
    payload["affected_open_finding_count"] = metadata.affected_open_finding_count if metadata else 0
    return VulnRuleRead.model_validate(payload)


def _to_import_response(result: VulnRuleImportResult) -> VulnRuleImportResponse:
    return VulnRuleImportResponse(
        dry_run=result.dry_run,
        mode=result.mode,
        detected_format=result.detected_format,
        total_in_file=result.total_in_file,
        created=result.created,
        updated=result.updated,
        skipped=result.skipped,
        error_count=result.error_count,
        created_ids=result.created_ids,
        updated_ids=result.updated_ids,
        skipped_ids=result.skipped_ids,
        errors=[
            {"rule_id": item.rule_id, "message": item.message}
            for item in result.errors
        ],
        impact_preview=RuleImportImpactPreviewRead.model_validate(
            {
                "created_rule_ids": result.impact_preview.created_rule_ids,
                "updated_rule_ids": result.impact_preview.updated_rule_ids,
                "skipped_rule_ids": result.impact_preview.skipped_rule_ids,
                "total_affected_open_findings": result.impact_preview.total_affected_open_findings,
                "high_risk_rule_ids": result.impact_preview.high_risk_rule_ids,
                "changes": [
                    {
                        "rule_id": item.rule_id,
                        "operation": item.operation,
                        "changed_fields": item.changed_fields,
                        "high_risk_flags": item.high_risk_flags,
                        "affected_open_findings": item.affected_open_findings,
                    }
                    for item in result.impact_preview.changes
                ],
            }
        ) if result.impact_preview is not None else None,
    )


def _queue_auto_intel_sync_if_needed(status_payload, *, db: Session | None = None) -> dict[str, object]:
    return _queue_intel_sync(status_payload, force=False, db=db)


def _queue_intel_sync(status_payload, *, force: bool, db: Session | None = None) -> dict[str, object]:
    global _last_auto_sync_queued_at, _last_auto_sync_task_id

    try:
        library_status = RULE_SERVICE.get_status()
        if not library_status.schema_ready:
            return {"sync_status": "schema_not_ready", "auto_sync_queued": False, "sync_task_id": None}
    except Exception as exc:
        logger.warning("vuln intel auto-sync status check failed: %s", exc)
        return {"sync_status": "unknown", "auto_sync_queued": False, "sync_task_id": None}

    if status_payload.tracked_rule_cves <= 0:
        return {"sync_status": "fresh", "auto_sync_queued": False, "sync_task_id": None}
    if not force and not status_payload.stale and status_payload.last_synced_at is not None:
        return {"sync_status": "fresh", "auto_sync_queued": False, "sync_task_id": None}

    now = datetime.now(UTC)
    if (
        not force
        and _last_auto_sync_queued_at is not None
        and now - _last_auto_sync_queued_at < timedelta(seconds=AUTO_INTEL_SYNC_COOLDOWN_SECONDS)
    ):
        return {"sync_status": "queued", "auto_sync_queued": False, "sync_task_id": _last_auto_sync_task_id}

    active_task = _get_active_vuln_intel_task_run(db)
    if active_task is not None:
        _last_auto_sync_queued_at = now
        _last_auto_sync_task_id = active_task.id
        return {"sync_status": "queued", "auto_sync_queued": False, "sync_task_id": active_task.id}

    try:
        task_run_id = _create_vuln_intel_task_run(db)
        task = sync_vuln_intel_task.delay(task_run_id)
        _bind_vuln_intel_celery_task(db, task_run_id, str(task.id or ""))
    except Exception as exc:
        logger.warning("vuln intel auto-sync enqueue failed: %s", exc)
        return {"sync_status": "stale", "auto_sync_queued": False, "sync_task_id": None}

    _last_auto_sync_queued_at = now
    _last_auto_sync_task_id = task_run_id
    return {"sync_status": "queued", "auto_sync_queued": True, "sync_task_id": _last_auto_sync_task_id}


def _get_active_vuln_intel_task_run(db: Session | None) -> TaskRun | None:
    statuses = list(ACTIVE_TASK_STATUSES)
    if db is not None:
        return get_latest_task_run_for_scope(
            db,
            scope_type="vuln_library",
            scope_id="intel",
            task_type=TaskType.VULN_INTEL_SYNC,
            statuses=statuses,
        )
    with SessionLocal() as fallback_db:
        return get_latest_task_run_for_scope(
            fallback_db,
            scope_type="vuln_library",
            scope_id="intel",
            task_type=TaskType.VULN_INTEL_SYNC,
            statuses=statuses,
        )


def _create_vuln_intel_task_run(db: Session | None) -> str:
    if db is not None:
        task_run = create_task_run(
            db,
            task_type=TaskType.VULN_INTEL_SYNC,
            scope_type="vuln_library",
            scope_id="intel",
            message="漏洞情报同步任务已入队",
        )
        return task_run.id
    with SessionLocal() as fallback_db:
        task_run = create_task_run(
            fallback_db,
            task_type=TaskType.VULN_INTEL_SYNC,
            scope_type="vuln_library",
            scope_id="intel",
            message="漏洞情报同步任务已入队",
        )
        return task_run.id


def _bind_vuln_intel_celery_task(db: Session | None, task_run_id: str, celery_task_id: str) -> None:
    if not celery_task_id:
        return
    if db is not None:
        task_run = db.get(TaskRun, task_run_id)
        if task_run is not None:
            update_task_run(db, task_run, celery_task_id=celery_task_id)
        return
    with SessionLocal() as fallback_db:
        task_run = fallback_db.get(TaskRun, task_run_id)
        if task_run is not None:
            update_task_run(fallback_db, task_run, celery_task_id=celery_task_id)


def _to_intel_status_read(payload, *, auto_sync: dict[str, object] | None = None) -> VulnIntelStatusRead:
    sync_status = "stale" if payload.stale else "fresh"
    sync_task_id = None
    auto_sync_queued = False
    if isinstance(auto_sync, dict):
        sync_status = str(auto_sync.get("sync_status") or sync_status)
        sync_task_id = str(auto_sync.get("sync_task_id") or "").strip() or None
        auto_sync_queued = bool(auto_sync.get("auto_sync_queued"))
    return VulnIntelStatusRead.model_validate(
        {
            "total_cves": payload.total_cves,
            "tracked_rule_cves": payload.tracked_rule_cves,
            "synced_cves": payload.synced_cves,
            "stale": payload.stale,
            "stale_count": payload.stale_count,
            "last_synced_at": payload.last_synced_at,
            "sources": payload.sources,
            "updated_cves": payload.updated_cves,
            "sync_status": sync_status,
            "sync_task_id": sync_task_id,
            "auto_sync_queued": auto_sync_queued,
        }
    )
