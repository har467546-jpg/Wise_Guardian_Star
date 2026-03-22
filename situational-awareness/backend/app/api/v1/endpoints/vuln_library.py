from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile, status

from app.api.deps import get_admin_user, get_current_user
from app.db.models.user import User
from app.rules import RuleConflictError, RuleDefinition, RuleNotFoundError, RuleStore
from app.schemas.common import PageMeta
from app.schemas.vuln_library import (
    RuleEngineStatusRead,
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
    VulnLibraryService,
    VulnRuleImportResult,
)

router = APIRouter()

RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "risk_rules.yaml"
RULE_STORE = RuleStore(RULES_PATH)
RULE_SERVICE = VulnLibraryService(RULE_STORE)


@router.get("/status", response_model=RuleEngineStatusRead)
def get_vuln_library_status(_: User = Depends(get_current_user)) -> RuleEngineStatusRead:
    status_payload = RULE_SERVICE.get_status()
    return RuleEngineStatusRead(
        path=status_payload.path,
        loaded_at=status_payload.loaded_at,
        source_mtime=status_payload.source_mtime,
        rule_count=status_payload.rule_count,
        last_error=status_payload.last_error,
        indexed_rule_count=status_payload.indexed_rule_count,
        index_synced_at=status_payload.index_synced_at,
        index_in_sync=status_payload.index_in_sync,
        index_last_error=status_payload.index_last_error,
    )


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
    return VulnRuleListResponse(
        items=[_to_read_model(item) for item in items],
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
    return _to_read_model(rule)


@router.post("/rules", response_model=VulnRuleRead, status_code=status.HTTP_201_CREATED)
def create_vuln_rule(payload: VulnRuleCreate, _: User = Depends(get_admin_user)) -> VulnRuleRead:
    try:
        rule = RULE_SERVICE.create_rule(payload.model_dump(mode="python"))
    except RuleConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _to_read_model(rule)


@router.put("/rules/{rule_id}", response_model=VulnRuleRead)
def update_vuln_rule(rule_id: str, payload: VulnRuleUpdate, _: User = Depends(get_admin_user)) -> VulnRuleRead:
    try:
        rule = RULE_SERVICE.update_rule(rule_id, payload.model_dump(mode="python"))
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return _to_read_model(rule)


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


def _to_read_model(rule: RuleDefinition) -> VulnRuleRead:
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
    )
