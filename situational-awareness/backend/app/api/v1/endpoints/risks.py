from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.db.models.asset import Asset
from app.db.models.enums import FindingStatus, RiskSeverity, TaskType
from app.db.models.risk_finding import RiskFinding
from app.db.models.user import User
from app.repositories.risk_repo import get_finding, list_findings_by_asset, list_findings_page
from app.rules import RuleDefinition, RuleStore, render_remediation_with_context, resolve_rule_remediation
from app.schemas.common import PageMeta
from app.repositories.task_repo import create_task_run, update_task_run
from app.schemas.risk import (
    RiskBatchVerifyRequest,
    RiskBatchVerifyResponse,
    RiskFindingAssignRequest,
    RiskFindingListResponse,
    RiskFindingMobileRead,
    RiskFindingPageResponse,
    RiskFindingRead,
    RiskFindingWaiverCreateRequest,
    RiskRemediationTemplateRead,
    RiskVerifyRequest,
    FindingGovernanceRead,
    FindingWaiverRead,
)
from app.schemas.task import TaskRunResponse
from app.services.finding_governance_service import (
    assign_finding_owner,
    create_finding_waiver,
    ensure_governance_for_findings,
    recalculate_finding_priority,
    resolve_waiver_status,
)
from app.tasks.verify_tasks import run_risk_verify_task

router = APIRouter()

RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "risk_rules.yaml"
RULE_STORE = RuleStore(RULES_PATH)


def _current_rules() -> list[RuleDefinition]:
    return RULE_STORE.loader.maybe_reload().rules


def _serialize_risk_finding_payload(finding: RiskFinding) -> dict[str, object]:
    asset = getattr(finding, "asset", None)
    governance = getattr(finding, "governance", None)
    waivers = getattr(finding, "waivers", []) or []
    return {
        "id": finding.id,
        "asset_id": finding.asset_id,
        "asset_ip": str(asset.ip) if asset is not None else "",
        "asset_hostname": asset.hostname if asset is not None else None,
        "asset_port_id": finding.asset_port_id,
        "severity": finding.severity,
        "status": finding.status,
        "title": finding.title,
        "description": finding.description,
        "evidence_json": finding.evidence_json or {},
        "detected_at": finding.detected_at,
        "resolved_at": finding.resolved_at,
        "priority_score": governance.priority_score if governance is not None else None,
        "priority_tier": governance.priority_tier if governance is not None else None,
        "priority_reason": governance.priority_reason_json if governance is not None else None,
        "owner_id": governance.owner_id if governance is not None else None,
        "sla_due_at": governance.sla_due_at if governance is not None else None,
        "waiver_status": resolve_waiver_status(finding),
        "governance": (
            {
                "finding_id": governance.finding_id,
                "priority_score": governance.priority_score,
                "priority_tier": governance.priority_tier,
                "priority_reason": governance.priority_reason_json,
                "owner_id": governance.owner_id,
                "sla_due_at": governance.sla_due_at,
                "status": governance.status,
                "updated_at": governance.updated_at,
            }
            if governance is not None
            else None
        ),
        "waivers": [
            {
                "id": waiver.id,
                "finding_id": waiver.finding_id,
                "waiver_type": waiver.waiver_type,
                "reason": waiver.reason,
                "expires_at": waiver.expires_at,
                "approved_by": waiver.approved_by,
                "status": waiver.status,
                "created_at": waiver.created_at,
                "updated_at": waiver.updated_at,
            }
            for waiver in waivers
        ],
    }


def _serialize_mobile_risk_finding(finding: RiskFinding) -> RiskFindingMobileRead:
    return RiskFindingMobileRead.model_validate(_serialize_risk_finding_payload(finding))


def _serialize_risk_finding(finding: RiskFinding) -> RiskFindingRead:
    return RiskFindingRead.model_validate(_serialize_risk_finding_payload(finding))


def _commit_if_supported(db: Session) -> None:
    if hasattr(db, "commit"):
        db.commit()


@router.get("", response_model=RiskFindingPageResponse)
def get_risk_list(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    severity: RiskSeverity | None = None,
    status: FindingStatus | None = None,
    keyword: str | None = Query(default=None),
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> RiskFindingPageResponse:
    items, total = list_findings_page(
        db,
        page=page,
        page_size=page_size,
        status=status,
        severity=severity,
        keyword=keyword,
    )
    if items:
        ensure_governance_for_findings(db, items, rules=_current_rules())
        _commit_if_supported(db)
    return RiskFindingPageResponse(
        items=[_serialize_mobile_risk_finding(item) for item in items],
        meta=PageMeta(total=total, page=page, page_size=page_size),
    )


@router.get("/{finding_id}", response_model=RiskFindingMobileRead)
def get_risk_detail(
    finding_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> RiskFindingMobileRead:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="风险发现不存在")
    ensure_governance_for_findings(db, [finding], rules=_current_rules())
    _commit_if_supported(db)
    return _serialize_mobile_risk_finding(finding)


@router.get("/assets/{asset_id}", response_model=RiskFindingListResponse)
def get_asset_risks(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> RiskFindingListResponse:
    findings = list_findings_by_asset(db=db, asset_id=asset_id)
    if findings:
        ensure_governance_for_findings(db, findings, rules=_current_rules())
        _commit_if_supported(db)
    return RiskFindingListResponse(items=[_serialize_risk_finding(item) for item in findings])


@router.post("/{finding_id}/assign", response_model=FindingGovernanceRead)
def assign_risk_finding(
    finding_id: str,
    payload: RiskFindingAssignRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> FindingGovernanceRead:
    try:
        governance = assign_finding_owner(
            db,
            finding_id,
            actor=user,
            owner_id=payload.owner_id,
            rules=_current_rules(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return FindingGovernanceRead.model_validate(
        {
            "finding_id": governance.finding_id,
            "priority_score": governance.priority_score,
            "priority_tier": governance.priority_tier,
            "priority_reason": governance.priority_reason_json,
            "owner_id": governance.owner_id,
            "sla_due_at": governance.sla_due_at,
            "status": governance.status,
            "updated_at": governance.updated_at,
        }
    )


@router.post("/{finding_id}/waivers", response_model=FindingWaiverRead)
def create_risk_finding_waiver(
    finding_id: str,
    payload: RiskFindingWaiverCreateRequest,
    db: Session = Depends(get_db_session),
    user: User = Depends(get_current_user),
) -> FindingWaiverRead:
    try:
        waiver = create_finding_waiver(
            db,
            finding_id,
            actor=user,
            waiver_type=payload.waiver_type,
            reason=payload.reason,
            expires_at=payload.expires_at,
            rules=_current_rules(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return FindingWaiverRead.model_validate(
        {
            "id": waiver.id,
            "finding_id": waiver.finding_id,
            "waiver_type": waiver.waiver_type,
            "reason": waiver.reason,
            "expires_at": waiver.expires_at,
            "approved_by": waiver.approved_by,
            "status": waiver.status,
            "created_at": waiver.created_at,
            "updated_at": waiver.updated_at,
        }
    )


@router.post("/{finding_id}/recalculate-priority", response_model=FindingGovernanceRead)
def recalculate_risk_finding_priority(
    finding_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> FindingGovernanceRead:
    try:
        governance = recalculate_finding_priority(db, finding_id, rules=_current_rules())
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return FindingGovernanceRead.model_validate(
        {
            "finding_id": governance.finding_id,
            "priority_score": governance.priority_score,
            "priority_tier": governance.priority_tier,
            "priority_reason": governance.priority_reason_json,
            "owner_id": governance.owner_id,
            "sla_due_at": governance.sla_due_at,
            "status": governance.status,
            "updated_at": governance.updated_at,
        }
    )


@router.post("/assets/batch/verify", response_model=RiskBatchVerifyResponse, status_code=status.HTTP_202_ACCEPTED)
def verify_asset_risks_batch(
    payload: RiskBatchVerifyRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> RiskBatchVerifyResponse:
    existing_ids = set(db.scalars(select(Asset.id).where(Asset.id.in_(payload.asset_ids))).all())
    missing_ids = [asset_id for asset_id in payload.asset_ids if asset_id not in existing_ids]
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"以下资产不存在：{', '.join(missing_ids)}",
        )

    task_ids: list[str] = []
    for asset_id in payload.asset_ids:
        task_run = create_task_run(
            db,
            task_type=TaskType.RISK_VERIFY,
            scope_type="asset",
            scope_id=asset_id,
            message="风险验证任务已入队",
        )
        task = run_risk_verify_task.delay(task_run.id, asset_id)
        update_task_run(db, task_run, celery_task_id=task.id)
        task_ids.append(task_run.id)

    return RiskBatchVerifyResponse(queued=len(task_ids), task_ids=task_ids)


@router.post("/assets/{asset_id}/verify", response_model=TaskRunResponse, status_code=status.HTTP_202_ACCEPTED)
def verify_asset_risks(
    asset_id: str,
    payload: RiskVerifyRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> TaskRunResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    task_run = create_task_run(db, task_type=TaskType.RISK_VERIFY, scope_type="asset", scope_id=asset_id, message="风险验证任务已入队")
    task = run_risk_verify_task.delay(task_run.id, asset_id)
    update_task_run(db, task_run, celery_task_id=task.id)
    return TaskRunResponse(task_id=task_run.id, status="pending")


@router.get("/{finding_id}/remediation-template", response_model=RiskRemediationTemplateRead)
def get_risk_remediation_template(
    finding_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> RiskRemediationTemplateRead:
    finding = get_finding(db, finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="风险发现不存在")

    evidence = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
    yaml_rule_id = str(evidence.get("yaml_rule_id") or "").strip()
    if not yaml_rule_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="风险发现未关联 YAML 规则")

    rule = RULE_STORE.get_rule(yaml_rule_id)
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"规则不存在：{yaml_rule_id}")

    remediation = resolve_rule_remediation(rule)
    rendered = render_remediation_with_context(
        remediation,
        _build_remediation_context(finding, rule, evidence),
    )
    source_references = list(
        dict.fromkeys(
            [
                *(rule.references or []),
                *(remediation.references or []),
            ]
        )
    )
    service_name = (
        str(evidence.get("service_name") or "").strip()
        or (finding.asset_port.service_name if finding.asset_port else None)
        or rule.service
        or None
    )
    return RiskRemediationTemplateRead.model_validate(
        {
            "finding_id": finding.id,
            "rule_id": rule.rule_id,
            "rule_name": rule.name or rule.rule_id,
            "asset_id": finding.asset_id,
            "asset_port_id": finding.asset_port_id,
            "service_name": service_name,
            "severity": finding.severity,
            "summary": rendered["summary"],
            "automation_level": rendered["automation_level"],
            "impact_summary": rendered.get("impact_summary"),
            "precheck_items": rendered.get("precheck_items") or rule.preconditions or [],
            "verify_items": rendered.get("verify_items") or rule.verify_playbook or [],
            "rollback_notes": rendered.get("rollback_notes") or [],
            "actions": rendered["actions"],
            "source_refs": {
                "yaml_rule_id": yaml_rule_id,
                "service": rule.service,
                "generated": rule.remediation is None,
                "references": source_references,
            },
        }
    )


def _build_remediation_context(
    finding: RiskFinding,
    rule: RuleDefinition,
    evidence: dict[str, object],
) -> dict[str, object]:
    port_value = evidence.get("port")
    port = port_value if isinstance(port_value, int) else finding.asset_port.port if finding.asset_port else None
    service_name = evidence.get("service_name") or (finding.asset_port.service_name if finding.asset_port else None) or rule.service
    service_version = evidence.get("service_version") or (finding.asset_port.service_version if finding.asset_port else None)
    fixed_versions = rule.package_conditions.fixed_versions if rule.package_conditions is not None else {}
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

    context: dict[str, object] = {
        "finding_id": finding.id,
        "rule_id": rule.rule_id,
        "rule_name": rule.name or rule.rule_id,
        "title": finding.title,
        "severity": severity,
        "asset_id": finding.asset_id,
        "asset_port_id": finding.asset_port_id,
        "port": port,
        "service": rule.service,
        "service_name": service_name,
        "service_version": service_version,
        "yaml_rule_id": evidence.get("yaml_rule_id"),
        "fixed_versions": fixed_versions,
        "finding": {
            "id": finding.id,
            "title": finding.title,
            "severity": severity,
        },
        "asset": {
            "id": finding.asset_id,
            "port_id": finding.asset_port_id,
            "port": port,
        },
        "evidence": {
            "yaml_rule_id": evidence.get("yaml_rule_id"),
            "service_name": service_name,
            "service_version": service_version,
            "port": port,
        },
        "rule": {
            "id": rule.rule_id,
            "name": rule.name or rule.rule_id,
            "service": rule.service,
            "match": {
                "package": {
                    "fixed_versions": fixed_versions,
                }
            },
        },
    }
    return context
