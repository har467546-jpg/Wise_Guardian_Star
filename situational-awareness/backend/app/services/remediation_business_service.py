from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.endpoints import risks as risks_endpoint
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import FindingStatus, TaskType
from app.db.models.remediation_session import RemediationSession
from app.db.models.risk_finding import RiskFinding
from app.db.models.task_run import TaskRun
from app.db.session import SessionLocal
from app.repositories.discovery_repo import create_job
from app.repositories.task_repo import create_task_run, get_task_run, update_task_run
from app.services.admin_cidr_service import get_admin_cidrs
from app.tasks.collection_tasks import (
    _build_collect_options,
    _collect_for_asset,
    _persist_collection_result,
    _run_collection_nse_followup,
    _verify_authorization_for_asset,
)
from app.tasks.discovery_tasks import discover_hosts, finalize_job, full_port_scan, probe_open_services, upsert_assets


BUSINESS_STATUS_PENDING_REVERIFY = "pending_reverify"
BUSINESS_STATUS_VERIFIED_CLOSED = "verified_closed"
BUSINESS_STATUS_VERIFIED_PARTIAL = "verified_partial"
BUSINESS_STATUS_VERIFIED_FAILED = "verified_failed"

EXECUTION_STATUS_PENDING = "pending"
EXECUTION_STATUS_SUCCEEDED = "succeeded"
EXECUTION_STATUS_FAILED = "failed"
EXECUTION_STATUS_PREVIEW_ONLY = "preview_only"

NETWORK_REVERIFY_ACTION_TYPES = {
    "remove_exposure",
    "toggle_feature",
    "set_bind_scope",
    "restrict_network",
    "set_access_policy",
    "remove_path",
}
COLLECTION_REVERIFY_ACTION_TYPES = {
    "upgrade_package",
    "reload_service",
    "restart_service",
    "disable_service",
    "set_config",
    "remove_config",
    "toggle_feature",
    "remove_exposure",
    "set_bind_scope",
    "restrict_network",
    "set_access_policy",
    "remove_path",
    "set_path_permission",
    "permission_set",
}


def build_reverify_queue_payload(
    db: Session,
    *,
    asset_id: str,
    remediation_task_id: str,
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    finding_id: str | None = None,
    stage_code: str | None = None,
    stage_name: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    targeted_context = _collect_targeted_finding_context(
        db,
        asset_id=asset_id,
        plan=plan,
        selected_steps=selected_steps,
        finding_id=finding_id,
    )
    action_types = {
        str(item.get("action_type") or "").strip().lower()
        for item in selected_steps
        if isinstance(item, dict) and str(item.get("action_type") or "").strip()
    }
    return {
        "asset_id": asset_id,
        "remediation_task_id": remediation_task_id,
        "session_id": session_id,
        "stage_code": stage_code,
        "stage_name": stage_name,
        "requires_rescan": bool(action_types & NETWORK_REVERIFY_ACTION_TYPES),
        "requires_recollect": bool(action_types & COLLECTION_REVERIFY_ACTION_TYPES),
        "selected_steps": [dict(item) for item in selected_steps if isinstance(item, dict)],
        "targeted_finding_ids": targeted_context["finding_ids"],
        "targeted_finding_specs": targeted_context["finding_specs"],
        "targeted_rule_ids": targeted_context["targeted_rule_ids"],
        "targeted_target_count": len(targeted_context["finding_specs"]),
    }


def queue_remediation_reverify(
    db: Session,
    *,
    asset_id: str,
    remediation_task_id: str,
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    finding_id: str | None = None,
    stage_code: str | None = None,
    stage_name: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    payload = build_reverify_queue_payload(
        db,
        asset_id=asset_id,
        remediation_task_id=remediation_task_id,
        plan=plan,
        selected_steps=selected_steps,
        finding_id=finding_id,
        stage_code=stage_code,
        stage_name=stage_name,
        session_id=session_id,
    )
    task_run = create_task_run(
        db,
        task_type=TaskType.RISK_VERIFY,
        scope_type="asset",
        scope_id=asset_id,
        message="修复后业务复验任务已入队",
    )
    update_task_run(
        db,
        task_run,
        result_json={
            "asset_id": asset_id,
            "remediation_task_id": remediation_task_id,
            "requires_rescan": payload["requires_rescan"],
            "requires_recollect": payload["requires_recollect"],
            "targeted_rule_ids": payload["targeted_rule_ids"],
            "targeted_target_count": payload["targeted_target_count"],
            "stage_code": stage_code,
            "stage_name": stage_name,
        },
    )
    from app.tasks.remediation_tasks import run_remediation_reverify_task

    task = run_remediation_reverify_task.delay(task_run.id, remediation_task_id, asset_id, payload)
    update_task_run(db, task_run, celery_task_id=task.id)
    return {
        "reverify_triggered": True,
        "reverify_task_id": task_run.id,
        "reverify_status": "pending",
    }


def finalize_remediation_business_outcome(
    db: Session,
    *,
    remediation_task_id: str,
    reverify_task_id: str,
    business_status: str,
    reverify_status: str,
    reverify_summary: dict[str, Any],
    targeted_finding_outcomes: list[dict[str, Any]],
    message: str,
) -> None:
    remediation_task = get_task_run(db, remediation_task_id)
    if remediation_task is None:
        return
    result_json = dict(remediation_task.result_json or {})
    execution = dict(result_json.get("execution") or {}) if isinstance(result_json.get("execution"), dict) else {}
    reverify = dict(result_json.get("reverify") or {}) if isinstance(result_json.get("reverify"), dict) else {}
    execution.setdefault("execution_status", result_json.get("execution_status") or EXECUTION_STATUS_SUCCEEDED)
    execution["business_status"] = business_status
    result_json["execution_status"] = str(execution.get("execution_status") or EXECUTION_STATUS_SUCCEEDED)
    result_json["business_status"] = business_status
    result_json["targeted_finding_outcomes"] = targeted_finding_outcomes
    result_json["reverify_task_id"] = reverify_task_id
    result_json["reverify_summary"] = reverify_summary
    reverify.update(
        {
            "reverify_triggered": True,
            "reverify_task_id": reverify_task_id,
            "reverify_status": reverify_status,
            "business_status": business_status,
            "reverify_summary": reverify_summary,
        }
    )
    result_json["execution"] = execution
    result_json["reverify"] = reverify
    update_task_run(
        db,
        remediation_task,
        message=message,
        result_json=result_json,
        commit=False,
        refresh=False,
    )
    _update_session_stage_business_outcome(
        db,
        remediation_task=remediation_task,
        reverify_task_id=reverify_task_id,
        business_status=business_status,
        reverify_summary=reverify_summary,
    )
    db.commit()


def build_business_status_message(
    business_status: str | None,
    *,
    stage_name: str | None = None,
) -> str:
    normalized = str(business_status or "").strip().lower()
    stage_prefix = f"阶段“{stage_name}”" if stage_name else "当前阶段"
    if normalized == BUSINESS_STATUS_PENDING_REVERIFY:
        return f"{stage_prefix}执行完成，正在复验目标风险"
    if normalized == BUSINESS_STATUS_VERIFIED_CLOSED:
        return f"{stage_prefix}目标风险已复验关闭"
    if normalized == BUSINESS_STATUS_VERIFIED_PARTIAL:
        return f"{stage_prefix}执行完成，但目标风险仍未关闭"
    if normalized == BUSINESS_STATUS_VERIFIED_FAILED:
        return f"{stage_prefix}执行或复验失败"
    return stage_prefix if stage_name else "修复任务状态已更新"


def build_reverify_outcome(
    db: Session,
    *,
    asset_id: str,
    followup_payload: dict[str, Any],
    scan_summary: dict[str, Any] | None,
    collection_summary: dict[str, Any] | None,
    verification_summary: dict[str, Any] | None,
) -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
    targeted_specs = [
        dict(item)
        for item in (followup_payload.get("targeted_finding_specs") or [])
        if isinstance(item, dict)
    ]
    targeted_keys = {_target_signature(item) for item in targeted_specs if _target_signature(item)}
    targeted_rule_ids = [
        str(item).strip()
        for item in (followup_payload.get("targeted_rule_ids") or [])
        if str(item).strip()
    ]
    open_findings = db.scalars(
        select(RiskFinding).where(
            RiskFinding.asset_id == asset_id,
            RiskFinding.status == FindingStatus.OPEN,
        )
    ).all()
    open_by_key: dict[str, RiskFinding] = {}
    for finding in open_findings:
        signature = _target_signature(_serialize_finding_scope(finding))
        if signature and signature not in open_by_key:
            open_by_key[signature] = finding
    outcomes: list[dict[str, Any]] = []
    open_target_count = 0
    for spec in targeted_specs:
        signature = _target_signature(spec)
        current = open_by_key.get(signature) if signature else None
        status = "open" if current is not None else "closed"
        if status == "open":
            open_target_count += 1
        outcomes.append(
            {
                "original_finding_id": spec.get("finding_id"),
                "rule_id": spec.get("rule_id"),
                "title": spec.get("title"),
                "service_name": spec.get("service_name"),
                "port": spec.get("port"),
                "evidence_scope": spec.get("evidence_scope"),
                "status": status,
                "current_finding_id": current.id if current is not None else None,
                "current_title": current.title if current is not None else None,
            }
        )
    business_blockers: list[str] = []
    if _requires_admin_cidrs(targeted_rule_ids) and not get_admin_cidrs():
        business_blockers.append("缺少管理网段配置，当前无法确认是否已收敛到管理网段")
    targeted_target_count = len(targeted_specs)
    if targeted_target_count <= 0:
        business_blockers.append("未解析到本阶段的目标风险范围")
    closed_target_count = max(0, targeted_target_count - open_target_count)
    other_open_finding_count = sum(
        1
        for finding in open_findings
        if _target_signature(_serialize_finding_scope(finding)) not in targeted_keys
    )
    summary = {
        "requires_rescan": bool(followup_payload.get("requires_rescan")),
        "requires_recollect": bool(followup_payload.get("requires_recollect")),
        "scan": scan_summary or {"status": "not_required"},
        "collection": collection_summary or {"status": "not_required"},
        "verification": verification_summary or {},
        "targeted_rule_ids": targeted_rule_ids,
        "targeted_target_count": targeted_target_count,
        "closed_target_count": closed_target_count,
        "open_target_count": open_target_count,
        "other_open_finding_count": other_open_finding_count,
        "business_blockers": business_blockers,
        "admin_cidrs_configured": bool(get_admin_cidrs()),
    }
    business_status = BUSINESS_STATUS_VERIFIED_CLOSED
    if business_blockers or open_target_count > 0:
        business_status = BUSINESS_STATUS_VERIFIED_PARTIAL
    return business_status, summary, outcomes


def build_reverify_failure_summary(
    *,
    followup_payload: dict[str, Any],
    error_message: str,
    scan_summary: dict[str, Any] | None = None,
    collection_summary: dict[str, Any] | None = None,
    verification_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "requires_rescan": bool(followup_payload.get("requires_rescan")),
        "requires_recollect": bool(followup_payload.get("requires_recollect")),
        "scan": scan_summary or {"status": "not_started"},
        "collection": collection_summary or {"status": "not_started"},
        "verification": verification_summary or {"status": "failed", "error": error_message},
        "targeted_rule_ids": [
            str(item).strip()
            for item in (followup_payload.get("targeted_rule_ids") or [])
            if str(item).strip()
        ],
        "targeted_target_count": int(followup_payload.get("targeted_target_count") or 0),
        "closed_target_count": 0,
        "open_target_count": int(followup_payload.get("targeted_target_count") or 0),
        "other_open_finding_count": None,
        "business_blockers": [error_message],
        "admin_cidrs_configured": bool(get_admin_cidrs()),
    }


def run_inline_rescan(asset: Asset) -> dict[str, Any]:
    job_id: str | None = None
    try:
        with SessionLocal() as db:
            job = create_job(
                db,
                cidr=f"{asset.ip}/32",
                label=f"auto-reverify-{asset.id}",
                created_by=None,
            )
            job_id = job.id
        discover_hosts(job_id)
        upsert_assets(job_id)
        full_port_scan(job_id)
        probe_open_services(job_id)
        finalize_job(job_id)
        with SessionLocal() as db:
            job = db.get(DiscoveryJob, job_id)
            summary_json = dict(job.summary_json or {}) if job is not None and isinstance(job.summary_json, dict) else {}
        port_scan_stats = summary_json.get("port_scan_stats") if isinstance(summary_json.get("port_scan_stats"), dict) else {}
        return {
            "status": "success",
            "discovery_job_id": job_id,
            "host_count": int(summary_json.get("host_count") or 0),
            "open_port_count": int(port_scan_stats.get("open_port_count") or 0),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "discovery_job_id": job_id,
            "error": str(exc),
        }


def run_inline_collection(asset_id: str) -> dict[str, Any]:
    with SessionLocal() as db:
        asset = db.get(Asset, asset_id)
        if asset is None:
            return {"status": "failed", "error": "资产不存在"}
        options = _build_collect_options(None, None, None)
        authorization = _verify_authorization_for_asset(db=db, asset=asset, credential_id=None, options=options)
        result = _collect_for_asset(
            db=db,
            asset=asset,
            credential_id=None,
            options=options,
            authorization_result=authorization,
        )
        summary = {
            "status": result.status,
            "authorization_status": authorization.status,
            "effective_privilege": authorization.effective_privilege,
        }
        if result.status not in {"success", "partial"}:
            summary["error"] = result.summary()
            db.commit()
            return summary
        snapshot = _persist_collection_result(db=db, asset=asset, result=result)
        nse_stats = _run_collection_nse_followup(db=db, asset=asset, snapshot=snapshot, collected_at=result.collected_at)
        db.commit()
        summary.update(
            {
                "collected_at": result.collected_at.isoformat(),
                "nse_candidate_port_count": nse_stats.candidate_port_count,
                "nse_executed_port_count": nse_stats.executed_port_count,
                "nse_script_run_count": nse_stats.script_run_count,
                "nse_hit_count": nse_stats.hit_count,
                "nse_skipped_count": nse_stats.skipped_count,
                "nse_error_count": nse_stats.error_count,
            }
        )
        return summary


def _collect_targeted_finding_context(
    db: Session,
    *,
    asset_id: str,
    plan: dict[str, Any],
    selected_steps: list[dict[str, Any]],
    finding_id: str | None = None,
) -> dict[str, Any]:
    finding_ids: list[str] = []
    targeted_rule_ids: list[str] = []
    fallback_title = str(plan.get("rule_name") or "").strip() or None
    fallback_service_name = str(plan.get("service_name") or "").strip() or None
    for step in selected_steps:
        if not isinstance(step, dict):
            continue
        if str(step.get("finding_id") or "").strip():
            finding_ids.append(str(step.get("finding_id")).strip())
        for item in step.get("related_findings") or []:
            if isinstance(item, dict) and str(item.get("finding_id") or "").strip():
                finding_ids.append(str(item.get("finding_id")).strip())
        for item in step.get("related_rules") or []:
            cleaned = str(item or "").strip()
            if cleaned:
                targeted_rule_ids.append(cleaned)
    if finding_id:
        finding_ids.append(str(finding_id).strip())
    normalized_finding_ids = _dedupe_strings(finding_ids)
    findings = []
    if normalized_finding_ids:
        findings = db.scalars(
            select(RiskFinding).where(
                RiskFinding.asset_id == asset_id,
                RiskFinding.id.in_(normalized_finding_ids),
            )
        ).all()
    finding_specs = [_serialize_finding_scope(item) for item in findings]
    if not finding_specs:
        fallback_rule_id = str(plan.get("rule_id") or "").strip()
        if fallback_rule_id:
            finding_specs.append(
                {
                    "finding_id": finding_id,
                    "rule_id": fallback_rule_id,
                    "title": fallback_title,
                    "service_name": fallback_service_name,
                    "port": None,
                    "evidence_scope": "asset",
                }
            )
            targeted_rule_ids.append(fallback_rule_id)
    else:
        targeted_rule_ids.extend(
            [
                str(item.get("rule_id") or "").strip()
                for item in finding_specs
                if str(item.get("rule_id") or "").strip()
            ]
        )
    return {
        "finding_ids": normalized_finding_ids,
        "finding_specs": finding_specs,
        "targeted_rule_ids": _dedupe_strings(targeted_rule_ids),
    }


def _serialize_finding_scope(finding: RiskFinding) -> dict[str, Any]:
    evidence = finding.evidence()
    port = evidence.get("port")
    try:
        normalized_port = int(port) if port is not None else None
    except (TypeError, ValueError):
        normalized_port = None
    rule_id = str(finding.resolved_yaml_rule_id() or finding.rule_id or "").strip() or None
    return {
        "finding_id": finding.id,
        "rule_id": rule_id,
        "title": finding.title,
        "service_name": str(evidence.get("service_name") or "").strip() or None,
        "port": normalized_port,
        "evidence_scope": str(evidence.get("evidence_scope") or "").strip() or "asset",
    }


def _target_signature(scope: dict[str, Any]) -> str:
    rule_id = str(scope.get("rule_id") or "").strip().lower()
    service_name = str(scope.get("service_name") or "").strip().lower()
    evidence_scope = str(scope.get("evidence_scope") or "").strip().lower() or "asset"
    port = scope.get("port")
    normalized_port = str(int(port)) if port not in (None, "") else "-"
    return "|".join([rule_id or "-", service_name or "-", normalized_port, evidence_scope])


def _dedupe_strings(values: list[str]) -> list[str]:
    items: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        items.append(normalized)
    return items


def _requires_admin_cidrs(rule_ids: list[str]) -> bool:
    for rule_id in rule_ids:
        rule = risks_endpoint.RULE_STORE.get_rule(rule_id)
        if not rule or not rule.remediation:
            continue
        for action in rule.remediation.actions:
            params = action.params or {}
            target_scope = str(params.get("target_scope") or params.get("target_policy") or "").strip().lower()
            if (
                action.action_type in {"set_bind_scope", "restrict_network", "set_access_policy"}
                and target_scope == "admin_segment_only"
            ):
                return True
    return False


def _update_session_stage_business_outcome(
    db: Session,
    *,
    remediation_task: TaskRun,
    reverify_task_id: str,
    business_status: str,
    reverify_summary: dict[str, Any],
) -> None:
    result_json = remediation_task.result_json if isinstance(remediation_task.result_json, dict) else {}
    context = result_json.get("context") if isinstance(result_json.get("context"), dict) else {}
    session_id = str(context.get("session_id") or "").strip()
    stage_code = str(context.get("stage_code") or "").strip()
    if not session_id or not stage_code:
        return
    session = db.get(RemediationSession, session_id)
    if session is None:
        return
    summary_state = dict(session.summary_json or {})
    stage_outcomes = dict(summary_state.get("stage_business_outcomes") or {})
    stage_outcomes[stage_code] = {
        "business_status": business_status,
        "targeted_rule_ids": list(reverify_summary.get("targeted_rule_ids") or []),
        "closed_target_count": int(reverify_summary.get("closed_target_count") or 0),
        "open_target_count": int(reverify_summary.get("open_target_count") or 0),
        "reverify_task_id": reverify_task_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    completed_stage_codes = [
        str(item).strip()
        for item in (summary_state.get("completed_stage_codes") or [])
        if str(item).strip()
    ]
    if business_status == BUSINESS_STATUS_VERIFIED_CLOSED:
        if stage_code not in completed_stage_codes:
            completed_stage_codes.append(stage_code)
    else:
        completed_stage_codes = [item for item in completed_stage_codes if item != stage_code]
    summary_state["stage_business_outcomes"] = stage_outcomes
    summary_state["completed_stage_codes"] = completed_stage_codes
    if business_status == BUSINESS_STATUS_PENDING_REVERIFY:
        summary_state["running_stage_code"] = stage_code
    elif str(summary_state.get("running_stage_code") or "").strip() == stage_code:
        summary_state["running_stage_code"] = None
    session.summary_json = summary_state
    if business_status == BUSINESS_STATUS_PENDING_REVERIFY:
        session.status = "running"
    elif business_status == BUSINESS_STATUS_VERIFIED_FAILED:
        session.status = "failed"
    else:
        session.status = "ready"
    session.updated_at = datetime.now(timezone.utc)
    db.add(session)
