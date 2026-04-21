from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.db.models.asset import Asset, AssetTag
from app.db.models.enums import FindingStatus
from app.db.models.finding_governance import FindingGovernance
from app.db.models.finding_waiver import FindingWaiver
from app.db.models.risk_finding import RiskFinding
from app.db.models.user import User
from app.rules.rule_matcher import RuleDefinition
from app.services.vuln_intel_service import build_rule_intel_summary_map

_SEVERITY_BASE_SCORE = {
    "low": 10,
    "medium": 30,
    "high": 60,
    "critical": 85,
}


@dataclass(frozen=True, slots=True)
class FindingPrioritySnapshot:
    priority_score: int
    priority_tier: str
    priority_reason: dict[str, Any]
    sla_due_at: datetime
    waiver_status: str


def ensure_governance_for_findings(db: Session, findings: list[RiskFinding], *, rules: list[RuleDefinition]) -> dict[str, FindingGovernance]:
    if not findings:
        return {}
    refresh_expired_waivers(db)
    rule_map = {rule.rule_id: rule for rule in rules}
    can_query_runtime = hasattr(db, "execute") or hasattr(db, "scalars")
    can_persist = hasattr(db, "add") and hasattr(db, "flush")
    intel_summaries = build_rule_intel_summary_map(db, list(rule_map.values())) if can_query_runtime else {}
    result: dict[str, FindingGovernance] = {}
    for finding in findings:
        snapshot = _build_priority_snapshot(
            finding,
            rule=rule_map.get(_yaml_rule_id(finding) or ""),
            intel_summary=intel_summaries.get(_yaml_rule_id(finding) or ""),
            waivers=getattr(finding, "waivers", []) or [],
        )
        governance = getattr(finding, "governance", None) or FindingGovernance(finding_id=str(getattr(finding, "id", "") or ""))
        asset = getattr(finding, "asset", None)
        if governance.owner_id is None and asset and getattr(asset, "owner_id", None):
            governance.owner_id = asset.owner_id
        governance.priority_score = snapshot.priority_score
        governance.priority_tier = snapshot.priority_tier
        governance.priority_reason_json = snapshot.priority_reason
        governance.sla_due_at = snapshot.sla_due_at
        finding_status = getattr(finding, "status", None)
        governance.status = "waived" if snapshot.waiver_status != "none" else finding_status.value if hasattr(finding_status, "value") else str(finding_status)
        if getattr(governance, "updated_at", None) is None:
            governance.updated_at = datetime.now(UTC)
        finding.governance = governance
        if can_persist:
            db.add(governance)
        finding_id = str(getattr(finding, "id", "") or "")
        if finding_id:
            result[finding_id] = governance
    if can_persist:
        db.flush()
    return result


def assign_finding_owner(
    db: Session,
    finding_id: str,
    *,
    actor: User,
    owner_id: str | None = None,
    rules: list[RuleDefinition],
) -> FindingGovernance:
    finding = _get_finding_with_context(db, finding_id)
    if finding is None:
        raise LookupError("风险发现不存在")
    target_owner_id = owner_id or actor.id
    owner = db.get(User, target_owner_id)
    if owner is None or not owner.is_active:
        raise LookupError("目标责任人不存在或已停用")
    governance = ensure_governance_for_findings(db, [finding], rules=rules).get(finding.id) or finding.governance or FindingGovernance(finding_id=finding.id)
    governance.owner_id = target_owner_id
    governance.updated_at = datetime.now(UTC)
    db.add(governance)
    db.commit()
    db.refresh(governance)
    return governance


def create_finding_waiver(
    db: Session,
    finding_id: str,
    *,
    actor: User,
    waiver_type: str,
    reason: str,
    expires_at: datetime | None = None,
    rules: list[RuleDefinition],
) -> FindingWaiver:
    finding = _get_finding_with_context(db, finding_id)
    if finding is None:
        raise LookupError("风险发现不存在")
    normalized_type = str(waiver_type or "").strip()
    if normalized_type not in {"false_positive", "accepted_risk", "temporary_exception"}:
        raise ValueError("不支持的豁免类型")
    if normalized_type == "temporary_exception" and expires_at is None:
        raise ValueError("临时例外必须设置到期时间")
    waiver = FindingWaiver(
        finding_id=finding.id,
        waiver_type=normalized_type,
        reason=reason.strip(),
        expires_at=expires_at,
        approved_by=actor.id,
        status="active",
    )
    db.add(waiver)
    db.flush()
    ensure_governance_for_findings(db, [finding], rules=rules)
    db.commit()
    db.refresh(waiver)
    return waiver


def recalculate_finding_priority(db: Session, finding_id: str, *, rules: list[RuleDefinition]) -> FindingGovernance:
    finding = _get_finding_with_context(db, finding_id)
    if finding is None:
        raise LookupError("风险发现不存在")
    governance = ensure_governance_for_findings(db, [finding], rules=rules).get(finding.id)
    db.commit()
    if governance is None:
        raise RuntimeError("未能生成风险治理记录")
    db.refresh(governance)
    return governance


def recalculate_open_finding_priorities(db: Session, *, rules: list[RuleDefinition]) -> int:
    findings = db.scalars(
        select(RiskFinding)
        .options(
            joinedload(RiskFinding.asset).joinedload(Asset.tags).joinedload(AssetTag.tag),
            joinedload(RiskFinding.asset).joinedload(Asset.owner),
            joinedload(RiskFinding.waivers),
            joinedload(RiskFinding.governance),
        )
        .where(RiskFinding.status == FindingStatus.OPEN)
    ).unique().all()
    ensure_governance_for_findings(db, findings, rules=rules)
    db.commit()
    return len(findings)


def refresh_expired_waivers(db: Session) -> int:
    if not hasattr(db, "scalars"):
        return 0
    now = datetime.now(UTC)
    items = db.scalars(
        select(FindingWaiver).where(
            FindingWaiver.status == "active",
            FindingWaiver.expires_at.is_not(None),
            FindingWaiver.expires_at < now,
        )
    ).all()
    for item in items:
        item.status = "expired"
        item.updated_at = now
        if hasattr(db, "add"):
            db.add(item)
    if items and hasattr(db, "flush"):
        db.flush()
    return len(items)


def resolve_waiver_status(finding: RiskFinding) -> str:
    active = _active_waiver(getattr(finding, "waivers", []) or [])
    if active is None:
        return "none"
    return active.waiver_type if active.status == "active" else "none"


def _build_priority_snapshot(
    finding: RiskFinding,
    *,
    rule: RuleDefinition | None,
    intel_summary: Any,
    waivers: list[FindingWaiver],
) -> FindingPrioritySnapshot:
    severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity or "").strip().lower()
    score = _SEVERITY_BASE_SCORE.get(severity, 10)
    reasons: list[str] = [f"severity={severity}"]
    if getattr(intel_summary, "kev_flag", False):
        score += 20
        reasons.append("kev")
    epss_score = getattr(intel_summary, "max_epss", None)
    if isinstance(epss_score, (int, float)) and epss_score >= 0.5:
        score += 10
        reasons.append("epss>=0.5")
    elif isinstance(epss_score, (int, float)) and epss_score >= 0.1:
        score += 5
        reasons.append("epss>=0.1")
    if _is_exposed_finding(finding, rule=rule):
        score += 10
        reasons.append("exposed")
    asset_score = _asset_value_score(finding)
    if asset_score:
        score += asset_score
        reasons.append(f"asset_value+{asset_score}")
    if _is_actively_confirmed(finding):
        score += 5
        reasons.append("active_confirmed")
    score = min(100, score)
    tier = _priority_tier(score)
    active_waiver = _active_waiver(waivers)
    waiver_status = active_waiver.waiver_type if active_waiver is not None else "none"
    return FindingPrioritySnapshot(
        priority_score=score,
        priority_tier=tier,
        priority_reason={
            "reasons": reasons,
            "kev_flag": bool(getattr(intel_summary, "kev_flag", False)),
            "epss_score": epss_score,
            "asset_value_score": asset_score,
            "verification_status": str((finding.evidence_json or {}).get("verification_status") or ""),
            "waiver_status": waiver_status,
        },
        sla_due_at=_sla_due_at(finding, tier),
        waiver_status=waiver_status,
    )


def _asset_value_score(finding: RiskFinding) -> int:
    asset = getattr(finding, "asset", None)
    if asset is None:
        return 0
    asset_tags = getattr(asset, "tags", []) or []
    tag_names = {str(binding.tag.name or "").strip().lower() for binding in asset_tags if getattr(binding, "tag", None)}
    if {"high-value", "critical", "production"} & tag_names:
        return 10
    if getattr(asset, "owner_id", None) or tag_names:
        return 5
    return 0


def _is_exposed_finding(finding: RiskFinding, *, rule: RuleDefinition | None) -> bool:
    evidence = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
    port = evidence.get("port")
    if isinstance(port, int) and port in {21, 22, 80, 443, 445, 8080, 8443, 3306, 5432, 6379, 9200, 27017, 3389}:
        return True
    rule_id = str(evidence.get("yaml_rule_id") or "").strip().lower()
    if any(token in rule_id for token in ("exposed", "exposure", "unauthorized", "manager", "path")):
        return True
    if rule is not None and "high-value" in {str(tag or "").strip().lower() for tag in (rule.tags or [])}:
        return True
    return False


def _is_actively_confirmed(finding: RiskFinding) -> bool:
    evidence = finding.evidence_json if isinstance(finding.evidence_json, dict) else {}
    return str(evidence.get("verification_status") or "").strip().lower() == "confirmed"


def _priority_tier(score: int) -> str:
    if score >= 90:
        return "P1"
    if score >= 70:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def _sla_due_at(finding: RiskFinding, priority_tier: str) -> datetime:
    detected_at = finding.detected_at or datetime.now(UTC)
    delta = {
        "P1": timedelta(hours=24),
        "P2": timedelta(hours=72),
        "P3": timedelta(days=14),
        "P4": timedelta(days=30),
    }.get(priority_tier, timedelta(days=30))
    return detected_at + delta


def _yaml_rule_id(finding: RiskFinding) -> str | None:
    return finding.resolved_yaml_rule_id()


def _active_waiver(waivers: list[FindingWaiver] | None) -> FindingWaiver | None:
    if not waivers:
        return None
    now = datetime.now(UTC)
    active_items = [
        item
        for item in waivers
        if str(item.status or "").strip().lower() == "active" and (item.expires_at is None or item.expires_at >= now)
    ]
    if not active_items:
        return None
    return max(active_items, key=lambda item: item.created_at)


def _get_finding_with_context(db: Session, finding_id: str) -> RiskFinding | None:
    return db.scalars(
        select(RiskFinding)
        .options(
            joinedload(RiskFinding.asset).joinedload(Asset.tags).joinedload(AssetTag.tag),
            joinedload(RiskFinding.asset).joinedload(Asset.owner),
            joinedload(RiskFinding.waivers),
            joinedload(RiskFinding.governance),
        )
        .where(RiskFinding.id == finding_id)
    ).unique().first()
