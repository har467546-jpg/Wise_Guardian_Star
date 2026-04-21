from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.asset import Asset, AssetPort
from app.db.models.enums import FindingStatus, RiskSeverity
from app.db.models.risk_finding import RiskFinding, build_finding_identity_hash
from app.db.models.risk_rule import RiskRule
from app.db.models.snapshot import HostSnapshot
from app.db.session import SessionLocal
from app.rules import RuleDefinition, RuleEngine, RuleInput, RuleMatcher
from app.scanner.nmap_nse import filter_nse_results
from app.scanner.service_fingerprint import infer_service_aliases, infer_service_versions
from app.schemas.device_alert import DeviceAbnormalAlertEvent
from app.services.device_alert_service import publish_device_abnormal_alert
from app.verifiers import VerificationContext, VerificationResult, get_verifier

PROBE_SNAPSHOT_TYPE = "ssh_probe_baseline"
NETWORK_INITIAL_SNAPSHOT_TYPE = "network_initial"
DEVICE_ALERT_SEVERITIES = (
    RiskSeverity.HIGH,
    RiskSeverity.CRITICAL,
)


@dataclass(frozen=True, slots=True)
class PassiveRuleMatchRecord:
    port: AssetPort
    service_name: str
    service_version: str | None
    banner: str | None
    fingerprint: dict[str, Any]
    config: dict[str, Any]
    package: dict[str, Any]
    nse: dict[str, Any]
    rule: RuleDefinition
    evidence_source_level: str


@dataclass(frozen=True, slots=True)
class ActiveRuleCandidate:
    context: VerificationContext


@dataclass(slots=True)
class RiskVerificationSummary:
    asset_id: str
    asset_found: bool = True
    processed_port_count: int = 0
    passive_match_count: int = 0
    active_check_total: int = 0
    active_confirmed_count: int = 0
    active_rejected_count: int = 0
    active_inconclusive_count: int = 0
    active_error_count: int = 0
    active_skipped_count: int = 0
    created_finding_count: int = 0
    rule_results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_found": self.asset_found,
            "processed_port_count": self.processed_port_count,
            "passive_match_count": self.passive_match_count,
            "active_check_total": self.active_check_total,
            "active_confirmed_count": self.active_confirmed_count,
            "active_rejected_count": self.active_rejected_count,
            "active_inconclusive_count": self.active_inconclusive_count,
            "active_error_count": self.active_error_count,
            "active_skipped_count": self.active_skipped_count,
            "created_finding_count": self.created_finding_count,
            "rule_results": self.rule_results,
        }


class RiskVerificationService:
    def __init__(
        self,
        rule_engine: RuleEngine,
        session_factory: Callable[[], Session] = SessionLocal,
    ) -> None:
        self.rule_engine = rule_engine
        self.session_factory = session_factory
        self.connect_timeout_seconds = int(settings.RISK_ACTIVE_VERIFY_CONNECT_TIMEOUT_SECONDS)
        self.read_timeout_seconds = int(settings.RISK_ACTIVE_VERIFY_READ_TIMEOUT_SECONDS)
        self.max_concurrency = max(1, int(settings.RISK_ACTIVE_VERIFY_MAX_CONCURRENCY))

    def evaluate_asset(
        self,
        asset_id: str,
        *,
        progress_callback: Callable[[int, str, dict[str, Any]], None] | None = None,
    ) -> RiskVerificationSummary:
        summary = RiskVerificationSummary(asset_id=asset_id)
        with self.session_factory() as db:
            asset = db.get(Asset, asset_id)
            if not asset:
                summary.asset_found = False
                return summary

            current_snapshot = latest_snapshot(asset.snapshots)
            fallback_snapshot = current_snapshot or latest_available_snapshot(asset.snapshots)
            ruleset = self.rule_engine.loader.maybe_reload()
            active_rules_by_service: dict[str, list[RuleDefinition]] = defaultdict(list)
            for rule in ruleset.rules:
                if rule.enabled and rule.active_check:
                    active_rules_by_service[rule.service].append(rule)

            if progress_callback:
                progress_callback(10, "已载入资产与规则上下文", summary.to_dict())

            existing_alert_signatures = _load_open_device_alert_signatures(db, asset_id=asset.id)
            pending_alert_signatures: set[str] = set()
            pending_alert_findings: list[RiskFinding] = []
            existing_findings = list(getattr(asset, "findings", []) or [])
            existing_finding_map = _index_findings_by_identity(existing_findings)
            rule_db_map = _load_db_rule_map(db)

            passive_records: list[PassiveRuleMatchRecord] = []
            active_candidates: list[ActiveRuleCandidate] = []
            active_candidate_keys: set[tuple[str, str]] = set()
            rules_by_id = {rule.rule_id: rule for rule in ruleset.rules}
            summary.processed_port_count = len(asset.ports)

            for port in asset.ports:
                fingerprint = port.fingerprint_json if isinstance(port.fingerprint_json, dict) else {}
                banner = fingerprint.get("banner") if isinstance(fingerprint.get("banner"), str) else None
                nse = extract_nse_results(fingerprint)
                service_aliases = normalize_service_aliases(port)
                if not service_aliases:
                    continue
                for service_name in service_aliases:
                    config = extract_service_config(current_snapshot, service_name)
                    package = extract_service_package_context(current_snapshot, service_name, config)
                    service_version = resolve_service_version(port, service_name, current_snapshot)
                    passive_matches = RuleMatcher.match(
                        RuleInput(service=service_name, version=service_version, config=config, nse=nse, package=package),
                        ruleset.rules,
                    )

                    for match in passive_matches:
                        rule = rules_by_id.get(match.rule_id)
                        if rule is None:
                            continue
                        passive_records.append(
                            PassiveRuleMatchRecord(
                                port=port,
                                service_name=service_name,
                                service_version=service_version,
                                banner=banner,
                                fingerprint=fingerprint,
                                config=config,
                                package=package,
                                nse=nse,
                                rule=rule,
                                evidence_source_level=_resolve_passive_evidence_source_level(
                                    rule=rule,
                                    service_version=service_version,
                                    config=config,
                                    package=package,
                                    nse=nse,
                                    fingerprint=fingerprint,
                                ),
                            )
                        )
                        if rule.active_check and rule.active_check.trigger == "on_passive_match":
                            key = (port.id, rule.rule_id)
                            if key not in active_candidate_keys:
                                active_candidate_keys.add(key)
                                active_candidates.append(
                                    ActiveRuleCandidate(
                                        context=VerificationContext(
                                            asset=asset,
                                            port=port,
                                            service_name=service_name,
                                            service_version=service_version,
                                            banner=banner,
                                            fingerprint=fingerprint,
                                            config=config,
                                            latest_snapshot=fallback_snapshot,
                                            rule=rule,
                                            connect_timeout_seconds=self.connect_timeout_seconds,
                                            read_timeout_seconds=self.read_timeout_seconds,
                                            package=package,
                                        )
                                    )
                                )

                    for rule in active_rules_by_service.get(service_name, []):
                        if rule.active_check is None or rule.active_check.trigger != "on_service_present":
                            continue
                        key = (port.id, rule.rule_id)
                        if key in active_candidate_keys:
                            continue
                        active_candidate_keys.add(key)
                        active_candidates.append(
                            ActiveRuleCandidate(
                                context=VerificationContext(
                                    asset=asset,
                                    port=port,
                                    service_name=service_name,
                                    service_version=service_version,
                                    banner=banner,
                                    fingerprint=fingerprint,
                                    config=config,
                                    latest_snapshot=fallback_snapshot,
                                    rule=rule,
                                    connect_timeout_seconds=self.connect_timeout_seconds,
                                    read_timeout_seconds=self.read_timeout_seconds,
                                    package=package,
                                )
                            )
                        )

            summary.passive_match_count = len(passive_records)
            if progress_callback:
                progress_callback(35, "被动规则匹配完成", summary.to_dict())

            active_results = asyncio.run(self._run_active_checks(active_candidates)) if active_candidates else {}
            summary.active_check_total = len(active_candidates)
            self._count_active_results(summary, active_results)
            summary.rule_results = self._build_rule_results(active_candidates, active_results)

            if progress_callback:
                progress_callback(70, "主动探测执行完成", summary.to_dict())

            created_keys: set[tuple[str, str]] = set()
            seen_identity_hashes: set[str] = set()
            for record in passive_records:
                db_rule_id = rule_db_map.get(_rule_lookup_key(record.rule))
                result = active_results.get((record.port.id, record.rule.rule_id))
                if record.rule.active_check is None:
                    finding = self._build_finding(
                        record,
                        rule_id=db_rule_id,
                        verification_status="not_applicable",
                        match_source="passive",
                    )
                    finding = self._upsert_finding(db, existing_finding_map, finding)
                    summary.created_finding_count += 1
                    created_keys.add((record.port.id, record.rule.rule_id))
                    if finding.identity_hash:
                        seen_identity_hashes.add(finding.identity_hash)
                    _collect_pending_device_alert(
                        finding,
                        existing_signatures=existing_alert_signatures,
                        pending_signatures=pending_alert_signatures,
                        sink=pending_alert_findings,
                    )
                    continue

                trigger = record.rule.active_check.trigger
                if trigger == "on_passive_match":
                    verification_status = result.status if result else "skipped"
                    match_source = "active" if result and result.status == "confirmed" else "passive"
                    finding = self._build_finding(
                        record,
                        rule_id=db_rule_id,
                        verification_status=verification_status,
                        match_source=match_source,
                        verification_result=result,
                    )
                    finding = self._upsert_finding(db, existing_finding_map, finding)
                    summary.created_finding_count += 1
                    created_keys.add((record.port.id, record.rule.rule_id))
                    if finding.identity_hash:
                        seen_identity_hashes.add(finding.identity_hash)
                    _collect_pending_device_alert(
                        finding,
                        existing_signatures=existing_alert_signatures,
                        pending_signatures=pending_alert_signatures,
                        sink=pending_alert_findings,
                    )
                    continue

                if trigger == "on_service_present" and result and result.status == "confirmed":
                    finding = self._build_finding(
                        record,
                        rule_id=db_rule_id,
                        verification_status="confirmed",
                        match_source="active",
                        verification_result=result,
                    )
                    finding = self._upsert_finding(db, existing_finding_map, finding)
                    summary.created_finding_count += 1
                    created_keys.add((record.port.id, record.rule.rule_id))
                    if finding.identity_hash:
                        seen_identity_hashes.add(finding.identity_hash)
                    _collect_pending_device_alert(
                        finding,
                        existing_signatures=existing_alert_signatures,
                        pending_signatures=pending_alert_signatures,
                        sink=pending_alert_findings,
                    )

            for candidate in active_candidates:
                key = (candidate.context.port.id, candidate.context.rule.rule_id)
                result = active_results.get(key)
                if key in created_keys:
                    continue
                if candidate.context.rule.active_check is None or candidate.context.rule.active_check.trigger != "on_service_present":
                    continue

                db_rule_id = rule_db_map.get(_rule_lookup_key(candidate.context.rule))
                verification_result = result or _default_verification_result(candidate.context.rule)
                if verification_result.status == "confirmed":
                    finding = self._build_finding_from_active(
                        candidate.context,
                        verification_result,
                        rule_id=db_rule_id,
                    )
                    finding = self._upsert_finding(db, existing_finding_map, finding)
                    summary.created_finding_count += 1
                    created_keys.add(key)
                    if finding.identity_hash:
                        seen_identity_hashes.add(finding.identity_hash)
                    _collect_pending_device_alert(
                        finding,
                        existing_signatures=existing_alert_signatures,
                        pending_signatures=pending_alert_signatures,
                        sink=pending_alert_findings,
                    )
                    continue

                existing_finding = existing_finding_map.get(
                    _finding_identity_hash(
                        asset_id=candidate.context.asset.id,
                        asset_port_id=candidate.context.port.id,
                        yaml_rule_id=candidate.context.rule.rule_id,
                        evidence_scope=_resolve_evidence_scope(candidate.context.service_name, candidate.context.fingerprint),
                    )
                    or ""
                )
                if existing_finding is None:
                    continue
                finding = self._build_finding_from_active(
                    candidate.context,
                    verification_result,
                    rule_id=db_rule_id,
                )
                finding = self._upsert_finding(db, existing_finding_map, finding, create_if_missing=False)
                if finding and finding.identity_hash:
                    seen_identity_hashes.add(finding.identity_hash)

            _converge_missing_findings(existing_findings, seen_identity_hashes)

            db.commit()
            if pending_alert_findings:
                high_risk_findings = _count_open_high_risk_findings(db)
                for finding in pending_alert_findings:
                    publish_device_abnormal_alert(
                        _build_device_abnormal_alert_event(
                            finding,
                            asset=asset,
                            high_risk_findings=high_risk_findings,
                        )
                    )
            if progress_callback:
                progress_callback(90, "风险结果写入完成", summary.to_dict())
        return summary

    async def _run_active_checks(
        self,
        candidates: list[ActiveRuleCandidate],
    ) -> dict[tuple[str, str], VerificationResult]:
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _run_candidate(candidate: ActiveRuleCandidate) -> tuple[tuple[str, str], VerificationResult]:
            context = candidate.context
            key = (context.port.id, context.rule.rule_id)
            active_check = context.rule.active_check
            if active_check is None:
                return key, VerificationResult(status="skipped", summary="规则未配置主动探测", detector="none")

            verifier = get_verifier(active_check.detector)
            if verifier is None:
                return key, VerificationResult(
                    status="error",
                    summary=f"未注册的主动探测器：{active_check.detector}",
                    detector=active_check.detector,
                )

            async with semaphore:
                try:
                    result = await asyncio.wait_for(verifier(context), timeout=active_check.timeout_seconds)
                except asyncio.TimeoutError:
                    result = VerificationResult(
                        status="error",
                        summary="主动探测超时",
                        detector=active_check.detector,
                    )
                except Exception as exc:
                    result = VerificationResult(
                        status="error",
                        summary=f"主动探测异常：{exc}",
                        detector=active_check.detector,
                    )
            return key, result

        pairs = await asyncio.gather(*[_run_candidate(item) for item in candidates])
        return dict(pairs)

    @staticmethod
    def _count_active_results(
        summary: RiskVerificationSummary,
        active_results: dict[tuple[str, str], VerificationResult],
    ) -> None:
        for result in active_results.values():
            if result.status == "confirmed":
                summary.active_confirmed_count += 1
            elif result.status == "rejected":
                summary.active_rejected_count += 1
            elif result.status == "inconclusive":
                summary.active_inconclusive_count += 1
            elif result.status == "skipped":
                summary.active_skipped_count += 1
            elif result.status == "error":
                summary.active_error_count += 1

    @staticmethod
    def _build_rule_results(
        candidates: list[ActiveRuleCandidate],
        active_results: dict[tuple[str, str], VerificationResult],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for candidate in candidates:
            key = (candidate.context.port.id, candidate.context.rule.rule_id)
            result = active_results.get(key)
            if result is None:
                continue
            rows.append(
                {
                    "rule_id": candidate.context.rule.rule_id,
                    "rule_name": candidate.context.rule.name or candidate.context.rule.rule_id,
                    "service": candidate.context.service_name,
                    "port": candidate.context.port.port,
                    "detector": result.detector,
                    "trigger": candidate.context.rule.active_check.trigger if candidate.context.rule.active_check else None,
                    "status": result.status,
                    "summary": result.summary,
                }
            )
        return rows

    @staticmethod
    def _build_finding(
        record: PassiveRuleMatchRecord,
        *,
        rule_id: str | None,
        verification_status: str,
        match_source: str,
        verification_result: VerificationResult | None = None,
    ) -> RiskFinding:
        active_detector = record.rule.active_check.detector if record.rule.active_check else None
        active_trigger = record.rule.active_check.trigger if record.rule.active_check else None
        evidence_scope = _resolve_evidence_scope(record.service_name, record.fingerprint)
        return RiskFinding(
            asset_id=record.port.asset_id,
            asset_port_id=record.port.id,
            yaml_rule_id=record.rule.rule_id,
            identity_hash=_finding_identity_hash(
                asset_id=record.port.asset_id,
                asset_port_id=record.port.id,
                yaml_rule_id=record.rule.rule_id,
                evidence_scope=evidence_scope,
            ),
            rule_id=rule_id,
            severity=RiskSeverity(record.rule.severity),
            status=FindingStatus.OPEN,
            title=record.rule.name or record.rule.rule_id,
            description=record.rule.description,
            evidence_json={
                "yaml_rule_id": record.rule.rule_id,
                "evidence_scope": evidence_scope,
                "evidence_source_level": record.evidence_source_level,
                "match_source": match_source,
                "passive_match_types": build_passive_match_types(record.rule),
                "verification_status": verification_status,
                "verification_summary": verification_result.summary if verification_result else "规则未配置主动探测",
                "active_detector": active_detector,
                "active_trigger": active_trigger,
                "active_evidence": verification_result.evidence if verification_result else {},
                "nse_match": bool(record.rule.nse_conditions),
                "nse_evidence": build_nse_evidence(record.rule, record.nse),
                "nse_scripts": build_nse_scripts(record.rule, record.nse),
                "service_name": record.service_name,
                "service_version": record.service_version,
                "port": record.port.port,
                "banner": record.banner,
                "config": record.config,
                "package": record.package,
            },
        )

    @staticmethod
    def _build_finding_from_active(
        context: VerificationContext,
        verification_result: VerificationResult,
        *,
        rule_id: str | None,
    ) -> RiskFinding:
        evidence_scope = _resolve_evidence_scope(context.service_name, context.fingerprint)
        return RiskFinding(
            asset_id=context.asset.id,
            asset_port_id=context.port.id,
            yaml_rule_id=context.rule.rule_id,
            identity_hash=_finding_identity_hash(
                asset_id=context.asset.id,
                asset_port_id=context.port.id,
                yaml_rule_id=context.rule.rule_id,
                evidence_scope=evidence_scope,
            ),
            rule_id=rule_id,
            severity=RiskSeverity(context.rule.severity),
            status=FindingStatus.OPEN,
            title=context.rule.name or context.rule.rule_id,
            description=context.rule.description,
            evidence_json={
                "yaml_rule_id": context.rule.rule_id,
                "evidence_scope": evidence_scope,
                "evidence_source_level": _resolve_active_evidence_source_level(context),
                "match_source": "active_only",
                "passive_match_types": build_passive_match_types(context.rule),
                "verification_status": verification_result.status,
                "verification_summary": verification_result.summary,
                "active_detector": verification_result.detector,
                "active_trigger": context.rule.active_check.trigger if context.rule.active_check else None,
                "active_evidence": verification_result.evidence,
                "nse_match": bool(context.rule.nse_conditions),
                "nse_evidence": build_nse_evidence(context.rule, extract_nse_results(context.fingerprint)),
                "nse_scripts": build_nse_scripts(context.rule, extract_nse_results(context.fingerprint)),
                "service_name": context.service_name,
                "service_version": context.service_version,
                "port": context.port.port,
                "banner": context.banner,
                "config": context.config,
                "package": context.package,
            },
        )

    @staticmethod
    def _upsert_finding(
        db: Session,
        existing_finding_map: dict[str, RiskFinding],
        candidate: RiskFinding,
        *,
        create_if_missing: bool = True,
    ) -> RiskFinding | None:
        identity_hash = candidate.identity_hash
        if not identity_hash:
            if create_if_missing:
                db.add(candidate)
            return candidate if create_if_missing else None

        existing = existing_finding_map.get(identity_hash)
        if existing is None:
            if not create_if_missing:
                return None
            existing_finding_map[identity_hash] = candidate
            db.add(candidate)
            return candidate

        existing.yaml_rule_id = candidate.yaml_rule_id
        existing.identity_hash = identity_hash
        existing.rule_id = candidate.rule_id
        existing.asset_port_id = candidate.asset_port_id
        existing.severity = candidate.severity
        existing.status = FindingStatus.OPEN
        existing.title = candidate.title
        existing.description = candidate.description
        existing.evidence_json = candidate.evidence_json
        existing.resolved_at = None
        return existing


def _load_open_device_alert_signatures(db: Session, *, asset_id: str) -> set[str]:
    if not hasattr(db, "scalars"):
        return set()
    stmt = select(RiskFinding).where(
        RiskFinding.asset_id == asset_id,
        RiskFinding.status == FindingStatus.OPEN,
        RiskFinding.severity.in_(DEVICE_ALERT_SEVERITIES),
    )
    try:
        findings = db.scalars(stmt).all()
    except Exception:
        return set()
    return {_build_device_alert_signature(item) for item in findings}


def _collect_pending_device_alert(
    finding: RiskFinding,
    *,
    existing_signatures: set[str],
    pending_signatures: set[str],
    sink: list[RiskFinding],
) -> None:
    _ensure_finding_identity(finding)
    if finding.status != FindingStatus.OPEN or finding.severity not in DEVICE_ALERT_SEVERITIES:
        return
    signature = _build_device_alert_signature(finding)
    if not signature or signature in existing_signatures or signature in pending_signatures:
        return
    pending_signatures.add(signature)
    sink.append(finding)


def _build_device_alert_signature(finding: RiskFinding) -> str:
    evidence = finding.evidence()
    yaml_rule_id = str(finding.resolved_yaml_rule_id() or "").strip()
    service_name = str(evidence.get("service_name") or "").strip()
    evidence_scope = str(evidence.get("evidence_scope") or "").strip()
    port = str(evidence.get("port") or "").strip()
    severity = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity)
    return "|".join(
        [
            str(finding.asset_id or "").strip(),
            str(finding.asset_port_id or "").strip(),
            yaml_rule_id,
            service_name,
            evidence_scope,
            port,
            severity,
        ]
    )


def _count_open_high_risk_findings(db: Session) -> int:
    if not hasattr(db, "scalar"):
        return 0
    stmt = select(func.count(RiskFinding.id)).where(
        RiskFinding.status == FindingStatus.OPEN,
        RiskFinding.severity.in_(DEVICE_ALERT_SEVERITIES),
    )
    try:
        return int(db.scalar(stmt) or 0)
    except Exception:
        return 0


def _build_device_abnormal_alert_event(
    finding: RiskFinding,
    *,
    asset: Asset,
    high_risk_findings: int,
) -> DeviceAbnormalAlertEvent:
    return DeviceAbnormalAlertEvent(
        finding_id=finding.id,
        asset_id=finding.asset_id,
        asset_ip=str(asset.ip),
        asset_hostname=asset.hostname,
        severity=finding.severity,
        title=finding.title,
        message=f"{_format_device_alert_asset_label(asset)} 新增{_format_device_alert_severity(finding.severity)}异常：{finding.title}",
        route=f"/risks/{finding.id}",
        navigate_with_go=False,
        high_risk_findings=high_risk_findings,
        detected_at=finding.detected_at,
    )


def _format_device_alert_asset_label(asset: Asset) -> str:
    hostname = str(asset.hostname or "").strip()
    ip = str(asset.ip)
    if not hostname:
        return ip
    return f"{ip}（{hostname}）"


def _format_device_alert_severity(severity: RiskSeverity) -> str:
    labels = {
        RiskSeverity.CRITICAL: "严重",
        RiskSeverity.HIGH: "高危",
        RiskSeverity.MEDIUM: "中危",
        RiskSeverity.LOW: "低危",
    }
    return labels.get(severity, "高危")


def _ensure_finding_identity(finding: RiskFinding) -> None:
    if not getattr(finding, "id", None):
        finding.id = str(uuid4())
    if not getattr(finding, "detected_at", None):
        finding.detected_at = datetime.now(timezone.utc)
    yaml_rule_id = finding.resolved_yaml_rule_id()
    if yaml_rule_id and not finding.yaml_rule_id:
        finding.yaml_rule_id = yaml_rule_id
    if not finding.identity_hash:
        finding.identity_hash = _finding_identity_hash(
            asset_id=finding.asset_id,
            asset_port_id=finding.asset_port_id,
            yaml_rule_id=finding.resolved_yaml_rule_id(),
            evidence_scope=finding.resolved_evidence_scope(),
        )


def latest_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    if not snapshots:
        return None
    filtered = [item for item in snapshots if not is_probe_snapshot(item)]
    if not filtered:
        return None
    return max(filtered, key=lambda item: item.collected_at)


def latest_available_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    if not snapshots:
        return None
    return max(snapshots, key=lambda item: item.collected_at)


def is_probe_snapshot(snapshot: HostSnapshot) -> bool:
    for payload in [snapshot.error_json, snapshot.services_json, snapshot.software_json]:
        if isinstance(payload, dict) and payload.get("snapshot_type") in {PROBE_SNAPSHOT_TYPE, NETWORK_INITIAL_SNAPSHOT_TYPE}:
            return True
    return False


def normalize_service_name(port: AssetPort) -> str | None:
    aliases = normalize_service_aliases(port)
    return aliases[0] if aliases else None


def normalize_service_aliases(port: AssetPort) -> list[str]:
    fingerprint = port.fingerprint_json if isinstance(port.fingerprint_json, dict) else {}
    record = dict(fingerprint)
    record.setdefault("port", port.port)
    record.setdefault("service_name", port.service_name)
    record.setdefault("service_version", port.service_version)

    aliases: list[str] = []
    seen: set[str] = set()
    stored_aliases = fingerprint.get("service_aliases")
    if isinstance(stored_aliases, list):
        for item in stored_aliases:
            normalized = _normalize_service_alias(item)
            if normalized and normalized not in seen:
                aliases.append(normalized)
                seen.add(normalized)
    for item in infer_service_aliases(record):
        normalized = _normalize_service_alias(item)
        if normalized and normalized not in seen:
            aliases.append(normalized)
            seen.add(normalized)
    return aliases


def extract_service_config(snapshot: HostSnapshot | None, service_name: str) -> dict[str, Any]:
    if snapshot is None:
        return {}

    normalized = service_name.lower()
    for payload in [snapshot.services_json, snapshot.software_json, snapshot.error_json]:
        resolved = resolve_config_from_payload(payload, normalized)
        if resolved:
            return resolved
    return {}


SERVICE_PACKAGE_ALIASES: dict[str, tuple[str, ...]] = {
    "ssh": ("openssh-server", "openssh", "sshd", "ssh"),
    "sudo": ("sudo",),
    "polkit": ("policykit-1", "polkit"),
    "nmap": ("nmap",),
    "screen": ("screen",),
    "redis": ("redis-server", "redis"),
    "vsftpd": ("vsftpd",),
    "samba": ("samba", "smbd"),
    "unrealircd": ("unrealircd",),
    "distccd": ("distcc", "distccd"),
    "apache": ("apache2", "httpd", "apache"),
    "tomcat": ("tomcat",),
    "postgresql": ("postgresql", "postgres"),
    "php": ("php",),
    "bind": ("bind9", "bind", "named"),
    "phpmyadmin": ("phpmyadmin",),
    "twiki": ("twiki",),
    "nginx": ("nginx",),
    "mysql": ("mysql-server", "mysql", "mariadb-server", "mariadb"),
    "docker": ("docker", "docker.io", "docker-ce", "moby-engine"),
    "systemd": ("systemd",),
    "cron": ("cron", "cronie", "fcron", "vixie-cron"),
    "logrotate": ("logrotate",),
}


def resolve_service_version(port: AssetPort, service_name: str, snapshot: HostSnapshot | None) -> str | None:
    if service_name == "linux-kernel" and snapshot is not None:
        return snapshot.kernel_version
    versions = resolve_service_versions(port, snapshot)
    if service_name in versions:
        return versions[service_name]
    return extract_service_package_version(snapshot, service_name)


def resolve_service_versions(port: AssetPort, snapshot: HostSnapshot | None) -> dict[str, str]:
    fingerprint = port.fingerprint_json if isinstance(port.fingerprint_json, dict) else {}
    record = dict(fingerprint)
    record.setdefault("port", port.port)
    record.setdefault("service_name", port.service_name)
    record.setdefault("service_version", port.service_version)
    versions = infer_service_versions(record)
    for alias in normalize_service_aliases(port):
        if alias in versions:
            continue
        package_version = extract_service_package_version(snapshot, alias)
        if package_version:
            versions[alias] = package_version
    return versions


def extract_service_package_version(snapshot: HostSnapshot | None, service_name: str) -> str | None:
    metadata = extract_service_package_metadata(snapshot, service_name)
    if not metadata:
        return None
    version = metadata.get("version")
    return str(version).strip() if isinstance(version, str) and version.strip() else None


def extract_service_package_context(
    snapshot: HostSnapshot | None,
    service_name: str,
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config if isinstance(config, dict) else {}
    metadata = extract_service_package_metadata(snapshot, service_name) or {}
    manager = _first_non_empty(config.get("package_manager"), metadata.get("manager"))
    name = _first_non_empty(config.get("package_name"), metadata.get("name")).lower()
    version = _first_non_empty(config.get("package_version_raw"), metadata.get("version"))
    distro = _first_non_empty(config.get("distro_name")).lower()
    release = _first_non_empty(config.get("distro_release"))
    if (not distro or not release) and snapshot is not None:
        normalized_distro, normalized_release = _normalize_snapshot_distro(snapshot)
        distro = distro or normalized_distro or ""
        release = release or normalized_release or ""
    if not any([manager, name, version, distro, release]):
        return {}
    return {
        "manager": manager.lower(),
        "name": name,
        "version": version,
        "distro": distro,
        "release": release,
    }


def extract_service_package_metadata(snapshot: HostSnapshot | None, service_name: str) -> dict[str, Any] | None:
    if snapshot is None or not isinstance(snapshot.software_json, dict):
        return None
    packages = snapshot.software_json.get("packages")
    if not isinstance(packages, list):
        return None

    aliases = SERVICE_PACKAGE_ALIASES.get(service_name.lower(), ())
    if not aliases:
        return None

    best_match: tuple[int, dict[str, Any]] | None = None
    for item in packages:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip().lower()
        if not name:
            continue
        score = _score_package_name(name, aliases)
        if score is None:
            continue
        if best_match is None or score < best_match[0]:
            best_match = (score, item)
    return dict(best_match[1]) if best_match else None


def _score_package_name(name: str, aliases: tuple[str, ...]) -> int | None:
    for alias in aliases:
        if name == alias:
            return 0
    for alias in aliases:
        if name.startswith(f"{alias}-") or name.startswith(f"{alias}:"):
            return 1
    for alias in aliases:
        if alias in name:
            return 2
    return None


def resolve_config_from_payload(payload: Any, service_name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    for key in ("config_by_service", "service_configs", "configs"):
        nested = payload.get(key)
        if isinstance(nested, dict):
            direct = nested.get(service_name)
            if isinstance(direct, dict):
                return direct

    services = payload.get("services")
    if isinstance(services, list):
        for item in services:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "")).strip().lower()
            if name != service_name:
                continue
            config = item.get("config")
            if isinstance(config, dict):
                return config

    return {}


def extract_nse_results(fingerprint: dict[str, Any]) -> dict[str, Any]:
    nse = fingerprint.get("nse")
    if isinstance(nse, dict):
        return nse
    return {}


def build_passive_match_types(rule: RuleDefinition) -> list[str]:
    match_types: list[str] = []
    if rule.version_constraint:
        match_types.append("version")
    if rule.config_conditions:
        match_types.append("config")
    if rule.nse_conditions:
        match_types.append("nse")
    if rule.package_conditions:
        match_types.append("package")
    return match_types


def build_nse_evidence(rule: RuleDefinition, nse: dict[str, Any]) -> dict[str, Any]:
    if rule.nse_conditions:
        scripts = {key.split(".", 1)[0] for key in rule.nse_conditions if isinstance(key, str) and key.strip()}
        return filter_nse_results(nse, scripts)

    hit_scripts = {
        script_id
        for script_id, payload in nse.items()
        if isinstance(script_id, str) and isinstance(payload, dict) and payload.get("hit") is True
    }
    return filter_nse_results(nse, hit_scripts)


def build_nse_scripts(rule: RuleDefinition, nse: dict[str, Any]) -> list[str]:
    evidence = build_nse_evidence(rule, nse)
    return sorted(evidence)


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if cleaned:
            return cleaned
    return ""


def _normalize_service_alias(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _resolve_evidence_scope(service_name: str, fingerprint: dict[str, Any]) -> str:
    if service_name in {"linux-kernel", "linux-host", "sudo", "polkit"}:
        return "authorized_local"
    if isinstance(fingerprint, dict) and str(fingerprint.get("authorization_scope") or "").strip().lower() == "authorized_local":
        return "authorized_local"
    return "network"


def _default_verification_result(rule: RuleDefinition) -> VerificationResult:
    detector = rule.active_check.detector if rule.active_check else "none"
    return VerificationResult(status="skipped", summary="主动探测未执行", detector=detector)


def _load_db_rule_map(db: Session) -> dict[tuple[str, str, str], str]:
    if not hasattr(db, "scalars"):
        return {}
    try:
        rows = db.scalars(select(RiskRule)).all()
    except Exception:
        return {}
    result: dict[tuple[str, str, str], str] = {}
    for row in rows:
        key = (
            str(row.service_name or "").strip().lower(),
            str(row.title or "").strip(),
            str(row.description or "").strip(),
        )
        if all(key) and row.id:
            result.setdefault(key, row.id)
    return result


def _rule_lookup_key(rule: RuleDefinition) -> tuple[str, str, str]:
    return (
        str(rule.service or "").strip().lower(),
        str(rule.name or rule.rule_id or "").strip(),
        str(rule.description or "").strip(),
    )


def _index_findings_by_identity(findings: list[RiskFinding]) -> dict[str, RiskFinding]:
    result: dict[str, RiskFinding] = {}
    for finding in findings:
        _ensure_finding_identity(finding)
        if not finding.identity_hash:
            continue
        current = result.get(finding.identity_hash)
        if current is None:
            result[finding.identity_hash] = finding
            continue
        current_is_open = current.status == FindingStatus.OPEN
        finding_is_open = finding.status == FindingStatus.OPEN
        if finding_is_open and not current_is_open:
            result[finding.identity_hash] = finding
            continue
        if finding.detected_at and current.detected_at and finding.detected_at < current.detected_at:
            result[finding.identity_hash] = finding
    return result


def _converge_missing_findings(existing_findings: list[RiskFinding], seen_identity_hashes: set[str]) -> None:
    resolved_at = datetime.now(timezone.utc)
    for finding in existing_findings:
        _ensure_finding_identity(finding)
        if not finding.identity_hash or finding.identity_hash in seen_identity_hashes:
            continue
        if finding.status == FindingStatus.OPEN:
            finding.status = FindingStatus.FIXED
            finding.resolved_at = resolved_at


def _finding_identity_hash(
    *,
    asset_id: str | None,
    asset_port_id: str | None,
    yaml_rule_id: str | None,
    evidence_scope: str | None,
) -> str | None:
    return build_finding_identity_hash(
        asset_id=asset_id,
        asset_port_id=asset_port_id,
        yaml_rule_id=yaml_rule_id,
        evidence_scope=evidence_scope,
    )


def _resolve_passive_evidence_source_level(
    *,
    rule: RuleDefinition,
    service_version: str | None,
    config: dict[str, Any],
    package: dict[str, Any],
    nse: dict[str, Any],
    fingerprint: dict[str, Any],
) -> str:
    sources: set[str] = set()
    if rule.config_conditions or rule.package_conditions or config or package:
        if config or package:
            sources.add("host_snapshot")
    if rule.version_constraint and service_version:
        if package and service_version == str(package.get("version") or "").strip():
            sources.add("host_snapshot")
        else:
            sources.add("network_fingerprint")
    if rule.nse_conditions or nse or fingerprint:
        sources.add("network_fingerprint")
    if sources == {"host_snapshot"}:
        return "host_snapshot"
    if sources == {"network_fingerprint"}:
        return "network_fingerprint"
    if len(sources) > 1:
        return "mixed"
    return "network_fingerprint"


def _resolve_active_evidence_source_level(context: VerificationContext) -> str:
    return _resolve_passive_evidence_source_level(
        rule=context.rule,
        service_version=context.service_version,
        config=context.config,
        package=context.package,
        nse=extract_nse_results(context.fingerprint),
        fingerprint=context.fingerprint,
    )


def _normalize_snapshot_distro(snapshot: HostSnapshot) -> tuple[str | None, str | None]:
    raw_sources = [snapshot.os_release]
    for payload in [snapshot.services_json, snapshot.software_json, snapshot.error_json]:
        if not isinstance(payload, dict):
            continue
        for key in ("os_release", "pretty_name", "distribution", "distro"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                raw_sources.append(value)
    for value in raw_sources:
        normalized = _normalize_distro_string(value)
        if normalized != (None, None):
            return normalized
    return None, None


def _normalize_distro_string(raw: str | None) -> tuple[str | None, str | None]:
    from app.utils.versioning import normalize_linux_distro_text

    return normalize_linux_distro_text(raw)


RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "risk_rules.yaml"
