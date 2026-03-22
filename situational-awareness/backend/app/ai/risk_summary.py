from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.ai.recommendation_engine import RecommendationEngine
from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import FindingStatus
from app.db.models.risk_finding import RiskFinding

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_SCORE = {"critical": 100, "high": 40, "medium": 10, "low": 3}
CATEGORY_PRIORITY = ["database", "cache", "web", "admin"]
CATEGORY_LABELS = {
    "database": "Database node",
    "cache": "Cache/queue node",
    "web": "Web service node",
    "admin": "Remote administration node",
}
WEB_PORTS = {80, 443, 8080, 8443}
DATABASE_PORTS = {3306}
CACHE_PORTS = {6379}
ADMIN_PORTS = {22}


@dataclass(slots=True)
class _AssetAnalysisContext:
    asset: Asset
    findings: list[RiskFinding]
    open_findings: list[RiskFinding]


class RiskSummaryService:
    def __init__(self, recommendation_engine: RecommendationEngine | None = None) -> None:
        self.recommendation_engine = recommendation_engine or RecommendationEngine()

    def summarize_asset(self, db: Session, asset_id: str) -> dict[str, Any]:
        asset = db.scalars(
            select(Asset)
            .where(Asset.id == asset_id)
            .options(
                joinedload(Asset.ports),
                joinedload(Asset.findings),
                joinedload(Asset.snapshots),
            )
        ).unique().one_or_none()
        if not asset:
            raise ValueError(f"资产不存在：{asset_id}")

        context = self._build_asset_context(asset)
        return self._asset_analysis(context)

    def summarize_job(self, db: Session, job_id: str) -> dict[str, Any]:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            raise ValueError(f"job not found: {job_id}")

        ips = [host.get("ip") for host in job.summary_json.get("hosts", []) if isinstance(host, dict) and host.get("ip")]
        assets: list[Asset] = []
        if ips:
            assets = db.scalars(
                select(Asset)
                .where(Asset.ip.in_(ips))
                .options(
                    joinedload(Asset.ports),
                    joinedload(Asset.findings),
                    joinedload(Asset.snapshots),
                )
            ).unique().all()

        asset_analyses = [self._asset_analysis(self._build_asset_context(asset)) for asset in assets]
        open_findings = [finding for asset in assets for finding in asset.findings if finding.status == FindingStatus.OPEN]
        severity_counts = self._severity_counts(open_findings)
        priority = self._priority_from_findings(open_findings, assets)
        top_assets = sorted(
            [
                {
                    "asset_id": item["asset"]["id"],
                    "ip": item["asset"]["ip"],
                    "hostname": item["asset"]["hostname"],
                    "priority": item["risk_priority"]["level"],
                    "score": item["risk_priority"]["score"],
                    "highest_severity": item["risk_summary"]["highest_severity"],
                    "open_findings": item["risk_summary"]["open_findings"],
                }
                for item in asset_analyses
            ],
            key=lambda item: (-item["score"], item["ip"]),
        )[:5]

        return {
            "job": {
                "id": job.id,
                "cidr": str(job.cidr),
                "label": job.label,
                "asset_count": len(assets),
            },
            "risk_summary": {
                "highest_severity": self._highest_severity(open_findings),
                "total_findings": len(open_findings),
                "severity_counts": severity_counts,
                "top_assets": top_assets,
            },
            "risk_priority": priority,
            "recommendations": self.recommendation_engine.build(open_findings),
            "asset_summaries": [
                {
                    "asset": item["asset"],
                    "risk_summary": item["risk_summary"],
                    "risk_priority": item["risk_priority"],
                    "usage_hypothesis": item["usage_hypothesis"],
                }
                for item in asset_analyses
            ],
        }

    def _build_asset_context(self, asset: Asset) -> _AssetAnalysisContext:
        findings = list(asset.findings)
        open_findings = [item for item in findings if item.status == FindingStatus.OPEN]
        return _AssetAnalysisContext(asset=asset, findings=findings, open_findings=open_findings)

    def _asset_analysis(self, context: _AssetAnalysisContext) -> dict[str, Any]:
        asset = context.asset
        severity_counts = self._severity_counts(context.open_findings)
        priority = self._priority_from_findings(context.open_findings, [asset])
        usage = self._usage_hypothesis(asset)
        key_findings = self._key_findings(context.open_findings)

        return {
            "asset": {
                "id": asset.id,
                "ip": str(asset.ip),
                "hostname": asset.hostname,
                "os_name": asset.os_name,
            },
            "services": [
                {
                    "port": port.port,
                    "service_name": port.service_name,
                    "service_version": port.service_version,
                    "state": port.state,
                }
                for port in sorted(asset.ports, key=lambda item: item.port)
            ],
            "risk_summary": {
                "highest_severity": self._highest_severity(context.open_findings),
                "open_findings": len(context.open_findings),
                "severity_counts": severity_counts,
                "key_findings": key_findings,
            },
            "risk_priority": priority,
            "recommendations": self.recommendation_engine.build(context.open_findings),
            "usage_hypothesis": usage,
        }

    def _severity_counts(self, findings: list[RiskFinding]) -> dict[str, int]:
        counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for finding in findings:
            severity = getattr(finding.severity, "value", str(finding.severity)).lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _highest_severity(self, findings: list[RiskFinding]) -> str | None:
        if not findings:
            return None
        severity = max(
            (getattr(item.severity, "value", str(item.severity)).lower() for item in findings),
            key=lambda value: SEVERITY_ORDER.get(value, 0),
        )
        return severity

    def _key_findings(self, findings: list[RiskFinding]) -> list[str]:
        ordered = sorted(
            findings,
            key=lambda item: -SEVERITY_ORDER.get(getattr(item.severity, "value", str(item.severity)).lower(), 0),
        )
        values: list[str] = []
        seen: set[str] = set()
        for finding in ordered:
            text = finding.description or finding.title
            if text in seen:
                continue
            seen.add(text)
            values.append(text)
            if len(values) >= 5:
                break
        return values

    def _priority_from_findings(self, findings: list[RiskFinding], assets: list[Asset]) -> dict[str, Any]:
        counts = self._severity_counts(findings)
        score = sum(SEVERITY_SCORE[level] * count for level, count in counts.items())
        if counts["critical"] > 0 or score >= 120:
            level = "P1"
        elif counts["high"] > 0 or score >= 40:
            level = "P2"
        elif counts["medium"] > 0 or score >= 10:
            level = "P3"
        elif counts["low"] > 0:
            level = "P4"
        else:
            level = "P5"

        reasons: list[str] = []
        for severity in ("critical", "high", "medium", "low"):
            if counts[severity]:
                reasons.append(f"{counts[severity]} {severity} findings")
        exposed_ports = sorted({port.port for asset in assets for port in asset.ports if port.state == "open"})
        if 22 in exposed_ports:
            reasons.append("remote management exposed on port 22")
        if any(port in exposed_ports for port in WEB_PORTS):
            reasons.append("internet-facing web ports are exposed")
        if not reasons:
            reasons.append("no open findings detected")

        return {
            "level": level,
            "score": score,
            "reasons": reasons,
        }

    def _usage_hypothesis(self, asset: Asset) -> dict[str, Any]:
        categories = {
            "database": {"port": False, "service": False, "evidence": []},
            "cache": {"port": False, "service": False, "evidence": []},
            "web": {"port": False, "service": False, "evidence": []},
            "admin": {"port": False, "service": False, "evidence": []},
        }

        for port in asset.ports:
            service_name = (port.service_name or "").lower()
            service_version = (port.service_version or "").lower()
            if port.port in DATABASE_PORTS:
                categories["database"]["port"] = True
                categories["database"]["evidence"].append(f"port {port.port} exposed")
            if port.port in CACHE_PORTS:
                categories["cache"]["port"] = True
                categories["cache"]["evidence"].append(f"port {port.port} exposed")
            if port.port in WEB_PORTS:
                categories["web"]["port"] = True
                categories["web"]["evidence"].append(f"ports {port.port} exposed")
            if port.port in ADMIN_PORTS and len(asset.ports) == 1:
                categories["admin"]["port"] = True
                categories["admin"]["evidence"].append("only port 22 exposed")

            if service_name in {"mysql"} or "mysql" in service_version:
                categories["database"]["service"] = True
                categories["database"]["evidence"].append("service indicates mysql")
            if service_name in {"redis"} or "redis" in service_version:
                categories["cache"]["service"] = True
                categories["cache"]["evidence"].append("service indicates redis")
            if service_name in {"nginx", "http", "https"} or "nginx" in service_version:
                categories["web"]["service"] = True
                categories["web"]["evidence"].append("service indicates web workload")
            if service_name == "ssh" or "openssh" in service_version:
                categories["admin"]["service"] = True
                categories["admin"]["evidence"].append("service indicates ssh access")

        chosen: str | None = None
        for category in CATEGORY_PRIORITY:
            evidence = categories[category]
            if evidence["port"] or evidence["service"]:
                chosen = category
                break

        if not chosen:
            return {
                "purpose": "Unknown asset role",
                "confidence": "low",
                "evidence": ["insufficient service and port evidence"],
            }

        selected = categories[chosen]
        active_categories = sum(1 for item in categories.values() if item["port"] or item["service"])
        if selected["port"] and selected["service"] and active_categories == 1:
            confidence = "high"
        elif selected["port"] and selected["service"]:
            confidence = "medium"
        elif selected["port"] or selected["service"]:
            confidence = "medium" if active_categories == 1 else "low"
        else:
            confidence = "low"

        evidence = list(dict.fromkeys(selected["evidence"]))
        return {
            "purpose": CATEGORY_LABELS[chosen],
            "confidence": confidence,
            "evidence": evidence or ["derived from exposed service metadata"],
        }
