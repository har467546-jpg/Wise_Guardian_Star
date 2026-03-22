from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PRIORITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass(frozen=True, slots=True)
class Recommendation:
    id: str
    priority: str
    target: str
    action: str
    rationale: str

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "priority": self.priority,
            "target": self.target,
            "action": self.action,
            "rationale": self.rationale,
        }


class RecommendationEngine:
    def build(self, findings: list[Any]) -> list[dict[str, str]]:
        dedup: dict[tuple[str, str], Recommendation] = {}
        for finding in findings:
            recommendation = self._from_finding(finding)
            key = (recommendation.target, recommendation.action)
            existing = dedup.get(key)
            if existing is None or PRIORITY_ORDER[recommendation.priority] > PRIORITY_ORDER[existing.priority]:
                dedup[key] = recommendation

        ordered = sorted(
            dedup.values(),
            key=lambda item: (-PRIORITY_ORDER[item.priority], item.target, item.action),
        )
        return [item.to_dict() for item in ordered]

    def _from_finding(self, finding: Any) -> Recommendation:
        evidence = getattr(finding, "evidence_json", {}) or {}
        rule_id = str(evidence.get("rule_id") or getattr(finding, "title", "") or "generic.finding")
        service_name = str(evidence.get("service_name") or "asset")
        severity = getattr(getattr(finding, "severity", None), "value", None) or str(getattr(finding, "severity", "medium"))
        severity = severity.lower()

        if rule_id.startswith("nginx.version."):
            return Recommendation(
                id="rec-nginx-upgrade",
                priority="high",
                target="nginx",
                action="Upgrade nginx to a supported secure release and verify web service compatibility",
                rationale="Reduce exposure to known nginx vulnerabilities while preserving service stability",
            )
        if rule_id.startswith("mysql.version."):
            return Recommendation(
                id="rec-mysql-upgrade",
                priority="high",
                target="mysql",
                action="Upgrade MySQL to a supported version after backup and compatibility validation",
                rationale="Lower database vulnerability exposure and avoid upgrade-induced data or client regressions",
            )
        if rule_id.startswith("redis.auth."):
            return Recommendation(
                id="rec-redis-enable-auth",
                priority="critical",
                target="redis",
                action="Enable Redis authentication and restrict network exposure to trusted sources only",
                rationale="Prevent unauthenticated access to cache data and administrative commands",
            )
        if rule_id.startswith("ssh.password_login."):
            return Recommendation(
                id="rec-ssh-disable-password-login",
                priority="high",
                target="ssh",
                action="Disable PasswordAuthentication and enforce key-based SSH login",
                rationale="Reduce brute-force and weak credential risk on remote administration access",
            )
        return Recommendation(
            id=f"rec-{service_name}-general-hardening",
            priority=severity if severity in PRIORITY_ORDER else "medium",
            target=service_name,
            action=f"Review and remediate the {service_name} finding based on exposed version and configuration evidence",
            rationale="Generic fallback recommendation for findings without a specialized remediation mapping",
        )
