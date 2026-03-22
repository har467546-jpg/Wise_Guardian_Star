from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.db.models.asset import Asset, AssetPort
from app.db.models.snapshot import HostSnapshot
from app.rules.rule_matcher import RuleDefinition


@dataclass(frozen=True, slots=True)
class VerificationContext:
    asset: Asset
    port: AssetPort
    service_name: str
    service_version: str | None
    banner: str | None
    fingerprint: dict[str, Any]
    config: dict[str, Any]
    latest_snapshot: HostSnapshot | None
    rule: RuleDefinition
    connect_timeout_seconds: int
    read_timeout_seconds: int
    package: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class VerificationResult:
    status: str
    summary: str
    detector: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "summary": self.summary,
            "detector": self.detector,
            "evidence": self.evidence,
        }
