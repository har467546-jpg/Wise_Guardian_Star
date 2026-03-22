from __future__ import annotations

from pathlib import Path
from collections.abc import Callable
from typing import Any

from app.core.celery_app import celery_app
from app.db.models.asset import AssetPort
from app.db.models.snapshot import HostSnapshot
from app.rules import RuleEngine
from app.services.risk_verification_service import (
    RiskVerificationService,
    extract_service_config,
    latest_snapshot,
    normalize_service_name,
)

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "risk_rules.yaml"
RULE_ENGINE = RuleEngine(RULES_PATH)
RISK_VERIFICATION_SERVICE = RiskVerificationService(RULE_ENGINE)


@celery_app.task(name="app.tasks.risk_tasks.evaluate_risks_for_asset")
def evaluate_risks_for_asset(asset_id: str) -> str:
    execute_risk_evaluation(asset_id)
    return asset_id


def execute_risk_evaluation(
    asset_id: str,
    *,
    progress_callback: Callable[[int, str, dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    return RISK_VERIFICATION_SERVICE.evaluate_asset(asset_id, progress_callback=progress_callback).to_dict()


def _latest_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    return latest_snapshot(snapshots)


def _normalize_service_name(port: AssetPort) -> str | None:
    return normalize_service_name(port)


def _extract_service_config(snapshot: HostSnapshot | None, service_name: str) -> dict[str, Any]:
    return extract_service_config(snapshot, service_name)
