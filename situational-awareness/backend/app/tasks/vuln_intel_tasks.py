from __future__ import annotations

from pathlib import Path

from app.core.celery_app import celery_app
from app.db.session import SessionLocal
from app.rules.rule_store import RuleStore
from app.services.vuln_intel_service import sync_vuln_intel

RULES_PATH = Path(__file__).resolve().parents[1] / "rules" / "risk_rules.yaml"
RULE_STORE = RuleStore(RULES_PATH)


@celery_app.task(name="app.tasks.vuln_intel_tasks.sync_vuln_intel")
def sync_vuln_intel_task() -> dict[str, object]:
    with SessionLocal() as db:
        rules = RULE_STORE.loader.maybe_reload().rules
        result = sync_vuln_intel(db, rules=rules)
        return {
            "tracked_rule_cves": result.tracked_rule_cves,
            "synced_cves": result.synced_cves,
            "updated_cves": result.updated_cves,
            "stale": result.stale,
            "stale_count": result.stale_count,
            "last_synced_at": result.last_synced_at.isoformat() if result.last_synced_at else None,
        }
