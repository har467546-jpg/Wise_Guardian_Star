from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.risk_rule import RiskRule


def load_rules_from_yaml(path: Path) -> list[dict]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return payload.get("rules", [])


def sync_rules(db: Session, rules: list[dict]) -> int:
    upserted = 0
    for item in rules:
        stmt = select(RiskRule).where(
            RiskRule.service_name == item["service_name"],
            RiskRule.version_constraint == item["version_constraint"],
            RiskRule.title == item["title"],
        )
        exists = db.scalar(stmt)
        if exists:
            exists.severity = item["severity"]
            exists.description = item["description"]
            exists.reference = item.get("reference")
            exists.enabled = item.get("enabled", True)
        else:
            db.add(
                RiskRule(
                    service_name=item["service_name"],
                    version_constraint=item["version_constraint"],
                    severity=item["severity"],
                    title=item["title"],
                    description=item["description"],
                    reference=item.get("reference"),
                    enabled=item.get("enabled", True),
                )
            )
        upserted += 1
    db.commit()
    return upserted
