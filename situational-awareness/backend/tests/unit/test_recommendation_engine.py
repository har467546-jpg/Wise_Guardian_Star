from types import SimpleNamespace

from app.ai.recommendation_engine import RecommendationEngine
from app.db.models.enums import RiskSeverity


def _finding(rule_id: str, severity: RiskSeverity, service_name: str = "ssh"):
    return SimpleNamespace(
        severity=severity,
        title=rule_id,
        evidence_json={"rule_id": rule_id, "service_name": service_name},
    )


def test_recommendation_engine_maps_specialized_rules() -> None:
    engine = RecommendationEngine()

    items = engine.build(
        [
            _finding("ssh.password_login.enabled", RiskSeverity.MEDIUM, "ssh"),
            _finding("redis.auth.disabled", RiskSeverity.CRITICAL, "redis"),
        ]
    )

    assert items[0]["target"] == "redis"
    assert any(item["id"] == "rec-ssh-disable-password-login" for item in items)


def test_recommendation_engine_deduplicates_by_target_and_action() -> None:
    engine = RecommendationEngine()

    items = engine.build(
        [
            _finding("ssh.password_login.enabled", RiskSeverity.MEDIUM, "ssh"),
            _finding("ssh.password_login.enabled", RiskSeverity.HIGH, "ssh"),
        ]
    )

    assert len(items) == 1
    assert items[0]["target"] == "ssh"
