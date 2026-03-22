import time

from app.rules.rule_engine import RuleEngine
from app.rules.rule_matcher import RuleInput


INITIAL_RULES = """
rules:
  - id: nginx.version.lt_1_18
    enabled: true
    service: nginx
    severity: high
    description: nginx version is older than 1.18
    match:
      version: "<1.18"
"""

UPDATED_RULES = """
rules:
  - id: nginx.version.lt_1_21
    enabled: true
    service: nginx
    severity: critical
    description: nginx version is older than 1.21
    match:
      version: "<1.21"
"""


def test_rule_engine_hot_reloads_on_mtime_change(tmp_path) -> None:
    path = tmp_path / "risk_rules.yaml"
    path.write_text(INITIAL_RULES, encoding="utf-8")

    engine = RuleEngine(path)
    initial = engine.match_one(RuleInput(service="nginx", version="1.20.0"))
    assert initial == []

    time.sleep(1.1)
    path.write_text(UPDATED_RULES, encoding="utf-8")

    updated = engine.match_one(RuleInput(service="nginx", version="1.20.0"))
    assert [item.rule_id for item in updated] == ["nginx.version.lt_1_21"]

    status = engine.status()
    assert status.rule_count == 1
    assert status.last_error is None
