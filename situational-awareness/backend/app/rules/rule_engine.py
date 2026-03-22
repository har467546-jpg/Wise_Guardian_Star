from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from app.rules.rule_loader import RuleLoader, RuleSet
from app.rules.rule_matcher import RuleInput, RuleMatch, RuleMatcher


@dataclass(frozen=True, slots=True)
class RuleEvaluationResult:
    rule_input: RuleInput
    matches: list[RuleMatch]


@dataclass(frozen=True, slots=True)
class RuleEngineStatus:
    path: str
    loaded_at: datetime | None
    source_mtime: float | None
    rule_count: int
    last_error: str | None


class RuleEngine:
    def __init__(self, rule_path: str | Path) -> None:
        self.loader = RuleLoader(rule_path)

    def match_one(self, rule_input: RuleInput) -> list[RuleMatch]:
        ruleset = self.loader.maybe_reload()
        return RuleMatcher.match(rule_input, ruleset.rules)

    def match_many(self, inputs: list[RuleInput]) -> list[RuleEvaluationResult]:
        ruleset = self.loader.maybe_reload()
        return [
            RuleEvaluationResult(rule_input=item, matches=RuleMatcher.match(item, ruleset.rules))
            for item in inputs
        ]

    def reload(self) -> RuleSet:
        return self.loader.load(force=True)

    def status(self) -> RuleEngineStatus:
        ruleset = self.loader.maybe_reload()
        return RuleEngineStatus(
            path=ruleset.path,
            loaded_at=ruleset.loaded_at,
            source_mtime=ruleset.source_mtime,
            rule_count=len(ruleset.rules),
            last_error=ruleset.last_error,
        )
