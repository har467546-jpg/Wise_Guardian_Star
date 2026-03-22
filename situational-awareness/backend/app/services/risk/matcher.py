from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from app.db.models.risk_rule import RiskRule
from app.utils.versioning import normalize_version_token


class RuleMatcher:
    @staticmethod
    def _normalize_version(raw: str) -> str | None:
        return normalize_version_token(raw)

    @staticmethod
    def matches(rule: RiskRule, version: str | None) -> bool:
        if not version:
            return False
        normalized = RuleMatcher._normalize_version(version)
        if not normalized:
            return False
        try:
            parsed_version = Version(normalized)
        except InvalidVersion:
            return False

        try:
            spec = SpecifierSet(rule.version_constraint)
        except InvalidSpecifier:
            return False

        return parsed_version in spec
