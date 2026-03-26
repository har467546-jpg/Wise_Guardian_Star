from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.vuln_cve_intel import VulnCveIntel
from app.rules.rule_matcher import RuleDefinition

_EXPLOIT_MATURITY_RANK = {
    "known_exploited": 4,
    "high_probability": 3,
    "elevated_probability": 2,
    "baseline": 1,
}


@dataclass(frozen=True, slots=True)
class RuleIntelSummary:
    cve_count: int = 0
    max_cvss: float | None = None
    max_epss: float | None = None
    kev_flag: bool = False
    exploit_maturity: str | None = None
    intel_synced_at: datetime | None = None
    stale: bool = False


@dataclass(frozen=True, slots=True)
class VulnIntelStatusPayload:
    total_cves: int
    tracked_rule_cves: int
    synced_cves: int
    stale: bool
    stale_count: int
    last_synced_at: datetime | None
    sources: list[str]


@dataclass(frozen=True, slots=True)
class VulnIntelSyncResult(VulnIntelStatusPayload):
    updated_cves: int


def sync_vuln_intel(db: Session, *, rules: list[RuleDefinition], client: httpx.Client | None = None) -> VulnIntelSyncResult:
    cve_ids = sorted(_all_rule_cve_ids(rules))
    if not cve_ids:
        return VulnIntelSyncResult(
            total_cves=0,
            tracked_rule_cves=0,
            synced_cves=0,
            stale=False,
            stale_count=0,
            last_synced_at=None,
            sources=["nvd", "kev", "epss"],
            updated_cves=0,
        )

    timeout = httpx.Timeout(float(settings.VULN_INTEL_SYNC_TIMEOUT_SECONDS))
    managed_client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    should_close = client is None
    updated = 0
    kev_failed = False
    epss_failed = False

    try:
        try:
            kev_catalog = _fetch_kev_catalog(managed_client)
        except Exception:
            kev_catalog = {}
            kev_failed = True
        try:
            epss_scores = _fetch_epss_scores(managed_client, cve_ids)
        except Exception:
            epss_scores = {}
            epss_failed = True

        for cve_id in cve_ids:
            existing = db.get(VulnCveIntel, cve_id)
            try:
                nvd_payload = _fetch_nvd_payload(managed_client, cve_id)
            except Exception:
                nvd_payload = None

            if nvd_payload is None and existing is None and cve_id not in kev_catalog and cve_id not in epss_scores:
                continue

            record = existing or VulnCveIntel(cve_id=cve_id)
            sources: list[str] = []
            if nvd_payload is not None:
                record.summary = nvd_payload.get("summary")
                record.cvss_v3 = _to_float(nvd_payload.get("cvss_v3"))
                record.references_json = list(dict.fromkeys(nvd_payload.get("references") or []))
                record.published_at = _parse_datetime(nvd_payload.get("published_at"))
                record.modified_at = _parse_datetime(nvd_payload.get("modified_at"))
                sources.append("nvd")
            if cve_id in kev_catalog:
                record.kev_flag = True
                sources.append("kev")
            elif not kev_failed:
                record.kev_flag = False
            if cve_id in epss_scores:
                record.epss_score = epss_scores[cve_id]
                sources.append("epss")
            elif not epss_failed:
                record.epss_score = None
            if not sources and existing is not None:
                sources = [part for part in str(existing.source or "").split(",") if part]
            record.source = ",".join(dict.fromkeys(sources)) or "nvd"
            record.exploit_maturity = _derive_exploit_maturity(
                kev_flag=bool(record.kev_flag),
                epss_score=_to_float(record.epss_score),
            )
            record.synced_at = datetime.now(UTC)
            db.merge(record)
            updated += 1
        db.commit()
    finally:
        if should_close:
            managed_client.close()

    return get_vuln_intel_status(db, rules=rules, updated_cves=updated)


def get_vuln_intel_status(
    db: Session,
    *,
    rules: list[RuleDefinition],
    updated_cves: int = 0,
) -> VulnIntelSyncResult:
    tracked_rule_cves = sorted(_all_rule_cve_ids(rules))
    rows = db.scalars(select(VulnCveIntel)).all()
    row_map = {row.cve_id.upper(): row for row in rows}
    stale_cutoff = datetime.now(UTC) - timedelta(hours=int(settings.VULN_INTEL_STALE_AFTER_HOURS))
    stale_count = 0
    synced_cves = 0
    last_synced_at: datetime | None = None

    for cve_id in tracked_rule_cves:
        record = row_map.get(cve_id)
        if record is None:
            stale_count += 1
            continue
        synced_cves += 1
        if last_synced_at is None or (record.synced_at and record.synced_at > last_synced_at):
            last_synced_at = record.synced_at
        if record.synced_at is None or record.synced_at < stale_cutoff:
            stale_count += 1

    return VulnIntelSyncResult(
        total_cves=len(rows),
        tracked_rule_cves=len(tracked_rule_cves),
        synced_cves=synced_cves,
        stale=stale_count > 0,
        stale_count=stale_count,
        last_synced_at=last_synced_at,
        sources=["nvd", "kev", "epss"],
        updated_cves=updated_cves,
    )


def build_rule_intel_summary_map(db: Session, rules: list[RuleDefinition]) -> dict[str, RuleIntelSummary]:
    cve_ids = sorted(_all_rule_cve_ids(rules))
    if not cve_ids:
        return {rule.rule_id: RuleIntelSummary(cve_count=len(_rule_cve_ids(rule))) for rule in rules}

    rows = db.scalars(select(VulnCveIntel).where(VulnCveIntel.cve_id.in_(cve_ids))).all()
    row_map = {row.cve_id.upper(): row for row in rows}
    stale_cutoff = datetime.now(UTC) - timedelta(hours=int(settings.VULN_INTEL_STALE_AFTER_HOURS))

    summaries: dict[str, RuleIntelSummary] = {}
    for rule in rules:
        rule_cves = _rule_cve_ids(rule)
        matched_rows = [row_map[cve] for cve in rule_cves if cve in row_map]
        max_cvss = max((row.cvss_v3 for row in matched_rows if row.cvss_v3 is not None), default=None)
        max_epss = max((row.epss_score for row in matched_rows if row.epss_score is not None), default=None)
        kev_flag = any(bool(row.kev_flag) for row in matched_rows)
        exploit_maturity = _highest_exploit_maturity(row.exploit_maturity for row in matched_rows)
        intel_synced_at = max((row.synced_at for row in matched_rows if row.synced_at is not None), default=None)
        stale = len(matched_rows) < len(rule_cves) or any(
            row.synced_at is None or row.synced_at < stale_cutoff
            for row in matched_rows
        )
        summaries[rule.rule_id] = RuleIntelSummary(
            cve_count=len(rule_cves),
            max_cvss=_round_or_none(max_cvss),
            max_epss=_round_or_none(max_epss, digits=4),
            kev_flag=kev_flag,
            exploit_maturity=exploit_maturity,
            intel_synced_at=intel_synced_at,
            stale=stale if rule_cves else False,
        )
    return summaries


def _all_rule_cve_ids(rules: list[RuleDefinition]) -> set[str]:
    values: set[str] = set()
    for rule in rules:
        values.update(_rule_cve_ids(rule))
    return values


def _rule_cve_ids(rule: RuleDefinition) -> list[str]:
    return list(dict.fromkeys(str(item or "").strip().upper() for item in (rule.cve_ids or []) if str(item or "").strip()))


def _fetch_kev_catalog(client: httpx.Client) -> dict[str, dict[str, Any]]:
    response = client.get(settings.VULN_INTEL_KEV_URL)
    response.raise_for_status()
    payload = response.json()
    records: dict[str, dict[str, Any]] = {}
    for item in payload.get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").strip().upper()
        if cve_id:
            records[cve_id] = item
    return records


def _fetch_epss_scores(client: httpx.Client, cve_ids: list[str]) -> dict[str, float]:
    result: dict[str, float] = {}
    for start in range(0, len(cve_ids), 50):
        batch = cve_ids[start : start + 50]
        response = client.get(settings.VULN_INTEL_EPSS_URL, params={"cve": ",".join(batch)})
        response.raise_for_status()
        payload = response.json()
        for item in payload.get("data") or []:
            cve_id = str(item.get("cve") or "").strip().upper()
            score = _to_float(item.get("epss"))
            if cve_id and score is not None:
                result[cve_id] = score
    return result


def _fetch_nvd_payload(client: httpx.Client, cve_id: str) -> dict[str, Any] | None:
    response = client.get(settings.VULN_INTEL_NVD_URL, params={"cveId": cve_id})
    response.raise_for_status()
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return None
    cve = (vulnerabilities[0] or {}).get("cve") or {}
    descriptions = cve.get("descriptions") or []
    english_description = next(
        (item.get("value") for item in descriptions if str(item.get("lang") or "").lower() == "en" and item.get("value")),
        None,
    )
    references = [str(item.get("url") or "").strip() for item in (cve.get("references") or []) if str(item.get("url") or "").strip()]
    return {
        "summary": english_description,
        "cvss_v3": _extract_nvd_cvss(cve),
        "references": references,
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
    }


def _extract_nvd_cvss(cve_payload: dict[str, Any]) -> float | None:
    metrics = cve_payload.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for item in metrics.get(key) or []:
            cvss_data = item.get("cvssData") or {}
            score = _to_float(cvss_data.get("baseScore"))
            if score is not None:
                return score
    return None


def _derive_exploit_maturity(*, kev_flag: bool, epss_score: float | None) -> str:
    if kev_flag:
        return "known_exploited"
    if epss_score is None:
        return "baseline"
    if epss_score >= 0.5:
        return "high_probability"
    if epss_score >= 0.1:
        return "elevated_probability"
    return "baseline"


def _highest_exploit_maturity(values: Any) -> str | None:
    highest: str | None = None
    highest_rank = -1
    for raw in values:
        value = str(raw or "").strip()
        rank = _EXPLOIT_MATURITY_RANK.get(value, 0)
        if rank > highest_rank:
            highest = value or None
            highest_rank = rank
    return highest


def _parse_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None


def _round_or_none(value: float | None, *, digits: int = 2) -> float | None:
    if value is None:
        return None
    return round(float(value), digits)


def _to_float(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None
