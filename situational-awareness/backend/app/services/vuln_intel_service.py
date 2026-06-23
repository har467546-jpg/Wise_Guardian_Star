from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Callable

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
FREE_VULN_INTEL_SOURCES: tuple[str, ...] = ("cve_project", "osv", "kev", "epss")


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


ProgressCallback = Callable[[int, str, dict[str, Any]], None]


def sync_vuln_intel(
    db: Session,
    *,
    rules: list[RuleDefinition],
    client: httpx.Client | None = None,
    progress_callback: ProgressCallback | None = None,
) -> VulnIntelSyncResult:
    cve_ids = sorted(_all_rule_cve_ids(rules))
    if not cve_ids:
        return VulnIntelSyncResult(
            total_cves=0,
            tracked_rule_cves=0,
            synced_cves=0,
            stale=False,
            stale_count=0,
            last_synced_at=None,
            sources=list(FREE_VULN_INTEL_SOURCES),
            updated_cves=0,
        )

    timeout = httpx.Timeout(float(settings.VULN_INTEL_SYNC_TIMEOUT_SECONDS))
    managed_client = client or httpx.Client(timeout=timeout, follow_redirects=True)
    should_close = client is None
    updated = 0
    kev_failed = False
    epss_failed = False

    try:
        _emit_progress(
            progress_callback,
            15,
            "正在准备漏洞情报同步",
            {"tracked_rule_cves": len(cve_ids), "sources": list(FREE_VULN_INTEL_SOURCES)},
        )
        try:
            _emit_progress(progress_callback, 25, "正在同步 KEV 已知利用目录", {"source": "kev"})
            kev_catalog = _fetch_kev_catalog(managed_client)
        except Exception:
            kev_catalog = {}
            kev_failed = True
        _emit_progress(
            progress_callback,
            35,
            "KEV 已知利用目录同步完成" if not kev_failed else "KEV 已知利用目录同步失败，继续使用可用情报",
            {"source": "kev", "matched_cves": len(kev_catalog), "failed": kev_failed},
        )
        try:
            _emit_progress(progress_callback, 45, "正在同步 EPSS 概率评分", {"source": "epss"})
            epss_scores = _fetch_epss_scores(managed_client, cve_ids)
        except Exception:
            epss_scores = {}
            epss_failed = True
        _emit_progress(
            progress_callback,
            55,
            "EPSS 概率评分同步完成" if not epss_failed else "EPSS 概率评分同步失败，继续使用可用情报",
            {"source": "epss", "matched_cves": len(epss_scores), "failed": epss_failed},
        )

        for index, cve_id in enumerate(cve_ids, start=1):
            existing = db.get(VulnCveIntel, cve_id)
            cve_project_payload = None
            osv_payload = None
            try:
                cve_project_payload = _fetch_cve_project_payload(managed_client, cve_id)
            except Exception:
                try:
                    cve_project_payload = _fetch_cve_list_payload(managed_client, cve_id)
                except Exception:
                    cve_project_payload = None
            if cve_project_payload is None:
                try:
                    osv_payload = _fetch_osv_payload(managed_client, cve_id)
                except Exception:
                    osv_payload = None

            base_payload = cve_project_payload or osv_payload
            if base_payload is None and existing is None and cve_id not in kev_catalog and cve_id not in epss_scores:
                continue

            record = existing or VulnCveIntel(cve_id=cve_id)
            sources: list[str] = []
            if base_payload is not None:
                record.summary = base_payload.get("summary")
                record.cvss_v3 = _to_float(base_payload.get("cvss_v3"))
                record.references_json = list(dict.fromkeys(base_payload.get("references") or []))
                record.published_at = _parse_datetime(base_payload.get("published_at"))
                record.modified_at = _parse_datetime(base_payload.get("modified_at"))
                sources.append(str(base_payload.get("source") or "cve_project"))
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
            record.source = ",".join(dict.fromkeys(sources)) or "cve_project"
            record.exploit_maturity = _derive_exploit_maturity(
                kev_flag=bool(record.kev_flag),
                epss_score=_to_float(record.epss_score),
            )
            record.synced_at = datetime.now(UTC)
            db.merge(record)
            updated += 1
            cve_progress = min(90, 60 + int((index / len(cve_ids)) * 30))
            _emit_progress(
                progress_callback,
                cve_progress,
                f"正在同步免费 CVE 漏洞详情（{index}/{len(cve_ids)}）",
                {
                    "source": base_payload.get("source") if base_payload else "kev_or_epss_only",
                    "current_cve": cve_id,
                    "processed_cves": index,
                    "total_cves": len(cve_ids),
                    "updated_cves": updated,
                },
            )
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
        synced_at = _ensure_utc_datetime(record.synced_at)
        if last_synced_at is None or (synced_at and synced_at > last_synced_at):
            last_synced_at = synced_at
        if synced_at is None or synced_at < stale_cutoff:
            stale_count += 1

    return VulnIntelSyncResult(
        total_cves=len(rows),
        tracked_rule_cves=len(tracked_rule_cves),
        synced_cves=synced_cves,
        stale=stale_count > 0,
        stale_count=stale_count,
        last_synced_at=last_synced_at,
        sources=list(FREE_VULN_INTEL_SOURCES),
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
        intel_synced_at = max(
            (synced_at for row in matched_rows if (synced_at := _ensure_utc_datetime(row.synced_at)) is not None),
            default=None,
        )
        stale = len(matched_rows) < len(rule_cves) or any(
            (synced_at := _ensure_utc_datetime(row.synced_at)) is None or synced_at < stale_cutoff
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


def _fetch_cve_project_payload(client: httpx.Client, cve_id: str) -> dict[str, Any] | None:
    response = client.get(f"{settings.VULN_INTEL_CVE_PROJECT_URL.rstrip('/')}/{cve_id}")
    response.raise_for_status()
    payload = response.json()
    if not payload:
        return None
    parsed = _parse_cve_record_payload(payload)
    if parsed is None:
        return None
    return {**parsed, "source": "cve_project"}


def _fetch_cve_list_payload(client: httpx.Client, cve_id: str) -> dict[str, Any] | None:
    if not str(settings.VULN_INTEL_CVE_LIST_URL or "").strip():
        return None
    year = _cve_year(cve_id)
    bucket = _cve_bucket(cve_id)
    if not year or not bucket:
        return None
    response = client.get(f"{settings.VULN_INTEL_CVE_LIST_URL.rstrip('/')}/{year}/{bucket}/{cve_id}.json")
    if response.status_code == 404:
        return None
    response.raise_for_status()
    payload = response.json()
    if not payload:
        return None
    parsed = _parse_cve_record_payload(payload)
    if parsed is None:
        return None
    return {**parsed, "source": "cvelist"}


def _parse_cve_record_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    metadata = payload.get("cveMetadata") or {}
    containers = payload.get("containers") or {}
    cna = containers.get("cna") or {}
    english_description = next(
        (item.get("value") for item in cna.get("descriptions") or [] if str(item.get("lang") or "").lower() == "en" and item.get("value")),
        None,
    )
    references: list[str] = []
    references.extend(_extract_cve_record_references(cna))
    for adp in containers.get("adp") or []:
        references.extend(_extract_cve_record_references(adp))
    return {
        "summary": english_description,
        "cvss_v3": _extract_cve_record_cvss(containers),
        "references": list(dict.fromkeys(references)),
        "published_at": metadata.get("datePublished"),
        "modified_at": metadata.get("dateUpdated"),
    }


def _fetch_osv_payload(client: httpx.Client, cve_id: str) -> dict[str, Any] | None:
    response = client.get(f"{settings.VULN_INTEL_OSV_URL.rstrip('/')}/{cve_id}")
    if response.status_code == 404:
        return None
    response.raise_for_status()
    payload = response.json()
    if not payload:
        return None
    references = [str(item.get("url") or "").strip() for item in payload.get("references") or [] if str(item.get("url") or "").strip()]
    return {
        "source": "osv",
        "summary": payload.get("details") or payload.get("summary"),
        "cvss_v3": _extract_osv_cvss(payload),
        "references": references,
        "published_at": payload.get("published"),
        "modified_at": payload.get("modified"),
    }


def _extract_cve_record_references(container: dict[str, Any]) -> list[str]:
    return [str(item.get("url") or "").strip() for item in container.get("references") or [] if str(item.get("url") or "").strip()]


def _extract_cve_record_cvss(containers: dict[str, Any]) -> float | None:
    metric_sets: list[Any] = []
    cna = containers.get("cna") or {}
    metric_sets.extend(cna.get("metrics") or [])
    for adp in containers.get("adp") or []:
        metric_sets.extend((adp or {}).get("metrics") or [])
    for item in metric_sets:
        if not isinstance(item, dict):
            continue
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            cvss_data = item.get(key)
            if isinstance(cvss_data, dict):
                score = _to_float(cvss_data.get("baseScore"))
                if score is not None:
                    return score
    return None


def _extract_osv_cvss(payload: dict[str, Any]) -> float | None:
    for item in payload.get("severity") or []:
        score = _to_float(item.get("score"))
        if score is not None:
            return score
        vector_score = _score_from_cvss_vector(item.get("score"))
        if vector_score is not None:
            return vector_score
    return None


def _score_from_cvss_vector(value: Any) -> float | None:
    text = str(value or "").strip()
    if not text.startswith("CVSS:"):
        return None
    if "/A:" not in text:
        return None
    if "CVSS:4." in text:
        return None

    metrics = dict(part.split(":", 1) for part in text.split("/") if ":" in part)
    version = str(metrics.get("CVSS") or "")
    try:
        if version.startswith("3."):
            return _score_cvss_v3(metrics)
    except (KeyError, ValueError, ZeroDivisionError):
        return None
    return None


def _score_cvss_v3(metrics: dict[str, str]) -> float | None:
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
    ac = {"L": 0.77, "H": 0.44}[metrics["AC"]]
    pr_values = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.5},
    }
    scope = metrics["S"]
    pr = pr_values[scope][metrics["PR"]]
    ui = {"N": 0.85, "R": 0.62}[metrics["UI"]]
    c = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["C"]]
    i = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["I"]]
    a = {"H": 0.56, "L": 0.22, "N": 0.0}[metrics["A"]]
    impact_subscore = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * ((impact_subscore - 0.02) ** 15)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    if scope == "U":
        return _round_up_1_decimal(min(impact + exploitability, 10))
    return _round_up_1_decimal(min(1.08 * (impact + exploitability), 10))


def _round_up_1_decimal(value: float) -> float:
    return int(value * 10 + 0.999999) / 10.0


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


def _cve_year(cve_id: str) -> str | None:
    parts = cve_id.upper().split("-")
    if len(parts) < 3 or parts[0] != "CVE" or len(parts[1]) != 4 or not parts[1].isdigit():
        return None
    return parts[1]


def _cve_bucket(cve_id: str) -> str | None:
    parts = cve_id.upper().split("-")
    if len(parts) < 3 or not parts[2].isdigit():
        return None
    serial = int(parts[2])
    return f"{serial // 1000}xxx"


def _ensure_utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


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


def _emit_progress(callback: ProgressCallback | None, progress: int, message: str, payload: dict[str, Any]) -> None:
    if callback is None:
        return
    callback(progress, message, payload)
