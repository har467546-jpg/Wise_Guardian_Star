import asyncio
import ipaddress
from datetime import datetime, timezone
from typing import Any
import logging

from celery import chain
from sqlalchemy import delete, select

from app.core.celery_app import celery_app
from app.core.config import settings
from app.db.models.asset import Asset, AssetPort
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.enums import AssetStatus, DiscoveryJobStatus
from app.db.models.snapshot import HostSnapshot
from app.db.session import SessionLocal
from app.scanner.network_discovery import AsyncNetworkDiscovery, DiscoveryConfig, DiscoveryLivenessError
from app.scanner.nmap_nse import (
    AsyncNmapScriptEnricher,
    build_nse_summary,
    select_nse_scripts_for_record,
)
from app.scanner.service_enrichment import (
    BACKDOOR_NMAP_SKIP_REASON,
    AsyncNmapServiceEnricher,
    apply_port_risk_annotation,
    build_network_initial_snapshot,
    enrich_python_service_record,
    is_nmap_enrichment_blocked,
    merge_service_records,
    needs_nmap_enrichment,
    to_fingerprint_json,
)
from app.scanner.service_fingerprint import DEFAULT_SERVICE_BY_PORT, infer_service_aliases
from app.tasks.collection_tasks import run_collection_for_asset
from app.tasks.risk_tasks import evaluate_risks_for_asset
from app.tasks.task_runtime import log_task_warning
from app.utils.local_asset import resolve_local_asset
from app.utils.sanitize import sanitize_json_value, sanitize_text

logger = logging.getLogger(__name__)
NETWORK_INITIAL_SNAPSHOT_TYPE = "network_initial"
BACKDOOR_VERSION_SKIP_REASON = "后门候选端口，已跳过版本识别"
DEFAULT_DISCOVERY_CONFIG = DiscoveryConfig()
FORCED_NMAP_ENRICH_PORTS = {21, 80, 111, 512, 513, 514, 1099, 1524, 2121, 3306, 3632, 6667, 8009, 8180}


@celery_app.task(name="app.tasks.discovery_tasks.run_discovery_pipeline")
def run_discovery_pipeline(job_id: str) -> None:
    chain(
        discover_hosts.s(),
        upsert_assets.s(),
        full_port_scan.s(),
        probe_open_services.s(),
        evaluate_risks.s(),
        finalize_job.s(),
    ).apply_async(args=[job_id])


@celery_app.task(
    name="app.tasks.discovery_tasks.discover_hosts",
    autoretry_for=(Exception,),
    dont_autoretry_for=(DiscoveryLivenessError,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3},
)
def discover_hosts(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        job.status = DiscoveryJobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        db.add(job)
        db.commit()

        scanner = AsyncNetworkDiscovery(config=_build_discovery_config())
        try:
            hosts = asyncio.run(scanner.discover(job.cidr, include_services=False))
        except DiscoveryLivenessError:
            logger.warning("host discovery failed for job=%s: 批量 nmap 探活未能完成", job_id, exc_info=True)
            raise
        filtered_hosts, excluded_local_hosts = _filter_excluded_local_hosts([host.to_dict() for host in hosts], cidr=job.cidr)
        job.summary_json = {
            "host_count": len(filtered_hosts),
            "hosts": filtered_hosts,
            "excluded_local_ip_count": len(excluded_local_hosts),
            "excluded_local_hosts": excluded_local_hosts,
            "discovery_source_stats": _build_discovery_source_stats(filtered_hosts),
            "baseline_diff_summary": _build_baseline_diff_summary(
                baseline_hosts=[host.to_dict() for host in hosts],
                accepted_hosts=filtered_hosts,
                excluded_hosts=excluded_local_hosts,
            ),
        }
        job.summary_json = sanitize_json_value(job.summary_json)
        db.add(job)
        db.commit()
    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.full_port_scan")
def full_port_scan(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        preserved_excluded_local_hosts = _extract_excluded_local_hosts(job.summary_json)
        hosts, excluded_local_hosts = _filter_excluded_local_hosts(_extract_hosts(job.summary_json), cidr=job.cidr)
        if preserved_excluded_local_hosts:
            excluded_local_hosts = preserved_excluded_local_hosts
        if not hosts:
            summary = dict(job.summary_json or {})
            summary["host_count"] = 0
            summary["hosts"] = []
            summary["excluded_local_ip_count"] = len(excluded_local_hosts)
            summary["excluded_local_hosts"] = excluded_local_hosts
            summary["port_scan_stats"] = {
                "host_count": 0,
                "open_port_count": 0,
                "scanned_port_count": 0,
                "service_probe_target_count": 0,
            }
            job.summary_json = sanitize_json_value(summary)
            db.add(job)
            db.commit()
            return job_id

        discovery_config = _build_discovery_config()
        scanner = AsyncNetworkDiscovery(config=discovery_config)
        scanned_hosts = asyncio.run(scanner.scan_known_hosts_ports_only(hosts))
        scanned_by_ip = {item.ip: item for item in scanned_hosts}

        prepared_hosts: list[dict[str, Any]] = []
        open_port_count = 0
        for host in hosts:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue
            scanned = scanned_by_ip.get(ip)
            scanned_ports = list(scanned.ports) if scanned else []
            open_port_count += len(scanned_ports)
            base_host = {
                "ip": ip,
                "hostname": _normalize_hostname(scanned.hostname if scanned else None) or _normalize_hostname(host.get("hostname")),
                "ports": scanned_ports,
                "services": [],
                "discovery_sources": _extract_string_list(host.get("discovery_sources")),
                "discovery_evidence": _extract_string_list(host.get("discovery_evidence")),
                "scan_scope": _build_host_scan_scope(scanner.scan_ports),
            }
            prepared_hosts.append(base_host)

        summary = dict(job.summary_json or {})
        summary["host_count"] = len(prepared_hosts)
        summary["hosts"] = prepared_hosts
        summary["excluded_local_ip_count"] = len(excluded_local_hosts)
        summary["excluded_local_hosts"] = excluded_local_hosts
        summary["port_scan_stats"] = {
            "host_count": len(prepared_hosts),
            "open_port_count": open_port_count,
            "scanned_port_count": len(scanner.scan_ports) * len(prepared_hosts),
            "service_probe_target_count": open_port_count,
            "closed_port_count": 0,
            "filtered_or_unknown_count": 0,
            "reconciled_stale_port_count": 0,
        }
        summary["service_enrichment_stats"] = _empty_service_enrichment_stats()
        job.summary_json = sanitize_json_value(summary)

        ips = _extract_ips(prepared_hosts)
        if ips:
            assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
            assets_by_ip = {str(asset.ip): asset for asset in assets}
            reconciliation_stats = _empty_port_scan_stats()
            for host in prepared_hosts:
                ip = str(host.get("ip") or "").strip()
                asset = assets_by_ip.get(ip)
                if not asset:
                    continue
                hostname = _normalize_hostname(host.get("hostname"))
                if hostname:
                    asset.hostname = hostname
                asset.last_seen_at = datetime.now(timezone.utc)
                host_stats = _upsert_asset_ports(db, asset, host)
                _merge_port_scan_stats(reconciliation_stats, host_stats)
                db.add(asset)
            summary["port_scan_stats"].update(reconciliation_stats)

        db.add(job)
        db.commit()
    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.probe_open_services")
def probe_open_services(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        preserved_excluded_local_hosts = _extract_excluded_local_hosts(job.summary_json)
        hosts, excluded_local_hosts = _filter_excluded_local_hosts(_extract_hosts(job.summary_json), cidr=job.cidr)
        if preserved_excluded_local_hosts:
            excluded_local_hosts = preserved_excluded_local_hosts
        if not hosts:
            summary = dict(job.summary_json or {})
            summary["host_count"] = 0
            summary["hosts"] = []
            summary["excluded_local_ip_count"] = len(excluded_local_hosts)
            summary["excluded_local_hosts"] = excluded_local_hosts
            summary["port_scan_stats"] = {
                "host_count": 0,
                "open_port_count": 0,
                "scanned_port_count": 0,
                "service_probe_target_count": 0,
            }
            summary["service_enrichment_stats"] = _empty_service_enrichment_stats()
            job.summary_json = sanitize_json_value(summary)
            db.add(job)
            db.commit()
            return job_id

        discovery_config = _build_discovery_config()
        scanner = AsyncNetworkDiscovery(config=discovery_config)
        scanned_hosts = asyncio.run(scanner.probe_known_open_ports(hosts))
        scanned_by_ip = {item.ip: item for item in scanned_hosts}
        high_backdoor_ports = set(discovery_config.high_backdoor_ports)

        identified_at = datetime.now(timezone.utc).isoformat()
        prepared_hosts: list[dict[str, Any]] = []
        service_probe_target_count = 0
        for host in hosts:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue
            open_ports = _derive_open_ports(host)
            service_probe_target_count += len(open_ports)
            scanned = scanned_by_ip.get(ip)
            base_host = {
                "ip": ip,
                "hostname": _normalize_hostname(scanned.hostname if scanned else None) or _normalize_hostname(host.get("hostname")),
                "ports": open_ports,
                "services": _enrich_python_services(scanned.services if scanned else [], identified_at),
                "discovery_sources": _extract_string_list(host.get("discovery_sources")),
                "discovery_evidence": _extract_string_list(host.get("discovery_evidence")),
                "scan_scope": _normalize_scan_scope(host.get("scan_scope")),
            }
            prepared_hosts.append(base_host)

        threshold = max(1, int(settings.DISCOVERY_LOW_CONFIDENCE_THRESHOLD))
        nmap_targets, low_confidence_count, nmap_skipped_count, backdoor_nmap_blocked_count = _build_nmap_targets(
            prepared_hosts,
            high_backdoor_ports,
            threshold,
        )

        nmap_enrichment_map: dict[str, dict[int, dict[str, Any]]] = {}
        nmap_timeout_count = 0
        if nmap_targets:
            try:
                enricher = AsyncNmapServiceEnricher(
                    mode=settings.DISCOVERY_NMAP_MODE,
                    timeout_seconds=max(1, int(settings.DISCOVERY_NMAP_TIMEOUT_SECONDS)),
                    version_intensity=max(0, int(settings.DISCOVERY_NMAP_VERSION_INTENSITY)),
                )
                nmap_enrichment_map = asyncio.run(
                    enricher.enrich_hosts(nmap_targets)
                )
                nmap_timeout_count = max(0, int(getattr(enricher, "last_timeout_count", 0)))
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.warning("nmap enrichment failed for job=%s: %s", job_id, exc)
                log_task_warning(
                    "nmap 服务富化失败",
                    stage_code="probe_open_services",
                    stage_name="开放端口探测",
                    payload_json={"job_id": job_id, "error": str(exc)},
                )
                nmap_enrichment_map = {}

        merged_hosts: list[dict[str, Any]] = []
        nmap_enriched_count = 0
        unresolved_count = 0
        protocol_probe_hit_count = 0
        product_identified_count = 0
        nmap_fallback_count = 0
        still_unknown_count = 0
        high_port_open_count = 0
        backdoor_candidate_count = 0
        for host in prepared_hosts:
            ip = str(host.get("ip") or "").strip()
            nmap_by_port = nmap_enrichment_map.get(ip, {})
            py_services = {
                _to_port(item.get("port")): item
                for item in host.get("services", [])
                if isinstance(item, dict) and _to_port(item.get("port")) is not None
            }
            merged_services: list[dict[str, Any]] = []
            merged_ports = sorted(set(_derive_open_ports(host)) | set(nmap_by_port.keys()))
            for port in merged_ports:
                py_record = py_services.get(port)
                if py_record is None:
                    py_record = enrich_python_service_record(
                        port=port,
                        record={
                            "service": DEFAULT_SERVICE_BY_PORT.get(port, "unknown"),
                            "version": None,
                            "banner": None,
                            "probe_method": "connect",
                        },
                        identified_at=identified_at,
                    )
                nmap_blocked = is_nmap_enrichment_blocked(port, py_record, high_backdoor_ports)
                nmap_record = None if nmap_blocked else nmap_by_port.get(port)
                merged = merge_service_records(py_record, nmap_record, nmap_blocked=nmap_blocked)
                merged = apply_port_risk_annotation(merged, high_backdoor_ports)
                if merged.get("source") == "nmap" and nmap_record is not None:
                    nmap_enriched_count += 1
                    nmap_fallback_count += 1
                probe_chain = merged.get("probe_chain") if isinstance(merged.get("probe_chain"), list) else []
                if any(isinstance(item, str) and item not in {"passive_read", "nmap"} for item in probe_chain):
                    protocol_probe_hit_count += 1
                if isinstance(merged.get("product_name"), str) and merged.get("product_name"):
                    product_identified_count += 1
                if _normalize_service_name(merged.get("service")) == "unknown" or int(merged.get("confidence") or 0) < threshold:
                    unresolved_count += 1
                    still_unknown_count += 1
                if port >= 1024:
                    high_port_open_count += 1
                if bool(merged.get("backdoor_candidate")):
                    backdoor_candidate_count += 1
                merged_services.append(merged)

            merged_host = {
                "ip": ip,
                "hostname": _normalize_hostname(host.get("hostname")) or _pick_hostname_from_services(merged_services),
                "ports": merged_ports,
                "services": sorted(merged_services, key=lambda item: int(item.get("port") or 0)),
                "discovery_sources": _extract_string_list(host.get("discovery_sources")),
                "discovery_evidence": _extract_string_list(host.get("discovery_evidence")),
                "scan_scope": _normalize_scan_scope(host.get("scan_scope")),
            }
            merged_hosts.append(merged_host)

        nse_targets, nse_candidate_port_count, nse_executed_port_count, nse_script_run_count, nse_skipped_count = _build_nse_targets(
            merged_hosts,
            high_backdoor_ports,
            include_vuln=bool(settings.DISCOVERY_NSE_ENABLE_VULN_SCRIPTS),
        )
        requested_nse_scripts = _requested_nse_scripts_by_host(nse_targets)
        nse_enrichment_map: dict[str, dict[int, dict[str, Any]]] = {}
        nse_error_count = 0
        if nse_targets:
            try:
                nse_enricher = AsyncNmapScriptEnricher(
                    mode=str(settings.DISCOVERY_NSE_MODE or "whitelist"),
                    timeout_seconds=max(1, int(settings.DISCOVERY_NSE_TIMEOUT_SECONDS)),
                    host_concurrency=max(1, int(settings.DISCOVERY_NSE_HOST_CONCURRENCY)),
                )
                nse_result = asyncio.run(
                    nse_enricher.enrich_hosts(nse_targets)
                )
                nse_enrichment_map = nse_result.by_host
                nse_error_count = nse_result.error_count
                nse_timeout_count = max(0, int(getattr(nse_result, "timeout_count", 0)))
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.warning("nmap NSE enrichment failed for job=%s: %s", job_id, exc)
                log_task_warning(
                    "NSE 富化失败",
                    stage_code="probe_open_services",
                    stage_name="开放端口探测",
                    payload_json={"job_id": job_id, "error": str(exc)},
                )
                nse_enrichment_map = {}
                nse_error_count = 1
                nse_timeout_count = 0
        else:
            nse_timeout_count = 0

        nse_hit_count = _apply_nse_results(merged_hosts, nse_enrichment_map, requested_nse_scripts)

        summary = dict(job.summary_json or {})
        summary["host_count"] = len(merged_hosts)
        summary["hosts"] = merged_hosts
        summary["excluded_local_ip_count"] = len(excluded_local_hosts)
        summary["excluded_local_hosts"] = excluded_local_hosts
        port_scan_stats = dict(summary.get("port_scan_stats") or {})
        port_scan_stats.update(
            {
                "host_count": len(merged_hosts),
                "open_port_count": sum(len(host.get("ports", [])) for host in merged_hosts),
                "service_probe_target_count": service_probe_target_count,
                "closed_port_count": 0,
                "filtered_or_unknown_count": 0,
                "reconciled_stale_port_count": 0,
            }
        )
        summary["port_scan_stats"] = port_scan_stats
        summary["service_enrichment_stats"] = {
            "low_confidence_count": low_confidence_count,
            "nmap_enriched_count": nmap_enriched_count,
            "nmap_skipped_count": nmap_skipped_count,
            "backdoor_nmap_blocked_count": backdoor_nmap_blocked_count,
            "protocol_probe_hit_count": protocol_probe_hit_count,
            "product_identified_count": product_identified_count,
            "nmap_fallback_count": nmap_fallback_count,
            "still_unknown_count": still_unknown_count,
            "unresolved_count": unresolved_count,
            "high_port_open_count": high_port_open_count,
            "backdoor_candidate_count": backdoor_candidate_count,
            "nse_candidate_port_count": nse_candidate_port_count,
            "nse_executed_port_count": nse_executed_port_count,
            "nse_script_run_count": nse_script_run_count,
            "nse_hit_count": nse_hit_count,
            "nse_skipped_count": nse_skipped_count,
            "nse_error_count": nse_error_count,
            "network_initial_snapshot_count": 0,
        }
        job.summary_json = sanitize_json_value(summary)

        ips = _extract_ips(merged_hosts)
        network_initial_snapshot_count = 0
        if ips:
            assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
            assets_by_ip = {str(asset.ip): asset for asset in assets}
            reconciliation_stats = _empty_port_scan_stats()
            for host in merged_hosts:
                ip = str(host.get("ip") or "").strip()
                asset = assets_by_ip.get(ip)
                if not asset:
                    continue
                hostname = _normalize_hostname(host.get("hostname"))
                if hostname:
                    asset.hostname = hostname
                asset.last_seen_at = datetime.now(timezone.utc)
                host_stats = _upsert_asset_ports(db, asset, host)
                _merge_port_scan_stats(reconciliation_stats, host_stats)
                snapshot = _build_network_initial_snapshot(asset, host)
                if snapshot is not None:
                    db.add(snapshot)
                    network_initial_snapshot_count += 1
                db.add(asset)
            summary["port_scan_stats"].update(reconciliation_stats)

        summary["service_enrichment_stats"]["network_initial_snapshot_count"] = network_initial_snapshot_count
        job.summary_json = sanitize_json_value(summary)
        db.add(job)
        db.commit()
        if backdoor_nmap_blocked_count:
            log_task_warning(
                "后门候选端口已按策略跳过 nmap 版本探测",
                stage_code="probe_open_services",
                stage_name="开放端口探测",
                payload_json={
                    "job_id": job_id,
                    "nmap_skipped_count": nmap_skipped_count,
                    "backdoor_nmap_blocked_count": backdoor_nmap_blocked_count,
                },
            )
        if nmap_timeout_count:
            log_task_warning(
                "部分端口 nmap 版本探测超时，已跳过富化",
                stage_code="probe_open_services",
                stage_name="开放端口探测",
                payload_json={"job_id": job_id, "nmap_timeout_count": nmap_timeout_count},
            )
        if nse_skipped_count:
            log_task_warning(
                "部分端口已按策略跳过 NSE 扫描",
                stage_code="probe_open_services",
                stage_name="开放端口探测",
                payload_json={
                    "job_id": job_id,
                    "nse_candidate_port_count": nse_candidate_port_count,
                    "nse_skipped_count": nse_skipped_count,
                },
            )
        if nse_timeout_count:
            log_task_warning(
                "部分端口 NSE 扫描超时，已跳过富化",
                stage_code="probe_open_services",
                stage_name="开放端口探测",
                payload_json={"job_id": job_id, "nse_timeout_count": nse_timeout_count},
            )
    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.scan_services")
def scan_services(job_id: str) -> str:
    full_port_scan(job_id)
    return probe_open_services(job_id)


@celery_app.task(name="app.tasks.discovery_tasks.upsert_assets")
def upsert_assets(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        preserved_excluded_local_hosts = _extract_excluded_local_hosts(job.summary_json)
        hosts, excluded_local_hosts = _filter_excluded_local_hosts(_extract_hosts(job.summary_json), cidr=job.cidr)
        if preserved_excluded_local_hosts:
            excluded_local_hosts = preserved_excluded_local_hosts
        if isinstance(job.summary_json, dict):
            summary = dict(job.summary_json)
            summary["excluded_local_ip_count"] = len(excluded_local_hosts)
            summary["excluded_local_hosts"] = excluded_local_hosts
            job.summary_json = sanitize_json_value(summary)
            db.add(job)
        _purge_excluded_local_assets(db, excluded_local_hosts)
        for host in hosts:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue

            stmt = select(Asset).where(Asset.ip == ip)
            asset = db.scalar(stmt)
            if not asset:
                asset = Asset(
                    ip=ip,
                    hostname=_normalize_hostname(host.get("hostname")),
                    status=AssetStatus.COLLECTING,
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_at=datetime.now(timezone.utc),
                )
                db.add(asset)
                db.flush()
            else:
                asset.hostname = _normalize_hostname(host.get("hostname")) or asset.hostname
                asset.status = AssetStatus.COLLECTING
                asset.last_seen_at = datetime.now(timezone.utc)
            _upsert_asset_ports(db, asset, host)
            db.add(asset)
        db.commit()

    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.collect_baseline")
def collect_baseline(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        hosts, _ = _filter_excluded_local_hosts(_extract_hosts(job.summary_json), cidr=job.cidr)
        ips = _extract_ips(hosts)
        if not ips:
            return job_id

        assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
        for asset in assets:
            run_collection_for_asset.delay(asset.id)
    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.evaluate_risks")
def evaluate_risks(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return job_id

        hosts, _ = _filter_excluded_local_hosts(_extract_hosts(job.summary_json), cidr=job.cidr)
        ips = _extract_ips(hosts)
        if not ips:
            return job_id

        assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
        for asset in assets:
            evaluate_risks_for_asset.delay(asset.id)
    return job_id


@celery_app.task(name="app.tasks.discovery_tasks.finalize_job")
def finalize_job(job_id: str) -> str:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if job:
            job.status = DiscoveryJobStatus.COMPLETED
            job.finished_at = datetime.now(timezone.utc)
            db.add(job)
            db.commit()
    return job_id


def _extract_hosts(summary_json: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(summary_json, dict):
        return []
    hosts = summary_json.get("hosts")
    if not isinstance(hosts, list):
        return []
    return [host for host in hosts if isinstance(host, dict)]


def _extract_ips(hosts: list[dict[str, Any]]) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        ip = str(host.get("ip") or "").strip()
        if not ip or ip in seen:
            continue
        ips.append(ip)
        seen.add(ip)
    return ips


def _extract_excluded_local_hosts(summary_json: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(summary_json, dict):
        return []
    hosts = summary_json.get("excluded_local_hosts")
    if not isinstance(hosts, list):
        return []
    return [item for item in hosts if isinstance(item, dict)]


def _filter_excluded_local_hosts(
    hosts: list[dict[str, Any]],
    *,
    cidr: str | None = None,
    local_node_hints: dict[str, list[str]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    filtered: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []
    for host in hosts:
        ip = str(host.get("ip") or "").strip()
        hostname = _normalize_hostname(host.get("hostname"))
        if not ip:
            continue
        exclusion_reason = _resolve_discovery_host_exclusion_reason(ip, hostname, cidr=cidr, local_node_hints=local_node_hints)
        if exclusion_reason:
            excluded.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "reason": exclusion_reason,
                }
            )
            continue
        filtered.append(host)
    return filtered, excluded


def _resolve_discovery_host_exclusion_reason(
    ip: str,
    hostname: str | None,
    *,
    cidr: str | None = None,
    local_node_hints: dict[str, list[str]] | None = None,
) -> str | None:
    explicit_reason = _resolve_local_node_hint_reason(ip, hostname, local_node_hints)
    if explicit_reason:
        return explicit_reason
    is_local, local_hint = resolve_local_asset(ip, hostname)
    if is_local:
        return local_hint or "匹配平台本机资产排除策略"
    return None


def _resolve_gateway_candidate_reason(ip: str, cidr: str | None) -> str | None:
    return None


def _resolve_local_node_hint_reason(
    ip: str,
    hostname: str | None,
    local_node_hints: dict[str, list[str]] | None,
) -> str | None:
    if not isinstance(local_node_hints, dict):
        return None
    hint_ips = {item for item in _extract_string_list(local_node_hints.get("ips"))}
    if ip in hint_ips:
        return "匹配扫描节点本机 IP"
    normalized_hostname = _normalize_hostname(hostname)
    if normalized_hostname:
        hint_hostnames = {item.lower() for item in _extract_string_list(local_node_hints.get("hostnames"))}
        if normalized_hostname.lower() in hint_hostnames or normalized_hostname.split(".")[0].lower() in hint_hostnames:
            return "匹配扫描节点本机主机名"
    return None


def _purge_excluded_local_assets(db, excluded_local_hosts: list[dict[str, Any]]) -> int:
    ips = _extract_ips(excluded_local_hosts)
    if not ips:
        return 0
    assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
    removed = 0
    for asset in assets:
        if getattr(asset, "host_runner", None) is not None:
            continue
        db.delete(asset)
        removed += 1
    return removed


def _normalize_hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = sanitize_text(value, max_length=255)
    if cleaned is None:
        return None
    cleaned = cleaned.strip()
    return cleaned or None


def _normalize_service_name(value: Any) -> str:
    if not isinstance(value, str):
        return "unknown"
    cleaned = value.strip().lower()
    return cleaned or "unknown"


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _enrich_python_services(raw_services: Any, identified_at: str) -> list[dict[str, Any]]:
    if not isinstance(raw_services, list):
        return []
    enriched: list[dict[str, Any]] = []
    for item in raw_services:
        if not isinstance(item, dict):
            continue
        port = _to_port(item.get("port"))
        if port is None:
            continue
        enriched.append(enrich_python_service_record(port=port, record=item, identified_at=identified_at))
    return enriched


def _derive_open_ports(host: dict[str, Any]) -> list[int]:
    ports: set[int] = set()
    raw_ports = host.get("ports")
    if isinstance(raw_ports, list):
        for item in raw_ports:
            if isinstance(item, dict):
                port = _to_port(item.get("port"))
            else:
                port = _to_port(item)
            if port is not None:
                ports.add(port)
    services = host.get("services")
    if isinstance(services, list):
        for service in services:
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is not None:
                ports.add(port)
    return sorted(ports)


def _extract_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            normalized.append(text)
    return normalized


def _build_nmap_targets(
    prepared_hosts: list[dict[str, Any]],
    high_backdoor_ports: set[int],
    threshold: int,
) -> tuple[list[dict[str, Any]], int, int, int]:
    nmap_targets: list[dict[str, Any]] = []
    low_confidence_count = 0
    nmap_skipped_count = 0
    backdoor_nmap_blocked_count = 0

    for host in prepared_hosts:
        low_ports: list[int] = []
        blocked_ports: set[int] = set()
        host_has_rpcbind = any(
            isinstance(service, dict) and "rpcbind" in set(infer_service_aliases(service))
            for service in host.get("services", [])
        )
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is None:
                continue
            if is_nmap_enrichment_blocked(port, service, high_backdoor_ports):
                if port not in blocked_ports:
                    blocked_ports.add(port)
                    nmap_skipped_count += 1
                    backdoor_nmap_blocked_count += 1
                continue
            should_enrich = needs_nmap_enrichment(service, threshold)
            if port in FORCED_NMAP_ENRICH_PORTS:
                should_enrich = True
            if host_has_rpcbind and port >= 1024 and _normalize_service_name(service.get("service")) == "unknown":
                should_enrich = True
            if should_enrich:
                low_confidence_count += 1
                low_ports.append(port)

        if low_ports:
            target: dict[str, Any] = {"ip": host.get("ip"), "ports": sorted(set(low_ports))}
            if blocked_ports:
                target["blocked_ports"] = sorted(blocked_ports)
            nmap_targets.append(target)

    return nmap_targets, low_confidence_count, nmap_skipped_count, backdoor_nmap_blocked_count


def _build_nse_targets(
    hosts: list[dict[str, Any]],
    high_backdoor_ports: set[int],
    *,
    include_vuln: bool,
) -> tuple[list[dict[str, Any]], int, int, int, int]:
    targets: list[dict[str, Any]] = []
    candidate_port_count = 0
    executed_port_count = 0
    script_run_count = 0
    skipped_count = 0

    for host in hosts:
        ip = str(host.get("ip") or "").strip()
        if not ip:
            continue
        port_scripts: dict[int, list[str]] = {}
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is None:
                continue
            scripts = select_nse_scripts_for_record(service, include_vuln=include_vuln)
            if not scripts:
                continue
            if is_nmap_enrichment_blocked(port, service, high_backdoor_ports):
                skipped_count += 1
                continue
            port_scripts[port] = scripts
            candidate_port_count += 1
            executed_port_count += 1
            script_run_count += len(scripts)
        if port_scripts:
            targets.append(
                {
                    "ip": ip,
                    "ports": sorted(port_scripts),
                    "scripts": sorted({script_id for scripts in port_scripts.values() for script_id in scripts}),
                    "port_scripts": {port: scripts for port, scripts in sorted(port_scripts.items())},
                }
            )
    return targets, candidate_port_count, executed_port_count, script_run_count, skipped_count


def _requested_nse_scripts_by_host(targets: list[dict[str, Any]]) -> dict[str, dict[int, list[str]]]:
    requested: dict[str, dict[int, list[str]]] = {}
    for target in targets:
        ip = str(target.get("ip") or "").strip()
        port_scripts = target.get("port_scripts")
        if not ip or not isinstance(port_scripts, dict):
            continue
        requested[ip] = {}
        for raw_port, scripts in port_scripts.items():
            port = _to_port(raw_port)
            if port is None or not isinstance(scripts, list):
                continue
            requested[ip][port] = [str(item).strip() for item in scripts if isinstance(item, str) and item.strip()]
    return requested


def _apply_nse_results(
    hosts: list[dict[str, Any]],
    nse_enrichment_map: dict[str, dict[int, dict[str, Any]]],
    requested_scripts: dict[str, dict[int, list[str]]],
) -> int:
    nse_hit_count = 0
    collected_at = datetime.now(timezone.utc).isoformat()
    for host in hosts:
        ip = str(host.get("ip") or "").strip()
        requested_by_port = requested_scripts.get(ip, {})
        results_by_port = nse_enrichment_map.get(ip, {})
        for service in host.get("services", []):
            if not isinstance(service, dict):
                continue
            port = _to_port(service.get("port"))
            if port is None:
                continue
            requested_for_port = requested_by_port.get(port, [])
            results_for_port = results_by_port.get(port, {})
            if not requested_for_port and not results_for_port:
                continue
            service["nse"] = results_for_port if isinstance(results_for_port, dict) else {}
            service["nse_summary"] = build_nse_summary(requested_for_port, results_for_port)
            service["nse_last_phase"] = "discovery"
            service["nse_last_collected_at"] = collected_at
            nse_hit_count += int((service["nse_summary"] or {}).get("hit_count") or 0)
    return nse_hit_count


def _pick_hostname_from_services(services: list[dict[str, Any]]) -> str | None:
    for item in services:
        hint = item.get("hostname_hint")
        if isinstance(hint, str) and hint.strip():
            return hint.strip()
    return None


def _apply_backdoor_port_policy(port: int, fingerprint_json: dict[str, Any], high_backdoor_ports: set[int]) -> dict[str, Any]:
    normalized = dict(fingerprint_json)
    is_backdoor_candidate = bool(normalized.get("backdoor_candidate") is True or port in high_backdoor_ports)
    if is_backdoor_candidate:
        normalized.update(
            {
                "backdoor_candidate": True,
                "nmap_skipped": True,
                "nmap_skip_reason": BACKDOOR_NMAP_SKIP_REASON,
                "version_skipped": True,
                "version_skip_reason": BACKDOOR_VERSION_SKIP_REASON,
                "nmap_service": None,
                "nmap_product": None,
            }
        )
        return normalized

    normalized.update(
        {
            "nmap_skipped": False,
            "nmap_skip_reason": "",
            "version_skipped": bool(normalized.get("version_skipped") is True),
            "version_skip_reason": str(normalized.get("version_skip_reason") or ""),
        }
    )
    return normalized


def _parse_port_csv(value: Any, fallback: tuple[int, ...]) -> tuple[int, ...]:
    if not isinstance(value, str) or not value.strip():
        return fallback
    parsed: list[int] = []
    seen: set[int] = set()
    for token in value.split(","):
        raw = token.strip()
        if not raw:
            continue
        try:
            port = int(raw)
        except ValueError:
            continue
        if port < 1 or port > 65535 or port in seen:
            continue
        seen.add(port)
        parsed.append(port)
    return tuple(parsed) if parsed else fallback


def _build_discovery_config() -> DiscoveryConfig:
    return DiscoveryConfig(
        liveness_ports=_parse_port_csv(settings.DISCOVERY_LIVENESS_PORTS, DEFAULT_DISCOVERY_CONFIG.liveness_ports),
        liveness_mode=str(getattr(settings, "DISCOVERY_LIVENESS_MODE", DEFAULT_DISCOVERY_CONFIG.liveness_mode) or DEFAULT_DISCOVERY_CONFIG.liveness_mode),
        nmap_min_rate=max(
            1,
            int(getattr(settings, "DISCOVERY_NMAP_MIN_RATE", DEFAULT_DISCOVERY_CONFIG.nmap_min_rate)),
        ),
        nmap_liveness_timeout_seconds=max(
            1,
            int(
                getattr(
                    settings,
                    "DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS",
                    DEFAULT_DISCOVERY_CONFIG.nmap_liveness_timeout_seconds,
                )
            ),
        ),
        nmap_full_scan_timeout_seconds=max(
            1,
            int(
                getattr(
                    settings,
                    "DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS",
                    DEFAULT_DISCOVERY_CONFIG.nmap_full_scan_timeout_seconds,
                )
            ),
        ),
        service_ports=_parse_port_csv(settings.DISCOVERY_SERVICE_PORTS, DEFAULT_DISCOVERY_CONFIG.service_ports),
        high_backdoor_ports=_parse_port_csv(
            settings.DISCOVERY_HIGH_BACKDOOR_PORTS,
            DEFAULT_DISCOVERY_CONFIG.high_backdoor_ports,
        ),
        portset_mode=str(settings.DISCOVERY_PORTSET_MODE or DEFAULT_DISCOVERY_CONFIG.portset_mode),
        top_ports_limit=max(1, int(settings.DISCOVERY_TOP_PORTS_LIMIT)),
        enable_arp_discovery=bool(getattr(settings, "DISCOVERY_ENABLE_ARP_DISCOVERY", getattr(DEFAULT_DISCOVERY_CONFIG, "enable_arp_discovery", True))),
        enable_fping=bool(getattr(settings, "DISCOVERY_ENABLE_FPING", getattr(DEFAULT_DISCOVERY_CONFIG, "enable_fping", True))),
        nmap_host_discovery_profile=str(
            getattr(
                settings,
                "DISCOVERY_NMAP_HOST_DISCOVERY_PROFILE",
                getattr(DEFAULT_DISCOVERY_CONFIG, "nmap_host_discovery_profile", "balanced"),
            )
            or getattr(DEFAULT_DISCOVERY_CONFIG, "nmap_host_discovery_profile", "balanced")
        ),
        full_scan_host_concurrency=max(1, int(getattr(settings, "DISCOVERY_FULL_SCAN_HOST_CONCURRENCY", DEFAULT_DISCOVERY_CONFIG.full_scan_host_concurrency))),
        service_probe_host_concurrency=max(1, int(getattr(settings, "DISCOVERY_SERVICE_PROBE_HOST_CONCURRENCY", DEFAULT_DISCOVERY_CONFIG.service_probe_host_concurrency))),
        port_concurrency=max(1, int(getattr(settings, "DISCOVERY_FULL_SCAN_PORT_CONCURRENCY", DEFAULT_DISCOVERY_CONFIG.port_concurrency))),
    )


def _empty_service_enrichment_stats() -> dict[str, int]:
    return {
        "low_confidence_count": 0,
        "nmap_enriched_count": 0,
        "nmap_skipped_count": 0,
        "backdoor_nmap_blocked_count": 0,
        "protocol_probe_hit_count": 0,
        "product_identified_count": 0,
        "nmap_fallback_count": 0,
        "still_unknown_count": 0,
        "unresolved_count": 0,
        "high_port_open_count": 0,
        "backdoor_candidate_count": 0,
        "nse_candidate_port_count": 0,
        "nse_executed_port_count": 0,
        "nse_script_run_count": 0,
        "nse_hit_count": 0,
        "nse_skipped_count": 0,
        "nse_error_count": 0,
        "network_initial_snapshot_count": 0,
    }


def _empty_port_scan_stats() -> dict[str, int]:
    return {
        "closed_port_count": 0,
        "filtered_or_unknown_count": 0,
        "reconciled_stale_port_count": 0,
    }


def _merge_port_scan_stats(target: dict[str, int], payload: dict[str, int]) -> None:
    for key in ("closed_port_count", "filtered_or_unknown_count", "reconciled_stale_port_count"):
        target[key] = int(target.get(key, 0) or 0) + int(payload.get(key, 0) or 0)


def _build_host_scan_scope(scan_ports: tuple[int, ...] | list[int]) -> dict[str, Any]:
    ports = sorted({int(port) for port in scan_ports if 1 <= int(port) <= 65535})
    if ports and len(ports) == 65535 and ports[0] == 1 and ports[-1] == 65535:
        return {
            "protocol": "tcp",
            "scope_kind": "all_tcp",
            "scanned_port_count": 65535,
        }
    return {
        "protocol": "tcp",
        "scope_kind": "explicit",
        "ports": ports,
        "scanned_port_count": len(ports),
    }


def _normalize_scan_scope(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    protocol = str(value.get("protocol") or "tcp").strip().lower() or "tcp"
    scope_kind = str(value.get("scope_kind") or "explicit").strip().lower() or "explicit"
    normalized = {"protocol": protocol, "scope_kind": scope_kind}
    if scope_kind == "all_tcp":
        normalized["scanned_port_count"] = max(0, int(value.get("scanned_port_count") or 65535))
        return normalized
    normalized["ports"] = sorted({
        port
        for port in (_to_port(item) for item in (value.get("ports") if isinstance(value.get("ports"), list) else []))
        if port is not None
    })
    normalized["scanned_port_count"] = max(0, int(value.get("scanned_port_count") or len(normalized["ports"])))
    return normalized


def _port_is_in_scope(port: int, scan_scope: dict[str, Any]) -> bool:
    scope_kind = str(scan_scope.get("scope_kind") or "").strip().lower()
    if scope_kind == "all_tcp":
        return True
    ports = scan_scope.get("ports") if isinstance(scan_scope.get("ports"), list) else []
    return port in {item for item in (_to_port(raw) for raw in ports) if item is not None}


def _build_discovery_source_stats(hosts: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for host in hosts:
        for source in _extract_string_list(host.get("discovery_sources")):
            counts[source] = int(counts.get(source, 0)) + 1
    return dict(sorted(counts.items()))


def _build_baseline_diff_summary(
    *,
    baseline_hosts: list[dict[str, Any]],
    accepted_hosts: list[dict[str, Any]],
    excluded_hosts: list[dict[str, Any]],
) -> dict[str, int]:
    baseline_count = len([item for item in baseline_hosts if isinstance(item, dict)])
    accepted_count = len([item for item in accepted_hosts if isinstance(item, dict)])
    excluded_count = len([item for item in excluded_hosts if isinstance(item, dict)])
    unexplained_missing = max(0, baseline_count - accepted_count - excluded_count)
    return {
        "baseline_host_count": baseline_count,
        "accepted_host_count": accepted_count,
        "excluded_host_count": excluded_count,
        "extra_host_count": 0,
        "unexplained_missing_host_count": unexplained_missing,
    }


def _normalize_open_ports_and_services(host: dict[str, Any]) -> tuple[list[int], dict[int, dict[str, Any]]]:
    high_backdoor_ports = set(_build_discovery_config().high_backdoor_ports)
    service_map: dict[int, dict[str, Any]] = {}
    for service in host.get("services", []):
        if not isinstance(service, dict):
            continue
        port = _to_port(service.get("port"))
        if port is None:
            continue
        service_name = service.get("service")
        if service_name is None:
            service_name = service.get("service_name")
        service_version = service.get("version")
        if service_version is None:
            service_version = service.get("service_version")
        fingerprint_json = service.get("fingerprint_json")
        if not isinstance(fingerprint_json, dict):
            fingerprint_json = to_fingerprint_json(service)
        fingerprint_json = _apply_backdoor_port_policy(port, fingerprint_json, high_backdoor_ports)
        is_backdoor_candidate = bool(fingerprint_json.get("backdoor_candidate") is True)
        if is_backdoor_candidate:
            service_version = None
        service_map[port] = {
            "service": sanitize_text(service_name, max_length=128) if isinstance(service_name, str) else None,
            "version": sanitize_text(service_version, max_length=128) if isinstance(service_version, str) else None,
            "fingerprint_json": sanitize_json_value(fingerprint_json),
        }

    open_ports: list[int] = []
    seen_ports: set[int] = set()
    for item in host.get("ports", []):
        if isinstance(item, dict):
            port = _to_port(item.get("port"))
            if port is None:
                continue
            if port not in service_map:
                service_name = item.get("service_name")
                service_version = item.get("service_version")
                fingerprint_json = item.get("fingerprint_json")
                if not isinstance(fingerprint_json, dict):
                    fingerprint_json = {}
                fingerprint_json = _apply_backdoor_port_policy(port, fingerprint_json, high_backdoor_ports)
                is_backdoor_candidate = bool(fingerprint_json.get("backdoor_candidate") is True)
                if is_backdoor_candidate:
                    service_version = None
                service_map[port] = {
                    "service": sanitize_text(service_name, max_length=128) if isinstance(service_name, str) else None,
                    "version": sanitize_text(service_version, max_length=128) if isinstance(service_version, str) else None,
                    "fingerprint_json": sanitize_json_value(fingerprint_json),
                }
        else:
            port = _to_port(item)
            if port is None:
                continue
        if port in seen_ports:
            continue
        seen_ports.add(port)
        open_ports.append(port)
    return open_ports, service_map


def _upsert_asset_ports(db, asset: Asset, host: dict[str, Any]) -> dict[str, int]:
    open_ports, service_map = _normalize_open_ports_and_services(host)
    stats = _empty_port_scan_stats()
    known: dict[tuple[int, str], AssetPort] = {(p.port, p.protocol): p for p in asset.ports}
    now = datetime.now(timezone.utc)
    open_port_set = set(open_ports)
    for port in open_ports:
        service_data = service_map.get(port, {})
        key = (port, "tcp")
        existing = known.get(key)
        if existing:
            existing.service_name = service_data.get("service")
            existing.service_version = service_data.get("version")
            if isinstance(service_data.get("fingerprint_json"), dict):
                existing.fingerprint_json = sanitize_json_value(service_data.get("fingerprint_json"))
            existing.state = "open"
            existing.last_seen_at = now
            continue
        db.add(
            AssetPort(
                asset_id=asset.id,
                port=port,
                protocol="tcp",
                service_name=service_data.get("service"),
                service_version=service_data.get("version"),
                fingerprint_json=(
                    sanitize_json_value(service_data.get("fingerprint_json"))
                    if isinstance(service_data.get("fingerprint_json"), dict)
                    else {}
                ),
                state="open",
                last_seen_at=now,
            )
        )
    scan_scope = _normalize_scan_scope(host.get("scan_scope"))
    if scan_scope:
        for existing in asset.ports:
            if existing.protocol != "tcp":
                continue
            if existing.port in open_port_set:
                continue
            if not _port_is_in_scope(existing.port, scan_scope):
                continue
            previous_state = str(existing.state or "").strip().lower()
            if previous_state == "open":
                stats["reconciled_stale_port_count"] += 1
            existing.state = "closed"
            existing.last_seen_at = now
            stats["closed_port_count"] += 1
    return stats


def _build_network_initial_snapshot(asset: Asset, host: dict[str, Any]) -> HostSnapshot | None:
    ip = str(host.get("ip") or "").strip()
    if not ip:
        return None
    hostname = _normalize_hostname(host.get("hostname")) or asset.hostname
    services = sanitize_json_value([item for item in host.get("services", []) if isinstance(item, dict)])
    summary_json, detail_json, collection_status = build_network_initial_snapshot(ip=ip, hostname=hostname, services=services)
    return HostSnapshot(
        asset_id=asset.id,
        hostname=hostname,
        os_release=summary_json.get("os_guess"),
        kernel_version=None,
        cpu_json=sanitize_json_value({"snapshot_type": NETWORK_INITIAL_SNAPSHOT_TYPE, "source": "network_initial"}),
        memory_json=sanitize_json_value({"snapshot_type": NETWORK_INITIAL_SNAPSHOT_TYPE, "source": "network_initial"}),
        software_json=sanitize_json_value({
            "snapshot_type": NETWORK_INITIAL_SNAPSHOT_TYPE,
            "source": "network_initial",
            "summary_json": summary_json,
            "detail_json": detail_json,
        }),
        services_json=sanitize_json_value({
            "snapshot_type": NETWORK_INITIAL_SNAPSHOT_TYPE,
            "source": "network_initial",
            "services": services,
        }),
        error_json=sanitize_json_value({
            "snapshot_type": NETWORK_INITIAL_SNAPSHOT_TYPE,
            "source": "network_initial",
            "errors": [],
        }),
        collection_status=collection_status,
        collected_at=datetime.now(timezone.utc),
    )


def apply_runner_discovery_scan_result(job_id: str, scan_result: dict[str, Any]) -> dict[str, Any]:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if job is None:
            return {}

        raw_hosts = [
            host
            for host in (scan_result.get("hosts") if isinstance(scan_result.get("hosts"), list) else [])
            if isinstance(host, dict)
        ]
        local_node_hints = scan_result.get("local_node_hints") if isinstance(scan_result.get("local_node_hints"), dict) else None
        filtered_hosts, excluded_local_hosts = _filter_excluded_local_hosts(
            raw_hosts,
            cidr=job.cidr,
            local_node_hints=local_node_hints,
        )

        summary = dict(job.summary_json or {}) if isinstance(job.summary_json, dict) else {}
        summary["host_count"] = len(filtered_hosts)
        summary["hosts"] = filtered_hosts
        summary["excluded_local_ip_count"] = len(excluded_local_hosts)
        summary["excluded_local_hosts"] = excluded_local_hosts
        summary["discovery_source_stats"] = (
            scan_result.get("discovery_source_stats")
            if isinstance(scan_result.get("discovery_source_stats"), dict)
            else _build_discovery_source_stats(filtered_hosts)
        )
        summary["baseline_diff_summary"] = _build_baseline_diff_summary(
            baseline_hosts=raw_hosts,
            accepted_hosts=filtered_hosts,
            excluded_hosts=excluded_local_hosts,
        )
        summary["runner_scan_errors"] = [
            item
            for item in (scan_result.get("runner_scan_errors") if isinstance(scan_result.get("runner_scan_errors"), list) else [])
            if isinstance(item, dict)
        ]
        port_scan_stats = {
            "host_count": len(filtered_hosts),
            "open_port_count": sum(len(_derive_open_ports(host)) for host in filtered_hosts),
            "scanned_port_count": int(
                (scan_result.get("port_scan_stats") or {}).get("scanned_port_count")
                if isinstance(scan_result.get("port_scan_stats"), dict)
                else 0
            ),
            "service_probe_target_count": sum(len(_derive_open_ports(host)) for host in filtered_hosts),
            "closed_port_count": 0,
            "filtered_or_unknown_count": 0,
            "reconciled_stale_port_count": 0,
        }
        summary["port_scan_stats"] = port_scan_stats
        summary["service_enrichment_stats"] = _empty_service_enrichment_stats()

        _purge_excluded_local_assets(db, excluded_local_hosts)
        assets_by_ip: dict[str, Asset] = {}
        ips = _extract_ips(filtered_hosts)
        if ips:
            assets_by_ip = {str(asset.ip): asset for asset in db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()}

        reconciliation_stats = _empty_port_scan_stats()
        network_initial_snapshot_count = 0
        product_identified_count = 0
        for host in filtered_hosts:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue
            asset = assets_by_ip.get(ip)
            if asset is None:
                asset = Asset(
                    ip=ip,
                    hostname=_normalize_hostname(host.get("hostname")),
                    status=AssetStatus.COLLECTING,
                    first_seen_at=datetime.now(timezone.utc),
                    last_seen_at=datetime.now(timezone.utc),
                )
                db.add(asset)
                db.flush()
                assets_by_ip[ip] = asset
            else:
                asset.hostname = _normalize_hostname(host.get("hostname")) or asset.hostname
                asset.status = AssetStatus.COLLECTING
                asset.last_seen_at = datetime.now(timezone.utc)
            host_stats = _upsert_asset_ports(db, asset, host)
            _merge_port_scan_stats(reconciliation_stats, host_stats)
            product_identified_count += sum(
                1
                for item in host.get("services", [])
                if isinstance(item, dict) and isinstance(item.get("product_name"), str) and item.get("product_name")
            )
            snapshot = _build_network_initial_snapshot(asset, host)
            if snapshot is not None:
                db.add(snapshot)
                network_initial_snapshot_count += 1
            db.add(asset)

        summary["port_scan_stats"].update(reconciliation_stats)
        summary["service_enrichment_stats"]["product_identified_count"] = product_identified_count
        summary["service_enrichment_stats"]["network_initial_snapshot_count"] = network_initial_snapshot_count
        summary["service_enrichment_stats"]["protocol_probe_hit_count"] = sum(
            1
            for host in filtered_hosts
            for item in host.get("services", [])
            if isinstance(item, dict) and "nmap" in {str(step).strip().lower() for step in (item.get("probe_chain") or []) if str(step).strip()}
        )

        job.summary_json = sanitize_json_value(summary)
        job.status = DiscoveryJobStatus.COMPLETED
        if job.started_at is None:
            job.started_at = datetime.now(timezone.utc)
        job.finished_at = datetime.now(timezone.utc)
        db.add(job)
        db.commit()

        if ips:
            assets = db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()
            for asset in assets:
                evaluate_risks_for_asset.delay(asset.id)
        return get_discovery_scan_stats(job_id)


def get_service_enrichment_stats(job_id: str) -> dict[str, int]:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return {}
        summary_json = job.summary_json if isinstance(job.summary_json, dict) else {}
        stats = summary_json.get("service_enrichment_stats")
        if not isinstance(stats, dict):
            return {}
        parsed: dict[str, int] = {}
        for key in (
            "low_confidence_count",
            "nmap_enriched_count",
            "nmap_skipped_count",
            "backdoor_nmap_blocked_count",
            "protocol_probe_hit_count",
            "product_identified_count",
            "nmap_fallback_count",
            "still_unknown_count",
            "unresolved_count",
            "high_port_open_count",
            "backdoor_candidate_count",
            "nse_candidate_port_count",
            "nse_executed_port_count",
            "nse_script_run_count",
            "nse_hit_count",
            "nse_skipped_count",
            "nse_error_count",
            "network_initial_snapshot_count",
        ):
            try:
                parsed[key] = int(stats.get(key, 0))
            except (TypeError, ValueError):
                parsed[key] = 0
        return parsed


def get_discovery_scan_stats(job_id: str) -> dict[str, int]:
    with SessionLocal() as db:
        job = db.get(DiscoveryJob, job_id)
        if not job:
            return {}
        summary_json = job.summary_json if isinstance(job.summary_json, dict) else {}
        combined: dict[str, int] = {}

        port_stats = summary_json.get("port_scan_stats")
        if isinstance(port_stats, dict):
            for key in (
                "host_count",
                "open_port_count",
                "scanned_port_count",
                "service_probe_target_count",
                "closed_port_count",
                "filtered_or_unknown_count",
                "reconciled_stale_port_count",
            ):
                try:
                    combined[key] = int(port_stats.get(key, 0))
                except (TypeError, ValueError):
                    combined[key] = 0

        combined.update(get_service_enrichment_stats(job_id))
        return combined
