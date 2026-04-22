from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.asset import Asset
from app.db.models.discovery_job import DiscoveryJob
from app.db.models.discovery_job_execution import DiscoveryJobExecution
from app.db.models.enums import DiscoveryJobStatus, TaskExecutionStatus, TaskType
from app.db.models.scanner_zone import ScannerZone
from app.repositories.task_repo import create_task_run, get_task_run, update_task_run
from app.services.campus_zone_service import choose_scanner_node_for_zone, find_matching_scanner_zones, get_scanner_zone
from app.tasks.discovery_tasks import (
    _build_baseline_diff_summary,
    _build_discovery_source_stats,
    _apply_discovery_asset_labels,
    _annotate_discovery_hosts_with_device_assessment,
    _empty_port_scan_stats,
    _empty_service_enrichment_stats,
    _extract_ips,
    _filter_excluded_local_hosts,
    _merge_port_scan_stats,
    _upsert_asset_ports,
    _build_network_initial_snapshot,
)
from app.db.models.snapshot import HostSnapshot
from app.db.models.enums import AssetStatus
from app.db.models.task_run import TaskRun
from app.repositories.task_repo import update_task_run
from app.services.campus_asset_association_service import upsert_asset_from_observation
from app.services.campus_data_source_service import CampusObservation
from app.tasks.risk_tasks import evaluate_risks_for_asset
from app.utils.sanitize import sanitize_json_value


def schedule_campus_discovery_job(
    db: Session,
    *,
    job: DiscoveryJob,
    parent_task_id: str,
    scanner_zone_id: str | None,
) -> list[DiscoveryJobExecution]:
    target_zones = _resolve_target_zones(db, cidr=job.cidr, scanner_zone_id=scanner_zone_id)
    executions: list[DiscoveryJobExecution] = []
    dispatch_errors: list[dict[str, str | None]] = []
    for zone in target_zones:
        assignment = choose_scanner_node_for_zone(db, zone=zone, target_cidr=job.cidr)
        if assignment is None:
            failure_message = "未找到可用的扫描节点"
            execution = DiscoveryJobExecution(
                discovery_job_id=job.id,
                scanner_zone_id=zone.id,
                asset_id=None,
                target_cidr=job.cidr,
                status="failure",
                progress=100,
                summary_json={"zone_name": zone.name},
                error_json={"message": failure_message},
                finished_at=datetime.now(timezone.utc),
            )
            db.add(execution)
            db.flush()
            executions.append(execution)
            dispatch_errors.append({"scanner_zone_id": zone.id, "zone_name": zone.name, "message": failure_message})
            continue
        execution = DiscoveryJobExecution(
            discovery_job_id=job.id,
            scanner_zone_id=zone.id,
            asset_id=assignment.asset_id,
            target_cidr=job.cidr,
            status="pending",
            progress=0,
            summary_json={"zone_name": zone.name, "runner_asset_id": assignment.asset_id},
        )
        db.add(execution)
        db.flush()
        child_task = create_task_run(
            db,
            task_type=TaskType.ASSET_SCAN,
            scope_type="discovery_execution",
            scope_id=execution.id,
            message=f"等待分区 {zone.name} 的扫描节点接单",
        )
        execution.task_run_id = child_task.id
        execution.summary_json = {
            **(execution.summary_json or {}),
            "task_run_id": child_task.id,
            "parent_task_id": parent_task_id,
        }
        update_task_run(
            db,
            child_task,
            result_json={
                "scan_phase": "baseline",
                "context": {
                    "job_id": job.id,
                    "execution_id": execution.id,
                    "parent_task_id": parent_task_id,
                    "runner_asset_id": assignment.asset_id,
                    "scanner_zone_id": zone.id,
                    "target_cidr": job.cidr,
                    "execution_boundary": "runner_dispatch",
                    "scan_phase": "baseline",
                }
            },
            message=f"等待分区 {zone.name} 的扫描节点接单",
        )
        db.add(execution)
        executions.append(execution)
    dispatch_now = datetime.now(timezone.utc)
    execution_summary = [
        {
            "execution_id": item.id,
            "scanner_zone_id": item.scanner_zone_id,
            "asset_id": item.asset_id,
            "status": item.status,
            "task_run_id": item.task_run_id,
            "error": item.error_json if isinstance(item.error_json, dict) and item.error_json else None,
        }
        for item in executions
    ]
    terminal_statuses = {"success", "failure", "failed", "canceled"}
    has_non_terminal_execution = any(str(item.status or "").strip().lower() not in terminal_statuses for item in executions)
    if not executions:
        dispatch_errors.append({"scanner_zone_id": scanner_zone_id, "zone_name": None, "message": "未找到匹配的扫描分区"})
    job.status = DiscoveryJobStatus.RUNNING if has_non_terminal_execution else DiscoveryJobStatus.FAILED
    if job.started_at is None:
        job.started_at = dispatch_now
    if job.status == DiscoveryJobStatus.FAILED:
        job.finished_at = dispatch_now
    job.summary_json = sanitize_json_value(
        {
            **(job.summary_json if isinstance(job.summary_json, dict) else {}),
            "campus_dispatch": {
                "execution_count": len(executions),
                "scanner_zone_id": scanner_zone_id,
                "target_zone_ids": [zone.id for zone in target_zones],
                "pending_execution_count": sum(
                    1 for item in executions if str(item.status or "").strip().lower() not in terminal_statuses
                ),
                "failed_execution_count": sum(
                    1 for item in executions if str(item.status or "").strip().lower() in {"failure", "failed"}
                ),
                "errors": dispatch_errors,
            },
            "execution_summary": execution_summary,
        }
    )
    db.add(job)
    if job.status == DiscoveryJobStatus.FAILED:
        parent_task = get_task_run(db, parent_task_id)
        if parent_task is not None:
            failure_message = dispatch_errors[0]["message"] if dispatch_errors else "校园分区发现任务执行失败"
            update_task_run(
                db,
                parent_task,
                status=TaskExecutionStatus.FAILURE,
                progress=100,
                message=str(failure_message),
                result_json={
                    **(parent_task.result_json if isinstance(parent_task.result_json, dict) else {}),
                    "job_id": job.id,
                    "campus_summary": job.summary_json,
                },
                error_json={"message": str(failure_message)},
                commit=False,
                refresh=False,
            )
    db.commit()
    for execution in executions:
        db.refresh(execution)
    return executions


def update_discovery_execution_from_task(
    db: Session,
    *,
    task_id: str,
    status: str,
    progress: int,
    summary_json: dict[str, Any] | None = None,
    error_json: dict[str, Any] | None = None,
) -> DiscoveryJobExecution | None:
    execution = db.scalar(select(DiscoveryJobExecution).where(DiscoveryJobExecution.task_run_id == task_id))
    if execution is None:
        return None
    execution.status = status
    execution.progress = max(0, min(100, int(progress)))
    if summary_json is not None:
        existing_summary = execution.summary_json if isinstance(execution.summary_json, dict) else {}
        execution.summary_json = sanitize_json_value({**existing_summary, **summary_json})
    if error_json is not None:
        execution.error_json = sanitize_json_value(error_json)
    if execution.started_at is None and status in {"running", "success", "failure", "failed"}:
        execution.started_at = datetime.now(timezone.utc)
    if status in {"success", "failure", "failed", "canceled"}:
        execution.finished_at = datetime.now(timezone.utc)
    db.add(execution)
    db.commit()
    db.refresh(execution)
    return execution


def aggregate_campus_discovery_job(
    db: Session,
    *,
    job_id: str,
    result_key: str = "scan_result",
    allow_partial: bool = False,
    finalize: bool = True,
) -> dict[str, Any]:
    job = db.get(DiscoveryJob, job_id)
    if job is None:
        return {}
    executions = db.scalars(select(DiscoveryJobExecution).where(DiscoveryJobExecution.discovery_job_id == job_id)).all()
    if not executions:
        return {}
    terminal_statuses = {"success", "failure", "failed", "canceled"}
    if not allow_partial and any(str(item.status or "").strip().lower() not in terminal_statuses for item in executions):
        return {}

    if result_key == "scan_result":
        successful = [
            item
            for item in executions
            if str(item.status or "").strip().lower() == "success"
            and isinstance((item.summary_json if isinstance(item.summary_json, dict) else {}).get("scan_result"), dict)
        ]
    else:
        successful = [
            item
            for item in executions
            if isinstance((item.summary_json if isinstance(item.summary_json, dict) else {}).get(result_key), dict)
        ]
    aggregated_hosts: list[dict[str, Any]] = []
    runner_scan_errors: list[dict[str, Any]] = []
    discovery_source_stats: dict[str, int] = {}
    port_scan_stats = _empty_port_scan_stats()
    network_initial_snapshot_count = 0
    product_identified_count = 0

    for execution in successful:
        payload = execution.summary_json if isinstance(execution.summary_json, dict) else {}
        scan_result = payload.get(result_key) if isinstance(payload.get(result_key), dict) else {}
        hosts = [item for item in (scan_result.get("hosts") if isinstance(scan_result.get("hosts"), list) else []) if isinstance(item, dict)]
        aggregated_hosts.extend(hosts)
        for key, value in (scan_result.get("discovery_source_stats") or {}).items() if isinstance(scan_result.get("discovery_source_stats"), dict) else []:
            discovery_source_stats[str(key)] = int(discovery_source_stats.get(str(key), 0)) + int(value or 0)
        runner_scan_errors.extend(
            [item for item in (scan_result.get("runner_scan_errors") if isinstance(scan_result.get("runner_scan_errors"), list) else []) if isinstance(item, dict)]
        )

    if not successful:
        return {}

    filtered_hosts, excluded_local_hosts = _filter_excluded_local_hosts(aggregated_hosts, cidr=job.cidr)
    filtered_hosts = _annotate_discovery_hosts_with_device_assessment(filtered_hosts, cidr=job.cidr)
    summary_json = dict(job.summary_json or {}) if isinstance(job.summary_json, dict) else {}
    summary_json["host_count"] = len(filtered_hosts)
    summary_json["hosts"] = filtered_hosts
    summary_json["excluded_local_ip_count"] = len(excluded_local_hosts)
    summary_json["excluded_local_hosts"] = excluded_local_hosts
    summary_json["discovery_source_stats"] = discovery_source_stats or _build_discovery_source_stats(filtered_hosts)
    summary_json["runner_scan_errors"] = runner_scan_errors
    summary_json["baseline_diff_summary"] = _build_baseline_diff_summary(
        baseline_hosts=aggregated_hosts,
        accepted_hosts=filtered_hosts,
        excluded_hosts=excluded_local_hosts,
    )
    summary_json["execution_summary"] = [
        {
            "execution_id": item.id,
            "scanner_zone_id": item.scanner_zone_id,
            "asset_id": item.asset_id,
            "status": item.status,
            "task_run_id": item.task_run_id,
        }
        for item in executions
    ]
    summary_json["port_scan_stats"] = {
        "host_count": len(filtered_hosts),
        "open_port_count": sum(len(item.get("ports") or []) for item in filtered_hosts),
        "scanned_port_count": sum(int((item.get("scan_scope") or {}).get("scanned_port_count") or 0) for item in filtered_hosts if isinstance(item, dict)),
        "service_probe_target_count": sum(len(item.get("ports") or []) for item in filtered_hosts),
        "closed_port_count": 0,
        "filtered_or_unknown_count": 0,
        "reconciled_stale_port_count": 0,
    }
    summary_json["service_enrichment_stats"] = _empty_service_enrichment_stats()

    assets_by_ip: dict[str, Asset] = {}
    if finalize:
        ips = _extract_ips(filtered_hosts)
        if ips:
            assets_by_ip = {str(asset.ip): asset for asset in db.scalars(select(Asset).where(Asset.ip.in_(ips))).all()}
        for host in filtered_hosts:
            ip = str(host.get("ip") or "").strip()
            if not ip:
                continue
            zone_name = _resolve_zone_name_for_host(executions, ip, result_key=result_key)
            observation = CampusObservation(
                source_type="active_scan",
                observed_at=datetime.now(timezone.utc),
                ip=ip,
                hostname=str(host.get("hostname") or "").strip() or None,
                network_zone=zone_name,
                raw_evidence=[str(item) for item in (host.get("discovery_evidence") or []) if str(item).strip()],
            )
            asset, _ = upsert_asset_from_observation(db, observation, identity_source="active_scan")
            asset.status = AssetStatus.COLLECTING
            assets_by_ip[ip] = asset
            host_stats = _upsert_asset_ports(db, asset, host)
            _apply_discovery_asset_labels(asset, host, cidr=job.cidr)
            _merge_port_scan_stats(port_scan_stats, host_stats)
            product_identified_count += sum(
                1 for item in (host.get("services") or []) if isinstance(item, dict) and isinstance(item.get("product_name"), str) and item.get("product_name")
            )
            snapshot = _build_network_initial_snapshot(asset, host)
            if snapshot is not None:
                db.add(snapshot)
                network_initial_snapshot_count += 1
            db.add(asset)
        summary_json["port_scan_stats"].update(port_scan_stats)
        summary_json["service_enrichment_stats"]["product_identified_count"] = product_identified_count
        summary_json["service_enrichment_stats"]["network_initial_snapshot_count"] = network_initial_snapshot_count
    summary_json["scan_phase"] = "deep" if finalize else "baseline"

    job.summary_json = sanitize_json_value(summary_json)
    job.status = (DiscoveryJobStatus.COMPLETED if successful else DiscoveryJobStatus.FAILED) if finalize else DiscoveryJobStatus.RUNNING
    job.finished_at = datetime.now(timezone.utc) if finalize else None
    db.add(job)
    if not finalize:
        db.commit()
        return summary_json
    if finalize:
        parent_task_ids: set[str] = set()
        for item in executions:
            if not isinstance(item.summary_json, dict):
                continue
            direct_parent_task_id = str(item.summary_json.get("parent_task_id") or "").strip()
            if direct_parent_task_id:
                parent_task_ids.add(direct_parent_task_id)
            context = item.summary_json.get("context") if isinstance(item.summary_json.get("context"), dict) else {}
            nested_parent_task_id = str(context.get("parent_task_id") or "").strip()
            if nested_parent_task_id:
                parent_task_ids.add(nested_parent_task_id)
        for parent_task_id in parent_task_ids:
            parent_task = db.get(TaskRun, parent_task_id)
            if parent_task is None:
                continue
            update_task_run(
                db,
                parent_task,
                status=TaskExecutionStatus.SUCCESS if successful else TaskExecutionStatus.FAILURE,
                progress=100,
                message="校园分区发现任务已完成" if successful else "校园分区发现任务执行失败",
                result_json={
                    **(parent_task.result_json if isinstance(parent_task.result_json, dict) else {}),
                    "campus_summary": summary_json,
                    "job_id": job_id,
                },
                commit=False,
                refresh=False,
            )
    db.commit()

    if finalize:
        for asset_id in [asset.id for asset in assets_by_ip.values()]:
            evaluate_risks_for_asset.delay(asset_id)
    return summary_json


def _resolve_target_zones(db: Session, *, cidr: str, scanner_zone_id: str | None) -> list[ScannerZone]:
    if scanner_zone_id:
        zone = get_scanner_zone(db, scanner_zone_id)
        return [zone] if zone is not None and zone.enabled else []
    return find_matching_scanner_zones(db, cidr)


def _resolve_zone_name_for_host(executions: list[DiscoveryJobExecution], ip: str, *, result_key: str = "scan_result") -> str | None:
    for execution in executions:
        summary = execution.summary_json if isinstance(execution.summary_json, dict) else {}
        scan_result = summary.get(result_key) if isinstance(summary.get(result_key), dict) else {}
        hosts = scan_result.get("hosts") if isinstance(scan_result.get("hosts"), list) else []
        if any(isinstance(item, dict) and str(item.get("ip") or "").strip() == ip for item in hosts):
            if execution.scanner_zone is not None:
                return execution.scanner_zone.name
    return None
