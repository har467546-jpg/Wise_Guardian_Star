import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from collections.abc import Callable
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collector.host_security import build_local_privilege_summary
from app.collector.ssh_collector import (
    AsyncSSHCollector,
    SSHAuthorizationResult,
    SSHCollectOptions,
    SSHCollectProfile,
    SSHCollectResult,
)
from app.core.celery_app import celery_app
from app.core.config import settings
from app.core.crypto import decrypt_text
from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import SSHCredential
from app.db.models.enums import AssetStatus, CredentialAuthType, TaskType
from app.db.models.snapshot import HostSnapshot
from app.db.models.task_run import TaskRun
from app.db.session import SessionLocal
from app.repositories.task_event_repo import create_task_event
from app.scanner.nmap_nse import (
    AsyncNmapScriptEnricher,
    build_nse_summary,
    compact_nse_results,
    select_nse_scripts_for_record,
)
from app.scanner.service_enrichment import is_nmap_enrichment_blocked
from app.tasks.task_runtime import get_current_task_run_id, log_task_warning, set_task_progress
from app.tasks.verify_tasks import run_risk_verify_task

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class CollectionNseStats:
    candidate_port_count: int = 0
    executed_port_count: int = 0
    script_run_count: int = 0
    hit_count: int = 0
    skipped_count: int = 0
    error_count: int = 0
    queued_risk_verify_count: int = 0
    queued_risk_verify_task_ids: list[str] = field(default_factory=list)

    def to_result(self) -> dict[str, Any]:
        return {
            "nse_candidate_port_count": self.candidate_port_count,
            "nse_executed_port_count": self.executed_port_count,
            "nse_script_run_count": self.script_run_count,
            "nse_hit_count": self.hit_count,
            "nse_skipped_count": self.skipped_count,
            "nse_error_count": self.error_count,
            "queued_risk_verify_count": self.queued_risk_verify_count,
            "queued_risk_verify_task_ids": list(self.queued_risk_verify_task_ids),
        }


def _set_collection_stage(
    *,
    progress: int,
    message: str,
    stage_code: str,
    stage_name: str,
    result_json: dict | None = None,
) -> None:
    task_run_id = get_current_task_run_id()
    if not task_run_id:
        return
    set_task_progress(
        task_run_id,
        progress,
        message,
        result_json,
        stage_code=stage_code,
        stage_name=stage_name,
    )


@celery_app.task(name="app.tasks.collection_tasks.run_collection_for_asset", autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_collection_for_asset(
    asset_id: str,
    credential_id: str | None = None,
    connect_timeout_seconds: int | None = None,
    command_timeout_seconds: int | None = None,
    asset_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    with SessionLocal() as db:
        asset = db.get(Asset, asset_id)
        if not asset:
            return {
                "asset_id": asset_id,
                "status": "missing",
                **CollectionNseStats().to_result(),
            }

        options = _build_collect_options(
            connect_timeout_seconds=connect_timeout_seconds,
            command_timeout_seconds=command_timeout_seconds,
            asset_timeout_seconds=asset_timeout_seconds,
        )
        _set_collection_stage(
            progress=15,
            message="正在验证 SSH 授权状态",
            stage_code="verify_authorization",
            stage_name="授权验证",
            result_json={"asset_id": asset.id},
        )
        auth_result = _verify_authorization_for_asset(db=db, asset=asset, credential_id=credential_id, options=options)
        _set_collection_stage(
            progress=25,
            message="正在识别当前管理员权限",
            stage_code="detect_privilege",
            stage_name="权限识别",
            result_json={"asset_id": asset.id, "status": auth_result.status, "effective_privilege": auth_result.effective_privilege},
        )
        _set_collection_stage(
            progress=40,
            message="正在执行 SSH 授权深度检查",
            stage_code="collect_inventory",
            stage_name="基础清单采集",
            result_json={"asset_id": asset.id},
        )
        result = _collect_for_asset(
            db=db,
            asset=asset,
            credential_id=credential_id,
            options=options,
            authorization_result=auth_result,
            on_stage=_build_task_stage_callback(asset.id),
        )
        _set_collection_stage(
            progress=70,
            message="正在写入采集结果",
            stage_code="persist_result",
            stage_name="结果落盘",
            result_json={"asset_id": asset.id, "status": result.status},
        )
        snapshot = _persist_collection_result(db=db, asset=asset, result=result)
        _set_collection_stage(
            progress=82,
            message="正在执行采集阶段 NSE 跟扫",
            stage_code="collection_nse_followup",
            stage_name="NSE 跟扫",
            result_json={"asset_id": asset.id, "status": result.status},
        )
        nse_stats = _run_collection_nse_followup(db=db, asset=asset, snapshot=snapshot, collected_at=result.collected_at)
        db.commit()
        _set_collection_stage(
            progress=92,
            message="正在触发风险验证任务",
            stage_code="queue_followup_risk_verify",
            stage_name="风险验证入队",
            result_json={"asset_id": asset.id, **nse_stats.to_result()},
        )
        queued_task_ids = _enqueue_followup_risk_verify_tasks(db=db, asset_ids=[asset.id] if result.status in {"success", "partial"} else [])
        nse_stats.queued_risk_verify_task_ids = queued_task_ids
        nse_stats.queued_risk_verify_count = len(queued_task_ids)
        return {
            "asset_id": asset.id,
            "status": result.status,
            **nse_stats.to_result(),
        }


@celery_app.task(name="app.tasks.collection_tasks.run_collection_for_assets_batch", autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_collection_for_assets_batch(
    asset_ids: list[str],
    credential_id: str | None = None,
    concurrency: int = 20,
    connect_timeout_seconds: int | None = None,
    command_timeout_seconds: int | None = None,
    asset_timeout_seconds: int | None = None,
) -> dict[str, Any]:
    with SessionLocal() as db:
        options = _build_collect_options(
            connect_timeout_seconds=connect_timeout_seconds,
            command_timeout_seconds=command_timeout_seconds,
            asset_timeout_seconds=asset_timeout_seconds,
        )
        _set_collection_stage(
            progress=20,
            message="正在校验批量 SSH 授权状态",
            stage_code="verify_authorization",
            stage_name="授权验证",
            result_json={"asset_count": len(asset_ids)},
        )
        _set_collection_stage(
            progress=35,
            message="正在执行批量 SSH 授权深度检查",
            stage_code="collect_inventory",
            stage_name="基础清单采集",
            result_json={"asset_count": len(asset_ids)},
        )
        assets = db.scalars(select(Asset).where(Asset.id.in_(asset_ids))).all()
        assets_by_id = {asset.id: asset for asset in assets}

        prebuilt_results: dict[str, SSHCollectResult] = {}
        profiles: list[SSHCollectProfile] = []
        for asset_id in asset_ids:
            asset = assets_by_id.get(asset_id)
            if not asset:
                prebuilt_results[asset_id] = SSHCollectResult.failed(asset_id=asset_id, ip="unknown", stage="asset", message="资产不存在")
                continue

            credential = _resolve_credential(db=db, asset=asset, credential_id=credential_id)
            if not credential:
                prebuilt_results[asset_id] = SSHCollectResult.failed(asset_id=asset.id, ip=str(asset.ip), stage="credential", message="未配置凭据")
                continue

            if not _credential_ready_for_authorized_collection(credential):
                prebuilt_results[asset_id] = SSHCollectResult.failed(
                    asset_id=asset.id,
                    ip=str(asset.ip),
                    stage="authorization",
                    message="凭据未完成授权确认或管理员权限验证",
                    authorization=_authorization_dict_from_credential(credential),
                )
                continue

            profile = _build_profile(asset=asset, credential=credential)
            if profile is None:
                prebuilt_results[asset_id] = SSHCollectResult.failed(asset_id=asset.id, ip=str(asset.ip), stage="credential", message="凭据内容不完整")
                continue

            profiles.append(profile)

        if profiles:
            collector = AsyncSSHCollector()
            results = asyncio.run(collector.collect_many(profiles, options=options, concurrency=concurrency))
            for result in results:
                prebuilt_results[result.asset_id] = result

        _set_collection_stage(
            progress=72,
            message="正在写入批量采集结果",
            stage_code="persist_result",
            stage_name="结果落盘",
            result_json={"asset_count": len(asset_ids)},
        )
        success = 0
        partial = 0
        failed = 0
        nse_stats = CollectionNseStats()
        followup_asset_ids: list[str] = []
        for asset_id in asset_ids:
            result = prebuilt_results.get(asset_id)
            asset = assets_by_id.get(asset_id)
            if result is None or asset is None:
                failed += 1
                continue
            snapshot = _persist_collection_result(db=db, asset=asset, result=result)
            run_stats = _run_collection_nse_followup(db=db, asset=asset, snapshot=snapshot, collected_at=result.collected_at)
            nse_stats.candidate_port_count += run_stats.candidate_port_count
            nse_stats.executed_port_count += run_stats.executed_port_count
            nse_stats.script_run_count += run_stats.script_run_count
            nse_stats.hit_count += run_stats.hit_count
            nse_stats.skipped_count += run_stats.skipped_count
            nse_stats.error_count += run_stats.error_count
            if result.status == "success":
                success += 1
                followup_asset_ids.append(asset.id)
            elif result.status == "partial":
                partial += 1
                followup_asset_ids.append(asset.id)
            else:
                failed += 1

        db.commit()
        _set_collection_stage(
            progress=84,
            message="批量采集阶段 NSE 跟扫完成",
            stage_code="collection_nse_followup",
            stage_name="NSE 跟扫",
            result_json={"processed": len(asset_ids), **nse_stats.to_result()},
        )
        _set_collection_stage(
            progress=92,
            message="正在触发后续风险验证任务",
            stage_code="queue_followup_risk_verify",
            stage_name="风险验证入队",
            result_json={"processed": len(asset_ids), "success": success, "partial": partial, "failed": failed, **nse_stats.to_result()},
        )
        queued_task_ids = _enqueue_followup_risk_verify_tasks(db=db, asset_ids=followup_asset_ids)
        nse_stats.queued_risk_verify_task_ids = queued_task_ids
        nse_stats.queued_risk_verify_count = len(queued_task_ids)
        return {
            "processed": len(asset_ids),
            "success": success,
            "partial": partial,
            "failed": failed,
            **nse_stats.to_result(),
        }


def _collect_for_asset(
    db: Session,
    asset: Asset,
    credential_id: str | None,
    options: SSHCollectOptions,
    *,
    authorization_result: SSHAuthorizationResult | None = None,
    on_stage: Callable[[str, str], None] | None = None,
) -> SSHCollectResult:
    credential = _resolve_credential(db=db, asset=asset, credential_id=credential_id)
    if not credential:
        return SSHCollectResult.failed(asset_id=asset.id, ip=str(asset.ip), stage="credential", message="未配置凭据")
    if not _credential_ready_for_authorized_collection(credential):
        return SSHCollectResult.failed(
            asset_id=asset.id,
            ip=str(asset.ip),
            stage="authorization",
            message="凭据未完成授权确认或管理员权限验证",
            authorization=_authorization_dict_from_credential(credential),
        )

    profile = _build_profile(asset=asset, credential=credential)
    if profile is None:
        return SSHCollectResult.failed(asset_id=asset.id, ip=str(asset.ip), stage="credential", message="凭据内容不完整")

    collector = AsyncSSHCollector()
    return asyncio.run(
        collector.collect_one(
            profile,
            options=options,
            authorization_result=authorization_result,
            on_stage=on_stage,
        )
    )


def _verify_authorization_for_asset(
    db: Session,
    asset: Asset,
    credential_id: str | None,
    options: SSHCollectOptions,
) -> SSHAuthorizationResult:
    credential = _resolve_credential(db=db, asset=asset, credential_id=credential_id)
    if not credential:
        return SSHAuthorizationResult(
            asset_id=asset.id,
            ip=str(asset.ip),
            status="failed",
            username=None,
            effective_user=None,
            effective_privilege=None,
            summary="未配置凭据",
            errors=[],
            detail_json={},
        )

    profile = _build_profile(asset=asset, credential=credential)
    if profile is None:
        return SSHAuthorizationResult(
            asset_id=asset.id,
            ip=str(asset.ip),
            status="failed",
            username=credential.username,
            effective_user=None,
            effective_privilege=None,
            summary="凭据内容不完整",
            errors=[],
            detail_json={},
        )

    collector = AsyncSSHCollector()
    result = asyncio.run(collector.verify_authorization(profile, options=options))
    credential.last_verified_at = result.verified_at
    credential.last_verification_status = result.status
    credential.last_effective_privilege = result.effective_privilege
    db.add(credential)
    return result


def _resolve_credential(db: Session, asset: Asset, credential_id: str | None) -> SSHCredential | None:
    if credential_id:
        return db.get(SSHCredential, credential_id)
    if asset.credential_bindings:
        binding = sorted(asset.credential_bindings, key=lambda item: item.priority)[0]
        return binding.credential
    return None


def _build_profile(asset: Asset, credential: SSHCredential) -> SSHCollectProfile | None:
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    if credential.auth_type == CredentialAuthType.PASSWORD:
        if not credential.secret_ciphertext:
            return None
        password = decrypt_text(credential.secret_ciphertext)
    elif credential.auth_type == CredentialAuthType.KEY:
        if not credential.key_ciphertext:
            return None
        private_key = decrypt_text(credential.key_ciphertext)
    else:
        return None
    if credential.sudo_secret_ciphertext:
        sudo_password = decrypt_text(credential.sudo_secret_ciphertext)

    return SSHCollectProfile(
        asset_id=asset.id,
        ip=str(asset.ip),
        username=credential.username,
        password=password,
        private_key=private_key,
        sudo_password=sudo_password,
    )


def _credential_ready_for_authorized_collection(credential: SSHCredential) -> bool:
    if credential.admin_authorized is not True:
        return False
    if str(credential.last_verification_status or "").strip().lower() != "success":
        return False
    privilege = str(credential.last_effective_privilege or "").strip().lower()
    return privilege in {"root", "sudo"}


def _authorization_dict_from_credential(credential: SSHCredential) -> dict[str, Any]:
    verified_at = credential.last_verified_at.isoformat() if credential.last_verified_at else None
    return {
        "status": credential.last_verification_status or "failed",
        "username": credential.username,
        "effective_user": credential.username,
        "effective_privilege": credential.last_effective_privilege,
        "verified_at": verified_at,
    }


def _build_task_stage_callback(asset_id: str) -> Callable[[str, str], None]:
    def _callback(stage_code: str, stage_name: str) -> None:
        if stage_code == "collect_inventory":
            progress = 40
            message = "正在执行 SSH 授权深度检查"
        elif stage_code == "collect_host_security":
            progress = 58
            message = "正在执行主机安全检查"
        else:
            progress = 40
            message = "正在执行 SSH 授权深度检查"
        _set_collection_stage(
            progress=progress,
            message=message,
            stage_code=stage_code,
            stage_name=stage_name,
            result_json={"asset_id": asset_id},
        )

    return _callback


def _build_collect_options(
    connect_timeout_seconds: int | None,
    command_timeout_seconds: int | None,
    asset_timeout_seconds: int | None,
) -> SSHCollectOptions:
    return SSHCollectOptions(
        connect_timeout=float(connect_timeout_seconds or 8),
        command_timeout=float(command_timeout_seconds or 20),
        asset_timeout=float(asset_timeout_seconds or 45),
    )


def _to_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if port < 1 or port > 65535:
        return None
    return port


def _normalize_protocol(value: Any) -> str:
    raw = str(value or "").strip().lower()
    return "udp" if raw.startswith("udp") else "tcp"


def _load_high_backdoor_ports() -> set[int]:
    raw = str(settings.DISCOVERY_HIGH_BACKDOOR_PORTS or "").strip()
    if not raw:
        return set()
    ports: set[int] = set()
    for token in raw.split(","):
        try:
            port = int(token.strip())
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports


def _build_collection_nse_record(port: AssetPort) -> dict[str, Any]:
    fingerprint = dict(port.fingerprint_json) if isinstance(port.fingerprint_json, dict) else {}
    service_name = str(port.service_name or "").strip().lower() or "unknown"
    version = str(port.service_version or "").strip() or None
    record = dict(fingerprint)
    record.update(
        {
            "port": int(port.port),
            "service": service_name,
            "service_name": service_name,
            "version": version,
            "product_version": fingerprint.get("product_version") or version,
            "tls_detected": bool(fingerprint.get("tls_detected") is True),
        }
    )
    return record


def _build_collection_nse_target(
    asset: Asset,
    *,
    include_vuln: bool,
    high_backdoor_ports: set[int],
) -> tuple[dict[str, Any] | None, dict[int, list[str]], CollectionNseStats]:
    stats = CollectionNseStats()
    ip = str(asset.ip or "").strip()
    if not ip:
        return None, {}, stats

    port_scripts: dict[int, list[str]] = {}
    for port in asset.ports:
        if _normalize_protocol(port.protocol) != "tcp":
            continue
        if str(port.state or "").strip().lower() != "open":
            continue
        record = _build_collection_nse_record(port)
        scripts = select_nse_scripts_for_record(record, include_vuln=include_vuln, scan_profile="collection")
        if not scripts:
            continue
        stats.candidate_port_count += 1
        if is_nmap_enrichment_blocked(port.port, record, high_backdoor_ports):
            stats.skipped_count += 1
            continue
        port_scripts[int(port.port)] = scripts
        stats.executed_port_count += 1
        stats.script_run_count += len(scripts)

    if not port_scripts:
        return None, {}, stats

    target = {
        "ip": ip,
        "ports": sorted(port_scripts),
        "scripts": sorted({script_id for scripts in port_scripts.values() for script_id in scripts}),
        "port_scripts": {port: scripts for port, scripts in sorted(port_scripts.items())},
    }
    return target, port_scripts, stats


def _rebuild_collection_snapshot_nse_view(
    db: Session,
    *,
    asset: Asset,
    snapshot: HostSnapshot,
    collected_at_iso: str,
) -> None:
    nse_by_port: dict[str, dict[str, Any]] = {}
    port_summaries: dict[str, dict[str, Any]] = {}
    total_hit_count = 0
    total_script_count = 0

    for port in asset.ports:
        if _normalize_protocol(port.protocol) != "tcp":
            continue
        if str(port.state or "").strip().lower() != "open":
            continue
        fingerprint = dict(port.fingerprint_json) if isinstance(port.fingerprint_json, dict) else {}
        nse = compact_nse_results(fingerprint.get("nse") if isinstance(fingerprint.get("nse"), dict) else {})
        summary = fingerprint.get("nse_summary") if isinstance(fingerprint.get("nse_summary"), dict) else {}
        if not summary and nse:
            summary = build_nse_summary(sorted(nse), nse)
        if not nse and not summary:
            continue
        key = str(int(port.port))
        if nse:
            nse_by_port[key] = nse
        if summary:
            port_summaries[key] = summary
            total_hit_count += int(summary.get("hit_count") or 0)
            total_script_count += int(summary.get("script_count") or 0)

    services_json = dict(snapshot.services_json) if isinstance(snapshot.services_json, dict) else {}
    services_json["nse_by_port"] = nse_by_port
    services_json["nse_summary"] = {
        "last_phase": "collection",
        "last_collected_at": collected_at_iso,
        "port_count": len(port_summaries) or len(nse_by_port),
        "script_count": total_script_count,
        "hit_count": total_hit_count,
        "port_summaries": port_summaries,
    }
    snapshot.services_json = services_json
    db.add(snapshot)


def _apply_collection_nse_results(
    db: Session,
    *,
    asset: Asset,
    snapshot: HostSnapshot,
    requested_by_port: dict[int, list[str]],
    results_by_port: dict[int, dict[str, Any]],
    collected_at: datetime,
) -> int:
    collected_at_iso = collected_at.isoformat()
    current_hit_count = 0

    for port in asset.ports:
        normalized_port = _to_port(port.port)
        if normalized_port is None:
            continue
        requested_scripts = requested_by_port.get(normalized_port, [])
        if not requested_scripts:
            continue
        compact_results = compact_nse_results(results_by_port.get(normalized_port, {}))
        current_hit_count += int(build_nse_summary(requested_scripts, compact_results).get("hit_count") or 0)

        fingerprint = dict(port.fingerprint_json) if isinstance(port.fingerprint_json, dict) else {}
        merged_nse = compact_nse_results(fingerprint.get("nse") if isinstance(fingerprint.get("nse"), dict) else {})
        for script_id in requested_scripts:
            merged_nse.pop(script_id, None)
        merged_nse.update(compact_results)

        summary_scripts = sorted(dict.fromkeys(list(merged_nse.keys()) + requested_scripts))
        fingerprint["nse"] = merged_nse
        fingerprint["nse_summary"] = build_nse_summary(summary_scripts, merged_nse)
        fingerprint["nse_last_phase"] = "collection"
        fingerprint["nse_last_collected_at"] = collected_at_iso
        port.fingerprint_json = fingerprint
        db.add(port)

    _rebuild_collection_snapshot_nse_view(db=db, asset=asset, snapshot=snapshot, collected_at_iso=collected_at_iso)
    return current_hit_count


def _run_collection_nse_followup(
    db: Session,
    *,
    asset: Asset,
    snapshot: HostSnapshot,
    collected_at: datetime,
) -> CollectionNseStats:
    stats = CollectionNseStats()
    target, requested_by_port, build_stats = _build_collection_nse_target(
        asset,
        include_vuln=bool(settings.DISCOVERY_NSE_ENABLE_VULN_SCRIPTS),
        high_backdoor_ports=_load_high_backdoor_ports(),
    )
    stats.candidate_port_count = build_stats.candidate_port_count
    stats.executed_port_count = build_stats.executed_port_count
    stats.script_run_count = build_stats.script_run_count
    stats.skipped_count = build_stats.skipped_count

    if str(settings.DISCOVERY_NSE_MODE or "").strip().lower() == "off":
        _rebuild_collection_snapshot_nse_view(db=db, asset=asset, snapshot=snapshot, collected_at_iso=collected_at.isoformat())
        return stats

    results_by_port: dict[int, dict[str, Any]] = {}
    if target:
        try:
            result = asyncio.run(
                AsyncNmapScriptEnricher(
                    mode=str(settings.DISCOVERY_NSE_MODE or "whitelist"),
                    timeout_seconds=max(1, int(settings.DISCOVERY_NSE_TIMEOUT_SECONDS)),
                    host_concurrency=max(1, int(settings.DISCOVERY_NSE_HOST_CONCURRENCY)),
                ).enrich_hosts([target])
            )
            results_by_port = result.by_host.get(str(asset.ip), {})
            stats.error_count = result.error_count
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("collection NSE follow-up failed for asset=%s: %s", asset.id, exc)
            log_task_warning(
                "采集阶段 NSE 跟进扫描失败",
                stage_code="collection_nse_followup",
                stage_name="NSE 跟扫",
                payload_json={"asset_id": asset.id, "error": str(exc)},
            )
            stats.error_count = 1
            results_by_port = {}

    stats.hit_count = _apply_collection_nse_results(
        db,
        asset=asset,
        snapshot=snapshot,
        requested_by_port=requested_by_port,
        results_by_port=results_by_port,
        collected_at=collected_at,
    )
    return stats


def _queue_followup_risk_verify_task(db: Session, asset_id: str) -> str:
    task_run = TaskRun(
        id=str(uuid4()),
        task_type=TaskType.RISK_VERIFY,
        scope_type="asset",
        scope_id=asset_id,
        message="风险验证任务已入队",
    )
    db.add(task_run)
    create_task_event(
        db,
        task_run_id=task_run.id,
        event_type="queued",
        level="info",
        message="风险验证任务已入队",
        progress=task_run.progress,
    )
    db.commit()

    task = run_risk_verify_task.delay(task_run.id, asset_id)
    task_run.celery_task_id = task.id
    db.add(task_run)
    db.commit()
    return task_run.id


def _enqueue_followup_risk_verify_tasks(db: Session, asset_ids: list[str]) -> list[str]:
    queued_ids: list[str] = []
    for asset_id in asset_ids:
        try:
            queued_ids.append(_queue_followup_risk_verify_task(db, asset_id))
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning("queue follow-up risk verify failed for asset=%s: %s", asset_id, exc)
            log_task_warning(
                "后续风险验证任务排队失败",
                stage_code="queue_followup_risk_verify",
                stage_name="风险验证入队",
                payload_json={"asset_id": asset_id, "error": str(exc)},
            )
    return queued_ids


def _persist_collection_result(db: Session, asset: Asset, result: SSHCollectResult) -> HostSnapshot:
    summary_json = _build_collection_summary(result)
    detail_json = _build_collection_detail(result)
    snapshot = HostSnapshot(
        asset_id=asset.id,
        hostname=result.hostname,
        os_release=result.os_release_text(),
        kernel_version=result.kernel_summary(),
        cpu_json=result.cpu,
        memory_json=result.memory,
        software_json={
            "packages": result.packages,
            "host_checks": result.host_checks,
            "authorization": result.authorization,
            "summary_json": summary_json,
            "detail_json": detail_json,
        },
        services_json={
            "services": result.services,
            "config_by_service": result.service_configs,
            "nse_by_port": {},
            "nse_summary": {},
        },
        error_json={
            "errors": [error.to_dict() for error in result.errors],
            "authorization": result.authorization,
        },
        collection_status=result.status,
        collected_at=result.collected_at,
    )
    db.add(snapshot)

    if result.hostname and result.status in {"success", "partial"}:
        asset.hostname = result.hostname
    if result.os_release_text() and result.status in {"success", "partial"}:
        asset.os_name = result.os_release_text()
    if result.status in {"success", "partial"}:
        asset.status = AssetStatus.ONLINE
    else:
        asset.status = AssetStatus.UNKNOWN
    if result.status in {"success", "partial"} and result.authorization:
        _ensure_authorized_management_port(db=db, asset=asset, result=result)
    db.add(asset)
    return snapshot


def _build_collection_summary(result: SSHCollectResult) -> dict[str, Any]:
    authorization = result.authorization if isinstance(result.authorization, dict) else {}
    host_checks = result.host_checks if isinstance(result.host_checks, dict) else {}
    service_configs = result.service_configs if isinstance(result.service_configs, dict) else {}
    sudoers = host_checks.get("sudoers") if isinstance(host_checks.get("sudoers"), dict) else {}
    suid_sgid = host_checks.get("suid_sgid") if isinstance(host_checks.get("suid_sgid"), dict) else {}
    capabilities = host_checks.get("capabilities") if isinstance(host_checks.get("capabilities"), dict) else {}
    writable = (
        host_checks.get("sensitive_world_writable")
        if isinstance(host_checks.get("sensitive_world_writable"), dict)
        else {}
    )
    summary = {
        "hostname": result.hostname,
        "os": result.os_release_text(),
        "kernel": result.kernel_summary(),
        "login_user": authorization.get("username"),
        "effective_user": authorization.get("effective_user"),
        "effective_privilege": authorization.get("effective_privilege"),
        "verified_at": authorization.get("verified_at"),
        "authorization_status": authorization.get("status"),
        "package_count": len(result.packages),
        "service_count": len(result.services),
        "sudo_risk_summary": _build_sudo_risk_summary(sudoers),
        "dangerous_suid_count": int(suid_sgid.get("dangerous_count") or 0),
        "capability_count": int(capabilities.get("dangerous_count") or 0),
        "sensitive_world_writable_count": int(writable.get("count") or 0),
        "error_count": len(result.errors),
    }
    summary.update(build_local_privilege_summary(service_configs))
    return summary


def _build_collection_detail(result: SSHCollectResult) -> dict[str, Any]:
    return {
        "authorization": result.authorization,
        "cpu": result.cpu,
        "memory": result.memory,
        "packages": result.packages,
        "services": result.services,
        "service_configs": result.service_configs,
        "host_checks": result.host_checks,
        "errors": [error.to_dict() for error in result.errors],
    }


def _build_sudo_risk_summary(sudoers: dict[str, Any]) -> str:
    tokens: list[str] = []
    if sudoers.get("full_privilege_rule"):
        tokens.append("存在 ALL=(ALL) ALL 级别授权")
    if sudoers.get("nopasswd_present"):
        tokens.append("存在 NOPASSWD 规则")
    if sudoers.get("setenv_present"):
        tokens.append("存在 SETENV 授权")
    if sudoers.get("dangerous_env_keep_present"):
        tokens.append("存在危险 env_keep 保留")
    if not tokens:
        return "未发现明显 sudo 高风险授权"
    return "；".join(tokens)


def _ensure_authorized_management_port(db: Session, asset: Asset, result: SSHCollectResult) -> None:
    authorization = result.authorization if isinstance(result.authorization, dict) else {}
    aliases = ["ssh", "linux-kernel", "linux-host", "sudo", "polkit", "nmap", "screen", "docker", "systemd", "cron", "logrotate"]
    target: AssetPort | None = None
    for port in asset.ports:
        if int(port.port) == 22 and _normalize_protocol(port.protocol) == "tcp":
            target = port
            break

    collected_at = result.collected_at
    if target is None:
        target = AssetPort(
            asset_id=asset.id,
            port=22,
            protocol="tcp",
            service_name="ssh",
            service_version=None,
            fingerprint_json={},
            state="open",
            last_seen_at=collected_at,
        )
        asset.ports.append(target)

    fingerprint = dict(target.fingerprint_json) if isinstance(target.fingerprint_json, dict) else {}
    existing_aliases = [item for item in fingerprint.get("service_aliases", []) if isinstance(item, str)]
    merged_aliases = list(dict.fromkeys(existing_aliases + aliases))
    fingerprint["service_aliases"] = merged_aliases
    fingerprint["authorization_scope"] = "authorized_local"
    fingerprint["authorization_verified_at"] = authorization.get("verified_at")
    fingerprint["effective_privilege"] = authorization.get("effective_privilege")
    fingerprint.setdefault("source", "ssh_collect")
    fingerprint.setdefault("reason", "authorized ssh deep inspection anchor")
    target.fingerprint_json = fingerprint
    target.state = "open"
    target.last_seen_at = collected_at
    if not str(target.service_name or "").strip() or str(target.service_name).strip().lower() == "unknown":
        target.service_name = "ssh"
    db.add(target)
