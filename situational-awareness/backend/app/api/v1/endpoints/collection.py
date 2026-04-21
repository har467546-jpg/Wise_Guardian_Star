import asyncio
from datetime import datetime, timezone

from sqlalchemy import select
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db_session
from app.collector.host_security import build_local_privilege_summary
from app.collector.ssh_collector import AsyncSSHCollector, SSHCollectProfile
from app.core.config import settings
from app.core.crypto import decrypt_text, encrypt_text
from app.db.models.asset import Asset, AssetPort
from app.db.models.credential import AssetCredentialBinding, SSHCredential
from app.db.models.enums import AssetStatus, CredentialAuthType, TaskType
from app.db.models.snapshot import HostSnapshot
from app.db.models.user import User
from app.repositories.task_repo import create_task_run, update_task_run
from app.scanner.service_enrichment import (
    BACKDOOR_NMAP_SKIP_REASON,
    build_network_initial_snapshot as build_network_initial_summary,
)
from app.scanner.service_fingerprint import DEFAULT_SERVICE_BY_PORT
from app.schemas.collection import (
    AssetCredentialBatchResponse,
    AssetCredentialBatchResult,
    AssetCredentialBatchUpsertRequest,
    AssetCredentialReadResponse,
    AssetCredentialUpsertRequest,
    AssetCredentialVerifyResponse,
    CollectBatchRunRequest,
    CollectInitialLatestResponse,
    CollectLatestResponse,
    CollectProbeLatestResponse,
    CollectProbeRunRequest,
    CollectProbeRunResponse,
    CollectRunRequest,
    CollectRunResponse,
)
from app.services.device_assessment_service import resolve_asset_device_assessment
from app.tasks.collect_tasks import run_asset_collect_task, run_batch_collect_task

router = APIRouter()
MANUAL_CREDENTIAL_PRIORITY = -100
PROBE_SNAPSHOT_TYPE = "ssh_probe_baseline"
NETWORK_INITIAL_SNAPSHOT_TYPE = "network_initial"
PROCESS_SERVICE_NAME_MAP: dict[str, str] = {
    "sshd": "ssh",
    "nginx": "http",
    "apache2": "http",
    "httpd": "http",
    "mysqld": "mysql",
    "mariadbd": "mysql",
    "postgres": "postgresql",
    "redis-server": "redis",
    "redis": "redis",
}
BACKDOOR_VERSION_SKIP_REASON = "后门候选端口，已跳过版本识别"


def _manual_credential_name(asset_id: str) -> str:
    return f"manual-asset-{asset_id}"


def _get_manual_credential(db: Session, asset_id: str) -> SSHCredential | None:
    return db.scalar(select(SSHCredential).where(SSHCredential.name == _manual_credential_name(asset_id)))


def _ensure_manual_binding(db: Session, asset_id: str, credential_id: str) -> None:
    binding = db.scalar(
        select(AssetCredentialBinding).where(
            AssetCredentialBinding.asset_id == asset_id,
            AssetCredentialBinding.credential_id == credential_id,
        )
    )
    if binding is None:
        binding = AssetCredentialBinding(
            asset_id=asset_id,
            credential_id=credential_id,
            priority=MANUAL_CREDENTIAL_PRIORITY,
        )
    else:
        binding.priority = MANUAL_CREDENTIAL_PRIORITY
    db.add(binding)


def _credential_response(asset_id: str, credential: SSHCredential | None, bound: bool) -> AssetCredentialReadResponse:
    if credential is None:
        return AssetCredentialReadResponse(
            asset_id=asset_id,
            credential_id=None,
            auth_type=None,
            username=None,
            bound=False,
            admin_authorized=False,
            last_verified_at=None,
            last_verification_status=None,
            effective_privilege=None,
        )
    return AssetCredentialReadResponse(
        asset_id=asset_id,
        credential_id=credential.id,
        auth_type=credential.auth_type.value,
        username=credential.username,
        bound=bound,
        admin_authorized=credential.admin_authorized,
        last_verified_at=credential.last_verified_at.isoformat() if credential.last_verified_at else None,
        last_verification_status=credential.last_verification_status,
        effective_privilege=credential.last_effective_privilege,
    )


def _resolve_credential(db: Session, asset: Asset, credential_id: str | None) -> SSHCredential | None:
    if credential_id:
        return db.get(SSHCredential, credential_id)
    if asset.credential_bindings:
        binding = sorted(asset.credential_bindings, key=lambda item: item.priority)[0]
        return binding.credential
    return None


def _build_profile(asset: Asset, credential: SSHCredential) -> SSHCollectProfile:
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None

    if credential.auth_type == CredentialAuthType.PASSWORD:
        if not credential.secret_ciphertext:
            raise ValueError("凭据中的密码为空，请重新保存")
        password = decrypt_text(credential.secret_ciphertext)
    elif credential.auth_type == CredentialAuthType.KEY:
        if not credential.key_ciphertext:
            raise ValueError("凭据中的私钥为空，请重新保存")
        private_key = decrypt_text(credential.key_ciphertext)
    else:
        raise ValueError(f"不支持的凭据认证方式：{credential.auth_type}")
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


def _credential_ready_for_authorized_collection(credential: SSHCredential | None) -> bool:
    if credential is None or credential.admin_authorized is not True:
        return False
    if str(credential.last_verification_status or "").strip().lower() != "success":
        return False
    return str(credential.last_effective_privilege or "").strip().lower() in {"root", "sudo"}


def _build_authorization_response(asset_id: str, result: dict) -> AssetCredentialVerifyResponse:
    return AssetCredentialVerifyResponse(
        asset_id=asset_id,
        status=str(result.get("status") or "failed"),
        username=result.get("username"),
        effective_user=result.get("effective_user"),
        effective_privilege=result.get("effective_privilege"),
        summary=str(result.get("summary") or ""),
        verified_at=str(result.get("verified_at") or datetime.now(timezone.utc).isoformat()),
        errors=result.get("errors") if isinstance(result.get("errors"), list) else [],
        detail_json=result.get("detail_json") if isinstance(result.get("detail_json"), dict) else {},
    )


def _upsert_manual_asset_credential(
    db: Session,
    *,
    asset: Asset,
    payload: AssetCredentialUpsertRequest,
    current_user: User,
) -> SSHCredential:
    credential = _get_manual_credential(db=db, asset_id=asset.id)
    auth_type = CredentialAuthType(payload.auth_type)
    password_ciphertext = encrypt_text((payload.password or "").strip()) if auth_type == CredentialAuthType.PASSWORD else None
    key_ciphertext = encrypt_text((payload.private_key or "").strip()) if auth_type == CredentialAuthType.KEY else None
    sudo_password = (payload.sudo_password or "").strip()
    sudo_ciphertext = encrypt_text(sudo_password) if payload.username.strip().lower() != "root" and sudo_password else None

    if credential is None:
        credential = SSHCredential(
            name=_manual_credential_name(asset.id),
            username=payload.username.strip(),
            auth_type=auth_type,
            secret_ciphertext=password_ciphertext,
            key_ciphertext=key_ciphertext,
            sudo_secret_ciphertext=sudo_ciphertext,
            treat_success_as_risk=False,
            admin_authorized=payload.admin_authorized,
            last_verified_at=None,
            last_verification_status=None,
            last_effective_privilege=None,
            created_by=current_user.id,
        )
    else:
        credential.username = payload.username.strip()
        credential.auth_type = auth_type
        credential.secret_ciphertext = password_ciphertext
        credential.key_ciphertext = key_ciphertext
        credential.sudo_secret_ciphertext = sudo_ciphertext
        credential.treat_success_as_risk = False
        credential.admin_authorized = payload.admin_authorized
        credential.last_verified_at = None
        credential.last_verification_status = None
        credential.last_effective_privilege = None
        credential.created_by = current_user.id

    db.add(credential)
    db.flush()
    _ensure_manual_binding(db=db, asset_id=asset.id, credential_id=credential.id)
    db.commit()
    db.refresh(credential)
    return credential


def _verify_manual_asset_credential(
    db: Session,
    *,
    asset: Asset,
    credential: SSHCredential,
) -> AssetCredentialVerifyResponse:
    if credential.admin_authorized is not True:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="保存 SSH 凭据前必须确认已获得管理员授权")

    try:
        profile = _build_profile(asset=asset, credential=credential)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    result = asyncio.run(AsyncSSHCollector().verify_authorization(profile))
    credential.last_verified_at = result.verified_at
    credential.last_verification_status = result.status
    credential.last_effective_privilege = result.effective_privilege
    db.add(credential)
    db.commit()
    db.refresh(credential)
    return _build_authorization_response(asset.id, result.to_dict())


def _build_probe_response_from_authorization(asset: Asset, result: AssetCredentialVerifyResponse) -> CollectProbeRunResponse:
    return CollectProbeRunResponse(
        asset_id=asset.id,
        ip=str(asset.ip),
        preset="baseline",
        status="success" if result.status == "success" else "failed",
        probe_method="ssh",
        results=[],
        errors=result.errors,
        summary_json={
            "username": result.username,
            "effective_user": result.effective_user,
            "effective_privilege": result.effective_privilege,
            "authorization_status": result.status,
        },
        detail_json=result.detail_json,
        friendly_text=[result.summary],
        executed_at=result.verified_at,
    )


def _snapshot_type(snapshot: HostSnapshot) -> str | None:
    for payload in [snapshot.error_json, snapshot.services_json, snapshot.software_json]:
        if isinstance(payload, dict) and payload.get("snapshot_type"):
            return str(payload["snapshot_type"])
    return None


def _persist_probe_result(db: Session, asset: Asset, result: CollectProbeRunResponse) -> None:
    executed_at = datetime.fromisoformat(result.executed_at)
    snapshot = HostSnapshot(
        asset_id=asset.id,
        hostname=result.summary_json.get("hostname"),
        os_release=result.summary_json.get("os"),
        kernel_version=result.summary_json.get("kernel"),
        cpu_json={
            "snapshot_type": PROBE_SNAPSHOT_TYPE,
            "source": "ssh_probe",
            "command_health": result.detail_json.get("command_health", {}),
        },
        memory_json={
            "snapshot_type": PROBE_SNAPSHOT_TYPE,
            "source": "ssh_probe",
        },
        software_json={
            "snapshot_type": PROBE_SNAPSHOT_TYPE,
            "source": "ssh_probe",
            "preset": result.preset,
            "raw_results": [item.model_dump() for item in result.results],
            "friendly_text": result.friendly_text,
        },
        services_json={
            "snapshot_type": PROBE_SNAPSHOT_TYPE,
            "source": "ssh_probe",
            "summary_json": result.summary_json,
            "detail_json": result.detail_json,
        },
        error_json={
            "snapshot_type": PROBE_SNAPSHOT_TYPE,
            "source": "ssh_probe",
            "errors": result.errors,
        },
        collection_status=result.status,
        collected_at=executed_at,
    )
    db.add(snapshot)

    hostname = (result.summary_json.get("hostname") or "").strip() if isinstance(result.summary_json, dict) else ""
    os_name = (result.summary_json.get("os") or "").strip() if isinstance(result.summary_json, dict) else ""
    if hostname and result.status in {"success", "partial"}:
        asset.hostname = hostname
    if os_name and result.status in {"success", "partial"}:
        asset.os_name = os_name
    _sync_asset_ports_from_probe(db=db, asset=asset, result=result, executed_at=executed_at)
    db.add(asset)


def _build_probe_response_from_snapshot(asset: Asset, snapshot: HostSnapshot) -> CollectProbeRunResponse:
    summary_json = {}
    detail_json = {}
    if isinstance(snapshot.services_json, dict):
        summary_json = snapshot.services_json.get("summary_json") or {}
        detail_json = snapshot.services_json.get("detail_json") or {}

    results = []
    friendly_text: list[str] = []
    if isinstance(snapshot.software_json, dict):
        results = snapshot.software_json.get("raw_results") or []
        friendly_text = snapshot.software_json.get("friendly_text") or []

    errors = []
    if isinstance(snapshot.error_json, dict):
        errors = snapshot.error_json.get("errors") or []

    return CollectProbeRunResponse(
        asset_id=asset.id,
        ip=str(asset.ip),
        preset="baseline",
        status=snapshot.collection_status,
        probe_method="ssh",
        results=results,
        errors=errors,
        summary_json=summary_json,
        detail_json=detail_json,
        friendly_text=friendly_text,
        executed_at=snapshot.collected_at.isoformat(),
    )


def _sync_asset_ports_from_probe(
    db: Session,
    asset: Asset,
    result: CollectProbeRunResponse,
    executed_at: datetime,
) -> None:
    listening_entries = _extract_listening_entries(result.detail_json)
    if not listening_entries:
        return

    existing_by_key: dict[tuple[int, str], AssetPort] = {}
    high_backdoor_ports = _load_high_backdoor_ports()
    for item in asset.ports:
        try:
            key = (int(item.port), _normalize_protocol(item.protocol))
        except (TypeError, ValueError):
            continue
        existing_by_key[key] = item

    for item in listening_entries:
        if item.get("scope") != "external":
            continue
        port = int(item["port"])
        protocol = _normalize_protocol(item.get("protocol"))
        process_name = item.get("process_name")
        key = (port, protocol)
        existing = existing_by_key.get(key)
        existing_fingerprint = existing.fingerprint_json if existing and isinstance(existing.fingerprint_json, dict) else None
        is_backdoor_candidate = _is_backdoor_candidate_port(
            port=port,
            high_backdoor_ports=high_backdoor_ports,
            fingerprint_json=existing_fingerprint,
        )

        service_name = _select_service_name(
            existing.service_name if existing else None,
            process_name=process_name,
            port=port,
            allow_default_mapping=not is_backdoor_candidate,
        )
        if existing:
            if _is_unknown_service_name(existing.service_name):
                existing.service_name = service_name
            if is_backdoor_candidate:
                existing.service_version = None
            existing.state = "open"
            existing.last_seen_at = executed_at
            existing.fingerprint_json = _build_probe_fingerprint(
                existing=existing.fingerprint_json,
                process_name=process_name,
                scope="external",
                identified_at=result.executed_at,
                backdoor_candidate=is_backdoor_candidate,
            )
            db.add(existing)
            continue

        created = AssetPort(
            asset_id=asset.id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            service_version=None,
            fingerprint_json=_build_probe_fingerprint(
                existing={},
                process_name=process_name,
                scope="external",
                identified_at=result.executed_at,
                backdoor_candidate=is_backdoor_candidate,
            ),
            state="open",
            last_seen_at=executed_at,
        )
        db.add(created)
        existing_by_key[key] = created


def _extract_listening_entries(detail_json: dict) -> list[dict]:
    payload = []
    if isinstance(detail_json, dict):
        if isinstance(detail_json.get("listening_entries"), list):
            payload = detail_json.get("listening_entries") or []
        elif isinstance(detail_json.get("listening_ports"), dict):
            nested = detail_json.get("listening_ports") or {}
            if isinstance(nested.get("entries"), list):
                payload = nested.get("entries") or []

    normalized: list[dict] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535:
            continue
        protocol = _normalize_protocol(item.get("protocol"))
        local_address = str(item.get("local_address") or "").strip().lower()
        process_raw = item.get("process_name")
        process_name = process_raw.strip().lower() if isinstance(process_raw, str) and process_raw.strip() else None
        scope = str(item.get("scope") or "").strip().lower()
        if scope not in {"external", "loopback"}:
            scope = "external"
        normalized.append(
            {
                "port": port,
                "protocol": protocol,
                "local_address": local_address,
                "process_name": process_name,
                "scope": scope,
            }
        )
    return normalized


def _normalize_protocol(value: object) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("udp"):
        return "udp"
    return "tcp"


def _load_high_backdoor_ports() -> set[int]:
    raw = str(settings.DISCOVERY_HIGH_BACKDOOR_PORTS or "").strip()
    if not raw:
        return set()
    ports: set[int] = set()
    for token in raw.split(","):
        value = token.strip()
        if not value:
            continue
        try:
            port = int(value)
        except ValueError:
            continue
        if 1 <= port <= 65535:
            ports.add(port)
    return ports


def _is_backdoor_candidate_port(
    *,
    port: int,
    high_backdoor_ports: set[int],
    fingerprint_json: dict | None,
) -> bool:
    if port in high_backdoor_ports:
        return True
    if isinstance(fingerprint_json, dict) and fingerprint_json.get("backdoor_candidate") is True:
        return True
    return False


def _is_unknown_service_name(value: str | None) -> bool:
    if not isinstance(value, str):
        return True
    return value.strip().lower() in {"", "unknown"}


def _service_from_process_name(process_name: str | None) -> str | None:
    if not process_name:
        return None
    value = process_name.strip().lower()
    if not value:
        return None
    if value in PROCESS_SERVICE_NAME_MAP:
        return PROCESS_SERVICE_NAME_MAP[value]
    if "ssh" in value:
        return "ssh"
    if "nginx" in value or "apache" in value or "httpd" in value:
        return "http"
    if "mysql" in value or "mariadb" in value:
        return "mysql"
    if "redis" in value:
        return "redis"
    if "postgres" in value:
        return "postgresql"
    return None


def _select_service_name(
    existing_name: str | None,
    *,
    process_name: str | None,
    port: int,
    allow_default_mapping: bool,
) -> str:
    if not _is_unknown_service_name(existing_name):
        return str(existing_name).strip().lower()
    process_service = _service_from_process_name(process_name)
    if process_service:
        return process_service
    if allow_default_mapping:
        fallback = DEFAULT_SERVICE_BY_PORT.get(port)
        if fallback:
            return fallback
    return "unknown"


def _build_probe_fingerprint(
    *,
    existing: dict | None,
    process_name: str | None,
    scope: str,
    identified_at: str,
    backdoor_candidate: bool,
) -> dict:
    payload = dict(existing) if isinstance(existing, dict) else {}
    payload.setdefault("source", "ssh_probe")
    payload.setdefault("reason", "derived from ssh probe listening entries")
    payload.setdefault("identified_at", identified_at)
    payload["scope"] = scope
    payload["backdoor_candidate"] = backdoor_candidate
    payload["nmap_skipped"] = backdoor_candidate
    payload["nmap_skip_reason"] = BACKDOOR_NMAP_SKIP_REASON if backdoor_candidate else ""
    payload["version_skipped"] = backdoor_candidate
    payload["version_skip_reason"] = BACKDOOR_VERSION_SKIP_REASON if backdoor_candidate else ""
    if process_name:
        payload["process_name"] = process_name
    return payload


def _pick_latest_probe_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    probe_snapshots = [item for item in snapshots if _snapshot_type(item) == PROBE_SNAPSHOT_TYPE]
    if not probe_snapshots:
        return None

    preferred = [item for item in probe_snapshots if item.collection_status in {"success", "partial"}]
    if preferred:
        return preferred[0]
    return probe_snapshots[0]


def _pick_latest_network_initial_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    initial_snapshots = [item for item in snapshots if _snapshot_type(item) == NETWORK_INITIAL_SNAPSHOT_TYPE]
    if not initial_snapshots:
        return None
    return initial_snapshots[0]


def _pick_latest_collection_snapshot(snapshots: list[HostSnapshot]) -> HostSnapshot | None:
    collection_snapshots = [item for item in snapshots if _snapshot_type(item) not in {PROBE_SNAPSHOT_TYPE, NETWORK_INITIAL_SNAPSHOT_TYPE}]
    if not collection_snapshots:
        return None
    return collection_snapshots[0]


def _build_latest_collection_payload(snapshot: HostSnapshot, *, asset: Asset | None = None) -> tuple[dict, dict]:
    summary_json = {}
    detail_json = {}
    if isinstance(snapshot.software_json, dict):
        summary_json = snapshot.software_json.get("summary_json") or {}
        detail_json = snapshot.software_json.get("detail_json") or {}
    if not detail_json:
        detail_json = {
            "authorization": snapshot.error_json.get("authorization") if isinstance(snapshot.error_json, dict) else {},
            "cpu": snapshot.cpu_json if isinstance(snapshot.cpu_json, dict) else {},
            "memory": snapshot.memory_json if isinstance(snapshot.memory_json, dict) else {},
            "packages": snapshot.software_json.get("packages") if isinstance(snapshot.software_json, dict) else [],
            "host_checks": snapshot.software_json.get("host_checks") if isinstance(snapshot.software_json, dict) else {},
            "service_configs": snapshot.services_json.get("config_by_service") if isinstance(snapshot.services_json, dict) else {},
            "services": snapshot.services_json.get("services") if isinstance(snapshot.services_json, dict) else [],
            "errors": snapshot.error_json.get("errors") if isinstance(snapshot.error_json, dict) else [],
        }
    if not summary_json:
        packages = detail_json.get("packages") if isinstance(detail_json.get("packages"), list) else []
        host_checks = detail_json.get("host_checks") if isinstance(detail_json.get("host_checks"), dict) else {}
        authorization = detail_json.get("authorization") if isinstance(detail_json.get("authorization"), dict) else {}
        suid_sgid = host_checks.get("suid_sgid") if isinstance(host_checks.get("suid_sgid"), dict) else {}
        capabilities = host_checks.get("capabilities") if isinstance(host_checks.get("capabilities"), dict) else {}
        writable = host_checks.get("sensitive_world_writable") if isinstance(host_checks.get("sensitive_world_writable"), dict) else {}
        summary_json = {
            "hostname": snapshot.hostname,
            "os": snapshot.os_release,
            "kernel": snapshot.kernel_version,
            "login_user": authorization.get("username"),
            "effective_user": authorization.get("effective_user"),
            "effective_privilege": authorization.get("effective_privilege"),
            "verified_at": authorization.get("verified_at"),
            "authorization_status": authorization.get("status"),
            "package_count": len(packages),
            "dangerous_suid_count": int(suid_sgid.get("dangerous_count") or 0),
            "capability_count": int(capabilities.get("dangerous_count") or 0),
            "sensitive_world_writable_count": int(writable.get("count") or 0),
        }
        service_configs = detail_json.get("service_configs") if isinstance(detail_json.get("service_configs"), dict) else {}
        summary_json.update(build_local_privilege_summary(service_configs))
    assessment = resolve_asset_device_assessment(asset) if asset is not None else None
    if assessment:
        summary_json.setdefault("device_assessment", assessment)
        detail_json.setdefault("device_assessment", assessment)
    return summary_json, detail_json


def _build_initial_from_asset(asset: Asset) -> tuple[dict, dict, str]:
    services: list[dict] = []
    for port in asset.ports:
        if str(port.state or "").lower() != "open":
            continue
        fingerprint = port.fingerprint_json if isinstance(port.fingerprint_json, dict) else {}
        confidence_raw = fingerprint.get("confidence")
        try:
            confidence = int(confidence_raw)
        except (TypeError, ValueError):
            confidence = 0
        if confidence <= 0:
            confidence = 55 if (port.service_name or "").strip() else 20

        service_name = (port.service_name or "").strip().lower() or "unknown"
        services.append(
            {
                "port": int(port.port),
                "service": service_name,
                "version": (port.service_version or "").strip() or None,
                "confidence": confidence,
                "source": str(fingerprint.get("source") or "asset"),
                "reason": str(fingerprint.get("reason") or "基于资产端口记录回填"),
                "evidence": fingerprint.get("evidence") if isinstance(fingerprint.get("evidence"), list) else [],
                "identified_at": str(fingerprint.get("identified_at") or port.last_seen_at.isoformat()),
            }
        )

    summary_json, detail_json, status = build_network_initial_summary(
        ip=str(asset.ip),
        hostname=asset.hostname,
        services=services,
    )
    assessment = resolve_asset_device_assessment(asset)
    if assessment:
        summary_json["device_assessment"] = assessment
        detail_json["device_assessment"] = assessment
    observations = summary_json.get("key_observations")
    if isinstance(observations, list):
        observations.append("当前展示为降级结果，等待发现任务生成完整网络快照")
    else:
        summary_json["key_observations"] = ["当前展示为降级结果，等待发现任务生成完整网络快照"]
    return summary_json, detail_json, status


@router.get("/assets/{asset_id}/credential", response_model=AssetCredentialReadResponse)
def get_asset_credential(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetCredentialReadResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    credential = _get_manual_credential(db, asset_id=asset.id)
    if credential is None:
        return _credential_response(asset_id=asset.id, credential=None, bound=False)

    is_bound = db.scalar(
        select(AssetCredentialBinding.id).where(
            AssetCredentialBinding.asset_id == asset.id,
            AssetCredentialBinding.credential_id == credential.id,
        )
    )
    return _credential_response(asset_id=asset.id, credential=credential, bound=bool(is_bound))


@router.post("/assets/{asset_id}/credential", response_model=AssetCredentialReadResponse)
def upsert_asset_credential(
    asset_id: str,
    payload: AssetCredentialUpsertRequest,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> AssetCredentialReadResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    credential = _upsert_manual_asset_credential(db, asset=asset, payload=payload, current_user=current_user)
    return _credential_response(asset_id=asset.id, credential=credential, bound=True)


@router.post("/assets/{asset_id}/credential/verify", response_model=AssetCredentialVerifyResponse)
def verify_asset_credential(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> AssetCredentialVerifyResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    credential = _get_manual_credential(db=db, asset_id=asset.id)
    if credential is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前资产未配置凭据，请先在资产详情中设置 SSH 凭据")
    return _verify_manual_asset_credential(db, asset=asset, credential=credential)


@router.post("/assets/credentials/batch", response_model=AssetCredentialBatchResponse)
def batch_upsert_asset_credentials(
    payload: AssetCredentialBatchUpsertRequest,
    db: Session = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
) -> AssetCredentialBatchResponse:
    results: list[AssetCredentialBatchResult] = []
    for asset_id in payload.asset_ids:
        normalized_asset_id = str(asset_id or "").strip()
        if not normalized_asset_id:
            continue
        asset = db.get(Asset, normalized_asset_id)
        if asset is None:
            results.append(
                AssetCredentialBatchResult(
                    asset_id=normalized_asset_id,
                    saved=False,
                    verified=False,
                    effective_privilege=None,
                    error_summary="资产不存在",
                )
            )
            continue

        saved = False
        verified = False
        effective_privilege: str | None = None
        error_summary: str | None = None
        try:
            credential = _upsert_manual_asset_credential(
                db,
                asset=asset,
                payload=AssetCredentialUpsertRequest(
                    auth_type=payload.auth_type,
                    username=payload.username,
                    password=payload.password,
                    private_key=payload.private_key,
                    sudo_password=payload.sudo_password,
                    admin_authorized=payload.admin_authorized,
                ),
                current_user=current_user,
            )
            saved = True
            if payload.verify_after_save:
                verify_result = _verify_manual_asset_credential(db, asset=asset, credential=credential)
                verified = str(verify_result.status or "").strip().lower() == "success"
                effective_privilege = verify_result.effective_privilege
                if not verified:
                    error_summary = verify_result.summary or "凭据已保存，但未通过管理员权限验证"
        except HTTPException as exc:
            db.rollback()
            error_summary = str(exc.detail or "保存或验证 SSH 凭据失败")
        except Exception:
            db.rollback()
            error_summary = "保存或验证 SSH 凭据失败"

        results.append(
            AssetCredentialBatchResult(
                asset_id=normalized_asset_id,
                saved=saved,
                verified=verified,
                effective_privilege=effective_privilege,
                error_summary=error_summary,
            )
        )

    success_count = sum(1 for item in results if item.verified)
    return AssetCredentialBatchResponse(
        mode=payload.mode,
        total_count=len(results),
        success_count=success_count,
        failure_count=max(0, len(results) - success_count),
        results=results,
    )


@router.post("/assets/batch/run", response_model=CollectRunResponse, status_code=status.HTTP_202_ACCEPTED)
def run_collection_batch(
    payload: CollectBatchRunRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectRunResponse:
    existing_ids = set(db.scalars(select(Asset.id).where(Asset.id.in_(payload.asset_ids))).all())
    missing_ids = [asset_id for asset_id in payload.asset_ids if asset_id not in existing_ids]
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"以下资产不存在：{', '.join(missing_ids)}",
        )

    task_run = create_task_run(db, task_type=TaskType.INFO_COLLECT, scope_type="asset_batch", scope_id=None, message="批量 SSH 授权深度检查任务已入队")
    task = run_batch_collect_task.delay(
        task_run.id,
        payload.asset_ids,
        payload.credential_id,
        payload.concurrency,
        payload.connect_timeout_seconds,
        payload.command_timeout_seconds,
        payload.asset_timeout_seconds,
    )
    update_task_run(db, task_run, celery_task_id=task.id)
    return CollectRunResponse(task_id=task_run.id, status="pending")


@router.post("/assets/{asset_id}/run", response_model=CollectRunResponse, status_code=status.HTTP_202_ACCEPTED)
def run_collection(
    asset_id: str,
    payload: CollectRunRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectRunResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    credential = _resolve_credential(db=db, asset=asset, credential_id=payload.credential_id)
    if payload.credential_id and credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="凭据不存在")
    if credential is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前资产未配置凭据，请先在资产详情中设置 SSH 凭据")
    if credential.admin_authorized is not True:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前 SSH 凭据尚未确认管理员授权")
    if str(credential.last_verification_status or "").strip().lower() != "success":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前 SSH 凭据尚未完成管理员权限验证")
    if str(credential.last_effective_privilege or "").strip().lower() not in {"root", "sudo"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前 SSH 凭据未验证到管理员权限")

    task_run = create_task_run(db, task_type=TaskType.INFO_COLLECT, scope_type="asset", scope_id=asset_id, message="SSH 授权深度检查任务已入队")
    task = run_asset_collect_task.delay(
        task_run.id,
        asset_id,
        payload.credential_id,
        payload.connect_timeout_seconds,
        payload.command_timeout_seconds,
        payload.asset_timeout_seconds,
    )
    update_task_run(db, task_run, celery_task_id=task.id)
    return CollectRunResponse(task_id=task_run.id, status="pending")


@router.post("/assets/{asset_id}/probe", response_model=CollectProbeRunResponse)
def run_asset_probe(
    asset_id: str,
    payload: CollectProbeRunRequest,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectProbeRunResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    credential = _resolve_credential(db=db, asset=asset, credential_id=payload.credential_id)
    if payload.credential_id and credential is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="凭据不存在")
    if not credential:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="当前资产未配置凭据，请先在资产详情中设置 SSH 凭据")
    if credential.admin_authorized is not True:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="保存 SSH 凭据前必须确认已获得管理员授权")

    try:
        profile = _build_profile(asset=asset, credential=credential)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    result = asyncio.run(
        AsyncSSHCollector().verify_authorization(
            profile,
            options=None,
        )
    )
    credential.last_verified_at = result.verified_at
    credential.last_verification_status = result.status
    credential.last_effective_privilege = result.effective_privilege
    db.add(credential)
    db.commit()
    response = _build_authorization_response(asset.id, result.to_dict())
    return CollectProbeRunResponse.model_validate(_build_probe_response_from_authorization(asset, response).model_dump())


@router.get("/assets/{asset_id}/probe/latest", response_model=CollectProbeLatestResponse)
def get_latest_asset_probe(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectProbeLatestResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")
    credential = _get_manual_credential(db=db, asset_id=asset.id)
    if credential is None or credential.last_verified_at is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="暂无授权验证结果")

    response = AssetCredentialVerifyResponse(
        asset_id=asset.id,
        status=credential.last_verification_status or "failed",
        username=credential.username,
        effective_user=credential.username,
        effective_privilege=credential.last_effective_privilege,
        summary="兼容接口：返回最近一次 SSH 管理员授权验证结果",
        verified_at=credential.last_verified_at.isoformat(),
        errors=[],
        detail_json={
            "authorization_source": "credential_cache",
            "admin_authorized": credential.admin_authorized,
        },
    )
    return CollectProbeLatestResponse.model_validate(_build_probe_response_from_authorization(asset, response).model_dump())


@router.get("/assets/{asset_id}/latest", response_model=CollectLatestResponse)
def get_latest_asset_collection(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectLatestResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    snapshots = db.scalars(
        select(HostSnapshot).where(HostSnapshot.asset_id == asset.id).order_by(HostSnapshot.collected_at.desc()).limit(100)
    ).all()
    latest = _pick_latest_collection_snapshot(snapshots)
    if latest is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="暂无 SSH 授权深度检查结果")

    summary_json, detail_json = _build_latest_collection_payload(latest, asset=asset)
    return CollectLatestResponse(
        asset_id=asset.id,
        status=latest.collection_status,
        collected_at=latest.collected_at.isoformat(),
        summary_json=summary_json,
        detail_json=detail_json,
    )


@router.get("/assets/{asset_id}/initial/latest", response_model=CollectInitialLatestResponse)
def get_latest_asset_initial(
    asset_id: str,
    db: Session = Depends(get_db_session),
    _: User = Depends(get_current_user),
) -> CollectInitialLatestResponse:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="资产不存在")

    snapshots = db.scalars(
        select(HostSnapshot).where(HostSnapshot.asset_id == asset.id).order_by(HostSnapshot.collected_at.desc()).limit(100)
    ).all()
    latest = _pick_latest_network_initial_snapshot(snapshots)
    if latest is None:
        summary_json, detail_json, fallback_status = _build_initial_from_asset(asset)
        if asset.status == AssetStatus.COLLECTING:
            fallback_status = "collecting"
        return CollectInitialLatestResponse(
            asset_id=asset.id,
            status=fallback_status,
            collected_at=(asset.last_seen_at or datetime.now(timezone.utc)).isoformat(),
            summary_json=summary_json,
            detail_json=detail_json,
        )

    summary_json = {}
    detail_json = {}
    if isinstance(latest.software_json, dict):
        summary_json = latest.software_json.get("summary_json") or {}
        detail_json = latest.software_json.get("detail_json") or {}
    if not summary_json and isinstance(latest.services_json, dict):
        summary_json = latest.services_json.get("summary_json") or summary_json
        detail_json = latest.services_json.get("detail_json") or detail_json
    assessment = resolve_asset_device_assessment(asset)
    if assessment:
        summary_json.setdefault("device_assessment", assessment)
        detail_json.setdefault("device_assessment", assessment)

    return CollectInitialLatestResponse(
        asset_id=asset.id,
        status=latest.collection_status,
        collected_at=latest.collected_at.isoformat(),
        summary_json=summary_json,
        detail_json=detail_json,
    )
