from __future__ import annotations

import re
import shutil
from time import perf_counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.enums import TaskExecutionStatus, TaskType
from app.db.models.task_run import TaskRun
from app.repositories.task_event_repo import create_task_event
from app.repositories.task_repo import create_task_run, get_task_run, update_task_run
from app.schemas.settings import (
    PlatformAIModelOption,
    PlatformAIModelsRequest,
    PlatformAIModelsResponse,
    PlatformAIValidateRequest,
    PlatformAIValidateResponse,
    PlatformSecretFieldStateRead,
    PlatformSettingsApplyComplete,
    PlatformSettingsApplyResponse,
    PlatformSettingsRead,
    PlatformSettingsSectionRead,
    PlatformSettingsUpdate,
)
from app.services.ai.providers import LLMRequest, build_provider, list_remote_models, resolve_provider_base_url

BACKEND_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ENV_PATH = BACKEND_ROOT / ".env.runtime"
EXAMPLE_ENV_PATH = BACKEND_ROOT / ".env.example"
RUNTIME_ENV_LABEL = "backend/.env.runtime"
RESTART_TARGETS = ["backend", "worker"]
SETTINGS_SCOPE_TYPE = "system"
SETTINGS_SCOPE_ID = "platform"

SETTINGS_SECTIONS = [
    PlatformSettingsSectionRead(
        key="remediation_runner",
        title="修复与 Runner",
        fields=[
            "runner_poll_interval_seconds",
            "runner_offline_grace_seconds",
            "remediation_auto_reverify_enabled",
            "remediation_stop_on_failure",
            "remediation_prepare_backups_enabled",
        ],
    ),
    PlatformSettingsSectionRead(
        key="scan_verify",
        title="扫描与验证",
        fields=[
            "discovery_liveness_ports",
            "discovery_liveness_mode",
            "discovery_service_ports",
            "discovery_high_backdoor_ports",
            "discovery_portset_mode",
            "discovery_top_ports_limit",
            "discovery_nmap_mode",
            "discovery_nmap_min_rate",
            "discovery_nmap_timeout_seconds",
            "discovery_nmap_liveness_timeout_seconds",
            "discovery_nmap_full_scan_timeout_seconds",
            "discovery_nmap_version_intensity",
            "discovery_low_confidence_threshold",
            "discovery_full_scan_host_concurrency",
            "discovery_full_scan_port_concurrency",
            "discovery_service_probe_host_concurrency",
            "discovery_nse_mode",
            "discovery_nse_timeout_seconds",
            "discovery_nse_host_concurrency",
            "discovery_nse_enable_vuln_scripts",
            "risk_active_verify_connect_timeout_seconds",
            "risk_active_verify_read_timeout_seconds",
            "risk_active_verify_max_concurrency",
        ],
    ),
    PlatformSettingsSectionRead(
        key="ai_planning",
        title="AI 与会话规划",
        fields=["llm_provider", "llm_model", "llm_base_url", "llm_wire_api", "llm_timeout_seconds", "llm_api_key"],
    ),
    PlatformSettingsSectionRead(
        key="platform_security",
        title="平台与安全",
        fields=["cors_allow_all", "cors_allow_origins", "local_asset_ips", "access_token_expire_minutes"],
    ),
]

FIELD_TO_ENV_KEY = {
    "runner_poll_interval_seconds": "RUNNER_POLL_INTERVAL_SECONDS",
    "runner_offline_grace_seconds": "RUNNER_OFFLINE_GRACE_SECONDS",
    "remediation_auto_reverify_enabled": "REMEDIATION_AUTO_REVERIFY_ENABLED",
    "remediation_stop_on_failure": "REMEDIATION_STOP_ON_FAILURE",
    "remediation_prepare_backups_enabled": "REMEDIATION_PREPARE_BACKUPS_ENABLED",
    "discovery_liveness_ports": "DISCOVERY_LIVENESS_PORTS",
    "discovery_liveness_mode": "DISCOVERY_LIVENESS_MODE",
    "discovery_service_ports": "DISCOVERY_SERVICE_PORTS",
    "discovery_high_backdoor_ports": "DISCOVERY_HIGH_BACKDOOR_PORTS",
    "discovery_portset_mode": "DISCOVERY_PORTSET_MODE",
    "discovery_top_ports_limit": "DISCOVERY_TOP_PORTS_LIMIT",
    "discovery_nmap_mode": "DISCOVERY_NMAP_MODE",
    "discovery_nmap_min_rate": "DISCOVERY_NMAP_MIN_RATE",
    "discovery_nmap_timeout_seconds": "DISCOVERY_NMAP_TIMEOUT_SECONDS",
    "discovery_nmap_liveness_timeout_seconds": "DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS",
    "discovery_nmap_full_scan_timeout_seconds": "DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS",
    "discovery_nmap_version_intensity": "DISCOVERY_NMAP_VERSION_INTENSITY",
    "discovery_low_confidence_threshold": "DISCOVERY_LOW_CONFIDENCE_THRESHOLD",
    "discovery_full_scan_host_concurrency": "DISCOVERY_FULL_SCAN_HOST_CONCURRENCY",
    "discovery_full_scan_port_concurrency": "DISCOVERY_FULL_SCAN_PORT_CONCURRENCY",
    "discovery_service_probe_host_concurrency": "DISCOVERY_SERVICE_PROBE_HOST_CONCURRENCY",
    "discovery_nse_mode": "DISCOVERY_NSE_MODE",
    "discovery_nse_timeout_seconds": "DISCOVERY_NSE_TIMEOUT_SECONDS",
    "discovery_nse_host_concurrency": "DISCOVERY_NSE_HOST_CONCURRENCY",
    "discovery_nse_enable_vuln_scripts": "DISCOVERY_NSE_ENABLE_VULN_SCRIPTS",
    "risk_active_verify_connect_timeout_seconds": "RISK_ACTIVE_VERIFY_CONNECT_TIMEOUT_SECONDS",
    "risk_active_verify_read_timeout_seconds": "RISK_ACTIVE_VERIFY_READ_TIMEOUT_SECONDS",
    "risk_active_verify_max_concurrency": "RISK_ACTIVE_VERIFY_MAX_CONCURRENCY",
    "llm_provider": "LLM_PROVIDER",
    "llm_model": "LLM_MODEL",
    "llm_base_url": "LLM_BASE_URL",
    "llm_wire_api": "LLM_WIRE_API",
    "llm_timeout_seconds": "LLM_TIMEOUT_SECONDS",
    "cors_allow_all": "CORS_ALLOW_ALL",
    "cors_allow_origins": "CORS_ALLOW_ORIGINS",
    "local_asset_ips": "LOCAL_ASSET_IPS",
    "access_token_expire_minutes": "ACCESS_TOKEN_EXPIRE_MINUTES",
}


def _helper_workspace_path(*parts: str) -> str:
    workspace_root = str(getattr(settings, "SETTINGS_HELPER_WORKSPACE_ROOT", "/workspace") or "/workspace").strip().rstrip("/") or "/workspace"
    suffix = "/".join(part.strip("/") for part in parts if str(part or "").strip("/"))
    if not suffix:
        return workspace_root
    return f"{workspace_root}/{suffix}"

def ensure_runtime_env_file() -> Path:
    if RUNTIME_ENV_PATH.exists():
        return RUNTIME_ENV_PATH
    if EXAMPLE_ENV_PATH.exists():
        shutil.copyfile(EXAMPLE_ENV_PATH, RUNTIME_ENV_PATH)
    else:
        RUNTIME_ENV_PATH.write_text("", encoding="utf-8")
    return RUNTIME_ENV_PATH


def _parse_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _stringify_env_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _render_env_file(data: dict[str, str]) -> str:
    lines = [f"{key}={value}" for key, value in data.items()]
    return "\n".join(lines).rstrip() + "\n"


def _mask_secret(value: str | None) -> str | None:
    normalized = str(value or "").strip()
    if not normalized:
        return None
    if len(normalized) <= 6:
        return f"{normalized[:2]}***"
    return f"{normalized[:3]}***{normalized[-3:]}"


def _current_api_key_state() -> PlatformSecretFieldStateRead:
    plain = str(settings.LLM_API_KEY or "").strip()
    return PlatformSecretFieldStateRead(
        configured=bool(plain),
        masked_value=_mask_secret(plain),
        editable=True,
    )


def _resolve_ai_validation_api_key(payload: PlatformAIValidateRequest) -> tuple[str, bool]:
    incoming_api_key = str(payload.llm_api_key or "").strip()
    if incoming_api_key:
        return incoming_api_key, False
    if payload.clear_llm_api_key:
        return "", False
    saved_api_key = str(settings.LLM_API_KEY or "").strip()
    if saved_api_key:
        return saved_api_key, True
    return "", False


def _extract_upstream_error_detail(response: httpx.Response) -> str:
    raw_text = response.text.strip()
    normalized_text = re.sub(r"\s+", " ", raw_text)
    if "<html" in raw_text.lower() or "<!doctype html" in raw_text.lower():
        title_match = re.search(r"<title>\s*([^<]+)\s*</title>", raw_text, re.IGNORECASE)
        title = re.sub(r"\s+", " ", str(title_match.group(1) if title_match else "")).strip()
        if "cloudflare" in raw_text.lower() and "bad gateway" in raw_text.lower():
            return f"上游返回 Cloudflare 错误页（{title or '502 Bad gateway'}），说明目标模型网关当前不可用"
        return f"上游返回 HTML 错误页（{title or '未知页面'}），请检查 Base URL 或网关状态"
    try:
        payload = response.json()
    except Exception:
        return normalized_text[:300]
    if isinstance(payload, dict):
        for key in ("error", "detail", "message"):
            value = payload.get(key)
            if isinstance(value, dict):
                nested = value.get("message")
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
            if isinstance(value, str) and value.strip():
                return value.strip()
    return normalized_text[:300]


def _humanize_ai_validation_error(exc: Exception) -> str:
    if isinstance(exc, ValueError):
        return str(exc)
    if isinstance(exc, httpx.TimeoutException):
        return "请求超时，请检查地址、网络连通性或超时设置"
    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        detail = _extract_upstream_error_detail(exc.response)
        if status_code in {401, 403}:
            return "鉴权失败，请检查 API Key 或访问令牌"
        if status_code == 404:
            return "上游接口路径不可用，请检查 Base URL 是否正确"
        if status_code == 400:
            return f"上游拒绝了请求，请检查模型名称、接口兼容性和请求参数：{detail}" if detail else "上游拒绝了请求，请检查模型名称、接口兼容性和请求参数"
        if status_code >= 500:
            return f"上游模型服务异常：{detail}" if detail else "上游模型服务异常，请稍后重试"
        return f"上游返回异常状态码 {status_code}：{detail}" if detail else f"上游返回异常状态码 {status_code}"
    if isinstance(exc, httpx.RequestError):
        return "无法连接到上游模型服务，请检查地址、端口和网络连通性"
    message = str(exc).strip()
    return message or "AI 连接验证失败"


def get_platform_settings_read() -> PlatformSettingsRead:
    ensure_runtime_env_file()
    return PlatformSettingsRead(
        sections=SETTINGS_SECTIONS,
        runner_poll_interval_seconds=int(settings.RUNNER_POLL_INTERVAL_SECONDS),
        runner_offline_grace_seconds=int(settings.RUNNER_OFFLINE_GRACE_SECONDS),
        remediation_auto_reverify_enabled=bool(settings.REMEDIATION_AUTO_REVERIFY_ENABLED),
        remediation_stop_on_failure=bool(settings.REMEDIATION_STOP_ON_FAILURE),
        remediation_prepare_backups_enabled=bool(settings.REMEDIATION_PREPARE_BACKUPS_ENABLED),
        discovery_liveness_ports=str(settings.DISCOVERY_LIVENESS_PORTS or ""),
        discovery_liveness_mode=str(settings.DISCOVERY_LIVENESS_MODE or "nmap_icmp"),
        discovery_service_ports=str(settings.DISCOVERY_SERVICE_PORTS or ""),
        discovery_high_backdoor_ports=str(settings.DISCOVERY_HIGH_BACKDOOR_PORTS or ""),
        discovery_portset_mode=str(settings.DISCOVERY_PORTSET_MODE or "top1000_plus_custom"),
        discovery_top_ports_limit=int(settings.DISCOVERY_TOP_PORTS_LIMIT),
        discovery_nmap_mode=str(settings.DISCOVERY_NMAP_MODE or "enrich"),
        discovery_nmap_min_rate=int(settings.DISCOVERY_NMAP_MIN_RATE),
        discovery_nmap_timeout_seconds=int(settings.DISCOVERY_NMAP_TIMEOUT_SECONDS),
        discovery_nmap_liveness_timeout_seconds=int(settings.DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS),
        discovery_nmap_full_scan_timeout_seconds=int(settings.DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS),
        discovery_nmap_version_intensity=int(settings.DISCOVERY_NMAP_VERSION_INTENSITY),
        discovery_low_confidence_threshold=int(settings.DISCOVERY_LOW_CONFIDENCE_THRESHOLD),
        discovery_full_scan_host_concurrency=int(settings.DISCOVERY_FULL_SCAN_HOST_CONCURRENCY),
        discovery_full_scan_port_concurrency=int(settings.DISCOVERY_FULL_SCAN_PORT_CONCURRENCY),
        discovery_service_probe_host_concurrency=int(settings.DISCOVERY_SERVICE_PROBE_HOST_CONCURRENCY),
        discovery_nse_mode=str(settings.DISCOVERY_NSE_MODE or "whitelist"),
        discovery_nse_timeout_seconds=int(settings.DISCOVERY_NSE_TIMEOUT_SECONDS),
        discovery_nse_host_concurrency=int(settings.DISCOVERY_NSE_HOST_CONCURRENCY),
        discovery_nse_enable_vuln_scripts=bool(settings.DISCOVERY_NSE_ENABLE_VULN_SCRIPTS),
        risk_active_verify_connect_timeout_seconds=int(settings.RISK_ACTIVE_VERIFY_CONNECT_TIMEOUT_SECONDS),
        risk_active_verify_read_timeout_seconds=int(settings.RISK_ACTIVE_VERIFY_READ_TIMEOUT_SECONDS),
        risk_active_verify_max_concurrency=int(settings.RISK_ACTIVE_VERIFY_MAX_CONCURRENCY),
        llm_provider=str(settings.LLM_PROVIDER or "mock").lower(),  # type: ignore[arg-type]
        llm_model=str(settings.LLM_MODEL or ""),
        llm_base_url=str(settings.LLM_BASE_URL or ""),
        llm_wire_api=str(settings.LLM_WIRE_API or "responses"),
        llm_timeout_seconds=int(settings.LLM_TIMEOUT_SECONDS),
        llm_api_key=_current_api_key_state(),
        cors_allow_all=bool(settings.CORS_ALLOW_ALL),
        cors_allow_origins=str(settings.CORS_ALLOW_ORIGINS or ""),
        local_asset_ips=str(settings.LOCAL_ASSET_IPS or ""),
        access_token_expire_minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def validate_platform_ai_settings(payload: PlatformAIValidateRequest) -> PlatformAIValidateResponse:
    started_at = perf_counter()
    provider_name = str(payload.llm_provider or "mock").strip().lower() or "mock"
    model = str(payload.llm_model or "").strip()
    resolved_api_key, used_saved_api_key = _resolve_ai_validation_api_key(payload)
    resolved_base_url = resolve_provider_base_url(provider_name, payload.llm_base_url)

    try:
        provider_result = build_provider(
            provider_name=provider_name,
            model=model,
            base_url=payload.llm_base_url,
            wire_api=payload.llm_wire_api,
            timeout_seconds=int(payload.llm_timeout_seconds),
            api_key=resolved_api_key,
            fallback_to_mock=False,
        )
        if provider_result.provider_name == "mock":
            latency_ms = int((perf_counter() - started_at) * 1000)
            return PlatformAIValidateResponse(
                ok=True,
                message="Mock 模式无需连接外部模型，当前配置可用",
                provider="mock",
                model=provider_result.model,
                resolved_base_url="",
                used_saved_api_key=False,
                latency_ms=latency_ms,
            )

        provider_result.provider.generate(
            LLMRequest.from_text(
                "仅返回 OK",
                system_prompt="你是平台的 AI 连通性测试助手。请严格只返回 OK。",
            )
        )
        latency_ms = int((perf_counter() - started_at) * 1000)
        return PlatformAIValidateResponse(
            ok=True,
            message="AI 连接验证成功",
            provider=provider_result.provider_name,  # type: ignore[arg-type]
            model=provider_result.model,
            resolved_base_url=provider_result.resolved_base_url,
            used_saved_api_key=used_saved_api_key,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        latency_ms = int((perf_counter() - started_at) * 1000)
        return PlatformAIValidateResponse(
            ok=False,
            message=_humanize_ai_validation_error(exc),
            provider=provider_name,  # type: ignore[arg-type]
            model=model,
            resolved_base_url=resolved_base_url,
            used_saved_api_key=used_saved_api_key,
            latency_ms=latency_ms,
        )


def list_platform_ai_models(payload: PlatformAIModelsRequest) -> PlatformAIModelsResponse:
    started_at = perf_counter()
    provider_name = str(payload.llm_provider or "mock").strip().lower() or "mock"
    resolved_api_key, used_saved_api_key = _resolve_ai_validation_api_key(payload)
    resolved_base_url = resolve_provider_base_url(provider_name, payload.llm_base_url)

    try:
        actual_base_url, models = list_remote_models(
            provider_name=provider_name,
            base_url=payload.llm_base_url,
            api_key=resolved_api_key,
            timeout_seconds=int(payload.llm_timeout_seconds),
        )
        latency_ms = int((perf_counter() - started_at) * 1000)
        return PlatformAIModelsResponse(
            ok=True,
            message=f"已获取 {len(models)} 个模型",
            provider=provider_name,  # type: ignore[arg-type]
            resolved_base_url=actual_base_url or resolved_base_url,
            used_saved_api_key=used_saved_api_key,
            latency_ms=latency_ms,
            models=[
                PlatformAIModelOption(id=item.id, display_name=item.display_name, owned_by=item.owned_by)
                for item in models
            ],
        )
    except Exception as exc:
        latency_ms = int((perf_counter() - started_at) * 1000)
        return PlatformAIModelsResponse(
            ok=False,
            message=_humanize_ai_validation_error(exc),
            provider=provider_name,  # type: ignore[arg-type]
            resolved_base_url=resolved_base_url,
            used_saved_api_key=used_saved_api_key,
            latency_ms=latency_ms,
            models=[],
        )


def _build_updated_env_map(payload: PlatformSettingsUpdate) -> tuple[dict[str, str], list[str]]:
    runtime_path = ensure_runtime_env_file()
    env_map = _parse_env_file(runtime_path)
    if not env_map:
        env_map = _parse_env_file(EXAMPLE_ENV_PATH)

    updated = payload.model_dump()
    changed_keys: list[str] = []
    for field_name, env_key in FIELD_TO_ENV_KEY.items():
        value = _stringify_env_value(updated[field_name])
        if env_map.get(env_key) != value:
            changed_keys.append(env_key)
        env_map[env_key] = value

    incoming_api_key = updated.get("llm_api_key")
    clear_api_key = bool(updated.get("clear_llm_api_key"))
    legacy_encrypted_present = "LLM_API_KEY_ENCRYPTED" in env_map
    if incoming_api_key is not None or clear_api_key:
        if clear_api_key:
            if env_map.get("LLM_API_KEY"):
                changed_keys.append("LLM_API_KEY")
            env_map["LLM_API_KEY"] = ""
        elif incoming_api_key:
            value = str(incoming_api_key)
            if env_map.get("LLM_API_KEY") != value:
                changed_keys.append("LLM_API_KEY")
            env_map["LLM_API_KEY"] = value
    if legacy_encrypted_present:
        env_map.pop("LLM_API_KEY_ENCRYPTED", None)
        changed_keys.append("LLM_API_KEY_ENCRYPTED")

    deduped_changed: list[str] = []
    seen: set[str] = set()
    for item in changed_keys:
        if item in seen:
            continue
        seen.add(item)
        deduped_changed.append(item)
    return env_map, deduped_changed


def _append_stage_event(
    db: Session,
    task_id: str,
    *,
    stage_code: str,
    stage_name: str,
    message: str,
    progress: int,
    payload_json: dict[str, Any] | None = None,
    event_type: str = "stage",
    level: str = "info",
) -> None:
    create_task_event(
        db,
        task_run_id=task_id,
        event_type=event_type,
        level=level,
        stage_code=stage_code,
        stage_name=stage_name,
        message=message,
        progress=progress,
        payload_json=payload_json or {},
    )


def queue_platform_settings_apply(db: Session, payload: PlatformSettingsUpdate) -> PlatformSettingsApplyResponse:
    env_map, changed_keys = _build_updated_env_map(payload)
    env_content = _render_env_file(env_map)
    task = create_task_run(
        db,
        task_type=TaskType.SETTINGS_APPLY,
        scope_type=SETTINGS_SCOPE_TYPE,
        scope_id=SETTINGS_SCOPE_ID,
        message="系统设置应用任务已入队",
    )
    result_json = {
        "changed_keys": changed_keys,
        "restart_targets": RESTART_TARGETS,
        "runtime_env_path": RUNTIME_ENV_LABEL,
        "helper_result": {"dispatch_status": "queued"},
        "applied_at": None,
    }
    update_task_run(
        db,
        task,
        status=TaskExecutionStatus.RUNNING,
        progress=8,
        message="设置校验完成，准备下发应用任务",
        result_json=result_json,
    )
    _append_stage_event(
        db,
        task.id,
        stage_code="validate_settings",
        stage_name="校验设置",
        message="设置校验完成",
        progress=8,
        payload_json={"changed_keys": changed_keys},
    )
    _append_stage_event(
        db,
        task.id,
        stage_code="process_ai_key",
        stage_name="处理 AI Key",
        message="AI Key 字段已完成处理",
        progress=18,
        payload_json={"secrets_changed": "LLM_API_KEY" in changed_keys or "LLM_API_KEY_ENCRYPTED" in changed_keys},
    )
    helper_payload = {
        "task_id": task.id,
        "env_content": env_content,
        "changed_keys": changed_keys,
        "restart_targets": RESTART_TARGETS,
        "runtime_env_path": _helper_workspace_path("backend", ".env.runtime"),
        "compose_dir": _helper_workspace_path("infra"),
        "health_url": "http://backend:8000/health",
        "callback_url": f"http://backend:8000{settings.API_V1_PREFIX}/settings/internal/tasks/{task.id}/complete",
    }
    try:
        response = httpx.post(
            settings.SETTINGS_HELPER_URL,
            headers={
                "Content-Type": "application/json",
                "X-Settings-Helper-Token": settings.SETTINGS_HELPER_TOKEN,
            },
            json=helper_payload,
            timeout=10,
        )
        response.raise_for_status()
    except Exception as exc:
        error_json = {"error": f"设置应用执行器不可用: {exc}"}
        update_task_run(
            db,
            task,
            status=TaskExecutionStatus.FAILURE,
            progress=100,
            message="设置应用执行器下发失败",
            result_json=result_json,
            error_json=error_json,
        )
        _append_stage_event(
            db,
            task.id,
            stage_code="dispatch_helper",
            stage_name="下发执行器",
            message="设置应用执行器下发失败",
            progress=100,
            payload_json=error_json,
            event_type="failure",
            level="error",
        )
        raise RuntimeError("设置应用执行器当前不可用，请稍后重试") from exc

    helper_result = dict(result_json.get("helper_result") or {})
    helper_result["dispatch_status"] = "accepted"
    helper_result["dispatch_response"] = response.json() if response.content else {}
    result_json["helper_result"] = helper_result
    update_task_run(
        db,
        task,
        status=TaskExecutionStatus.RUNNING,
        progress=30,
        message="设置应用任务已下发",
        result_json=result_json,
    )
    _append_stage_event(
        db,
        task.id,
        stage_code="dispatch_helper",
        stage_name="下发执行器",
        message="设置应用任务已下发至宿主机执行器",
        progress=30,
        payload_json={"helper_url": settings.SETTINGS_HELPER_URL},
    )
    db.commit()
    db.refresh(task)
    return PlatformSettingsApplyResponse(task_id=task.id, status=task.status)


def complete_platform_settings_apply(db: Session, task_id: str, payload: PlatformSettingsApplyComplete) -> TaskRun:
    task = get_task_run(db, task_id)
    if task is None or task.task_type != TaskType.SETTINGS_APPLY:
        raise LookupError("设置应用任务不存在")
    result_json = dict(task.result_json or {})
    result_json.update(payload.result_json or {})
    for event in payload.stage_events:
        _append_stage_event(
            db,
            task.id,
            stage_code=event.stage_code or "",
            stage_name=event.stage_name or event.message,
            message=event.message,
            progress=event.progress or task.progress,
            payload_json=event.payload_json,
            event_type=event.event_type,
            level=event.level,
        )
    if payload.status == "success":
        update_task_run(
            db,
            task,
            status=TaskExecutionStatus.SUCCESS,
            progress=100,
            message=payload.message,
            result_json=result_json,
            error_json={},
        )
        _append_stage_event(
            db,
            task.id,
            stage_code="complete_apply",
            stage_name="完成应用",
            message=payload.message,
            progress=100,
            payload_json=result_json,
            event_type="success",
        )
    else:
        update_task_run(
            db,
            task,
            status=TaskExecutionStatus.FAILURE,
            progress=100,
            message=payload.message,
            result_json=result_json,
            error_json=payload.error_json or {"error": payload.message},
        )
        _append_stage_event(
            db,
            task.id,
            stage_code="complete_apply",
            stage_name="完成应用",
            message=payload.message,
            progress=100,
            payload_json=payload.error_json or {"error": payload.message},
            event_type="failure",
            level="error",
        )
    db.commit()
    db.refresh(task)
    return task


def verify_settings_helper_token(token: str | None) -> None:
    if token != settings.SETTINGS_HELPER_TOKEN:
        raise PermissionError("settings helper token invalid")
