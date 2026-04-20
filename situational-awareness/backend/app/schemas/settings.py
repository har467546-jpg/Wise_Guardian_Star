from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.db.models.enums import TaskExecutionStatus
from app.services.ai.providers import (
    normalize_provider_name,
    provider_requires_base_url,
    resolve_provider_base_url,
    resolve_provider_default_wire_api,
    resolve_provider_saved_base_url,
)


def _normalize_csv_text(value: str | None, *, allow_empty: bool = False) -> str:
    items = [item.strip() for item in str(value or "").split(",") if item.strip()]
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    if not deduped and not allow_empty:
        raise ValueError("该字段不能为空")
    return ",".join(deduped)


def _normalize_port_csv(value: str | None, *, allow_empty: bool = False) -> str:
    items = [item.strip() for item in str(value or "").split(",") if item.strip()]
    ports: list[int] = []
    seen: set[int] = set()
    for item in items:
        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError("端口列表必须是逗号分隔的数字") from exc
        if port < 1 or port > 65535:
            raise ValueError("端口号必须位于 1 到 65535 之间")
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
    if not ports and not allow_empty:
        raise ValueError("端口列表不能为空")
    return ",".join(str(port) for port in ports)


LLMProvider = Literal["mock", "openai", "minimax", "custom_proxy", "ollama_remote"]
LLMWireAPI = Literal["auto", "chat_completions", "responses"]


def _normalize_optional_url(value: str | None) -> str:
    return str(value or "").strip()


def _normalize_llm_fields(model: Any) -> Any:
    model.llm_provider = normalize_provider_name(model.llm_provider)  # type: ignore[assignment]
    model.llm_base_url = resolve_provider_saved_base_url(model.llm_provider, model.llm_base_url)
    fields_set = set(getattr(model, "__pydantic_fields_set__", set()) or set())
    if "llm_wire_api" not in fields_set or not str(model.llm_wire_api or "").strip():
        model.llm_wire_api = resolve_provider_default_wire_api(model.llm_provider)  # type: ignore[assignment]
    return model


class PlatformSettingsSectionRead(BaseModel):
    key: str
    title: str
    fields: list[str] = Field(default_factory=list)


class PlatformSecretFieldStateRead(BaseModel):
    configured: bool
    masked_value: str | None = None
    editable: bool = True


class PlatformSettingsRead(BaseModel):
    sections: list[PlatformSettingsSectionRead] = Field(default_factory=list)

    runner_poll_interval_seconds: int
    runner_offline_grace_seconds: int
    remediation_auto_reverify_enabled: bool
    remediation_stop_on_failure: bool
    remediation_prepare_backups_enabled: bool

    discovery_liveness_ports: str
    discovery_liveness_mode: str
    discovery_enable_arp_discovery: bool
    discovery_enable_fping: bool
    discovery_nmap_host_discovery_profile: str
    discovery_service_ports: str
    discovery_high_backdoor_ports: str
    discovery_portset_mode: str
    discovery_top_ports_limit: int
    discovery_nmap_mode: str
    discovery_nmap_min_rate: int
    discovery_nmap_timeout_seconds: int
    discovery_nmap_liveness_timeout_seconds: int
    discovery_nmap_full_scan_timeout_seconds: int
    discovery_nmap_version_intensity: int
    discovery_low_confidence_threshold: int
    discovery_full_scan_host_concurrency: int
    discovery_full_scan_port_concurrency: int
    discovery_service_probe_host_concurrency: int
    discovery_nse_mode: str
    discovery_nse_timeout_seconds: int
    discovery_nse_host_concurrency: int
    discovery_nse_enable_vuln_scripts: bool
    risk_active_verify_connect_timeout_seconds: int
    risk_active_verify_read_timeout_seconds: int
    risk_active_verify_max_concurrency: int

    llm_provider: LLMProvider
    llm_model: str
    llm_base_url: str
    llm_wire_api: LLMWireAPI
    llm_timeout_seconds: int
    llm_api_key: PlatformSecretFieldStateRead

    cors_allow_all: bool
    cors_allow_origins: str
    local_asset_ips: str
    security_admin_cidrs: str = ""
    access_token_expire_minutes: int


class PlatformSettingsUpdate(BaseModel):
    runner_poll_interval_seconds: int = Field(ge=1, le=3600)
    runner_offline_grace_seconds: int = Field(ge=5, le=86400)
    remediation_auto_reverify_enabled: bool
    remediation_stop_on_failure: bool
    remediation_prepare_backups_enabled: bool

    discovery_liveness_ports: str
    discovery_liveness_mode: Literal["multi_source", "nmap_icmp", "tcp_connect"]
    discovery_enable_arp_discovery: bool
    discovery_enable_fping: bool
    discovery_nmap_host_discovery_profile: Literal["balanced", "aggressive"]
    discovery_service_ports: str
    discovery_high_backdoor_ports: str
    discovery_portset_mode: Literal["curated", "top1000_plus_custom", "full"]
    discovery_top_ports_limit: int = Field(ge=1, le=65535)
    discovery_nmap_mode: Literal["off", "enrich"]
    discovery_nmap_min_rate: int = Field(ge=1, le=1_000_000)
    discovery_nmap_timeout_seconds: int = Field(ge=1, le=7200)
    discovery_nmap_liveness_timeout_seconds: int = Field(ge=1, le=7200)
    discovery_nmap_full_scan_timeout_seconds: int = Field(ge=1, le=7200)
    discovery_nmap_version_intensity: int = Field(ge=0, le=9)
    discovery_low_confidence_threshold: int = Field(ge=1, le=100)
    discovery_full_scan_host_concurrency: int = Field(ge=1, le=4096)
    discovery_full_scan_port_concurrency: int = Field(ge=1, le=65535)
    discovery_service_probe_host_concurrency: int = Field(ge=1, le=4096)
    discovery_nse_mode: Literal["off", "whitelist", "all"]
    discovery_nse_timeout_seconds: int = Field(ge=1, le=7200)
    discovery_nse_host_concurrency: int = Field(ge=1, le=4096)
    discovery_nse_enable_vuln_scripts: bool
    risk_active_verify_connect_timeout_seconds: int = Field(ge=1, le=300)
    risk_active_verify_read_timeout_seconds: int = Field(ge=1, le=300)
    risk_active_verify_max_concurrency: int = Field(ge=1, le=1024)

    llm_provider: LLMProvider
    llm_model: str = Field(min_length=1, max_length=128)
    llm_base_url: str = Field(default="", max_length=1024)
    llm_wire_api: LLMWireAPI = "responses"
    llm_timeout_seconds: int = Field(default=60, ge=1, le=600)
    llm_api_key: str | None = Field(default=None, max_length=4096)
    clear_llm_api_key: bool = False

    cors_allow_all: bool
    cors_allow_origins: str
    local_asset_ips: str
    security_admin_cidrs: str = ""
    access_token_expire_minutes: int = Field(ge=5, le=10080)

    @field_validator("discovery_liveness_ports", "discovery_service_ports")
    @classmethod
    def _normalize_required_port_csv(cls, value: str) -> str:
        return _normalize_port_csv(value, allow_empty=False)

    @field_validator("discovery_high_backdoor_ports")
    @classmethod
    def _normalize_optional_port_csv(cls, value: str) -> str:
        return _normalize_port_csv(value, allow_empty=True)

    @field_validator("cors_allow_origins", "local_asset_ips", "security_admin_cidrs")
    @classmethod
    def _normalize_csv(cls, value: str) -> str:
        return _normalize_csv_text(value, allow_empty=True)

    @field_validator("llm_model")
    @classmethod
    def _normalize_model(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("模型名称不能为空")
        return normalized

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _normalize_provider(cls, value: str) -> str:
        return normalize_provider_name(str(value or "mock"))

    @field_validator("llm_base_url")
    @classmethod
    def _normalize_base_url(cls, value: str) -> str:
        return _normalize_optional_url(value)

    @field_validator("llm_api_key")
    @classmethod
    def _normalize_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or ""

    @model_validator(mode="after")
    def _validate_cors(self) -> "PlatformSettingsUpdate":
        if not self.cors_allow_all and not self.cors_allow_origins:
            raise ValueError("关闭全量跨域时必须填写允许的来源列表")
        if self.clear_llm_api_key and self.llm_api_key:
            raise ValueError("清空 API Key 时不能同时提交新的 API Key")
        _normalize_llm_fields(self)
        if provider_requires_base_url(self.llm_provider) and not self.llm_base_url:
            raise ValueError("当前模型接入方式必须填写 Base URL")
        return self


class PlatformSettingsApplyResponse(BaseModel):
    task_id: str
    status: TaskExecutionStatus


class PlatformAIValidateRequest(BaseModel):
    llm_provider: LLMProvider
    llm_model: str = Field(min_length=1, max_length=128)
    llm_base_url: str = Field(default="", max_length=1024)
    llm_wire_api: LLMWireAPI = "responses"
    llm_timeout_seconds: int = Field(default=60, ge=1, le=600)
    llm_api_key: str | None = Field(default=None, max_length=4096)
    clear_llm_api_key: bool = False

    @field_validator("llm_model")
    @classmethod
    def _normalize_validate_model(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized:
            raise ValueError("模型名称不能为空")
        return normalized

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _normalize_validate_provider(cls, value: str) -> str:
        return normalize_provider_name(str(value or "mock"))

    @field_validator("llm_base_url")
    @classmethod
    def _normalize_validate_base_url(cls, value: str) -> str:
        return _normalize_optional_url(value)

    @field_validator("llm_api_key")
    @classmethod
    def _normalize_validate_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or ""

    @model_validator(mode="after")
    def _validate_ai_config(self) -> "PlatformAIValidateRequest":
        if self.clear_llm_api_key and self.llm_api_key:
            raise ValueError("清空 API Key 时不能同时提交新的 API Key")
        return _normalize_llm_fields(self)


class PlatformAIValidateResponse(BaseModel):
    ok: bool
    message: str
    provider: LLMProvider
    model: str
    resolved_base_url: str
    used_saved_api_key: bool = False
    latency_ms: int = Field(default=0, ge=0)


class PlatformAIModelOption(BaseModel):
    id: str
    display_name: str | None = None
    owned_by: str | None = None


class PlatformAIModelsRequest(BaseModel):
    llm_provider: LLMProvider
    llm_base_url: str = Field(default="", max_length=1024)
    llm_wire_api: LLMWireAPI = "responses"
    llm_timeout_seconds: int = Field(default=60, ge=1, le=600)
    llm_api_key: str | None = Field(default=None, max_length=4096)
    clear_llm_api_key: bool = False

    @field_validator("llm_base_url")
    @classmethod
    def _normalize_models_base_url(cls, value: str) -> str:
        return _normalize_optional_url(value)

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _normalize_models_provider(cls, value: str) -> str:
        return normalize_provider_name(str(value or "mock"))

    @field_validator("llm_api_key")
    @classmethod
    def _normalize_models_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or ""

    @model_validator(mode="after")
    def _validate_models_request(self) -> "PlatformAIModelsRequest":
        if self.clear_llm_api_key and self.llm_api_key:
            raise ValueError("清空 API Key 时不能同时提交新的 API Key")
        return _normalize_llm_fields(self)


class PlatformAIModelsResponse(BaseModel):
    ok: bool
    message: str
    provider: LLMProvider
    resolved_base_url: str
    used_saved_api_key: bool = False
    latency_ms: int = Field(default=0, ge=0)
    models: list[PlatformAIModelOption] = Field(default_factory=list)


class PlatformSettingsHelperEvent(BaseModel):
    event_type: Literal["stage", "warning", "success", "failure"] = "stage"
    level: Literal["info", "warning", "error"] = "info"
    stage_code: str | None = None
    stage_name: str | None = None
    message: str
    progress: int | None = None
    payload_json: dict[str, Any] = Field(default_factory=dict)


class PlatformSettingsApplyComplete(BaseModel):
    status: Literal["success", "failure"]
    message: str
    result_json: dict[str, Any] = Field(default_factory=dict)
    error_json: dict[str, Any] = Field(default_factory=dict)
    stage_events: list[PlatformSettingsHelperEvent] = Field(default_factory=list)
