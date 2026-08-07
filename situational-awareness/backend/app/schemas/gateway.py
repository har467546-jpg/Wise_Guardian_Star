from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

GatewayProvider = Literal["mock", "openai", "anthropic", "minimax", "custom_proxy", "ollama"]
GatewayStatus = Literal["active", "disabled"]
GatewayWireAPI = Literal["", "auto", "chat_completions", "responses"]


class GatewayChannelBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    provider: GatewayProvider
    api_base: str = Field(default="", max_length=1024)
    model_name: str = Field(min_length=1, max_length=128)
    priority: int = Field(default=100, ge=1, le=100)
    status: GatewayStatus = "active"
    wire_api: GatewayWireAPI = ""
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    supports_json_mode: bool | None = None
    supports_streaming: bool | None = None
    weight: float = Field(default=1.0, ge=0.01, le=100.0)
    tags: list[str] = Field(default_factory=list, max_length=20)
    config_json: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name", "api_base", "model_name", "wire_api", mode="before")
    @classmethod
    def _strip_text(cls, value: str | None) -> str:
        return str(value or "").strip()

    @field_validator("provider", mode="before")
    @classmethod
    def _normalize_provider(cls, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized == "ollama_remote":
            return "ollama"
        return normalized

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("标签必须是数组")
        tags: list[str] = []
        seen: set[str] = set()
        for item in value:
            tag = str(item or "").strip().lower()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            tags.append(tag)
        return tags


class GatewayChannelCreate(GatewayChannelBase):
    api_key: str | None = Field(default=None, max_length=4096)

    @field_validator("api_key")
    @classmethod
    def _normalize_api_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()

    @model_validator(mode="after")
    def _validate_create(self) -> "GatewayChannelCreate":
        if self.provider in {"openai", "anthropic", "minimax", "custom_proxy"} and not self.api_key:
            raise ValueError("当前通道类型必须填写 API Key")
        if self.provider in {"anthropic", "custom_proxy", "ollama"} and not self.api_base:
            raise ValueError("当前通道类型必须填写 API Base")
        return self


class GatewayChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    provider: GatewayProvider | None = None
    api_base: str | None = Field(default=None, max_length=1024)
    api_key: str | None = Field(default=None, max_length=4096)
    clear_api_key: bool = False
    model_name: str | None = Field(default=None, min_length=1, max_length=128)
    priority: int | None = Field(default=None, ge=1, le=100)
    status: GatewayStatus | None = None
    wire_api: GatewayWireAPI | None = None
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)
    supports_json_mode: bool | None = None
    supports_streaming: bool | None = None
    weight: float | None = Field(default=None, ge=0.01, le=100.0)
    tags: list[str] | None = Field(default=None, max_length=20)
    config_json: dict[str, Any] | None = None

    @field_validator("name", "api_base", "api_key", "model_name", "wire_api", mode="before")
    @classmethod
    def _strip_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return str(value or "").strip()

    @field_validator("provider", mode="before")
    @classmethod
    def _normalize_optional_provider(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = str(value or "").strip().lower()
        if normalized == "ollama_remote":
            return "ollama"
        return normalized

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_optional_tags(cls, value: Any) -> list[str] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("标签必须是数组")
        tags: list[str] = []
        seen: set[str] = set()
        for item in value:
            tag = str(item or "").strip().lower()
            if not tag or tag in seen:
                continue
            seen.add(tag)
            tags.append(tag)
        return tags

    @model_validator(mode="after")
    def _validate_update(self) -> "GatewayChannelUpdate":
        if self.clear_api_key and self.api_key:
            raise ValueError("清空 API Key 时不能同时提交新的 API Key")
        return self


class GatewayChannelTestResponse(BaseModel):
    channel_id: int
    success: bool
    latency_ms: int
    error: str = ""
    status_code: int | None = None
    purpose: str = "probe"
