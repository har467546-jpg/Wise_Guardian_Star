from typing import Literal

from pydantic import BaseModel, Field, model_validator


class CollectRunRequest(BaseModel):
    credential_id: str | None = None
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)
    asset_timeout_seconds: int | None = Field(default=None, ge=1, le=900)


class CollectBatchRunRequest(CollectRunRequest):
    asset_ids: list[str] = Field(min_length=1)
    concurrency: int = Field(default=20, ge=1, le=256)


class CollectRunResponse(BaseModel):
    task_id: str
    status: str


class ProbeCommandResult(BaseModel):
    name: str
    command: str
    success: bool
    exit_status: int | None
    stdout: str
    stderr: str
    duration_ms: int


class CollectProbeRunRequest(BaseModel):
    credential_id: str | None = None
    preset: str = Field(default="baseline", pattern="^baseline$")
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)


class CollectProbeRunResponse(BaseModel):
    asset_id: str
    ip: str
    preset: str
    status: str
    probe_method: str = "ssh"
    results: list[ProbeCommandResult]
    errors: list[dict]
    summary_json: dict
    detail_json: dict
    friendly_text: list[str]
    executed_at: str


class CollectProbeLatestResponse(CollectProbeRunResponse):
    pass


class CollectInitialLatestResponse(BaseModel):
    asset_id: str
    status: str
    collected_at: str
    summary_json: dict
    detail_json: dict


class AssetCredentialUpsertRequest(BaseModel):
    auth_type: Literal["password", "key"]
    username: str = Field(min_length=1, max_length=128)
    password: str | None = None
    private_key: str | None = None
    sudo_password: str | None = None
    admin_authorized: bool = False

    @model_validator(mode="after")
    def validate_auth_payload(self) -> "AssetCredentialUpsertRequest":
        if self.auth_type == "password" and not (self.password or "").strip():
            raise ValueError("认证方式为密码时必须填写密码")
        if self.auth_type == "key" and not (self.private_key or "").strip():
            raise ValueError("认证方式为私钥时必须填写私钥")
        if not self.admin_authorized:
            raise ValueError("保存 SSH 凭据前必须确认已获得管理员授权")
        if self.username.strip().lower() != "root" and not (self.sudo_password or "").strip():
            raise ValueError("非 root 用户必须填写 sudo 密码")
        return self


class AssetCredentialReadResponse(BaseModel):
    asset_id: str
    credential_id: str | None
    auth_type: Literal["password", "key"] | None
    username: str | None
    bound: bool
    admin_authorized: bool = False
    last_verified_at: str | None = None
    last_verification_status: str | None = None
    effective_privilege: str | None = None


class AssetCredentialVerifyResponse(BaseModel):
    asset_id: str
    status: str
    username: str | None
    effective_user: str | None
    effective_privilege: str | None
    summary: str
    verified_at: str
    errors: list[dict]
    detail_json: dict


class AssetCredentialBatchUpsertRequest(AssetCredentialUpsertRequest):
    asset_ids: list[str] = Field(min_length=1)
    mode: Literal["same_credential_batch"] = "same_credential_batch"
    verify_after_save: bool = True


class AssetCredentialBatchResult(BaseModel):
    asset_id: str
    saved: bool
    verified: bool
    effective_privilege: str | None = None
    error_summary: str | None = None


class AssetCredentialBatchResponse(BaseModel):
    mode: Literal["same_credential_batch"] = "same_credential_batch"
    total_count: int
    success_count: int
    failure_count: int
    results: list[AssetCredentialBatchResult] = Field(default_factory=list)


class CollectLatestResponse(BaseModel):
    asset_id: str
    status: str
    collected_at: str
    summary_json: dict
    detail_json: dict
