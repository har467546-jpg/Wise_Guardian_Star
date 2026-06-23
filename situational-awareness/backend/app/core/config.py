import os
import secrets
import shutil
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

try:
    import fcntl
except ModuleNotFoundError:
    fcntl = None

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.fernet import Fernet


BACKEND_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_ENV_PATH = BACKEND_ROOT / ".env.runtime"
EXAMPLE_ENV_PATH = BACKEND_ROOT / ".env.example"
LEGACY_ENV_PATH = BACKEND_ROOT / ".env"
RUNTIME_ENV_LOCK_PATH = BACKEND_ROOT / ".env.runtime.lock"
RUNTIME_ENV_BOOTSTRAP_MARKER_PATH = BACKEND_ROOT / ".env.runtime.bootstrap"


def _default_private_network_cors_origins() -> str:
    origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://192.168.*.*:3000",
        "http://10.*.*.*:3000",
    ]
    origins.extend(f"http://172.{second_octet}.*.*:3000" for second_octet in range(16, 32))
    return ",".join(origins)


DEFAULT_PRIVATE_NETWORK_CORS_ORIGINS = _default_private_network_cors_origins()
WEAK_RUNTIME_SECRET_KEYS = {"", "change-me", "change-this-secret"}


@dataclass(frozen=True, slots=True)
class RuntimeEnvBootstrapState:
    runtime_env_path: Path
    generated_encryption_key: bool = False
    generated_secret_key: bool = False


def _atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent) as handle:
        handle.write(content)
        temp_name = handle.name
    Path(temp_name).replace(path)


def _ensure_runtime_env_file() -> Path:
    if RUNTIME_ENV_PATH.exists():
        return RUNTIME_ENV_PATH
    RUNTIME_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    if EXAMPLE_ENV_PATH.exists():
        shutil.copyfile(EXAMPLE_ENV_PATH, RUNTIME_ENV_PATH)
    else:
        RUNTIME_ENV_PATH.write_text("", encoding="utf-8")
    return RUNTIME_ENV_PATH


def _write_bootstrap_marker(*, generated_encryption_key: bool, generated_secret_key: bool) -> None:
    _atomic_write_text(
        RUNTIME_ENV_BOOTSTRAP_MARKER_PATH,
        "\n".join(
            [
                f"generated_encryption_key={str(generated_encryption_key).lower()}",
                f"generated_secret_key={str(generated_secret_key).lower()}",
            ]
        )
        + "\n",
    )


def _extract_env_value(lines: list[str], key: str) -> str:
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        existing_key, value = raw_line.split("=", 1)
        if existing_key.strip() == key:
            return value.strip()
    return ""


def _has_env_key(lines: list[str], key: str) -> bool:
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        existing_key, _ = raw_line.split("=", 1)
        if existing_key.strip() == key:
            return True
    return False


def _upsert_env_line(lines: list[str], key: str, value: str) -> list[str]:
    updated = False
    rendered = list(lines)
    for index, raw_line in enumerate(rendered):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        existing_key, _ = raw_line.split("=", 1)
        if existing_key.strip() == key:
            rendered[index] = f"{key}={value}"
            updated = True
            break
    if not updated:
        if rendered and rendered[-1].strip():
            rendered.append("")
        rendered.append(f"{key}={value}")
    return rendered


def _drop_env_line(lines: list[str], key: str) -> list[str]:
    rendered: list[str] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            rendered.append(raw_line)
            continue
        existing_key, _ = raw_line.split("=", 1)
        if existing_key.strip() == key:
            continue
        rendered.append(raw_line)
    return rendered


def ensure_runtime_encryption_key() -> RuntimeEnvBootstrapState:
    if RUNTIME_ENV_PATH == BACKEND_ROOT / ".env.runtime":
        if _process_env_has_runtime_secrets():
            return RuntimeEnvBootstrapState(runtime_env_path=RUNTIME_ENV_PATH)
        if _process_env_is_production() and not RUNTIME_ENV_PATH.exists():
            return RuntimeEnvBootstrapState(runtime_env_path=RUNTIME_ENV_PATH)

    RUNTIME_ENV_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with RUNTIME_ENV_LOCK_PATH.open("a+", encoding="utf-8") as lock_handle:
        if fcntl is not None:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        runtime_env = _ensure_runtime_env_file()
        lines = runtime_env.read_text(encoding="utf-8").splitlines()
        generated_secret_key = False
        generated_encryption_key = False
        updated_lines = list(lines)

        if _extract_env_value(updated_lines, "SECRET_KEY") in WEAK_RUNTIME_SECRET_KEYS:
            updated_lines = _upsert_env_line(updated_lines, "SECRET_KEY", secrets.token_urlsafe(48))
            generated_secret_key = True

        if not _extract_env_value(updated_lines, "ENCRYPTION_KEY"):
            generated_key = Fernet.generate_key().decode()
            updated_lines = _upsert_env_line(updated_lines, "ENCRYPTION_KEY", generated_key)
            generated_encryption_key = True

        if generated_secret_key or generated_encryption_key:
            _atomic_write_text(runtime_env, "\n".join(updated_lines).rstrip("\n") + "\n")
            _write_bootstrap_marker(
                generated_encryption_key=generated_encryption_key,
                generated_secret_key=generated_secret_key,
            )
        return RuntimeEnvBootstrapState(
            runtime_env_path=runtime_env,
            generated_encryption_key=generated_encryption_key,
            generated_secret_key=generated_secret_key,
        )


def _process_env_has_runtime_secrets() -> bool:
    secret_key = str(os.getenv("SECRET_KEY") or "").strip()
    encryption_key = str(os.getenv("ENCRYPTION_KEY") or "").strip()
    return bool(secret_key and secret_key not in WEAK_RUNTIME_SECRET_KEYS and encryption_key)


def _process_env_is_production() -> bool:
    return str(os.getenv("ENV") or "").strip().lower() in {"prod", "production"}


def migrate_legacy_llm_api_key_storage() -> bool:
    if _process_env_is_production() and not RUNTIME_ENV_PATH.exists():
        return False
    runtime_env = _ensure_runtime_env_file()
    lines = runtime_env.read_text(encoding="utf-8").splitlines()
    has_legacy_key = _has_env_key(lines, "LLM_API_KEY_ENCRYPTED")
    if not has_legacy_key:
        return False
    plain_value = _extract_env_value(lines, "LLM_API_KEY")
    encrypted_value = _extract_env_value(lines, "LLM_API_KEY_ENCRYPTED")
    updated_lines = list(lines)
    if not plain_value and encrypted_value:
        encryption_key = _extract_env_value(lines, "ENCRYPTION_KEY")
        if not encryption_key:
            return False
        try:
            plain_value = Fernet(encryption_key.encode()).decrypt(encrypted_value.encode()).decode()
        except Exception:
            return False
        updated_lines = _upsert_env_line(updated_lines, "LLM_API_KEY", plain_value)
    updated_lines = _drop_env_line(updated_lines, "LLM_API_KEY_ENCRYPTED")
    _atomic_write_text(runtime_env, "\n".join(updated_lines).rstrip("\n") + "\n")
    return True


def consume_runtime_bootstrap_marker() -> bool:
    if not RUNTIME_ENV_BOOTSTRAP_MARKER_PATH.exists():
        return False
    try:
        RUNTIME_ENV_BOOTSTRAP_MARKER_PATH.unlink()
    except FileNotFoundError:
        return False
    return True


def _parse_env_file(path: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    if not path.exists():
        return snapshot
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        snapshot[key.strip()] = value.strip()
    return snapshot


def read_runtime_env_snapshot() -> dict[str, str]:
    runtime_env = _ensure_runtime_env_file()
    snapshot = _parse_env_file(runtime_env)
    if not snapshot:
        snapshot = _parse_env_file(EXAMPLE_ENV_PATH)

    override_keys = set(snapshot)
    override_keys.update(_parse_env_file(EXAMPLE_ENV_PATH))
    for key in override_keys:
        env_value = os.getenv(key)
        if env_value is not None:
            snapshot[key] = env_value.strip()
    return snapshot


def read_runtime_env_value(key: str, fallback: str = "") -> str:
    value = read_runtime_env_snapshot().get(key)
    if value is None:
        return str(fallback or "")
    return str(value).strip()


runtime_env_bootstrap_state = ensure_runtime_encryption_key()
migrate_legacy_llm_api_key_storage()


class Settings(BaseSettings):
    APP_NAME: str = "Asset Situational Awareness"
    APP_VERSION: str = "0.1.0"
    API_V1_PREFIX: str = "/api/v1"

    ENV: str = "dev"
    SECRET_KEY: str = Field(default="change-me", min_length=8)
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8
    REFRESH_TOKEN_EXPIRE_DAYS: int = 14
    JWT_ALGORITHM: str = "HS256"

    DATABASE_URL: str = "postgresql+pg8000://asset:asset@postgres:5432/assetdb"
    REDIS_URL: str = "redis://redis:6379/0"
    DEVICE_ALERTS_REDIS_CHANNEL: str = "sa:device_abnormal_alerts"
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 600
    RATE_LIMIT_AUTH_PER_MINUTE: int = 60
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_REDIS_PREFIX: str = "sa:rate_limit"
    RATE_LIMIT_EXEMPT_PATHS: str = "/health,/docs,/redoc,/openapi.json"

    CORS_ALLOW_ALL: bool = False
    CORS_ALLOW_ORIGINS: str = DEFAULT_PRIVATE_NETWORK_CORS_ORIGINS
    LOCAL_ASSET_IPS: str = "127.0.0.1,::1"
    SECURITY_ADMIN_CIDRS: str = ""
    SECURITY_TRUSTED_PROXY_CIDRS: str = "127.0.0.1/32,::1/128,172.16.0.0/12"
    SECURITY_WS_TICKET_TTL_SECONDS: int = 10
    SECURITY_TOKEN_DENYLIST_ENABLED: bool = True
    SECURITY_TOKEN_DENYLIST_REDIS_PREFIX: str = "sa:token_denylist"
    SECURITY_REFRESH_TOKEN_REDIS_PREFIX: str = "sa:refresh_token"
    SECURITY_REFRESH_TOKEN_GRACE_SECONDS: int = 10
    SECURITY_USER_STATE_CACHE_PREFIX: str = "sa:user_state"
    SECURITY_USER_STATE_CACHE_TTL_SECONDS: int = 60
    SECURITY_USER_REVOKED_AFTER_PREFIX: str = "sa:user_revoked_after"
    SECURITY_WS_TICKET_REDIS_PREFIX: str = "sa:ws_ticket"
    AGENT_CHECKPOINT_REDIS_PREFIX: str = "sa:agent_checkpoint"
    AGENT_CHECKPOINT_TTL_SECONDS: int = 86400
    SECURITY_TERMINAL_INPUT_FILTER_ENABLED: bool = True
    AUTO_CREATE_SCHEMA: bool = False
    STRICT_SCHEMA_REVISION_CHECK: bool = False

    ENCRYPTION_KEY: str = ""
    SETTINGS_HELPER_URL: str = "http://settings-helper:8091/internal/apply"
    SETTINGS_HELPER_TOKEN: str = "change-settings-helper-token"
    SETTINGS_HELPER_WORKSPACE_ROOT: str = "/workspace"

    DISCOVERY_LIVENESS_PORTS: str = "22,80,443,8080,8443"
    DISCOVERY_LIVENESS_MODE: str = "multi_source"
    DISCOVERY_NMAP_MIN_RATE: int = 100000
    DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS: int = 90
    DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS: int = 90
    DISCOVERY_ENABLE_ARP_DISCOVERY: bool = True
    DISCOVERY_ENABLE_FPING: bool = True
    DISCOVERY_NMAP_HOST_DISCOVERY_PROFILE: str = "balanced"
    DISCOVERY_SERVICE_PORTS: str = (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,"
        "1433,1521,2049,2375,2376,3000,3306,3389,5432,5601,5672,5900,"
        "5984,6379,6443,7001,8000,8080,8081,8443,9000,9090,9200,9300,"
        "11211,27017"
    )
    DISCOVERY_HIGH_BACKDOOR_PORTS: str = (
        "1337,4444,5555,6666,6667,6969,7007,10001,10008,12345,12346,16000,"
        "20001,30001,40001,50001,"
        "19191,20034,27374,31337,32764,54321,55555,60000,65000"
    )
    DISCOVERY_NMAP_MODE: str = "enrich"
    DISCOVERY_NMAP_TIMEOUT_SECONDS: int = 8
    DISCOVERY_LOW_CONFIDENCE_THRESHOLD: int = 70
    DISCOVERY_PORTSET_MODE: str = "top1000_plus_custom"
    DISCOVERY_TOP_PORTS_LIMIT: int = 1000
    DISCOVERY_FULL_SCAN_HOST_CONCURRENCY: int = 8
    DISCOVERY_FULL_SCAN_PORT_CONCURRENCY: int = 256
    DISCOVERY_SERVICE_PROBE_HOST_CONCURRENCY: int = 32
    DISCOVERY_NMAP_VERSION_INTENSITY: int = 7
    DISCOVERY_NSE_MODE: str = "whitelist"
    DISCOVERY_NSE_TIMEOUT_SECONDS: int = 8
    DISCOVERY_NSE_HOST_CONCURRENCY: int = 8
    DISCOVERY_NSE_ENABLE_VULN_SCRIPTS: bool = True
    DISCOVERY_WEB_PROBE_CONNECT_TIMEOUT_SECONDS: float = 1.5
    DISCOVERY_WEB_PROBE_READ_TIMEOUT_SECONDS: float = 2.0
    DISCOVERY_WEB_PROBE_HOST_CONCURRENCY: int = 16
    CAMPUS_DEFAULT_PORTSET_MODE: str = "top1000_plus_custom"
    CAMPUS_ALLOW_FULL_SCAN_DEFAULT: bool = False
    CAMPUS_ZONE_HOST_CONCURRENCY_LIMIT: int = 8
    CAMPUS_ZONE_NMAP_MIN_RATE: int = 5000
    CAMPUS_DHCP_DEFAULT_INTERVAL_SECONDS: int = 1800
    CAMPUS_SNMP_DEFAULT_INTERVAL_SECONDS: int = 1800
    CAMPUS_AUTO_BOOTSTRAP_ENABLED: bool = True
    CAMPUS_BOOTSTRAP_DHCP_LEASE_PATH: str = ""
    RISK_ACTIVE_VERIFY_CONNECT_TIMEOUT_SECONDS: int = 3
    RISK_ACTIVE_VERIFY_READ_TIMEOUT_SECONDS: int = 3
    RISK_ACTIVE_VERIFY_MAX_CONCURRENCY: int = 4
    TASK_ACTIVE_STALE_AFTER_HOURS: int = 24
    RUNNER_PUBLIC_BASE_URL: str = ""
    VULN_INTEL_SYNC_TIMEOUT_SECONDS: int = 20
    VULN_INTEL_STALE_AFTER_HOURS: int = 36
    VULN_INTEL_CVE_PROJECT_URL: str = "https://cveawg.mitre.org/api/cve"
    VULN_INTEL_CVE_LIST_URL: str = ""
    VULN_INTEL_OSV_URL: str = "https://api.osv.dev/v1/vulns"
    VULN_INTEL_NVD_URL: str = ""
    VULN_INTEL_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    VULN_INTEL_EPSS_URL: str = "https://api.first.org/data/v1/epss"
    RUNNER_POLL_INTERVAL_SECONDS: int = 10
    RUNNER_OFFLINE_GRACE_SECONDS: int = 45
    REMEDIATION_AUTO_REVERIFY_ENABLED: bool = True
    REMEDIATION_STOP_ON_FAILURE: bool = True
    REMEDIATION_PREPARE_BACKUPS_ENABLED: bool = True

    LLM_PROVIDER: str = "mock"
    LLM_API_KEY: str = ""
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_BASE_URL: str = ""
    LLM_WIRE_API: str = "responses"
    LLM_TIMEOUT_SECONDS: int = 60
    HAOR_REPLY_REWRITE_ENABLED: bool = False

    model_config = SettingsConfigDict(
        env_file=(str(LEGACY_ENV_PATH), str(EXAMPLE_ENV_PATH), str(RUNTIME_ENV_PATH)),
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    def resolved_llm_api_key(self) -> str:
        return str(self.LLM_API_KEY or "").strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
