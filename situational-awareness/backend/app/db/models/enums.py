from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"


class AssetStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    COLLECTING = "collecting"
    UNKNOWN = "unknown"


class DiscoveryJobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CredentialAuthType(str, Enum):
    PASSWORD = "password"
    KEY = "key"


class RiskSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, Enum):
    OPEN = "open"
    IGNORED = "ignored"
    FIXED = "fixed"


class ReportScope(str, Enum):
    JOB = "job"
    ASSET = "asset"


class TaskType(str, Enum):
    ASSET_SCAN = "asset_scan"
    INFO_COLLECT = "info_collect"
    RISK_VERIFY = "risk_verify"
    REPORT_GENERATE = "report_generate"
    CREDENTIAL_VERIFY = "credential_verify"
    RUNNER_INSTALL = "runner_install"
    REMEDIATION_EXECUTE = "remediation_execute"
    AGENT_ORCHESTRATE = "agent_orchestrate"
    SETTINGS_APPLY = "settings_apply"
    VULN_INTEL_SYNC = "vuln_intel_sync"


class TaskExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    RETRY = "retry"
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELED = "canceled"
