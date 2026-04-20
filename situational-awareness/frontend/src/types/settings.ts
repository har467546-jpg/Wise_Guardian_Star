import type { TaskStatus } from "@/types/task";

export type PlatformSettingsSection = {
  key: string;
  title: string;
  fields: string[];
};

export type PlatformSecretFieldState = {
  configured: boolean;
  masked_value: string | null;
  editable: boolean;
};

export type LLMProvider = "mock" | "openai" | "minimax" | "custom_proxy" | "ollama_remote";
export type LLMWireAPI = "auto" | "chat_completions" | "responses";

export type PlatformSettings = {
  sections: PlatformSettingsSection[];
  runner_poll_interval_seconds: number;
  runner_offline_grace_seconds: number;
  remediation_auto_reverify_enabled: boolean;
  remediation_stop_on_failure: boolean;
  remediation_prepare_backups_enabled: boolean;
  discovery_liveness_ports: string;
  discovery_liveness_mode: "multi_source" | "nmap_icmp" | "tcp_connect";
  discovery_enable_arp_discovery: boolean;
  discovery_enable_fping: boolean;
  discovery_nmap_host_discovery_profile: "balanced" | "aggressive";
  discovery_service_ports: string;
  discovery_high_backdoor_ports: string;
  discovery_portset_mode: "curated" | "top1000_plus_custom" | "full";
  discovery_top_ports_limit: number;
  discovery_nmap_mode: "off" | "enrich";
  discovery_nmap_min_rate: number;
  discovery_nmap_timeout_seconds: number;
  discovery_nmap_liveness_timeout_seconds: number;
  discovery_nmap_full_scan_timeout_seconds: number;
  discovery_nmap_version_intensity: number;
  discovery_low_confidence_threshold: number;
  discovery_full_scan_host_concurrency: number;
  discovery_full_scan_port_concurrency: number;
  discovery_service_probe_host_concurrency: number;
  discovery_nse_mode: "off" | "whitelist" | "all";
  discovery_nse_timeout_seconds: number;
  discovery_nse_host_concurrency: number;
  discovery_nse_enable_vuln_scripts: boolean;
  risk_active_verify_connect_timeout_seconds: number;
  risk_active_verify_read_timeout_seconds: number;
  risk_active_verify_max_concurrency: number;
  llm_provider: LLMProvider;
  llm_model: string;
  llm_base_url: string;
  llm_wire_api: LLMWireAPI;
  llm_timeout_seconds: number;
  llm_api_key: PlatformSecretFieldState;
  cors_allow_all: boolean;
  cors_allow_origins: string;
  local_asset_ips: string;
  security_admin_cidrs: string;
  access_token_expire_minutes: number;
};

export type PlatformSettingsInput = {
  runner_poll_interval_seconds: number;
  runner_offline_grace_seconds: number;
  remediation_auto_reverify_enabled: boolean;
  remediation_stop_on_failure: boolean;
  remediation_prepare_backups_enabled: boolean;
  discovery_liveness_ports: string;
  discovery_liveness_mode: "multi_source" | "nmap_icmp" | "tcp_connect";
  discovery_enable_arp_discovery: boolean;
  discovery_enable_fping: boolean;
  discovery_nmap_host_discovery_profile: "balanced" | "aggressive";
  discovery_service_ports: string;
  discovery_high_backdoor_ports: string;
  discovery_portset_mode: "curated" | "top1000_plus_custom" | "full";
  discovery_top_ports_limit: number;
  discovery_nmap_mode: "off" | "enrich";
  discovery_nmap_min_rate: number;
  discovery_nmap_timeout_seconds: number;
  discovery_nmap_liveness_timeout_seconds: number;
  discovery_nmap_full_scan_timeout_seconds: number;
  discovery_nmap_version_intensity: number;
  discovery_low_confidence_threshold: number;
  discovery_full_scan_host_concurrency: number;
  discovery_full_scan_port_concurrency: number;
  discovery_service_probe_host_concurrency: number;
  discovery_nse_mode: "off" | "whitelist" | "all";
  discovery_nse_timeout_seconds: number;
  discovery_nse_host_concurrency: number;
  discovery_nse_enable_vuln_scripts: boolean;
  risk_active_verify_connect_timeout_seconds: number;
  risk_active_verify_read_timeout_seconds: number;
  risk_active_verify_max_concurrency: number;
  llm_provider: LLMProvider;
  llm_model: string;
  llm_base_url: string;
  llm_wire_api: LLMWireAPI;
  llm_timeout_seconds: number;
  llm_api_key?: string | null;
  clear_llm_api_key: boolean;
  cors_allow_all: boolean;
  cors_allow_origins: string;
  local_asset_ips: string;
  security_admin_cidrs: string;
  access_token_expire_minutes: number;
};

export type SettingsApplyResponse = {
  task_id: string;
  status: TaskStatus;
};

export type PlatformAIValidateInput = {
  llm_provider: LLMProvider;
  llm_model: string;
  llm_base_url: string;
  llm_wire_api: LLMWireAPI;
  llm_timeout_seconds: number;
  llm_api_key?: string | null;
  clear_llm_api_key: boolean;
};

export type PlatformAIValidateResult = {
  ok: boolean;
  message: string;
  provider: LLMProvider;
  model: string;
  resolved_base_url: string;
  used_saved_api_key: boolean;
  latency_ms: number;
};

export type PlatformAIModelOption = {
  id: string;
  display_name: string | null;
  owned_by: string | null;
};

export type PlatformAIModelListInput = {
  llm_provider: LLMProvider;
  llm_base_url: string;
  llm_wire_api: LLMWireAPI;
  llm_timeout_seconds: number;
  llm_api_key?: string | null;
  clear_llm_api_key: boolean;
};

export type PlatformAIModelListResult = {
  ok: boolean;
  message: string;
  provider: LLMProvider;
  resolved_base_url: string;
  used_saved_api_key: boolean;
  latency_ms: number;
  models: PlatformAIModelOption[];
};
