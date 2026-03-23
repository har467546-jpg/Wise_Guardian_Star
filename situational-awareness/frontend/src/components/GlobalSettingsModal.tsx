"use client";

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Button, Card, Form, Input, InputNumber, Modal, Select, Space, Spin, Switch, Tabs, Tag, Typography, message } from "antd";

import type { StoredUserRole } from "@/lib/auth";
import { getPlatformSettings, listPlatformAIModels, updatePlatformSettings, validatePlatformAISettings } from "@/services/api";
import type {
  PlatformAIModelListInput,
  PlatformAIModelListResult,
  PlatformAIModelOption,
  LLMProvider,
  LLMWireAPI,
  PlatformAIValidateInput,
  PlatformAIValidateResult,
  PlatformSettings,
  PlatformSettingsInput,
} from "@/types/settings";

const { TextArea, Password } = Input;

type GlobalSettingsModalProps = {
  open: boolean;
  onClose: () => void;
  userRole: StoredUserRole;
};

type SettingsTabKey = "remediation-runner" | "scan-verify" | "ai-planning" | "platform-security";

const FIELD_TO_TAB_KEY: Record<string, SettingsTabKey> = {
  runner_poll_interval_seconds: "remediation-runner",
  runner_offline_grace_seconds: "remediation-runner",
  remediation_auto_reverify_enabled: "remediation-runner",
  remediation_stop_on_failure: "remediation-runner",
  remediation_prepare_backups_enabled: "remediation-runner",
  discovery_liveness_ports: "scan-verify",
  discovery_liveness_mode: "scan-verify",
  discovery_service_ports: "scan-verify",
  discovery_high_backdoor_ports: "scan-verify",
  discovery_portset_mode: "scan-verify",
  discovery_top_ports_limit: "scan-verify",
  discovery_nmap_mode: "scan-verify",
  discovery_nmap_min_rate: "scan-verify",
  discovery_nmap_timeout_seconds: "scan-verify",
  discovery_nmap_liveness_timeout_seconds: "scan-verify",
  discovery_nmap_full_scan_timeout_seconds: "scan-verify",
  discovery_nmap_version_intensity: "scan-verify",
  discovery_low_confidence_threshold: "scan-verify",
  discovery_full_scan_host_concurrency: "scan-verify",
  discovery_full_scan_port_concurrency: "scan-verify",
  discovery_service_probe_host_concurrency: "scan-verify",
  discovery_nse_mode: "scan-verify",
  discovery_nse_timeout_seconds: "scan-verify",
  discovery_nse_host_concurrency: "scan-verify",
  discovery_nse_enable_vuln_scripts: "scan-verify",
  risk_active_verify_connect_timeout_seconds: "scan-verify",
  risk_active_verify_read_timeout_seconds: "scan-verify",
  risk_active_verify_max_concurrency: "scan-verify",
  llm_provider: "ai-planning",
  llm_model: "ai-planning",
  llm_base_url: "ai-planning",
  llm_wire_api: "ai-planning",
  llm_timeout_seconds: "ai-planning",
  llm_api_key: "ai-planning",
  clear_llm_api_key: "ai-planning",
  cors_allow_all: "platform-security",
  cors_allow_origins: "platform-security",
  local_asset_ips: "platform-security",
  access_token_expire_minutes: "platform-security",
};

const AI_FIELD_KEYS = new Set(["llm_provider", "llm_model", "llm_base_url", "llm_wire_api", "llm_timeout_seconds", "llm_api_key", "clear_llm_api_key"]);
const AI_VALIDATE_FIELD_NAMES: Array<keyof PlatformAIValidateInput> = [
  "llm_provider",
  "llm_model",
  "llm_base_url",
  "llm_wire_api",
  "llm_timeout_seconds",
  "llm_api_key",
];
const AI_MODEL_DISCOVERY_FIELD_NAMES: Array<keyof PlatformAIModelListInput> = [
  "llm_provider",
  "llm_base_url",
  "llm_wire_api",
  "llm_timeout_seconds",
  "llm_api_key",
];

const READ_ONLY_DEFAULTS: PlatformSettingsInput = {
  runner_poll_interval_seconds: 10,
  runner_offline_grace_seconds: 45,
  remediation_auto_reverify_enabled: true,
  remediation_stop_on_failure: true,
  remediation_prepare_backups_enabled: true,
  discovery_liveness_ports: "22,80,443,8080,8443",
  discovery_liveness_mode: "nmap_icmp",
  discovery_service_ports: "22,80,443,3306,5432,6379,8080,8443",
  discovery_high_backdoor_ports: "1337,4444,5555,6666,31337",
  discovery_portset_mode: "full",
  discovery_top_ports_limit: 1000,
  discovery_nmap_mode: "enrich",
  discovery_nmap_min_rate: 100000,
  discovery_nmap_timeout_seconds: 8,
  discovery_nmap_liveness_timeout_seconds: 90,
  discovery_nmap_full_scan_timeout_seconds: 90,
  discovery_nmap_version_intensity: 7,
  discovery_low_confidence_threshold: 70,
  discovery_full_scan_host_concurrency: 8,
  discovery_full_scan_port_concurrency: 256,
  discovery_service_probe_host_concurrency: 32,
  discovery_nse_mode: "whitelist",
  discovery_nse_timeout_seconds: 8,
  discovery_nse_host_concurrency: 8,
  discovery_nse_enable_vuln_scripts: true,
  risk_active_verify_connect_timeout_seconds: 3,
  risk_active_verify_read_timeout_seconds: 3,
  risk_active_verify_max_concurrency: 4,
  llm_provider: "mock",
  llm_model: "gpt-4o-mini",
  llm_base_url: "",
  llm_wire_api: "responses",
  llm_timeout_seconds: 60,
  llm_api_key: "",
  clear_llm_api_key: false,
  cors_allow_all: true,
  cors_allow_origins: "http://localhost:3000",
  local_asset_ips: "127.0.0.1,::1",
  access_token_expire_minutes: 480,
};

function toFormValues(payload: PlatformSettings): PlatformSettingsInput {
  return {
    runner_poll_interval_seconds: payload.runner_poll_interval_seconds,
    runner_offline_grace_seconds: payload.runner_offline_grace_seconds,
    remediation_auto_reverify_enabled: payload.remediation_auto_reverify_enabled,
    remediation_stop_on_failure: payload.remediation_stop_on_failure,
    remediation_prepare_backups_enabled: payload.remediation_prepare_backups_enabled,
    discovery_liveness_ports: payload.discovery_liveness_ports,
    discovery_liveness_mode: payload.discovery_liveness_mode,
    discovery_service_ports: payload.discovery_service_ports,
    discovery_high_backdoor_ports: payload.discovery_high_backdoor_ports,
    discovery_portset_mode: payload.discovery_portset_mode,
    discovery_top_ports_limit: payload.discovery_top_ports_limit,
    discovery_nmap_mode: payload.discovery_nmap_mode,
    discovery_nmap_min_rate: payload.discovery_nmap_min_rate,
    discovery_nmap_timeout_seconds: payload.discovery_nmap_timeout_seconds,
    discovery_nmap_liveness_timeout_seconds: payload.discovery_nmap_liveness_timeout_seconds,
    discovery_nmap_full_scan_timeout_seconds: payload.discovery_nmap_full_scan_timeout_seconds,
    discovery_nmap_version_intensity: payload.discovery_nmap_version_intensity,
    discovery_low_confidence_threshold: payload.discovery_low_confidence_threshold,
    discovery_full_scan_host_concurrency: payload.discovery_full_scan_host_concurrency,
    discovery_full_scan_port_concurrency: payload.discovery_full_scan_port_concurrency,
    discovery_service_probe_host_concurrency: payload.discovery_service_probe_host_concurrency,
    discovery_nse_mode: payload.discovery_nse_mode,
    discovery_nse_timeout_seconds: payload.discovery_nse_timeout_seconds,
    discovery_nse_host_concurrency: payload.discovery_nse_host_concurrency,
    discovery_nse_enable_vuln_scripts: payload.discovery_nse_enable_vuln_scripts,
    risk_active_verify_connect_timeout_seconds: payload.risk_active_verify_connect_timeout_seconds,
    risk_active_verify_read_timeout_seconds: payload.risk_active_verify_read_timeout_seconds,
    risk_active_verify_max_concurrency: payload.risk_active_verify_max_concurrency,
    llm_provider: payload.llm_provider,
    llm_model: payload.llm_model,
    llm_base_url: payload.llm_base_url,
    llm_wire_api: payload.llm_wire_api,
    llm_timeout_seconds: payload.llm_timeout_seconds,
    llm_api_key: "",
    clear_llm_api_key: false,
    cors_allow_all: payload.cors_allow_all,
    cors_allow_origins: payload.cors_allow_origins,
    local_asset_ips: payload.local_asset_ips,
    access_token_expire_minutes: payload.access_token_expire_minutes,
  };
}

function SectionCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="panel-card global-settings-form-card" size="small" title={title}>
      {children}
    </Card>
  );
}

function getLLMProviderMeta(provider: LLMProvider) {
  if (provider === "openai") {
    return {
      title: "OpenAI 官方接口",
      description: "适用于直接连接 OpenAI 官方服务，可选覆盖官方 Base URL。",
      baseUrlLabel: "Base URL",
      baseUrlExtra: "留空时默认使用 https://api.openai.com/v1；如接入网关可填写自定义地址。",
      baseUrlPlaceholder: "https://api.openai.com/v1",
      apiKeyLabel: "OpenAI API Key",
      apiKeyExtra: "填写新值时更新，留空则保持当前配置。",
    };
  }
  if (provider === "openai_compatible") {
    return {
      title: "OpenAI 兼容 / 自定义中转",
      description: "适用于 One API、New API、vLLM、LM Studio、企业自建中转等 OpenAI 兼容接口。",
      baseUrlLabel: "兼容接口 Base URL",
      baseUrlExtra: "必须填写完整的兼容接口根地址，例如 https://relay.example.com/v1。",
      baseUrlPlaceholder: "https://relay.example.com/v1",
      apiKeyLabel: "中转 API Key",
      apiKeyExtra: "多数中转或兼容网关会要求 API Key；本地兼容服务可留空。",
    };
  }
  if (provider === "ollama_remote") {
    return {
      title: "远程 Ollama",
      description: "适用于接入远程 Ollama 服务或带鉴权的 Ollama 反向代理。",
      baseUrlLabel: "Ollama 地址",
      baseUrlExtra: "必须填写远程 Ollama 的访问地址，例如 http://192.168.1.10:11434。",
      baseUrlPlaceholder: "http://ollama.example.com:11434",
      apiKeyLabel: "访问令牌（可选）",
      apiKeyExtra: "标准 Ollama 默认不需要 API Key；如果前面挂了网关或反向代理，可在此填写令牌。",
    };
  }
  return {
    title: "Mock 回退模式",
    description: "不连接外部模型，系统会直接返回模板化摘要，适合作为离线兜底。",
    baseUrlLabel: "Base URL",
    baseUrlExtra: "Mock 模式不会使用该地址，但会保留已填写的配置，便于后续切换。",
    baseUrlPlaceholder: "https://api.openai.com/v1",
    apiKeyLabel: "API Key",
    apiKeyExtra: "Mock 模式不会使用该密钥，但可以提前保存以便后续切换。",
  };
}

function getLLMWireApiOptions(provider: LLMProvider): Array<{ label: string; value: LLMWireAPI }> {
  const autoLabel = provider === "ollama_remote" ? "自动协商（Ollama 固定走远程生成）" : "自动协商（优先 Responses）";
  return [
    { label: "Responses API（推荐）", value: "responses" },
    { label: autoLabel, value: "auto" },
    { label: "Chat Completions", value: "chat_completions" },
  ];
}

function toModelSelectOptions(models: PlatformAIModelOption[]): Array<{ label: string; value: string }> {
  return models.map((item) => ({
    label: item.display_name ? `${item.display_name} (${item.id})` : item.id,
    value: item.id,
  }));
}

function extractFieldKey(name: unknown): string | null {
  if (typeof name === "string" || typeof name === "number") {
    return String(name);
  }
  if (Array.isArray(name) && name.length > 0) {
    const first = name[0];
    if (typeof first === "string" || typeof first === "number") {
      return String(first);
    }
  }
  return null;
}

function NumberField(props: {
  name: keyof PlatformSettingsInput;
  label: string;
  min: number;
  max?: number;
  disabled: boolean;
  extra?: string;
}) {
  return (
    <Form.Item name={props.name} label={props.label} extra={props.extra}>
      <InputNumber min={props.min} max={props.max} style={{ width: "100%" }} disabled={props.disabled} />
    </Form.Item>
  );
}

function TextField(props: {
  name: keyof PlatformSettingsInput;
  label: string;
  disabled: boolean;
  extra?: string;
  textarea?: boolean;
}) {
  return (
    <Form.Item name={props.name} label={props.label} extra={props.extra}>
      {props.textarea ? <TextArea rows={3} disabled={props.disabled} /> : <Input disabled={props.disabled} />}
    </Form.Item>
  );
}

function SelectField<T extends string>(props: {
  name: keyof PlatformSettingsInput;
  label: string;
  disabled: boolean;
  options: Array<{ label: string; value: T }>;
}) {
  return (
    <Form.Item name={props.name} label={props.label}>
      <Select disabled={props.disabled} options={props.options} />
    </Form.Item>
  );
}

function SwitchField(props: {
  name: keyof PlatformSettingsInput;
  label: string;
  disabled: boolean;
}) {
  return (
    <Form.Item name={props.name} label={props.label} valuePropName="checked">
      <Switch disabled={props.disabled} />
    </Form.Item>
  );
}

export default function GlobalSettingsModal({ open, onClose, userRole }: GlobalSettingsModalProps) {
  const isAdmin = userRole === "admin";
  const [form] = Form.useForm<PlatformSettingsInput>();
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [validatingAI, setValidatingAI] = useState(false);
  const [loadingModels, setLoadingModels] = useState(false);
  const [activeTab, setActiveTab] = useState<SettingsTabKey>("remediation-runner");
  const [aiValidationResult, setAiValidationResult] = useState<PlatformAIValidateResult | null>(null);
  const [aiModelListResult, setAiModelListResult] = useState<PlatformAIModelListResult | null>(null);
  const [aiDiscoveredModels, setAiDiscoveredModels] = useState<PlatformAIModelOption[]>([]);
  const [settingsState, setSettingsState] = useState<PlatformSettings | null>(null);
  const disabled = !isAdmin || loading || saving || validatingAI || loadingModels;
  const llmProvider = Form.useWatch("llm_provider", form) ?? READ_ONLY_DEFAULTS.llm_provider;
  const llmProviderMeta = getLLMProviderMeta(llmProvider);
  const llmWireApi = Form.useWatch("llm_wire_api", form) ?? READ_ONLY_DEFAULTS.llm_wire_api;
  const modelSelectOptions = toModelSelectOptions(aiDiscoveredModels);
  const requiresDiscoveredModel = llmProvider !== "mock";
  const requireBaseUrl = llmProvider === "openai_compatible" || llmProvider === "ollama_remote";

  useEffect(() => {
    if (!open) {
      return;
    }
    setActiveTab("remediation-runner");
    setAiValidationResult(null);
    setAiModelListResult(null);
    if (!isAdmin) {
      setSettingsState(null);
      setAiDiscoveredModels([]);
      form.setFieldsValue(READ_ONLY_DEFAULTS);
      return;
    }
    let canceled = false;
    setLoading(true);
    getPlatformSettings()
      .then((payload) => {
        if (canceled) {
          return;
        }
        setSettingsState(payload);
        form.setFieldsValue(toFormValues(payload));
        setAiDiscoveredModels([]);
      })
      .catch((error) => {
        if (canceled) {
          return;
        }
        message.error(error instanceof Error ? error.message : "设置加载失败");
      })
      .finally(() => {
        if (!canceled) {
          setLoading(false);
        }
      });
    return () => {
      canceled = true;
    };
  }, [form, isAdmin, open]);

  const apiKeyState = settingsState?.llm_api_key;

  const revealValidationError = (error: unknown, fallbackTab: SettingsTabKey = activeTab) => {
    const errorFields =
      error && typeof error === "object" && "errorFields" in error && Array.isArray((error as { errorFields?: unknown[] }).errorFields)
        ? ((error as { errorFields: Array<{ name?: unknown; errors?: string[] }> }).errorFields)
        : [];
    const firstField = errorFields[0];
    const fieldKey = extractFieldKey(firstField?.name);
    const targetTab = (fieldKey && FIELD_TO_TAB_KEY[fieldKey]) || fallbackTab;
    const firstError = firstField?.errors?.find((item) => Boolean(item && item.trim()));
    setActiveTab(targetTab);
    message.error(firstError || "请先修正未通过校验的设置项");
    if (firstField?.name) {
      window.setTimeout(() => {
        form.scrollToField(firstField.name as Parameters<typeof form.scrollToField>[0], { block: "center" });
      }, 0);
    }
  };

  const handleSave = async () => {
    try {
      const validatedValues = await form.validateFields();
      const baseValues = settingsState ? toFormValues(settingsState) : READ_ONLY_DEFAULTS;
      const values: PlatformSettingsInput = {
        ...baseValues,
        ...form.getFieldsValue(true),
        ...validatedValues,
      };
      setSaving(true);
      const payload: PlatformSettingsInput = {
        ...values,
        llm_api_key: values.llm_api_key || undefined,
        clear_llm_api_key: Boolean(values.clear_llm_api_key),
      };
      const result = await updatePlatformSettings(payload);
      message.success(`设置应用任务已提交：${result.task_id}`);
      onClose();
    } catch (error) {
      if (error && typeof error === "object" && "errorFields" in error) {
        revealValidationError(error);
        return;
      }
      message.error(error instanceof Error ? error.message : "设置保存失败");
    } finally {
      setSaving(false);
    }
  };

  const handleValidateAI = async () => {
    try {
      setActiveTab("ai-planning");
      const values = await form.validateFields(AI_VALIDATE_FIELD_NAMES);
      setValidatingAI(true);
      const payload: PlatformAIValidateInput = {
        llm_provider: values.llm_provider,
        llm_model: values.llm_model,
        llm_base_url: values.llm_base_url,
        llm_wire_api: values.llm_wire_api,
        llm_timeout_seconds: values.llm_timeout_seconds,
        llm_api_key: values.llm_api_key || undefined,
        clear_llm_api_key: Boolean(form.getFieldValue("clear_llm_api_key")),
      };
      const result = await validatePlatformAISettings(payload);
      setAiValidationResult(result);
      if (result.ok) {
        message.success(result.message);
      } else {
        message.error(result.message);
      }
    } catch (error) {
      if (error && typeof error === "object" && "errorFields" in error) {
        revealValidationError(error, "ai-planning");
        return;
      }
      setAiValidationResult(null);
      message.error(error instanceof Error ? error.message : "AI 连接验证失败");
    } finally {
      setValidatingAI(false);
    }
  };

  const handleLoadModels = async () => {
    try {
      setActiveTab("ai-planning");
      const values = await form.validateFields(AI_MODEL_DISCOVERY_FIELD_NAMES);
      setLoadingModels(true);
      const payload: PlatformAIModelListInput = {
        llm_provider: values.llm_provider,
        llm_base_url: values.llm_base_url,
        llm_wire_api: values.llm_wire_api,
        llm_timeout_seconds: values.llm_timeout_seconds,
        llm_api_key: values.llm_api_key || undefined,
        clear_llm_api_key: Boolean(form.getFieldValue("clear_llm_api_key")),
      };
      const result = await listPlatformAIModels(payload);
      setAiModelListResult(result);
      setAiDiscoveredModels(result.models);
      if (result.ok) {
        const currentModelValue = String(form.getFieldValue("llm_model") || "").trim();
        const currentModelStillValid = result.models.some((item) => item.id === currentModelValue);
        if (result.models.length === 0) {
          form.setFieldValue("llm_model", undefined);
        } else if (!currentModelStillValid) {
          form.setFieldValue("llm_model", result.models[0].id);
        }
        message.success(result.message);
      } else {
        message.error(result.message);
      }
    } catch (error) {
      if (error && typeof error === "object" && "errorFields" in error) {
        revealValidationError(error, "ai-planning");
        return;
      }
      setAiModelListResult(null);
      setAiDiscoveredModels([]);
      message.error(error instanceof Error ? error.message : "获取模型列表失败");
    } finally {
      setLoadingModels(false);
    }
  };

  return (
    <Modal
      title={(
        <div className="global-settings-modal-title-wrap">
          <span className="global-settings-modal-kicker">平台设置</span>
          <div className="global-settings-modal-title-row">
            <Typography.Title level={4} className="global-settings-modal-title">
              系统设置中心
            </Typography.Title>
            <Tag color={isAdmin ? "blue" : "default"}>{isAdmin ? "可编辑" : "只读"}</Tag>
          </div>
        </div>
      )}
      open={open}
      onCancel={saving || validatingAI ? undefined : onClose}
      centered
      width={1040}
      className="global-settings-modal"
      destroyOnHidden={false}
      footer={[
        <Button key="cancel" onClick={onClose} disabled={saving || validatingAI || loadingModels}>
          取消
        </Button>,
        <Button key="save" type="primary" onClick={handleSave} loading={saving} disabled={!isAdmin || loading || validatingAI || loadingModels}>
          保存并应用
        </Button>,
      ]}
    >
      <Spin spinning={loading}>
        <Form
          form={form}
          layout="vertical"
          initialValues={READ_ONLY_DEFAULTS}
          className="global-settings-form"
          onValuesChange={(changedValues) => {
            if ("llm_api_key" in changedValues && changedValues.llm_api_key) {
              form.setFieldValue("clear_llm_api_key", false);
            }
            const changedKeys = Object.keys(changedValues || {});
            if (changedKeys.some((key) => AI_FIELD_KEYS.has(key))) {
              setAiValidationResult(null);
              setAiModelListResult(null);
              if (changedKeys.some((key) => ["llm_provider", "llm_base_url", "llm_wire_api", "llm_api_key", "clear_llm_api_key"].includes(key))) {
                setAiDiscoveredModels([]);
                if ((form.getFieldValue("llm_provider") as LLMProvider | undefined) !== "mock") {
                  form.setFieldValue("llm_model", undefined);
                }
              }
            }
          }}
        >
          <Form.Item name="clear_llm_api_key" hidden>
            <Input type="hidden" />
          </Form.Item>
          <Tabs
            activeKey={activeTab}
            className="global-settings-tabs"
            onChange={(key) => setActiveTab(key as SettingsTabKey)}
            items={[
              {
                key: "remediation-runner",
                label: "修复与 Runner",
                forceRender: true,
                children: (
                  <div className="global-settings-form-grid">
                    <SectionCard title="Runner 心跳">
                      <NumberField name="runner_poll_interval_seconds" label="Runner 拉取间隔" min={1} max={3600} disabled={disabled} extra="单位：秒" />
                      <NumberField name="runner_offline_grace_seconds" label="Runner 离线宽限" min={5} max={86400} disabled={disabled} extra="单位：秒" />
                    </SectionCard>
                    <SectionCard title="修复执行">
                      <SwitchField name="remediation_auto_reverify_enabled" label="修复后自动复测" disabled={disabled} />
                      <SwitchField name="remediation_stop_on_failure" label="步骤失败后停止" disabled={disabled} />
                      <SwitchField name="remediation_prepare_backups_enabled" label="执行前自动备份" disabled={disabled} />
                    </SectionCard>
                  </div>
                ),
              },
              {
                key: "scan-verify",
                label: "扫描与验证",
                forceRender: true,
                children: (
                  <div className="global-settings-form-grid">
                    <SectionCard title="发现链路">
                      <TextField name="discovery_liveness_ports" label="存活探测端口" disabled={disabled} extra="使用逗号分隔端口" />
                      <SelectField
                        name="discovery_liveness_mode"
                        label="存活探测模式"
                        disabled={disabled}
                        options={[
                          { label: "Nmap ICMP", value: "nmap_icmp" },
                          { label: "TCP Connect", value: "tcp_connect" },
                        ]}
                      />
                      <TextField name="discovery_service_ports" label="服务识别端口" disabled={disabled} textarea extra="使用逗号分隔端口" />
                      <TextField name="discovery_high_backdoor_ports" label="高危后门端口" disabled={disabled} textarea extra="允许为空" />
                      <SelectField
                        name="discovery_portset_mode"
                        label="端口集模式"
                        disabled={disabled}
                        options={[
                          { label: "全量端口", value: "full" },
                          { label: "Top + 自定义", value: "top1000_plus_custom" },
                          { label: "仅自定义", value: "curated" },
                        ]}
                      />
                      <NumberField name="discovery_top_ports_limit" label="Top 端口数量" min={1} max={65535} disabled={disabled} />
                    </SectionCard>
                    <SectionCard title="Nmap 与并发">
                      <SelectField
                        name="discovery_nmap_mode"
                        label="Nmap 版本探测模式"
                        disabled={disabled}
                        options={[
                          { label: "关闭", value: "off" },
                          { label: "启用", value: "enrich" },
                        ]}
                      />
                      <NumberField name="discovery_nmap_min_rate" label="Nmap 最小速率" min={1} max={1000000} disabled={disabled} />
                      <NumberField name="discovery_nmap_timeout_seconds" label="Nmap 单次超时" min={1} max={7200} disabled={disabled} extra="单位：秒" />
                      <NumberField name="discovery_nmap_liveness_timeout_seconds" label="存活探测超时" min={1} max={7200} disabled={disabled} extra="单位：秒" />
                      <NumberField name="discovery_nmap_full_scan_timeout_seconds" label="全扫描超时" min={1} max={7200} disabled={disabled} extra="单位：秒" />
                      <NumberField name="discovery_nmap_version_intensity" label="版本探测强度" min={0} max={9} disabled={disabled} />
                      <NumberField name="discovery_low_confidence_threshold" label="低置信度阈值" min={1} max={100} disabled={disabled} />
                      <NumberField name="discovery_full_scan_host_concurrency" label="全扫描主机并发" min={1} max={4096} disabled={disabled} />
                      <NumberField name="discovery_full_scan_port_concurrency" label="全扫描端口并发" min={1} max={65535} disabled={disabled} />
                      <NumberField name="discovery_service_probe_host_concurrency" label="服务探测主机并发" min={1} max={4096} disabled={disabled} />
                    </SectionCard>
                    <SectionCard title="NSE 与风险验证">
                      <SelectField
                        name="discovery_nse_mode"
                        label="NSE 模式"
                        disabled={disabled}
                        options={[
                          { label: "关闭", value: "off" },
                          { label: "白名单", value: "whitelist" },
                          { label: "全部", value: "all" },
                        ]}
                      />
                      <NumberField name="discovery_nse_timeout_seconds" label="NSE 超时" min={1} max={7200} disabled={disabled} extra="单位：秒" />
                      <NumberField name="discovery_nse_host_concurrency" label="NSE 主机并发" min={1} max={4096} disabled={disabled} />
                      <SwitchField name="discovery_nse_enable_vuln_scripts" label="启用漏洞脚本" disabled={disabled} />
                      <NumberField name="risk_active_verify_connect_timeout_seconds" label="验证连接超时" min={1} max={300} disabled={disabled} extra="单位：秒" />
                      <NumberField name="risk_active_verify_read_timeout_seconds" label="验证读取超时" min={1} max={300} disabled={disabled} extra="单位：秒" />
                      <NumberField name="risk_active_verify_max_concurrency" label="验证最大并发" min={1} max={1024} disabled={disabled} />
                    </SectionCard>
                  </div>
                ),
              },
              {
                key: "ai-planning",
                label: "AI 与会话规划",
                forceRender: true,
                children: (
                  <div className="global-settings-form-grid">
                    <SectionCard title="模型接入">
                      <Space direction="vertical" size={8} style={{ width: "100%", marginBottom: 12 }}>
                        <Typography.Text strong>{llmProviderMeta.title}</Typography.Text>
                        <Typography.Text type="secondary">{llmProviderMeta.description}</Typography.Text>
                      </Space>
                      <SelectField
                        name="llm_provider"
                        label="Provider"
                        disabled={disabled}
                        options={[
                          { label: "Mock", value: "mock" },
                          { label: "OpenAI", value: "openai" },
                          { label: "OpenAI 兼容 / 自定义中转", value: "openai_compatible" },
                          { label: "远程 Ollama", value: "ollama_remote" },
                        ]}
                      />
                      <Form.Item
                        name="llm_base_url"
                        label={llmProviderMeta.baseUrlLabel}
                        extra={llmProviderMeta.baseUrlExtra}
                        rules={[
                          {
                            validator: async (_, value) => {
                              if (requireBaseUrl && !String(value || "").trim()) {
                                throw new Error("当前接入方式必须填写 Base URL");
                              }
                            },
                          },
                        ]}
                      >
                        <Input disabled={disabled} placeholder={llmProviderMeta.baseUrlPlaceholder} />
                      </Form.Item>
                      <SelectField
                        name="llm_wire_api"
                        label="Wire API"
                        disabled={disabled || llmProvider === "mock" || llmProvider === "ollama_remote"}
                        options={getLLMWireApiOptions(llmProvider)}
                      />
                      {llmProvider === "openai_compatible" ? (
                        <Typography.Text type="secondary" style={{ display: "block", marginTop: -4, marginBottom: 12 }}>
                          兼容中转默认优先走 `Responses API`；如果上游只兼容旧协议，再切回 `Chat Completions`。
                        </Typography.Text>
                      ) : null}
                      <Form.Item
                        name="llm_model"
                        label="模型名称"
                        extra="请先获取上游 /models 列表，再从返回结果中选择模型。"
                        rules={[
                          {
                            validator: async (_, value) => {
                              const normalized = String(value || "").trim();
                              if (!normalized) {
                                throw new Error(requiresDiscoveredModel ? "请先获取模型列表并选择模型" : "模型名称不能为空");
                              }
                              if (!requiresDiscoveredModel) {
                                return;
                              }
                              if (aiDiscoveredModels.length === 0) {
                                throw new Error("请先点击“获取模型列表”再选择模型");
                              }
                              if (!aiDiscoveredModels.some((item) => item.id === normalized)) {
                                throw new Error("模型名称必须从已获取的模型列表中选择");
                              }
                            },
                          },
                        ]}
                      >
                        <Select
                          showSearch
                          optionFilterProp="label"
                          disabled={disabled}
                          loading={loadingModels}
                          options={modelSelectOptions}
                          placeholder={loadingModels ? "正在获取模型列表" : "先获取模型列表后选择"}
                          notFoundContent={requiresDiscoveredModel ? "请先获取模型列表" : "暂无可选模型"}
                        />
                      </Form.Item>
                      {requiresDiscoveredModel && settingsState?.llm_model && aiDiscoveredModels.length === 0 ? (
                        <Typography.Text type="secondary" style={{ display: "block", marginTop: -4, marginBottom: 12 }}>
                          当前已保存模型：{settingsState.llm_model}。如需保存或验证，请先重新获取模型列表并选择。
                        </Typography.Text>
                      ) : null}
                      {isAdmin ? (
                        <Space size={12} wrap style={{ marginBottom: 12 }}>
                          <Button type="default" onClick={handleLoadModels} loading={loadingModels} disabled={loading || saving || validatingAI}>
                            获取模型列表
                          </Button>
                          {aiModelListResult ? (
                            <Typography.Text type={aiModelListResult.ok ? "secondary" : "danger"}>
                              {aiModelListResult.message}
                            </Typography.Text>
                          ) : null}
                        </Space>
                      ) : null}
                      <NumberField
                        name="llm_timeout_seconds"
                        label="请求超时"
                        min={1}
                        max={600}
                        disabled={disabled}
                        extra="单位：秒"
                      />
                      {isAdmin ? (
                        <Button type="default" onClick={handleValidateAI} loading={validatingAI} disabled={loading || saving}>
                          验证连接
                        </Button>
                      ) : null}
                    </SectionCard>
                    <SectionCard title="API Key">
                      <Space direction="vertical" size={12} style={{ width: "100%" }}>
                        <div className="global-settings-secret-row">
                          <span>当前状态</span>
                          <Tag color={apiKeyState?.configured ? "blue" : "default"}>
                            {apiKeyState?.configured ? "已配置" : "未配置"}
                          </Tag>
                          {isAdmin && apiKeyState?.masked_value ? (
                            <Typography.Text type="secondary">{apiKeyState.masked_value}</Typography.Text>
                          ) : null}
                        </div>
                        <Form.Item
                          name="llm_api_key"
                          label={llmProviderMeta.apiKeyLabel}
                          extra={`${llmProviderMeta.apiKeyExtra} 保存后会直接写入运行时配置。`}
                        >
                          <Password
                            disabled={disabled}
                            placeholder={isAdmin ? "输入新的访问密钥" : ""}
                          />
                        </Form.Item>
                        <Button
                          disabled={disabled || !apiKeyState?.configured}
                          onClick={() => {
                            form.setFieldValue("llm_api_key", "");
                            form.setFieldValue("clear_llm_api_key", true);
                            setAiValidationResult(null);
                          }}
                        >
                          清空密钥
                        </Button>
                      </Space>
                    </SectionCard>
                    {aiValidationResult ? (
                      <Card className="panel-card global-settings-form-card" size="small" title="验证结果" style={{ gridColumn: "1 / -1" }}>
                        <Space direction="vertical" size={10} style={{ width: "100%" }}>
                          <Space size={8} wrap>
                            <Tag color={aiValidationResult.ok ? "success" : "error"}>{aiValidationResult.ok ? "连接成功" : "连接失败"}</Tag>
                            <Tag>{aiValidationResult.provider}</Tag>
                            <Tag>{aiValidationResult.model}</Tag>
                          </Space>
                          <Typography.Text>{aiValidationResult.message}</Typography.Text>
                          <Typography.Text type="secondary">
                            Base URL：{aiValidationResult.resolved_base_url || "无需外部地址"}
                          </Typography.Text>
                          <Typography.Text type="secondary">Wire API：{llmWireApi}</Typography.Text>
                          <Typography.Text type="secondary">
                            API Key 来源：{aiValidationResult.used_saved_api_key ? "使用已保存 Key" : "使用当前表单输入"}
                          </Typography.Text>
                          <Typography.Text type="secondary">验证耗时：{aiValidationResult.latency_ms} ms</Typography.Text>
                        </Space>
                      </Card>
                    ) : null}
                    {aiModelListResult ? (
                      <Card className="panel-card global-settings-form-card" size="small" title="模型列表" style={{ gridColumn: "1 / -1" }}>
                        <Space direction="vertical" size={10} style={{ width: "100%" }}>
                          <Typography.Text>{aiModelListResult.message}</Typography.Text>
                          <Typography.Text type="secondary">
                            Base URL：{aiModelListResult.resolved_base_url || "无需外部地址"}
                          </Typography.Text>
                          <Typography.Text type="secondary">
                            API Key 来源：{aiModelListResult.used_saved_api_key ? "使用已保存 Key" : "使用当前表单输入"}
                          </Typography.Text>
                          <Typography.Text type="secondary">获取耗时：{aiModelListResult.latency_ms} ms</Typography.Text>
                          {aiModelListResult.ok ? (
                            <Typography.Text type="secondary">
                              共发现 {aiModelListResult.models.length} 个模型
                            </Typography.Text>
                          ) : null}
                        </Space>
                      </Card>
                    ) : null}
                  </div>
                ),
              },
              {
                key: "platform-security",
                label: "平台与安全",
                forceRender: true,
                children: (
                  <div className="global-settings-form-grid">
                    <SectionCard title="跨域与本机识别">
                      <SwitchField name="cors_allow_all" label="允许全部跨域来源" disabled={disabled} />
                      <TextField
                        name="cors_allow_origins"
                        label="允许的跨域来源"
                        disabled={disabled}
                        textarea
                        extra="使用逗号分隔 Origin，支持通配符，例如 http://192.168.*.*:3000"
                      />
                      <TextField name="local_asset_ips" label="本机 IP / 网段" disabled={disabled} textarea extra="使用逗号分隔 IP 或网段" />
                    </SectionCard>
                    <SectionCard title="认证时效">
                      <NumberField name="access_token_expire_minutes" label="访问令牌有效期" min={5} max={10080} disabled={disabled} extra="单位：分钟" />
                    </SectionCard>
                  </div>
                ),
              },
            ]}
          />
        </Form>
      </Spin>
    </Modal>
  );
}
