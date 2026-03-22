"use client";

import { useDeferredValue, useEffect, useMemo, useState, useTransition } from "react";
import type { FormInstance, UploadFile } from "antd";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Empty,
  Form,
  Grid,
  Input,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
  Upload,
  message,
} from "antd";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";
import { getStoredUserRole } from "@/lib/auth";
import {
  batchUpdateVulnRuleStatus,
  createVulnRule,
  deleteVulnRule,
  exportVulnRules,
  getVulnLibraryStatus,
  getVulnRule,
  importVulnRules,
  listVulnRules,
  rebuildVulnLibraryIndex,
  updateVulnRule,
} from "@/services/api";
import {
  VulnLibraryStatus,
  VulnRule,
  VulnRuleActiveCheckDetector,
  VulnRuleActiveCheckTrigger,
  VulnRuleCatalogView,
  VulnRuleExportFormat,
  VulnRuleFileFormat,
  VulnRuleImportMode,
  VulnRuleImportResponse,
  VulnRuleInput,
  VulnRuleRemediation,
} from "@/types/vuln-library";

type Severity = "low" | "medium" | "high" | "critical";

type RuleFormValues = {
  id?: string;
  name: string;
  enabled: boolean;
  service: string;
  severity: Severity;
  description: string;
  version?: string;
  config_text?: string;
  nse_text?: string;
  package_text?: string;
  remediation_text?: string;
  cve_ids_text?: string;
  cwe_ids_text?: string;
  affected_versions_text?: string;
  exploit_module?: string;
  preconditions_text?: string;
  verify_playbook_text?: string;
  mitigations_text?: string;
  references_text?: string;
  tags_text?: string;
  active_check_enabled?: boolean;
  active_check_detector?: VulnRuleActiveCheckDetector;
  active_check_trigger?: VulnRuleActiveCheckTrigger;
  active_check_timeout_seconds?: number;
  active_check_params_text?: string;
};

const activeCheckDetectorOptions: Array<{ label: string; value: VulnRuleActiveCheckDetector }> = [
  { label: "vsftpd 笑脸后门验证", value: "vsftpd_smiley_backdoor" },
  { label: "FTP 匿名登录验证", value: "ftp_anonymous_login" },
  { label: "Tomcat 管理后台默认凭据验证", value: "tomcat_manager_default_creds" },
  { label: "distccd 无害命令验证", value: "distccd_rce_probe" },
  { label: "UnrealIRCd 后门验证", value: "unrealircd_backdoor_probe" },
  { label: "Redis 未授权 INFO 验证", value: "redis_unauth_info_probe" },
  { label: "HTTP 风险方法验证", value: "http_risky_methods_probe" },
];

const activeCheckTriggerOptions: Array<{ label: string; value: VulnRuleActiveCheckTrigger }> = [
  { label: "被动命中后触发", value: "on_passive_match" },
  { label: "服务存在即触发", value: "on_service_present" },
];

const activeCheckDetectorLabelMap: Record<VulnRuleActiveCheckDetector, string> = {
  vsftpd_smiley_backdoor: "vsftpd 笑脸后门验证",
  ftp_anonymous_login: "FTP 匿名登录验证",
  tomcat_manager_default_creds: "Tomcat 管理后台默认凭据验证",
  distccd_rce_probe: "distccd 无害命令验证",
  unrealircd_backdoor_probe: "UnrealIRCd 后门验证",
  redis_unauth_info_probe: "Redis 未授权 INFO 验证",
  http_risky_methods_probe: "HTTP 风险方法验证",
};

const activeCheckTriggerLabelMap: Record<VulnRuleActiveCheckTrigger, string> = {
  on_passive_match: "被动命中后触发",
  on_service_present: "服务存在即触发",
};

const governanceTagLabelMap: Record<string, string> = {
  "high-value": "高价值",
  "legacy-exposure": "普通老版本",
};

const remediationLevelLabelMap: Record<NonNullable<VulnRuleRemediation["automation_level"]>, string> = {
  callable: "自动处理",
};

function getRuleCatalogType(rule: VulnRule): "high-value" | "legacy-exposure" | "standard" {
  if (rule.tags.includes("legacy-exposure")) {
    return "legacy-exposure";
  }
  if (rule.tags.includes("high-value")) {
    return "high-value";
  }
  return "standard";
}

function getRuleCatalogTypeLabel(rule: VulnRule): string {
  const type = getRuleCatalogType(rule);
  if (type === "high-value") {
    return "高价值";
  }
  if (type === "legacy-exposure") {
    return "普通老版本";
  }
  return "标准";
}

function renderGovernanceTag(tag: string) {
  const label = governanceTagLabelMap[tag] || tag;
  const className =
    tag === "high-value"
      ? "console-inline-chip console-inline-chip-info"
      : tag === "legacy-exposure"
        ? "console-inline-chip console-inline-chip-warning"
        : "console-inline-chip";
  return (
    <span key={tag} className={className}>
      {label}
    </span>
  );
}

function splitLines(value?: string): string[] {
  return (value || "")
    .split("\n")
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatLines(values?: string[]): string {
  return (values || []).join("\n");
}

function parseJsonObjectMapping(
  value: string | undefined,
  label: string,
): Record<string, Record<string, unknown>> | null {
  const raw = (value || "").trim();
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
      throw new Error(label);
    }
    return parsed as Record<string, Record<string, unknown>>;
  } catch {
    throw new Error(`${label}必须是合法 JSON 对象`);
  }
}

function parseJsonObject(value: string | undefined, label: string): Record<string, unknown> | null {
  const raw = (value || "").trim();
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
      throw new Error(label);
    }
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`${label}必须是合法 JSON 对象`);
  }
}

function getRuleNseScripts(match?: VulnRule["match"] | null): string[] {
  const nse = match?.nse;
  if (!nse || typeof nse !== "object" || Array.isArray(nse)) {
    return [];
  }
  return Array.from(
    new Set(
      Object.keys(nse)
        .map((item) => item.split(".", 1)[0]?.trim())
        .filter(Boolean),
    ),
  ).sort((a, b) => a.localeCompare(b));
}

function renderCompactScriptMatches(scripts: string[]) {
  if (!scripts.length) {
    return <Typography.Text type="secondary">无</Typography.Text>;
  }

  const visibleScripts = scripts.slice(0, 2);
  const hiddenCount = scripts.length - visibleScripts.length;
  return (
    <Tooltip title={scripts.join("、")}>
      <div className="ui-chip-row">
        {visibleScripts.map((item) => (
          <span key={item} className="console-inline-chip mono-text">
            {item}
          </span>
        ))}
        {hiddenCount > 0 ? <Tag>+{hiddenCount}</Tag> : null}
      </div>
    </Tooltip>
  );
}

function buildPayload(values: RuleFormValues): VulnRuleInput & { id?: string } {
  const config = parseJsonObjectMapping(values.config_text, "配置匹配");
  const nse = parseJsonObjectMapping(values.nse_text, "Nmap 脚本匹配");
  const packageMatch = parseJsonObject(values.package_text, "软件包匹配") as VulnRule["match"]["package"];
  const remediation = parseJsonObject(values.remediation_text, "修复模板") as VulnRule["remediation"];
  if (remediation) {
    if (remediation.automation_level !== "callable") {
      throw new Error("修复模板的 automation_level 只能为 callable");
    }
    const invalidAction = (remediation.actions as Array<{ action_type: string }>).find(
      (action) => action.action_type === "manual_step" || action.action_type === "rotate_credential",
    );
    if (invalidAction) {
      throw new Error(`修复模板动作 ${invalidAction.action_type} 已不再支持，请改为自动处理动作`);
    }
  }

  const version = (values.version || "").trim() || null;
  if (!version && !config && !nse && !packageMatch) {
    throw new Error("请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配");
  }

  let activeCheck = null;
  if (values.active_check_enabled) {
    if (!values.active_check_detector || !values.active_check_trigger) {
      throw new Error("启用主动探测时必须选择探测器和触发方式");
    }
    let params: Record<string, unknown> = {};
    const paramsText = (values.active_check_params_text || "").trim();
    if (paramsText) {
      try {
        const parsed = JSON.parse(paramsText) as Record<string, unknown>;
        if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
          throw new Error("主动探测参数必须是 JSON 对象");
        }
        params = parsed;
      } catch {
        throw new Error("主动探测参数必须是合法 JSON 对象");
      }
    }
    activeCheck = {
      detector: values.active_check_detector,
      trigger: values.active_check_trigger,
      timeout_seconds: Number(values.active_check_timeout_seconds || 5),
      params,
    };
  }

  return {
    id: values.id?.trim(),
    name: values.name.trim(),
    enabled: values.enabled,
    service: values.service.trim().toLowerCase(),
    severity: values.severity,
    description: values.description.trim(),
    match: {
      version,
      config,
      nse,
      package: packageMatch,
    },
    cve_ids: splitLines(values.cve_ids_text),
    cwe_ids: splitLines(values.cwe_ids_text),
    affected_versions_text: (values.affected_versions_text || "").trim() || null,
    exploit_module: (values.exploit_module || "").trim() || null,
    preconditions: splitLines(values.preconditions_text),
    verify_playbook: splitLines(values.verify_playbook_text),
    mitigations: splitLines(values.mitigations_text),
    remediation,
    references: splitLines(values.references_text),
    tags: splitLines(values.tags_text),
    active_check: activeCheck,
  };
}

function fillForm(form: FormInstance<RuleFormValues>, rule?: VulnRule | null) {
  form.setFieldsValue({
    id: rule?.id,
    name: rule?.name || "",
    enabled: rule?.enabled ?? true,
    service: rule?.service || "",
    severity: rule?.severity || "medium",
    description: rule?.description || "",
    version: rule?.match.version || "",
    config_text: rule?.match.config ? JSON.stringify(rule.match.config, null, 2) : "",
    nse_text: rule?.match.nse ? JSON.stringify(rule.match.nse, null, 2) : "",
    package_text: rule?.match.package ? JSON.stringify(rule.match.package, null, 2) : "",
    remediation_text: rule?.remediation ? JSON.stringify(rule.remediation, null, 2) : "",
    cve_ids_text: formatLines(rule?.cve_ids),
    cwe_ids_text: formatLines(rule?.cwe_ids),
    affected_versions_text: rule?.affected_versions_text || "",
    exploit_module: rule?.exploit_module || "",
    preconditions_text: formatLines(rule?.preconditions),
    verify_playbook_text: formatLines(rule?.verify_playbook),
    mitigations_text: formatLines(rule?.mitigations),
    references_text: formatLines(rule?.references),
    tags_text: formatLines(rule?.tags),
    active_check_enabled: Boolean(rule?.active_check),
    active_check_detector: rule?.active_check?.detector,
    active_check_trigger: rule?.active_check?.trigger,
    active_check_timeout_seconds: rule?.active_check?.timeout_seconds || 5,
    active_check_params_text: rule?.active_check ? JSON.stringify(rule.active_check.params || {}, null, 2) : "",
  });
}

function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

function importResultSummary(result: VulnRuleImportResponse) {
  return `新增 ${result.created} 条，更新 ${result.updated} 条，跳过 ${result.skipped} 条，错误 ${result.error_count} 条`;
}

export default function VulnLibraryPage() {
  const screens = Grid.useBreakpoint();
  const [rules, setRules] = useState<VulnRule[]>([]);
  const [status, setStatus] = useState<VulnLibraryStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [rebuildLoading, setRebuildLoading] = useState(false);
  const [batchLoading, setBatchLoading] = useState<"enable" | "disable" | null>(null);
  const [exportLoading, setExportLoading] = useState(false);
  const [keyword, setKeyword] = useState("");
  const deferredKeyword = useDeferredValue(keyword);
  const [isKeywordPending, startKeywordTransition] = useTransition();
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [enabledFilter, setEnabledFilter] = useState<"all" | "enabled" | "disabled">("all");
  const [catalogView, setCatalogView] = useState<VulnRuleCatalogView>("default");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<VulnRule | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [formOpen, setFormOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<VulnRule | null>(null);
  const [reloadToken, setReloadToken] = useState(0);
  const [selectedRowKeys, setSelectedRowKeys] = useState<string[]>([]);
  const [exportFormat, setExportFormat] = useState<VulnRuleExportFormat>("yaml");
  const [importFile, setImportFile] = useState<File | null>(null);
  const [importFormat, setImportFormat] = useState<VulnRuleFileFormat>("auto");
  const [importMode, setImportMode] = useState<VulnRuleImportMode>("skip_existing");
  const [importPreview, setImportPreview] = useState<VulnRuleImportResponse | null>(null);
  const [importPreviewLoading, setImportPreviewLoading] = useState(false);
  const [importConfirmLoading, setImportConfirmLoading] = useState(false);
  const [form] = Form.useForm<RuleFormValues>();
  const activeCheckEnabled = Form.useWatch("active_check_enabled", form) ?? false;

  const userRole = getStoredUserRole();
  const isAdmin = userRole === "admin";

  const refreshPage = () => {
    setReloadToken((current) => current + 1);
  };

  const refreshSelectedRule = async (ruleId: string | null | undefined) => {
    if (!ruleId) {
      return;
    }
    try {
      const detail = await getVulnRule(ruleId);
      setSelectedRule(detail);
    } catch {
      return;
    }
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    listVulnRules({
      page,
      pageSize,
      keyword: deferredKeyword || undefined,
      service: serviceFilter !== "all" ? serviceFilter : undefined,
      severity: severityFilter !== "all" ? severityFilter : undefined,
      enabled: enabledFilter === "all" ? undefined : enabledFilter === "enabled",
      catalogView,
    })
      .then((ruleResponse) => {
        if (cancelled) {
          return;
        }
        setRules(ruleResponse.items);
        setTotal(ruleResponse.meta.total);
        setError(null);
      })
      .catch((err) => {
        if (!cancelled) {
          setError((err as Error).message);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    getVulnLibraryStatus()
      .then((statusResponse) => {
        if (cancelled) {
          return;
        }
        setStatus(statusResponse);
        setStatusError(null);
      })
      .catch((err) => {
        if (!cancelled) {
          setStatus(null);
          setStatusError((err as Error).message);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [page, pageSize, deferredKeyword, serviceFilter, severityFilter, enabledFilter, catalogView, reloadToken]);

  const serviceOptions = useMemo(
    () =>
      Array.from(new Set(rules.map((item) => item.service)))
        .sort((a, b) => a.localeCompare(b))
        .map((value) => ({ label: value, value })),
    [rules],
  );

  const selectedCount = selectedRowKeys.length;
  const indexHealthy = Boolean(status?.index_in_sync && !status?.last_error && !status?.index_last_error);
  const importFileList = useMemo<UploadFile[]>(
    () =>
      importFile
        ? [
            {
              uid: importFile.name,
              name: importFile.name,
              status: "done",
              size: importFile.size,
            },
          ]
        : [],
    [importFile],
  );

  const columns = [
    {
      title: "规则摘要",
      key: "summary",
      width: screens.xl ? "32%" : "40%",
      render: (_: unknown, record: VulnRule) => (
        <div className="ui-cell-stack">
          <OverflowText value={record.name} block strong />
          <OverflowText value={record.id} block secondary mono />
          <div className="ui-chip-wrap">
            {getRuleCatalogType(record) === "high-value" ? <Tag color="red">高价值</Tag> : null}
            {getRuleCatalogType(record) === "legacy-exposure" ? <Tag color="gold">普通老版本</Tag> : null}
            <span className="console-inline-chip mono-text">{record.service}</span>
            {record.cve_ids.slice(0, 1).map((item) => (
              <Tag key={item} color="blue">
                {item}
              </Tag>
            ))}
            {record.cve_ids.length > 1 ? <Tag>+{record.cve_ids.length - 1}</Tag> : null}
          </div>
        </div>
      ),
    },
    {
      title: "匹配与探测",
      key: "match_summary",
      width: screens.xl ? "30%" : "34%",
      render: (_: unknown, record: VulnRule) => {
        const scripts = getRuleNseScripts(record.match);
        const versionText =
          record.match.version
          || (record.match.package ? "软件包条件" : record.match.config ? "配置条件" : scripts.length ? "脚本条件" : "无");
        const activeCheckText = record.active_check
          ? `${activeCheckDetectorLabelMap[record.active_check.detector]} / ${activeCheckTriggerLabelMap[record.active_check.trigger]}`
          : "未启用主动探测";
        return (
          <div className="ui-cell-stack">
            <OverflowText value={`版本/条件：${versionText}`} block />
            {scripts.length ? (
              <OverflowText value={`脚本：${scripts.join("、")}`} block secondary lines={2} />
            ) : (
              <OverflowText value="脚本：无" block secondary tooltip={false} />
            )}
            <OverflowText value={activeCheckText} block secondary lines={2} />
          </div>
        );
      },
    },
    ...(screens.xl
      ? [{
          title: "规则说明",
          key: "description",
          width: "20%",
          render: (_: unknown, record: VulnRule) => (
            <OverflowText value={record.description} block lines={2} />
          ),
        }]
      : []),
    {
      title: "风险状态",
      key: "risk_state",
      width: screens.xl ? 180 : 150,
      render: (_: unknown, record: VulnRule) => (
        <div className="ui-cell-stack">
          <StatusTag value={record.severity} />
          <StatusTag value={record.enabled ? "enabled" : "disabled"} />
        </div>
      ),
    },
    {
      title: "更新时间",
      dataIndex: "updated_at",
      key: "updated_at",
      width: 180,
      render: (value: string | null) => <OverflowText value={value ? new Date(value).toLocaleString() : "未记录"} block />,
    },
    ...(screens.xxl
      ? [{
          title: "脚本",
          key: "nse_compact",
          width: 220,
          render: (_: unknown, record: VulnRule) => renderCompactScriptMatches(getRuleNseScripts(record.match)),
        }]
      : []),
  ];

  const openRuleDetail = async (ruleId: string) => {
    try {
      setDrawerOpen(true);
      setDetailLoading(true);
      const detail = await getVulnRule(ruleId);
      setSelectedRule(detail);
    } catch (err) {
      message.error((err as Error).message);
      setDrawerOpen(false);
    } finally {
      setDetailLoading(false);
    }
  };

  const openCreateModal = () => {
    setEditingRule(null);
    fillForm(form, null);
    setFormOpen(true);
  };

  const openEditModal = async (ruleId: string) => {
    try {
      const detail = selectedRule?.id === ruleId ? selectedRule : await getVulnRule(ruleId);
      setEditingRule(detail);
      fillForm(form, detail);
      setFormOpen(true);
    } catch (err) {
      message.error((err as Error).message);
    }
  };

  const saveRule = async () => {
    try {
      const values = await form.validateFields();
      const payload = buildPayload(values);
      setSaving(true);
      let savedRule: VulnRule;
      if (editingRule) {
        savedRule = await updateVulnRule(editingRule.id, payload);
        message.success("规则已更新并立即生效");
      } else {
        savedRule = await createVulnRule(payload as VulnRuleInput & { id: string });
        message.success("规则已创建并立即生效");
      }
      if (selectedRule?.id === savedRule.id) {
        setSelectedRule(savedRule);
      }
      setFormOpen(false);
      refreshPage();
    } catch (err) {
      if ((err as { errorFields?: unknown }).errorFields) {
        return;
      }
      message.error((err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (ruleId: string) => {
    try {
      await deleteVulnRule(ruleId);
      message.success("规则已删除");
      setSelectedRowKeys((current) => current.filter((item) => item !== ruleId));
      if (selectedRule?.id === ruleId) {
        setDrawerOpen(false);
        setSelectedRule(null);
      }
      refreshPage();
    } catch (err) {
      message.error((err as Error).message);
    }
  };

  const clearSelection = () => {
    setSelectedRowKeys([]);
  };

  const handleBatchStatus = async (enabled: boolean) => {
    if (!selectedRowKeys.length) {
      return;
    }
    try {
      setBatchLoading(enabled ? "enable" : "disable");
      const response = await batchUpdateVulnRuleStatus(selectedRowKeys, enabled);
      message.success(
        `${enabled ? "批量启用" : "批量停用"}完成：更新 ${response.updated} 条，未变更 ${response.unchanged} 条，缺失 ${response.missing} 条`,
      );
      await refreshSelectedRule(selectedRule?.id);
      refreshPage();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setBatchLoading(null);
    }
  };

  const handleExport = async () => {
    try {
      setExportLoading(true);
      const response = await exportVulnRules({
        format: exportFormat,
        ruleIds: selectedRowKeys.length ? selectedRowKeys : undefined,
        keyword: selectedRowKeys.length ? undefined : deferredKeyword || undefined,
        service: selectedRowKeys.length || serviceFilter === "all" ? undefined : serviceFilter,
        severity: selectedRowKeys.length || severityFilter === "all" ? undefined : severityFilter,
        enabled:
          selectedRowKeys.length || enabledFilter === "all"
            ? undefined
            : enabledFilter === "enabled",
        catalogView: selectedRowKeys.length ? "all" : catalogView,
      });
      triggerBrowserDownload(
        response.blob,
        response.filename || `vuln_rules_export.${exportFormat === "json" ? "json" : "yaml"}`,
      );
      message.success(selectedRowKeys.length ? `已导出 ${selectedRowKeys.length} 条选中规则` : "已导出当前筛选结果");
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setExportLoading(false);
    }
  };

  const handleRebuildIndex = async () => {
    try {
      setRebuildLoading(true);
      const response = await rebuildVulnLibraryIndex();
      message.success(
        response.index_in_sync
          ? `索引重建完成，共 ${response.indexed_rule_count} 条规则`
          : "索引重建已执行，但状态仍未同步",
      );
      refreshPage();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setRebuildLoading(false);
    }
  };

  const closeImportModal = () => {
    setImportOpen(false);
    setImportFile(null);
    setImportPreview(null);
    setImportFormat("auto");
    setImportMode("skip_existing");
  };

  const previewImport = async () => {
    if (!importFile) {
      message.warning("请先选择导入文件");
      return;
    }
    try {
      setImportPreviewLoading(true);
      const result = await importVulnRules({
        file: importFile,
        format: importFormat,
        mode: importMode,
        dryRun: true,
      });
      setImportPreview(result);
      if (result.error_count) {
        message.warning(`预检完成：${importResultSummary(result)}`);
      } else {
        message.success(`预检完成：${importResultSummary(result)}`);
      }
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setImportPreviewLoading(false);
    }
  };

  const applyImport = async () => {
    if (!importFile) {
      message.warning("请先选择导入文件");
      return;
    }
    try {
      setImportConfirmLoading(true);
      const result = await importVulnRules({
        file: importFile,
        format: importFormat,
        mode: importMode,
        dryRun: false,
      });
      setImportPreview(result);
      if (result.error_count) {
        message.warning(`导入未执行：${importResultSummary(result)}`);
        return;
      }
      message.success(`导入完成：${importResultSummary(result)}`);
      clearSelection();
      closeImportModal();
      await refreshSelectedRule(selectedRule?.id);
      refreshPage();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setImportConfirmLoading(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="规则治理"
        title="漏洞规则工作台"
        description="规则运行真源保持为 YAML；当前桌面工作台聚焦索引健康、批量启停、导入导出与规则维护。"
        meta={[
          { label: "规则总数", value: status?.rule_count ?? 0, tone: "accent" },
          { label: "当前筛选", value: total, tone: "neutral" },
          {
            label: "规则视图",
            value: catalogView === "default" ? "高价值优先" : catalogView === "legacy" ? "普通老版本" : "全部规则",
            tone: catalogView === "legacy" ? "warning" : "neutral",
          },
          { label: "批量选择", value: selectedCount, tone: selectedCount ? "accent" : "neutral" },
          { label: "索引状态", value: indexHealthy ? "已同步" : "待修复", tone: indexHealthy ? "success" : "warning" },
        ]}
      />

      {statusError ? <Alert type="warning" showIcon message={`状态读取失败：${statusError}`} /> : null}
      {status ? (
        <Alert
          type={status.last_error || status.index_last_error || !status.index_in_sync ? "warning" : "success"}
          showIcon
          message={
            status.last_error
              ? `规则加载存在告警：${status.last_error}`
              : status.index_last_error
                ? `索引同步存在告警：${status.index_last_error}`
                : status.index_in_sync
                  ? `规则引擎与索引已同步，共 ${status.rule_count} 条规则`
                  : "规则索引与 YAML 不一致，建议重建索引"
          }
        />
      ) : null}

      <Card className="panel-card compact-workbench-card">
        <div className="compact-toolbar-stack">
          <div className="compact-toolbar-row">
            <Space className="vuln-library-toolbar" wrap>
              <Input.Search
                className="vuln-library-search"
                placeholder="搜索规则名、服务、CVE、标签"
                allowClear
                value={keyword}
                loading={isKeywordPending}
                onChange={(event) => {
                  const nextValue = event.target.value;
                  startKeywordTransition(() => {
                    setPage(1);
                    setKeyword(nextValue);
                  });
                }}
              />
              <Select
                value={catalogView}
                onChange={(value) => {
                  setPage(1);
                  setCatalogView(value);
                }}
                style={{ width: 170 }}
                options={[
                  { label: "高价值优先", value: "default" },
                  { label: "全部规则", value: "all" },
                  { label: "普通老版本", value: "legacy" },
                ]}
              />
              <Select
                value={serviceFilter}
                onChange={(value) => {
                  setPage(1);
                  setServiceFilter(value);
                }}
                options={[{ label: "全部服务", value: "all" }, ...serviceOptions]}
                style={{ width: 180 }}
              />
              <Select
                value={severityFilter}
                onChange={(value) => {
                  setPage(1);
                  setSeverityFilter(value);
                }}
                style={{ width: 160 }}
                options={[
                  { label: "全部级别", value: "all" },
                  { label: "低危", value: "low" },
                  { label: "中危", value: "medium" },
                  { label: "高危", value: "high" },
                  { label: "严重", value: "critical" },
                ]}
              />
              <Select
                value={enabledFilter}
                onChange={(value) => {
                  setPage(1);
                  setEnabledFilter(value);
                }}
                style={{ width: 160 }}
                options={[
                  { label: "全部状态", value: "all" },
                  { label: "仅启用", value: "enabled" },
                  { label: "仅停用", value: "disabled" },
                ]}
              />
              <Button onClick={refreshPage}>刷新</Button>
              {isAdmin ? (
                <Button loading={rebuildLoading} onClick={() => void handleRebuildIndex()}>
                  重建索引
                </Button>
              ) : null}
              {isAdmin ? (
                <Button type="primary" onClick={openCreateModal}>
                  新增规则
                </Button>
              ) : null}
            </Space>
          </div>
          {isAdmin ? (
            <div className="compact-toolbar-row compact-toolbar-row-secondary">
              <Space className="vuln-library-batch-toolbar" wrap>
                <Typography.Text>已选 {selectedCount} 项</Typography.Text>
                <Button disabled={!selectedCount || batchLoading !== null} loading={batchLoading === "enable"} onClick={() => void handleBatchStatus(true)}>
                  批量启用
                </Button>
                <Button disabled={!selectedCount || batchLoading !== null} loading={batchLoading === "disable"} onClick={() => void handleBatchStatus(false)}>
                  批量停用
                </Button>
                <Select
                  value={exportFormat}
                  onChange={(value) => setExportFormat(value)}
                  style={{ width: 140 }}
                  options={[
                    { label: "导出 YAML", value: "yaml" },
                    { label: "导出 JSON", value: "json" },
                  ]}
                />
                <Button loading={exportLoading} onClick={() => void handleExport()}>
                  {selectedCount ? "导出选中规则" : "导出当前筛选"}
                </Button>
                <Button onClick={() => setImportOpen(true)}>导入规则文件</Button>
                <Button onClick={clearSelection} disabled={!selectedCount}>
                  清空选择
                </Button>
              </Space>
            </div>
          ) : null}
        </div>
      </Card>

      <Card className="panel-card">
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
        <Table
          className="console-table"
          rowKey="id"
          loading={loading}
          dataSource={rules}
          columns={columns}
          rowSelection={
            isAdmin
              ? {
                  selectedRowKeys,
                  onChange: (keys) => setSelectedRowKeys(keys as string[]),
                  preserveSelectedRowKeys: true,
                  columnWidth: 52,
                }
              : undefined
          }
          pagination={{
            current: page,
            pageSize,
            total,
            showSizeChanger: true,
            onChange: (nextPage, nextPageSize) => {
              setPage(nextPage);
              setPageSize(nextPageSize);
            },
          }}
          locale={{ emptyText: <Empty description="暂无漏洞规则" /> }}
          onRow={(record) => ({
            onClick: (event) => {
              const target = event.target as HTMLElement;
              if (target.closest("button") || target.closest("a") || target.closest("input") || target.closest(".ant-checkbox-wrapper")) {
                return;
              }
              void openRuleDetail(record.id);
            },
            style: { cursor: "pointer" },
          })}
        />
      </Card>

      <Drawer
        title={<OverflowText value={selectedRule?.name || "漏洞规则详情"} block lines={2} />}
        width={560}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        extra={
          isAdmin && selectedRule ? (
            <Space>
              <Button onClick={() => void openEditModal(selectedRule.id)}>编辑</Button>
              <Popconfirm
                title="确认删除该规则？"
                description="删除后将从 YAML 规则库移除，并影响后续风险匹配。"
                onConfirm={() => void handleDelete(selectedRule.id)}
              >
                <Button danger>删除</Button>
              </Popconfirm>
            </Space>
          ) : null
        }
      >
        {detailLoading || !selectedRule ? (
          <Empty description="正在加载详情" />
        ) : (
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: "1", label: "规则 ID", children: <span className="ui-detail-wrap mono-text">{selectedRule.id}</span> },
                { key: "2", label: "服务", children: selectedRule.service },
                { key: "3", label: "严重级别", children: <StatusTag value={selectedRule.severity} /> },
                { key: "4", label: "规则类型", children: getRuleCatalogTypeLabel(selectedRule) },
                { key: "5", label: "启用状态", children: selectedRule.enabled ? "启用" : "停用" },
                {
                  key: "6",
                  label: "版本匹配",
                  children: (
                    <span className="ui-detail-wrap">
                      {selectedRule.match.version || (selectedRule.match.package ? "软件包条件" : "配置型规则")}
                    </span>
                  ),
                },
                {
                  key: "7",
                  label: "Nmap 脚本匹配",
                  children: <span className="ui-detail-wrap mono-text">{getRuleNseScripts(selectedRule.match).length ? getRuleNseScripts(selectedRule.match).join("、") : "无"}</span>,
                },
                {
                  key: "8",
                  label: "主动探测",
                  children: selectedRule.active_check ? (
                    <div className="ui-cell-stack">
                      <span className="ui-detail-wrap">{activeCheckDetectorLabelMap[selectedRule.active_check.detector]}</span>
                      <Typography.Text type="secondary">{activeCheckTriggerLabelMap[selectedRule.active_check.trigger]}</Typography.Text>
                    </div>
                  ) : "未启用",
                },
                { key: "9", label: "影响版本说明", children: <span className="ui-detail-wrap">{selectedRule.affected_versions_text || "未填写"}</span> },
                { key: "10", label: "利用模块", children: <span className="ui-detail-wrap mono-text">{selectedRule.exploit_module || "未填写"}</span> },
                {
                  key: "11",
                  label: "最近更新",
                  children: selectedRule.updated_at ? new Date(selectedRule.updated_at).toLocaleString() : "未记录",
                },
              ]}
            />

            <Card size="small" title="漏洞描述">
              <Typography.Paragraph style={{ marginBottom: 0 }}>{selectedRule.description}</Typography.Paragraph>
            </Card>

            <Card size="small" title="匹配条件">
              <Space direction="vertical" size={8} style={{ width: "100%" }}>
                <Typography.Text className="ui-detail-wrap">版本约束：{selectedRule.match.version || "无"}</Typography.Text>
                <Typography.Text>配置匹配：</Typography.Text>
                <div className="code-block ui-code-scroll">{selectedRule.match.config ? JSON.stringify(selectedRule.match.config, null, 2) : "无"}</div>
                <Typography.Text>Nmap 脚本匹配：</Typography.Text>
                <div className="code-block ui-code-scroll">{selectedRule.match.nse ? JSON.stringify(selectedRule.match.nse, null, 2) : "无"}</div>
                <Typography.Text>软件包匹配：</Typography.Text>
                <div className="code-block ui-code-scroll">{selectedRule.match.package ? JSON.stringify(selectedRule.match.package, null, 2) : "无"}</div>
              </Space>
            </Card>

            <Card size="small" title="主动探测">
              {selectedRule.active_check ? (
                <Space direction="vertical" size={8} style={{ width: "100%" }}>
                  <Typography.Text className="ui-detail-wrap">探测器：{activeCheckDetectorLabelMap[selectedRule.active_check.detector]}</Typography.Text>
                  <Typography.Text className="ui-detail-wrap">触发方式：{activeCheckTriggerLabelMap[selectedRule.active_check.trigger]}</Typography.Text>
                  <Typography.Text>超时时间：{selectedRule.active_check.timeout_seconds} 秒</Typography.Text>
                  <Typography.Text>参数：</Typography.Text>
                  <div className="code-block ui-code-scroll">{JSON.stringify(selectedRule.active_check.params || {}, null, 2)}</div>
                </Space>
              ) : (
                <Typography.Text type="secondary">该规则未配置主动探测</Typography.Text>
              )}
            </Card>

            <Card size="small" title="标识与参考">
              <div className="ui-chip-wrap">
                {selectedRule.cve_ids.map((item) => (
                  <span key={item} className="console-inline-chip console-inline-chip-info mono-text">{item}</span>
                ))}
                {selectedRule.cwe_ids.map((item) => (
                  <span key={item} className="console-inline-chip mono-text">{item}</span>
                ))}
                {selectedRule.tags.map((item) => renderGovernanceTag(item))}
              </div>
              <Space direction="vertical" size={8} style={{ width: "100%", marginTop: 12 }}>
                {selectedRule.references.length ? (
                  selectedRule.references.map((item) => (
                    <Typography.Link key={item} href={item} target="_blank" rel="noreferrer" className="ui-link-wrap">
                      {item}
                    </Typography.Link>
                  ))
                ) : (
                  <Typography.Text type="secondary">暂无参考链接</Typography.Text>
                )}
              </Space>
            </Card>

            <Card size="small" title="验证建议">
              {selectedRule.verify_playbook.length ? (
                <Space direction="vertical" size={8}>
                  {selectedRule.verify_playbook.map((item) => (
                    <Typography.Paragraph key={item} style={{ marginBottom: 0 }}>
                      {item}
                    </Typography.Paragraph>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary">暂无验证建议</Typography.Text>
              )}
            </Card>

            <Card size="small" title="缓解措施">
              {selectedRule.mitigations.length ? (
                <Space direction="vertical" size={8}>
                  {selectedRule.mitigations.map((item) => (
                    <Typography.Paragraph key={item} style={{ marginBottom: 0 }}>
                      {item}
                    </Typography.Paragraph>
                  ))}
                </Space>
              ) : (
                <Typography.Text type="secondary">暂无缓解措施</Typography.Text>
              )}
            </Card>

            <Card size="small" title="结构化修复模板">
              {selectedRule.remediation ? (
                <Space direction="vertical" size={12} style={{ width: "100%" }}>
                  <Typography.Paragraph style={{ marginBottom: 0 }}>
                    {selectedRule.remediation.summary}
                  </Typography.Paragraph>
                  {selectedRule.remediation.impact_summary ? (
                    <Alert type="info" showIcon message="影响范围" description={selectedRule.remediation.impact_summary} />
                  ) : null}
                  <Typography.Text>
                    处理方式：{remediationLevelLabelMap[selectedRule.remediation.automation_level]}
                  </Typography.Text>
                  {selectedRule.remediation.precheck_items.length ? (
                    <div className="ui-cell-stack">
                      <Typography.Text strong>执行前检查</Typography.Text>
                      {selectedRule.remediation.precheck_items.map((item) => (
                        <Typography.Text key={item} className="ui-detail-wrap">
                          • {item}
                        </Typography.Text>
                      ))}
                    </div>
                  ) : null}
                  {selectedRule.remediation.verify_items.length ? (
                    <div className="ui-cell-stack">
                      <Typography.Text strong>执行后验证</Typography.Text>
                      {selectedRule.remediation.verify_items.map((item) => (
                        <Typography.Text key={item} className="ui-detail-wrap">
                          • {item}
                        </Typography.Text>
                      ))}
                    </div>
                  ) : null}
                  {selectedRule.remediation.rollback_notes.length ? (
                    <div className="ui-cell-stack">
                      <Typography.Text strong>回滚说明</Typography.Text>
                      {selectedRule.remediation.rollback_notes.map((item) => (
                        <Typography.Text key={item} type="secondary" className="ui-detail-wrap">
                          • {item}
                        </Typography.Text>
                      ))}
                    </div>
                  ) : null}
                  <Space direction="vertical" size={8} style={{ width: "100%" }}>
                    {selectedRule.remediation.actions.map((action, index) => (
                      <Card
                        key={`${action.action_type}-${index}`}
                        size="small"
                        type="inner"
                        title={`${index + 1}. ${action.title}`}
                      >
                        <Space direction="vertical" size={6} style={{ width: "100%" }}>
                          <Typography.Text className="mono-text">
                            动作类型：{action.action_type}
                          </Typography.Text>
                          <div className="code-block ui-code-scroll">
                            {JSON.stringify(action.params || {}, null, 2)}
                          </div>
                          {action.target_files.length ? (
                            <Typography.Text className="ui-detail-wrap">
                              目标文件：{action.target_files.join("、")}
                            </Typography.Text>
                          ) : null}
                          {action.target_services.length ? (
                            <Typography.Text className="ui-detail-wrap">
                              目标服务：{action.target_services.join("、")}
                            </Typography.Text>
                          ) : null}
                          {action.target_paths.length ? (
                            <Typography.Text className="ui-detail-wrap">
                              目标路径：{action.target_paths.join("、")}
                            </Typography.Text>
                          ) : null}
                          {action.verify_items.length ? (
                            <div className="ui-cell-stack">
                              <Typography.Text>步骤验证：</Typography.Text>
                              {action.verify_items.map((item) => (
                                <Typography.Text key={item} className="ui-detail-wrap">
                                  • {item}
                                </Typography.Text>
                              ))}
                            </div>
                          ) : null}
                          {action.requires_confirmation ? <Typography.Text>执行前需要确认</Typography.Text> : null}
                          {action.rollback_hint ? (
                            <Typography.Text type="secondary">{action.rollback_hint}</Typography.Text>
                          ) : null}
                        </Space>
                      </Card>
                    ))}
                  </Space>
                  {selectedRule.remediation.references.length ? (
                    <Space direction="vertical" size={4} style={{ width: "100%" }}>
                      <Typography.Text>模板参考：</Typography.Text>
                      {selectedRule.remediation.references.map((item) => (
                        <Typography.Link key={item} href={item} target="_blank" rel="noreferrer" className="ui-link-wrap">
                          {item}
                        </Typography.Link>
                      ))}
                    </Space>
                  ) : null}
                </Space>
              ) : (
                <Typography.Text type="secondary">暂无结构化修复模板</Typography.Text>
              )}
            </Card>
          </Space>
        )}
      </Drawer>

      <Modal
        title={editingRule ? "编辑漏洞规则" : "新增漏洞规则"}
        open={formOpen}
        width={780}
        onOk={() => void saveRule()}
        confirmLoading={saving}
        onCancel={() => setFormOpen(false)}
        destroyOnClose
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ enabled: true, severity: "medium", active_check_enabled: false, active_check_timeout_seconds: 5 }}
        >
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="id" label="规则 ID" rules={[{ required: true, message: "请输入规则 ID" }]}>
                <Input disabled={Boolean(editingRule)} placeholder="例如 samba.usermap_script.lt_3_0_25rc3" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="name" label="规则名称" rules={[{ required: true, message: "请输入规则名称" }]}>
                <Input placeholder="例如 Samba 用户名映射脚本命令执行风险" />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={8}>
              <Form.Item name="service" label="服务名" rules={[{ required: true, message: "请输入服务名" }]}>
                <Input placeholder="例如 samba / tomcat / mysql" />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="severity" label="严重级别" rules={[{ required: true, message: "请选择严重级别" }]}>
                <Select
                  options={[
                    { label: "低危", value: "low" },
                    { label: "中危", value: "medium" },
                    { label: "高危", value: "high" },
                    { label: "严重", value: "critical" },
                  ]}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item name="enabled" label="启用状态" valuePropName="checked">
                <Switch checkedChildren="启用" unCheckedChildren="停用" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="description" label="漏洞描述" rules={[{ required: true, message: "请输入漏洞描述" }]}>
            <Input.TextArea rows={3} />
          </Form.Item>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="version" label="版本匹配">
                <Input placeholder="例如 <3.0.25rc3 或 ==2.3.4" />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="affected_versions_text" label="影响版本说明">
                <Input placeholder="例如 Samba 3.0.0 至 3.0.25rc3" />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="config_text" label="配置匹配（JSON）">
            <Input.TextArea rows={5} placeholder='例如 {"requirepass":{"exists":false}}' />
          </Form.Item>

          <Form.Item name="nse_text" label="Nmap 脚本匹配（JSON）">
            <Input.TextArea
              rows={5}
              placeholder={'例如 {"ftp-anon.hit":{"eq":true},"http-methods.risky_methods":{"contains":"PUT"}}'}
            />
          </Form.Item>

          <Form.Item name="package_text" label="软件包匹配（JSON）">
            <Input.TextArea
              rows={6}
              placeholder={'例如 {"manager":"dpkg","name":"sudo","compare":"lt_fixed","fixed_versions":{"ubuntu":{"20.04":"1.8.31-1ubuntu1.2"},"debian":{"11":"1.9.5p2-3+deb11u1"}}}'}
            />
          </Form.Item>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="cve_ids_text" label="CVE（每行一条）">
                <Input.TextArea rows={4} placeholder={"CVE-2011-2523\nCVE-2007-2447"} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="cwe_ids_text" label="CWE（每行一条）">
                <Input.TextArea rows={4} placeholder={"CWE-94\nCWE-284"} />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="exploit_module" label="利用模块">
            <Input placeholder="例如 exploit/unix/ftp/vsftpd_234_backdoor" />
          </Form.Item>

          <Card size="small" title="主动探测配置" style={{ marginBottom: 16 }}>
            <Row gutter={[16, 0]}>
              <Col xs={24} md={8}>
                <Form.Item name="active_check_enabled" label="启用主动探测" valuePropName="checked">
                  <Switch checkedChildren="启用" unCheckedChildren="停用" />
                </Form.Item>
              </Col>
              <Col xs={24} md={8}>
                <Form.Item name="active_check_detector" label="探测器">
                  <Select disabled={!activeCheckEnabled} options={activeCheckDetectorOptions} placeholder="选择探测器" />
                </Form.Item>
              </Col>
              <Col xs={24} md={8}>
                <Form.Item name="active_check_trigger" label="触发方式">
                  <Select disabled={!activeCheckEnabled} options={activeCheckTriggerOptions} placeholder="选择触发方式" />
                </Form.Item>
              </Col>
            </Row>

            <Row gutter={[16, 0]}>
              <Col xs={24} md={8}>
                <Form.Item name="active_check_timeout_seconds" label="超时时间（秒）">
                  <Input disabled={!activeCheckEnabled} type="number" min={1} max={60} />
                </Form.Item>
              </Col>
            </Row>

            <Form.Item name="active_check_params_text" label="探测器参数（JSON）">
              <Input.TextArea
                disabled={!activeCheckEnabled}
                rows={5}
                placeholder={'例如 {"credentials":[{"username":"tomcat","password":"tomcat"}]}'}
              />
            </Form.Item>
          </Card>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="preconditions_text" label="利用条件（每行一条）">
                <Input.TextArea rows={4} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="verify_playbook_text" label="验证建议（每行一条）">
                <Input.TextArea rows={4} />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="mitigations_text" label="缓解措施（每行一条）">
                <Input.TextArea rows={4} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item name="references_text" label="参考链接（每行一条）">
                <Input.TextArea rows={4} />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item name="remediation_text" label="修复模板（JSON）">
            <Input.TextArea
              rows={8}
              placeholder={'例如 {"summary":"升级组件并重载服务","automation_level":"callable","impact_summary":"可能导致短暂重载","precheck_items":["确认配置已备份"],"verify_items":["确认风险复测通过"],"rollback_notes":["保留原版本回滚路径"],"actions":[{"action_type":"upgrade_package","title":"升级软件包","params":{"package_name":"nginx"},"target_services":["nginx"],"verify_items":["确认 nginx 健康检查通过"]}]}'}
            />
          </Form.Item>

          <Form.Item name="tags_text" label="标签（每行一条）">
            <Input.TextArea rows={3} placeholder={"lab-baseline\nweb\nlegacy"} />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="导入漏洞规则"
        open={importOpen}
        onCancel={closeImportModal}
        destroyOnClose
        footer={[
          <Button key="cancel" onClick={closeImportModal}>
            取消
          </Button>,
          <Button key="preview" loading={importPreviewLoading} onClick={() => void previewImport()}>
            预检导入
          </Button>,
          <Button
            key="confirm"
            type="primary"
            loading={importConfirmLoading}
            disabled={!importPreview || importPreview.error_count > 0}
            onClick={() => void applyImport()}
          >
            确认导入
          </Button>,
        ]}
      >
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Alert
            type="info"
            showIcon
            message="导入流程"
            description="先执行预检查看新增、更新和错误摘要；确认无误后再正式导入。YAML 仍为唯一真源。"
          />

          <Upload
            beforeUpload={(file) => {
              setImportFile(file);
              setImportPreview(null);
              return false;
            }}
            onRemove={() => {
              setImportFile(null);
              setImportPreview(null);
            }}
            fileList={importFileList}
            maxCount={1}
          >
            <Button>选择 YAML / JSON 文件</Button>
          </Upload>

          <Space wrap style={{ width: "100%" }}>
            <Select
              value={importFormat}
              onChange={(value) => setImportFormat(value)}
              style={{ width: 180 }}
              options={[
                { label: "自动识别格式", value: "auto" },
                { label: "按 YAML 解析", value: "yaml" },
                { label: "按 JSON 解析", value: "json" },
              ]}
            />
            <Select
              value={importMode}
              onChange={(value) => setImportMode(value)}
              style={{ width: 220 }}
              options={[
                { label: "跳过已存在规则", value: "skip_existing" },
                { label: "存在则覆盖更新", value: "upsert" },
              ]}
            />
          </Space>

          {importPreview ? (
            <Card size="small" title="预检结果">
              <Space direction="vertical" size={10} style={{ width: "100%" }}>
                <Space size={[8, 8]} wrap>
                  <span className="console-inline-chip console-inline-chip-info">检测格式：{importPreview.detected_format.toUpperCase()}</span>
                  <span className="console-inline-chip">文件规则数：{importPreview.total_in_file}</span>
                  <span className="console-inline-chip console-inline-chip-success">新增：{importPreview.created}</span>
                  <span className="console-inline-chip console-inline-chip-warning">更新：{importPreview.updated}</span>
                  <span className="console-inline-chip">跳过：{importPreview.skipped}</span>
                  <span className={`console-inline-chip ${importPreview.error_count ? "console-inline-chip-danger" : "console-inline-chip-success"}`}>错误：{importPreview.error_count}</span>
                </Space>
                {importPreview.errors.length ? (
                  <Alert
                    type="warning"
                    showIcon
                    message="预检发现错误，修复后请重新预检"
                    description={
                      <Space direction="vertical" size={6}>
                        {importPreview.errors.map((item, index) => (
                          <Typography.Text key={`${item.rule_id || "error"}-${index}`}>
                            {(item.rule_id ? `${item.rule_id}：` : "") + item.message}
                          </Typography.Text>
                        ))}
                      </Space>
                    }
                  />
                ) : (
                  <Alert type="success" showIcon message={importResultSummary(importPreview)} />
                )}
              </Space>
            </Card>
          ) : null}
        </Space>
      </Modal>
    </Space>
  );
}
