"use client";

import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Form,
  Input,
  List,
  Modal,
  Progress,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";

import {
  getAsset,
  getAssetCredential,
  getLatestAssetCollection,
  getLatestAssetInitial,
  listAssetRisks,
  runAssetCollection,
  runRiskVerify,
  setAssetCredential,
  verifyAssetCredential,
} from "@/services/api";
import { Asset } from "@/types/asset";
import {
  AssetCredentialReadResponse,
  AssetCredentialUpsertRequest,
  AssetCredentialVerifyResponse,
  AssetLatestCollectionResponse,
  AssetLatestInitialResponse,
  CredentialAuthType,
} from "@/types/collection";
import { RiskFinding } from "@/types/risk";
import CollapsibleJsonBlock from "@/components/CollapsibleJsonBlock";
import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";

type CredentialFormValues = {
  auth_type: CredentialAuthType;
  username: string;
  password?: string;
  private_key?: string;
};

const ACTIVE_DETECTOR_LABELS: Record<string, string> = {
  vsftpd_smiley_backdoor: "vsftpd 笑脸后门验证",
  ftp_anonymous_login: "FTP 匿名登录验证",
  tomcat_manager_default_creds: "Tomcat 管理后台默认凭据验证",
  distccd_rce_probe: "distccd 无害命令验证",
  unrealircd_backdoor_probe: "UnrealIRCd 后门验证",
  redis_unauth_info_probe: "Redis 未授权 INFO 验证",
  http_risky_methods_probe: "HTTP 风险方法验证",
};

function toRecord(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }
  return input as Record<string, unknown>;
}

function toStringArray(input: unknown): string[] {
  if (!Array.isArray(input)) {
    return [];
  }
  return input
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
}

function normalizeDisplayText(input: unknown): string {
  return typeof input === "string" ? input.trim() : "";
}

function displayOrNone(input: unknown): string {
  const value = normalizeDisplayText(input);
  return value || "无";
}

function compactDisplayParts(...values: unknown[]): string {
  const parts = values.map((item) => normalizeDisplayText(item)).filter(Boolean);
  return parts.join(" / ");
}

const ASSET_CATEGORY_LABELS: Record<string, string> = {
  network_infrastructure: "网络基础设施",
  virtual_network_component: "虚拟网络组件",
  iot_device: "物联网设备",
  general_endpoint: "通用终端",
};

const DEVICE_ROLE_LABELS: Record<string, string> = {
  gateway_dns: "网关设备 / DNS 服务",
  gateway: "网关设备",
  dns_resolver: "DNS 解析服务",
  dhcp_dns: "DHCP / DNS 服务",
  dhcp_service: "DHCP 服务",
  network_infrastructure: "网络基础设施",
};

const IDENTITY_SOURCE_LABELS: Record<string, string> = {
  network_discovery_inferred: "发现推断",
};

function formatAssetCategory(value: unknown): string {
  const normalized = normalizeDisplayText(value);
  return ASSET_CATEGORY_LABELS[normalized] || normalized;
}

function formatDeviceRole(value: unknown): string {
  const normalized = normalizeDisplayText(value);
  return DEVICE_ROLE_LABELS[normalized] || normalized;
}

function formatIdentitySource(value: unknown): string {
  const normalized = normalizeDisplayText(value);
  return IDENTITY_SOURCE_LABELS[normalized] || normalized;
}

function isRecognizedServiceName(input: unknown): boolean {
  const value = normalizeDisplayText(input).toLowerCase();
  return value !== "" && value !== "unknown" && value !== "未知服务";
}

function resolveServiceName(record: Asset["ports"][number]): string {
  if (isRecognizedServiceName(record.service_name)) {
    return String(record.service_name).trim();
  }
  const payload = toRecord(record.fingerprint_json);
  const aliases = toStringArray(payload.service_aliases);
  const candidates = [
    payload.application_service,
    payload.product_name,
    payload.transport_service,
    payload.nmap_service,
    payload.nmap_product,
    aliases[0],
  ];
  for (const item of candidates) {
    if (isRecognizedServiceName(item)) {
      return normalizeDisplayText(item);
    }
  }
  return "无";
}

function resolveServiceVersion(record: Asset["ports"][number]): string {
  const direct = normalizeDisplayText(record.service_version);
  if (direct) {
    return direct;
  }
  const payload = toRecord(record.fingerprint_json);
  const candidates = [payload.product_version, payload.version, payload.nmap_version];
  for (const item of candidates) {
    const value = normalizeDisplayText(item);
    if (value) {
      return value;
    }
  }
  return "";
}

function buildLocalAssetLabel(asset: Asset): string {
  if (!asset.is_local) {
    return "否";
  }
  const hint = normalizeDisplayText(asset.local_hint) || "本机命中";
  return `是（${hint}）`;
}

function buildAssetHeaderDescription(asset: Asset): string {
  const facts = [asset.hostname, asset.os_name].map((item) => normalizeDisplayText(item)).filter(Boolean);
  facts.push("用于桌面端纵深分析和再采集操作。");
  return facts.join(" · ");
}

function formatNmapSkipReason(reason: unknown): string {
  const raw = typeof reason === "string" ? reason.trim() : "";
  if (!raw) {
    return "";
  }
  if (raw === "backdoor_candidate_policy") {
    return "后门候选端口，已跳过 nmap 版本探测";
  }
  return raw;
}

function formatNsePhase(value: unknown): string {
  const raw = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (raw === "collection") {
    return "SSH 授权深度检查";
  }
  if (raw === "discovery") {
    return "发现任务";
  }
  return raw;
}

function buildNseMetaLine(payload: Record<string, unknown>): string {
  const phase = formatNsePhase(payload.nse_last_phase);
  const collectedAtRaw = typeof payload.nse_last_collected_at === "string" ? payload.nse_last_collected_at : "";
  const collectedAt = collectedAtRaw ? new Date(collectedAtRaw) : null;
  const collectedLabel = collectedAt && !Number.isNaN(collectedAt.getTime()) ? collectedAt.toLocaleString() : "";
  if (phase && collectedLabel) {
    return `来源：${phase} / ${collectedLabel}`;
  }
  if (phase) {
    return `来源：${phase}`;
  }
  if (collectedLabel) {
    return `最近执行：${collectedLabel}`;
  }
  return "";
}

function getActiveDetectorLabel(detector: unknown): string {
  const key = typeof detector === "string" ? detector.trim() : "";
  if (!key) {
    return "";
  }
  return ACTIVE_DETECTOR_LABELS[key] || key;
}

function buildNseSummaryView(input: unknown): {
  requestedScripts: string[];
  hitScripts: string[];
  summaryLines: string[];
} {
  const payload = toRecord(input);
  const requestedScripts = toStringArray(payload.requested_scripts);
  const hitScripts = toStringArray(payload.hit_scripts);
  const summaries = toRecord(payload.script_summaries);
  const summaryLines = Object.entries(summaries)
    .map(([scriptId, summary]) => {
      const message = typeof summary === "string" ? summary.trim() : "";
      return message ? `${scriptId}：${message}` : "";
    })
    .filter(Boolean);
  return { requestedScripts, hitScripts, summaryLines };
}

export default function AssetDetailView({ assetId }: { assetId: string }) {
  const router = useRouter();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [risks, setRisks] = useState<RiskFinding[]>([]);
  const [credentialMeta, setCredentialMeta] = useState<AssetCredentialReadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastTaskId, setLastTaskId] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<"collect" | "verify" | null>(null);
  const [credentialVerifyLoading, setCredentialVerifyLoading] = useState(false);
  const [credentialVerifyResult, setCredentialVerifyResult] = useState<AssetCredentialVerifyResponse | null>(null);
  const [latestInitial, setLatestInitial] = useState<AssetLatestInitialResponse | null>(null);
  const [latestCollection, setLatestCollection] = useState<AssetLatestCollectionResponse | null>(null);
  const [credentialSaving, setCredentialSaving] = useState(false);
  const [credentialEditing, setCredentialEditing] = useState(true);
  const [authorizationModalOpen, setAuthorizationModalOpen] = useState(false);
  const [sudoModalOpen, setSudoModalOpen] = useState(false);
  const [pendingCredentialValues, setPendingCredentialValues] = useState<CredentialFormValues | null>(null);
  const [sudoPasswordDraft, setSudoPasswordDraft] = useState("");
  const [sudoPasswordError, setSudoPasswordError] = useState<string | null>(null);
  const [viewportWidth, setViewportWidth] = useState(1200);
  const [viewportHeight, setViewportHeight] = useState(900);
  const [leftStackHeight, setLeftStackHeight] = useState(0);
  const [credentialForm] = Form.useForm<CredentialFormValues>();
  const leftStackRef = useRef<HTMLDivElement | null>(null);
  const credentialAuthType = Form.useWatch("auth_type", credentialForm) || "password";

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      getAsset(assetId),
      listAssetRisks(assetId),
      getAssetCredential(assetId),
      getLatestAssetInitial(assetId).catch(() => null),
      getLatestAssetCollection(assetId).catch(() => null),
    ])
      .then(([assetData, riskData, credentialData, initialSnapshot, latestCollectionResult]) => {
        if (cancelled) {
          return;
        }
        setAsset(assetData);
        setRisks(riskData.items);
        setCredentialMeta(credentialData);
        setCredentialEditing(!credentialData.bound);
        if (initialSnapshot) {
          setLatestInitial(initialSnapshot);
        }
        if (latestCollectionResult) {
          setLatestCollection(latestCollectionResult);
        }
        credentialForm.setFieldsValue({
          auth_type: credentialData.auth_type || "password",
          username: credentialData.username || "",
          password: "",
          private_key: "",
        });
      })
      .catch((err) => {
        if (!cancelled) {
          setError((err as Error).message);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [assetId, credentialForm]);

  useEffect(() => {
    const updateViewport = () => {
      setViewportWidth(window.innerWidth);
      setViewportHeight(window.innerHeight);
    };
    updateViewport();
    window.addEventListener("resize", updateViewport, { passive: true });
    return () => {
      window.removeEventListener("resize", updateViewport);
    };
  }, []);

  useLayoutEffect(() => {
    const node = leftStackRef.current;
    if (!node || typeof ResizeObserver === "undefined") {
      return;
    }
    const updateHeight = () => {
      const next = Math.ceil(node.getBoundingClientRect().height);
      setLeftStackHeight(next > 0 ? next : 0);
    };
    updateHeight();
    const observer = new ResizeObserver(() => updateHeight());
    observer.observe(node);
    return () => {
      observer.disconnect();
    };
  }, [asset, risks.length, latestCollection, latestInitial]);

  const isCompactLayout = viewportWidth < 1200;
  const isMobileLayout = viewportWidth < 768;
  const compactPanelHeight = isMobileLayout ? 320 : 420;
  const desktopMaxCardHeight = Math.max(600, viewportHeight - 180);
  const desktopCardHeightBase = leftStackHeight > 0 ? leftStackHeight : desktopMaxCardHeight;
  const desktopCardHeight = Math.min(desktopCardHeightBase, desktopMaxCardHeight);
  const portsCardStyle = !isCompactLayout ? { height: desktopCardHeight } : undefined;
  const panelHeight = isCompactLayout ? compactPanelHeight : Math.max(380, desktopCardHeight - 80);
  const portsPanelStyle = { height: panelHeight };
  const tableScrollY = Math.max(280, panelHeight - 48);

  const highestSeverity = useMemo(
    () =>
      [...risks]
        .map((item) => item.severity)
        .sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b] - { critical: 4, high: 3, medium: 2, low: 1 }[a]))[0],
    [risks],
  );

  const sortedPorts = useMemo(
    () =>
      [...(asset?.ports || [])].sort((a, b) => {
        const portDelta = Number(a.port) - Number(b.port);
        if (portDelta !== 0) {
          return portDelta;
        }
        return String(a.protocol || "").localeCompare(String(b.protocol || ""));
      }),
    [asset?.ports],
  );

  const portColumns = useMemo(
    () => [
      {
        title: "端口",
        key: "port_summary",
        width: isCompactLayout ? 120 : 140,
        render: (_: unknown, record: Asset["ports"][number]) => (
          <div className="ui-cell-stack">
            <OverflowText value={`${record.port}/${record.protocol}`} block strong mono />
            <StatusTag value={record.state} />
          </div>
        ),
      },
      {
        title: "服务与版本",
        key: "service_summary",
        render: (_: unknown, record: Asset["ports"][number]) => {
          const payload = toRecord(record.fingerprint_json);
          const strategySkipped = Boolean(payload.nmap_skipped) || Boolean(payload.version_skipped);
          const skipReason = formatNmapSkipReason(payload.nmap_skip_reason) || "后门候选端口，已跳过版本探测";
          const serviceName = resolveServiceName(record);
          const serviceVersion = resolveServiceVersion(record);
          return (
            <div className="ui-cell-stack">
              <OverflowText value={serviceName} block strong />
              {!record.service_version && strategySkipped ? (
                <Tooltip title={skipReason}>
                  <Tag color="orange">策略跳过</Tag>
                </Tooltip>
              ) : serviceVersion ? (
                <OverflowText value={serviceVersion} block secondary />
              ) : null}
            </div>
          );
        },
      },
      {
        title: "NSE / 说明",
        key: "nse_summary",
        render: (_: unknown, record: Asset["ports"][number]) => {
          const payload = toRecord(record.fingerprint_json);
          const nseSummary = buildNseSummaryView(payload.nse_summary);
          const skippedReason = formatNmapSkipReason(payload.nmap_skip_reason);
          const nseMetaLine = buildNseMetaLine(payload);
          if (!nseSummary.requestedScripts.length) {
            if (Boolean(payload.nmap_skipped)) {
              return (
                <Tooltip title={skippedReason || "后门候选端口，已跳过 Nmap 脚本探测"}>
                  <Tag color="orange">策略跳过</Tag>
                </Tooltip>
              );
            }
            return <OverflowText value="未执行" block secondary tooltip={false} />;
          }
          const firstScript = nseSummary.hitScripts[0] || nseSummary.requestedScripts[0] || "无";
          const tooltipLines = [
            `请求脚本：${nseSummary.requestedScripts.join("、")}`,
            nseSummary.hitScripts.length ? `命中脚本：${nseSummary.hitScripts.join("、")}` : "命中脚本：无",
            ...nseSummary.summaryLines,
            nseMetaLine,
          ].filter(Boolean);
          return (
            <Tooltip title={tooltipLines.join("\n")}>
              <div className="ui-cell-stack">
                <div className="ui-chip-row">
                  <Tag color="blue">脚本 {nseSummary.requestedScripts.length}</Tag>
                  <Tag color={nseSummary.hitScripts.length ? "red" : "default"}>命中 {nseSummary.hitScripts.length}</Tag>
                </div>
                <OverflowText value={firstScript} block secondary />
              </div>
            </Tooltip>
          );
        },
      },
    ],
    [isCompactLayout],
  );

  const collectionMetrics = useMemo(() => {
    const portCount = sortedPorts.length;
    const identifiedServiceCount = sortedPorts.filter((item) => {
      const value = resolveServiceName(item).trim().toLowerCase();
      return value !== "" && value !== "无";
    }).length;
    const externalPortCount = sortedPorts.filter((item) => {
      const fingerprint = item.fingerprint_json;
      if (!fingerprint || typeof fingerprint !== "object") {
        return true;
      }
      const scope = String((fingerprint as Record<string, unknown>).scope || "").trim().toLowerCase();
      return scope !== "loopback";
    }).length;
    const backdoorCandidateCount = sortedPorts.filter((item) => {
      const fingerprint = item.fingerprint_json;
      return !!fingerprint && typeof fingerprint === "object" && Boolean((fingerprint as Record<string, unknown>).backdoor_candidate);
    }).length;
    const recognitionRate = portCount ? Math.round((identifiedServiceCount / portCount) * 100) : 0;
    const latestSummary = toRecord(latestCollection?.summary_json);
    return {
      status: latestCollection?.status || latestInitial?.status || asset?.status || "unknown",
      executedAt: latestCollection?.collected_at || latestInitial?.collected_at || null,
      commandSuccessRate: typeof latestSummary.command_success_rate === "number" ? latestSummary.command_success_rate : null,
      portCount,
      externalPortCount,
      identifiedServiceCount,
      unknownServiceCount: Math.max(0, portCount - identifiedServiceCount),
      backdoorCandidateCount,
      recognitionRate,
    };
  }, [
    sortedPorts,
    latestCollection?.status,
    latestCollection?.collected_at,
    latestCollection?.summary_json,
    latestInitial?.status,
    latestInitial?.collected_at,
    asset?.status,
  ]);

  const latestCollectionSummary = useMemo(() => toRecord(latestCollection?.summary_json), [latestCollection?.summary_json]);
  const latestCollectionDetail = useMemo(() => toRecord(latestCollection?.detail_json), [latestCollection?.detail_json]);
  const latestCollectionView = useMemo(() => {
    const verifiedAt = typeof latestCollectionSummary.verified_at === "string" ? latestCollectionSummary.verified_at : "";
    const packageCount =
      typeof latestCollectionSummary.package_count === "number"
        ? latestCollectionSummary.package_count
        : Number(latestCollectionSummary.package_count || 0) || 0;
    const dangerousSuidCount =
      typeof latestCollectionSummary.dangerous_suid_count === "number"
        ? latestCollectionSummary.dangerous_suid_count
        : Number(latestCollectionSummary.dangerous_suid_count || 0) || 0;
    const capabilityCount =
      typeof latestCollectionSummary.capability_count === "number"
        ? latestCollectionSummary.capability_count
        : Number(latestCollectionSummary.capability_count || 0) || 0;
    const sensitiveWorldWritableCount =
      typeof latestCollectionSummary.sensitive_world_writable_count === "number"
        ? latestCollectionSummary.sensitive_world_writable_count
        : Number(latestCollectionSummary.sensitive_world_writable_count || 0) || 0;
    const localPrivescExposureCount =
      typeof latestCollectionSummary.local_privesc_exposure_count === "number"
        ? latestCollectionSummary.local_privesc_exposure_count
        : Number(latestCollectionSummary.local_privesc_exposure_count || 0) || 0;
    const highRiskVersionExposureCount =
      typeof latestCollectionSummary.high_risk_version_exposure_count === "number"
        ? latestCollectionSummary.high_risk_version_exposure_count
        : Number(latestCollectionSummary.high_risk_version_exposure_count || 0) || 0;
    const writableExecChainCount =
      typeof latestCollectionSummary.writable_exec_chain_count === "number"
        ? latestCollectionSummary.writable_exec_chain_count
        : Number(latestCollectionSummary.writable_exec_chain_count || 0) || 0;
    const privilegedRuntimeExposureCount =
      typeof latestCollectionSummary.privileged_runtime_exposure_count === "number"
        ? latestCollectionSummary.privileged_runtime_exposure_count
        : Number(latestCollectionSummary.privileged_runtime_exposure_count || 0) || 0;
    return {
      loginUser: typeof latestCollectionSummary.login_user === "string" ? latestCollectionSummary.login_user : "未识别",
      privilege: typeof latestCollectionSummary.effective_privilege === "string" ? latestCollectionSummary.effective_privilege : "未识别",
      verifiedAt,
      kernel: typeof latestCollectionSummary.kernel === "string" ? latestCollectionSummary.kernel : "未识别",
      packageCount,
      sudoRiskSummary: typeof latestCollectionSummary.sudo_risk_summary === "string" ? latestCollectionSummary.sudo_risk_summary : "暂无",
      dangerousSuidCount,
      capabilityCount,
      sensitiveWorldWritableCount,
      localPrivescExposureCount,
      highRiskVersionExposureCount,
      writableExecChainCount,
      privilegedRuntimeExposureCount,
    };
  }, [latestCollectionSummary]);

  const credentialSubmitLoading = credentialSaving || credentialVerifyLoading;

  const assetOverviewItems = useMemo(() => {
    if (!asset) {
      return [];
    }
    const items = [
      { key: "1", label: "资产 ID", children: <span className="ui-detail-wrap mono-text">{asset.id}</span> },
      { key: "2", label: "本机标识", children: <span className="ui-detail-wrap">{buildLocalAssetLabel(asset)}</span> },
    ];

    const macVendor = compactDisplayParts(asset.mac_address, asset.vendor);
    if (macVendor) {
      items.push({ key: "3", label: "MAC / 厂商", children: <span className="ui-detail-wrap">{macVendor}</span> });
    }

    const zoneVlan = compactDisplayParts(asset.network_zone, asset.network_vlan);
    if (zoneVlan) {
      items.push({ key: "4", label: "分区 / VLAN", children: <span className="ui-detail-wrap">{zoneVlan}</span> });
    }

    const buildingDepartment = compactDisplayParts(asset.building, asset.department);
    if (buildingDepartment) {
      items.push({ key: "5", label: "楼宇 / 部门", children: <span className="ui-detail-wrap">{buildingDepartment}</span> });
    }

    const categoryRole = compactDisplayParts(formatAssetCategory(asset.asset_category), formatDeviceRole(asset.device_role));
    if (categoryRole) {
      items.push({ key: "6", label: "类别 / 角色", children: <span className="ui-detail-wrap">{categoryRole}</span> });
    }

    const identitySource = formatIdentitySource(asset.identity_source);
    if (identitySource) {
      items.push({ key: "7", label: "身份来源", children: <span className="ui-detail-wrap">{identitySource}</span> });
    }

    if (asset.last_auth_time) {
      items.push({
        key: "8",
        label: "最近认证时间",
        children: <span className="ui-detail-wrap">{new Date(asset.last_auth_time).toLocaleString()}</span>,
      });
    }

    items.push({
      key: "9",
      label: "首次发现",
      children: <span className="ui-detail-wrap">{new Date(asset.first_seen_at).toLocaleString()}</span>,
    });
    items.push({
      key: "10",
      label: "最近发现",
      children: <span className="ui-detail-wrap">{new Date(asset.last_seen_at).toLocaleString()}</span>,
    });
    return items;
  }, [asset]);

  const resetCredentialFlow = () => {
    setAuthorizationModalOpen(false);
    setSudoModalOpen(false);
    setPendingCredentialValues(null);
    setSudoPasswordDraft("");
    setSudoPasswordError(null);
  };

  const refreshCredentialVerification = async (options?: { preserveEditingOnFailure?: boolean }) => {
    if (!asset) {
      return null;
    }
    setCredentialVerifyLoading(true);
    setCredentialVerifyResult(null);
    try {
      const verifyResponse = await verifyAssetCredential(asset.id);
      setCredentialVerifyResult(verifyResponse);

      const latestCredentialMeta = await getAssetCredential(asset.id);
      setCredentialMeta(latestCredentialMeta);

      if (verifyResponse.status === "success") {
        setCredentialEditing(false);
        message.success(
          verifyResponse.effective_privilege === "root"
            ? "已验证 root 管理员凭据"
            : "已验证 sudo 管理员凭据",
        );
      } else if (options?.preserveEditingOnFailure) {
        setCredentialEditing(true);
        message.error(verifyResponse.summary || "管理员权限验证失败");
      } else {
        message.error(verifyResponse.summary || "管理员权限验证失败");
      }

      return verifyResponse;
    } finally {
      setCredentialVerifyLoading(false);
    }
  };

  const persistCredential = async (values: CredentialFormValues, sudoPassword?: string) => {
    if (!asset) {
      return;
    }

    const payload: AssetCredentialUpsertRequest = {
      auth_type: values.auth_type,
      username: values.username.trim(),
      admin_authorized: true,
    };
    if (values.auth_type === "password") {
      payload.password = (values.password || "").trim();
    } else {
      payload.private_key = values.private_key || "";
    }
    if (values.username.trim().toLowerCase() !== "root") {
      payload.sudo_password = (sudoPassword || "").trim();
    }

    setCredentialSaving(true);
    setCredentialVerifyResult(null);
    setSudoPasswordError(null);

    try {
      const response = await setAssetCredential(asset.id, payload);
      setCredentialMeta(response);

      const verifyResponse = await refreshCredentialVerification({ preserveEditingOnFailure: true });

      if (verifyResponse?.status === "success") {
        credentialForm.setFieldsValue({
          auth_type: response.auth_type || values.auth_type,
          username: response.username || values.username,
          password: "",
          private_key: "",
        });
        resetCredentialFlow();
        return;
      }

      resetCredentialFlow();
    } catch (err) {
      setCredentialEditing(true);
      resetCredentialFlow();
      message.error((err as Error).message);
    } finally {
      setCredentialSaving(false);
    }
  };

  const saveCredential = async () => {
    if (!asset) {
      return;
    }
    try {
      const values = await credentialForm.validateFields();
      setPendingCredentialValues({
        auth_type: values.auth_type,
        username: values.username.trim(),
        password: values.password,
        private_key: values.private_key,
      });
      setSudoPasswordDraft("");
      setSudoPasswordError(null);
      setAuthorizationModalOpen(true);
    } catch (err) {
      if ((err as { errorFields?: unknown }).errorFields) {
        return;
      }
      message.error((err as Error).message);
    }
  };

  const credentialReadyForCollection = Boolean(
    credentialMeta?.admin_authorized &&
      String(credentialMeta?.last_verification_status || "").trim().toLowerCase() === "success" &&
      ["root", "sudo"].includes(String(credentialMeta?.effective_privilege || "").trim().toLowerCase()),
  );

  const handleRunCollection = async () => {
    if (!asset) {
      return;
    }
    try {
      setActionLoading("collect");
      const res = await runAssetCollection(asset.id);
      setLastTaskId(res.task_id);
      message.success(`SSH 授权深度检查任务已提交：${res.task_id}`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setActionLoading(null);
    }
  };

  if (error) {
    return <Alert type="error" showIcon message={error} />;
  }

  if (!asset) {
    return <Empty description="未加载到资产详情" />;
  }

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="资产纵深"
        title={asset.ip}
        description={buildAssetHeaderDescription(asset)}
        meta={[
          { label: "资产状态", value: <StatusTag value={asset.status} />, tone: asset.status === "online" ? "success" : "warning" },
          { label: "最高风险", value: <StatusTag value={highestSeverity || null} />, tone: highestSeverity ? "danger" : "neutral" },
          { label: "开放端口", value: asset.ports.length, tone: "accent" },
          { label: "风险数", value: risks.length, tone: risks.length ? "danger" : "success" },
        ]}
        actions={(
          <Space wrap>
            {asset.is_local ? (
              <Tooltip title={asset.local_hint || "平台本机资产"}>
                <Tag color="magenta">本机资产</Tag>
              </Tooltip>
            ) : null}
            <Button
              loading={actionLoading === "verify"}
              disabled={actionLoading !== null}
              onClick={async () => {
                try {
                  setActionLoading("verify");
                  const res = await runRiskVerify(asset.id);
                  setLastTaskId(res.task_id);
                  message.success(`验证任务已提交：${res.task_id}`);
                } catch (err) {
                  message.error((err as Error).message);
                } finally {
                  setActionLoading(null);
                }
              }}
            >
              风险验证
            </Button>
          </Space>
        )}
      />

      {lastTaskId ? <Alert type="info" showIcon message={`最近任务：${lastTaskId}`} /> : null}

      <Row gutter={[14, 14]} align="stretch" className="asset-overview-ports-row">
        <Col xs={24} xl={9}>
          <div className="asset-left-stack" ref={leftStackRef}>
            <Card className="panel-card" title="资产概览">
              <Descriptions
                column={1}
                size="small"
                items={assetOverviewItems}
              />
              <div style={{ marginTop: 16 }}>
                <Typography.Text type="secondary">风险密度</Typography.Text>
                <Progress percent={Math.min(risks.length * 15, 100)} strokeColor="#ea580c" />
              </div>
            </Card>
            <Card className="panel-card" title="采集与识别状态">
              <Descriptions
                column={1}
                size="small"
                items={[
                  { key: "1", label: "当前状态", children: <StatusTag value={collectionMetrics.status} /> },
                  {
                    key: "2",
                    label: "最近采集",
                    children: collectionMetrics.executedAt ? new Date(collectionMetrics.executedAt).toLocaleString() : "暂无",
                  },
                  {
                    key: "3",
                    label: "命令成功率",
                    children: collectionMetrics.commandSuccessRate === null ? "暂无" : `${collectionMetrics.commandSuccessRate}%`,
                  },
                  { key: "4", label: "开放端口", children: `${collectionMetrics.externalPortCount} / ${collectionMetrics.portCount}` },
                  { key: "5", label: "已识别服务", children: `${collectionMetrics.identifiedServiceCount}（未识别 ${collectionMetrics.unknownServiceCount}）` },
                  { key: "6", label: "后门候选端口", children: collectionMetrics.backdoorCandidateCount },
                ]}
              />
              <div style={{ marginTop: 16 }}>
                <Typography.Text type="secondary">服务识别率</Typography.Text>
                <Progress percent={collectionMetrics.recognitionRate} strokeColor="#0f766e" />
              </div>
            </Card>
          </div>
        </Col>
        <Col xs={24} xl={15} className="asset-ports-col">
          <Card className="panel-card asset-ports-card" title="开放端口与服务" style={portsCardStyle}>
            <div className="ports-scroll-panel" style={portsPanelStyle}>
              <Table
                className="ports-service-table"
                rowKey="id"
                dataSource={sortedPorts}
                pagination={false}
                columns={portColumns}
                size="small"
                tableLayout="fixed"
                scroll={{ y: tableScrollY, scrollToFirstRowOnChange: false }}
              />
            </div>
          </Card>
        </Col>
      </Row>

      <Card className="panel-card" title="初步信息采集（网络侧）">
        {!latestInitial ? (
          <Empty description="暂无网络侧初步采集结果" />
        ) : (
          <Space direction="vertical" size={12} style={{ width: "100%" }}>
            <Space wrap>
              <StatusTag value={latestInitial.status} />
              <Typography.Text type="secondary">采集时间：{new Date(latestInitial.collected_at).toLocaleString()}</Typography.Text>
            </Space>
            <Descriptions
              column={1}
              size="small"
                items={[
                  { key: "1", label: "主机名", children: <span className="ui-detail-wrap">{displayOrNone((latestInitial.summary_json || {}).hostname)}</span> },
                  { key: "2", label: "系统猜测", children: <span className="ui-detail-wrap">{displayOrNone((latestInitial.summary_json || {}).os_guess)}</span> },
                  { key: "3", label: "用途猜测", children: <span className="ui-detail-wrap">{displayOrNone((latestInitial.summary_json || {}).role_guess)}</span> },
                  {
                    key: "4",
                    label: "关键观察",
                    children: (
                      <span className="ui-detail-wrap">
                        {Array.isArray((latestInitial.summary_json || {}).key_observations)
                          ? ((latestInitial.summary_json || {}).key_observations as string[]).join("；")
                          : "无"}
                      </span>
                    ),
                  },
                ]}
            />
          </Space>
        )}
      </Card>

      <Card
        className="panel-card"
        title="SSH 授权凭据"
        extra={(
          credentialMeta?.bound ? (
            <Button
              onClick={() => {
                setCredentialEditing((current) => {
                  const next = !current;
                  if (next) {
                    credentialForm.setFieldsValue({ password: "", private_key: "" });
                  }
                  return next;
                });
              }}
            >
              {credentialEditing ? "取消修改" : "重新设置凭据"}
            </Button>
          ) : null
        )}
      >
        <Space direction="vertical" style={{ width: "100%" }} size={16}>
          <Alert
            type={credentialMeta?.bound ? "success" : "warning"}
            showIcon
            message={
              credentialMeta?.bound
                ? `已绑定 SSH 授权凭据：${credentialMeta.username || "-"}（${credentialMeta.auth_type === "key" ? "私钥" : "密码"}）`
                : "当前资产未配置 SSH 授权凭据，请先保存管理员账户后再执行深度检查。"
            }
          />
          {credentialMeta?.bound ? (
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: "1", label: "授权确认", children: credentialMeta.admin_authorized ? "已确认" : "未确认" },
                { key: "2", label: "最近验证", children: credentialMeta.last_verified_at ? new Date(credentialMeta.last_verified_at).toLocaleString() : "暂无" },
                { key: "3", label: "验证状态", children: <StatusTag value={credentialMeta.last_verification_status || "pending"} /> },
                { key: "4", label: "权限级别", children: credentialMeta.effective_privilege || "未验证" },
              ]}
            />
          ) : null}
          {credentialVerifyResult ? (
            <Alert
              type={credentialVerifyResult.status === "success" ? "success" : "error"}
              showIcon
              message={credentialVerifyResult.summary}
            />
          ) : null}
          <Space wrap>
            {credentialMeta?.bound ? (
              <Button
                loading={credentialVerifyLoading}
                disabled={credentialSaving}
                onClick={() => void refreshCredentialVerification()}
              >
                重新验证管理员凭据
              </Button>
            ) : null}
            <Tooltip title={credentialReadyForCollection ? "使用已验证的管理员凭据执行主机级只读检查" : "请先保存并验证管理员凭据"}>
              <Button
                type="primary"
                loading={actionLoading === "collect"}
                disabled={actionLoading !== null || !credentialReadyForCollection}
                onClick={() => void handleRunCollection()}
              >
                执行 SSH 授权深度检查
              </Button>
            </Tooltip>
          </Space>

          {!credentialMeta?.bound || credentialEditing ? (
            <Form layout="vertical" form={credentialForm}>
              <Row gutter={[16, 0]}>
                <Col xs={24} md={8}>
                  <Form.Item name="auth_type" label="认证方式" rules={[{ required: true, message: "请选择认证方式" }]}>
                    <Select
                      options={[
                        { label: "用户名 + 密码", value: "password" },
                        { label: "用户名 + 私钥", value: "key" },
                      ]}
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} md={16}>
                  <Form.Item name="username" label="SSH 用户名" rules={[{ required: true, message: "请输入用户名" }]}>
                    <Input placeholder="请输入 root 或具备管理员权限的账户" />
                  </Form.Item>
                </Col>
              </Row>
              {credentialAuthType === "password" ? (
                <Form.Item name="password" label="SSH 密码" rules={[{ required: true, message: "请输入密码" }]}>
                  <Input.Password placeholder="输入该资产的 SSH 登录密码" autoComplete="new-password" />
                </Form.Item>
              ) : (
                <Form.Item name="private_key" label="SSH 私钥" rules={[{ required: true, message: "请输入 SSH 私钥内容" }]}>
                  <Input.TextArea rows={8} placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."} />
                </Form.Item>
              )}
              <Button type="primary" loading={credentialSubmitLoading} onClick={() => void saveCredential()}>
                保存并验证管理员凭据
              </Button>
            </Form>
          ) : (
            <Typography.Text type="secondary">
              凭据已保存并隐藏敏感内容。如需修改请点击“重新设置凭据”。
            </Typography.Text>
          )}
        </Space>
      </Card>

      <Modal
        title="管理员授权同意书"
        open={authorizationModalOpen}
        okText="我已确认并继续"
        cancelText="取消"
        confirmLoading={credentialSubmitLoading}
        closable={!credentialSubmitLoading}
        maskClosable={!credentialSubmitLoading}
        keyboard={!credentialSubmitLoading}
        onCancel={() => {
          if (!credentialSubmitLoading) {
            resetCredentialFlow();
          }
        }}
        onOk={() => {
          if (!pendingCredentialValues) {
            return;
          }
          if (pendingCredentialValues.username.trim().toLowerCase() === "root") {
            void persistCredential(pendingCredentialValues);
            return;
          }
          setAuthorizationModalOpen(false);
          setSudoPasswordError(null);
          setSudoModalOpen(true);
        }}
      >
        <Space direction="vertical" size={8}>
          <Typography.Text>请确认当前 SSH 账号已获得合法管理员授权，仅用于只读的 SSH 授权深度检查。</Typography.Text>
          <Typography.Text type="secondary">`root` 账号将直接执行保存与验证。</Typography.Text>
          <Typography.Text type="secondary">非 `root` 账号将在下一步补充 `sudo` 密码，用于确认具备管理员权限。</Typography.Text>
          <Typography.Text type="secondary">保存成功后，系统会立即执行一次轻量登录和权限确认。</Typography.Text>
        </Space>
      </Modal>

      <Modal
        title="填写 sudo 密码"
        open={sudoModalOpen}
        okText="保存并验证"
        cancelText="取消"
        confirmLoading={credentialSubmitLoading}
        closable={!credentialSubmitLoading}
        maskClosable={!credentialSubmitLoading}
        keyboard={!credentialSubmitLoading}
        onCancel={() => {
          if (!credentialSubmitLoading) {
            resetCredentialFlow();
          }
        }}
        onOk={() => {
          if (!pendingCredentialValues) {
            return;
          }
          const normalizedSudoPassword = sudoPasswordDraft.trim();
          if (!normalizedSudoPassword) {
            setSudoPasswordError("非 root 用户必须填写 sudo 密码");
            return;
          }
          void persistCredential(pendingCredentialValues, normalizedSudoPassword);
        }}
      >
        <Space direction="vertical" size={12} style={{ width: "100%" }}>
          <Typography.Text>检测到当前 SSH 用户不是 `root`，请填写该用户的 `sudo` 密码以验证管理员权限。</Typography.Text>
          <Input.Password
            value={sudoPasswordDraft}
            autoFocus
            autoComplete="new-password"
            placeholder="输入 sudo 密码后继续"
            status={sudoPasswordError ? "error" : undefined}
            onChange={(event) => {
              setSudoPasswordDraft(event.target.value);
              if (sudoPasswordError) {
                setSudoPasswordError(null);
              }
            }}
            onPressEnter={(event) => {
              event.preventDefault();
              if (credentialSubmitLoading || !pendingCredentialValues) {
                return;
              }
              const normalizedSudoPassword = sudoPasswordDraft.trim();
              if (!normalizedSudoPassword) {
                setSudoPasswordError("非 root 用户必须填写 sudo 密码");
                return;
              }
              void persistCredential(pendingCredentialValues, normalizedSudoPassword);
            }}
          />
          {sudoPasswordError ? <Alert type="error" showIcon message={sudoPasswordError} /> : null}
        </Space>
      </Modal>

      <Card className="panel-card" title="最近一次 SSH 授权深度检查">
        {!latestCollection ? (
          <Empty description="完成管理员凭据验证后，可执行 SSH 授权深度检查并查看结果。" />
        ) : (
          <Space direction="vertical" style={{ width: "100%" }} size={12}>
            <Space wrap>
              <StatusTag value={latestCollection.status} />
              <Typography.Text type="secondary">执行时间：{new Date(latestCollection.collected_at).toLocaleString()}</Typography.Text>
            </Space>
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: "1", label: "登录用户", children: latestCollectionView.loginUser },
                { key: "2", label: "当前权限级别", children: latestCollectionView.privilege },
                { key: "3", label: "最近授权验证", children: latestCollectionView.verifiedAt ? new Date(latestCollectionView.verifiedAt).toLocaleString() : "暂无" },
                { key: "4", label: "内核版本", children: latestCollectionView.kernel },
                { key: "5", label: "软件包数量", children: String(latestCollectionView.packageCount) },
                { key: "6", label: "sudo 风险摘要", children: latestCollectionView.sudoRiskSummary },
                { key: "7", label: "高风险 SUID/SGID", children: String(latestCollectionView.dangerousSuidCount) },
                { key: "8", label: "高风险 Capability", children: String(latestCollectionView.capabilityCount) },
                { key: "9", label: "敏感可写路径", children: String(latestCollectionView.sensitiveWorldWritableCount) },
                { key: "10", label: "本地提权暴露命中数", children: String(latestCollectionView.localPrivescExposureCount) },
                { key: "11", label: "高风险版本暴露数", children: String(latestCollectionView.highRiskVersionExposureCount) },
                { key: "12", label: "可写执行链命中数", children: String(latestCollectionView.writableExecChainCount) },
                { key: "13", label: "高权限运行时暴露数", children: String(latestCollectionView.privilegedRuntimeExposureCount) },
              ]}
            />
            {Object.keys(latestCollectionDetail).length ? (
              <CollapsibleJsonBlock title="完整深度检查结果（JSON）" value={latestCollectionDetail} />
            ) : null}
          </Space>
        )}
      </Card>

      <Card className="panel-card" title="风险发现">
        {risks.length ? (
          <List
            dataSource={risks}
            renderItem={(risk) => (
              <List.Item>
                <List.Item.Meta
                  title={(
                    <Space>
                      <StatusTag value={risk.severity} />
                      <StatusTag value={String(toRecord(risk.evidence_json).verification_status || "not_applicable")} />
                      {String(toRecord(risk.evidence_json).evidence_scope || "") === "authorized_local" ? (
                        <Tag color="magenta">主机级（经 SSH 授权）</Tag>
                      ) : null}
                      {risk.title}
                    </Space>
                  )}
                  description={(
                    (() => {
                      const evidence = toRecord(risk.evidence_json);
                      const nseScripts = toStringArray(evidence.nse_scripts);
                      const nseEvidence = toRecord(evidence.nse_evidence);
                      const activeDetector = getActiveDetectorLabel(evidence.active_detector);
                      return (
                        <Space direction="vertical" size={6} style={{ width: "100%" }}>
                          <Typography.Paragraph style={{ marginBottom: 8 }}>{risk.description}</Typography.Paragraph>
                          <Space size={[8, 8]} wrap>
                            <Typography.Text type="secondary">
                              匹配方式: <StatusTag value={String(evidence.match_source || "passive")} />
                            </Typography.Text>
                            {activeDetector ? (
                              <Typography.Text type="secondary">探测器: {activeDetector}</Typography.Text>
                            ) : null}
                            {evidence.port ? (
                              <Typography.Text type="secondary">端口: {String(evidence.port)}</Typography.Text>
                            ) : null}
                          </Space>
                          {evidence.verification_summary ? (
                            <Alert
                              type={String(evidence.verification_status || "") === "confirmed" ? "success" : "info"}
                              showIcon
                              message={String(evidence.verification_summary)}
                            />
                          ) : null}
                          {nseScripts.length ? (
                            <Space direction="vertical" size={4} style={{ width: "100%" }}>
                              <Typography.Text type="secondary">NSE 脚本：{nseScripts.join("、")}</Typography.Text>
                            </Space>
                          ) : null}
                          {Object.keys(nseEvidence).length ? <CollapsibleJsonBlock title="NSE 证据（JSON）" value={nseEvidence} /> : null}
                          {Object.keys(evidence).length ? <CollapsibleJsonBlock title="完整证据（JSON）" value={evidence} /> : null}
                          <Space wrap>
                            <Button size="small" onClick={() => router.push(`/remediation/${assetId}?findingId=${risk.id}`)}>
                              进入修复
                            </Button>
                          </Space>
                          <Typography.Text type="secondary">发现时间: {new Date(risk.detected_at).toLocaleString()}</Typography.Text>
                        </Space>
                      );
                    })()
                  )}
                />
              </List.Item>
            )}
          />
        ) : (
          <Empty description="当前资产暂无风险发现" />
        )}
      </Card>
    </Space>
  );
}
