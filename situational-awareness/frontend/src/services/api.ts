import { Asset, AssetBatchDeleteResponse, AssetListResponse } from "@/types/asset";
import {
  AgentGoal,
  AgentApprovalRequest,
  AgentApprovalResponse,
  AgentMessageCreateRequest,
  AgentSession,
  AgentSessionSummary,
  AgentUIStepRequest,
} from "@/types/agent";
import {
  AssetCredentialBatchResponse,
  AssetCredentialBatchUpsertRequest,
  AssetCredentialReadResponse,
  AssetCredentialUpsertRequest,
  AssetCredentialVerifyResponse,
  AssetLatestCollectionResponse,
  AssetLatestInitialResponse,
  AssetLatestProbeResponse,
  AssetProbeResponse,
  ProbePreset,
} from "@/types/collection";
import { DiscoveryJobCreateResponse, DiscoveryJobListResponse, DiscoverySchedulingOption } from "@/types/discovery";
import { clearStoredToken, getStoredRefreshToken, getStoredToken, setStoredAuthTokens } from "@/lib/auth";
import { DashboardOverview } from "@/types/dashboard";
import { ExportDataType, ExportFileFormat, ServerImportResponse } from "@/types/data-exchange";
import { PlatformLogListResponse, PlatformLogLevel, PlatformLogServiceName, PlatformLogSourceKind } from "@/types/logs";
import { MobileOverview } from "@/types/mobile";
import { PlatformLiveMetrics } from "@/types/monitoring";
import { BootstrapStatusResponse, LogoutResponse, TokenResponse, UserRead } from "@/types/auth";
import {
  FindingGovernance,
  FindingWaiver,
  RiskBatchVerifyResponse,
  RiskFindingAssignRequest,
  RiskFindingListResponse,
  RiskFindingPageResponse,
  RiskFindingWaiverCreateRequest,
  RiskRemediationTemplate,
} from "@/types/risk";
import {
  HostRunner,
  HostRunnerInstallResponse,
  RemediationAssetDetail,
  RemediationAssetList,
  RemediationExecuteRequest,
  RemediationExecuteResponse,
  RemediationPlan,
  RemediationSession,
  RemediationSessionApproveResponse,
  RemediationSessionApproveRequest,
  RemediationSessionCreateRequest,
  RemediationSessionMessageCreateRequest,
  RemediationTask,
  RemediationTaskEvidence,
  RemediationWorkspace,
  TerminalTicket,
} from "@/types/remediation";
import {
  TaskEventListResponse,
  TaskLogLevel,
  TaskRunClearResponse,
  TaskRunDetail,
  TaskRunListResponse,
  TaskRunResponse,
  TaskStatus,
  TaskType,
} from "@/types/task";
import {
  PlatformAIModelListInput,
  PlatformAIModelListResult,
  PlatformAIValidateInput,
  PlatformAIValidateResult,
  PlatformSettings,
  PlatformSettingsInput,
  SettingsApplyResponse,
} from "@/types/settings";
import {
  CampusDataSource,
  CampusDataSourceTestResult,
  CampusDataSourceWrite,
  DiscoveryJobExecutionListResponse,
  ScannerNodeAssignment,
  ScannerNodeAssignmentWrite,
  ScannerZone,
  ScannerZoneListResponse,
  ScannerZoneWrite,
} from "@/types/campus";
import {
  VulnIntelStatus,
  VulnLibraryStatus,
  VulnRule,
  VulnRuleBatchStatusResponse,
  VulnRuleCatalogView,
  VulnRuleExportFormat,
  VulnRuleFileFormat,
  VulnRuleImportMode,
  VulnRuleImportResponse,
  VulnRuleIndexRebuildResponse,
  VulnRuleInput,
  VulnRuleListResponse,
} from "@/types/vuln-library";
import { GenerateReportResponse, Report } from "@/types/report";

const API_BASE = (process.env.NEXT_PUBLIC_API_BASE || "/api/v1").replace(/\/$/, "");
const REQUEST_ERROR_MESSAGE = "前端无法连接 API 代理或后端未启动，请检查服务状态后重试";

class ApiRequestError extends Error {}

type ApiFetchOptions = {
  preferBackendDetail?: boolean;
  skipAuthRefresh?: boolean;
};

function buildPlatformHeaders(): Record<string, string> {
  if (typeof window === "undefined") {
    return {};
  }

  const headers: Record<string, string> = {};
  const host = window.location.host || "";
  const origin = window.location.origin || "";
  if (host) {
    headers["X-Platform-Host"] = host;
  }
  if (origin) {
    headers["X-Platform-Origin"] = origin;
  }
  return headers;
}

function extractErrorDetail(raw: string): string {
  if (!raw) {
    return "";
  }
  try {
    const parsed = JSON.parse(raw) as { detail?: unknown; message?: unknown; error?: unknown };
    if (typeof parsed.detail === "string") {
      return parsed.detail;
    }
    if (parsed.detail && typeof parsed.detail === "object" && "message" in parsed.detail) {
      const detailMessage = (parsed.detail as { message?: unknown }).message;
      if (typeof detailMessage === "string") {
        return detailMessage;
      }
    }
    if (Array.isArray(parsed.detail)) {
      const messages = parsed.detail
        .map((item) => (item && typeof item === "object" && "msg" in item ? String((item as { msg?: string }).msg || "") : ""))
        .filter(Boolean);
      if (messages.length) {
        return messages.join("；");
      }
    }
    if (typeof parsed.message === "string") {
      return parsed.message;
    }
    if (parsed.error && typeof parsed.error === "object" && "message" in parsed.error) {
      const errorMessage = (parsed.error as { message?: unknown }).message;
      if (typeof errorMessage === "string") {
        return errorMessage;
      }
    }
  } catch {
    return raw;
  }
  return raw;
}

function shouldPreferBackendDetail(status: number, detail: string): boolean {
  const normalized = detail.trim();
  if (!normalized) {
    return false;
  }
  if (status === 400 || status === 404 || status === 409 || status === 502) {
    return true;
  }
  return /[\u4e00-\u9fff]/.test(normalized);
}

function mapErrorMessage(status: number, detail: string): string {
  const detailLower = detail.toLowerCase();

  if (detail.includes("Incorrect username or password")) {
    return "用户名或密码错误";
  }
  if (detail.includes("Bootstrap already completed")) {
    return "系统已完成初始化，请直接登录";
  }
  if (detail.includes("Invalid authentication token")) {
    return "登录状态已失效，请重新登录";
  }
  if (detail.includes("User not found or disabled")) {
    return "当前账号不可用，请联系管理员";
  }
  if (detail.includes("Disallowed CORS origin")) {
    return "跨域访问被拒绝，请检查前端访问地址与后端 CORS 配置";
  }
  if (detail.includes("Admin role required")) {
    return "仅管理员可执行该操作";
  }
  if (detail.includes("set manual ssh credential first")) {
    return "请先在资产详情中设置 SSH 凭据";
  }
  if (detailLower.includes("asset not found")) {
    return "资产不存在";
  }
  if (detailLower.startsWith("assets not found:")) {
    return `以下资产不存在：${detail.split(":").slice(1).join(":").trim()}`;
  }
  if (detailLower.includes("task not found")) {
    return "任务不存在";
  }
  if (detail.includes("任务当前状态不支持中断") || detailLower.includes("task cannot be canceled")) {
    return "当前任务状态不支持中断";
  }
  if (detail.includes("任务中断请求下发失败")) {
    return detail;
  }
  if (detail.includes("任务清理前中断失败")) {
    return detail;
  }
  if (detailLower.includes("job not found")) {
    return "发现任务不存在";
  }
  if (detailLower.includes("report not found")) {
    return "报告不存在";
  }
  if (detailLower === "rule not found" || detailLower.startsWith("rule not found:")) {
    const ruleId = detail.split(":").slice(1).join(":").trim();
    return ruleId ? `规则不存在：${ruleId}` : "规则不存在";
  }
  if (detailLower.startsWith("rule already exists:")) {
    return `规则已存在：${detail.split(":").slice(1).join(":").trim()}`;
  }
  if (detailLower.startsWith("duplicate rule id:")) {
    return `规则 ID 重复：${detail.split(":").slice(1).join(":").trim()}`;
  }
  if (detailLower.includes("no probe snapshot found")) {
    return "暂无基础探测结果";
  }
  if (detail.includes("保存 SSH 凭据前必须确认已获得管理员授权")) {
    return detail;
  }
  if (detail.includes("非 root 用户必须填写 sudo 密码")) {
    return detail;
  }
  if (detail.includes("当前 SSH 凭据尚未确认管理员授权")) {
    return detail;
  }
  if (detail.includes("当前 SSH 凭据尚未完成管理员权限验证")) {
    return detail;
  }
  if (detail.includes("当前 SSH 凭据未验证到管理员权限")) {
    return detail;
  }
  if (detail.includes("暂无 SSH 授权深度检查结果")) {
    return detail;
  }
  if (detail.includes("暂无授权验证结果")) {
    return detail;
  }
  if (detailLower.includes("no credential configured")) {
    return "未配置可用凭据";
  }
  if (detailLower.includes("credential payload is incomplete")) {
    return "凭据内容不完整，请重新保存";
  }
  if (detailLower.includes("credential password is empty")) {
    return "凭据中的密码为空，请重新保存";
  }
  if (detailLower.includes("credential private key is empty")) {
    return "凭据中的私钥为空，请重新保存";
  }
  if (detailLower.includes("password is required when auth_type=password")) {
    return "认证方式为密码时必须填写密码";
  }
  if (detailLower.includes("private_key is required when auth_type=key")) {
    return "认证方式为私钥时必须填写私钥";
  }
  if (detail.includes("请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配")) {
    return detail;
  }
  if (detail.includes("请至少填写版本匹配、配置匹配或 Nmap 脚本匹配")) {
    return "请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配";
  }
  if (detailLower.includes("match.version or match.config is required")) {
    return "请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配";
  }
  if (
    detailLower.includes("match.version or match.config or match.nse is required") ||
    detailLower.includes("match.version or match.config or match.nse or match.package is required") ||
    detail.includes("match.version、match.config 或 match.nse") ||
    detail.includes("match.version、match.config、match.nse 或 match.package")
  ) {
    return "请至少填写版本匹配、配置匹配、Nmap 脚本匹配或软件包匹配";
  }
  if (detail.includes("NSE 匹配必须是对象结构") || detailLower.includes("nse match must be an object")) {
    return "Nmap 脚本匹配必须是 JSON 对象";
  }
  if (detail.includes("软件包匹配必须是对象结构") || detailLower.includes("package match must be an object")) {
    return "软件包匹配必须是 JSON 对象";
  }
  if (detailLower.includes("unsupported export format")) {
    return "导出格式不受支持，请选择 YAML 或 JSON";
  }
  if (detailLower.includes("unsupported import mode")) {
    return "导入模式不受支持";
  }
  if (detailLower.includes("unsupported credential auth type")) {
    return "不支持的凭据认证方式";
  }
  if (detailLower.includes("each rule must be a mapping")) {
    return "导入文件中的每条规则都必须是对象结构";
  }
  if (detailLower.includes("invalid severity for rule")) {
    return "规则严重级别无效";
  }
  if (detailLower.includes("invalid version constraint for rule")) {
    return "版本匹配条件无效";
  }
  if (detailLower.includes("unsupported config operators for rule")) {
    return "配置匹配中存在不受支持的操作符";
  }
  if (detailLower.includes("unsupported nse operators for rule")) {
    return "Nmap 脚本匹配中存在不受支持的操作符";
  }
  if (detailLower.includes("unsupported active_check.detector")) {
    return "主动探测器类型不受支持";
  }
  if (detailLower.includes("unsupported active_check.trigger")) {
    return "主动探测触发方式不受支持";
  }
  if (detail.includes("PDF 导出依赖未安装")) {
    return detail;
  }
  if (detailLower.includes("invalid private key")) {
    return "私钥格式无效，请检查后重试";
  }
  if (detailLower.includes("permission denied")) {
    return "权限被拒绝，请检查账号权限";
  }
  if (detailLower.includes("authentication failed")) {
    return "认证失败，请检查账号、密码或私钥";
  }
  if (detailLower.includes("timed out")) {
    return "请求超时，请稍后重试";
  }
  if (detailLower.includes("connection refused")) {
    return "连接被拒绝，请确认目标服务是否已启动";
  }
  if (detail.includes("当前未配置 ENCRYPTION_KEY")) {
    return detail;
  }
  if (detail.includes("关闭全量跨域时必须填写允许的来源列表")) {
    return detail;
  }
  if (detail.includes("设置应用执行器")) {
    return detail;
  }
  if (status === 400) {
    return "请求参数错误，请检查输入后重试";
  }
  if (status === 401) {
    return "认证失败，请重新登录";
  }
  if (status === 403) {
    return "无权限执行该操作";
  }
  if (status === 404) {
    return "请求资源不存在";
  }
  if (status === 409) {
    return "存在冲突请求，系统已处理，请刷新后查看最新状态";
  }
  if (status === 422) {
    return detail || "请求参数校验失败，请检查输入格式";
  }
  if (status >= 500) {
    return "后端服务异常，请稍后重试";
  }
  return "请求失败，请稍后重试";
}

let refreshPromise: Promise<string> | null = null;

function shouldAttemptAuthRefresh(path: string, options?: ApiFetchOptions): boolean {
  if (options?.skipAuthRefresh || !getStoredRefreshToken()) {
    return false;
  }
  return !(
    path.startsWith("/auth/login") ||
    path.startsWith("/auth/bootstrap-admin") ||
    path.startsWith("/auth/bootstrap-status") ||
    path.startsWith("/auth/refresh") ||
    path.startsWith("/auth/logout")
  );
}

async function performApiFetch(path: string, init: RequestInit | undefined, token: string, withJsonContentType: boolean): Promise<Response> {
  const isFormData = typeof FormData !== "undefined" && init?.body instanceof FormData;
  return fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      ...(withJsonContentType && !isFormData ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...buildPlatformHeaders(),
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
}

async function refreshAccessToken(): Promise<string> {
  const refreshToken = getStoredRefreshToken();
  if (!refreshToken) {
    throw new ApiRequestError("认证失败，请重新登录");
  }
  if (!refreshPromise) {
    refreshPromise = (async () => {
      const response = await performApiFetch(
        "/auth/refresh",
        {
          method: "POST",
          body: JSON.stringify({ refresh_token: refreshToken }),
        },
        "",
        true,
      );
      if (!response.ok) {
        const raw = await response.text();
        const detail = extractErrorDetail(raw);
        clearStoredToken();
        throw new ApiRequestError(mapErrorMessage(response.status, detail));
      }
      const payload = (await response.json()) as TokenResponse;
      setStoredAuthTokens(payload);
      return payload.access_token;
    })().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

export async function apiFetch<T>(path: string, init?: RequestInit, options?: ApiFetchOptions): Promise<T> {
  try {
    const token = getStoredToken() || process.env.NEXT_PUBLIC_TOKEN || "";
    let response = await performApiFetch(path, init, token, true);

    if (response.status === 401 && shouldAttemptAuthRefresh(path, options)) {
      try {
        const refreshedToken = await refreshAccessToken();
        response = await performApiFetch(path, init, refreshedToken, true);
      } catch (error) {
        if (error instanceof ApiRequestError) {
          throw error;
        }
        clearStoredToken();
        throw new ApiRequestError("认证失败，请重新登录");
      }
    }

    if (!response.ok) {
      const raw = await response.text();
      const detail = extractErrorDetail(raw);
      const errorMessage =
        options?.preferBackendDetail && shouldPreferBackendDetail(response.status, detail)
          ? detail
          : mapErrorMessage(response.status, detail);
      if (response.status === 401) {
        clearStoredToken();
      }
      throw new ApiRequestError(errorMessage);
    }

    if (response.status === 204) {
      return undefined as T;
    }
    const contentLength = response.headers.get("content-length");
    if (contentLength === "0") {
      return undefined as T;
    }

    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiRequestError) {
      throw error;
    }
    throw new Error(REQUEST_ERROR_MESSAGE);
  }
}

async function apiFetchBlob(path: string, init?: RequestInit): Promise<{ blob: Blob; filename: string | null }> {
  try {
    const token = getStoredToken() || process.env.NEXT_PUBLIC_TOKEN || "";
    let response = await performApiFetch(path, init, token, false);
    if (response.status === 401 && shouldAttemptAuthRefresh(path)) {
      try {
        const refreshedToken = await refreshAccessToken();
        response = await performApiFetch(path, init, refreshedToken, false);
      } catch (error) {
        if (error instanceof ApiRequestError) {
          throw error;
        }
        clearStoredToken();
        throw new ApiRequestError("认证失败，请重新登录");
      }
    }
    if (!response.ok) {
      const raw = await response.text();
      const detail = extractErrorDetail(raw);
      throw new ApiRequestError(mapErrorMessage(response.status, detail));
    }
    const disposition = response.headers.get("content-disposition") || "";
    const match = disposition.match(/filename="?([^"]+)"?/i);
    return {
      blob: await response.blob(),
      filename: match?.[1] || null,
    };
  } catch (error) {
    if (error instanceof ApiRequestError) {
      throw error;
    }
    throw new Error(REQUEST_ERROR_MESSAGE);
  }
}

export function login(payload: { username: string; password: string }) {
  return apiFetch<TokenResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  }, { skipAuthRefresh: true });
}

export function getBootstrapStatus() {
  return apiFetch<BootstrapStatusResponse>("/auth/bootstrap-status");
}

export function bootstrapAdmin(payload: { username: string; email: string; password: string }) {
  return apiFetch<TokenResponse>("/auth/bootstrap-admin", {
    method: "POST",
    body: JSON.stringify(payload),
  }, { skipAuthRefresh: true });
}

export function getCurrentUser() {
  return apiFetch<UserRead>("/auth/me");
}

export function logoutCurrentSession() {
  return apiFetch<LogoutResponse>("/auth/logout", {
    method: "POST",
    body: JSON.stringify({ refresh_token: getStoredRefreshToken() || null }),
  }, { skipAuthRefresh: true });
}

export function listAssets(params?: {
  page?: number;
  pageSize?: number;
  keyword?: string;
  status?: "online" | "offline" | "collecting" | "unknown" | "all";
  networkZone?: string;
  assetCategory?: string;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 100),
  });
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  if (params?.status && params.status !== "all") {
    query.set("status", params.status);
  }
  if (params?.networkZone) {
    query.set("network_zone", params.networkZone);
  }
  if (params?.assetCategory) {
    query.set("asset_category", params.assetCategory);
  }
  return apiFetch<AssetListResponse>(`/assets?${query.toString()}`);
}

export function getAsset(assetId: string) {
  return apiFetch<Asset>(`/assets/${assetId}`);
}

export function updateAsset(assetId: string, payload: { tag_ids?: string[] | null }) {
  return apiFetch<Asset>(`/assets/${assetId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function deleteAsset(assetId: string) {
  return apiFetch<void>(`/assets/${assetId}`, {
    method: "DELETE",
  });
}

export function deleteAssetsBatch(assetIds: string[]) {
  return apiFetch<AssetBatchDeleteResponse>("/assets/batch/delete", {
    method: "POST",
    body: JSON.stringify({ asset_ids: assetIds }),
  });
}

export function listAssetRisks(assetId: string) {
  return apiFetch<RiskFindingListResponse>(`/risks/assets/${assetId}`);
}

export function listGlobalRisks(params?: {
  page?: number;
  pageSize?: number;
  severity?: "low" | "medium" | "high" | "critical" | "all";
  status?: "open" | "ignored" | "fixed" | "all";
  keyword?: string;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 50),
  });
  if (params?.severity && params.severity !== "all") {
    query.set("severity", params.severity);
  }
  if (params?.status && params.status !== "all") {
    query.set("status", params.status);
  }
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  return apiFetch<RiskFindingPageResponse>(`/risks?${query.toString()}`);
}

export function assignRiskFinding(findingId: string, payload: RiskFindingAssignRequest = {}) {
  return apiFetch<FindingGovernance>(`/risks/${findingId}/assign`, {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function createRiskWaiver(findingId: string, payload: RiskFindingWaiverCreateRequest) {
  return apiFetch<FindingWaiver>(`/risks/${findingId}/waivers`, {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function recalculateRiskPriority(findingId: string) {
  return apiFetch<FindingGovernance>(`/risks/${findingId}/recalculate-priority`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function getDashboardOverview() {
  return apiFetch<DashboardOverview>("/dashboard/overview");
}

export function getMobileOverview() {
  return apiFetch<MobileOverview>("/mobile/overview");
}

export function getPlatformLiveMetrics() {
  return apiFetch<PlatformLiveMetrics>("/monitoring/platform/live");
}

export function listPlatformLogs(params?: {
  page?: number;
  pageSize?: number;
  sourceKind?: PlatformLogSourceKind | "all";
  serviceName?: PlatformLogServiceName | "all";
  level?: PlatformLogLevel | "all";
  keyword?: string;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 50),
  });
  if (params?.sourceKind && params.sourceKind !== "all") {
    query.set("source_kind", params.sourceKind);
  }
  if (params?.serviceName && params.serviceName !== "all") {
    query.set("service_name", params.serviceName);
  }
  if (params?.level && params.level !== "all") {
    query.set("level", params.level);
  }
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  return apiFetch<PlatformLogListResponse>(`/logs?${query.toString()}`);
}

export function createDiscoveryJob(payload: { cidr: string; label?: string; runner_asset_id?: string; scanner_zone_id?: string }) {
  return apiFetch<DiscoveryJobCreateResponse>("/discovery/jobs", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getDiscoverySchedulingOptions(cidr?: string) {
  const query = new URLSearchParams();
  if (cidr?.trim()) {
    query.set("cidr", cidr.trim());
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return apiFetch<DiscoverySchedulingOption>(`/discovery/options${suffix}`);
}

export function importServersCsv(file: File) {
  const formData = new FormData();
  formData.append("file", file);
  return apiFetch<ServerImportResponse>("/data-exchange/servers/import", {
    method: "POST",
    body: formData,
  }, { preferBackendDetail: true });
}

export function downloadServerImportTemplate() {
  return apiFetchBlob("/data-exchange/servers/template");
}

export function exportDataSet(dataType: ExportDataType, format: ExportFileFormat) {
  const query = new URLSearchParams({ format });
  return apiFetchBlob(`/data-exchange/export/${dataType}?${query.toString()}`);
}

export function listScannerZones(params?: { page?: number; pageSize?: number }) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 50),
  });
  return apiFetch<ScannerZoneListResponse>(`/campus/zones?${query.toString()}`);
}

export function createScannerZone(payload: ScannerZoneWrite) {
  return apiFetch<ScannerZone>("/campus/zones", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateScannerZone(zoneId: string, payload: ScannerZoneWrite) {
  return apiFetch<ScannerZone>(`/campus/zones/${zoneId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function listZoneNodes(zoneId: string) {
  return apiFetch<ScannerNodeAssignment[]>(`/campus/zones/${zoneId}/nodes`);
}

export function createZoneNode(zoneId: string, payload: ScannerNodeAssignmentWrite) {
  return apiFetch<ScannerNodeAssignment>(`/campus/zones/${zoneId}/nodes`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function listCampusDataSources(zoneId?: string) {
  const query = new URLSearchParams();
  if (zoneId) {
    query.set("zone_id", zoneId);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return apiFetch<CampusDataSource[]>(`/campus/data-sources${suffix}`);
}

export function createCampusDataSource(payload: CampusDataSourceWrite) {
  return apiFetch<CampusDataSource>("/campus/data-sources", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateCampusDataSource(sourceId: string, payload: CampusDataSourceWrite) {
  return apiFetch<CampusDataSource>(`/campus/data-sources/${sourceId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export function testCampusDataSource(sourceId: string) {
  return apiFetch<CampusDataSourceTestResult>(`/campus/data-sources/${sourceId}/test`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function collectCampusDataSource(sourceId: string) {
  return apiFetch<CampusDataSourceTestResult>(`/campus/data-sources/${sourceId}/collect`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function listDiscoveryJobExecutions(jobId: string, params?: { page?: number; pageSize?: number }) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 100),
  });
  return apiFetch<DiscoveryJobExecutionListResponse>(`/campus/discovery-jobs/${jobId}/executions?${query.toString()}`);
}

export function listDiscoveryJobs(params?: { page?: number; pageSize?: number }) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 20),
  });
  return apiFetch<DiscoveryJobListResponse>(`/discovery/jobs?${query.toString()}`);
}

export function listTasks(params?: { page?: number; pageSize?: number; taskType?: TaskType | "all"; status?: TaskStatus | "all" }) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 100),
  });
  if (params?.taskType && params.taskType !== "all") {
    query.set("task_type", params.taskType);
  }
  if (params?.status && params.status !== "all") {
    query.set("status", params.status);
  }
  return apiFetch<TaskRunListResponse>(`/tasks?${query.toString()}`);
}

export function getTask(taskId: string) {
  return apiFetch<TaskRunDetail>(`/tasks/${taskId}`);
}

export function cancelTask(taskId: string) {
  return apiFetch<TaskRunResponse>(`/tasks/${taskId}/cancel`, {
    method: "POST",
  });
}

export function listTaskEvents(params?: {
  page?: number;
  pageSize?: number;
  taskType?: TaskType | "all";
  status?: TaskStatus | "all";
  level?: TaskLogLevel | "all";
  taskId?: string;
  keyword?: string;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 100),
  });
  if (params?.taskType && params.taskType !== "all") {
    query.set("task_type", params.taskType);
  }
  if (params?.status && params.status !== "all") {
    query.set("status", params.status);
  }
  if (params?.level && params.level !== "all") {
    query.set("level", params.level);
  }
  if (params?.taskId) {
    query.set("task_id", params.taskId);
  }
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  return apiFetch<TaskEventListResponse>(`/tasks/events?${query.toString()}`);
}

export function getTaskEvents(taskId: string, params?: { page?: number; pageSize?: number; level?: TaskLogLevel | "all" }) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 200),
  });
  if (params?.level && params.level !== "all") {
    query.set("level", params.level);
  }
  return apiFetch<TaskEventListResponse>(`/tasks/${taskId}/events?${query.toString()}`);
}

export function clearTasks(params?: { taskType?: TaskType | "all"; status?: TaskStatus | "all"; includeActive?: boolean }) {
  const query = new URLSearchParams();
  if (params?.taskType && params.taskType !== "all") {
    query.set("task_type", params.taskType);
  }
  if (params?.status && params.status !== "all") {
    query.set("status", params.status);
  }
  if (params?.includeActive) {
    query.set("include_active", "true");
  }
  const path = query.toString() ? `/tasks?${query.toString()}` : "/tasks";
  return apiFetch<TaskRunClearResponse>(path, {
    method: "DELETE",
  });
}

export function runAssetCollection(assetId: string) {
  return apiFetch<TaskRunResponse>(`/collection/assets/${assetId}/run`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function getAssetCredential(assetId: string) {
  return apiFetch<AssetCredentialReadResponse>(`/collection/assets/${assetId}/credential`);
}

export function setAssetCredential(assetId: string, payload: AssetCredentialUpsertRequest) {
  return apiFetch<AssetCredentialReadResponse>(`/collection/assets/${assetId}/credential`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function verifyAssetCredential(assetId: string) {
  return apiFetch<AssetCredentialVerifyResponse>(`/collection/assets/${assetId}/credential/verify`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function setAssetCredentialBatch(payload: AssetCredentialBatchUpsertRequest) {
  return apiFetch<AssetCredentialBatchResponse>("/collection/assets/credentials/batch", {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function runAssetProbe(
  assetId: string,
  payload?: { preset?: ProbePreset; credential_id?: string; connect_timeout_seconds?: number; command_timeout_seconds?: number },
) {
  return apiFetch<AssetProbeResponse>(`/collection/assets/${assetId}/probe`, {
    method: "POST",
    body: JSON.stringify(payload || {}),
  });
}

export function getLatestAssetProbe(assetId: string) {
  return apiFetch<AssetLatestProbeResponse>(`/collection/assets/${assetId}/probe/latest`);
}

export function getLatestAssetInitial(assetId: string) {
  return apiFetch<AssetLatestInitialResponse>(`/collection/assets/${assetId}/initial/latest`);
}

export function getLatestAssetCollection(assetId: string) {
  return apiFetch<AssetLatestCollectionResponse>(`/collection/assets/${assetId}/latest`);
}

export function generateAssetReport(assetId: string) {
  return apiFetch<GenerateReportResponse>(`/reports/assets/${assetId}/generate`, {
    method: "POST",
  });
}

export function getLatestAssetReport(assetId: string) {
  return apiFetch<Report>(`/reports/assets/${assetId}/latest`);
}

export function getLatestJobReport(jobId: string) {
  return apiFetch<Report>(`/reports/jobs/${jobId}/latest`);
}

export function fetchReportHtml(reportId: string) {
  return apiFetchBlob(`/reports/${reportId}/download/html`);
}

export function fetchReportPdf(reportId: string) {
  return apiFetchBlob(`/reports/${reportId}/download/pdf`);
}

export function runAssetCollectionBatch(payload: {
  asset_ids: string[];
  concurrency?: number;
  credential_id?: string;
  connect_timeout_seconds?: number;
  command_timeout_seconds?: number;
  asset_timeout_seconds?: number;
}) {
  return apiFetch<TaskRunResponse>("/collection/assets/batch/run", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function runRiskVerify(assetId: string) {
  return apiFetch<TaskRunResponse>(`/risks/assets/${assetId}/verify`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function getRiskRemediationTemplate(findingId: string) {
  return apiFetch<RiskRemediationTemplate>(`/risks/${findingId}/remediation-template`);
}

export function getPlatformSettings() {
  return apiFetch<PlatformSettings>("/settings");
}

const AGENT_API_PREFIX = "/agent/xuanwu";

export function getHaorSession() {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session`, undefined, { preferBackendDetail: true });
}

export function getHaorSessionSummary() {
  return apiFetch<AgentSessionSummary>(`${AGENT_API_PREFIX}/summary`, undefined, { preferBackendDetail: true });
}

export function getHaorGoals(limit = 12) {
  return apiFetch<AgentGoal[]>(`${AGENT_API_PREFIX}/goals?limit=${encodeURIComponent(String(limit))}`, undefined, { preferBackendDetail: true });
}

export function getHaorGoal(goalId: string) {
  return apiFetch<AgentGoal>(`${AGENT_API_PREFIX}/goals/${encodeURIComponent(goalId)}`, undefined, { preferBackendDetail: true });
}

export function resumeHaorGoal(goalId: string) {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/goals/${encodeURIComponent(goalId)}/resume`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function cancelHaorGoal(goalId: string) {
  return apiFetch<AgentGoal>(`${AGENT_API_PREFIX}/goals/${encodeURIComponent(goalId)}/cancel`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function buildHaorSessionStreamUrl(token: string) {
  if (API_BASE.startsWith("http://") || API_BASE.startsWith("https://")) {
    const parsed = new URL(API_BASE);
    const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    const streamPath = `${parsed.pathname.replace(/\/$/, "")}${AGENT_API_PREFIX}/session/stream`;
    return `${protocol}//${parsed.host}${streamPath}?token=${encodeURIComponent(token)}`;
  }
  const streamPath = `${API_BASE}${AGENT_API_PREFIX}/session/stream`;
  const protocol = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss" : "ws";
  const host = typeof window !== "undefined" ? window.location.host : "localhost";
  return `${protocol}://${host}${streamPath}?token=${encodeURIComponent(token)}`;
}

export function resetHaorSession() {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session/reset`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function recoverHaorSession() {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session/recover`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function postHaorMessage(payload: AgentMessageCreateRequest) {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session/messages`, {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function postHaorStep(payload: AgentUIStepRequest) {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session/steps`, {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function approveHaorSession(payload: AgentApprovalRequest = {}) {
  return apiFetch<AgentApprovalResponse>(`${AGENT_API_PREFIX}/session/approve`, {
    method: "POST",
    body: JSON.stringify(payload),
  }, { preferBackendDetail: true });
}

export function interruptHaorSession() {
  return apiFetch<AgentSession>(`${AGENT_API_PREFIX}/session/interrupt`, {
    method: "POST",
    body: JSON.stringify({}),
  }, { preferBackendDetail: true });
}

export function updatePlatformSettings(payload: PlatformSettingsInput) {
  return apiFetch<SettingsApplyResponse>("/settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function validatePlatformAISettings(payload: PlatformAIValidateInput) {
  return apiFetch<PlatformAIValidateResult>("/settings/ai/validate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function listPlatformAIModels(payload: PlatformAIModelListInput) {
  return apiFetch<PlatformAIModelListResult>("/settings/ai/models", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function listRemediationAssets(params?: {
  page?: number;
  pageSize?: number;
  keyword?: string;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 24),
  });
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  return apiFetch<RemediationAssetList>(`/remediation/assets?${query.toString()}`);
}

export function getRemediationWorkspace(assetId: string) {
  return apiFetch<RemediationWorkspace>(`/remediation/assets/${assetId}/workspace`);
}

export function getRemediationAsset(assetId: string) {
  return apiFetch<RemediationAssetDetail>(`/remediation/assets/${assetId}`);
}

export function getAssetRunner(assetId: string) {
  return apiFetch<HostRunner>(`/remediation/assets/${assetId}/runner`);
}

export function installAssetRunner(assetId: string) {
  return apiFetch<HostRunnerInstallResponse>(`/remediation/assets/${assetId}/runner/install`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function issueTerminalTicket(assetId: string) {
  return apiFetch<TerminalTicket>(`/remediation/assets/${assetId}/terminal/tickets`, {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export function createRemediationSession(assetId: string, payload: RemediationSessionCreateRequest = {}) {
  return apiFetch<RemediationSession>(`/remediation/assets/${assetId}/sessions`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getRemediationSession(sessionId: string) {
  return apiFetch<RemediationSession>(`/remediation/sessions/${sessionId}`);
}

export function postRemediationSessionMessage(sessionId: string, payload: RemediationSessionMessageCreateRequest) {
  return apiFetch<RemediationSession>(`/remediation/sessions/${sessionId}/messages`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function approveRemediationSession(sessionId: string, payload: RemediationSessionApproveRequest = {}) {
  return apiFetch<RemediationSessionApproveResponse>(`/remediation/sessions/${sessionId}/approve`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getRemediationPlan(findingId: string) {
  return apiFetch<RemediationPlan>(`/remediation/findings/${findingId}/plan`);
}

export function executeRemediationPlan(findingId: string, payload: RemediationExecuteRequest) {
  return apiFetch<RemediationExecuteResponse>(`/remediation/findings/${findingId}/execute`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getRemediationTask(taskId: string) {
  return apiFetch<RemediationTask>(`/remediation/tasks/${taskId}`);
}

export function getRemediationTaskEvidence(taskId: string) {
  return apiFetch<RemediationTaskEvidence>(`/remediation/tasks/${taskId}/evidence`);
}

export function runRiskVerifyBatch(assetIds: string[]) {
  return apiFetch<RiskBatchVerifyResponse>("/risks/assets/batch/verify", {
    method: "POST",
    body: JSON.stringify({ asset_ids: assetIds }),
  });
}

export function listVulnRules(params?: {
  page?: number;
  pageSize?: number;
  keyword?: string;
  service?: string;
  severity?: "low" | "medium" | "high" | "critical";
  enabled?: boolean;
  catalogView?: VulnRuleCatalogView;
}) {
  const query = new URLSearchParams({
    page: String(params?.page ?? 1),
    page_size: String(params?.pageSize ?? 20),
  });
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  if (params?.service) {
    query.set("service", params.service);
  }
  if (params?.severity) {
    query.set("severity", params.severity);
  }
  if (typeof params?.enabled === "boolean") {
    query.set("enabled", String(params.enabled));
  }
  query.set("catalog_view", params?.catalogView || "default");
  return apiFetch<VulnRuleListResponse>(`/vuln-library/rules?${query.toString()}`);
}

export function getVulnRule(ruleId: string) {
  return apiFetch<VulnRule>(`/vuln-library/rules/${ruleId}`);
}

export function createVulnRule(payload: VulnRuleInput & { id: string }) {
  return apiFetch<VulnRule>("/vuln-library/rules", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function updateVulnRule(ruleId: string, payload: VulnRuleInput) {
  return apiFetch<VulnRule>(`/vuln-library/rules/${ruleId}`, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export function deleteVulnRule(ruleId: string) {
  return apiFetch<void>(`/vuln-library/rules/${ruleId}`, {
    method: "DELETE",
  });
}

export function batchUpdateVulnRuleStatus(ruleIds: string[], enabled: boolean) {
  return apiFetch<VulnRuleBatchStatusResponse>("/vuln-library/rules/batch/status", {
    method: "POST",
    body: JSON.stringify({ rule_ids: ruleIds, enabled }),
  });
}

export function importVulnRules(payload: {
  file: File;
  format?: VulnRuleFileFormat;
  mode?: VulnRuleImportMode;
  dryRun?: boolean;
}) {
  const body = new FormData();
  body.append("file", payload.file);
  body.append("format", payload.format || "auto");
  body.append("mode", payload.mode || "skip_existing");
  body.append("dry_run", String(Boolean(payload.dryRun)));
  return apiFetch<VulnRuleImportResponse>("/vuln-library/rules/import", {
    method: "POST",
    body,
  });
}

export function exportVulnRules(params?: {
  format?: VulnRuleExportFormat;
  ruleIds?: string[];
  keyword?: string;
  service?: string;
  severity?: "low" | "medium" | "high" | "critical";
  enabled?: boolean;
  catalogView?: VulnRuleCatalogView;
}) {
  const query = new URLSearchParams({
    format: params?.format || "yaml",
    catalog_view: params?.catalogView || "default",
  });
  params?.ruleIds?.forEach((ruleId) => query.append("rule_ids", ruleId));
  if (params?.keyword) {
    query.set("keyword", params.keyword);
  }
  if (params?.service) {
    query.set("service", params.service);
  }
  if (params?.severity) {
    query.set("severity", params.severity);
  }
  if (typeof params?.enabled === "boolean") {
    query.set("enabled", String(params.enabled));
  }
  return apiFetchBlob(`/vuln-library/rules/export?${query.toString()}`);
}

export function getVulnLibraryStatus() {
  return apiFetch<VulnLibraryStatus>("/vuln-library/status");
}

export function rebuildVulnLibraryIndex() {
  return apiFetch<VulnRuleIndexRebuildResponse>("/vuln-library/index/rebuild", {
    method: "POST",
  });
}

export function getVulnIntelStatus() {
  return apiFetch<VulnIntelStatus>("/vuln-library/intel/status");
}

export function syncVulnIntel() {
  return apiFetch<VulnIntelStatus>("/vuln-library/intel/sync", {
    method: "POST",
    body: JSON.stringify({}),
  }, {
    preferBackendDetail: true,
  });
}
