import type { RemediationWorkspace } from "@/types/remediation";

export type RollbackArtifactDiff = {
  label: string;
  before: string;
  after: string;
};

type RollbackArtifactSummary = {
  packageName: string | null;
  manager: string | null;
  rollbackVersion: string | null;
  transactionId: string | null;
};

function toRecord(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }
  return input as Record<string, unknown>;
}

function renderArtifactValue(value: unknown): string {
  if (typeof value === "boolean") {
    return value ? "是" : "否";
  }
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  return String(value).trim() || "-";
}

export function getRollbackArtifact(input: unknown): Record<string, unknown> | null {
  const artifact = toRecord(input);
  return Object.keys(artifact).length ? artifact : null;
}

export function getRollbackArtifactSummary(input: unknown): RollbackArtifactSummary | null {
  const artifact = getRollbackArtifact(input);
  if (!artifact) {
    return null;
  }
  return {
    packageName: renderArtifactValue(artifact.package_name) === "-" ? null : renderArtifactValue(artifact.package_name),
    manager: renderArtifactValue(artifact.manager) === "-" ? null : renderArtifactValue(artifact.manager),
    rollbackVersion: renderArtifactValue(artifact.rollback_version) === "-" ? null : renderArtifactValue(artifact.rollback_version),
    transactionId: renderArtifactValue(artifact.transaction_id) === "-" ? null : renderArtifactValue(artifact.transaction_id),
  };
}

export function getRollbackArtifactDiffs(input: unknown): RollbackArtifactDiff[] {
  const artifact = getRollbackArtifact(input);
  if (!artifact) {
    return [];
  }
  const before = toRecord(artifact.before);
  const after = toRecord(artifact.after);
  const fields: Array<[string, string]> = [
    ["version", "版本"],
    ["arch", "架构"],
    ["state", "状态"],
    ["installed", "安装状态"],
  ];
  return fields.reduce<RollbackArtifactDiff[]>((items, [key, label]) => {
    const beforeValue = renderArtifactValue(before[key]);
    const afterValue = renderArtifactValue(after[key]);
    if (beforeValue !== afterValue) {
      items.push({ label, before: beforeValue, after: afterValue });
    }
    return items;
  }, []);
}

export function buildRemediationAssetPath(
  assetId: string,
  params?: {
    findingId?: string | null;
    taskId?: string | null;
  },
): string {
  const query = new URLSearchParams();
  if (params?.findingId) {
    query.set("findingId", params.findingId);
  }
  if (params?.taskId) {
    query.set("taskId", params.taskId);
  }
  const queryString = query.toString();
  return queryString ? `/remediation/${assetId}?${queryString}` : `/remediation/${assetId}`;
}

export function buildInteractiveRemediationPath(
  assetId: string,
  params?: {
    findingId?: string | null;
    taskId?: string | null;
  },
): string {
  const query = new URLSearchParams();
  if (params?.findingId) {
    query.set("findingId", params.findingId);
  }
  if (params?.taskId) {
    query.set("taskId", params.taskId);
  }
  const queryString = query.toString();
  return queryString ? `/remediation-workspace/${assetId}?${queryString}` : `/remediation-workspace/${assetId}`;
}

export function severityRank(value: string | null | undefined): number {
  switch ((value || "").trim().toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

export function pickRecommendedFindingId(workspace: Pick<RemediationWorkspace, "findings"> | null | undefined): string | null {
  const findings = workspace?.findings || [];
  if (!findings.length) {
    return null;
  }
  const sorted = [...findings].sort((left, right) => {
    const severityDelta = severityRank(right.severity) - severityRank(left.severity);
    if (severityDelta !== 0) {
      return severityDelta;
    }
    const detectedDelta = new Date(right.detected_at).getTime() - new Date(left.detected_at).getTime();
    if (detectedDelta !== 0) {
      return detectedDelta;
    }
    return 0;
  });
  return sorted[0]?.finding_id || null;
}

export function remediationBusinessStatusLabel(value: string | null | undefined): string {
  switch ((value || "").trim().toLowerCase()) {
    case "pending_reverify":
      return "待复验";
    case "verified_closed":
      return "已闭环";
    case "verified_partial":
      return "未闭环";
    case "verified_failed":
      return "复验失败";
    default:
      return "-";
  }
}

export function remediationExecutionStatusLabel(value: string | null | undefined): string {
  switch ((value || "").trim().toLowerCase()) {
    case "pending":
      return "执行中";
    case "succeeded":
      return "执行成功";
    case "failed":
      return "执行失败";
    case "preview_only":
      return "仅预演";
    default:
      return "-";
  }
}


export function remediationExecutionOutcomeLabel(
  executionStatus: string | null | undefined,
  businessStatus: string | null | undefined,
): string {
  switch ((businessStatus || "").trim().toLowerCase()) {
    case "pending_reverify":
      return "执行完成，待复验";
    case "verified_closed":
      return "执行完成，已闭环";
    case "verified_partial":
      return "执行完成，但未闭环";
    case "verified_failed":
      return "执行完成，但复验失败";
    default:
      return remediationExecutionStatusLabel(executionStatus);
  }
}


export function remediationResolvedTaskMessage(
  message: string | null | undefined,
  executionStatus: string | null | undefined,
  businessStatus: string | null | undefined,
): string {
  const normalizedMessage = String(message || "").trim();
  const normalizedBusinessStatus = String(businessStatus || "").trim().toLowerCase();
  if (
    normalizedMessage === "Host Runner 已完成整机修复计划"
    && normalizedBusinessStatus === "verified_partial"
  ) {
    return "当前阶段执行完成，但目标风险仍未关闭";
  }
  if (
    normalizedMessage === "Host Runner 已完成整机修复计划"
    && normalizedBusinessStatus === "verified_closed"
  ) {
    return "当前阶段执行完成，目标风险已闭环";
  }
  if (
    normalizedMessage === "Host Runner 已完成当前阶段执行"
    && normalizedBusinessStatus === "verified_partial"
  ) {
    return "当前阶段执行完成，但目标风险仍未关闭";
  }
  if (
    normalizedMessage === "Host Runner 已完成当前阶段执行"
    && normalizedBusinessStatus === "verified_closed"
  ) {
    return "当前阶段执行完成，目标风险已闭环";
  }
  if (!normalizedMessage) {
    return remediationExecutionOutcomeLabel(executionStatus, businessStatus);
  }
  return normalizedMessage;
}
