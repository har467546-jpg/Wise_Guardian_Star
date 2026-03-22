import type { RemediationWorkspace } from "@/types/remediation";

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
