import { RiskFinding } from "@/types/risk";
import { TaskRun } from "@/types/task";

export type DashboardDiscoveryEntry = {
  enabled: boolean;
  pending_jobs: number;
  running_jobs: number;
};

export type DashboardSeverityTotals = {
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type DashboardRiskyAsset = {
  id: string;
  ip: string;
  hostname: string | null;
  finding_count: number;
  highest_severity: "low" | "medium" | "high" | "critical";
};

export type DashboardOverview = {
  asset_total: number;
  online_assets: number;
  high_risk_findings: number;
  active_tasks: number;
  discovery_entry: DashboardDiscoveryEntry;
  recent_risks: RiskFinding[];
  risky_assets: DashboardRiskyAsset[];
  severity_totals: DashboardSeverityTotals;
  task_health: TaskRun[];
};
