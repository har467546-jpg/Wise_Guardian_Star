import { RiskFinding } from "@/types/risk";
import { TaskRun } from "@/types/task";

export type MobileDiscoveryEntry = {
  enabled: boolean;
  pending_jobs: number;
  running_jobs: number;
};

export type MobileOverview = {
  asset_total: number;
  online_assets: number;
  high_risk_findings: number;
  active_tasks: number;
  recent_tasks: TaskRun[];
  recent_risks: RiskFinding[];
  discovery_entry: MobileDiscoveryEntry;
};
