export type Report = {
  id: string;
  scope: "job" | "asset";
  scope_id: string;
  summary_md: string;
  risk_overview_json: Record<string, number>;
  analysis_json: Record<string, unknown>;
  created_at: string;
};

export type GenerateReportResponse = {
  task_id: string;
  status: string;
};
