export type TaskType =
  | "asset_scan"
  | "info_collect"
  | "risk_verify"
  | "report_generate"
  | "runner_install"
  | "remediation_execute"
  | "agent_orchestrate"
  | "settings_apply";
export type TaskStatus = "pending" | "running" | "retry" | "success" | "failure" | "canceled";
export type TaskLogLevel = "info" | "warning" | "error";

export type TaskTiming = {
  queue_duration_ms: number | null;
  run_duration_ms: number | null;
  total_duration_ms: number | null;
  current_stage_code: string | null;
  current_stage_name: string | null;
  current_stage_duration_ms: number | null;
  has_event_logs: boolean;
};

export type TaskStageTiming = {
  stage_code: string | null;
  stage_name: string | null;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
};

export type TaskEvent = {
  id: string;
  task_run_id: string;
  task_type: TaskType | null;
  status: TaskStatus | null;
  event_type: string;
  level: TaskLogLevel;
  stage_code: string | null;
  stage_name: string | null;
  message: string | null;
  progress: number | null;
  payload_json: Record<string, unknown>;
  created_at: string;
};

export type TaskRun = {
  id: string;
  task_type: TaskType;
  status: TaskStatus;
  scope_type: string | null;
  scope_id: string | null;
  celery_task_id: string | null;
  progress: number;
  message: string | null;
  retry_count: number;
  result_json: Record<string, unknown>;
  error_json: Record<string, unknown>;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  updated_at: string;
  timing: TaskTiming;
};

export type TaskRunDetail = TaskRun & {
  stage_timings: TaskStageTiming[];
  event_count: number;
  last_event_at: string | null;
};

export type TaskRunListResponse = {
  items: TaskRun[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type TaskEventListResponse = {
  items: TaskEvent[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};

export type TaskRunResponse = {
  task_id: string;
  status: TaskStatus;
};

export type TaskRunClearResponse = {
  deleted: number;
};
