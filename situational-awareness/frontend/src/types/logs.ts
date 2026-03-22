import { TaskType } from "@/types/task";

export type PlatformLogLevel = "info" | "warning" | "error";
export type PlatformLogSourceKind = "system" | "task_raw";
export type PlatformLogServiceName = "backend" | "worker";

export type PlatformLogEntry = {
  id: string;
  source_kind: PlatformLogSourceKind;
  service_name: PlatformLogServiceName;
  logger_name: string;
  task_run_id: string | null;
  task_type: TaskType | null;
  event_type: string;
  level: PlatformLogLevel;
  stage_code: string | null;
  stage_name: string | null;
  message: string | null;
  payload_json: Record<string, unknown>;
  created_at: string;
};

export type PlatformLogListResponse = {
  items: PlatformLogEntry[];
  meta: {
    total: number;
    page: number;
    page_size: number;
  };
};
