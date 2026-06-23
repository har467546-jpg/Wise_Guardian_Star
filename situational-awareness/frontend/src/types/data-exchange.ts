export type ServerImportIssue = {
  row: number;
  field: string | null;
  message: string;
};

export type ServerImportResponse = {
  total_rows: number;
  created: number;
  updated: number;
  credential_saved: number;
  skipped: number;
  issues: ServerImportIssue[];
};

export type ExportDataType = "servers" | "alerts" | "audit_logs" | "reports";
export type ExportFileFormat = "csv" | "json";
