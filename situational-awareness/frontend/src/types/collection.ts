export type ProbePreset = "baseline";
export type CredentialAuthType = "password" | "key";

export type ProbeCommandResult = {
  name: string;
  command: string;
  success: boolean;
  exit_status: number | null;
  stdout: string;
  stderr: string;
  duration_ms: number;
};

export type AssetProbeResponse = {
  asset_id: string;
  ip: string;
  preset: ProbePreset;
  status: "success" | "partial" | "failed";
  probe_method: "ssh";
  results: ProbeCommandResult[];
  errors: Array<Record<string, unknown>>;
  summary_json: Record<string, unknown>;
  detail_json: Record<string, unknown>;
  friendly_text: string[];
  executed_at: string;
};

export type AssetLatestProbeResponse = AssetProbeResponse;

export type AssetLatestInitialResponse = {
  asset_id: string;
  status: "success" | "partial" | "failed";
  collected_at: string;
  summary_json: Record<string, unknown>;
  detail_json: Record<string, unknown>;
};

export type AssetCredentialReadResponse = {
  asset_id: string;
  credential_id: string | null;
  auth_type: CredentialAuthType | null;
  username: string | null;
  bound: boolean;
  admin_authorized: boolean;
  last_verified_at: string | null;
  last_verification_status: string | null;
  effective_privilege: string | null;
};

export type AssetCredentialUpsertRequest = {
  auth_type: CredentialAuthType;
  username: string;
  password?: string;
  private_key?: string;
  sudo_password?: string;
  admin_authorized: boolean;
};

export type AssetCredentialVerifyResponse = {
  asset_id: string;
  status: "success" | "failed";
  username: string | null;
  effective_user: string | null;
  effective_privilege: "root" | "sudo" | null;
  summary: string;
  verified_at: string;
  errors: Array<Record<string, unknown>>;
  detail_json: Record<string, unknown>;
};

export type AssetCredentialBatchUpsertRequest = AssetCredentialUpsertRequest & {
  asset_ids: string[];
  mode: "same_credential_batch";
  verify_after_save: boolean;
};

export type AssetCredentialBatchResult = {
  asset_id: string;
  saved: boolean;
  verified: boolean;
  effective_privilege: "root" | "sudo" | null | string;
  error_summary: string | null;
};

export type AssetCredentialBatchResponse = {
  mode: "same_credential_batch";
  total_count: number;
  success_count: number;
  failure_count: number;
  results: AssetCredentialBatchResult[];
};

export type AssetLatestCollectionResponse = {
  asset_id: string;
  status: "success" | "partial" | "failed";
  collected_at: string;
  summary_json: Record<string, unknown>;
  detail_json: Record<string, unknown>;
};
