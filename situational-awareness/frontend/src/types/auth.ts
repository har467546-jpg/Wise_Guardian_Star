export type TokenResponse = {
  access_token: string;
  refresh_token?: string | null;
  token_type: string;
  expires_in?: number | null;
  refresh_expires_in?: number | null;
};

export type LogoutResponse = {
  revoked: boolean;
};

export type BootstrapStatusResponse = {
  bootstrapped: boolean;
  can_bootstrap_admin: boolean;
  user_count: number;
};

export type UserRead = {
  id: string;
  username: string;
  email: string;
  role: "admin" | "analyst";
  is_active: boolean;
  created_at: string;
};
