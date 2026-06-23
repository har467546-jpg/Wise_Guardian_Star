export type TokenResponse = {
  access_token: string;
  token_type: string;
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
