export type TokenResponse = {
  access_token: string;
  token_type: string;
};

export type BootstrapStatusResponse = {
  bootstrapped: boolean;
  can_bootstrap_admin: boolean;
  user_count: number;
};
