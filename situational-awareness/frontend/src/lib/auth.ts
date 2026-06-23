const TOKEN_KEY = "sa_access_token";
const REFRESH_TOKEN_KEY = "sa_refresh_token";
const ROLE_KEY = "sa_user_role";
export type StoredUserRole = "admin" | "analyst" | "";

export function getStoredToken(): string {
  if (typeof window === "undefined") {
    return "";
  }
  return window.localStorage.getItem(TOKEN_KEY) || "";
}

export function setStoredToken(token: string): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.setItem(TOKEN_KEY, token);
}

export function getStoredRefreshToken(): string {
  if (typeof window === "undefined") {
    return "";
  }
  return window.localStorage.getItem(REFRESH_TOKEN_KEY) || "";
}

export function setStoredRefreshToken(token: string): void {
  if (typeof window === "undefined") {
    return;
  }
  if (!token) {
    window.localStorage.removeItem(REFRESH_TOKEN_KEY);
    return;
  }
  window.localStorage.setItem(REFRESH_TOKEN_KEY, token);
}

export function setStoredAuthTokens(tokens: { access_token: string; refresh_token?: string | null }): void {
  setStoredToken(tokens.access_token);
  if (tokens.refresh_token) {
    setStoredRefreshToken(tokens.refresh_token);
  }
}

export function clearStoredToken(): void {
  if (typeof window === "undefined") {
    return;
  }
  window.localStorage.removeItem(TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.localStorage.removeItem(ROLE_KEY);
}

export function setStoredUserRole(role: StoredUserRole): void {
  if (typeof window === "undefined") {
    return;
  }
  if (!role) {
    window.localStorage.removeItem(ROLE_KEY);
    return;
  }
  window.localStorage.setItem(ROLE_KEY, role);
}

function decodeTokenPayload(token: string): Record<string, unknown> | null {
  const segments = token.split(".");
  if (segments.length < 2) {
    return null;
  }
  try {
    const normalized = segments[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
    const decoded = window.atob(padded);
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function getStoredUserRole(): StoredUserRole {
  if (typeof window === "undefined") {
    return "";
  }
  const role = (window.localStorage.getItem(ROLE_KEY) || "").toLowerCase();
  if (role === "admin" || role === "analyst") {
    return role;
  }
  return "";
}
