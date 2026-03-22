/** @type {import('next').NextConfig} */
const backendInternalUrl = process.env.BACKEND_INTERNAL_URL || "http://backend:8000";

function normalizeAllowedDevOrigin(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) {
    return null;
  }
  if (raw.includes("://")) {
    try {
      return new URL(raw).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
  const withoutPath = raw.split("/")[0] || "";
  if (!withoutPath) {
    return null;
  }
  return withoutPath.replace(/:\d+$/, "") || null;
}

const allowedDevOrigins = Array.from(
  new Set(
    (process.env.NEXT_ALLOWED_DEV_ORIGINS || "")
      .split(",")
      .map((item) => normalizeAllowedDevOrigin(item))
      .filter(Boolean),
  ),
);

const nextConfig = {
  reactStrictMode: true,
  ...(allowedDevOrigins.length ? { allowedDevOrigins } : {}),
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendInternalUrl}/api/v1/:path*`,
      },
      {
        source: "/health",
        destination: `${backendInternalUrl}/health`,
      },
    ];
  },
};

export default nextConfig;
