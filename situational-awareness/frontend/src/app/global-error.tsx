"use client";

import { useEffect, useMemo, useState } from "react";

const CHUNK_RELOAD_STORAGE_KEY = "haor:chunk-reload-signature";

function isRecoverableChunkError(message: string): boolean {
  return [
    /ChunkLoadError/i,
    /Loading chunk [\w-]+ failed/i,
    /Failed to fetch dynamically imported module/i,
    /_next\/static\/chunks\//i,
  ].some((pattern) => pattern.test(message));
}

function buildReloadUrl() {
  const url = new URL(window.location.href);
  url.searchParams.set("__haor_chunk_reload", String(Date.now()));
  return url.toString();
}

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  const errorMessage = error.message || "出现未预期异常，请稍后重试。";
  const chunkReloadError = useMemo(() => isRecoverableChunkError(errorMessage), [errorMessage]);
  const [autoRefreshing, setAutoRefreshing] = useState(false);

  useEffect(() => {
    if (!chunkReloadError || typeof window === "undefined") {
      return;
    }
    const signature = errorMessage.trim().slice(0, 240) || "chunk-load-error";
    const previousSignature = window.sessionStorage.getItem(CHUNK_RELOAD_STORAGE_KEY);
    if (previousSignature === signature) {
      return;
    }
    window.sessionStorage.setItem(CHUNK_RELOAD_STORAGE_KEY, signature);
    setAutoRefreshing(true);
    const timerId = window.setTimeout(() => {
      window.location.replace(buildReloadUrl());
    }, 160);
    return () => window.clearTimeout(timerId);
  }, [chunkReloadError, errorMessage]);

  return (
    <html lang="zh-CN">
      <body>
        <div className="exception-shell">
          <div className="exception-card">
            <p className="exception-eyebrow">全局错误</p>
            <h1 className="exception-title">页面渲染失败</h1>
            <p className="exception-description">
              {autoRefreshing
                ? "检测到前端资源已更新，正在自动刷新页面。若仍未恢复，请手动再试一次。"
                : errorMessage}
            </p>
            {autoRefreshing ? <p className="exception-description">{errorMessage}</p> : null}
            <button type="button" onClick={() => reset()} className="exception-button">
              {autoRefreshing ? "立即重试" : "重新尝试"}
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
