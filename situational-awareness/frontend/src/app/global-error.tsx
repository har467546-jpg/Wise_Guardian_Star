"use client";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="zh-CN">
      <body>
        <div className="exception-shell">
          <div className="exception-card">
            <p className="exception-eyebrow">全局错误</p>
            <h1 className="exception-title">页面渲染失败</h1>
            <p className="exception-description">{error.message || "出现未预期异常，请稍后重试。"}</p>
            <button type="button" onClick={() => reset()} className="exception-button">
              重新尝试
            </button>
          </div>
        </div>
      </body>
    </html>
  );
}
