import Link from "next/link";

export default function NotFoundPage() {
  return (
    <div className="exception-shell exception-shell-inline">
      <div className="exception-card exception-card-inline">
        <p className="exception-eyebrow">页面未找到</p>
        <h1 className="exception-title">请求的页面不存在</h1>
        <p className="exception-description">该地址可能已经变更，或者当前路由未开放。</p>
        <Link href="/" className="exception-link-button">
          返回态势总览
        </Link>
      </div>
    </div>
  );
}
