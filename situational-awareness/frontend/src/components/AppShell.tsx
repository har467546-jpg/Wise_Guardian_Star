"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { CloseOutlined, LogoutOutlined, MenuOutlined, SettingOutlined } from "@ant-design/icons";
import { Button, ConfigProvider, Spin, Tooltip } from "antd";

import GlobalSettingsModal from "@/components/GlobalSettingsModal";
import HaorAgentDrawer from "@/components/HaorAgentDrawer";
import { clearStoredToken, getStoredToken, getStoredUserRole } from "@/lib/auth";

// --- 类型定义与配置 ---
type RouteMeta = {
  title: string;
  description: string;
  kicker: string;
};

const routeMetaMap: Array<{ match: (pathname: string) => boolean; meta: RouteMeta }> = [
  { match: (p) => p === "/", meta: { title: "态势总控页", description: "面向桌面端的资产、风险与任务全局视图。", kicker: "态势总览" } },
  { match: (p) => p === "/discovery", meta: { title: "扫描发起台", description: "提交网段任务并追踪当前扫描动作。", kicker: "扫描发起台" } },
  { match: (p) => p === "/assets", meta: { title: "资产情报面板", description: "按状态、服务和批量动作管理当前资产池。", kicker: "资产列表" } },
  { match: (p) => p.startsWith("/assets/"), meta: { title: "资产纵深详情", description: "查看端口、探测、凭据和风险发现的完整上下文。", kicker: "资产纵深" } },
  { match: (p) => p.startsWith("/remediation"), meta: { title: "修复工作台", description: "围绕漏洞模板、SSH 授权和流式执行构建交互式修复闭环。", kicker: "漏洞修复" } },
  { match: (p) => p === "/vuln-library", meta: { title: "漏洞规则工作台", description: "围绕 YAML 真源进行规则检索、批量启停与索引治理。", kicker: "漏洞库" } },
  { match: (p) => p === "/tasks", meta: { title: "任务控制台", description: "观察扫描、采集与验证任务的实时执行情况。", kicker: "任务中心" } },
  { match: (p) => p === "/tasks/logs", meta: { title: "任务日志", description: "查看结构化任务事件、告警与重试记录。", kicker: "任务日志" } },
  { match: (p) => p.startsWith("/tasks/"), meta: { title: "任务详情", description: "查看任务耗时、阶段切片与结构化事件日志。", kicker: "任务详情" } },
  { match: (p) => p === "/risks", meta: { title: "全局风险列表", description: "按资产维度查看全局风险，并跳转到资产详情继续验证与处置。", kicker: "风险总览" } },
];

// --- 辅助函数 ---
function resolveRouteMeta(pathname: string): RouteMeta {
  return routeMetaMap.find((item) => item.match(pathname))?.meta || {
    title: "资产态势感知平台",
    description: "桌面端安全运营控制台。",
    kicker: "控制台",
  };
}

const formatRole = (role: string) => ({ admin: "管理员", analyst: "分析员" }[role] || "访客");

const formatClock = (now: Date) => 
  new Intl.DateTimeFormat("zh-CN", { hour: "2-digit", minute: "2-digit", month: "2-digit", day: "2-digit" }).format(now);

const isActivePath = (pathname: string, href: string) => 
  href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);

// --- 主组件 ---
export default function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const currentPathname = pathname || "/";
  const router = useRouter();

  const [ready, setReady] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [clock, setClock] = useState(() => formatClock(new Date()));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  // 1. 路由守卫与身份核验
  useEffect(() => {
    const token = getStoredToken() || process.env.NEXT_PUBLIC_TOKEN || "";
    const hasAuth = Boolean(token);
    
    setAuthenticated(hasAuth);
    setReady(true);

    if (!hasAuth && currentPathname !== "/login") {
      router.replace("/login");
    } else if (hasAuth && currentPathname === "/login") {
      router.replace("/");
    }
  }, [currentPathname, router]);

  // 2. 时钟更新
  useEffect(() => {
    const timer = window.setInterval(() => setClock(formatClock(new Date())), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setNavOpen(false);
  }, [currentPathname]);

  const userRole = getStoredUserRole();
  const currentMeta = useMemo(() => resolveRouteMeta(currentPathname), [currentPathname]);
  const isLoginPage = currentPathname === "/login";
  const handleLogout = () => {
    clearStoredToken();
    router.replace("/login");
  };

  const menuItems = useMemo(() => [
    { key: "01", href: "/", label: "态势总览", note: "总览" },
    { key: "02", href: "/discovery", label: "扫描发起台", note: "扫描" },
    { key: "03", href: "/assets", label: "资产列表", note: "资产" },
    { key: "04", href: "/remediation", label: "修复工作台", note: "修复" },
    { key: "05", href: "/vuln-library", label: "漏洞库", note: "规则" },
    { key: "06", href: "/tasks", label: "任务中心", note: "任务" },
  ], []);

  // 3. 渲染前屏障：防止未授权内容闪烁
  if (!ready || (!authenticated && !isLoginPage)) {
    return (
      <div className="auth-loading auth-loading-shell">
        <div className="auth-loading-stack">
          <Spin size="large" />
          <span className="auth-loading-text">系统加载中...</span>
        </div>
      </div>
    );
  }

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: "#3b82f6",
          colorInfo: "#3b82f6",
          colorSuccess: "#0f9f7f",
          colorWarning: "#d97706",
          colorError: "#dc2626",
          colorBgBase: "#f7fbff",
          colorBgContainer: "#ffffff",
          colorTextBase: "#17324d",
          colorText: "#17324d",
          colorTextSecondary: "#5c7188",
          colorBorder: "rgba(124, 159, 197, 0.22)",
          borderRadius: 20,
          borderRadiusLG: 24,
          borderRadiusSM: 14,
          fontSize: 14,
          fontFamily: '"Manrope", "Avenir Next", "PingFang SC", "Microsoft YaHei", sans-serif',
          fontFamilyCode: '"JetBrains Mono", monospace',
          boxShadowSecondary: "0 22px 52px rgba(45, 84, 124, 0.12)",
        },
        components: {
          Button: {
            controlHeight: 40,
            primaryShadow: "0 16px 34px rgba(59, 130, 246, 0.18)",
            borderRadius: 999,
          },
          Card: { headerHeight: 52 },
          Table: {
            headerBg: "rgba(240, 247, 255, 0.92)",
            headerColor: "#28435c",
            colorBgContainer: "#ffffff",
          },
          Input: {
            colorBgContainer: "rgba(248, 251, 255, 0.96)",
            hoverBorderColor: "rgba(59, 130, 246, 0.32)",
            activeBorderColor: "rgba(59, 130, 246, 0.52)",
          },
          Select: {
            colorBgContainer: "rgba(248, 251, 255, 0.96)",
            optionSelectedBg: "rgba(59, 130, 246, 0.12)",
          },
          Modal: { contentBg: "#ffffff", headerBg: "#ffffff", borderRadiusLG: 28 },
          Drawer: { colorBgElevated: "#ffffff" },
          Tabs: { cardBg: "rgba(242, 247, 255, 0.82)" },
          Alert: { withDescriptionPadding: "14px 18px" },
          Descriptions: { colorFillAlter: "rgba(244, 248, 253, 0.9)" },
        },
      }}
    >
      {isLoginPage ? (
        children
      ) : (
        <div className="app-shell">
          <button
            type="button"
            className={`console-sidebar-backdrop ${navOpen ? "console-sidebar-backdrop-visible" : ""}`}
            aria-label="关闭导航"
            onClick={() => setNavOpen(false)}
          />

          <aside className={`console-sidebar ${navOpen ? "console-sidebar-open" : ""}`}>
            <div className="console-sidebar-surface">
              <div className="console-sidebar-head">
                <div className="console-brand">
                  <span className="console-brand-kicker">Unified Security Workspace</span>
                  <h1 className="console-brand-title">资产态势感知</h1>
                  <p className="console-brand-description">冷白科技风格的统一安全工作台，覆盖资产、风险、修复与规则治理。</p>
                </div>
                <Button
                  type="text"
                  shape="circle"
                  className="console-sidebar-close"
                  aria-label="关闭导航"
                  onClick={() => setNavOpen(false)}
                >
                  <CloseOutlined />
                </Button>
              </div>

              <div className="console-sidebar-intro">
                <span className="console-sidebar-intro-label">当前视图</span>
                <strong>{currentMeta.kicker}</strong>
                <p>{currentMeta.description}</p>
              </div>

              <nav className="console-nav">
                {menuItems.map((item) => {
                  const active = isActivePath(currentPathname, item.href);
                  return (
                    <Link key={item.key} href={item.href} className={`console-nav-link ${active ? "console-nav-link-active" : ""}`}>
                      <span className="console-nav-index">{item.key}</span>
                      <span className="console-nav-copy">
                        <strong>{item.label}</strong>
                        <small>{item.note}</small>
                      </span>
                    </Link>
                  );
                })}
              </nav>

              <div className="console-sidebar-footer">
                <Button block icon={<LogoutOutlined />} onClick={handleLogout}>
                  退出登录
                </Button>
              </div>
            </div>
          </aside>

          <div className="console-main">
            <header className="console-topbar">
              <div className="console-topbar-leading">
                <Tooltip title="打开导航">
                  <Button
                    shape="circle"
                    type="text"
                    className="console-topbar-nav-button"
                    onClick={() => setNavOpen(true)}
                  >
                    <MenuOutlined />
                  </Button>
                </Tooltip>
                <div className="console-topbar-copy">
                  <span className="console-topbar-kicker">{currentMeta.kicker}</span>
                  <h2 className="console-topbar-title">{currentMeta.title}</h2>
                  <p className="console-topbar-description">{currentMeta.description}</p>
                </div>
              </div>
              <div className="console-topbar-meta">
                <Tooltip title="设置">
                  <Button
                    shape="circle"
                    type="text"
                    className="console-topbar-settings-button"
                    onClick={() => setSettingsOpen(true)}
                  >
                    <SettingOutlined />
                  </Button>
                </Tooltip>
                <div className="console-topbar-pill">
                  <span>角色</span>
                  <strong>{formatRole(userRole)}</strong>
                </div>
                <div className="console-topbar-pill console-topbar-clock">
                  <span>时间</span>
                  <strong>{clock}</strong>
                </div>
              </div>
            </header>

            <main className="app-content">
              <div className="content-shell">{children}</div>
            </main>
          </div>

          <GlobalSettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} userRole={userRole} />
          <HaorAgentDrawer userRole={userRole} />
        </div>
      )}
    </ConfigProvider>
  );
}
