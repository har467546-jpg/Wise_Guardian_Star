# 前端设计说明

## 文档目的与适用读者
- 面向维护 `frontend/` 的前端工程师和需要联调 Web 控制台的后端工程师。
- 重点说明页面结构、组件组织、API 调用、实时交互和 Haor 前端运行时。

## 当前实现范围
- 前端采用 Next.js 15 App Router、React 19、TypeScript 与 Ant Design 5。
- 覆盖登录、总览、发现、资产、风险、修复、漏洞库、任务中心与 Haor 会话抽屉。

## 核心模块与数据流

### 页面与外壳
- `frontend/src/app/layout.tsx`
  - 注入全局样式、Ant Design reset 和统一外壳。
- `frontend/src/components/AppShell.tsx`
  - 负责路由守卫、导航、顶部信息、主题、设置弹层和 Haor 入口。
- 页面入口主要位于：
  - `frontend/src/app/page.tsx`
  - `frontend/src/app/discovery/page.tsx`
  - `frontend/src/app/assets/page.tsx`
  - `frontend/src/app/risks/page.tsx`
  - `frontend/src/app/remediation/page.tsx`
  - `frontend/src/app/tasks/page.tsx`
  - `frontend/src/app/vuln-library/page.tsx`
  - `frontend/src/app/login/page.tsx`

### API 接入与鉴权
- `frontend/src/services/api.ts`
  - 统一封装所有 REST 请求、错误映射、平台访问头和 token 注入。
- `frontend/src/lib/auth.ts`
  - 管理浏览器本地 token 与角色读取。
- `next.config.mjs`
  - 通过 rewrites 将 `/api/v1/*` 代理到后端，默认无需前端手写完整后端地址。

### 组件组织
- 页面容器组件负责业务编排与状态加载，例如：
  - `DashboardBoard`
  - `DiscoveryForm`
  - `AssetTable`
  - `AssetDetailView`
  - `HostRemediationSessionView`
  - `TaskTable`
  - `TaskLogCenter`
- 类型定义集中在 `frontend/src/types/`，和后端响应模型保持字段语义一致。

### 实时交互
- 轮询：
  - 总览页定时拉取平台实时监控指标。
  - Haor 悬浮入口在未打开时定时拉取摘要。
- WebSocket：
  - Haor 会话流
  - 平台日志流
  - 修复任务流
  - 移动端异常告警流对应的前端兼容接口

### Haor 前端运行时
- `frontend/src/components/HaorAgentLauncher.tsx`
  - 提供全站悬浮入口和注意力提示。
- `frontend/src/components/HaorAgentDrawer.tsx`
  - 负责消息流、审批、恢复、打断、任务观察和安全输入弹层。
- `frontend/src/lib/haor-browser-runtime.ts`
  - 采集路由、选中对象、DOM 摘要、表单、开放面板与候选 UI 动作。
- 这套运行时把当前页面状态结构化后交给后端 Haor 编排层，而不是只发送纯文本消息。

## 关键代码入口
- `frontend/src/app/layout.tsx`
- `frontend/src/components/AppShell.tsx`
- `frontend/src/services/api.ts`
- `frontend/src/lib/auth.ts`
- `frontend/src/lib/haor-browser-runtime.ts`
- `frontend/src/components/HaorAgentLauncher.tsx`
- `frontend/src/components/HaorAgentDrawer.tsx`
- `frontend/src/components/DashboardBoard.tsx`
- `frontend/src/components/HostRemediationSessionView.tsx`

## 配置、依赖与限制
- `NEXT_PUBLIC_API_BASE` 默认留空，由 Next.js 代理转发到后端。
- `BACKEND_INTERNAL_URL` 控制容器内部代理目标。
- `NEXT_ALLOWED_DEV_ORIGINS` 控制局域网开发访问来源。
- 当前文档主线聚焦桌面端；Flutter 移动端位于仓库同级目录，不纳入本文件详细展开。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 总体架构：[architecture.md](architecture.md)
- 后端设计：[backend-design.md](backend-design.md)
- 接口说明：[api-contract.md](api-contract.md)
- Haor 设计：[haor-agent-design.md](haor-agent-design.md)
- 测试与验收：[testing-and-acceptance.md](testing-and-acceptance.md)
