# Project1 前端迁移记录（2026-04-21）

## 背景
- 来源工程：`/root/Desktop/Project1/situational-awareness/frontend`
- 目标工程：`/root/Desktop/Project/situational-awareness/frontend`
- 目标：
  - 将 `Project1` 的前端界面风格迁入当前项目
  - 保留当前项目已演进的后端接口能力
  - 保留本轮对话中已完成的显示修复、基础设施标注和状态语义修复
  - 保证迁移后前后端仍可成功联调

## 差异总览
对比结果显示，两边前端的技术栈和路由骨架一致：
- Next.js 15
- React 19
- Ant Design 5
- `src/app` 与 `src/components` 结构一致

真正有差异的核心文件主要包括：
- `src/components/AssetTable.tsx`
- `src/components/AssetDetailView.tsx`
- `src/components/DesktopPageHeader.tsx`
- `src/components/DiscoveryForm.tsx`
- `src/components/GlobalSettingsModal.tsx`
- `src/components/HostRemediationSessionView.tsx`
- `src/styles/globals.css`
- `src/services/api.ts`
- `src/types/asset.ts`
- `src/types/discovery.ts`
- `src/types/remediation.ts`
- `src/types/settings.ts`

同时，当前项目独有：
- `src/app/campus`
- `src/components/CampusEmbeddedPanel.tsx`
- `src/types/campus.ts`

## 迁移原则
本次迁移采用“三层拆分”策略：

1. 视觉和布局层：
   - 优先向 `Project1` 靠拢
   - 包括页头、卡片、扫描发起台、资产列表布局等

2. 数据和类型层：
   - 优先保留当前项目的超集定义
   - 避免回退到旧接口形状导致当前后端无法联调

3. 本轮修复保留层：
   - 不回退本轮已完成的资产显示、基础设施标注和状态语义修复

## 已迁移内容

### 1. 页头组件
- `DesktopPageHeader` 已恢复 `Project1` 风格：
  - 支持 `detail`
  - 恢复 `desktop-page-header-chip-detail` 的视觉表现

涉及文件：
- `src/components/DesktopPageHeader.tsx`
- `src/styles/globals.css`

### 2. 扫描发起台
- `DiscoveryForm` 已切换为 `Project1` 版本：
  - 恢复三段流水线说明
  - 恢复任务复用提示与 CIDR 摘要
  - 保持和当前 `createDiscoveryJob` 接口兼容

涉及文件：
- `src/components/DiscoveryForm.tsx`

### 3. 资产列表页
- 资产列表布局已回到 `Project1` 的卡片基线
- 同时保留本轮修复：
  - 无主机名时不显示“未识别主机名”
  - 基础设施资产右上角显示角色标签
  - 如 `网关 / DNS`

涉及文件：
- `src/components/AssetTable.tsx`

### 4. 资产详情页
- 未直接回退成 `Project1` 旧版
- 保留当前项目中的增强能力：
  - 端口服务名回退显示
  - 有值才显示的资产概览项
  - 基础设施类别 / 角色 / 来源的中文展示

涉及文件：
- `src/components/AssetDetailView.tsx`

### 5. 修复工作台
- 未做 1:1 整文件覆盖
- 仅恢复可安全迁回的 `Project1` 呈现：
  - 页头剩余开放风险明细
  - 阶段卡片“修复该阶段”按钮
  - 更贴近 `Project1` 的阶段审批入口

同时继续保持当前后端语义：
- 不强行恢复旧版“一键全部修复”交互
- 不依赖当前后端已不保证返回的字段行为

涉及文件：
- `src/components/HostRemediationSessionView.tsx`
- `src/types/remediation.ts`

## 保留当前项目超集实现的部分

### 1. 设置面板
`GlobalSettingsModal` 没有整文件回退，因为当前项目已经支持：
- 多源发现
- ARP / fping 配置
- 校园默认扫描策略
- 更完整的 AI / 平台设置

当前实现比 `Project1` 更完整，视觉结构已经基本接近，因此保留当前版本。

### 2. API 与类型
保留当前项目的超集，以兼容当前后端：
- `src/services/api.ts`
- `src/types/asset.ts`
- `src/types/discovery.ts`
- `src/types/settings.ts`

这些文件比 `Project1` 多出：
- 校园能力字段
- 资产分类与角色字段
- 更完整的扫描与设置参数

## 本轮修复保留项
迁移过程中显式保留了以下改动：
- 资产列表空主机名不显示
- 资产详情空属性按有值渲染
- 资产详情端口服务名从 `fingerprint_json` 回退显示
- 基础设施资产自动打标
- 资产卡片右上角显示基础设施角色
- `network_initial success/partial -> asset.status=online`

## 联调验证
迁移完成后已执行：
- 前端生产构建成功
- 关键页面可访问：
  - `/`
  - `/assets`
  - `/discovery`
  - `/remediation`
- 后端健康检查通过：
  - `/health`
- 真实接口联调通过：
  - 登录
  - 资产列表
  - 平台设置读取
  - 创建发现任务

## 后续建议
如果还要继续向 `Project1` 靠拢，推荐按下面顺序推进：

1. `GlobalSettingsModal`
   - 只做视觉层对齐，不回退字段能力
2. `HostRemediationSessionView`
   - 继续恢复 `Project1` 的阶段进度呈现和信息卡片布局
   - 但仍需避免引入当前后端不支持的旧交互语义
3. 页面级回归
   - 为 `assets / discovery / remediation` 三页补一轮视觉 smoke 测试截图
