# 前端迁移记录

## 背景
- 记录日期：2026-04-21
- 来源工程：`/root/Desktop/Project1/situational-awareness/frontend`
- 目标工程：`/root/Desktop/Project/situational-awareness/frontend`
- 目标：
  - 将 `Project1` 的前端视觉与布局风格迁入当前项目
  - 保留当前项目已演进的后端接口能力
  - 保留本轮已完成的显示修复、基础设施标注和状态语义修复

## 环境
- 两边工程技术栈一致：
  - Next.js 15
  - React 19
  - Ant Design 5
- 当前项目独有校园相关模块，需要在迁移中保留：
  - `src/app/campus`
  - `src/components/CampusEmbeddedPanel.tsx`
  - `src/types/campus.ts`

## 执行步骤
1. 对比两边 `src/app`、`src/components`、`src/services` 与 `src/types` 的结构和差异。
2. 按“视觉和布局层、数据和类型层、本轮修复保留层”三层原则拆分迁移。
3. 优先恢复 `Project1` 的页头、扫描发起台、资产列表等视觉基线。
4. 保留当前项目接口超集定义，避免前端回退成旧接口形状。
5. 检查修复工作台、全局设置和当前独有模块的兼容性。

## 关键观测
- 差异集中在以下前端文件：
  - `src/components/AssetTable.tsx`
  - `src/components/AssetDetailView.tsx`
  - `src/components/DesktopPageHeader.tsx`
  - `src/components/DiscoveryForm.tsx`
  - `src/components/GlobalSettingsModal.tsx`
  - `src/components/HostRemediationSessionView.tsx`
  - `src/styles/globals.css`
  - `src/services/api.ts`
  - 多个 `src/types/*.ts`
- 迁移过程确认：
  - 视觉可回到 `Project1` 风格
  - 后端接口能力必须保持当前项目超集
  - 本轮已修复的问题不能回退

## 结论
- 当前项目已完成一轮“视觉迁移优先、接口超集保留、本轮修复不回退”的前端迁移。
- 迁移成果后续需要通过 Smoke 验证来确认页面可达、接口兼容和关键交互稳定性。

## 影响范围
- 主要影响前端视图层、组件布局和部分类型适配。
- 不应直接改变后端接口、数据库模型和任务协议。

## 相关标准文档
- 前端设计：[../frontend-design.md](../frontend-design.md)
- 测试与验收：[../testing-and-acceptance.md](../testing-and-acceptance.md)
- 文档索引：[../README.md](../README.md)
