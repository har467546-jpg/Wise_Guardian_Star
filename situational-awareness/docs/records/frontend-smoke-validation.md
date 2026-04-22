# 前端 Smoke 验证记录

## 背景
- 记录日期：2026-04-21
- 背景：验证 `Project1` 前端风格迁入当前项目后，页面可访问、接口可联调且本轮修复未回退。

## 环境
- 前端入口：`http://localhost:3000`
- 后端入口：`http://localhost:8000`
- 依赖接口：
  - `POST /api/v1/discovery/jobs`
  - `GET /api/v1/remediation/assets/{asset_id}`
  - `POST /api/v1/remediation/assets/{asset_id}/sessions`
  - `GET /api/v1/remediation/sessions/{session_id}`
  - `GET /api/v1/settings`

## 执行步骤
1. 检查后端 `/health` 是否正常。
2. 检查首页、资产页、扫描发起台、修复工作台等页面是否可访问。
3. 逐页验证迁移后的视觉、状态显示和接口兼容情况。
4. 重点检查资产列表、资产详情、扫描发起台、修复工作台和全局设置。

## 关键观测
- 后端健康检查预期返回：
```json
{"status":"ok"}
```
- 页面级关键检查项包括：
  - 资产列表采用迁移后的卡片基线
  - 无主机名时不显示“未识别主机名”
  - 基础设施资产右上角能显示角色标识
  - 扫描发起台保留三段式流水线说明和 CIDR 校验
  - 修复工作台不回退到旧版不兼容语义
  - 全局设置仍保留当前项目的字段超集

## 结论
- 前端迁移后的关键页面具备继续联调的基础，视觉与布局迁移没有直接破坏当前后端接口能力。
- 详细验收结论已吸收进标准文档中的测试与验收说明。

## 影响范围
- 主要影响前端页面可达性、样式和与当前后端接口的联调稳定性。
- 不应被视为完整端到端自动化回归的替代。

## 相关标准文档
- 测试与验收：[../testing-and-acceptance.md](../testing-and-acceptance.md)
- 前端设计：[../frontend-design.md](../frontend-design.md)
- 运行手册：[../runbook.md](../runbook.md)
