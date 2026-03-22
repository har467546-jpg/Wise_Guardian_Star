# 架构说明

## 总体架构
- 前端：Next.js + TypeScript + Ant Design。
- 后端：FastAPI 提供 API，Celery 负责任务编排。
- 数据层：PostgreSQL 持久化资产台账与风险结果，Redis 作为 Celery broker/backend。

## 核心流程
1. 提交 CIDR 到 `/api/v1/discovery/jobs`。
2. Celery 执行 `discover -> upsert -> collect -> risk -> report` 流程。
3. API 提供资产、风险、报告查询。

## 安全设计
- RBAC：单租户角色（admin/analyst）。
- SSH 凭据：应用层对密码或私钥进行加密后保存。
- AI 报告：通过可插拔网关调用模型，失败时回退模板摘要。
