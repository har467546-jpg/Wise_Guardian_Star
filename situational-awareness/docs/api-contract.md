# API 接口说明

## 文档目的与适用读者
- 面向前后端联调、测试与二次开发人员。
- 仅记录当前真实挂载到 `backend/app/api/v1/router.py` 的 `/api/v1` 接口与 WebSocket 入口。

## 当前实现范围
- 鉴权方式默认分为三类：
  - 无鉴权：初始化前的 `auth` 接口
  - 用户鉴权：JWT Bearer Token
  - 管理员鉴权：JWT Bearer Token 且角色为 `admin`
  - 机器鉴权：Runner Token 或 settings-helper 内部令牌

## HTTP API 分组

### Auth
- `GET /api/v1/auth/bootstrap-status`
  - 无鉴权
  - 查询系统是否已初始化管理员
- `POST /api/v1/auth/bootstrap-admin`
  - 无鉴权
  - 首次初始化管理员并返回访问 token
- `POST /api/v1/auth/login`
  - 无鉴权
  - 用户登录并返回访问 token

### Dashboard
- `GET /api/v1/dashboard/overview`
  - 用户鉴权
  - 返回总览页聚合数据

### Agent
- `GET /api/v1/agent/haor/summary`
- `GET /api/v1/agent/haor/session`
- `GET /api/v1/agent/haor/goals`
- `GET /api/v1/agent/haor/goals/{goal_id}`
- `POST /api/v1/agent/haor/goals/{goal_id}/resume`
- `POST /api/v1/agent/haor/goals/{goal_id}/cancel`
- `POST /api/v1/agent/haor/session/reset`
- `POST /api/v1/agent/haor/session/recover`
- `POST /api/v1/agent/haor/session/messages`
- `POST /api/v1/agent/haor/session/steps`
- `POST /api/v1/agent/haor/session/approve`
  - 管理员鉴权
- `POST /api/v1/agent/haor/session/interrupt`

### Discovery
- `POST /api/v1/discovery/jobs`
  - 用户鉴权
  - 提交发现任务
- `GET /api/v1/discovery/jobs`
- `GET /api/v1/discovery/jobs/{job_id}`

### Campus
- `GET /api/v1/campus/zones`
- `POST /api/v1/campus/zones`
- `PATCH /api/v1/campus/zones/{zone_id}`
- `DELETE /api/v1/campus/zones/{zone_id}`
- `GET /api/v1/campus/zones/{zone_id}/nodes`
- `POST /api/v1/campus/zones/{zone_id}/nodes`
- `GET /api/v1/campus/data-sources`
- `POST /api/v1/campus/data-sources`
- `PATCH /api/v1/campus/data-sources/{source_id}`
- `DELETE /api/v1/campus/data-sources/{source_id}`
- `POST /api/v1/campus/data-sources/{source_id}/test`
- `POST /api/v1/campus/data-sources/{source_id}/collect`
- `GET /api/v1/campus/discovery-jobs/{job_id}/executions`
  - 全部为管理员鉴权

### Mobile
- `GET /api/v1/mobile/overview`
  - 用户鉴权
  - 返回移动端概览数据

### Monitoring
- `GET /api/v1/monitoring/platform/live`
  - 用户鉴权
  - 返回平台实时监控指标

### Assets
- `GET /api/v1/assets`
- `GET /api/v1/assets/{asset_id}`
- `PATCH /api/v1/assets/{asset_id}`
- `DELETE /api/v1/assets/{asset_id}`
- `POST /api/v1/assets/batch/delete`
  - 全部为用户鉴权

### Collection
- `GET /api/v1/collection/assets/{asset_id}/credential`
- `POST /api/v1/collection/assets/{asset_id}/credential`
- `POST /api/v1/collection/assets/{asset_id}/credential/verify`
- `POST /api/v1/collection/assets/credentials/batch`
- `POST /api/v1/collection/assets/batch/run`
- `POST /api/v1/collection/assets/{asset_id}/run`
- `POST /api/v1/collection/assets/{asset_id}/probe`
- `GET /api/v1/collection/assets/{asset_id}/probe/latest`
- `GET /api/v1/collection/assets/{asset_id}/latest`
- `GET /api/v1/collection/assets/{asset_id}/initial/latest`
  - 全部为用户鉴权

### Risks
- `GET /api/v1/risks`
- `GET /api/v1/risks/{finding_id}`
- `GET /api/v1/risks/assets/{asset_id}`
- `POST /api/v1/risks/{finding_id}/assign`
- `POST /api/v1/risks/{finding_id}/waivers`
- `POST /api/v1/risks/{finding_id}/recalculate-priority`
- `POST /api/v1/risks/assets/batch/verify`
- `POST /api/v1/risks/assets/{asset_id}/verify`
- `GET /api/v1/risks/{finding_id}/remediation-template`
  - 全部为用户鉴权

### Remediation
- `GET /api/v1/remediation/assets`
- `GET /api/v1/remediation/assets/{asset_id}`
- `GET /api/v1/remediation/assets/{asset_id}/runner`
- `POST /api/v1/remediation/assets/{asset_id}/runner/install`
- `GET /api/v1/remediation/assets/{asset_id}/workspace`
- `POST /api/v1/remediation/assets/{asset_id}/sessions`
- `GET /api/v1/remediation/sessions/{session_id}`
- `POST /api/v1/remediation/sessions/{session_id}/messages`
- `POST /api/v1/remediation/sessions/{session_id}/approve`
- `GET /api/v1/remediation/findings/{finding_id}/plan`
- `POST /api/v1/remediation/findings/{finding_id}/execute`
- `GET /api/v1/remediation/tasks/{task_id}`
- `GET /api/v1/remediation/tasks/{task_id}/evidence`
  - 全部为管理员鉴权

### Runner
- `POST /api/v1/runner/register`
  - 机器接口
- `POST /api/v1/runner/heartbeat`
- `POST /api/v1/runner/poll`
- `POST /api/v1/runner/tasks/{task_id}/events`
- `POST /api/v1/runner/tasks/{task_id}/complete`
  - 以上四项通过 Runner Token 认证

### Settings
- `GET /api/v1/settings`
- `PUT /api/v1/settings`
- `POST /api/v1/settings/ai/validate`
- `POST /api/v1/settings/ai/models`
  - 全部为管理员鉴权
- `POST /api/v1/settings/internal/tasks/{task_id}/complete`
  - 内部接口，通过 settings-helper 令牌认证

### Tasks
- `GET /api/v1/tasks/events`
- `GET /api/v1/tasks`
- `GET /api/v1/tasks/{task_id}/events`
- `GET /api/v1/tasks/{task_id}`
- `POST /api/v1/tasks/{task_id}/cancel`
- `DELETE /api/v1/tasks`
  - 全部为用户鉴权

### Logs
- `GET /api/v1/logs`
  - 管理员鉴权

### Vulnerability Library
- `GET /api/v1/vuln-library/status`
- `GET /api/v1/vuln-library/intel/status`
- `GET /api/v1/vuln-library/rules`
- `GET /api/v1/vuln-library/rules/{rule_id}`
  - 用户鉴权
- `POST /api/v1/vuln-library/intel/sync`
- `GET /api/v1/vuln-library/rules/export`
- `POST /api/v1/vuln-library/rules/import`
- `POST /api/v1/vuln-library/rules/batch/status`
- `POST /api/v1/vuln-library/rules`
- `PUT /api/v1/vuln-library/rules/{rule_id}`
- `DELETE /api/v1/vuln-library/rules/{rule_id}`
- `POST /api/v1/vuln-library/index/rebuild`
  - 管理员鉴权

## WebSocket 入口
- `GET ws /api/v1/agent/haor/session/stream`
  - Haor 会话流
- `GET ws /api/v1/remediation/tasks/{task_id}/stream`
  - 修复任务流
- `GET ws /api/v1/remediation/sessions/{session_id}/stream`
  - 修复会话流
- `GET ws /api/v1/logs/stream`
  - 平台日志流，管理员可用
- `GET ws /api/v1/mobile/alerts/stream`
  - 移动端异常告警流

## 说明与限制
- 本文档以 `backend/app/api/v1/router.py` 为准；存在实现文件但未挂载的接口，不属于当前标准 API。
- 当前 `backend/app/api/v1/endpoints/reports.py` 未挂载到主路由，因此不在本文件范围内。

## 关键代码入口
- `backend/app/api/v1/router.py`
- `backend/app/api/v1/endpoints/`
- `backend/app/api/deps.py`
- `backend/app/api/websocket_auth.py`

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 文档总索引：[README.md](README.md)
- 后端设计：[backend-design.md](backend-design.md)
- Haor 设计：[haor-agent-design.md](haor-agent-design.md)
- 运行手册：[runbook.md](runbook.md)
