# 数据模型说明

## 文档目的与适用读者
- 面向需要理解 PostgreSQL 运行时模型的后端工程师、数据迁移维护人员与联调人员。
- 重点说明当前真实运行时实体、关系、索引方向与模型边界。

## 当前实现范围
- 当前项目不是只有资产与风险两张表，而是围绕资产、任务、修复、Haor、日志和规则治理构成完整运行时模型。
- ORM 入口位于 `backend/app/db/models/`，数据库会通过 Alembic 与运行时初始化共同维护。

## 运行时模型域

### 1. 资产域
- `assets`
  - 资产主表，承载 IP、主机名、状态、最后发现时间、画像等信息。
- `asset_ports`
  - 资产端口与服务识别结果。
- `tags` / `asset_tags`
  - 标签与资产标签关联。
- `snapshots`
  - 保存探测、采集与网络初始快照。

### 2. 风险与治理域
- `risk_findings`
  - 风险发现主表，保存规则、严重级别、证据、状态与稳定身份键。
- `finding_governance`
  - 风险责任人、优先级等治理信息。
- `finding_waiver`
  - 例外申请与审批数据。
- `risk_rules`
  - 规则定义对象。

### 3. 任务观测域
- `task_runs`
  - 平台统一异步任务表，覆盖发现、采集、验证、修复、智能体编排等任务。
- `task_events`
  - 任务事件与阶段日志明细。

### 4. 修复与 Runner 域
- `host_runners`
  - Host Runner 注册、心跳、能力、兼容性和可见网段信息。
- `remediation_sessions`
  - 资产级修复会话与阶段状态。
- `remediation_messages`
  - 修复会话内的消息流、AI 解读与审计说明。
- `credential` 相关模型
  - 保存 SSH 凭据绑定及验证状态。

### 5. 智能体运行时域
- `agent_sessions`
  - Haor 当前会话状态、页面上下文、工作上下文和运行时状态。
- `agent_goals`
  - 当前目标、成功标准、阻塞原因与恢复策略。
- `agent_messages`
  - 用户消息、智能体回复、计划、动作更新和错误反馈。

### 6. 平台与规则治理域
- `platform_log_entries`
  - 平台日志中心持久化表。
- `scanner_zones` / `scanner_node_assignments` / `campus_data_sources`
  - 校园/扫描节点相关配置对象。
- `vuln_rule_index` / `vuln_rule_governance` / `vuln_cve_intel`
  - 漏洞库索引、治理状态和情报同步结果。
- `users`
  - 平台用户与角色。

## 关键关系
- `assets 1:N asset_ports`
- `assets 1:N snapshots`
- `assets 1:N risk_findings`
- `assets 1:N remediation_sessions`
- `risk_findings 1:N finding_waiver`
- `task_runs 1:N task_events`
- `remediation_sessions 1:N remediation_messages`
- `agent_sessions 1:N agent_messages`
- `agent_goals 1:N agent_sessions` 以当前目标和最近任务的方式形成弱绑定
- `host_runners 1:N remediation_sessions`

## 索引与查询关注点
- 资产类查询通常依赖：
  - `ip`
  - `status`
  - `last_seen_at`
- 风险类查询通常依赖：
  - `asset_id`
  - `status`
  - `severity`
  - `identity_hash`
  - `yaml_rule_id` 或规则键
- 任务类查询通常依赖：
  - `task_type`
  - `status`
  - `created_at`
  - `scope_type + scope_id`
- 平台日志查询通常依赖：
  - `source_kind`
  - `service_name`
  - `task_run_id`
  - `level`
  - `created_at`

## ORM 与代码入口
- SQLAlchemy 会话入口：`backend/app/db/session.py`
- ORM 模型导出：`backend/app/db/models/__init__.py`
- 典型模型入口：
  - `backend/app/db/models/asset.py`
  - `backend/app/db/models/risk_finding.py`
  - `backend/app/db/models/task_run.py`
  - `backend/app/db/models/task_event.py`
  - `backend/app/db/models/remediation_session.py`
  - `backend/app/db/models/agent_session.py`
  - `backend/app/db/models/platform_log_entry.py`

## 迁移与维护说明
- 新库或演示环境可以依赖启动时的 `create_all()` 兜底建表。
- 已有数据库升级必须以 Alembic 迁移为准，不应依赖运行时自动建表替代列升级和索引变更。
- 运行时配置或平台设置变更不会直接修改 schema，但可能影响任务和日志等运行数据形态。

## 历史说明
- 早期文档曾用 `assets / services / findings / tasks / scan_results` 五张核心表来讨论业务骨架。
- 当前仓库实际运行时已经扩展为多域模型；研发交接应以本文件描述的运行时模型为主，而不是只看早期抽象骨架。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 文档总索引：[README.md](README.md)
- 总体架构：[architecture.md](architecture.md)
- 后端设计：[backend-design.md](backend-design.md)
- 接口说明：[api-contract.md](api-contract.md)
- 运行手册：[runbook.md](runbook.md)
