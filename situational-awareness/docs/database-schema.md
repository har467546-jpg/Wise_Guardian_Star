# PostgreSQL 数据库结构设计

该设计对应一套更聚焦的核心表结构，围绕 `assets`、`services`、`findings`、`tasks`、`scan_results` 五张表组织。它和当前运行时模型分离，便于先讨论结构，再决定是否迁移现网代码。

当前项目实际运行时已经在这套核心表之外，引入了智能体会话、修复会话和任务事件等表。也就是说：
- 如果只是讨论“资产态势感知”的核心业务骨架，这五张表足够。
- 如果要完整描述当前仓库已落地的能力，需要把智能体运行时、修复编排与任务观测表一起考虑进去。

## 关系设计

- `assets 1:N services`
  - 一个资产可以有多个开放端口和服务。
  - `services.asset_id -> assets.id`，删除资产时级联删除服务。

- `assets 1:N findings`
  - 风险发现始终归属于某个资产。
  - `findings.asset_id -> assets.id`，删除资产时级联删除发现。

- `services 1:N findings`
  - 风险发现可以进一步精确到某个服务。
  - `findings.service_id -> services.id`，删除服务时置空，保留历史发现。

- `tasks 1:N scan_results`
  - 一个扫描任务会产生多个按主机聚合的扫描结果。
  - `scan_results.task_id -> tasks.id`，删除任务时级联删除结果。

- `tasks 1:N findings`
  - 发现可以关联到触发它的任务。
  - `findings.task_id -> tasks.id`，删除任务时置空，保留风险记录。

- `assets 1:N scan_results`
  - 资产可以关联多个历史扫描结果。
  - `scan_results.asset_id -> assets.id`，删除资产时置空，保留任务侧原始结果。

## 索引设计

- `assets`
  - `UNIQUE(ip)`：保证资产主键外的网络唯一性。
  - `(status, last_seen_at)`：支持在线资产与最近发现查询。
  - `(owner)`：支持责任人过滤。
  - `GIN(tags)`：支持标签包含检索。

- `services`
  - `UNIQUE(asset_id, port, protocol)`：防止同一资产端口重复。
  - `(asset_id, state)`：支持查看资产当前开放服务。
  - `(service_name, version)`：支持按产品版本筛查脆弱面。
  - `(last_seen_at)`：支持最近变更服务查询。

- `tasks`
  - `(task_type, status, created_at)`：支持任务列表分页与状态筛选。
  - `(status, started_at)`：支持查看正在运行或失败任务。

- `scan_results`
  - `(task_id, scanned_at)`：支持按任务回看扫描结果。
  - `(asset_id, scanned_at)`：支持资产历史扫描轨迹。
  - `(ip)`：支持按 IP 追溯。
  - `GIN(raw_result)`：支持对原始结果的结构化检索。

- `findings`
  - `(asset_id, status, severity)`：支持风险面板和资产详情页。
  - `(service_id)`：支持定位具体服务问题。
  - `(task_id)`：支持回溯某次任务发现了哪些问题。
  - `(rule_key)`：支持按规则或漏洞键聚合。
  - `GIN(evidence)`：支持证据字段检索。

## SQL 与 ORM

- PostgreSQL DDL: [asset_schema.sql](../infra/postgres/asset_schema.sql)
- 示例数据: [asset_schema_seed.sql](../infra/postgres/asset_schema_seed.sql)
- SQLAlchemy ORM: [schema_models.py](../backend/app/db/schema_models.py)

## 当前运行时补充模型

### 智能体运行时

- `agent_sessions`
  - 记录 Haor 当前会话状态。
  - 关键字段包括：
    - `route_context_json`：当前页面路由和查询参数
    - `working_context_json`：当前聚焦资产、任务等工作上下文
    - `pending_plan_json`：待执行计划
    - `browser_runtime_json`：当前运行阶段，如等待回复、等待 UI 回传、等待审批
    - `agent_state_json`：聚焦对象、执行阶段、解释和任务观察状态
    - `current_goal_id` / `last_task_id`：当前目标和最近任务引用

- `agent_goals`
  - 记录用户当前目标，而不只是一次消息。
  - 关键字段包括：
    - `goal_kind`：如扫描网段、验证风险、安装 Runner、准备修复
    - `success_criteria_json`：成功标准
    - `context_json` / `plan_json` / `progress_json`：目标上下文、执行计划和过程进度
    - `blocked_reason`：阻塞原因
    - `last_session_id` / `last_task_id`：最近关联会话和任务

- `agent_messages`
  - 记录智能体会话内的消息流。
  - 支持按 `role` 和 `message_type` 区分用户消息、普通回复、澄清、计划、动作更新、错误等。

- 关系补充
  - `agent_sessions 1:N agent_messages`
  - `agent_goals 1:N agent_sessions(current_goal_id)`
  - `task_runs 1:N agent_goals/agent_sessions(last_task_id)` 以最近任务方式关联，而不是严格的单向级联历史表

### 修复编排运行时

- `remediation_sessions`
  - 记录资产级自动修复会话。
  - 关键字段包括：
    - `asset_id`：目标资产
    - `runner_id`：负责执行的 Host Runner
    - `plan_json`：可执行修复计划
    - `finding_snapshot_json`：修复启动时的发现快照
    - `summary_json`：修复摘要
    - `approved_at` / `approved_by`：审批信息
    - `last_task_id`：最近一次修复任务

- `remediation_messages`
  - 记录修复会话里的对话与系统消息，和 `remediation_sessions` 构成会话消息流。

- 关系补充
  - `assets 1:N remediation_sessions`
  - `host_runners 1:N remediation_sessions`
  - `remediation_sessions 1:N remediation_messages`
  - `task_runs 1:N remediation_sessions(last_task_id)` 用于追踪最近执行任务

### 任务观测运行时

- `task_runs`
  - 是平台统一任务表，覆盖扫描、风险验证、Runner 安装、智能体编排、修复执行等异步任务。
  - 通过 `task_type`、`status`、`scope_type`、`scope_id` 表示任务类型、状态和业务归属。

- `task_events`
  - 是任务事件流明细表，记录阶段、日志、进度和结构化 payload。
  - 用于任务中心、Haor 任务观察和修复工作区的流式回看。

- 关系补充
  - `task_runs 1:N task_events`
  - `discovery_jobs / assets / remediation_sessions / agent_sessions` 等对象都可能通过 `scope_type + scope_id` 与 `task_runs` 建立弱关联

## 使用建议

- 如果你要直接建库，先执行 `asset_schema.sql`，再执行 `asset_schema_seed.sql`。
- 如果你要把这套结构并入当前平台，优先把 `services/findings/tasks/scan_results` 映射到现有 `asset_ports/risk_findings/discovery_jobs` 等运行时模型的演进路径，再做迁移脚本，避免直接重命名造成接口回归。
- 如果你要继续补齐文档，请把这份“核心结构设计”与运行时模型一起看：
  - 智能体：`backend/app/db/models/agent_session.py`、`agent_goal.py`、`agent_message.py`
  - 修复：`backend/app/db/models/remediation_session.py`、`remediation_message.py`
  - 任务观测：`backend/app/db/models/task_run.py`、`task_event.py`
