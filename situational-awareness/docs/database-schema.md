# PostgreSQL 数据库结构设计

该设计对应一套更聚焦的核心表结构，围绕 `assets`、`services`、`findings`、`tasks`、`scan_results` 五张表组织。它和当前运行时模型分离，便于先讨论结构，再决定是否迁移现网代码。

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

- PostgreSQL DDL: [asset_schema.sql](/root/Desktop/态势感知/situational-awareness/infra/postgres/asset_schema.sql)
- 示例数据: [asset_schema_seed.sql](/root/Desktop/态势感知/situational-awareness/infra/postgres/asset_schema_seed.sql)
- SQLAlchemy ORM: [schema_models.py](/root/Desktop/态势感知/situational-awareness/backend/app/db/schema_models.py)

## 使用建议

- 如果你要直接建库，先执行 `asset_schema.sql`，再执行 `asset_schema_seed.sql`。
- 如果你要把这套结构并入当前平台，优先把 `services/findings/tasks/scan_results` 映射到现有 `asset_ports/risk_findings/discovery_jobs` 等运行时模型的演进路径，再做迁移脚本，避免直接重命名造成接口回归。
