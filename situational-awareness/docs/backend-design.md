# 后端设计说明

## 文档目的与适用读者
- 面向需要维护 `backend/` 的后端工程师、平台工程师与联调人员。
- 重点说明 FastAPI 应用结构、任务编排、配置安全、日志监控与关键代码入口。

## 当前实现范围
- 后端当前覆盖认证、发现、采集、风险、修复、任务、日志、设置、校园扫描、移动端概览和 Haor 智能体。
- 核心技术栈为 FastAPI + SQLAlchemy 2 + Pydantic 2 + Celery 5 + Redis + PostgreSQL。

## 核心模块与数据流

### 应用入口与基础设施
- `backend/app/main.py`
  - 创建 FastAPI 应用，注册 CORS、异常处理、中间件、`/health` 与 `/api/v1`。
  - 启动时执行数据库初始化、运行时环境自举、平台日志捕获和设备告警 Hub。
- `backend/app/core/config.py`
  - 管理 `.env.example` 与 `.env.runtime`，自动补齐 `ENCRYPTION_KEY`。
- `backend/app/core/security.py`
  - 负责 JWT、bcrypt 密码校验。
- `backend/app/core/crypto.py`
  - 负责 Fernet 加解密，用于 SSH 凭据与敏感配置。
- `backend/app/core/celery_app.py`
  - 统一 Celery 配置、任务注册、队列路由和定时任务。

### HTTP API 分层
- `backend/app/api/v1/router.py`
  - 按业务域挂载 `auth / dashboard / agent / discovery / campus / mobile / monitoring / assets / collection / risks / remediation / runner / settings / tasks / logs / vuln-library`。
- endpoint 层负责：
  - 参数校验
  - 鉴权与角色校验
  - 错误转 HTTP 语义
  - 调用 service 或 task
- service 层负责：
  - 业务编排
  - 运行时状态变更
  - 规则、修复、Runner、日志与智能体逻辑
- repository 层负责：
  - 通用查询
  - 任务与事件读写
  - 日志与资产相关对象的基础操作

### 异步任务体系
- Celery 任务分为 `discovery / collection / risk / report` 等队列。
- 典型任务入口：
  - `backend/app/tasks/discovery_tasks.py`
  - `backend/app/tasks/scan_tasks.py`
  - `backend/app/tasks/collection_tasks.py`
  - `backend/app/tasks/risk_tasks.py`
  - `backend/app/tasks/remediation_tasks.py`
  - `backend/app/tasks/agent_tasks.py`
- 统一任务运行状态通过 `task_runs` 与 `task_events` 记录，前端任务中心、修复工作区和 Haor 会复用同一条观测链路。

### 发现、采集、风险、修复
- 发现链路：
  - `discover_hosts -> upsert_assets -> full_port_scan -> probe_open_services -> evaluate_risks -> finalize_job`
  - 支持多源探活、全端口扫描、服务增强和 NSE 富化。
- 采集链路：
  - 使用 `asyncssh` 做 SSH 授权验证、主机信息采集和配置解析。
- 风险链路：
  - 通过规则引擎与验证服务把端口、快照、服务配置转换为 `risk_findings`。
- 修复链路：
  - 通过 SSH 执行器或 Host Runner 执行修复步骤，并补齐备份、回滚工件和复验。

### 平台设置、日志与监控
- `backend/app/services/platform_settings_service.py`
  - 管理运行时设置、AI 配置校验、模型列表和 settings helper 回调。
- `backend/app/services/platform_log_service.py`
  - 捕获 backend/worker 日志，写入数据库并通过 Redis Pub/Sub 推送。
- `backend/app/services/platform_monitoring_service.py`
  - 采集 CPU、内存、磁盘、网络实时指标。

## 关键代码入口
- `backend/app/main.py`
- `backend/app/api/v1/router.py`
- `backend/app/core/config.py`
- `backend/app/core/celery_app.py`
- `backend/app/tasks/discovery_tasks.py`
- `backend/app/tasks/scan_tasks.py`
- `backend/app/tasks/remediation_tasks.py`
- `backend/app/services/platform_settings_service.py`
- `backend/app/services/platform_log_service.py`
- `backend/app/services/platform_monitoring_service.py`
- `backend/app/services/haor_agent_service.py`
- `backend/app/services/runner_service.py`

## 配置、依赖与限制
- 默认通过 Docker Compose 提供 PostgreSQL 与 Redis。
- JWT 和敏感字段保护依赖 `SECRET_KEY`、`ENCRYPTION_KEY`。
- 平台设置写入 `backend/.env.runtime`；运行时实际值可能覆盖 `.env.example`。
- `backend/app/api/v1/endpoints/reports.py` 目前存在实现文件，但未挂载到 `api_router`，不属于当前对外标准 API。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 总体架构：[architecture.md](architecture.md)
- 接口说明：[api-contract.md](api-contract.md)
- 数据模型：[database-schema.md](database-schema.md)
- Haor 设计：[haor-agent-design.md](haor-agent-design.md)
- 运行手册：[runbook.md](runbook.md)
