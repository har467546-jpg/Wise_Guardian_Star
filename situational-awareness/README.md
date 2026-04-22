# 内网资产态势感知平台 V1

面向测试环境的内网资产态势感知平台，围绕“发现 -> 识别 -> 校验 -> 修复 -> 观测 -> 智能体协同”构建桌面控制台、后端任务编排与运行时治理能力。

## 核心能力
- 资产发现：CIDR 探测、主机存活识别、端口与服务指纹采集
- 信息采集：SSH 授权验证、主机信息采集、最近采集结果回看
- 风险识别：规则匹配、风险分级、主动验证、治理与修复模板生成
- 修复闭环：Runner 安装、修复会话、执行跟踪、复验与回滚工件
- 平台观测：任务中心、平台日志、实时监控、移动端告警流
- 智能体协同：Haor 站内自治助手，支持页面理解、审批控制与任务联动

## 技术栈
- 前端：Next.js 15、React 19、TypeScript、Ant Design 5
- 后端：FastAPI、SQLAlchemy 2、Pydantic 2、Celery 5
- 数据与基础设施：PostgreSQL 16、Redis 7、Docker Compose
- 安全与智能：JWT、bcrypt、Fernet、asyncssh、可切换 LLM provider、Haor

## 快速开始
1. 按需检查环境变量模板：
```bash
vi backend/.env.example
vi frontend/.env.example
```
2. 启动默认生产式环境：
```bash
cd infra
docker compose up -d --build
```
3. 如需开发模式：
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```
4. 访问入口：
- 生产式前端：`http://localhost:3000`
- 生产式后端文档：`http://localhost:8000/docs`
- 开发前端：`http://localhost:3001`
- 开发后端文档：`http://localhost:8001/docs`

## 文档导航

标准文档入口：
- 文档总索引：[docs/README.md](docs/README.md)
- 总体架构：[docs/architecture.md](docs/architecture.md)
- 前端设计：[docs/frontend-design.md](docs/frontend-design.md)
- 后端设计：[docs/backend-design.md](docs/backend-design.md)
- 数据模型：[docs/database-schema.md](docs/database-schema.md)
- 接口说明：[docs/api-contract.md](docs/api-contract.md)
- 运行手册：[docs/runbook.md](docs/runbook.md)
- 测试与验收：[docs/testing-and-acceptance.md](docs/testing-and-acceptance.md)
- Haor 设计：[docs/haor-agent-design.md](docs/haor-agent-design.md)

历史记录入口：
- 记录索引：[docs/records/README.md](docs/records/README.md)

## 目录说明
- `backend/`：FastAPI、业务服务、任务编排、数据库模型与测试
- `frontend/`：Next.js 桌面控制台、Haor 前端运行时与页面组件
- `infra/`：Docker Compose、PostgreSQL 初始化、settings helper
- `docs/`：标准项目文档与标准化历史记录
- `situational-awareness-mobile/`：移动端配套应用

## 说明
- 项目文档以代码实现为准；若文档与实现不一致，应优先修正文档。
- 根目录 `README.md` 只作为项目总入口，详细研发交接内容统一收敛到 `docs/`。
