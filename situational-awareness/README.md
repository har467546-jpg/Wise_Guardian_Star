# 内网资产态势感知平台 V1

一个面向测试环境的资产态势感知平台，围绕“发现 -> 识别 -> 校验 -> 修复 -> 观测”闭环构建，提供桌面端控制台、后端任务编排与配套规则治理能力。

## 核心能力
- 资产发现：CIDR 探测、主机存活识别、端口与服务指纹采集
- 资产管理：资产台账自动更新、标签管理、详情页纵深分析
- 信息采集：SSH 授权验证、主机级信息采集与最近采集结果回看
- 风险识别：规则库匹配、风险分级、热点资产与趋势聚合
- 漏洞修复：Runner 安装、修复会话编排、任务输出追踪
- 智能体协同：站内自治助手 Haor，支持页面理解、UI 代理、后端编排与审批控制
- 平台观测：CPU、内存、磁盘、网络实时指标与统一日志中心
- 移动配套：发现队列、高危风险与设备异常告警流的移动端总览能力

## 目录
- `backend/` FastAPI + SQLAlchemy + Celery，负责 API、任务编排、规则执行与智能体服务
- `frontend/` Next.js + Ant Design，提供桌面端控制台与 Haor 前端运行时
- `infra/` Docker Compose、本地 PostgreSQL 初始化与 settings helper
- `docs/` 架构、API、数据库与运行说明

## 技术栈
- 前端：Next.js 15、React 19、TypeScript、Ant Design 5
- 后端：FastAPI、SQLAlchemy 2、Celery、Redis、PostgreSQL、Alembic
- 安全与智能：SSH 凭据加密、规则库、可切换 LLM provider、Haor 站内自治助手

## 当前模块
- 总览页：平台实时监控、发现队列、风险热点资产、风险态势波形
- 扫描发起台：提交 CIDR 任务，自动进入主机发现、端口与风险校验流水线
- 资产列表/详情：查看资产、端口、SSH 授权、信息采集和风险发现
- 修复工作台：资产级修复入口、Runner 安装与修复会话管理
- 漏洞库：YAML 真源规则检索、导入导出、启停与索引治理
- 任务中心/日志：任务详情、事件日志、平台运行日志统一查看
- Haor：全站可调起的站内自治助手，会话、审批、任务状态与流式反馈全链路联动

## 快速开始
1. 按需修改环境变量文件
```bash
vi backend/.env.example
vi frontend/.env.example
```
> 当前 `docker compose` 默认直接读取 `backend/.env.example` 和 `frontend/.env.example`。
> `backend/.env.runtime` 仅作为本地运行时覆盖文件使用，不再作为仓库默认配置的一部分提交。

2. 启动默认生产式环境
```bash
cd infra
docker compose up -d --build
```

如需显式启动开发环境：
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```

3. 首次访问初始化管理员
- 打开前端登录页后，若系统尚未初始化，会自动切换到“初始化管理员”表单
- 初始化成功后会自动登录进入总览页

4. 访问入口
- 默认生产式前端：http://localhost:3000
- 默认生产式后端：http://localhost:8000/docs
- 开发前端：http://localhost:3001
- 开发后端：http://localhost:8001/docs
- PostgreSQL：`localhost:5433`
- Redis：`localhost:6380`
- 前端默认通过 Next.js 代理把 `/api/v1/*` 转发到后端容器，无需手工填写 `NEXT_PUBLIC_API_BASE`

## 常用开发命令
- 启动默认生产式服务：
```bash
cd infra
docker compose up -d --build
```
- 启动显式开发环境：
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```
- 查看容器状态：
```bash
cd infra
docker compose ps
```
- 查看后端日志：
```bash
docker logs -f sa-backend
```
- 查看 worker 日志：
```bash
docker logs -f sa-worker
```
- 查看开发态后端日志：
```bash
docker logs -f sa-backend-dev
```
- 查看开发态前端日志：
```bash
docker logs -f sa-frontend-dev
```
- 停止并移除容器：
```bash
cd infra
docker compose down
```

## Docker 默认生产式运行
- Docker Compose 默认启动生产式服务：
  - 前端服务使用 `next start`
  - 后端服务使用不带 `--reload` 的 `uvicorn`
  - 默认前后端容器不挂载源码目录，重启后仍按镜像内构建结果运行
- 默认访问地址：
  - 前端入口：`http://localhost:3000`
  - 后端文档：`http://localhost:8000/docs`
- 这套默认入口更适合日常演示、联调验收和接近真实部署方式的验证。

## Docker 开发模式
- 开发模式改为显式 `dev` profile：
  - 前端服务为 `frontend-dev`，使用 `next dev`
  - 后端服务为 `backend-dev`，使用 `uvicorn --reload`
  - worker 服务为 `worker-dev`
  - 前后端源码目录会挂载到容器内，适合本地改代码联调
- 启动命令：
```bash
cd infra
docker compose --profile dev up -d --build backend-dev worker-dev frontend-dev
```
- 开发访问地址：
  - 前端开发入口：`http://localhost:3001`
  - 后端开发文档：`http://localhost:8001/docs`
- 前端开发模式会把 `node_modules`、`.next` 与 `.next-dev` 缓存留在容器卷内，不污染项目目录。
- 若需要从局域网访问前端开发入口，请在前端环境变量中设置 `NEXT_ALLOWED_DEV_ORIGINS`，可直接使用私网通配规则，例如：
```bash
NEXT_ALLOWED_DEV_ORIGINS=localhost,127.0.0.1,192.168.*.*,10.*.*.*,172.*.*.*
```

## Haor 说明
- Haor 不是普通聊天机器人，而是站内自治助手
- 前端会为其提供当前页面路由、业务语义、可见动作、表单与 DOM 上下文
- Haor 可在白名单范围内执行站内 UI 动作，并把结果回传后端继续决策
- 复杂写操作进入后端编排链，低风险动作可自动推进，高风险动作进入审批
- `mock` 模式下会保留完整链路，但不会真正执行高风险写动作

## 说明
- 前端用户可见文案默认使用中文；仅保留 `IP / CIDR / CVE / CWE / YAML / JSON / SSH / nmap` 等必要技术缩写。
- 当前扫描分层执行：
  - `liveness` 默认模式：`nmap_icmp`
  - `liveness` 默认命令：`nmap -sn -PE -n -T5 --min-rate 100000 <cidr> -oX -`
  - 扫描阶段不再发起任何主动 DNS 查询；纯探活阶段默认只返回存活 IP
  - `full_port_scan` 在 `full` 模式下优先使用 `nmap -Pn -n -T5 --min-rate 100000 --open -p- <ip> -oX -`
  - `liveness_ports` 仅在 `hybrid` 模式下生效，默认值：`22,80,443,8080,8443`
  - `service` 服务识别端口默认：`Top1000 TCP 端口 + 自定义重点端口 + 高位后门特征端口`
  - `high_backdoor` 后门特征高位端口默认：`1337,4444,...,65000`
- 命中后门特征端口时，平台会跳过版本识别并将版本字段置空，仅保留端口与服务名识别结果。
- 若运行 `nmap_icmp` 模式时缺少 `nmap`、命令超时或 XML 解析失败，主机发现任务会直接失败，不会静默回退到逐 IP `ping`。
- 扫描阶段保留的主机名只来自被动证据，例如已有资产主机名、协议探测得到的 `hostname_hint`、TLS 证书或 HTTP 响应中的名称。
- 本机资产排除不再依赖 hostname 的 DNS 反查；如需稳定排除平台自身，请显式配置 `LOCAL_ASSET_IPS` 或写入 runtime hints。
- 若容器内可用 `nmap`，低置信、仅端口猜测或缺少产品/版本的端口会自动触发定向 `-sV --version-intensity 7` XML 补扫。
- `nmap -sV` 与 NSE 默认超时均为 `8` 秒，超时后仅跳过当前富化，不阻塞整轮扫描。
- 服务识别优先使用被动 banner + 轻量协议探测，当前已覆盖 `ssh/ftp/http/https/redis/mysql/postgresql/smtp/pop3/imap/telnet/memcached/rpcbind/irc/java-rmi/ajp13/rexec/rlogin/rsh`，不足时再回退到 nmap。
- 扫描端口模式和三类端口都可通过后端环境变量覆盖：
  - `DISCOVERY_PORTSET_MODE`
  - `DISCOVERY_TOP_PORTS_LIMIT`
  - `DISCOVERY_LIVENESS_PORTS`
  - `DISCOVERY_LIVENESS_MODE`
  - `DISCOVERY_NMAP_MIN_RATE`
  - `DISCOVERY_NMAP_LIVENESS_TIMEOUT_SECONDS`
  - `DISCOVERY_NMAP_FULL_SCAN_TIMEOUT_SECONDS`
  - `DISCOVERY_NMAP_TIMEOUT_SECONDS`
  - `DISCOVERY_NSE_TIMEOUT_SECONDS`
  - `DISCOVERY_SERVICE_PORTS`
  - `DISCOVERY_HIGH_BACKDOOR_PORTS`
- `DISCOVERY_PORTSET_MODE` 支持：
  - `curated`：仅扫描自定义重点端口与高位后门特征端口
  - `top1000_plus_custom`：默认模式，扫描 Top1000 TCP 端口并叠加自定义重点端口与高位后门特征端口
  - `full`：扫描 `1-65535`
- `DISCOVERY_TOP_PORTS_LIMIT` 默认 `1000`。
- `DISCOVERY_NMAP_VERSION_INTENSITY` 默认 `7`，用于控制 nmap 版本探测强度。
- 端口配置采用逗号分隔的离散端口列表（例如 `10001,20001,30001,40001,50001`）。
- 风险规则初始位于 `backend/app/rules/risk_rules.yaml`。
- 漏洞库页面现支持：
  - YAML/JSON 规则导入预检与正式导入
  - 按选中规则或当前筛选条件导出 YAML/JSON
  - 批量启用/停用规则
  - 规则索引健康检查与手动重建
- LLM 默认 `mock`，可通过后端环境变量切换 provider。
- 扫描任务已内置去重：同一 CIDR 若已有排队中或运行中的任务，将复用已有任务而不重复创建。
- Docker Compose 默认使用前端代理转发：
  - 浏览器请求同源 `/api/v1/*`
  - Next.js 再转发到 `BACKEND_INTERNAL_URL=http://backend:8000`
- 只有前端独立部署到 Docker 外时，才需要显式设置 `NEXT_PUBLIC_API_BASE` 指向外部后端地址。

## 相关文档
- 架构说明：[docs/architecture.md](docs/architecture.md)
- API 契约：[docs/api-contract.md](docs/api-contract.md)
- 数据库结构：[docs/database-schema.md](docs/database-schema.md)
- 运行手册：[docs/runbook.md](docs/runbook.md)

## 数据库迁移
- 后端目录已提供 `backend/alembic.ini`，可直接执行 Alembic：
```bash
docker exec sa-backend sh -lc 'cd /app && alembic upgrade head'
```
- 现有应用启动仍会保留 `create_all()` 兜底，但推荐把结构变更收敛到 Alembic。
- 当前迁移链已补齐对现有 schema 的幂等保护，适用于已由应用初始化过的数据库和全新数据库。
- 如果代码已升级、但仍沿用旧的 Docker 数据卷，必须显式执行一次 `alembic upgrade head`；`create_all()` 不能替代已有库的列升级。
- 漏洞情报同步排障建议按下面顺序检查：
  1. 先访问 `/api/v1/vuln-library/status`，确认 `schema_ready` 是否为 `true`
  2. 若为 `false`，执行 `docker exec sa-backend sh -lc 'cd /app && alembic upgrade head'`
  3. 重启 `sa-backend` 与 `sa-worker`
  4. 重新点击“同步情报”
  5. 仅当 schema 已就绪后，再继续检查外网连通性、上游 NVD / KEV / EPSS 超时等问题

## CORS 预检排查
- 默认环境建议使用 `CORS_ALLOW_ALL=false`，并通过 `CORS_ALLOW_ORIGINS` 维护允许访问的来源白名单。
- 若前端出现 `NetworkError when attempting to fetch resource` 且后端有 `OPTIONS ... 400`，优先检查后端容器读取的环境变量：
  - `CORS_ALLOW_ALL=true`，或
  - `CORS_ALLOW_ALL=false` 且 `CORS_ALLOW_ORIGINS` 包含当前前端实际来源（完整协议+主机+端口）。
- `CORS_ALLOW_ORIGINS` 支持 `*` 通配符，可一次覆盖常见局域网地址，例如：
```bash
CORS_ALLOW_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://192.168.*.*:3000,http://10.*.*.*:3000,http://172.16.*.*:3000,http://172.17.*.*:3000,http://172.18.*.*:3000,http://172.19.*.*:3000,http://172.20.*.*:3000,http://172.21.*.*:3000,http://172.22.*.*:3000,http://172.23.*.*:3000,http://172.24.*.*:3000,http://172.25.*.*:3000,http://172.26.*.*:3000,http://172.27.*.*:3000,http://172.28.*.*:3000,http://172.29.*.*:3000,http://172.30.*.*:3000,http://172.31.*.*:3000
```
- 生产环境建议关闭全放开模式：`CORS_ALLOW_ALL=false`，并显式设置 `CORS_ALLOW_ORIGINS` 白名单。
