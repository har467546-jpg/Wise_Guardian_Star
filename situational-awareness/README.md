# 内网资产态势感知平台 V1

一个面向测试环境的资产态势感知平台，围绕“发现 -> 识别 -> 校验 -> 修复 -> 观测”闭环构建，提供桌面端控制台、后端任务编排与配套规则治理能力。

## 核心能力
- 资产发现：CIDR 探测、主机存活识别、端口与服务指纹采集
- 资产管理：资产台账自动更新、标签管理、详情页纵深分析
- 信息采集：SSH 授权验证、主机级信息采集与最近采集结果回看
- 风险识别：规则库匹配、风险分级、热点资产与趋势聚合
- 漏洞修复：Runner 安装、修复会话编排、任务输出追踪
- 智能体协同：站内自治助手 Haor，支持页面理解、UI 代理、安全输入、后端编排与审批控制
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
- 修复工作台：资产修复入口、修复资产总览、交互式修复工作区、Runner 安装与修复会话管理
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

## Haor 当前能力边界
- 当前以单智能体 `Haor` 为核心，对外表现为一个站内助手，对内通过多个技能剧本（playbook）驱动具体任务，不是多个互相独立的人格型 agent。
- 已落地的剧本包括：
  - 扫描并分析网段
  - 分析资产风险
  - 验证资产风险
  - 安装 Host Runner
  - 准备自动修复会话
  - 配置 SSH 凭据
  - 解读首页总览
- Haor 会结合当前页面路由、查询参数、所选资产、语义动作、表单和 DOM 摘要来判断当前焦点对象，再决定读数据、发起 UI 动作还是提交后端任务。
- 当前受支持的后端读能力主要覆盖资产、风险、任务、修复资产、修复会话和漏洞规则等对象查询；写动作白名单包括：
  - `create_discovery_job`
  - `verify_asset_risks`
  - `install_runner`
  - `create_or_resume_remediation_session`
  - `approve_remediation_session`
  - `configure_ssh_credential`
- 低风险动作目前可自动推进：
  - 发起扫描
  - 触发风险验证
  - 安装 Host Runner
- 高风险动作目前要求显式审批后再继续：
  - 创建或恢复自动修复会话
  - 审批自动修复执行
- SSH 密码、私钥和 sudo 密码不会直接写入聊天消息；Haor 会引导进入专用安全弹层录入，保存后立即做权限验证，并在验证成功后自动续接原本被阻塞的目标。
- Haor 具备完整运行时状态：
  - 会话：保存当前上下文、待执行计划、最近任务和消息流
  - 目标：记录当前用户目标、成功标准、阻塞原因和恢复策略
  - 流式反馈：通过 WebSocket 推送回复增量、UI 动作请求、审批等待和任务进度

## 从开发流程看 AI 智能体

如果从平台研发实现来看，Haor 的开发流程不是“接一个大模型接口”这么简单，而是把页面上下文、任务编排、审批控制和安全输入串成一条可落地的自治链路。

### 1. 前端先把“当前页面”翻译成智能体可用上下文
- 入口在 `frontend/src/components/HaorAgentLauncher.tsx` 和 `frontend/src/components/HaorAgentDrawer.tsx`。
- 用户打开 Haor 后，前端会采集当前路由、查询参数、选中资产、页面语义信息和可执行 UI 动作，再提交给后端。
- 这一步的目标不是单纯传聊天文本，而是告诉智能体“我现在在哪个页面、正在看哪个对象、页面允许做什么”。

### 2. 后端为每次交互建立会话、目标和消息流
- Haor API 入口在 `backend/app/api/v1/endpoints/agent.py`。
- 后端收到消息后，会把本轮交互绑定到 `agent_sessions`、`agent_goals`、`agent_messages` 三类运行时对象。
- 这样做的意义是把“对话”升级成“有状态目标执行”：
  - `agent_sessions` 负责保存当前页面上下文、工作上下文和浏览器运行时状态
  - `agent_goals` 负责保存当前要完成的目标、成功标准、阻塞原因和恢复策略
  - `agent_messages` 负责沉淀消息、计划、动作更新和错误反馈

### 3. 先匹配 playbook，再决定是读、写还是驱动 UI
- 核心剧本定义在 `backend/app/services/agent_playbook_service.py`。
- 当前平台不是给每个场景单独造一个 agent，而是用一个主智能体加多个 playbook 来承接具体能力。
- 每个 playbook 都会声明：
  - 入口意图：用户说什么话会命中这个能力
  - 必需上下文：例如 `cidr`、`asset_id`
  - 读链路和写链路：需要调用哪些读能力、哪些写动作
  - 成功标准、阻塞条件和恢复策略
- 这意味着开发新能力时，第一步通常不是改提示词，而是先把能力抽象成一个明确的 playbook。

### 4. 动作执行要走策略层，不是模型说了就直接执行
- 主编排逻辑在 `backend/app/services/haor_agent_service.py`。
- 这里定义了支持的读工具、写动作、UI 动作，以及每类动作的风险等级和执行策略。
- 当前平台把动作分成三类：
  - 读操作：如查资产、查风险、查任务、查修复会话
  - 站内 UI 动作：如跳转、点击、输入、提交、等待页面反馈
  - 后端写动作：如创建扫描任务、验证风险、安装 Runner、创建修复会话
- 低风险动作可自动推进，高风险动作必须进入审批，敏感输入则必须走专用安全弹层，不能直接出现在聊天消息里。

### 5. 真正的重活交给异步任务系统执行
- 智能体异步编排任务在 `backend/app/tasks/agent_tasks.py`。
- 一旦 Haor 需要发起扫描、安装 Runner、准备修复或继续审批后的执行，都会落到统一任务体系里。
- 任务执行状态统一写入 `task_runs` 和 `task_events`，因此任务中心、修复工作台和 Haor 会话都能看到同一条执行链路。
- 这一步保证了智能体不是“口头建议”，而是真正能接入平台已有任务编排体系。

### 6. 执行结果再回流到会话，形成闭环
- Haor 会通过 WebSocket 把回复增量、UI 动作请求、审批等待和任务进度持续推给前端。
- 如果执行被阻塞，例如缺少 SSH 凭据、Runner 未安装、需要审批，系统不会简单报错结束，而是把阻塞原因写回目标状态，并给出恢复入口。
- 用户完成审批或安全输入后，会话还能自动续接原目标，而不是让用户从头再说一遍。

## 开发者新增一个智能体能力的推荐步骤

对平台开发者来说，新增 Haor 能力通常遵循下面这条链路：

1. 先定义场景边界：明确这是“读分析能力”还是“会触发写操作”的执行能力。
2. 在 `backend/app/services/agent_playbook_service.py` 新增 playbook，补齐入口意图、必需上下文、成功标准和阻塞条件。
3. 在 `backend/app/services/haor_agent_service.py` 注册对应读工具或写动作，并声明风险等级、是否允许自动执行、是否需要审批。
4. 如果动作会触发真实业务执行，就接入现有 service 和 Celery task，而不是把业务逻辑直接写进聊天流程。
5. 如果场景需要页面操作或敏感输入，就同步补前端运行时能力，例如 UI action 执行器和安全弹层。
6. 最后补齐任务观测、会话恢复和测试，确保这项能力在“成功、阻塞、审批、恢复”几条路径下都可回放和追踪。

换句话说，这个平台里的 AI 智能体开发，本质上是在做“带状态的业务编排层”。模型负责理解意图和生成解释，但真正让能力可上线的是 playbook、策略控制、任务系统和可恢复运行时。

## 说明
- 前端用户可见文案默认使用中文；仅保留 `IP / CIDR / CVE / CWE / YAML / JSON / SSH / nmap` 等必要技术缩写。
- 当前扫描分层执行：
  - `liveness` 默认模式：`multi_source`
  - 同网段优先使用 `arp-scan`，缺失时回退 `arping`
  - 跨网段和补充探活默认结合 `fping` 与 `nmap` 多探针主机发现
  - 默认 `nmap` 主机发现命令会使用 `-PE + -PS + -PA` 组合，而不是仅依赖单一 ICMP Echo
  - 扫描阶段不再发起任何主动 DNS 查询；纯探活阶段默认只返回存活 IP 和来源证据
  - `full_port_scan` 在 `full` 模式下优先使用 `nmap -Pn -n -T5 --min-rate 100000 --open -p- <ip> -oX -`
  - `liveness_ports` 仅在 `hybrid` 模式下生效，默认值：`22,80,443,8080,8443`
  - `service` 服务识别端口默认：`Top1000 TCP 端口 + 自定义重点端口 + 高位后门特征端口`
  - `high_backdoor` 后门特征高位端口默认：`1337,4444,...,65000`
- 发现结果会保留 `discovery_sources` 与 `discovery_evidence`，用于说明主机是通过 `arp_scan / arping / fping / nmap_host_discovery / tcp_connect` 中哪些链路识别出来的。
- 不再根据 `.1`、`.254` 或网段边界自动排除“网关候选”地址；只有命中平台本机或扫描节点本机的显式证据时才会被排除。
- 端口状态已改为按本轮扫描范围做对账：本轮确认关闭的历史开放端口会收敛为 `closed`，不会长期保留脏 `open` 状态。
- 命中后门特征端口时，平台会跳过版本识别并将版本字段置空，仅保留端口与服务名识别结果。
- 多源发现模式下，任一单工具失败不会直接判整轮发现失败；只有全部已启用链路都不可用或全部执行失败时，发现任务才会失败。
- 扫描阶段保留的主机名只来自被动证据，例如已有资产主机名、协议探测得到的 `hostname_hint`、TLS 证书或 HTTP 响应中的名称。
- 本机资产排除不再依赖 hostname 的 DNS 反查；如需稳定排除平台自身，请显式配置 `LOCAL_ASSET_IPS` 或写入 runtime hints。
- 若要在真实多网段环境中使用扫描节点，推荐复用现有 Host Runner，由扫描节点接单执行发现脚本并直接回传结果。
- Docker 默认 `bridge` 网络仅适合演示或联调，不代表容器天然可见真实局域网；真实网络验收应在具备目标网段可见性的宿主机或扫描节点上执行。
- 若容器内可用 `nmap`，低置信、仅端口猜测或缺少产品/版本的端口会自动触发定向 `-sV --version-intensity 7` XML 补扫。
- `nmap -sV` 与 NSE 默认超时均为 `8` 秒，超时后仅跳过当前富化，不阻塞整轮扫描。
- 服务识别优先使用被动 banner + 轻量协议探测，当前已覆盖 `ssh/ftp/http/https/redis/mysql/postgresql/smtp/pop3/imap/telnet/memcached/rpcbind/irc/java-rmi/ajp13/rexec/rlogin/rsh`，不足时再回退到 nmap。
- 扫描端口模式和三类端口都可通过后端环境变量覆盖：
  - `DISCOVERY_PORTSET_MODE`
  - `DISCOVERY_TOP_PORTS_LIMIT`
  - `DISCOVERY_LIVENESS_PORTS`
  - `DISCOVERY_LIVENESS_MODE`
  - `DISCOVERY_ENABLE_ARP_DISCOVERY`
  - `DISCOVERY_ENABLE_FPING`
  - `DISCOVERY_NMAP_HOST_DISCOVERY_PROFILE`
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
