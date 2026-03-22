# 内网资产态势感知平台 V1

一个面向测试环境的资产发现与风险识别平台，覆盖以下能力：
- 资产发现：CIDR 探测、主机与端口服务识别
- 资产管理：台账自动更新与标签管理
- 信息采集：SSH 基础信息采集
- 风险识别：规则库版本匹配与分级
- AI 报告：风险摘要与自动报告
- 平台监控：CPU、内存、磁盘与网络实时指标
- 平台日志：后端与 worker 运行日志统一查询
- 移动总览：发现队列、高危风险与设备异常告警流

## 目录
- `backend/` FastAPI + SQLAlchemy + Celery
- `frontend/` Next.js + Ant Design
- `infra/` Docker Compose
- `docs/` 架构、API、运行说明

## 快速开始
1. 按需修改环境变量文件
```bash
vi backend/.env.example
vi frontend/.env.example
```
> 当前 `docker compose` 默认直接读取 `backend/.env.example` 和 `frontend/.env.example`。

2. 默认启动开发环境
```bash
cd infra
docker compose up -d --build
```
3. 首次访问初始化管理员
- 打开前端登录页后，若系统尚未初始化，会自动切换到“初始化管理员”表单
- 初始化成功后会自动登录进入总览页
4. 打开
- 前端：http://localhost:3000
- 后端：http://localhost:8000/docs
- 前端默认通过 Next.js 代理把 `/api/v1/*` 转发到后端容器，无需手工填写 `NEXT_PUBLIC_API_BASE`

## Docker 开发模式
- Docker Compose 默认以开发模式启动：
  - 前端服务使用 `next dev`
  - 后端服务使用 `uvicorn --reload`
  - 前后端源码目录都会挂载到容器内，适合本地联调
- 前端开发容器启动时会自动安装依赖到容器卷，避免宿主机残留的 `node_modules` 污染运行环境
- 默认访问地址：
  - 前端开发入口：`http://localhost:3000`
  - 后端文档：`http://localhost:8000/docs`
- 前端开发模式会把 `node_modules` 与 `.next` 缓存留在容器卷内，不污染项目目录。
- 若需要从局域网访问前端开发入口，请在前端环境变量中设置 `NEXT_ALLOWED_DEV_ORIGINS`，填入完整来源列表，例如：
```bash
NEXT_ALLOWED_DEV_ORIGINS=http://localhost:3000,http://127.0.0.1:3000,http://192.168.10.131:3000
```
- 如需临时验证生产式前端构建，可额外启动预览入口：
```bash
cd infra
docker compose --profile prod up -d --build frontend-prod
```
- 生产式前端预览地址为 `http://localhost:3001`。

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

## 数据库迁移
- 后端目录已提供 `backend/alembic.ini`，可直接执行 Alembic：
```bash
docker exec sa-backend sh -lc 'cd /app && alembic upgrade head'
```
- 现有应用启动仍会保留 `create_all()` 兜底，但推荐把结构变更收敛到 Alembic。
- 当前迁移链已补齐对现有 schema 的幂等保护，适用于已由应用初始化过的数据库和全新数据库。

## CORS 预检排查
- 开发环境默认 `CORS_ALLOW_ALL=true`，允许 `localhost/127.0.0.1/局域网IP` 访问后端 API。
- 若前端出现 `NetworkError when attempting to fetch resource` 且后端有 `OPTIONS ... 400`，优先检查后端容器读取的环境变量：
  - `CORS_ALLOW_ALL=true`，或
  - `CORS_ALLOW_ALL=false` 且 `CORS_ALLOW_ORIGINS` 包含当前前端实际来源（完整协议+主机+端口）。
- 生产环境建议关闭全放开模式：`CORS_ALLOW_ALL=false`，并显式设置 `CORS_ALLOW_ORIGINS` 白名单。
