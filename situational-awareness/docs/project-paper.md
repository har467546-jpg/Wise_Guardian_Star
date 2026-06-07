# 内网资产态势感知平台的设计与实现

作者：XXX  
单位：XXX学院 计算机科学与技术专业，XXX 000000  
指导教师：XXX

## 摘要

针对高校、园区和企业内网中资产变化频繁、服务暴露面不透明、风险发现重复堆积以及整改过程缺少闭环审计等问题，设计并实现了一套内网资产态势感知平台。系统以“发现、识别、验证、修复、观测、智能体协同”为主线，采用前后端分离和异步任务架构，基于 FastAPI、SQLAlchemy、Celery、Redis、PostgreSQL、Next.js 和 Flutter 等技术构建桌面端控制台、移动端应用、后端 API 服务和异步 Worker。平台实现了 CIDR 网段发现、主机存活识别、端口扫描、服务指纹识别、SSH 深度采集、规则化风险验证、风险治理、修复会话编排、Host Runner 执行、任务观测、平台日志和移动端告警等功能。风险识别模块基于 YAML 规则库对服务版本、配置项、Nmap NSE 结果和软件包信息进行综合匹配，并通过稳定身份键 `identity_hash` 解决重复扫描导致的风险重复入库问题。修复模块将风险规则与整改模板关联，支持预检查、审批、预演、执行、证据归档、复验和回滚提示。测试与联调结果表明，系统能够在内网环境中完成资产发现、风险收敛、任务追踪和整改闭环，为中小规模内网安全运营提供了一种可落地的工程实现方案。

**关键词：** 态势感知；资产发现；风险验证；漏洞治理；自动化修复；智能体

## Design and Implementation of an Intranet Asset Situational Awareness Platform

Author: XXX  
Affiliation: School of Computer Science and Technology, XXX, XXX 000000, China

## Abstract

To address the problems of frequent asset changes, opaque service exposure, duplicated risk findings, and insufficient remediation auditing in campus, enterprise, and park intranet environments, this paper designs and implements an intranet asset situational awareness platform. The platform follows a closed-loop workflow of discovery, identification, verification, remediation, observation, and agent-assisted operations. It adopts a frontend-backend separated architecture with asynchronous task orchestration, and is implemented with FastAPI, SQLAlchemy, Celery, Redis, PostgreSQL, Next.js, and Flutter. The system supports CIDR-based asset discovery, host liveness detection, port scanning, service fingerprinting, SSH-based deep collection, rule-based risk verification, remediation session orchestration, Host Runner execution, task observability, platform logging, and mobile alerts. The risk verification module matches service versions, configurations, Nmap NSE outputs, and package information using YAML rules, and introduces `identity_hash` as a stable finding identity to reduce duplicated risk records. The remediation module connects risk rules with structured remediation templates and supports pre-checks, approval, dry-run execution, evidence archiving, re-verification, and rollback hints. Experimental and integration results show that the platform can effectively discover assets, converge risk findings, trace tasks, and support remediation governance in intranet environments.

**Key words:** situational awareness; asset discovery; risk verification; vulnerability governance; automated remediation; agent

## 1 引言

随着数字化业务持续扩展，高校、园区和企业内部网络中的服务器、办公终端、数据库、中间件、测试主机和物联网设备数量不断增加。内网资产具有分布广、变化快、责任主体多和运行状态复杂等特点。若缺少持续化资产发现与风险治理机制，容易出现端口暴露未知、服务版本滞后、配置弱化、授权边界不清以及整改过程不可追踪等问题，进而影响组织整体安全运营能力。

传统漏洞扫描工具通常能够完成单次端口探测和漏洞识别，但在持续治理场景下仍存在不足：一是扫描结果与资产台账割裂，难以沉淀为可维护的资产画像；二是网络侧证据与主机侧配置证据缺少统一模型，影响风险验证准确性；三是重复扫描容易生成重复风险项，增加研判负担；四是整改建议多以文本形式存在，缺少审批、执行、证据和复验链路；五是平台自身任务运行和日志观测不足，难以满足值班巡检和移动响应需求。

针对上述问题，本文基于实际工程项目设计并实现了一套内网资产态势感知平台。平台围绕资产发现、信息采集、风险验证、治理修复和持续观测构建完整闭环，并引入站内智能体 Haor 辅助用户完成跨页面、多步骤操作。本文主要工作如下：

1. 设计了面向内网安全运营的分层架构，将资产、端口、快照、风险、任务、修复会话、Runner、日志和智能体会话统一建模。
2. 实现了多源资产发现与服务识别流程，支持 CIDR 探测、端口扫描、协议指纹识别和 Nmap NSE 富化。
3. 构建了基于 YAML 规则库的风险验证机制，通过稳定身份键实现风险项收敛，降低重复扫描造成的数据冗余。
4. 实现了结构化修复闭环，支持风险模板生成、修复计划编排、审批执行、证据归档、复验和回滚提示。
5. 设计了桌面端、移动端和 Haor 智能体协同模式，提升安全运营人员在桌面治理和值班巡检场景下的操作效率。

## 2 相关技术与系统需求分析

### 2.1 相关技术

平台采用的关键技术如表 1 所示。

**表 1 平台关键技术栈**

| 层次 | 技术选型 | 主要作用 |
| --- | --- | --- |
| 桌面端 | Next.js 15、React 19、TypeScript、Ant Design 5 | Web 控制台、资产治理、风险研判、修复工作台 |
| 移动端 | Flutter、Riverpod、go_router、dio | 移动巡检、告警确认、任务与风险查看 |
| 后端 API | FastAPI、Pydantic 2、SQLAlchemy 2 | REST API、数据校验、ORM 持久化 |
| 异步任务 | Celery 5、Redis | 扫描、采集、验证、修复等长任务编排 |
| 数据存储 | PostgreSQL 16、Redis 7 | 业务数据持久化、任务队列、日志与告警流 |
| 安全能力 | JWT、bcrypt、Fernet、asyncssh | 认证鉴权、密码校验、敏感信息加密、SSH 采集 |
| 智能协同 | 可切换 LLM provider、Haor Playbook | 页面理解、任务联动、审批控制 |

### 2.2 功能需求

结合内网资产治理场景，系统功能需求如下。

1. 资产发现与管理：支持用户提交 CIDR 网段，自动完成主机探活、端口扫描、服务识别、资产入库和资产详情展示。
2. 信息采集：支持 SSH 凭据配置、凭据验证、批量采集和主机快照保存，为配置类风险和本地权限类风险提供证据。
3. 风险识别与治理：支持基于版本、配置、NSE 输出和软件包信息的风险识别，并提供风险分级、列表查询、详情查看、责任分配、例外申请和批量复验。
4. 修复闭环：支持从风险项生成修复计划，完成 Runner 安装、修复会话创建、阶段审批、预演执行、真实执行、证据查看和复验。
5. 平台观测：支持统一任务中心、任务事件、平台日志、实时监控指标和移动端高危告警。
6. 智能体协同：支持 Haor 根据页面上下文和用户意图完成查询、跳转、扫描创建、风险验证和修复准备，并对高风险动作实施审批控制。

### 2.3 非功能需求

系统非功能需求包括以下方面。

1. 可扩展性：扫描、采集、风险验证和修复执行均应通过异步任务执行，避免阻塞前端请求。
2. 可观测性：所有长任务应具有统一状态、阶段事件和日志输出，便于用户追踪执行过程。
3. 安全性：系统应支持用户认证、角色权限控制、Runner 鉴权、敏感配置加密和修复审批。
4. 可维护性：风险规则、接口契约和数据模型应保持结构化，便于后续扩展。
5. 端侧适配性：桌面端承担完整治理操作，移动端承担值班巡检和轻量确认，二者复用同一后端能力。

## 3 系统总体设计

### 3.1 系统架构

系统采用前后端分离与异步任务解耦架构，整体包括桌面端控制台、移动端应用、后端 API 服务、异步 Worker、PostgreSQL、Redis、Host Runner 和 Haor 智能体。系统总体结构如图 1 所示。

```text
                +--------------------+
                |   桌面端 Web 控制台 |
                +----------+---------+
                           |
                           | REST / WebSocket
                           |
+--------------------------v---------------------------+
|                    FastAPI 后端服务                  |
|  Auth | Assets | Discovery | Risks | Remediation | AI |
+-----------+------------------+-----------------------+
            |                  |
            | SQLAlchemy       | Celery Task
            |                  |
 +----------v---------+   +----v----------------+
 |   PostgreSQL 数据库 |   |  Worker 异步任务进程 |
 +--------------------+   +----+----------------+
                               |
                               | Scan / SSH / Runner
                    +----------v----------+
                    | 内网资产与 Host Runner |
                    +---------------------+

                +--------------------+
                |      Flutter 移动端 |
                +--------------------+
```

**图 1 系统总体架构**

桌面端负责完整治理操作，包括总览、发现、资产、风险、修复、漏洞库、任务、日志和设置等页面。移动端面向值班巡检和现场排障，提供总览、资产、风险、任务、修复轻量跟进和告警提醒。后端 API 负责认证、业务接口、数据持久化和 WebSocket 推送。Worker 负责执行扫描、采集、风险验证、修复执行和智能体长任务。PostgreSQL 保存业务数据，Redis 用于 Celery broker/backend、日志流和告警推送。

### 3.2 业务闭环流程

系统核心业务闭环如图 2 所示。

```text
网段输入 -> 资产发现 -> 服务识别 -> SSH 深采集 -> 风险验证
   ^                                              |
   |                                              v
复验结果 <- 证据归档 <- 修复执行 <- 审批确认 <- 修复计划
```

**图 2 资产风险治理闭环流程**

用户首先提交网段扫描任务，后端创建发现任务和统一任务运行记录。Worker 执行主机发现、端口扫描、服务识别和风险验证，并将资产、端口、快照、风险和任务事件写入数据库。安全运营人员根据风险列表进行研判，管理员在修复工作台创建修复会话并审批执行。修复完成后，系统记录执行证据并触发复验，从而形成从发现到治理的闭环。

### 3.3 模块设计

系统主要模块如表 2 所示。

**表 2 系统模块划分**

| 模块 | 主要职责 |
| --- | --- |
| 认证模块 | 管理员初始化、登录、JWT 签发、角色鉴权 |
| 发现模块 | CIDR 扫描、主机探活、端口扫描、服务识别、扫描区域管理 |
| 资产模块 | 资产列表、资产详情、端口信息、标签、资产状态维护 |
| 采集模块 | SSH 凭据配置、凭据验证、主机信息采集、快照保存 |
| 风险模块 | 规则加载、风险匹配、主动验证、风险治理、例外申请 |
| 修复模块 | 修复计划、修复会话、审批、执行、证据、复验 |
| Runner 模块 | Host Runner 注册、心跳、能力管理和任务拉取 |
| 任务模块 | 统一任务状态、任务事件、任务查询 |
| 日志与监控模块 | 平台日志、Redis 推送、CPU/内存/磁盘/网络指标 |
| 智能体模块 | Haor 会话、目标、Playbook、动作执行和审批恢复 |
| 移动端模块 | 移动总览、风险与任务查看、设备异常提醒 |

### 3.4 数据模型设计

系统数据模型围绕资产、风险、任务、修复、智能体和平台治理展开，核心实体关系如表 3 所示。

**表 3 核心数据实体**

| 领域 | 核心表 | 说明 |
| --- | --- | --- |
| 资产域 | `assets`、`asset_ports`、`snapshots`、`tags` | 保存资产主信息、端口服务、采集快照和标签 |
| 风险域 | `risk_findings`、`risk_rules`、`finding_governance`、`finding_waiver` | 保存风险发现、规则、治理责任和豁免信息 |
| 任务域 | `task_runs`、`task_events` | 保存异步任务状态和阶段事件 |
| 修复域 | `host_runners`、`remediation_sessions`、`remediation_messages` | 保存 Runner、修复会话和会话消息 |
| 智能体域 | `agent_sessions`、`agent_goals`、`agent_messages` | 保存 Haor 会话、目标和消息 |
| 平台域 | `platform_log_entries`、`scanner_zones`、`campus_data_sources`、`vuln_rule_index` | 保存平台日志、扫描区域、数据源和漏洞库索引 |

其中，`assets` 与 `asset_ports`、`snapshots`、`risk_findings`、`remediation_sessions` 均为一对多关系；`task_runs` 与 `task_events` 为一对多关系；`agent_sessions` 与 `agent_messages` 为一对多关系。风险发现表中的 `identity_hash` 字段用于标识同一资产、同一端口、同一规则和同一证据范围下的稳定风险身份。

## 4 关键流程与算法设计

### 4.1 资产发现与服务识别

资产发现流程以 CIDR 网段为输入。系统优先使用多源探活和 Nmap 能力，在工具不可用或权限不足时退化为 socket 探测。发现流程包括主机存活识别、端口扫描、服务指纹识别和结果入库四个阶段。

主机存活识别支持 ICMP、ARP、常用端口连接和已知主机列表等来源。端口扫描阶段通过异步端口扫描器执行 TCP 探测，并根据环境能力选择 SYN 探测或 connect 探测。对开放端口，系统继续执行协议级探测，覆盖 HTTP/HTTPS、SSH、FTP、Redis、MySQL、PostgreSQL、SMTP、POP3、IMAP、Telnet 和 Memcached 等服务。识别结果包括端口号、服务名称、banner、版本、主机名线索和指纹详情。

### 4.2 风险规则匹配

风险规则定义在 `risk_rules.yaml` 中，包含规则 ID、服务名称、严重等级、描述、匹配条件、CVE 编号、影响版本、前置条件、验证步骤、缓解建议、修复模板、参考链接和标签等内容。当前规则库包含 129 条规则。

设资产集合为 A，资产 a 的端口集合为 P(a)，规则集合为 R。对每个资产 a、端口 p 和规则 r，系统根据服务名称、版本条件、配置条件、NSE 条件和软件包条件进行匹配，可抽象为：

```text
match(a, p, r) = service_match(p, r) AND evidence_match(a, p, r)
```

其中 `service_match` 判断端口服务是否与规则目标服务一致，`evidence_match` 综合版本、配置、NSE 输出和软件包证据。若规则声明主动验证并满足触发条件，系统继续执行主动检查；否则根据被动证据生成风险发现。

### 4.3 风险稳定身份与收敛

为避免重复扫描造成同一风险多次入库，系统为风险发现构建稳定身份键。其计算逻辑可表示为：

```text
identity_hash = H(asset_id, asset_port_id, yaml_rule_id, evidence_scope)
```

其中，`H` 为哈希函数，`asset_id` 表示资产，`asset_port_id` 表示端口，`yaml_rule_id` 表示规则，`evidence_scope` 表示证据范围。风险验证服务在写入风险前先按 `identity_hash` 索引现有开放风险。若身份键已存在，则更新原风险证据和状态；若不存在，则创建新风险。若某次验证后原开放风险未再次命中，则将其状态收敛为 `fixed`。该机制使风险列表反映当前资产态势，而非简单累积历史扫描结果。

### 4.4 SSH 深度采集

网络侧扫描能够识别端口和服务，但难以确认主机内部配置和本地权限状态。因此系统提供 SSH 深度采集能力。用户可为资产配置密码或密钥凭据，并指定是否具备管理员授权。凭据和敏感字段通过 Fernet 加密保存。

采集任务使用 `asyncssh` 连接目标主机，获取系统信息、安装包列表、服务状态、配置文件摘要和主机安全检查结果，并写入 `snapshots`。风险验证模块随后从快照中提取 MySQL、Nginx、Docker、SSH、Tomcat、Linux 权限等相关证据，从而识别配置类、版本类和本地权限类风险。

### 4.5 修复计划与执行闭环

修复模块以风险发现为入口。系统根据规则中的 `remediation` 模板或内置命令规划器生成修复计划。计划包含摘要、自动化等级、影响说明、前置检查项、验证项、回滚说明和动作列表。动作类型包括软件包升级、服务重载或重启、配置项开关、暴露面收敛、权限修复和路径清理等。

修复流程包括会话准备、计划生成、审批、执行、证据归档和复验。管理员创建或恢复资产级修复会话后，系统检查 Runner 状态、SSH 授权和阻塞项。审批接口支持 `dry_run` 和 `apply` 两种模式，前者用于生成命令预览，后者用于提交真实执行。执行过程中，系统将阶段进度写入 `task_runs` 和 `task_events`，并在修复会话消息中记录状态变化。执行完成后，系统构建证据对象并触发复验任务。

### 4.6 Haor 智能体协同

Haor 是平台内置的站内自治助手。其运行不脱离平台权限体系，而是基于页面上下文、Playbook、任务编排和审批机制受控执行。前端采集当前路由、选中对象、页面语义、DOM 摘要和候选 UI 动作，后端创建或恢复 `agent_session`，并用 `agent_goal` 记录当前目标。

Haor 动作分为读工具、UI 动作和写动作。读工具用于查询资产、风险、任务、修复对象和漏洞规则；UI 动作用于跳转、点击、输入、选择和提交；写动作包括创建扫描任务、验证风险、安装 Runner、创建修复会话、审批修复和配置 SSH 凭据。系统对高风险写动作要求管理员审批，对敏感输入要求安全弹层处理，从而兼顾自动化效率与安全边界。

## 5 系统实现

### 5.1 后端实现

后端位于 `situational-awareness/backend/`。应用入口 `app/main.py` 负责创建 FastAPI 应用，注册 CORS、异常处理、中间件、健康检查和 `/api/v1` 路由。`app/api/v1/router.py` 按业务域挂载认证、仪表盘、智能体、发现、资产、采集、风险、修复、Runner、设置、任务、日志和漏洞库等接口。

业务逻辑主要位于 `app/services/`。发现相关服务负责扫描区域、数据源、扫描节点和资产关联；风险相关服务负责规则加载、规则匹配和风险验证；修复相关服务负责计划生成、会话管理、执行器、证据构建和 Runner 管理；智能体相关服务负责会话、目标、状态机、执行注册和任务联动。

异步任务位于 `app/tasks/`，包括发现任务、扫描任务、采集任务、风险任务、修复任务、报告任务和智能体任务。Celery 配置位于 `app/core/celery_app.py`，通过 Redis 提供 broker 和 backend。安全方面，`app/core/security.py` 负责 JWT 和 bcrypt 密码校验，`app/core/crypto.py` 使用 Fernet 对 SSH 凭据与敏感配置加密。

### 5.2 桌面端实现

桌面端位于 `situational-awareness/frontend/`，采用 Next.js App Router。系统通过 `src/services/api.ts` 封装后端接口调用，并使用 Ant Design 构建表格、表单、详情页、任务中心、修复工作台和智能体抽屉。桌面端适合资产运营、规则治理、风险研判、修复审批和日志审计等重操作场景。

### 5.3 移动端实现

移动端位于 `situational-awareness-mobile/`，基于 Flutter 3.22 以上版本开发，使用 Riverpod 管理状态，go_router 管理路由，dio 访问后端 API，flutter_secure_storage 保存令牌，flutter_local_notifications 与 workmanager 支持本地通知和后台同步。移动端主要用于值班巡检、现场排障、风险详情查看、任务跟踪和异常提醒确认。

### 5.4 部署实现

系统通过 Docker Compose 提供部署骨架，包括 `frontend`、`backend`、`worker`、`postgres`、`redis` 和 `settings-helper`。默认访问入口为桌面端 `http://localhost:3000`，后端文档 `http://localhost:8000/docs`，健康检查 `http://localhost:8000/health`。开发模式提供 `frontend-dev`、`backend-dev` 和 `worker-dev`，方便本地联调。

## 6 测试与结果分析

### 6.1 测试环境与测试内容

项目测试覆盖后端单元测试、后端集成测试、移动端测试、前端 Smoke、Haor 智能体离线评测和真实风险联调。当前后端单元测试文件覆盖认证、发现、采集、风险、修复、Runner、智能体、设置、任务、日志和监控等模块；移动端测试覆盖 API client、响应式布局、登录页、修复页、风险详情、设备异常告警和模型等内容。为降低智能体迭代中的行为回归风险，系统新增 Haor Playbook 离线评测集和 LLM 输出回放评测，对意图匹配、读工具选择、低风险自动执行、高风险审批、敏感输入引导、模型 JSON 解析和关键参数保留进行断言。测试内容如表 4 所示。

**表 4 测试内容**

| 测试类型 | 测试对象 | 验证目标 |
| --- | --- | --- |
| 后端单元测试 | service、task、endpoint | 验证核心业务逻辑和接口行为 |
| 后端集成测试 | 健康检查、CORS | 验证基础服务可用性 |
| 移动端测试 | 页面、模型、API client | 验证移动端基础交互和数据模型 |
| 智能体离线评测 | Haor Playbook、LLM replay、动作策略 | 验证工具选择、模型输出解析、审批边界和敏感输入策略 |
| 前端 Smoke | 首页、资产、发现、风险、修复 | 验证主要页面可达和接口联通 |
| 真实风险联调 | 真实或模拟网段 | 验证资产识别、风险生成和风险收敛 |

后端测试执行命令如下：

```bash
cd situational-awareness/backend
pytest
```

移动端测试执行命令如下：

```bash
cd situational-awareness-mobile
flutter test
```

Haor 智能体离线评测执行命令如下：

```bash
cd situational-awareness
python scripts/haor_playbook_eval.py --fail-under 1.0
python scripts/haor_llm_replay_eval.py --fail-under 1.0
```

### 6.2 测试结果

根据项目验收记录，系统主要测试结论如下。

1. 前端 Smoke 验证表明，首页、资产列表、扫描发起台和修复工作台等页面可正常访问，前端迁移未破坏后端接口能力。
2. 真实风险联调表明，系统能够识别靶机和开放端口；在无 SSH 深采集时能够生成稳定网络侧风险；完成 SSH 深采集后能够补齐本地权限类和配置类风险。
3. 多次执行风险验证后，风险总量不会无意义增长，说明 `identity_hash` 风险收敛机制有效。
4. 修复闭环验证表明，系统能够根据风险项生成修复模板和主机级修复计划，并在 Runner、SSH 授权、审批状态和维护窗口满足条件时推进执行与复验。
5. Haor 离线评测表明，默认 Playbook 用例能够保持预期的读工具选择和动作策略，高风险修复动作不会绕过审批进入自动执行列表，SSH 凭据类请求会进入安全输入流程；LLM 输出回放评测能够复盘模型 JSON 输出并检查高风险动作边界；运行时转换回归测试进一步验证默认 Playbook 产出的读工具、自动动作和待处理动作不会在服务层被静默丢弃。
6. 移动端验证表明，平台能够为值班巡检场景提供总览、风险、任务和异常提醒能力。

### 6.3 结果分析

从工程效果看，平台将资产发现、风险验证和修复执行从离散工具操作整合为统一闭环。稳定身份键降低了重复扫描导致的风险重复问题；统一任务模型使用户能够跨页面追踪扫描、采集、验证和修复进度；修复会话与证据模型提升了整改过程的可审计性；Haor 智能体降低了复杂工作流的操作门槛。

从不足看，系统仍有进一步完善空间。首先，完整端到端自动化测试仍需补齐，前端回归仍主要依赖人工 Smoke。其次，真实网络扫描效果受宿主机权限、Nmap 可用性、网络可达性和防火墙策略影响。再次，当前规则库虽已包含 129 条规则，但面向大型生产网络仍需持续扩展。最后，Haor 当前采用单智能体多 Playbook 架构，虽然已补充 LLM 输出回放评测、运行时 trace 和统一动作策略源，但仍需要将线上真实模型输出、浏览器端端到端任务成功率、误执行率和成本统计持续沉淀为规模化评测集。

### 6.4 Haor 智能体客观评价与行业差距

客观来看，Haor 目前更接近“受控的安全运营协作助手”，而不是行业一线意义上的高自治安全智能体。其优势在于已经接入平台权限体系、页面上下文、任务编排、审批、安全输入和修复闭环，能够把扫描、风险验证、Runner 安装和修复准备等站内操作串起来；经过优化后，写动作风险等级、必填槽位、自动执行权限和审批策略已收敛到统一策略源，运行时能够记录模型调用、估算 token、成本估算单位、延迟、工具调用、动作执行和端到端成功字段，LLM 输出也可通过 replay 评测进行离线复盘。其不足仍在于复杂长程规划、异常恢复和大规模真实模型样本评测仍不充分。

本次排查暴露的核心问题是跨层契约不够统一：Playbook、动作策略、Pydantic 运行时 schema、执行注册表和前端安全输入之间曾存在重复声明。此前 `configure_ssh_credential` 已被 Playbook 和策略层声明为敏感输入动作，但运行时动作 schema 未同步接收该类型，导致 SSH 凭据配置动作在 Playbook 到运行时决策转换时被静默丢弃。优化后，动作类型由 `haor/action_policy.py` 统一声明，运行时 schema 从该策略源校验动作类型，并通过默认 Playbook 转换测试和 LLM replay 测试持续约束。

与行业一线智能体系统相比，Haor 的差距主要体现在三个方面。第一，评测规模不足，当前 replay 能覆盖模型输出结构和关键安全边界，但还不能系统证明真实 LLM 在多轮上下文、噪声页面、失败重试和边界提示下的成功率。第二，可观测性仍处于会话内 trace 阶段，尚未形成跨会话检索、成本报表、模型版本对比和失败聚类。第三，长程任务能力不足，面对跨页面、多资产、多阻塞条件和部分失败恢复时，更多依赖既有业务流程，而不是稳定的自主规划与自我校验。

因此，Haor 距离行业一线水平的差距不在于是否接入了大模型，而在于是否具备可度量、可回放、可审计、可灰度和可持续演进的智能体工程体系。当前实现已经具备业务闭环雏形、安全边界、统一动作策略源、LLM replay 和基础 trace，但仍处于工程化中期阶段；要达到一线水平，需要把线上真实 trace 转化为持续评测资产，并补齐浏览器端端到端成功率、失败聚类、成本报表和多步骤异常恢复能力。

## 7 结论与展望

本文设计并实现了一套内网资产态势感知平台。系统采用前后端分离和异步任务架构，基于 FastAPI、Celery、PostgreSQL、Redis、Next.js 和 Flutter 等技术，实现了资产发现、服务识别、SSH 深度采集、规则化风险验证、风险收敛、修复会话、执行证据、复验、平台观测和移动端告警等功能。实践结果表明，平台能够支撑中小规模内网环境下的资产安全运营和风险整改闭环。

后续工作可从以下方向展开：第一，补齐端到端自动化测试和前端自动化回归测试；第二，扩展风险规则库和漏洞情报同步能力，引入更丰富的 CVE、配置基线和弱口令检测策略；第三，增强多扫描节点调度和大规模网段扫描能力；第四，继续完善 Haor 智能体评测体系，将离线 Playbook 回归扩展为真实 LLM 输出回归、端到端任务成功率、误执行率、澄清率、审批触发率和完整 trace 观测；第五，提升 Haor 的跨页面规划、异常恢复和多步骤审批能力，使其更好地辅助安全运营人员完成复杂治理任务。

## 参考文献

[1] Endsley M R. Toward a theory of situation awareness in dynamic systems[J]. Human Factors, 1995, 37(1): 32-64.

[2] Bass L, Clements P, Kazman R. Software Architecture in Practice[M]. 4th ed. Boston: Addison-Wesley, 2021.

[3] Fielding R T. Architectural styles and the design of network-based software architectures[D]. Irvine: University of California, 2000.

[4] OWASP Foundation. OWASP Application Security Verification Standard 4.0.3[S/OL]. 2021.

[5] NIST. Guide to Enterprise Patch Management Planning: Preventive Maintenance for Technology[S]. NIST SP 800-40 Rev. 4, 2022.

[6] FastAPI. FastAPI Documentation[EB/OL]. https://fastapi.tiangolo.com/.

[7] Celery Project. Celery Distributed Task Queue Documentation[EB/OL]. https://docs.celeryq.dev/.

[8] PostgreSQL Global Development Group. PostgreSQL Documentation[EB/OL]. https://www.postgresql.org/docs/.

[9] 项目文档. 内网资产态势感知平台 V1 README[Z]. `situational-awareness/README.md`.

[10] 项目文档. 总体架构说明[Z]. `situational-awareness/docs/architecture.md`.

[11] 项目文档. 后端设计说明[Z]. `situational-awareness/docs/backend-design.md`.

[12] 项目文档. 数据模型说明[Z]. `situational-awareness/docs/database-schema.md`.

[13] 项目源码. 风险规则库[Z]. `situational-awareness/backend/app/rules/risk_rules.yaml`.

[14] 项目源码. 风险验证服务[Z]. `situational-awareness/backend/app/services/risk_verification_service.py`.

[15] 项目源码. 修复计划与命令规划服务[Z]. `situational-awareness/backend/app/services/remediation_service.py`.
