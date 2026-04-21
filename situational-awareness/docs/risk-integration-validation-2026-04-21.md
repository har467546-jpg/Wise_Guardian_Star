# 风险识别链路真实联调记录（2026-04-21）

## 范围
- 目标网段：`192.168.130.0/24`
- 真实靶机：`192.168.130.138`
- 验证目标：
  - 发现链路能否在真实局域网内识别目标主机与端口
  - 网络侧证据能否在无 SSH 深采集时生成稳定 finding
  - SSH 深采集后能否补齐 `authorized_local` finding
  - finding 生命周期是否稳定，不因重跑而重复新增
  - 结构化 `yaml_rule_id` 与修复链路是否可持续工作

## 环境
- 执行节点：与目标网段直连的宿主机，地址 `192.168.130.137/24`
- 可用扫描工具：`nmap`、`fping`、`arp-scan`
- 联调数据库：`situational-awareness/integration-risk-192130138.db`
- SSH 凭据：通过手工绑定方式注入，未在仓库内记录明文

## 执行链路
1. 使用 `arp-scan`、`fping`、`nmap -sn` 对 `192.168.130.0/24` 进行探测，确认 `192.168.130.138` 为实验靶机。
2. 使用项目发现链路执行：
   - `discover_hosts`
   - `upsert_assets`
   - `full_port_scan`
   - `probe_open_services`
3. 对已发现资产执行一次风险验证，记录网络侧 finding。
4. 绑定 SSH 凭据并执行 `run_collection_for_asset`，完成授权验证、主机清单采集、配置解析和采集阶段 NSE 跟扫。
5. 再次执行风险验证，确认 `authorized_local` finding 与 finding 稳定键行为。

## 关键观测

### 1. 网络侧发现
- 真实发现到的靶机开放端口数：`23`
- 服务/NSE 富化成功，主机命中 `9` 项 NSE 结果
- 无 SSH 深采集时已命中网络侧 finding `5` 条，包含：
  - `openssh.legacy.lt_4_8`
  - `apache.httpd.lt_2_2_9`
  - `php.legacy.lt_5_2_5`
  - `samba.user_enumeration.disclosed`
  - `tomcat.legacy.lte_5_5_20`

### 2. SSH 深采集
- SSH 授权验证成功
- `last_verification_status=success`
- `last_effective_privilege=sudo`
- 采集状态：`partial`
- 采集到的软件包数：`593`
- 采集到的重点配置服务包括：
  - `sudo`
  - `nmap`
  - `screen`
  - `cron`
  - `linux-host`
  - `apache`
  - `ssh`
  - `mysql`
  - `tomcat`

### 3. 风险复核结果
- 采集后风险验证统计：
  - `passive_match_count=18`
  - `active_check_total=1`
  - `active_rejected_count=1`
  - `created_finding_count=17`
- 总 finding 数提升到 `18`
- 新增的 `authorized_local` finding 包括：
  - `linux-kernel.legacy.lt_3_10`
  - `linux-host.dangerous_suid.present`
  - `linux-host.suid.nmap.present`
  - `linux-host.suid.screen.present`
  - `sudo.full_privilege_rule.enabled`
  - `nmap.legacy_interactive_privesc.exposed`
  - `cron.root_writable_job_chain.exposed`

### 4. finding 稳定性
- 对同一资产重复执行风险验证后：
  - finding 总数未重复增长
  - 既有 finding `id` 保持不变
  - 稳定键 `identity_hash` 生效
- 同一规则可按不同证据域并存：
  - `openssh.legacy.lt_4_8` 的 `network` finding 在 SSH 深采集后收敛为 `fixed`
  - `openssh.legacy.lt_4_8` 的 `authorized_local` finding 作为独立结果保持 `open`

## 本次联调中补齐的兼容点

### 老 Ubuntu 发行版识别
- 目标机不存在 `/etc/os-release`
- 原实现无法从 SSH 深采集结果中识别 `distro_name/distro_release`
- 已补齐回退链路：
  - `lsb_release -d`
  - `/etc/issue`
- 复测后目标机已正确识别为：
  - `os_release=Ubuntu 8.04`
  - `distro_name=ubuntu`
  - `distro_release=8.04`

### 老 sudo 兼容
- 原 `sudo_list` 命令使用 `sudo -k -l`
- 在老 sudo 上会报 “Only one of ... may be used”
- 已改为兼容的 `sudo -l`

### EOL 发行版 sudo 包规则
- `Ubuntu 8.04` 已不再提供发行版修复包
- 为了让实验靶机上的 `dpkg lt_fixed` 规则能够稳定识别 Baron Samedit 暴露面，本次将旧版 Ubuntu 的判定基线补为上游修复版本 `1.8.32`
- 该基线用于检测，不代表仍可在 EOL 发行版上直接通过仓库安装该确切版本完成修复

## 结论
- 本轮“结果稳定性优先”的改动已在真实靶机上跑通
- 网络侧证据、SSH 深采集、`authorized_local` finding、稳定键 upsert、结构化 `yaml_rule_id`、修复计划读取链路均已验证
- 旧版 Linux 的 OS 识别和 sudo 采集兼容问题已通过真实联调发现并修复
- 对 EOL 发行版的包规则仍需按具体实验环境持续补齐；本次已补到 `Ubuntu 8.04` 的 sudo Baron Samedit 检测基线
