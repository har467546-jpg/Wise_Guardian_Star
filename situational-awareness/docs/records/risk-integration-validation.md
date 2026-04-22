# 风险识别链路真实联调记录

## 背景
- 记录日期：2026-04-21
- 目标网段：`192.168.130.0/24`
- 真实靶机：`192.168.130.138`
- 验证目标：
  - 发现链路能否在真实局域网识别目标主机与端口
  - 无 SSH 深采集时能否生成稳定网络侧 finding
  - SSH 深采集后能否补齐 `authorized_local` finding
  - finding 生命周期是否稳定，不因重跑重复新增

## 环境
- 执行节点：`192.168.130.137/24`
- 可用扫描工具：`nmap`、`fping`、`arp-scan`
- 联调数据库：`situational-awareness/integration-risk-192130138.db`
- SSH 凭据：通过手工绑定方式注入，仓库内未保存明文

## 执行步骤
1. 使用 `arp-scan`、`fping`、`nmap -sn` 对目标网段做探测，确认靶机。
2. 执行项目发现链路：
   - `discover_hosts`
   - `upsert_assets`
   - `full_port_scan`
   - `probe_open_services`
3. 对发现出的资产执行风险验证，记录网络侧 finding。
4. 绑定 SSH 凭据并执行 `run_collection_for_asset`，完成授权验证、主机采集与配置解析。
5. 再次执行风险验证，确认本地权限类 finding 和稳定键行为。

## 关键观测
- 网络侧发现：
  - 真实靶机开放端口数：`23`
  - 命中 `9` 项 NSE 结果
  - 无 SSH 深采集时已命中网络侧 finding `5` 条
- SSH 深采集：
  - SSH 授权验证成功
  - `last_verification_status=success`
  - `last_effective_privilege=sudo`
  - 采集状态：`partial`
  - 软件包数量：`593`
- 风险复核结果：
  - `passive_match_count=18`
  - `active_check_total=1`
  - `active_rejected_count=1`
  - `created_finding_count=17`
  - 总 finding 数提升到 `18`
- finding 稳定性：
  - 重复执行后总数未重复增长
  - 既有 finding `id` 保持不变
  - `identity_hash` 生效

## 结论
- 平台风险识别链路能够在真实局域网环境完成“发现 -> 采集 -> 风险复核 -> finding 稳定化”的闭环。
- 该结果说明当前规则链路不仅能处理网络侧证据，也能在 SSH 深采集后稳定补齐本地权限与配置类风险。

## 影响范围
- 本记录为真实环境联调证据，对风险链路可信度、规则稳定性和修复前置条件判断具有参考价值。
- 不应直接在普通开发容器中按相同网络条件复现；复现需要真实目标网段可见性。

## 相关标准文档
- 测试与验收：[../testing-and-acceptance.md](../testing-and-acceptance.md)
- 运行手册：[../runbook.md](../runbook.md)
- 后端设计：[../backend-design.md](../backend-design.md)
