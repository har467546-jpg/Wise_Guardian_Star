const taskTypeLabelMap: Record<string, string> = {
  asset_scan: "资产扫描",
  info_collect: "SSH 授权深度检查",
  risk_verify: "风险验证",
  report_generate: "报告生成",
  credential_verify: "授权凭据验证",
  runner_install: "Host Runner 安装",
  remediation_execute: "交互式漏洞修复",
  agent_orchestrate: "玄武智能体编排",
  settings_apply: "系统设置应用",
  vuln_intel_sync: "漏洞情报同步",
};

const scopeTypeLabelMap: Record<string, string> = {
  asset: "资产",
  job: "任务",
  discovery_job: "发现任务",
  agent_session: "智能体会话",
  vuln_library: "漏洞规则库",
};

const taskMessageLabelMap: Record<string, string> = {
  "starting asset scan": "开始资产扫描",
  "discovery job queued": "扫描任务已入队",
  "discovery job reused": "已复用已有扫描任务",
  "discovery job reused after conflict": "检测到并发冲突，已复用已有扫描任务",
  "hosts discovered": "主机发现完成",
  "asset inventory updated": "资产台账已更新",
  "collection tasks queued": "采集任务已入队",
  "batch collection queued": "批量 SSH 授权深度检查任务已入队",
  "asset collection queued": "SSH 授权深度检查任务已入队",
  "service scan completed": "服务扫描完成",
  "risk verification queued": "风险验证任务已入队",
  "risk verification tasks queued": "风险验证任务已入队",
  "scan pipeline completed": "扫描流水线完成",
  "starting asset collection": "开始 SSH 授权深度检查",
  "asset collection completed": "SSH 授权深度检查完成",
  "starting batch collection": "开始批量 SSH 授权深度检查",
  "batch collection completed": "批量 SSH 授权深度检查完成",
  "ssh 授权深度检查任务已入队": "SSH 授权深度检查任务已入队",
  "批量 ssh 授权深度检查任务已入队": "批量 SSH 授权深度检查任务已入队",
  "ssh 授权深度检查完成": "SSH 授权深度检查完成",
  "批量 ssh 授权深度检查完成": "批量 SSH 授权深度检查完成",
  "授权凭据验证任务已入队": "授权凭据验证任务已入队",
  "批量授权凭据验证任务已入队": "批量授权凭据验证任务已入队",
  "授权凭据验证完成": "授权凭据验证完成",
  "批量授权凭据验证完成": "批量授权凭据验证完成",
  "job report queued": "任务报告已入队",
  "building job report": "正在生成任务报告",
  "job report generated": "任务报告已生成",
  "asset report queued": "资产报告已入队",
  "building asset report": "正在生成资产报告",
  "asset report generated": "资产报告已生成",
  "host runner 安装任务已入队": "Host Runner 安装任务已入队",
  "host runner 安装完成": "Host Runner 安装完成",
  "交互式漏洞修复任务已入队": "交互式漏洞修复任务已入队",
  "交互式漏洞修复完成": "交互式漏洞修复完成",
  "haor 编排任务已入队": "玄武编排任务已入队",
  "玄武 编排任务已入队": "玄武编排任务已入队",
  "系统设置应用任务已入队": "系统设置应用任务已入队",
  "漏洞情报同步任务已入队": "漏洞情报同步任务已入队",
  "正在同步漏洞情报": "正在同步漏洞情报",
  "正在准备漏洞情报同步": "正在准备漏洞情报同步",
  "正在同步 kev 已知利用目录": "正在同步 KEV 已知利用目录",
  "kev 已知利用目录同步完成": "KEV 已知利用目录同步完成",
  "kev 已知利用目录同步失败，继续使用可用情报": "KEV 已知利用目录同步失败，继续使用可用情报",
  "正在同步 epss 概率评分": "正在同步 EPSS 概率评分",
  "epss 概率评分同步完成": "EPSS 概率评分同步完成",
  "epss 概率评分同步失败，继续使用可用情报": "EPSS 概率评分同步失败，继续使用可用情报",
  "正在同步免费 cve 漏洞详情": "正在同步免费 CVE 漏洞详情",
  "正在刷新漏洞规则索引": "正在刷新漏洞规则索引",
  "正在重算开放风险优先级": "正在重算开放风险优先级",
  "漏洞情报同步完成": "漏洞情报同步完成",
  "task canceled": "任务已中断",
  "asset not found": "资产不存在",
  "no credential configured": "未配置凭据",
  "credential payload is incomplete": "凭据内容不完整",
};

const taskLogLevelLabelMap: Record<string, string> = {
  info: "信息",
  warning: "告警",
  error: "错误",
};

const taskEventTypeLabelMap: Record<string, string> = {
  queued: "已入队",
  started: "开始执行",
  stage: "阶段推进",
  warning: "告警",
  retry: "等待重试",
  success: "执行成功",
  failure: "执行失败",
  canceled: "已中断",
  command: "执行命令",
  stream: "实时输出",
  reverify: "自动复测",
};

const taskStageLabelMap: Record<string, string> = {
  discover_hosts: "主机发现",
  upsert_assets: "资产入库",
  queue_deep_scan: "深度扫描入队",
  full_port_scan: "全端口扫描",
  probe_open_services: "开放端口探测",
  queue_risk_verification: "风险验证入队",
  finalize_job: "任务收尾",
  runner_discover_hosts: "Runner 主机发现",
  runner_scan_ports: "Runner 端口扫描",
  runner_complete_baseline: "Runner 基础信息回传",
  runner_complete_scan: "Runner 深度扫描回传",
  runner_complete: "扫描节点回传",
  resolve_credential: "凭据解析",
  verify_authorization: "授权验证",
  detect_privilege: "权限识别",
  collect_inventory: "基础清单采集",
  collect_host_security: "主机安全检查",
  ssh_collect: "SSH 采集",
  persist_result: "结果落盘",
  collection_nse_followup: "NSE 跟扫",
  queue_followup_risk_verify: "风险验证入队",
  load_context: "载入上下文",
  passive_match: "被动匹配",
  active_check: "主动探测",
  generate_report: "报告生成",
  load_workspace_context: "载入上下文",
  render_execution_plan: "计划渲染",
  verify_runner_install_context: "校验上下文",
  prepare_runner_bundle: "准备安装包",
  upload_and_install_runner: "上传并安装",
  wait_runner_register: "等待注册",
  prepare_backups: "备份准备",
  runner_dispatch: "Runner 接单",
  runner_pending: "等待 Runner",
  execute_steps: "执行步骤",
  post_validate: "结果校验",
  auto_reverify: "自动复测",
  agent_prepare: "载入计划",
  agent_execute_action: "执行动作",
  agent_action_dispatched: "动作已下发",
  agent_wait_subtask: "等待子任务",
  agent_finalize: "结果收尾",
  validate_settings: "校验设置",
  encrypt_secrets: "敏感字段处理",
  process_ai_key: "处理 AI Key",
  dispatch_helper: "下发执行器",
  write_runtime_env: "写入运行时环境",
  restart_services: "重启服务",
  wait_backend_health: "等待后端恢复",
  complete_apply: "完成应用",
};

export function getTaskTypeLabel(value: string | null | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  return taskTypeLabelMap[normalized] || "未知任务";
}

export function getScopeTypeLabel(value: string | null | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  return scopeTypeLabelMap[normalized] || "未知范围";
}

export function localizeTaskMessage(value: string | null | undefined): string {
  const raw = String(value || "").trim();
  if (!raw) {
    return "";
  }
  const normalized = raw.toLowerCase();
  if (taskMessageLabelMap[normalized]) {
    return taskMessageLabelMap[normalized];
  }
  return raw
    .replace(/incorrect username or password/gi, "用户名或密码错误")
    .replace(/bootstrap already completed/gi, "系统已完成初始化")
    .replace(/invalid authentication token/gi, "登录状态已失效")
    .replace(/user not found or disabled/gi, "当前账号不可用")
    .replace(/admin role required/gi, "仅管理员可执行该操作")
    .replace(/disallowed cors origin/gi, "跨域访问被拒绝")
    .replace(/asset not found/gi, "资产不存在")
    .replace(/assets not found/gi, "以下资产不存在")
    .replace(/task not found/gi, "任务不存在")
    .replace(/job not found/gi, "发现任务不存在")
    .replace(/report not found/gi, "报告不存在")
    .replace(/rule not found/gi, "规则不存在")
    .replace(/no probe snapshot found/gi, "暂无基础探测结果")
    .replace(/no credential configured/gi, "未配置凭据")
    .replace(/credential payload is incomplete/gi, "凭据内容不完整")
    .replace(/credential password is empty/gi, "凭据中的密码为空")
    .replace(/credential private key is empty/gi, "凭据中的私钥为空")
    .replace(/must confirm admin authorization before saving ssh credential/gi, "保存 SSH 凭据前必须确认已获得管理员授权")
    .replace(/password is required when auth_type=password/gi, "认证方式为密码时必须填写密码")
    .replace(/private_key is required when auth_type=key/gi, "认证方式为私钥时必须填写私钥")
    .replace(/match\.version or match\.config is required/gi, "请至少填写版本匹配或配置匹配")
    .replace(/match\.version or match\.config or match\.nse is required/gi, "请至少填写版本匹配、配置匹配或 Nmap 脚本匹配")
    .replace(/match\.version、match\.config 或 match\.nse/gi, "match.version、match.config 或 match.nse")
    .replace(/permission denied/gi, "权限被拒绝")
    .replace(/authentication failed/gi, "认证失败")
    .replace(/timed out/gi, "执行超时")
    .replace(/connection refused/gi, "连接被拒绝");
}

export function getTaskLogLevelLabel(value: string | null | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  return taskLogLevelLabelMap[normalized] || "信息";
}

export function getTaskEventTypeLabel(value: string | null | undefined): string {
  const normalized = String(value || "").trim().toLowerCase();
  return taskEventTypeLabelMap[normalized] || String(value || "事件");
}

export function getTaskStageLabel(stageCode: string | null | undefined, fallbackName?: string | null): string {
  const normalized = String(stageCode || "").trim().toLowerCase();
  if (normalized && taskStageLabelMap[normalized]) {
    return taskStageLabelMap[normalized];
  }
  if (fallbackName) {
    return fallbackName;
  }
  return "未分段";
}

export function formatDurationMs(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "-";
  }
  const totalSeconds = Math.max(0, Math.floor(value / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) {
    return `${hours}时${minutes}分${seconds}秒`;
  }
  if (minutes > 0) {
    return `${minutes}分${seconds}秒`;
  }
  return `${seconds}秒`;
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
}

export function isTaskActive(value: string | null | undefined): boolean {
  const normalized = String(value || "").trim().toLowerCase();
  return normalized === "pending" || normalized === "running" || normalized === "retry";
}
