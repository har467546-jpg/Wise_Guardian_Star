# 前端迁移后 Smoke 验证清单（2026-04-21）

## 目标
验证 `Project1` 前端界面迁入当前项目后：
- 页面可正常访问
- 当前后端接口仍可联调
- 本轮对话中的修复未回退

## 基础服务检查

### 后端健康
```bash
curl -s http://localhost:8000/health
```
预期：
- 返回 `{"status":"ok"}`

### 前端页面可达
```bash
curl -I http://localhost:3000/
curl -I http://localhost:3000/assets
curl -I http://localhost:3000/discovery
curl -I http://localhost:3000/remediation
```
预期：
- 均返回 `200`

## 页面级检查

### 1. 资产列表
检查项：
- 页面能正常加载
- 资产卡片布局采用迁移后的 `Project1` 风格
- 无主机名时不显示“未识别主机名”
- 基础设施资产右上角显示角色标识，例如 `网关 / DNS`
- 资产状态 `network_initial` 成功/部分成功后显示为 `在线`，不再显示“正在采集”

重点样例：
- `192.168.130.138`
- `192.168.130.2`

### 2. 资产详情
检查项：
- 页面能正常打开
- 端口服务名优先显示真实识别结果
- 若主字段缺失，会从 `fingerprint_json` 回退显示
- 无值的概览项不展示，或按当前规则最小化显示
- 网络基础设施资产能看到类别 / 角色 / 来源标签

### 3. 扫描发起台
检查项：
- 页面采用 `Project1` 风格的三段式流水线说明
- CIDR 输入校验正常
- 提交任务后显示任务创建或任务复用反馈
- 任务复用时展示 `reused` 提示

接口依赖：
- `POST /api/v1/discovery/jobs`

### 4. 修复工作台
检查项：
- 页面可访问
- 顶部页头展示工作台状态、剩余开放风险、当前任务
- 阶段卡片存在“修复该阶段”入口
- 不显示与当前后端语义不兼容的旧版“一键全部修复”行为
- 任务输出、AI 解读、前置条件卡片均能正常渲染

接口依赖：
- `GET /api/v1/remediation/assets/{asset_id}`
- `POST /api/v1/remediation/assets/{asset_id}/sessions`
- `GET /api/v1/remediation/sessions/{session_id}`

### 5. 全局设置
检查项：
- 页面可打开
- 当前实现仍保留扫描、校园、AI、平台安全等超集字段
- 保存时不会因为迁移回退字段而导致后端拒绝

接口依赖：
- `GET /api/v1/settings`
- `POST /api/v1/settings/apply`

## 接口联调最小回归

建议以管理员身份验证：

1. 登录
```bash
POST /api/v1/auth/login
```

2. 拉取资产列表
```bash
GET /api/v1/assets?page=1&page_size=5
```

3. 拉取设置
```bash
GET /api/v1/settings
```

4. 提交一个发现任务
```bash
POST /api/v1/discovery/jobs
```

## 2026-04-21 实际验证结果
- 后端健康检查通过
- 前端关键页面可访问：
  - `/`
  - `/assets`
  - `/discovery`
  - `/remediation`
- 已执行真实接口验证：
  - 登录成功
  - 资产列表读取成功
  - 设置读取成功
  - 发现任务创建成功

## 已知保留差异
- `GlobalSettingsModal` 未 1:1 回退到 `Project1`，原因是当前项目字段能力更多
- `HostRemediationSessionView` 仅恢复到“Project1 风格 + 当前后端兼容”的折中版本
- `AssetDetailView` 保留了本轮修复的服务回退显示与空字段处理
