# 测试与验收说明

## 文档目的与适用读者
- 面向开发、测试、联调和验收人员。
- 说明仓库内测试分层、基本执行方式、关键 Smoke 结论与真实联调结论。

## 当前实现范围
- 测试覆盖后端单元测试、集成测试、基础 E2E 占位。
- 文档层面额外保留了前端迁移 Smoke、真实风险联调与迁移记录。

## 测试分层

### 自动化测试
- 后端单元测试：`backend/tests/unit/`
  - 覆盖 auth、discovery、collection、risk、remediation、runner、agent、settings、task 等模块。
- 后端集成测试：`backend/tests/integration/`
  - 当前包含健康检查与 CORS 基础验证。
- E2E：
  - `backend/tests/e2e/test_placeholder.py` 当前为占位，说明完整端到端自动化仍可继续补齐。

### 人工验证
- 前端 Smoke：页面可达、前后端可联调、关键页面可正常展示。
- 真实风险联调：在真实局域网靶机上验证发现、SSH 深采集、风险复核与 finding 稳定性。
- 前端迁移验证：确认视觉迁移后未破坏现有后端接口能力与当前修复语义。

## 执行方式
- 后端测试：
```bash
cd backend
pytest
```
- 单模块测试示例：
```bash
cd backend
pytest tests/unit/test_discovery_tasks.py
pytest tests/unit/test_haor_agent_service.py
pytest tests/unit/test_runner_service.py
```
- 基本运行检查参考：[runbook.md](runbook.md)

## 关键验收结论

### 1. 前端 Smoke
- 迁移后首页、资产列表、扫描发起台、修复工作台等页面可访问。
- 当前后端接口仍能支撑前端页面工作，未因样式迁移导致接口形状回退。
- 详细过程记录见：[records/frontend-smoke-validation.md](records/frontend-smoke-validation.md)

### 2. 风险识别真实联调
- 真实网段扫描能够识别靶机与开放端口。
- 无 SSH 深采集时即可生成稳定网络侧 finding。
- SSH 深采集后可补齐 `authorized_local` 一类本地权限与配置类 finding。
- 重复执行风险验证后 finding 总量不会无意义重复增长，`identity_hash` 生效。
- 详细过程记录见：[records/risk-integration-validation.md](records/risk-integration-validation.md)

### 3. 前端迁移记录
- 当前项目前端已吸收 `Project1` 的部分视觉和布局风格。
- 迁移过程明确遵循“视觉迁移、接口超集保留、本轮修复不回退”的策略。
- 详细过程记录见：[records/frontend-migration.md](records/frontend-migration.md)

## 验收清单
- 项目启动后，前端与后端默认入口可访问。
- 初次部署能够完成管理员初始化并正常登录。
- 提交发现任务后，可在任务中心查看基础扫描与深度扫描状态。
- 资产、风险、修复、任务、日志和设置页面均可完成基础加载。
- 玄武会话可创建、恢复、审批并接收流式反馈。
- 平台监控与日志流能够提供实时可观察性。

## 关键代码入口
- `backend/tests/unit/`
- `backend/tests/integration/`
- `backend/tests/e2e/`
- `docs/records/frontend-smoke-validation.md`
- `docs/records/risk-integration-validation.md`
- `docs/records/frontend-migration.md`

## 配置、依赖与限制
- 当前仓库主测试覆盖集中在后端，前端自动化回归仍以人工 Smoke 为主。
- 真实靶机联调依赖可访问目标网段的宿主机、扫描工具与单独数据库，不应默认在普通开发容器中复现。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 运行手册：[runbook.md](runbook.md)
- 总体架构：[architecture.md](architecture.md)
- 历史记录索引：[records/README.md](records/README.md)
