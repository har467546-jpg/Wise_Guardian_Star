# 项目文档索引

## 文档目的与适用读者
- 面向研发交接、二次开发、联调验收与运维排障。
- 默认读者是新加入项目的前后端工程师、测试与运维协作人员。

## 阅读顺序
1. 项目总入口：[../README.md](../README.md)
2. 总体架构：[architecture.md](architecture.md)
3. 前端设计：[frontend-design.md](frontend-design.md)
4. 后端设计：[backend-design.md](backend-design.md)
5. 数据模型：[database-schema.md](database-schema.md)
6. 接口说明：[api-contract.md](api-contract.md)
7. 运行手册：[runbook.md](runbook.md)
8. 测试与验收：[testing-and-acceptance.md](testing-and-acceptance.md)
9. Haor 设计：[haor-agent-design.md](haor-agent-design.md)
10. Haor 评测：[agent-evaluation.md](agent-evaluation.md)

## 标准文档

### 项目总览
- [architecture.md](architecture.md)
  - 说明系统分层、核心链路、部署骨架和阅读入口。

### 前后端实现
- [frontend-design.md](frontend-design.md)
  - 说明 Next.js 页面结构、组件组织、API 接入、实时交互与 Haor 前端运行时。
- [backend-design.md](backend-design.md)
  - 说明 FastAPI、service/task/repository 分层、配置、安全、日志与监控。
- [haor-agent-design.md](haor-agent-design.md)
  - 说明 Haor 的会话模型、playbook、动作策略、审批、恢复与流式反馈。
- [agent-evaluation.md](agent-evaluation.md)
  - 说明 Haor playbook 与动作策略的离线评测集、运行方式、指标和扩展方向。

### 数据与接口
- [database-schema.md](database-schema.md)
  - 说明运行时实体、关系、索引与模型边界。
- [api-contract.md](api-contract.md)
  - 说明当前真实挂载的 `/api/v1` 接口、鉴权要求和 WebSocket 入口。

### 运行与验收
- [runbook.md](runbook.md)
  - 说明启动、初始化、配置、迁移、排障与常见运维操作。
- [testing-and-acceptance.md](testing-and-acceptance.md)
  - 说明测试分层、Smoke、真实联调与验收结论。

## 历史记录
- [records/README.md](records/README.md)
  - 标准化保留迁移、联调和验证记录；这些文档用于证据留存，不作为主入口。

## 当前实现范围
- 当前文档体系覆盖桌面端 Web 控制台、后端平台服务、任务编排、Haor 智能体、数据库模型与运维流程。
- 移动端只在需要理解接口或告警流时做简要提及，不作为本套研发交接文档主线。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 历史记录索引：[records/README.md](records/README.md)
