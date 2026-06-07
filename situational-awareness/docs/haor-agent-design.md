# Haor 智能体设计说明

## 文档目的与适用读者
- 面向维护 Haor 智能体链路的前后端工程师。
- 重点说明会话模型、playbook、动作策略、审批恢复机制与关键代码入口。

## 当前实现范围
- 当前以单智能体 `Haor` 为核心，对外表现为站内自治助手。
- 对内通过浏览器上下文、playbook、策略层、任务编排与流式反馈实现完整闭环。

## 核心模块与数据流

### 运行时对象
- `agent_sessions`
  - 保存当前页面上下文、工作上下文、浏览器运行时状态、最近任务与会话状态。
- `agent_goals`
  - 保存用户目标、成功标准、阻塞原因、恢复策略与任务绑定。
- `agent_messages`
  - 保存用户消息、计划、动作更新、错误反馈与系统消息。

### 前后端协作链路
1. 前端打开 Haor 抽屉，采集当前路由、选中对象、页面语义与 DOM 摘要。
2. 后端建立或恢复 `agent_session`，并将消息与当前目标绑定。
3. `agent_playbook_service` 根据当前意图和上下文匹配 playbook。
4. `haor_agent_service` 决定执行读工具、UI 动作还是后端写动作。
5. 若需要真实执行，则通过 `agent_tasks.py` 接入统一任务体系。
6. 会话快照、增量回复、审批等待、任务进度通过 WebSocket 回流前端。

### Playbook 能力
- 当前已落地的典型 playbook：
  - 扫描并分析网段
  - 分析资产风险
  - 验证资产风险
  - 安装 Host Runner
  - 准备自动修复会话
  - 配置 SSH 凭据
- 每个 playbook 会声明：
  - 入口意图
  - 必需上下文
  - 读链路和写链路
  - 成功标准
  - 阻塞条件与恢复策略

### 动作策略
- 支持三类动作：
  - 读工具：查资产、风险、任务、修复对象、漏洞规则
  - UI 动作：跳转、点击、输入、选择、提交、等待
  - 写动作：创建扫描任务、验证风险、安装 Runner、创建修复会话、审批修复、配置 SSH 凭据
- 写动作策略已收敛到 `backend/app/services/haor/action_policy.py`，统一声明支持动作、风险等级、必填槽位、审批要求、自动执行权限和后续跟踪策略。
- 当前动作策略核心约束：
  - 低风险动作可自动执行
  - 高风险动作必须审批
  - 敏感输入必须通过专用安全弹层

### 恢复与阻塞
- 常见阻塞：
  - 缺少 SSH 凭据
  - SSH 授权未验证
  - Runner 未安装或离线
  - 修复动作待审批
- Haor 不会在阻塞时直接终止目标，而是把阻塞原因写回 session/goal，待用户完成审批或安全输入后自动续接。

## 关键代码入口
- `backend/app/api/v1/endpoints/agent.py`
- `backend/app/services/haor_agent_service.py`
- `backend/app/services/haor/action_policy.py`
- `backend/app/services/haor/observability.py`
- `backend/app/services/agent/llm_replay_evaluation.py`
- `backend/app/services/agent_playbook_service.py`
- `backend/app/services/agent_goal_service.py`
- `backend/app/services/agent/session_service.py`
- `backend/app/tasks/agent_tasks.py`
- `frontend/src/components/HaorAgentDrawer.tsx`
- `frontend/src/components/HaorAgentLauncher.tsx`
- `frontend/src/lib/haor-browser-runtime.ts`

## 配置、依赖与限制
- LLM provider 通过平台设置统一管理，当前支持 `mock / openai / minimax / custom_proxy / ollama_remote`。
- `mock` 模式保留完整链路，但不会真正执行高风险写操作。
- Haor 当前是单智能体多 playbook 架构，不是多个自治人格协作。

## 评测与质量控制
- 当前已提供 Haor playbook 离线回归评测，用于验证意图匹配、工具选择、低风险自动执行、高风险审批、敏感输入引导和关键参数保留。
- 同时增加默认 playbook 到运行时决策 schema 的转换回归，要求 playbook 产出的读工具、自动动作和待处理动作在 `haor_agent_service` 中完整保留。
- 新增 LLM 输出回放评测，用于复盘真实或记录下来的模型 JSON 输出，验证模型输出解析、读工具选择、自动动作边界和审批边界。
- 运行时会在 `agent_state_json.traces` 中记录最近轮次 trace，包含模型调用次数、估算 token、模型延迟、读工具延迟、动作延迟、动作数量和端到端成功字段。
- 评测入口：
  - `backend/app/services/agent/evaluation.py`
  - `backend/app/services/agent/llm_replay_evaluation.py`
  - `scripts/haor_playbook_eval.py`
  - `scripts/haor_llm_replay_eval.py`
  - `backend/tests/unit/test_agent_evaluation.py`
  - `backend/tests/unit/test_haor_agent_service.py`
- 默认通过标准：
  - `pass_rate = 100%`
  - `unsafe_auto_execute_count = 0`
- 运行命令：

```bash
cd situational-awareness
python scripts/haor_playbook_eval.py --fail-under 1.0
python scripts/haor_llm_replay_eval.py --fail-under 1.0
```

- 当前评测仍不等同于完整生产质量评测。后续应继续把真实线上 trace 抽样固化为 replay fixture，并补充浏览器端端到端任务成功率、误执行率、澄清率和审批触发率。
- 新增动作类型时必须先更新 `haor/action_policy.py`，再同步执行器和前端安全输入/审批 UI；`_ProposedWriteAction` 已从该策略源校验动作类型，避免跨层白名单漂移。

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 总体架构：[architecture.md](architecture.md)
- 前端设计：[frontend-design.md](frontend-design.md)
- 后端设计：[backend-design.md](backend-design.md)
- 数据模型：[database-schema.md](database-schema.md)
- 接口说明：[api-contract.md](api-contract.md)
- Haor 评测：[agent-evaluation.md](agent-evaluation.md)
