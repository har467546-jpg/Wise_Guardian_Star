# 开发接口文档

## 文档范围
- 适用读者：前端、移动端、后端、Runner、测试与二次开发人员。
- 基准版本：`Asset Situational Awareness 0.1.0`。
- HTTP 基础路径：`/api/v1`。
- 健康检查路径：`GET /health`。
- 本文档只记录当前真实挂载到 `backend/app/api/v1/router.py` 的接口；OpenAPI 不覆盖的 WebSocket 入口在单独章节列出。

## 联调约定
- 默认请求体为 `application/json`，文件上传接口为 `multipart/form-data`。
- 分页统一使用 `page`、`page_size`，响应分页元数据为 `meta: { total, page, page_size }`。
- 时间字段通常为 ISO 8601 字符串或 Pydantic `datetime` 序列化结果。
- 枚举值使用小写字符串，不使用中文值。
- FastAPI 校验失败统一返回 `422`，业务错误通常返回 `400`、`401`、`403`、`404`、`409` 或 `502`，错误体为 `{"detail": "..."}` 或 FastAPI 校验错误数组。
- 生产式后端 Swagger UI：`http://localhost:8000/docs`；开发后端 Swagger UI：`http://localhost:8001/docs`。

## 认证方式
| 类型 | 使用方式 | 说明 |
| --- | --- | --- |
| 无鉴权 | 不带认证头 | 仅初始化、登录、健康检查等入口使用。 |
| 用户鉴权 | `Authorization: Bearer <access_token>` | 登录或初始化管理员后获取。 |
| 管理员鉴权 | `Authorization: Bearer <access_token>` 且用户角色为 `admin` | 用于配置、校区、修复、日志、规则管理等高权限操作。 |
| Runner 鉴权 | `X-Runner-Token: <runner_token>` 或 `Authorization: Bearer <runner_token>` | Runner 注册后获取。 |
| settings-helper 鉴权 | `X-Settings-Helper-Token: <token>` | 内部回调接口使用。 |
| WebSocket 鉴权 | 多数为 `?token=<access_token>`；Haor 流也支持首帧 `{"type":"auth","token":"..."}` | 鉴权失败关闭码通常为 `1008`。 |

## 常用枚举
| 枚举 | 可选值 |
| --- | --- |
| `UserRole` | `admin`, `analyst` |
| `AssetStatus` | `online`, `offline`, `collecting`, `unknown` |
| `DiscoveryJobStatus` | `pending`, `running`, `completed`, `failed` |
| `RiskSeverity` | `low`, `medium`, `high`, `critical` |
| `FindingStatus` | `open`, `ignored`, `fixed` |
| `TaskType` | `asset_scan`, `info_collect`, `risk_verify`, `report_generate`, `credential_verify`, `runner_install`, `remediation_execute`, `agent_orchestrate`, `settings_apply` |
| `TaskExecutionStatus` | `pending`, `running`, `retry`, `success`, `failure`, `canceled` |

## 接口总览
| 分组 | 前缀 | 鉴权概览 |
| --- | --- | --- |
| Auth | `/auth` | 无鉴权 |
| Dashboard | `/dashboard` | 用户鉴权 |
| Agent | `/agent` | 用户鉴权，审批接口要求管理员 |
| Discovery | `/discovery` | 用户鉴权 |
| Campus | `/campus` | 管理员鉴权 |
| Mobile | `/mobile` | 用户鉴权 |
| Monitoring | `/monitoring` | 用户鉴权 |
| Assets | `/assets` | 用户鉴权 |
| Collection | `/collection` | 用户鉴权 |
| Risks | `/risks` | 用户鉴权 |
| Remediation | `/remediation` | 管理员鉴权 |
| Reports | `/reports` | 用户鉴权 |
| Runner | `/runner` | 注册接口使用注册令牌，其他接口使用 Runner Token |
| Settings | `/settings` | 管理员鉴权，内部回调使用 settings-helper 令牌 |
| Tasks | `/tasks` | 用户鉴权 |
| Logs | `/logs` | 管理员鉴权 |
| Vulnerability Library | `/vuln-library` | 查询接口用户鉴权，变更接口管理员鉴权 |

## Auth
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/auth/bootstrap-status` | 无 | 无 | `BootstrapStatusResponse` |
| `POST` | `/api/v1/auth/bootstrap-admin` | 无 | `BootstrapAdminRequest` | `TokenResponse` |
| `POST` | `/api/v1/auth/login` | 无 | `LoginRequest` | `TokenResponse` |

请求模型：
- `BootstrapAdminRequest`: `username`, `email`, `password`。
- `LoginRequest`: `username`, `password`。

响应模型：
- `BootstrapStatusResponse`: `bootstrapped`, `can_bootstrap_admin`, `user_count`。
- `TokenResponse`: `access_token`, `token_type`。

示例：
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin-password"}'
```

## Dashboard
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/dashboard/overview` | 用户 | 无 | `DashboardOverviewRead` |

`DashboardOverviewRead` 返回资产总数、在线资产数、高风险风险数、活跃任务数、发现入口状态、近期风险、高风险资产、风险等级统计和任务健康列表。

## Agent / Haor
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/agent/haor/summary` | 用户 | 无 | `AgentSessionSummaryRead` |
| `GET` | `/api/v1/agent/haor/session` | 用户 | 无 | `AgentSessionRead` |
| `GET` | `/api/v1/agent/haor/goals` | 用户 | Query: `limit=12` | `list[AgentGoalRead]` |
| `GET` | `/api/v1/agent/haor/goals/{goal_id}` | 用户 | Path: `goal_id` | `AgentGoalRead` |
| `POST` | `/api/v1/agent/haor/goals/{goal_id}/resume` | 用户 | Path: `goal_id` | `AgentSessionRead` |
| `POST` | `/api/v1/agent/haor/goals/{goal_id}/cancel` | 用户 | Path: `goal_id` | `AgentGoalRead` |
| `POST` | `/api/v1/agent/haor/session/reset` | 用户 | 无 | `AgentSessionRead` |
| `POST` | `/api/v1/agent/haor/session/recover` | 用户 | 无 | `AgentSessionRead` |
| `POST` | `/api/v1/agent/haor/session/messages` | 用户 | `AgentMessageCreateRequest` | `AgentSessionRead` |
| `POST` | `/api/v1/agent/haor/session/steps` | 用户 | `AgentUIStepRequest` | `AgentSessionRead` |
| `POST` | `/api/v1/agent/haor/session/approve` | 管理员 | `AgentApprovalRequest` | `202 AgentApprovalResponse` |
| `POST` | `/api/v1/agent/haor/session/interrupt` | 用户 | 无 | `AgentSessionRead` |

核心请求模型：
- `AgentMessageCreateRequest`: `client_message_id?`, `content`, `page_context`, `browser_context`。
- `AgentUIStepRequest`: `step_request_id?`, `browser_context`, `ui_action_results[]`。
- `AgentApprovalRequest`: `note?`。

核心响应模型：
- `AgentSessionRead`: `session_id`, `status`, `route_context_json`, `working_context_json`, `dialog_state_json`, `pending_plan_json`, `browser_runtime_json`, `agent_state_json`, `runtime_snapshot`, `current_goal_id?`, `messages[]` 等。
- `AgentApprovalResponse`: `session_id`, `task_id`, `status`。

## Discovery
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/discovery/jobs` | 用户 | `DiscoveryJobCreate` | `201 DiscoveryJobCreateResponse`，复用已有任务时为 `200` |
| `GET` | `/api/v1/discovery/jobs` | 用户 | Query: `page`, `page_size`, `status?` | `DiscoveryJobListResponse` |
| `GET` | `/api/v1/discovery/jobs/{job_id}` | 用户 | Path: `job_id` | `DiscoveryJobRead` |

请求模型：
- `DiscoveryJobCreate`: `cidr`, `label?`, `runner_asset_id?`, `scanner_zone_id?`。

响应模型：
- `DiscoveryJobCreateResponse`: `job`, `task_id`, `status`, `reused`。
- `DiscoveryJobRead`: `id`, `cidr`, `status`, `label`, `scanner_zone_id?`, `started_at?`, `finished_at?`, `created_at`, `summary_json`。

## Campus
全部接口要求管理员鉴权。

| 方法 | 路径 | 参数/Body | 响应 |
| --- | --- | --- | --- |
| `GET` | `/api/v1/campus/zones` | Query: `page`, `page_size` | `ScannerZoneListResponse` |
| `POST` | `/api/v1/campus/zones` | `ScannerZoneWrite` | `201 ScannerZoneRead` |
| `PATCH` | `/api/v1/campus/zones/{zone_id}` | Path: `zone_id`; Body: `ScannerZoneWrite` | `ScannerZoneRead` |
| `DELETE` | `/api/v1/campus/zones/{zone_id}` | Path: `zone_id` | `204` |
| `GET` | `/api/v1/campus/zones/{zone_id}/nodes` | Path: `zone_id` | `list[ScannerNodeAssignmentRead]` |
| `POST` | `/api/v1/campus/zones/{zone_id}/nodes` | Path: `zone_id`; Body: `ScannerNodeAssignmentWrite` | `201 ScannerNodeAssignmentRead` |
| `GET` | `/api/v1/campus/data-sources` | Query: `zone_id?` | `list[CampusDataSourceRead]` |
| `POST` | `/api/v1/campus/data-sources` | `CampusDataSourceWrite` | `201 CampusDataSourceRead` |
| `PATCH` | `/api/v1/campus/data-sources/{source_id}` | Path: `source_id`; Body: `CampusDataSourceWrite` | `CampusDataSourceRead` |
| `DELETE` | `/api/v1/campus/data-sources/{source_id}` | Path: `source_id` | `204` |
| `POST` | `/api/v1/campus/data-sources/{source_id}/test` | Path: `source_id` | `CampusDataSourceTestResponse` |
| `POST` | `/api/v1/campus/data-sources/{source_id}/collect` | Path: `source_id` | `CampusDataSourceTestResponse` |
| `GET` | `/api/v1/campus/discovery-jobs/{job_id}/executions` | Path: `job_id`; Query: `page`, `page_size` | `DiscoveryJobExecutionListResponse` |

请求模型：
- `ScannerZoneWrite`: `name`, `zone_type`, `description?`, `priority`, `enabled`, `cidrs_json[]`, `default_scan_profile_json`, `allowed_data_source_types_json[]`。
- `ScannerNodeAssignmentWrite`: `asset_id`, `enabled`, `priority`, `visible_cidrs_json[]`, `max_concurrent_jobs`。
- `CampusDataSourceWrite`: `scanner_zone_id`, `asset_id?`, `name`, `source_type`, `enabled`, `collection_interval_seconds`, `config_json`, `secret_plaintext?`。

枚举：
- `zone_type`: `office`, `dormitory`, `wireless`, `server`, `iot`, `custom`。
- `source_type`: `dhcp_lease`, `snmp_switch`。

## Mobile
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/mobile/overview` | 用户 | 无 | `MobileOverviewRead` |

`MobileOverviewRead` 返回移动端总览数据：资产、风险、任务和发现入口状态。

## Monitoring
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/monitoring/platform/live` | 用户 | 无 | `PlatformLiveMetricsRead` |

`PlatformLiveMetricsRead` 包含 CPU、内存、磁盘、网络实时指标。

## Assets
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/assets` | 用户 | Query: `page`, `page_size`, `ip?`, `keyword?`, `status?`, `network_zone?`, `asset_category?`, `tag_id?` | `AssetListResponse` |
| `GET` | `/api/v1/assets/{asset_id}` | 用户 | Path: `asset_id` | `AssetRead` |
| `PATCH` | `/api/v1/assets/{asset_id}` | 用户 | Path: `asset_id`; Body: `AssetUpdate` | `AssetRead` |
| `DELETE` | `/api/v1/assets/{asset_id}` | 用户 | Path: `asset_id` | `204` |
| `POST` | `/api/v1/assets/batch/delete` | 用户 | `AssetBatchDeleteRequest` | `AssetBatchDeleteResponse` |

请求模型：
- `AssetUpdate`: `tag_ids?`。
- `AssetBatchDeleteRequest`: `asset_ids[]`，1 到 200 个。

响应模型：
- `AssetRead`: `id`, `ip`, `mac_address?`, `vendor?`, `hostname?`, `os_name?`, `network_zone?`, `asset_category?`, `device_role?`, `device_assessment_json`, `status`, `is_local`, `local_hint?`, `first_seen_at`, `last_seen_at`, `ports[]` 等。

## Collection
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/collection/assets/{asset_id}/credential` | 用户 | Path: `asset_id` | `AssetCredentialReadResponse` |
| `POST` | `/api/v1/collection/assets/{asset_id}/credential` | 用户 | Path: `asset_id`; Body: `AssetCredentialUpsertRequest` | `AssetCredentialReadResponse` |
| `POST` | `/api/v1/collection/assets/{asset_id}/credential/verify` | 用户 | Path: `asset_id` | `AssetCredentialVerifyResponse` |
| `POST` | `/api/v1/collection/assets/credentials/batch` | 用户 | `AssetCredentialBatchUpsertRequest` | `AssetCredentialBatchResponse` |
| `POST` | `/api/v1/collection/assets/batch/run` | 用户 | `CollectBatchRunRequest` | `202 CollectRunResponse` |
| `POST` | `/api/v1/collection/assets/{asset_id}/run` | 用户 | Path: `asset_id`; Body: `CollectRunRequest` | `202 CollectRunResponse` |
| `POST` | `/api/v1/collection/assets/{asset_id}/probe` | 用户 | Path: `asset_id`; Body: `CollectProbeRunRequest` | `CollectProbeRunResponse` |
| `GET` | `/api/v1/collection/assets/{asset_id}/probe/latest` | 用户 | Path: `asset_id` | `CollectProbeLatestResponse` |
| `GET` | `/api/v1/collection/assets/{asset_id}/latest` | 用户 | Path: `asset_id` | `CollectLatestResponse` |
| `GET` | `/api/v1/collection/assets/{asset_id}/initial/latest` | 用户 | Path: `asset_id` | `CollectInitialLatestResponse` |

请求模型：
- `AssetCredentialUpsertRequest`: `auth_type` 为 `password` 或 `key`，并包含 `username`, `password?`, `private_key?`, `sudo_password?`, `admin_authorized`。
- `AssetCredentialBatchUpsertRequest`: 继承单资产凭据字段，并包含 `asset_ids[]`, `mode=same_credential_batch`, `verify_after_save`。
- `CollectRunRequest`: `credential_id?`, `connect_timeout_seconds?`, `command_timeout_seconds?`, `asset_timeout_seconds?`。
- `CollectBatchRunRequest`: 继承采集请求字段，并包含 `asset_ids[]`, `concurrency`。
- `CollectProbeRunRequest`: `credential_id?`, `preset`, `connect_timeout_seconds?`, `command_timeout_seconds?`。当前测试覆盖的合法 `preset` 为 `baseline`。

## Risks
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/risks` | 用户 | Query: `page`, `page_size`, `severity?`, `status?`, `keyword?` | `RiskFindingPageResponse` |
| `GET` | `/api/v1/risks/{finding_id}` | 用户 | Path: `finding_id` | `RiskFindingMobileRead` |
| `GET` | `/api/v1/risks/assets/{asset_id}` | 用户 | Path: `asset_id` | `RiskFindingListResponse` |
| `POST` | `/api/v1/risks/{finding_id}/assign` | 用户 | Path: `finding_id`; Body: `RiskFindingAssignRequest` | `FindingGovernanceRead` |
| `POST` | `/api/v1/risks/{finding_id}/waivers` | 用户 | Path: `finding_id`; Body: `RiskFindingWaiverCreateRequest` | `FindingWaiverRead` |
| `POST` | `/api/v1/risks/{finding_id}/recalculate-priority` | 用户 | Path: `finding_id` | `FindingGovernanceRead` |
| `POST` | `/api/v1/risks/assets/batch/verify` | 用户 | `RiskBatchVerifyRequest` | `202 RiskBatchVerifyResponse` |
| `POST` | `/api/v1/risks/assets/{asset_id}/verify` | 用户 | Path: `asset_id`; Body: `{}` | `202 TaskRunResponse` |
| `GET` | `/api/v1/risks/{finding_id}/remediation-template` | 用户 | Path: `finding_id` | `RiskRemediationTemplateRead` |

请求模型：
- `RiskFindingAssignRequest`: `owner_id?`。
- `RiskFindingWaiverCreateRequest`: `waiver_type`, `reason`, `expires_at?`；`waiver_type` 可选 `false_positive`, `accepted_risk`, `temporary_exception`。
- `RiskBatchVerifyRequest`: `asset_ids[]`，1 到 200 个。

响应模型：
- `RiskFindingMobileRead`: 风险基础信息、资产 IP/主机名、等级、状态、证据、治理、豁免等。

## Remediation
全部接口要求管理员鉴权。

| 方法 | 路径 | 参数/Body | 响应 |
| --- | --- | --- | --- |
| `GET` | `/api/v1/remediation/assets` | Query: `page`, `page_size`, `keyword?` | `RemediationAssetListRead` |
| `GET` | `/api/v1/remediation/assets/{asset_id}` | Path: `asset_id` | `RemediationAssetDetailRead` |
| `GET` | `/api/v1/remediation/assets/{asset_id}/runner` | Path: `asset_id` | `HostRunnerRead` |
| `POST` | `/api/v1/remediation/assets/{asset_id}/runner/install` | Path: `asset_id` | `202 HostRunnerInstallRead` |
| `GET` | `/api/v1/remediation/assets/{asset_id}/workspace` | Path: `asset_id` | `RemediationWorkspaceRead` |
| `POST` | `/api/v1/remediation/assets/{asset_id}/sessions` | Path: `asset_id`; Body: `RemediationSessionCreateRequest` | `RemediationSessionRead` |
| `GET` | `/api/v1/remediation/sessions/{session_id}` | Path: `session_id` | `RemediationSessionRead` |
| `POST` | `/api/v1/remediation/sessions/{session_id}/messages` | Path: `session_id`; Body: `RemediationSessionMessageCreateRequest` | `RemediationSessionRead` |
| `POST` | `/api/v1/remediation/sessions/{session_id}/approve` | Path: `session_id`; Body: `RemediationSessionApproveRequest?` | `202 RemediationSessionApproveResponse` |
| `GET` | `/api/v1/remediation/findings/{finding_id}/plan` | Path: `finding_id` | `RemediationPlanRead` |
| `POST` | `/api/v1/remediation/findings/{finding_id}/execute` | Path: `finding_id`; Body: `RemediationExecuteRequest` | `202 RemediationExecuteResponse` |
| `GET` | `/api/v1/remediation/tasks/{task_id}` | Path: `task_id` | `RemediationTaskRead` |
| `GET` | `/api/v1/remediation/tasks/{task_id}/evidence` | Path: `task_id` | `RemediationTaskEvidenceRead` |

请求模型：
- `RemediationSessionCreateRequest`: `note?`。
- `RemediationSessionMessageCreateRequest`: `intent`, `note?`。
- `RemediationSessionApproveRequest`: `stage_code?`, `execution_mode` 为 `dry_run` 或 `apply`，`change_ticket?`, `maintenance_window_id?`。默认 `execution_mode=apply`。
- `RemediationExecuteRequest`: `steps[]`，每项包含 `step_id`；`execution_mode` 为 `dry_run` 或 `apply`，默认 `dry_run`；`change_ticket?`, `maintenance_window_id?`。

响应模型：
- `HostRunnerInstallRead`: `task_id`, `status`, `runner_id?`, `stream_url`。
- `RemediationExecuteResponse`: `task_id`, `status`, `stream_url`, `execution_mode`。
- `RemediationSessionRead`: 会话状态、资产、授权、Runner、发现项、主机级修复计划、消息、最近任务等。

## Reports
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/reports/jobs/{job_id}/generate` | 用户 | Path: `job_id` | `202 GenerateReportResponse` |
| `POST` | `/api/v1/reports/assets/{asset_id}/generate` | 用户 | Path: `asset_id` | `202 GenerateReportResponse` |
| `GET` | `/api/v1/reports/jobs/{job_id}/latest` | 用户 | Path: `job_id` | `ReportRead` |
| `GET` | `/api/v1/reports/assets/{asset_id}/latest` | 用户 | Path: `asset_id` | `ReportRead` |
| `GET` | `/api/v1/reports/{report_id}` | 用户 | Path: `report_id` | `ReportRead` |
| `GET` | `/api/v1/reports/{report_id}/download/html` | 用户 | Path: `report_id` | `text/html` |
| `GET` | `/api/v1/reports/{report_id}/download/pdf` | 用户 | Path: `report_id` | `application/pdf` |

响应模型：
- `GenerateReportResponse`: `task_id`, `status`。
- `ReportRead`: `id`, `scope`, `scope_id`, `summary_md`, `risk_overview_json`, `analysis_json`, `created_at`。

## Runner
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/runner/register` | 注册令牌在 Body 中 | `RunnerRegisterRequest` | `RunnerRegisterResponse` |
| `POST` | `/api/v1/runner/heartbeat` | Runner Token | `RunnerHeartbeatRequest` | `HostRunnerRead` |
| `POST` | `/api/v1/runner/poll` | Runner Token | `RunnerPollRequest` | `RunnerPollResponse` |
| `POST` | `/api/v1/runner/tasks/{task_id}/events` | Runner Token | Path: `task_id`; Body: `RunnerTaskEventBatch` | `202 {"status":"accepted"}` |
| `POST` | `/api/v1/runner/tasks/{task_id}/complete` | Runner Token | Path: `task_id`; Body: `RunnerTaskCompleteRequest` | `dict` |

请求模型：
- `RunnerRegisterRequest`: `registration_token`, `asset_id`, `version?`, `capabilities`, `runtime_kind?`, `install_mode?`, `service_mode?`, `host_facts`, `compatibility_issues[]`。
- `RunnerHeartbeatRequest`: `version?`, `status?`, `capabilities`, `last_error?`, `runtime_kind?`, `install_mode?`, `service_mode?`, `host_facts`, `compatibility_issues[]`。
- `RunnerPollRequest`: `max_tasks`，默认 `1`。
- `RunnerTaskEventBatch`: `events[]`，事件包含 `event_type`, `level`, `stage_code?`, `stage_name?`, `message?`, `progress?`, `payload_json`。
- `RunnerTaskCompleteRequest`: `status` 为 `success` 或 `failure`，并包含 `execution`, `backups`, `step_results[]`, `message?`。

## Settings
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/settings` | 管理员 | 无 | `PlatformSettingsRead` |
| `PUT` | `/api/v1/settings` | 管理员 | `PlatformSettingsUpdate` | `202 PlatformSettingsApplyResponse` |
| `POST` | `/api/v1/settings/ai/validate` | 管理员 | `PlatformAIValidateRequest` | `PlatformAIValidateResponse` |
| `POST` | `/api/v1/settings/ai/models` | 管理员 | `PlatformAIModelsRequest` | `PlatformAIModelsResponse` |
| `POST` | `/api/v1/settings/internal/tasks/{task_id}/complete` | settings-helper | Header: `X-Settings-Helper-Token`; Body: `PlatformSettingsApplyComplete` | `dict` |

请求模型：
- `PlatformSettingsUpdate` 包含 Runner、修复、发现、校区、主动验证、LLM、CORS、本地资产、管理员 CIDR、Token 过期时间等配置字段。
- `llm_provider`: `mock`, `openai`, `minimax`, `custom_proxy`, `ollama_remote`。
- `llm_wire_api`: `auto`, `chat_completions`, `responses`。
- `PlatformAIValidateRequest` 和 `PlatformAIModelsRequest` 均包含 `llm_provider`, `llm_model/base_url`, `llm_wire_api`, `llm_timeout_seconds`, `llm_api_key?`, `clear_llm_api_key`。

响应模型：
- `PlatformSettingsApplyResponse`: `task_id`, `status`。
- `PlatformAIValidateResponse`: `ok`, `message`, `provider`, `model`, `resolved_base_url`, `used_saved_api_key`, `latency_ms`。
- `PlatformAIModelsResponse`: 上述字段加 `models[]`。

## Tasks
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/tasks/events` | 用户 | Query: `page`, `page_size`, `task_type?`, `status?`, `level?`, `task_id?`, `keyword?` | `TaskEventListResponse` |
| `GET` | `/api/v1/tasks` | 用户 | Query: `page`, `page_size`, `task_type?`, `status?` | `TaskRunListResponse` |
| `DELETE` | `/api/v1/tasks` | 用户 | Query: `task_type?`, `status?`, `include_active=false` | `TaskRunClearResponse` |
| `GET` | `/api/v1/tasks/{task_id}/events` | 用户 | Path: `task_id`; Query: `page`, `page_size`, `level?` | `TaskEventListResponse` |
| `GET` | `/api/v1/tasks/{task_id}` | 用户 | Path: `task_id` | `TaskRunDetailRead` |
| `POST` | `/api/v1/tasks/{task_id}/cancel` | 用户 | Path: `task_id` | `TaskRunResponse` |

响应模型：
- `TaskRunRead`: `id`, `task_type`, `status`, `scope_type?`, `scope_id?`, `celery_task_id?`, `progress`, `message?`, `retry_count`, `result_json`, `error_json`, `created_at`, `started_at?`, `finished_at?`, `updated_at`, `timing`。
- `TaskEventRead`: `id`, `task_run_id`, `task_type?`, `status?`, `event_type`, `level`, `stage_code?`, `stage_name?`, `message?`, `progress?`, `payload_json`, `created_at`。

## Logs
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/logs` | 管理员 | Query: `page`, `page_size`, `source_kind?`, `service_name?`, `task_id?`, `task_type?`, `level?`, `keyword?` | `LogEntryListResponse` |

`LogEntryRead` 字段：`id`, `source_kind`, `service_name`, `logger_name`, `task_run_id?`, `task_type?`, `event_type`, `level`, `stage_code?`, `stage_name?`, `message?`, `payload_json`, `created_at`。

## Vulnerability Library
| 方法 | 路径 | 鉴权 | 参数/Body | 响应 |
| --- | --- | --- | --- | --- |
| `GET` | `/api/v1/vuln-library/status` | 用户 | 无 | `RuleEngineStatusRead` |
| `GET` | `/api/v1/vuln-library/intel/status` | 用户 | 无 | `VulnIntelStatusRead` |
| `POST` | `/api/v1/vuln-library/intel/sync` | 管理员 | 无 | `VulnIntelStatusRead` |
| `GET` | `/api/v1/vuln-library/rules` | 用户 | Query: `page`, `page_size`, `keyword?`, `service?`, `severity?`, `enabled?`, `catalog_view=default` | `VulnRuleListResponse` |
| `POST` | `/api/v1/vuln-library/rules` | 管理员 | `VulnRuleCreate` | `201 VulnRuleRead` |
| `GET` | `/api/v1/vuln-library/rules/export` | 管理员 | Query: `format` 为 `yaml` 或 `json`，`rule_ids?`, `keyword?`, `service?`, `severity?`, `enabled?`, `catalog_view?` | 文件下载 |
| `POST` | `/api/v1/vuln-library/rules/import` | 管理员 | `multipart/form-data`: `file`, `format`, `mode`, `dry_run` | `VulnRuleImportResponse` |
| `POST` | `/api/v1/vuln-library/rules/batch/status` | 管理员 | `VulnRuleBatchStatusRequest` | `VulnRuleBatchStatusResponse` |
| `GET` | `/api/v1/vuln-library/rules/{rule_id}` | 用户 | Path: `rule_id` | `VulnRuleRead` |
| `PUT` | `/api/v1/vuln-library/rules/{rule_id}` | 管理员 | Path: `rule_id`; Body: `VulnRuleUpdate` | `VulnRuleRead` |
| `DELETE` | `/api/v1/vuln-library/rules/{rule_id}` | 管理员 | Path: `rule_id` | `204` |
| `POST` | `/api/v1/vuln-library/index/rebuild` | 管理员 | 无 | `VulnRuleIndexRebuildResponse` |

规则请求模型：
- `VulnRuleCreate`: `id` 加 `VulnRuleBase` 字段。
- `VulnRuleBase`: `name`, `enabled`, `service`, `severity`, `description`, `match`, `cve_ids[]`, `cwe_ids[]`, `affected_versions_text?`, `exploit_module?`, `preconditions[]`, `verify_playbook[]`, `mitigations[]`, `remediation?`, `references[]`, `tags[]`, `active_check?`。
- `VulnRuleMatch`: 至少包含 `version`, `config`, `nse`, `package` 之一。
- `VulnRuleBatchStatusRequest`: `rule_ids[]`, `enabled`。
- 导入参数：`format` 为 `auto`, `yaml`, `json`；`mode` 为 `skip_existing`, `upsert`。

## WebSocket 接口
| 路径 | 鉴权 | 客户端消息 | 服务端消息 |
| --- | --- | --- | --- |
| `ws /api/v1/agent/haor/session/stream` | 用户；`?token=` 或首帧 `{"type":"auth","token":"..."}` | `hello`, `message`, `ui_step`, `approve_plan`, `ping` | `session_snapshot`, `agent_state`, `turn_started`, `assistant_message_start`, `assistant_message_delta`, `assistant_message_done`, `action_update`, `ui_actions_requested`, `plan_pending`, `task_update`, `error`, `turn_done` |
| `ws /api/v1/remediation/tasks/{task_id}/stream?token=...` | 管理员 | 无主动业务消息 | `task`, `event`, `complete`, `error` |
| `ws /api/v1/remediation/sessions/{session_id}/stream?token=...` | 管理员 | 无主动业务消息 | `session_snapshot`, `ai_generation_started`, `session_message_added`, `error` |
| `ws /api/v1/logs/stream?token=...` | 管理员 | 无主动业务消息 | `snapshot`, `log_append`, `heartbeat`, `error` |
| `ws /api/v1/mobile/alerts/stream?token=...` | 用户 | 任意文本用于保持连接 | `ready` 和设备异常告警事件 |

### Haor WebSocket 客户端消息
`AgentStreamClientEnvelope` 字段：
- `type`: `hello`, `message`, `ui_step`, `approve_plan`, `ping`。
- `client_message_id?`, `step_request_id?`, `content?`, `note?`。
- `page_context`: `pathname`, `query`, `asset_id?`, `finding_id?`, `task_id?`。
- `browser_context`: 页面 DOM、可见操作、语义区块、表单、选中实体等浏览器运行时上下文。
- `ui_action_results[]`: UI 执行结果，仅 `ui_step` 使用。

示例：
```json
{
  "type": "message",
  "client_message_id": "msg-1",
  "content": "帮我查看当前资产的高危风险",
  "page_context": {
    "pathname": "/assets/asset-1",
    "query": {},
    "asset_id": "asset-1",
    "finding_id": null,
    "task_id": null
  },
  "browser_context": {
    "pathname": "/assets/asset-1",
    "query": {},
    "visible_actions": [],
    "semantic_actions": [],
    "semantic_forms": [],
    "dom_snapshot": []
  },
  "ui_action_results": []
}
```

### 修复任务 WebSocket 消息
任务流消息：
- `{"type":"task","task":{"task_id":"...","status":"running","progress":50,"message":"..."}}`
- `{"type":"event","event":{...TaskEventRead}}`
- `{"type":"complete","status":"success"}`
- `{"type":"error","message":"任务不存在"}`

修复会话流消息：
- `{"type":"session_snapshot","session":{...RemediationSessionRead}}`
- `{"type":"ai_generation_started","reason":"..."}`
- `{"type":"session_message_added","message":{...RemediationMessageRead}}`
- `{"type":"error","message":"..."}`

日志流消息：
- `snapshot`: 初始日志列表和分页信息。
- `log_append`: 新增日志项。
- `heartbeat`: 心跳。
- `error`: 实时日志通道错误。

## 代码入口
- 路由挂载：[backend/app/api/v1/router.py](../backend/app/api/v1/router.py)
- HTTP 实现：[backend/app/api/v1/endpoints/](../backend/app/api/v1/endpoints/)
- 请求/响应模型：[backend/app/schemas/](../backend/app/schemas/)
- 鉴权依赖：[backend/app/api/deps.py](../backend/app/api/deps.py)
- WebSocket 认证：[backend/app/api/websocket_auth.py](../backend/app/api/websocket_auth.py)
- 前端 API 客户端：[frontend/src/services/api.ts](../frontend/src/services/api.ts)
- 移动端 API 客户端：[../situational-awareness-mobile/lib/core/network/api_client.dart](../../situational-awareness-mobile/lib/core/network/api_client.dart)

## 校验方式
在后端虚拟环境中生成 OpenAPI，用于核对 HTTP 接口是否与本文档一致：
```bash
cd backend
.venv/bin/python - <<'PY'
from app.main import app
schema = app.openapi()
print(schema["info"])
print("paths", len(schema["paths"]))
for path, methods in schema["paths"].items():
    print(path, ",".join(methods))
PY
```

## 相关文档
- 项目总入口：[../README.md](../README.md)
- 文档总索引：[README.md](README.md)
- 后端设计：[backend-design.md](backend-design.md)
- 前端设计：[frontend-design.md](frontend-design.md)
- Haor 设计：[haor-agent-design.md](haor-agent-design.md)
- 运行手册：[runbook.md](runbook.md)
