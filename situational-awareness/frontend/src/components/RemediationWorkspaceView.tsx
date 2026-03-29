"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Input,
  List,
  Row,
  Col,
  Space,
  Typography,
  message,
  Tag,
} from "antd";

import CollapsibleJsonBlock from "@/components/CollapsibleJsonBlock";
import DesktopPageHeader from "@/components/DesktopPageHeader";
import StatusTag from "@/components/StatusTag";
import { getStoredToken } from "@/lib/auth";
import {
  buildRemediationAssetPath,
  pickRecommendedFindingId,
  remediationBusinessStatusLabel,
  remediationExecutionStatusLabel,
} from "@/lib/remediation";
import { formatDateTime, getTaskEventTypeLabel, localizeTaskMessage } from "@/lib/ui-text";
import { executeRemediationPlan, getRemediationPlan, getRemediationTask, getRemediationWorkspace } from "@/services/api";
import { RemediationPlan, RemediationStreamEnvelope, RemediationTask, RemediationWorkspace } from "@/types/remediation";

function toRecord(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }
  return input as Record<string, unknown>;
}

function buildRemediationWebSocketUrl(streamPath: string, token: string): string {
  const apiBase = (process.env.NEXT_PUBLIC_API_BASE || "/api/v1").replace(/\/$/, "");
  if (apiBase.startsWith("http://") || apiBase.startsWith("https://")) {
    const parsed = new URL(apiBase);
    const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${parsed.host}${streamPath}?token=${encodeURIComponent(token)}`;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${streamPath}?token=${encodeURIComponent(token)}`;
}

function remediationBusinessStatusColor(value: string | null | undefined): string {
  switch ((value || "").trim().toLowerCase()) {
    case "verified_closed":
      return "green";
    case "pending_reverify":
      return "blue";
    case "verified_partial":
      return "orange";
    case "verified_failed":
      return "red";
    default:
      return "default";
  }
}

export default function RemediationWorkspaceView({ assetId }: { assetId: string }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const findingId = searchParams?.get("findingId") || "";
  const taskId = searchParams?.get("taskId") || "";

  const [workspace, setWorkspace] = useState<RemediationWorkspace | null>(null);
  const [plan, setPlan] = useState<RemediationPlan | null>(null);
  const [task, setTask] = useState<RemediationTask | null>(null);
  const [workspaceLoading, setWorkspaceLoading] = useState(false);
  const [planLoading, setPlanLoading] = useState(false);
  const [executeModeLoading, setExecuteModeLoading] = useState<"dry_run" | "apply" | null>(null);
  const [taskLoading, setTaskLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [streamLines, setStreamLines] = useState<string[]>([]);
  const [activeTaskId, setActiveTaskId] = useState(taskId);

  useEffect(() => {
    setActiveTaskId(taskId);
  }, [taskId]);

  useEffect(() => {
    setWorkspaceLoading(true);
    getRemediationWorkspace(assetId)
      .then((result) => {
        setWorkspace(result);
        setError(null);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setWorkspaceLoading(false));
  }, [assetId]);

  useEffect(() => {
    if (!workspace || !assetId || findingId) {
      return;
    }
    const recommendedFindingId = pickRecommendedFindingId(workspace);
    if (!recommendedFindingId) {
      return;
    }
    router.replace(
      buildRemediationAssetPath(assetId, {
        findingId: recommendedFindingId,
        taskId: taskId || undefined,
      }),
    );
  }, [assetId, findingId, router, taskId, workspace]);

  useEffect(() => {
    if (!findingId) {
      setPlan(null);
      return;
    }
    setPlanLoading(true);
    getRemediationPlan(findingId)
      .then((result) => {
        setPlan(result);
        setError(null);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setPlanLoading(false));
  }, [findingId]);

  useEffect(() => {
    if (!activeTaskId) {
      setTask(null);
      setStreamLines([]);
      return;
    }
    setTaskLoading(true);
    getRemediationTask(activeTaskId)
      .then((result) => {
        setTask(result);
        setError(null);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setTaskLoading(false));
  }, [activeTaskId]);

  useEffect(() => {
    if (!activeTaskId) {
      return undefined;
    }
    const token = getStoredToken();
    if (!token) {
      return undefined;
    }
    const ws = new WebSocket(buildRemediationWebSocketUrl(`/api/v1/remediation/tasks/${activeTaskId}/stream`, token));
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as RemediationStreamEnvelope;
        if (payload.type === "task") {
          setTask((current) =>
            current
              ? {
                  ...current,
                  status: payload.task.status as RemediationTask["status"],
                  progress: payload.task.progress,
                  message: payload.task.message,
                }
              : current,
          );
          return;
        }
        if (payload.type === "event") {
          const raw = toRecord(payload.event);
          const eventType = String(raw.event_type || "");
          const payloadJson = toRecord(raw.payload_json);
          let nextLine = "";
          if (eventType === "stream") {
            nextLine = String(payloadJson.text || "");
          } else if (eventType === "command") {
            nextLine = `$ ${String(payloadJson.submitted_command || "")}`.trim();
          } else {
            nextLine = `[${getTaskEventTypeLabel(eventType)}] ${localizeTaskMessage(String(raw.message || ""))}`.trim();
          }
          if (nextLine) {
            setStreamLines((current) => [...current.slice(-199), nextLine]);
          }
          return;
        }
        if (payload.type === "complete") {
          void getRemediationTask(activeTaskId).then(setTask);
        }
      } catch {
        // ignore malformed stream frames
      }
    };
    return () => ws.close();
  }, [activeTaskId]);

  useEffect(() => {
    if (!activeTaskId || !task || !["pending", "running", "retry"].includes(task.status)) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void getRemediationTask(activeTaskId).then(setTask).catch(() => undefined);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeTaskId, task]);

  const supportedStepCount = useMemo(
    () => (plan?.steps || []).filter((step) => step.execution_state === "ready").length,
    [plan],
  );
  const stepResults = useMemo(() => {
    const execution = toRecord(task?.execution);
    const raw = execution.step_results;
    return Array.isArray(raw) ? raw.map((item) => toRecord(item)) : [];
  }, [task]);

  const navigateToAssetWorkspace = (
    nextFindingId?: string | null,
    nextTaskId?: string | null,
    options?: { replace?: boolean },
  ) => {
    const target = buildRemediationAssetPath(assetId, {
      findingId: nextFindingId ?? undefined,
      taskId: nextTaskId ?? undefined,
    });
    if (options?.replace) {
      router.replace(target);
      return;
    }
    router.push(target);
  };

  const openFinding = (nextFindingId: string) => {
    navigateToAssetWorkspace(nextFindingId, null);
  };

  const onExecute = async (executionMode: "dry_run" | "apply") => {
    if (!plan) {
      return;
    }
    try {
      setExecuteModeLoading(executionMode);
      const response = await executeRemediationPlan(plan.finding_id, {
        steps: plan.steps
          .filter((step) => step.execution_state === "ready")
          .map((step) => ({ step_id: step.step_id })),
        execution_mode: executionMode,
      });
      message.success(executionMode === "dry_run" ? `修复预演已生成：${response.task_id}` : `修复任务已提交：${response.task_id}`);
      setStreamLines([]);
      setActiveTaskId(response.task_id);
      navigateToAssetWorkspace(plan.finding_id, response.task_id);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setExecuteModeLoading(null);
    }
  };

  const refreshWorkspace = async () => {
    try {
      setWorkspaceLoading(true);
      const result = await getRemediationWorkspace(assetId);
      setWorkspace(result);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setWorkspaceLoading(false);
    }
    if (!activeTaskId) {
      return;
    }
    try {
      setTaskLoading(true);
      const result = await getRemediationTask(activeTaskId);
      setTask(result);
    } catch {
      // ignore task refresh failures and keep current page state
    } finally {
      setTaskLoading(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="漏洞修复"
        title="资产修复工作区"
        description="围绕当前资产的可修复风险、模板命令和 SSH 授权执行结果，完成单资产修复闭环。"
        meta={[
          { label: "当前资产", value: workspace?.asset.hostname || workspace?.asset.ip || assetId, tone: "success" },
          { label: "可修复风险", value: workspace?.findings.length || 0, tone: workspace?.findings.length ? "danger" : "neutral" },
          { label: "当前任务", value: activeTaskId || "无", tone: activeTaskId ? "accent" : "neutral" },
        ]}
        actions={(
          <Space wrap>
            <Button onClick={() => router.push("/remediation")}>返回资产选择</Button>
            <Button onClick={() => activeTaskId && router.push(`/tasks/${activeTaskId}`)} disabled={!activeTaskId}>
              查看任务详情
            </Button>
            <Button onClick={() => void refreshWorkspace()} loading={workspaceLoading || taskLoading}>
              刷新工作区
            </Button>
          </Space>
        )}
      />

      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Row gutter={16} align="top">
        <Col xs={24} xl={8}>
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Card className="panel-card" loading={workspaceLoading} title="资产与授权">
              {workspace ? (
                <Descriptions column={1} size="small" bordered>
                  <Descriptions.Item label="资产">{workspace.asset.hostname || workspace.asset.ip}</Descriptions.Item>
                  <Descriptions.Item label="系统">{workspace.asset.os_name || "-"}</Descriptions.Item>
                  <Descriptions.Item label="授权状态">
                    <Space wrap>
                      <StatusTag value={workspace.authorization.last_verification_status || "unknown"} />
                      <Typography.Text>{workspace.authorization.effective_privilege || "-"}</Typography.Text>
                    </Space>
                  </Descriptions.Item>
                  <Descriptions.Item label="最近验证">{formatDateTime(workspace.authorization.last_verified_at)}</Descriptions.Item>
                  <Descriptions.Item label="最近深度检查">{formatDateTime(workspace.latest_collection?.collected_at || null)}</Descriptions.Item>
                </Descriptions>
              ) : (
                <Empty description="暂无资产上下文" />
              )}
              {workspace?.authorization.blocked_reasons?.length ? (
                <Alert
                  style={{ marginTop: 12 }}
                  type="warning"
                  showIcon
                  message="当前不满足自动修复执行条件"
                  description={workspace.authorization.blocked_reasons.join("；")}
                />
              ) : null}
            </Card>

            <Card className="panel-card" title="可修复风险">
              {workspace?.findings?.length ? (
                <List
                  dataSource={workspace.findings}
                  renderItem={(item) => (
                    <List.Item
                      actions={[
                        <Button key="open" size="small" type={item.finding_id === findingId ? "primary" : "default"} onClick={() => openFinding(item.finding_id)}>
                          载入计划
                        </Button>,
                      ]}
                    >
                      <List.Item.Meta
                        title={(
                          <Space wrap>
                            <StatusTag value={item.severity} />
                            {item.title}
                          </Space>
                        )}
                        description={(
                          <Space direction="vertical" size={4}>
                            <Typography.Text type="secondary">规则: {item.rule_id || "-"}</Typography.Text>
                            <Typography.Text type="secondary">服务: {item.service_name || "-"}</Typography.Text>
                            <Typography.Text type="secondary">发现时间: {new Date(item.detected_at).toLocaleString()}</Typography.Text>
                          </Space>
                        )}
                      />
                    </List.Item>
                  )}
                />
              ) : (
                <Empty description="当前资产暂无可修复风险" />
              )}
            </Card>
          </Space>
        </Col>

        <Col xs={24} xl={16}>
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Card
              className="panel-card"
              loading={planLoading}
              title="修复模板与命令"
              extra={(
                <Space wrap>
                  <Button
                    type="primary"
                    onClick={() => void onExecute("dry_run")}
                    loading={executeModeLoading === "dry_run"}
                    disabled={!plan || !plan.execution_ready || supportedStepCount === 0}
                  >
                    生成修复预演
                  </Button>
                  <Button
                    onClick={() => void onExecute("apply")}
                    loading={executeModeLoading === "apply"}
                    disabled={!plan || !plan.execution_ready || supportedStepCount === 0}
                  >
                    正式执行
                  </Button>
                </Space>
              )}
            >
              {!plan ? (
                <Empty description="选择一条风险后加载修复计划。" />
              ) : (
                <Space direction="vertical" size={12} style={{ width: "100%" }}>
                  <Space wrap>
                    <StatusTag value={plan.severity} />
                    <Tag color={plan.execution_ready ? "green" : "orange"}>{plan.execution_ready ? "可执行" : "仅查看"}</Tag>
                    <Typography.Text strong>{plan.rule_name}</Typography.Text>
                  </Space>
                  <Typography.Paragraph style={{ marginBottom: 0 }}>{plan.summary}</Typography.Paragraph>
                  <Alert
                    type="info"
                    showIcon
                    message="默认先预演，再决定是否正式执行"
                    description="预演只生成命令、证据项与执行边界，不会修改主机；正式执行才会真正写入目标主机。"
                  />
                  {plan.blocked_reasons.length ? <Alert type="warning" showIcon message={plan.blocked_reasons.join("；")} /> : null}
                  <List
                    dataSource={plan.steps}
                    renderItem={(step) => {
                      return (
                        <List.Item>
                          <Space direction="vertical" size={8} style={{ width: "100%" }}>
                            <Space wrap>
                              <Typography.Text strong>{step.title}</Typography.Text>
                              <Tag color={step.execution_state === "ready" ? "green" : "orange"}>
                                {step.execution_state === "ready" ? "自动执行" : "阻塞"}
                              </Tag>
                              <Tag color={step.risk_level === "high" ? "red" : step.risk_level === "medium" ? "orange" : "green"}>
                                风险 {step.risk_level}
                              </Tag>
                              {step.dry_run_supported ? <Tag color="blue">支持预演</Tag> : null}
                              <Tag color={step.rollback_supported ? "green" : "default"}>
                                {step.rollback_supported ? "支持回滚" : "回滚受限"}
                              </Tag>
                              {step.requires_maintenance_window ? <Tag color="magenta">需维护窗口</Tag> : null}
                              {step.fallback_strategy === "legacy_debian_auto_guess" ? <Tag color="gold">旧版 Debian 自动解析</Tag> : null}
                            </Space>
                            <Typography.Text type="secondary">{step.render_reason}</Typography.Text>
                            {step.blocked_reason ? <Alert type="warning" showIcon message={step.blocked_reason} /> : null}
                            {step.fallback_strategy === "legacy_debian_auto_guess" && step.fallback_candidates.length ? (
                              <Typography.Text type="secondary">
                                候选包/服务: {step.fallback_candidates.join("、")}
                              </Typography.Text>
                            ) : null}
                            {step.backup_plan ? (
                              <Typography.Text type="secondary">
                                备份: {step.backup_plan.kind} / {step.backup_plan.targets.join("、") || "-"}
                              </Typography.Text>
                            ) : null}
                            <Typography.Text type="secondary">
                              适配器: {step.adapter_id || "-"} / {step.adapter_version || "-"}
                            </Typography.Text>
                            {step.evidence_items.length ? (
                              <Typography.Text type="secondary">
                                证据项: {step.evidence_items.join("、")}
                              </Typography.Text>
                            ) : null}
                            <Input.TextArea
                              rows={step.execution_state === "ready" ? 6 : 3}
                              value={step.generated_command || ""}
                              readOnly
                              disabled
                            />
                          </Space>
                        </List.Item>
                      );
                    }}
                  />
                  <CollapsibleJsonBlock title="模板来源（JSON）" value={plan.source_refs} />
                </Space>
              )}
            </Card>

            <Card className="panel-card" loading={taskLoading} title="执行状态与流式输出">
              {task ? (
                <Space direction="vertical" size={12} style={{ width: "100%" }}>
                  <Descriptions column={1} size="small" bordered>
                    <Descriptions.Item label="任务状态">
                      <Space wrap>
                        <StatusTag value={task.status} />
                        <Typography.Text>{task.execution_boundary || "-"}</Typography.Text>
                        <Tag>{task.execution_mode || "-"}</Tag>
                        <Tag>{remediationExecutionStatusLabel(task.execution_status)}</Tag>
                        {task.business_status ? (
                          <Tag color={remediationBusinessStatusColor(task.business_status)}>
                            {remediationBusinessStatusLabel(task.business_status)}
                          </Tag>
                        ) : null}
                      </Space>
                    </Descriptions.Item>
                    <Descriptions.Item label="进度">{task.progress}%</Descriptions.Item>
                    <Descriptions.Item label="最近消息">{localizeTaskMessage(task.message)}</Descriptions.Item>
                    <Descriptions.Item label="自动复测">
                      {String(task.reverify_task_id || toRecord(task.reverify).reverify_task_id || "-")}
                    </Descriptions.Item>
                    {task.business_status ? (
                      <Descriptions.Item label="业务闭环">
                        {remediationBusinessStatusLabel(task.business_status)}
                      </Descriptions.Item>
                    ) : null}
                  </Descriptions>
                  {Object.keys(task.reverify_summary || {}).length ? (
                    <Alert
                      type={task.business_status === "verified_closed" ? "success" : task.business_status === "verified_failed" ? "error" : "info"}
                      showIcon
                      message={remediationBusinessStatusLabel(task.business_status)}
                      description={localizeTaskMessage(task.message)}
                    />
                  ) : null}
                  <div className="remediation-stream-shell">
                    <pre className="remediation-stream-body">
                      {(streamLines.length ? streamLines : ["等待任务输出..."]).join("\n")}
                    </pre>
                  </div>
                </Space>
              ) : (
                <Empty description="执行修复后会在此显示流式输出。" />
              )}
            </Card>

            <Card className="panel-card" title="步骤结果">
              {stepResults.length ? (
                <List
                  dataSource={stepResults}
                  renderItem={(item) => (
                    <List.Item>
                      <List.Item.Meta
                        title={(
                          <Space wrap>
                            <StatusTag value={String(item.status || "-")} />
                            {String(item.title || item.step_id || "-")}
                          </Space>
                        )}
                        description={(
                          <Space direction="vertical" size={4}>
                            <Typography.Text type="secondary">开始: {formatDateTime(String(item.started_at || ""))}</Typography.Text>
                            <Typography.Text type="secondary">完成: {formatDateTime(String(item.finished_at || ""))}</Typography.Text>
                            {item.error ? <Typography.Text type="danger">{String(item.error)}</Typography.Text> : null}
                          </Space>
                        )}
                      />
                    </List.Item>
                  )}
                />
              ) : (
                <Empty description="暂无步骤执行结果" />
              )}
              {task ? <CollapsibleJsonBlock title="任务结果（JSON）" value={task.execution} /> : null}
              {task ? <CollapsibleJsonBlock title="业务复验（JSON）" value={task.reverify_summary} /> : null}
            </Card>
          </Space>
        </Col>
      </Row>
    </Space>
  );
}
