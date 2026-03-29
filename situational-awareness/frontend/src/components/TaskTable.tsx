"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert, Button, Card, Grid, Popconfirm, Progress, Select, Space, Table, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";
import { cancelTask, clearTasks, listTasks } from "@/services/api";
import { TaskRun, TaskStatus, TaskType } from "@/types/task";
import {
  formatDurationMs,
  getScopeTypeLabel,
  getTaskStageLabel,
  getTaskTypeLabel,
  isTaskActive,
  localizeTaskMessage,
} from "@/lib/ui-text";

function renderTaskSummary(value: Record<string, unknown>, record: TaskRun): string {
  if (record.task_type === "risk_verify") {
    const passive = Number(value?.passive_match_count ?? 0);
    const total = Number(value?.active_check_total ?? 0);
    const confirmed = Number(value?.active_confirmed_count ?? 0);
    const rejected = Number(value?.active_rejected_count ?? 0);
    const abnormal = Number(value?.active_error_count ?? 0) + Number(value?.active_inconclusive_count ?? 0);
    if (!passive && !total && !confirmed && !rejected && !abnormal) {
      return "-";
    }
    return `被动命中:${passive} / 主动探测:${total} / 已确认:${confirmed} / 已排除:${rejected} / 异常或待确认:${abnormal}`;
  }
  if (record.task_type === "info_collect") {
    const processed = Number(value?.processed ?? 0);
    const success = Number(value?.success ?? 0);
    const partial = Number(value?.partial ?? 0);
    const failed = Number(value?.failed ?? 0);
    const nseCandidates = Number(value?.nse_candidate_port_count ?? 0);
    const nseExecuted = Number(value?.nse_executed_port_count ?? 0);
    const nseScripts = Number(value?.nse_script_run_count ?? 0);
    const nseHits = Number(value?.nse_hit_count ?? 0);
    const nseSkipped = Number(value?.nse_skipped_count ?? 0);
    const nseErrors = Number(value?.nse_error_count ?? 0);
    const queuedRisk = Number(value?.queued_risk_verify_count ?? 0);
    if (!processed && !success && !partial && !failed && !nseCandidates && !nseExecuted && !nseScripts && !nseHits && !nseSkipped && !nseErrors && !queuedRisk) {
      return "-";
    }
    const batchPrefix = processed ? `处理:${processed} / 成功:${success} / 部分成功:${partial} / 失败:${failed} / ` : "";
    return `${batchPrefix}NSE候选:${nseCandidates} / NSE执行:${nseExecuted} / NSE脚本:${nseScripts} / NSE命中:${nseHits} / NSE跳过:${nseSkipped} / NSE异常:${nseErrors} / 已触发风险验证:${queuedRisk}`;
  }
  if (record.task_type === "remediation_execute") {
    const execution = (value?.execution || {}) as Record<string, unknown>;
    const success = Number(execution?.success_count ?? 0);
    const executed = Number(execution?.executed_count ?? 0);
    const reverify = (value?.reverify || {}) as Record<string, unknown>;
    const boundary = String(execution?.execution_boundary || "-");
    const businessStatus = String(value?.business_status || execution?.business_status || "-");
    if (!success && !executed && !reverify?.reverify_task_id && businessStatus === "-") {
      return "-";
    }
    return `已执行:${executed} / 成功:${success} / 执行边界:${boundary} / 业务状态:${businessStatus} / 复测任务:${String((value?.reverify_task_id as string) || reverify?.reverify_task_id || "-")}`;
  }
  if (record.task_type === "runner_install") {
    const install = (value?.install || {}) as Record<string, unknown>;
    const runnerStatus = String(install?.runner_status || "-");
    const installStatus = String(install?.status || "-");
    return `安装状态:${installStatus} / Runner状态:${runnerStatus}`;
  }
  const low = Number(value?.low_confidence_count ?? 0);
  const enriched = Number(value?.nmap_enriched_count ?? 0);
  const skipped = Number(value?.nmap_skipped_count ?? 0);
  const unresolved = Number(value?.unresolved_count ?? 0);
  const highPortOpen = Number(value?.high_port_open_count ?? 0);
  const backdoorCandidate = Number(value?.backdoor_candidate_count ?? 0);
  const nseExecuted = Number(value?.nse_executed_port_count ?? 0);
  const nseScripts = Number(value?.nse_script_run_count ?? 0);
  const nseHits = Number(value?.nse_hit_count ?? 0);
  const nseSkipped = Number(value?.nse_skipped_count ?? 0);
  const nseErrors = Number(value?.nse_error_count ?? 0);
  if (!low && !enriched && !skipped && !unresolved && !highPortOpen && !backdoorCandidate && !nseExecuted && !nseScripts && !nseHits && !nseSkipped && !nseErrors) {
    return "-";
  }
  return `低置信:${low} / nmap补扫:${enriched} / 策略跳过:${skipped} / NSE端口:${nseExecuted} / NSE脚本:${nseScripts} / NSE命中:${nseHits} / NSE跳过:${nseSkipped} / NSE异常:${nseErrors} / 未解决:${unresolved} / 高位开放:${highPortOpen} / 后门候选:${backdoorCandidate}`;
}

export default function TaskTable() {
  const screens = Grid.useBreakpoint();
  const router = useRouter();
  const [items, setItems] = useState<TaskRun[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<TaskStatus | "all">("all");
  const [taskType, setTaskType] = useState<TaskType | "all">("all");
  const [clearing, setClearing] = useState(false);
  const [cancelingTaskId, setCancelingTaskId] = useState<string | null>(null);

  const load = async () => {
    try {
      setLoading(true);
      const result = await listTasks({ pageSize: 100, status, taskType });
      setItems(result.items);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [status, taskType]);

  const hasActiveTasks = useMemo(() => items.some((item) => isTaskActive(item.status)), [items]);

  useEffect(() => {
    if (!hasActiveTasks) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [hasActiveTasks, status, taskType]);

  const summary = useMemo(() => {
    const queued = items.filter((item) => ["pending", "running", "retry"].includes(item.status)).length;
    const success = items.filter((item) => item.status === "success").length;
    const failed = items.filter((item) => item.status === "failure").length;
    const canceled = items.filter((item) => item.status === "canceled").length;
    const avgProgress = items.length
      ? Math.round(items.reduce((sum, item) => sum + Number(item.progress || 0), 0) / items.length)
      : 0;
    return { queued, success, failed, canceled, avgProgress };
  }, [items]);

  const onClearTasks = async () => {
    try {
      setClearing(true);
      const result = await clearTasks({ taskType, status, includeActive: true });
      message.success(`已清除 ${result.deleted} 条任务记录`);
      await load();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setClearing(false);
    }
  };

  const onCancelTask = async (taskId: string) => {
    try {
      setCancelingTaskId(taskId);
      const result = await cancelTask(taskId);
      message.success(result.status === "canceled" ? "任务已中断" : "中断请求已提交");
      await load();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setCancelingTaskId(null);
    }
  };

  const columns: ColumnsType<TaskRun> = useMemo(() => [
    {
      title: "任务",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={getTaskTypeLabel(record.task_type)} block strong />
          <div className="ui-chip-row">
            <StatusTag value={record.status} />
            {record.retry_count ? <Typography.Text type="secondary">重试 {record.retry_count} 次</Typography.Text> : null}
          </div>
        </div>
      ),
    },
    {
      title: "范围与阶段",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText
            value={`${getScopeTypeLabel(record.scope_type)}${record.scope_id ? ` / ${record.scope_id}` : ""}`}
            block
          />
          <OverflowText value={getTaskStageLabel(record.timing?.current_stage_code, record.timing?.current_stage_name)} block secondary />
        </div>
      ),
    },
    {
      title: "进度与耗时",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <Progress percent={record.progress} size="small" />
          <OverflowText
            value={`排队 ${formatDurationMs(record.timing?.queue_duration_ms)} / 运行 ${formatDurationMs(record.timing?.run_duration_ms)} / 总耗时 ${formatDurationMs(record.timing?.total_duration_ms)}`}
            block
            secondary
          />
        </div>
      ),
    },
    {
      title: "消息与摘要",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={localizeTaskMessage(record.message) || "-"} block />
          <OverflowText value={renderTaskSummary(record.result_json, record)} block secondary lines={2} />
        </div>
      ),
    },
    ...(screens.xl
      ? [{
          title: "创建时间",
          key: "created_at",
          width: 180,
          render: (_: unknown, record: TaskRun) => <OverflowText value={new Date(record.created_at).toLocaleString()} block />,
        }]
      : []),
    {
      title: "操作",
      key: "actions",
      width: 190,
      render: (_, record) => (
        <div className="ui-table-action-row">
          {isTaskActive(record.status) ? (
            <div className="ui-table-action-wide">
              <Popconfirm
                title="确认中断当前任务？"
                description="系统会尝试撤销 Celery 任务，并把当前任务标记为已中断。"
                okText="中断任务"
                cancelText="取消"
                onConfirm={() => void onCancelTask(record.id)}
              >
                <Button danger size="small" block loading={cancelingTaskId === record.id}>中断任务</Button>
              </Popconfirm>
            </div>
          ) : null}
          <Button size="small" block onClick={() => router.push(`/tasks/${record.id}`)}>查看详情</Button>
          <Button size="small" block onClick={() => router.push(`/tasks/logs?task_id=${record.id}`)}>查看日志</Button>
        </div>
      ),
    },
  ], [cancelingTaskId, onCancelTask, router, screens.xl]);

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="执行队列"
        title="任务控制台"
        description="查看扫描、采集与验证任务的执行进度、阶段耗时与结构化日志入口。"
        meta={[
          { label: "进行中", value: summary.queued, tone: summary.queued ? "warning" : "success" },
          { label: "成功", value: summary.success, tone: "success" },
          { label: "失败", value: summary.failed, tone: summary.failed ? "danger" : "neutral" },
          { label: "已中断", value: summary.canceled, tone: summary.canceled ? "warning" : "neutral" },
          { label: "平均进度", value: `${summary.avgProgress}%`, tone: "accent" },
        ]}
        actions={(
          <Space wrap>
            <Button onClick={() => router.push("/tasks/logs")}>任务日志</Button>
            <Button onClick={() => void load()} loading={loading}>刷新</Button>
          </Space>
        )}
      />

      <Card
        className="panel-card"
        title="任务列表"
        extra={(
          <Space wrap>
            <Button onClick={() => void load()} loading={loading}>刷新</Button>
            <Popconfirm
              title="确认一键清除任务记录？"
              description="会按当前筛选条件清空任务记录；进行中的任务会先尝试中断后再清理。"
              okText="清除"
              cancelText="取消"
              onConfirm={() => void onClearTasks()}
            >
              <Button danger loading={clearing}>一键清除</Button>
            </Popconfirm>
          </Space>
        )}
      >
        <Space wrap className="ui-toolbar-wrap" style={{ marginBottom: 16, width: "100%" }}>
          <Select value={taskType} onChange={setTaskType} style={{ width: 180 }} options={[
            { label: "全部类型", value: "all" },
            { label: "资产扫描", value: "asset_scan" },
            { label: "SSH 授权深度检查", value: "info_collect" },
            { label: "风险验证", value: "risk_verify" },
            { label: "报告生成", value: "report_generate" },
            { label: "Host Runner 安装", value: "runner_install" },
            { label: "交互式漏洞修复", value: "remediation_execute" },
            { label: "系统设置应用", value: "settings_apply" },
          ]} />
          <Select value={status} onChange={setStatus} style={{ width: 180 }} options={[
            { label: "全部状态", value: "all" },
            { label: "排队中", value: "pending" },
            { label: "运行中", value: "running" },
            { label: "重试中", value: "retry" },
            { label: "成功", value: "success" },
            { label: "失败", value: "failure" },
            { label: "已中断", value: "canceled" },
          ]} />
        </Space>
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
        <Table
          className="console-table"
          rowKey="id"
          loading={loading}
          dataSource={items}
          columns={columns}
          tableLayout="fixed"
          pagination={{ pageSize: 12 }}
        />
      </Card>
    </Space>
  );
}
