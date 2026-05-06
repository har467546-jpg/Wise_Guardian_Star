"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert, Button, Card, Descriptions, Empty, Grid, Popconfirm, Select, Space, Table, Tag, message } from "antd";
import type { ColumnsType } from "antd/es/table";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";
import { cancelTask, fetchReportHtml, fetchReportPdf, getTask, getTaskEvents } from "@/services/api";
import { TaskEvent, TaskLogLevel, TaskRunDetail } from "@/types/task";
import {
  formatDateTime,
  formatDurationMs,
  getScopeTypeLabel,
  getTaskEventTypeLabel,
  getTaskLogLevelLabel,
  getTaskStageLabel,
  getTaskTypeLabel,
  isTaskActive,
  localizeTaskMessage,
} from "@/lib/ui-text";

function levelColor(level: TaskLogLevel): string {
  if (level === "error") {
    return "error";
  }
  if (level === "warning") {
    return "warning";
  }
  return "processing";
}

function triggerBrowserDownload(blob: Blob, filename: string) {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

export default function TaskDetailView({ taskId }: { taskId: string }) {
  const screens = Grid.useBreakpoint();
  const router = useRouter();
  const [task, setTask] = useState<TaskRunDetail | null>(null);
  const [events, setEvents] = useState<TaskEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [level, setLevel] = useState<TaskLogLevel | "all">("all");
  const [canceling, setCanceling] = useState(false);
  const [reportActionLoading, setReportActionLoading] = useState<"html" | "pdf" | null>(null);

  const load = async () => {
    try {
      setLoading(true);
      const [taskDetail, eventRes] = await Promise.all([
        getTask(taskId),
        getTaskEvents(taskId, { pageSize: 300, level }),
      ]);
      setTask(taskDetail);
      setEvents(eventRes.items);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, [taskId, level]);

  useEffect(() => {
    if (!task || !isTaskActive(task.status)) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [taskId, level, task?.status]);

  const stageColumns: ColumnsType<TaskRunDetail["stage_timings"][number]> = [
    {
      title: "阶段",
      dataIndex: "stage_name",
      render: (value: string | null, record) => (
        <OverflowText value={getTaskStageLabel(record.stage_code, value)} block />
      ),
    },
    {
      title: "时间范围",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={`开始：${formatDateTime(record.started_at)}`} block />
          <OverflowText value={`结束：${formatDateTime(record.finished_at)}`} block secondary />
        </div>
      ),
    },
    { title: "耗时", dataIndex: "duration_ms", width: 120, render: (value: number | null) => formatDurationMs(value) },
  ];

  const eventColumns: ColumnsType<TaskEvent> = [
    { title: "时间", dataIndex: "created_at", width: 180, render: (value: string) => <OverflowText value={formatDateTime(value)} block /> },
    {
      title: "事件概况",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <div className="ui-chip-row">
            <Tag color={levelColor(record.level)}>{getTaskLogLevelLabel(record.level)}</Tag>
          </div>
          <OverflowText value={getTaskStageLabel(record.stage_code, record.stage_name)} block />
          <OverflowText value={getTaskEventTypeLabel(record.event_type)} block secondary />
        </div>
      ),
    },
    {
      title: "消息",
      render: (_, record) => <OverflowText value={localizeTaskMessage(record.message) || "-"} block lines={screens.xl ? 2 : 1} />,
    },
  ];

  const onCancelTask = async () => {
    try {
      setCanceling(true);
      const result = await cancelTask(taskId);
      message.success(result.status === "canceled" ? "任务已中断" : "中断请求已提交");
      await load();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setCanceling(false);
    }
  };

  const rawReportId = task?.result_json ? task.result_json["report_id"] : null;
  const reportId = typeof rawReportId === "string" ? rawReportId : "";
  const canAccessGeneratedReport = task?.task_type === "report_generate" && Boolean(reportId);

  const onDownloadReportHtml = async () => {
    if (!reportId) {
      return;
    }
    try {
      setReportActionLoading("html");
      const { blob, filename } = await fetchReportHtml(reportId);
      triggerBrowserDownload(blob, filename || `${reportId}.html`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setReportActionLoading(null);
    }
  };

  const onDownloadReportPdf = async () => {
    if (!reportId) {
      return;
    }
    try {
      setReportActionLoading("pdf");
      const { blob, filename } = await fetchReportPdf(reportId);
      triggerBrowserDownload(blob, filename || `${reportId}.pdf`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setReportActionLoading(null);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="任务详情"
        title={task ? `${getTaskTypeLabel(task.task_type)}详情` : "任务详情"}
        description="查看任务排队时间、运行耗时、阶段切片与结构化事件日志。"
        meta={[
          { label: "状态", value: task ? <StatusTag value={task.status} /> : "-", tone: "accent" },
          { label: "排队耗时", value: formatDurationMs(task?.timing.queue_duration_ms ?? null), tone: "neutral" },
          { label: "运行耗时", value: formatDurationMs(task?.timing.run_duration_ms ?? null), tone: "warning" },
          { label: "总耗时", value: formatDurationMs(task?.timing.total_duration_ms ?? null), tone: "success" },
        ]}
        actions={(
          <Space wrap>
            {task && isTaskActive(task.status) ? (
              <Popconfirm
                title="确认中断当前任务？"
                description="系统会尝试撤销 Celery 任务，并把当前任务标记为已中断。"
                okText="中断任务"
                cancelText="取消"
                onConfirm={() => void onCancelTask()}
              >
                <Button danger loading={canceling}>中断任务</Button>
              </Popconfirm>
            ) : null}
            {canAccessGeneratedReport ? (
              <Button onClick={() => void onDownloadReportHtml()} loading={reportActionLoading === "html"}>
                下载 HTML 报告
              </Button>
            ) : null}
            {canAccessGeneratedReport ? (
              <Button onClick={() => void onDownloadReportPdf()} loading={reportActionLoading === "pdf"}>
                下载 PDF 报告
              </Button>
            ) : null}
            <Button onClick={() => router.push(`/tasks/logs?task_id=${taskId}`)}>查看全局日志</Button>
            <Button onClick={() => void load()} loading={loading}>刷新</Button>
          </Space>
        )}
      />

      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Card className="panel-card" title="任务概况" loading={loading}>
        {task ? (
          <Descriptions column={{ xs: 1, md: 2, xl: 3 }} labelStyle={{ width: 120 }}>
            <Descriptions.Item label="任务 ID">
              <span className="ui-detail-wrap mono-text">{task.id}</span>
            </Descriptions.Item>
            <Descriptions.Item label="任务类型">{getTaskTypeLabel(task.task_type)}</Descriptions.Item>
            <Descriptions.Item label="当前阶段">
              <span className="ui-detail-wrap">{getTaskStageLabel(task.timing.current_stage_code, task.timing.current_stage_name)}</span>
            </Descriptions.Item>
            <Descriptions.Item label="范围">
              <span className="ui-detail-wrap">{`${getScopeTypeLabel(task.scope_type)}${task.scope_id ? ` / ${task.scope_id}` : ""}`}</span>
            </Descriptions.Item>
            <Descriptions.Item label="当前消息">
              <span className="ui-detail-wrap">{localizeTaskMessage(task.message) || "-"}</span>
            </Descriptions.Item>
            <Descriptions.Item label="当前阶段耗时">{formatDurationMs(task.timing.current_stage_duration_ms)}</Descriptions.Item>
            <Descriptions.Item label="创建时间">{formatDateTime(task.created_at)}</Descriptions.Item>
            <Descriptions.Item label="开始时间">{formatDateTime(task.started_at)}</Descriptions.Item>
            <Descriptions.Item label="结束时间">{formatDateTime(task.finished_at)}</Descriptions.Item>
            <Descriptions.Item label="Celery 任务">
              <span className="ui-detail-wrap mono-text">{task.celery_task_id || "-"}</span>
            </Descriptions.Item>
            <Descriptions.Item label="重试次数">{task.retry_count}</Descriptions.Item>
            <Descriptions.Item label="事件条数">{task.event_count}</Descriptions.Item>
          </Descriptions>
        ) : (
          <Empty description="暂无任务详情" />
        )}
      </Card>

      <Card className="panel-card" title="阶段耗时" loading={loading}>
        {task?.stage_timings?.length ? (
          <Table
            className="console-table"
            rowKey={(record) => `${record.stage_code || "stage"}-${record.started_at || ""}`}
            pagination={false}
            dataSource={task.stage_timings}
            columns={stageColumns}
            tableLayout="fixed"
          />
        ) : (
          <Empty description="当前任务暂无阶段耗时记录" />
        )}
      </Card>

      <Card
        className="panel-card"
        title="事件日志"
        loading={loading}
        extra={(
          <Select
            value={level}
            onChange={setLevel}
            style={{ width: 160 }}
            options={[
              { label: "全部级别", value: "all" },
              { label: "信息", value: "info" },
              { label: "告警", value: "warning" },
              { label: "错误", value: "error" },
            ]}
          />
        )}
      >
        {events.length ? (
          <Table
            className="console-table"
            rowKey="id"
            pagination={false}
            dataSource={events}
            columns={eventColumns}
            tableLayout="fixed"
          />
        ) : (
          <Empty description="当前任务暂无结构化事件日志" />
        )}
      </Card>
    </Space>
  );
}
