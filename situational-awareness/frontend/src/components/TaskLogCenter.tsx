"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Alert, Button, Card, Grid, Input, Select, Space, Table, Tag, Tooltip } from "antd";
import type { ColumnsType } from "antd/es/table";
import { useSearchParams } from "next/navigation";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import PlatformLogPanel from "@/components/PlatformLogPanel";
import StatusTag from "@/components/StatusTag";
import { listTaskEvents } from "@/services/api";
import { TaskEvent, TaskLogLevel, TaskStatus, TaskType } from "@/types/task";
import {
  formatDateTime,
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

export default function TaskLogCenter() {
  const screens = Grid.useBreakpoint();
  const searchParams = useSearchParams();
  const [items, setItems] = useState<TaskEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [taskType, setTaskType] = useState<TaskType | "all">("all");
  const [status, setStatus] = useState<TaskStatus | "all">("all");
  const [level, setLevel] = useState<TaskLogLevel | "all">("all");
  const [taskId, setTaskId] = useState(searchParams?.get("task_id") || "");
  const [keyword, setKeyword] = useState(searchParams?.get("keyword") || "");

  const load = async () => {
    try {
      setLoading(true);
      const result = await listTaskEvents({
        pageSize: 200,
        taskType,
        status,
        level,
        taskId: taskId || undefined,
        keyword: keyword || undefined,
      });
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
  }, [taskType, status, level, taskId, keyword]);

  const hasActiveRows = items.some((item) => isTaskActive(item.status));

  useEffect(() => {
    if (!hasActiveRows) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void load();
    }, 3000);
    return () => window.clearInterval(timer);
  }, [hasActiveRows, taskType, status, level, taskId, keyword]);

  const columns: ColumnsType<TaskEvent> = [
    { title: "时间", dataIndex: "created_at", width: 180, render: (value: string) => <OverflowText value={formatDateTime(value)} block /> },
    {
      title: "任务",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <div className="ui-chip-row">
            {record.status ? <StatusTag value={record.status} /> : null}
            <Tag color={levelColor(record.level)}>{getTaskLogLevelLabel(record.level)}</Tag>
          </div>
          <OverflowText value={getTaskTypeLabel(record.task_type)} block />
          <Tooltip title={record.task_run_id}>
            <Link href={`/tasks/${record.task_run_id}`} className="ui-link-ellipsis mono-text">
              {record.task_run_id}
            </Link>
          </Tooltip>
        </div>
      ),
    },
    {
      title: "阶段与事件",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={getTaskStageLabel(record.stage_code, record.stage_name)} block />
          <OverflowText value={getTaskEventTypeLabel(record.event_type)} block secondary />
        </div>
      ),
    },
    {
      title: "消息",
      render: (_, record) => (
        <OverflowText
          value={localizeTaskMessage(record.message) || "-"}
          block
          lines={screens.xl ? 2 : 1}
        />
      ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="任务日志"
        title="结构化任务日志"
        description="查看任务阶段推进、告警、重试和完成事件，并可跳转回具体任务详情。"
        meta={[
          { label: "日志条数", value: items.length, tone: "accent" },
          { label: "活跃任务日志", value: items.filter((item) => isTaskActive(item.status)).length, tone: "warning" },
        ]}
        actions={<Button onClick={() => void load()} loading={loading}>刷新</Button>}
      />

      <Card className="panel-card" title="筛选条件">
        <Space wrap className="ui-toolbar-wrap" style={{ width: "100%" }}>
          <Select value={taskType} onChange={setTaskType} style={{ width: 180 }} options={[
            { label: "全部任务类型", value: "all" },
            { label: "资产扫描", value: "asset_scan" },
            { label: "SSH 授权深度检查", value: "info_collect" },
            { label: "风险验证", value: "risk_verify" },
            { label: "报告生成", value: "report_generate" },
            { label: "Host Runner 安装", value: "runner_install" },
            { label: "交互式漏洞修复", value: "remediation_execute" },
            { label: "系统设置应用", value: "settings_apply" },
          ]} />
          <Select value={status} onChange={setStatus} style={{ width: 180 }} options={[
            { label: "全部任务状态", value: "all" },
            { label: "排队中", value: "pending" },
            { label: "运行中", value: "running" },
            { label: "重试中", value: "retry" },
            { label: "成功", value: "success" },
            { label: "失败", value: "failure" },
            { label: "已中断", value: "canceled" },
          ]} />
          <Select value={level} onChange={setLevel} style={{ width: 160 }} options={[
            { label: "全部级别", value: "all" },
            { label: "信息", value: "info" },
            { label: "告警", value: "warning" },
            { label: "错误", value: "error" },
          ]} />
          <Input
            placeholder="按任务 ID 筛选"
            value={taskId}
            onChange={(event) => setTaskId(event.target.value)}
            style={{ width: 240 }}
          />
          <Input
            placeholder="按消息关键词筛选"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            style={{ width: 260 }}
          />
        </Space>
      </Card>

      <Card className="panel-card" title="日志列表" loading={loading}>
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
        <Table
          className="console-table"
          rowKey="id"
          dataSource={items}
          columns={columns}
          tableLayout="fixed"
          pagination={{ pageSize: 20 }}
        />
      </Card>

      <PlatformLogPanel />
    </Space>
  );
}
