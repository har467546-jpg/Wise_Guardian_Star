"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Alert, Button, Card, Input, Select, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";

import OverflowText from "@/components/OverflowText";
import { getStoredUserRole } from "@/lib/auth";
import { formatDateTime, getTaskTypeLabel, localizeTaskMessage } from "@/lib/ui-text";
import { listPlatformLogs } from "@/services/api";
import { PlatformLogEntry, PlatformLogLevel, PlatformLogServiceName, PlatformLogSourceKind } from "@/types/logs";

function levelColor(level: PlatformLogLevel): string {
  if (level === "error") {
    return "error";
  }
  if (level === "warning") {
    return "warning";
  }
  return "processing";
}

export default function PlatformLogPanel() {
  const [items, setItems] = useState<PlatformLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [sourceKind, setSourceKind] = useState<PlatformLogSourceKind | "all">("all");
  const [serviceName, setServiceName] = useState<PlatformLogServiceName | "all">("all");
  const [level, setLevel] = useState<PlatformLogLevel | "all">("all");
  const [keyword, setKeyword] = useState("");

  useEffect(() => {
    setIsAdmin(getStoredUserRole() === "admin");
  }, []);

  const load = async () => {
    if (!isAdmin) {
      return;
    }
    try {
      setLoading(true);
      const result = await listPlatformLogs({
        pageSize: 50,
        sourceKind,
        serviceName,
        level,
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
  }, [isAdmin, sourceKind, serviceName, level, keyword]);

  if (!isAdmin) {
    return (
      <Card className="panel-card" title="平台运行日志">
        <Alert showIcon type="info" message="平台运行日志仅管理员可见。" />
      </Card>
    );
  }

  const columns: ColumnsType<PlatformLogEntry> = [
    {
      title: "时间",
      dataIndex: "created_at",
      width: 180,
      render: (value: string) => <OverflowText value={formatDateTime(value)} block />,
    },
    {
      title: "服务",
      width: 180,
      render: (_, record) => (
        <div className="ui-cell-stack">
          <div className="ui-chip-row">
            <Tag color={levelColor(record.level)}>{record.level.toUpperCase()}</Tag>
            <Tag>{record.service_name}</Tag>
          </div>
          <OverflowText value={record.source_kind} block secondary />
        </div>
      ),
    },
    {
      title: "任务",
      width: 220,
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={record.task_type ? getTaskTypeLabel(record.task_type) : "系统日志"} block />
          {record.task_run_id ? (
            <Link href={`/tasks/${record.task_run_id}`} className="ui-link-ellipsis mono-text">
              {record.task_run_id}
            </Link>
          ) : (
            <Typography.Text type="secondary">无关联任务</Typography.Text>
          )}
        </div>
      ),
    },
    {
      title: "消息",
      render: (_, record) => (
        <OverflowText
          value={localizeTaskMessage(record.message) || record.message || record.logger_name}
          block
          lines={2}
        />
      ),
    },
  ];

  return (
    <Card
      className="panel-card"
      title="平台运行日志"
      extra={
        <Button onClick={() => void load()} loading={loading}>
          刷新
        </Button>
      }
    >
      <Space wrap className="ui-toolbar-wrap" style={{ width: "100%", marginBottom: 16 }}>
        <Select
          value={sourceKind}
          onChange={setSourceKind}
          style={{ width: 170 }}
          options={[
            { label: "全部来源", value: "all" },
            { label: "系统日志", value: "system" },
            { label: "任务原始日志", value: "task_raw" },
          ]}
        />
        <Select
          value={serviceName}
          onChange={setServiceName}
          style={{ width: 170 }}
          options={[
            { label: "全部服务", value: "all" },
            { label: "backend", value: "backend" },
            { label: "worker", value: "worker" },
          ]}
        />
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
        <Input
          placeholder="按日志关键词筛选"
          value={keyword}
          onChange={(event) => setKeyword(event.target.value)}
          style={{ width: 260 }}
        />
      </Space>

      {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}

      <Table
        className="console-table"
        rowKey="id"
        dataSource={items}
        columns={columns}
        tableLayout="fixed"
        loading={loading}
        pagination={{ pageSize: 10 }}
      />
    </Card>
  );
}
