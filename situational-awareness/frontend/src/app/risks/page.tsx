"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Input, Select, Space, Table, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";
import { formatDateTime } from "@/lib/ui-text";
import { listGlobalRisks } from "@/services/api";
import { RiskFinding } from "@/types/risk";

export default function RisksPage() {
  const [items, setItems] = useState<RiskFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [severity, setSeverity] = useState<RiskFinding["severity"] | "all">("all");
  const [status, setStatus] = useState<RiskFinding["status"] | "all">("all");
  const [keyword, setKeyword] = useState("");

  const load = async () => {
    try {
      setLoading(true);
      const result = await listGlobalRisks({
        pageSize: 100,
        severity,
        status,
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
  }, [severity, status, keyword]);

  const summary = useMemo(
    () => ({
      critical: items.filter((item) => item.severity === "critical").length,
      high: items.filter((item) => item.severity === "high").length,
      open: items.filter((item) => item.status === "open").length,
    }),
    [items],
  );

  const columns: ColumnsType<RiskFinding> = [
    {
      title: "发现时间",
      dataIndex: "detected_at",
      width: 180,
      render: (value: string) => <OverflowText value={formatDateTime(value)} block />,
    },
    {
      title: "资产",
      width: 220,
      render: (_, record) => (
        <div className="ui-cell-stack">
          <Link href={`/assets/${record.asset_id}`} className="ui-link-ellipsis mono-text">
            {record.asset_ip || record.asset_id}
          </Link>
          <OverflowText value={record.asset_hostname || "未识别主机名"} block secondary />
        </div>
      ),
    },
    {
      title: "风险",
      render: (_, record) => (
        <div className="ui-cell-stack">
          <OverflowText value={record.title} block />
          <OverflowText value={record.description} block secondary lines={2} />
        </div>
      ),
    },
    {
      title: "等级",
      width: 100,
      render: (_, record) => <StatusTag value={record.severity} />,
    },
    {
      title: "状态",
      width: 100,
      render: (_, record) => <StatusTag value={record.status} />,
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="风险视图"
        title="全局风险列表"
        description="按资产维度集中查看最近风险发现，并快速跳转到具体资产详情。"
        meta={[
          { label: "风险总数", value: items.length, tone: "accent" },
          { label: "严重", value: summary.critical, tone: summary.critical ? "danger" : "neutral" },
          { label: "高危", value: summary.high, tone: summary.high ? "warning" : "neutral" },
          { label: "未关闭", value: summary.open, tone: summary.open ? "danger" : "success" },
        ]}
        actions={
          <Button onClick={() => void load()} loading={loading}>
            刷新
          </Button>
        }
      />

      <Card className="panel-card" title="筛选条件">
        <Space wrap className="ui-toolbar-wrap" style={{ width: "100%" }}>
          <Select
            value={severity}
            onChange={setSeverity}
            style={{ width: 160 }}
            options={[
              { label: "全部等级", value: "all" },
              { label: "严重", value: "critical" },
              { label: "高危", value: "high" },
              { label: "中危", value: "medium" },
              { label: "低危", value: "low" },
            ]}
          />
          <Select
            value={status}
            onChange={setStatus}
            style={{ width: 160 }}
            options={[
              { label: "全部状态", value: "all" },
              { label: "开放", value: "open" },
              { label: "已忽略", value: "ignored" },
              { label: "已修复", value: "fixed" },
            ]}
          />
          <Input
            placeholder="按标题、描述或 IP 筛选"
            value={keyword}
            onChange={(event) => setKeyword(event.target.value)}
            style={{ width: 280 }}
          />
        </Space>
      </Card>

      <Card className="panel-card" title="风险列表" loading={loading}>
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}
        <Table
          className="console-table"
          rowKey="id"
          dataSource={items}
          columns={columns}
          tableLayout="fixed"
          pagination={{ pageSize: 20 }}
        />
        <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
          风险详情与验证动作仍在资产详情页执行，当前页面负责全局检索与分流。
        </Typography.Paragraph>
      </Card>
    </Space>
  );
}
