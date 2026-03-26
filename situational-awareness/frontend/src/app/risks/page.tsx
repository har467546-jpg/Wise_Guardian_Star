"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Form, Input, Modal, Select, Space, Table, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import StatusTag from "@/components/StatusTag";
import { formatDateTime } from "@/lib/ui-text";
import { assignRiskFinding, createRiskWaiver, listGlobalRisks, recalculateRiskPriority } from "@/services/api";
import { RiskFinding } from "@/types/risk";

export default function RisksPage() {
  const [items, setItems] = useState<RiskFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState<string | null>(null);
  const [severity, setSeverity] = useState<RiskFinding["severity"] | "all">("all");
  const [status, setStatus] = useState<RiskFinding["status"] | "all">("all");
  const [keyword, setKeyword] = useState("");
  const [waiverModalOpen, setWaiverModalOpen] = useState(false);
  const [waiverTarget, setWaiverTarget] = useState<RiskFinding | null>(null);
  const [waiverSubmitting, setWaiverSubmitting] = useState(false);
  const [waiverForm] = Form.useForm<{ waiver_type: "false_positive" | "accepted_risk" | "temporary_exception"; reason: string; expires_at?: string }>();

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
      p1: items.filter((item) => item.priority_tier === "P1").length,
      waived: items.filter((item) => item.waiver_status !== "none").length,
      overdue: items.filter((item) => item.sla_due_at && new Date(item.sla_due_at).getTime() < Date.now() && item.status === "open").length,
    }),
    [items],
  );

  const assignToMe = async (findingId: string) => {
    try {
      setActionLoadingId(findingId);
      await assignRiskFinding(findingId, {});
      message.success("责任人已更新");
      await load();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const recalcPriority = async (findingId: string) => {
    try {
      setActionLoadingId(findingId);
      await recalculateRiskPriority(findingId);
      message.success("优先级已重算");
      await load();
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setActionLoadingId(null);
    }
  };

  const openWaiverModal = (item: RiskFinding) => {
    setWaiverTarget(item);
    waiverForm.setFieldsValue({
      waiver_type: "accepted_risk",
      reason: "",
      expires_at: "",
    });
    setWaiverModalOpen(true);
  };

  const submitWaiver = async () => {
    if (!waiverTarget) {
      return;
    }
    try {
      const values = await waiverForm.validateFields();
      setWaiverSubmitting(true);
      await createRiskWaiver(waiverTarget.id, {
        waiver_type: values.waiver_type,
        reason: values.reason,
        expires_at: values.expires_at ? new Date(values.expires_at).toISOString() : null,
      });
      message.success("豁免已创建");
      setWaiverModalOpen(false);
      setWaiverTarget(null);
      await load();
    } catch (err) {
      if ((err as { errorFields?: unknown }).errorFields) {
        return;
      }
      message.error((err as Error).message);
    } finally {
      setWaiverSubmitting(false);
    }
  };

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
      title: "优先级",
      width: 120,
      render: (_, record) => (
        <div className="ui-cell-stack">
          <StatusTag value={record.priority_tier || "unknown"} />
          <Typography.Text type="secondary">
            {typeof record.priority_score === "number" ? `${record.priority_score} 分` : "未计算"}
          </Typography.Text>
        </div>
      ),
    },
    {
      title: "治理",
      width: 180,
      render: (_, record) => (
        <div className="ui-cell-stack">
          <StatusTag value={record.status} />
          <Typography.Text type="secondary">
            SLA：{record.sla_due_at ? formatDateTime(record.sla_due_at) : "未设置"}
          </Typography.Text>
          <Typography.Text type="secondary">
            豁免：{record.waiver_status === "none" ? "无" : record.waiver_status}
          </Typography.Text>
          <Typography.Text type="secondary">
            责任人：{record.owner_id || "未分配"}
          </Typography.Text>
        </div>
      ),
    },
    {
      title: "操作",
      width: 220,
      render: (_, record) => (
        <Space size={4} wrap>
          <Button size="small" loading={actionLoadingId === record.id} onClick={() => void assignToMe(record.id)}>
            分配给我
          </Button>
          <Button size="small" loading={actionLoadingId === record.id} onClick={() => void recalcPriority(record.id)}>
            重算
          </Button>
          <Button size="small" onClick={() => openWaiverModal(record)}>
            豁免
          </Button>
        </Space>
      ),
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
          { label: "P1", value: summary.p1, tone: summary.p1 ? "danger" : "neutral" },
          { label: "已豁免", value: summary.waived, tone: summary.waived ? "warning" : "neutral" },
          { label: "SLA 超期", value: summary.overdue, tone: summary.overdue ? "danger" : "neutral" },
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
          当前页面已支持基础治理动作：优先级重算、责任人分配和豁免录入；更深度的验证与修复仍在资产详情页执行。
        </Typography.Paragraph>
      </Card>

      <Modal
        title={waiverTarget ? `为风险创建豁免：${waiverTarget.title}` : "创建豁免"}
        open={waiverModalOpen}
        confirmLoading={waiverSubmitting}
        onOk={() => void submitWaiver()}
        onCancel={() => {
          setWaiverModalOpen(false);
          setWaiverTarget(null);
        }}
        destroyOnClose
      >
        <Form form={waiverForm} layout="vertical" initialValues={{ waiver_type: "accepted_risk" }}>
          <Form.Item name="waiver_type" label="豁免类型" rules={[{ required: true, message: "请选择豁免类型" }]}>
            <Select
              options={[
                { label: "误报", value: "false_positive" },
                { label: "接受风险", value: "accepted_risk" },
                { label: "临时例外", value: "temporary_exception" },
              ]}
            />
          </Form.Item>
          <Form.Item name="reason" label="原因" rules={[{ required: true, message: "请输入豁免原因" }]}>
            <Input.TextArea rows={4} placeholder="说明为什么接受该风险或标记为误报" />
          </Form.Item>
          <Form.Item shouldUpdate noStyle>
            {() =>
              waiverForm.getFieldValue("waiver_type") === "temporary_exception" ? (
                <Form.Item
                  name="expires_at"
                  label="到期时间"
                  rules={[{ required: true, message: "临时例外必须填写到期时间" }]}
                >
                  <Input type="datetime-local" />
                </Form.Item>
              ) : null
            }
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
}
