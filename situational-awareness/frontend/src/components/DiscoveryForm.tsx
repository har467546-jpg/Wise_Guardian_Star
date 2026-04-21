"use client";

import { useState } from "react";
import { Alert, Button, Card, Col, Form, Input, Row, Space, Typography, message, Divider, Tag } from "antd";
import { RocketOutlined, AimOutlined, TagOutlined, CheckCircleOutlined, InfoCircleOutlined } from "@ant-design/icons";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import { createDiscoveryJob } from "@/services/api";

const { Title, Paragraph, Text } = Typography;

const pipelineStages = [
  {
    code: "01",
    title: "主机发现",
    description: "识别 CIDR 范围内的可达主机，建立本轮发现入口。",
  },
  {
    code: "02",
    title: "端口与指纹",
    description: "识别开放端口、服务类型和版本线索，形成资产基础画像。",
  },
  {
    code: "03",
    title: "风险验证",
    description: "基于规则和主动校验补齐风险确认结果，进入任务中心持续跟踪。",
  },
];

type DiscoveryFormValues = {
  cidr: string;
  label?: string;
};

type DiscoverySubmissionSummary = {
  normalizedCidr: string;
  estimatedHostCount: number | null;
  discoveredHostCount: number | null;
};

function isValidDiscoveryCidr(value: string): boolean {
  const input = value.trim();
  if (!input) {
    return false;
  }

  const segments = input.split("/");
  if (segments.length > 2) {
    return false;
  }

  const [ip, prefix] = segments;
  const octets = ip.split(".");
  if (octets.length !== 4) {
    return false;
  }

  const isValidOctet = octets.every((octet) => /^\d+$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255);
  if (!isValidOctet) {
    return false;
  }

  if (prefix === undefined) {
    return true;
  }

  return /^\d+$/.test(prefix) && Number(prefix) >= 0 && Number(prefix) <= 32;
}

function normalizeDiscoveryValues(values: DiscoveryFormValues): DiscoveryFormValues {
  const cidr = values.cidr.trim();
  const label = values.label?.trim();

  return {
    cidr,
    label: label || undefined,
  };
}

function estimateDiscoverableHosts(cidr: string): number | null {
  const normalized = cidr.trim();
  if (!isValidDiscoveryCidr(normalized)) {
    return null;
  }

  const [, rawPrefix] = normalized.split("/");
  if (rawPrefix === undefined) {
    return 1;
  }

  const prefix = Number(rawPrefix);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return null;
  }
  if (prefix === 32) {
    return 1;
  }
  if (prefix === 31) {
    return 2;
  }
  return 2 ** (32 - prefix) - 2;
}

function extractDiscoveredHostCount(summaryJson: Record<string, unknown> | undefined): number | null {
  if (!summaryJson) {
    return null;
  }
  const rawHostCount = summaryJson.host_count;
  if (typeof rawHostCount === "number" && Number.isFinite(rawHostCount)) {
    return rawHostCount;
  }
  if (typeof rawHostCount === "string" && rawHostCount.trim() && !Number.isNaN(Number(rawHostCount))) {
    return Number(rawHostCount);
  }
  return null;
}

export default function DiscoveryForm() {
  const [form] = Form.useForm<DiscoveryFormValues>();
  const [taskId, setTaskId] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [reused, setReused] = useState(false);
  const [submissionSummary, setSubmissionSummary] = useState<DiscoverySubmissionSummary | null>(null);

  const onSubmit = async (values: DiscoveryFormValues) => {
    const payload = normalizeDiscoveryValues(values);

    try {
      setSubmitting(true);
      setTaskId(null);
      setJobId(null);
      setReused(false);
      setSubmissionSummary(null);

      const response = await createDiscoveryJob(payload);

      if (!response || !response.task_id) {
        throw new Error("接口未返回有效的任务 ID");
      }

      setTaskId(response.task_id);
      setJobId(response.job?.id || "未知 ID");
      setReused(!!response.reused);
      setSubmissionSummary({
        normalizedCidr: String(response.job?.cidr || payload.cidr),
        estimatedHostCount: estimateDiscoverableHosts(String(response.job?.cidr || payload.cidr)),
        discoveredHostCount: extractDiscoveredHostCount(response.job?.summary_json),
      });

      if (response.reused) {
        message.info("检测到进行中任务，已自动复用队列");
      } else {
        message.success("扫描任务已成功下发至引擎");
        form.resetFields(["cidr"]);
      }
    } catch (error) {
      console.error("提交失败:", error);
      message.error((error as Error).message || "任务提交失败，请重试");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Space direction="vertical" size={20} style={{ width: "100%", padding: "4px" }}>
      <DesktopPageHeader
        eyebrow="ENGINE CONTROL"
        title="扫描发起台"
        description="提交 CIDR 网段以触发全自动资产发现与风险校验流水线。"
        meta={[
          { label: "流水线模式", value: "全自动", tone: "success" },
          {
            label: "当前状态",
            value: submitting ? "提交中" : taskId ? (reused ? "任务已复用" : "指令已下发") : "就绪",
            tone: submitting ? "warning" : taskId ? (reused ? "warning" : "accent") : "neutral",
          },
        ]}
      />

      <Row gutter={[20, 20]}>
        <Col xs={24} lg={15}>
          <Card className="panel-card discovery-command-card" data-haor-section="任务配置" bordered={false}>
            <Title level={4}>任务配置</Title>
            <Paragraph type="secondary">
              系统将按照 <Text code>主机存活 -{">"} 端口指纹 -{">"} 风险验证</Text> 的顺序执行。
            </Paragraph>

            <Form form={form} layout="vertical" onFinish={onSubmit} size="large" data-haor-section="扫描发起表单">
              <Form.Item
                name="cidr"
                label={<Text strong>CIDR 目标网段</Text>}
                rules={[
                  { required: true, message: "请输入扫描目标" },
                  {
                    validator: async (_, value: string | undefined) => {
                      if (!value || isValidDiscoveryCidr(value)) {
                        return;
                      }
                      throw new Error("请输入有效的 IPv4 CIDR 格式，如 10.0.0.0/24");
                    },
                  },
                ]}
              >
                <Input
                  prefix={<AimOutlined className="ui-input-icon" />}
                  placeholder="10.10.0.0/24"
                  className="mono-text"
                />
              </Form.Item>

              <Form.Item name="label" label={<Text strong>任务备注标签</Text>}>
                <Input
                  prefix={<TagOutlined className="ui-input-icon" />}
                  placeholder="例如: 核心业务段季度扫描"
                />
              </Form.Item>

              <Button
                type="primary"
                htmlType="submit"
                icon={<RocketOutlined />}
                loading={submitting}
                disabled={submitting}
                className="discovery-submit-button"
                data-haor-section="启动流水线"
              >
                启动流水线
              </Button>
            </Form>

            {taskId && (
              <div className="discovery-result-wrap">
                <Divider dashed />
                <Alert
                  type={reused ? "warning" : "success"}
                  showIcon
                  icon={reused ? <InfoCircleOutlined /> : <CheckCircleOutlined />}
                  message={
                    <Space>
                      <Text strong>{reused ? "任务复用中" : "新任务已创建"}</Text>
                      <Tag color={reused ? "orange" : "blue"}>{taskId}</Tag>
                    </Space>
                  }
                  description={
                    <Space direction="vertical" size={6}>
                      <Text>后台任务 ID: {jobId || "处理中..."}。您可以在“任务中心”查看实时扫描进度。</Text>
                      {submissionSummary ? (
                        <Text type="secondary">
                          网段摘要：
                          {submissionSummary.normalizedCidr}
                          {submissionSummary.estimatedHostCount !== null
                            ? `，预计最多可探测 ${submissionSummary.estimatedHostCount} 个主机地址`
                            : ""}
                          {submissionSummary.discoveredHostCount !== null
                            ? `，当前已识别在线 ${submissionSummary.discoveredHostCount} 台主机`
                            : ""}
                        </Text>
                      ) : null}
                    </Space>
                  }
                />
              </div>
            )}
          </Card>
        </Col>

        <Col xs={24} lg={9}>
          <Card className="panel-card discovery-stage-card" data-haor-section="自动化流水线详情" bordered={false} title={<Text strong>自动化流水线详情</Text>}>
            <div className="workflow-stage-list">
              {pipelineStages.map((stage) => (
                <div key={stage.code} className="workflow-stage-item">
                  <span className="workflow-stage-index">{stage.code}</span>
                  <div className="workflow-stage-copy">
                    <strong>{stage.title}</strong>
                    <p>{stage.description}</p>
                  </div>
                </div>
              ))}
            </div>
            <Alert
              showIcon
              type="info"
              message="提交后会在任务中心自动持续追踪"
              description="如果系统检测到相同 CIDR 已存在排队中或运行中的任务，本页会自动显示任务复用状态。"
            />
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
