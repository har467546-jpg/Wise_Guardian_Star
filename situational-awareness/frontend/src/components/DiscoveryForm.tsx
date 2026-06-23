"use client";

import { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Col, Collapse, Form, Input, Row, Select, Space, Typography, message, Divider, Tag } from "antd";
import { DownloadOutlined, ImportOutlined, RocketOutlined, AimOutlined, TagOutlined, CheckCircleOutlined, InfoCircleOutlined } from "@ant-design/icons";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import { createDiscoveryJob, downloadServerImportTemplate, exportDataSet, getDiscoverySchedulingOptions, importServersCsv } from "@/services/api";
import type { ExportDataType, ExportFileFormat, ServerImportResponse } from "@/types/data-exchange";
import type { DiscoverySchedulingOption } from "@/types/discovery";

const { Title, Paragraph, Text } = Typography;

const exportOptions: Array<{ type: ExportDataType; label: string; purpose: string }> = [
  {
    type: "servers",
    label: "服务器列表",
    purpose: "资产管理、批量导入",
  },
  {
    type: "alerts",
    label: "告警数据",
    purpose: "告警分析、报告",
  },
  {
    type: "audit_logs",
    label: "审计日志",
    purpose: "审计、合规检查",
  },
  {
    type: "reports",
    label: "报表",
    purpose: "汇报、归档",
  },
];

type DiscoveryFormValues = {
  cidr: string;
  label?: string;
  runner_asset_id?: string;
  scanner_zone_id?: string;
};

type DiscoverySubmissionSummary = {
  normalizedCidr: string;
  estimatedHostCount: number | null;
  discoveredHostCount: number | null;
  executionBoundary: string | null;
  runnerAssetId: string | null;
  scannerZoneId: string | null;
  matchedZoneIds: string[];
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
    runner_asset_id: values.runner_asset_id?.trim() || undefined,
    scanner_zone_id: values.scanner_zone_id?.trim() || undefined,
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
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const watchedCidr = Form.useWatch("cidr", form);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [reused, setReused] = useState(false);
  const [submissionSummary, setSubmissionSummary] = useState<DiscoverySubmissionSummary | null>(null);
  const [optionsLoading, setOptionsLoading] = useState(false);
  const [options, setOptions] = useState<DiscoverySchedulingOption | null>(null);
  const [importing, setImporting] = useState(false);
  const [exportingKey, setExportingKey] = useState<string | null>(null);
  const [importResult, setImportResult] = useState<ServerImportResponse | null>(null);

  useEffect(() => {
    const cidr = watchedCidr;
    if (!cidr || !isValidDiscoveryCidr(cidr)) {
      setOptions(null);
      return;
    }
    let cancelled = false;
    setOptionsLoading(true);
    void getDiscoverySchedulingOptions(cidr)
      .then((result) => {
        if (!cancelled) {
          setOptions(result);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setOptions(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setOptionsLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [watchedCidr]);

  const onSubmit = async (values: DiscoveryFormValues) => {
    const payload = normalizeDiscoveryValues(values);
    if (payload.runner_asset_id && payload.scanner_zone_id) {
      message.error("扫描分区和指定 Runner 不能同时选择");
      return;
    }

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
        executionBoundary: String((((response.job?.summary_json || {}) as Record<string, unknown>).request as Record<string, unknown> | undefined)?.execution_boundary || "") || null,
        runnerAssetId: String((((response.job?.summary_json || {}) as Record<string, unknown>).request as Record<string, unknown> | undefined)?.runner_asset_id || "") || null,
        scannerZoneId: String((((response.job?.summary_json || {}) as Record<string, unknown>).request as Record<string, unknown> | undefined)?.scanner_zone_id || "") || null,
        matchedZoneIds: Array.isArray((((response.job?.summary_json || {}) as Record<string, unknown>).request as Record<string, unknown> | undefined)?.matched_zone_ids)
          ? (((response.job?.summary_json || {}) as Record<string, unknown>).request as Record<string, unknown>).matched_zone_ids as string[]
          : [],
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

  const saveBlob = (blob: Blob, filename: string | null, fallbackName: string) => {
    const url = window.URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename || fallbackName;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    window.URL.revokeObjectURL(url);
  };

  const onDownloadTemplate = async () => {
    try {
      const { blob, filename } = await downloadServerImportTemplate();
      saveBlob(blob, filename, "server-import-template.csv");
    } catch (error) {
      message.error((error as Error).message || "模板下载失败");
    }
  };

  const onImportFile = async (file: File | undefined) => {
    if (!file) {
      return;
    }
    try {
      setImporting(true);
      setImportResult(null);
      const result = await importServersCsv(file);
      setImportResult(result);
      if (result.skipped) {
        message.warning(`导入完成，跳过 ${result.skipped} 行`);
      } else {
        message.success("服务器列表导入完成");
      }
    } catch (error) {
      message.error((error as Error).message || "服务器列表导入失败");
    } finally {
      setImporting(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
    }
  };

  const onExport = async (dataType: ExportDataType, format: ExportFileFormat) => {
    const key = `${dataType}-${format}`;
    try {
      setExportingKey(key);
      const { blob, filename } = await exportDataSet(dataType, format);
      saveBlob(blob, filename, `${dataType}.${format}`);
    } catch (error) {
      message.error((error as Error).message || "数据导出失败");
    } finally {
      setExportingKey(null);
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
              系统将按照 <Text code>主机发现 -{">"} 基础信息扫描 -{">"} 深度扫描 -{">"} 风险验证</Text> 的顺序执行。
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

              <Collapse
                items={[
                  {
                    key: "advanced-dispatch",
                    label: "高级调度",
                    children: (
                      <Space direction="vertical" size={16} style={{ width: "100%" }}>
                        <Form.Item name="scanner_zone_id" label={<Text strong>扫描分区</Text>}>
                          <Select
                            allowClear
                            placeholder={optionsLoading ? "正在加载可用分区..." : "自动匹配或手动选择分区"}
                            options={(options?.scanner_zones || []).map((zone) => ({
                              label: `${zone.name} (${zone.zone_type})`,
                              value: zone.id,
                            }))}
                            disabled={Boolean(form.getFieldValue("runner_asset_id"))}
                          />
                        </Form.Item>
                        <Form.Item name="runner_asset_id" label={<Text strong>指定 Runner</Text>}>
                          <Select
                            allowClear
                            placeholder={optionsLoading ? "正在加载可用 Runner..." : "指定扫描节点"}
                            options={(options?.runner_assets || []).map((runner) => ({
                              label: `${runner.asset_hostname || runner.asset_ip || runner.asset_id}${runner.scanner_zone_id ? ` · ${runner.scanner_zone_id}` : ""}`,
                              value: runner.asset_id,
                            }))}
                            disabled={Boolean(form.getFieldValue("scanner_zone_id"))}
                          />
                        </Form.Item>
                        {options?.recommended_zone_ids?.length ? (
                          <Text type="secondary">当前 CIDR 推荐分区：{options.recommended_zone_ids.join("、")}</Text>
                        ) : (
                          <Text type="secondary">未指定调度时，系统将按 CIDR 自动匹配分区或走本地扫描。</Text>
                        )}
                      </Space>
                    ),
                  },
                ]}
              />

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
                          {submissionSummary.executionBoundary ? `，执行边界 ${submissionSummary.executionBoundary}` : ""}
                          {submissionSummary.runnerAssetId ? `，Runner ${submissionSummary.runnerAssetId}` : ""}
                          {submissionSummary.scannerZoneId ? `，分区 ${submissionSummary.scannerZoneId}` : ""}
                          {submissionSummary.matchedZoneIds.length ? `，匹配分区 ${submissionSummary.matchedZoneIds.join("、")}` : ""}
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
          <Card className="panel-card discovery-stage-card" data-haor-section="导入导出工具" bordered={false} title={<Text strong>导入 / 导出</Text>}>
            <Space direction="vertical" size={14} style={{ width: "100%" }}>
              <Alert
                showIcon
                type="info"
                message="服务器列表 CSV 导入"
                description="必填 name、hostname、ip；password 将使用 AES-256-GCM 加密存储。"
              />
              <Space wrap>
                <Button icon={<DownloadOutlined />} onClick={() => void onDownloadTemplate()}>
                  下载 CSV 模板
                </Button>
                <Button icon={<ImportOutlined />} loading={importing} onClick={() => fileInputRef.current?.click()}>
                  导入服务器 CSV
                </Button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv,text/csv"
                  style={{ display: "none" }}
                  onChange={(event) => void onImportFile(event.target.files?.[0])}
                />
              </Space>

              {importResult ? (
                <div className="data-exchange-import-result">
                  <Tag color="blue">{`总行数 ${importResult.total_rows}`}</Tag>
                  <Tag color="green">{`新增 ${importResult.created}`}</Tag>
                  <Tag color="cyan">{`更新 ${importResult.updated}`}</Tag>
                  <Tag color="purple">{`凭据 ${importResult.credential_saved}`}</Tag>
                  {importResult.skipped ? <Tag color="orange">{`跳过 ${importResult.skipped}`}</Tag> : null}
                  {importResult.issues.slice(0, 3).map((issue) => (
                    <Text key={`${issue.row}-${issue.field}-${issue.message}`} type="secondary" className="ui-detail-wrap">
                      第 {issue.row} 行{issue.field ? ` ${issue.field}` : ""}：{issue.message}
                    </Text>
                  ))}
                </div>
              ) : null}

              <Divider style={{ margin: "4px 0" }} />

              <div className="data-exchange-export-list">
                {exportOptions.map((item) => (
                  <div key={item.type} className="data-exchange-export-item">
                    <div>
                      <Text strong>{item.label}</Text>
                      <br />
                      <Text type="secondary">{item.purpose}</Text>
                    </div>
                    <Space>
                      <Button
                        size="small"
                        onClick={() => void onExport(item.type, "csv")}
                        loading={exportingKey === `${item.type}-csv`}
                      >
                        CSV
                      </Button>
                      <Button
                        size="small"
                        onClick={() => void onExport(item.type, "json")}
                        loading={exportingKey === `${item.type}-json`}
                      >
                        JSON
                      </Button>
                    </Space>
                  </div>
                ))}
              </div>

              <Alert
                showIcon
                type="success"
                message="CSV 导出已带 UTF-8 BOM"
                description="中文字段名可直接用 Excel 打开，日期字段按标准格式输出。"
              />
            </Space>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
