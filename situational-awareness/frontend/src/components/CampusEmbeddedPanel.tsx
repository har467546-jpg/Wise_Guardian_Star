"use client";

import { useEffect, useMemo, useState } from "react";
import { Button, Card, Col, Form, Input, InputNumber, Row, Select, Space, Switch, Table, Tag, Typography, message } from "antd";

import {
  createCampusDataSource,
  createScannerZone,
  createZoneNode,
  listAssets,
  listCampusDataSources,
  listScannerZones,
  listZoneNodes,
  testCampusDataSource,
} from "@/services/api";
import type { Asset } from "@/types/asset";
import type { CampusDataSource, ScannerNodeAssignment, ScannerZone } from "@/types/campus";

type ZoneValues = {
  name: string;
  zone_type: ScannerZone["zone_type"];
  priority: number;
  enabled: boolean;
  cidrs_csv: string;
};

type NodeValues = {
  asset_id: string;
  priority: number;
  enabled: boolean;
  max_concurrent_jobs: number;
};

type SourceValues = {
  name: string;
  source_type: CampusDataSource["source_type"];
  collection_interval_seconds: number;
  enabled: boolean;
  config_json: string;
  secret_plaintext?: string;
};

function parseCsv(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

export default function CampusEmbeddedPanel() {
  const [zones, setZones] = useState<ScannerZone[]>([]);
  const [nodes, setNodes] = useState<ScannerNodeAssignment[]>([]);
  const [dataSources, setDataSources] = useState<CampusDataSource[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [selectedZoneId, setSelectedZoneId] = useState("");
  const [zoneForm] = Form.useForm<ZoneValues>();
  const [nodeForm] = Form.useForm<NodeValues>();
  const [sourceForm] = Form.useForm<SourceValues>();

  const load = async (preferredZoneId?: string) => {
    const [zoneResult, assetResult] = await Promise.all([
      listScannerZones({ page: 1, pageSize: 100 }),
      listAssets({ page: 1, pageSize: 200 }),
    ]);
    setZones(zoneResult.items);
    setAssets(assetResult.items);
    const nextZone = preferredZoneId || selectedZoneId || zoneResult.items[0]?.id || "";
    setSelectedZoneId(nextZone);
    if (nextZone) {
      const [nodeResult, sourceResult] = await Promise.all([
        listZoneNodes(nextZone),
        listCampusDataSources(nextZone),
      ]);
      setNodes(nodeResult);
      setDataSources(sourceResult);
    } else {
      setNodes([]);
      setDataSources([]);
    }
  };

  useEffect(() => {
    zoneForm.setFieldsValue({ zone_type: "office", priority: 100, enabled: true, cidrs_csv: "" });
    nodeForm.setFieldsValue({ priority: 100, enabled: true, max_concurrent_jobs: 1 });
    sourceForm.setFieldsValue({ source_type: "dhcp_lease", collection_interval_seconds: 1800, enabled: true, config_json: "{}" });
    void load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedZoneId) {
      return;
    }
    void Promise.all([listZoneNodes(selectedZoneId), listCampusDataSources(selectedZoneId)]).then(([nodeResult, sourceResult]) => {
      setNodes(nodeResult);
      setDataSources(sourceResult);
    });
  }, [selectedZoneId]);

  const zoneOptions = useMemo(() => zones.map((zone) => ({ label: `${zone.name}（${zone.zone_type}）`, value: zone.id })), [zones]);
  const assetOptions = useMemo(() => assets.map((asset) => ({ label: `${asset.ip}${asset.hostname ? ` / ${asset.hostname}` : ""}`, value: asset.id })), [assets]);

  return (
    <Row gutter={[20, 20]}>
      <Col xs={24} xl={10}>
        <Card className="panel-card" title="校园扫描分区">
          <Form
            layout="vertical"
            form={zoneForm}
            onFinish={(values) =>
              void createScannerZone({
                name: values.name.trim(),
                zone_type: values.zone_type,
                priority: values.priority,
                enabled: values.enabled,
                cidrs_json: parseCsv(values.cidrs_csv),
                allowed_data_source_types_json: ["dhcp_lease", "snmp_switch"],
                default_scan_profile_json: {},
              })
                .then(() => {
                  message.success("扫描分区已创建");
                  zoneForm.resetFields();
                  zoneForm.setFieldsValue({ zone_type: "office", priority: 100, enabled: true, cidrs_csv: "" });
                  return load();
                })
                .catch((error) => message.error((error as Error).message))
            }
          >
            <Form.Item name="name" label="分区名称" rules={[{ required: true, message: "请输入分区名称" }]}>
              <Input placeholder="例如：宿舍区 A / 办公网" />
            </Form.Item>
            <Form.Item name="zone_type" label="分区类型">
              <Select options={[{ label: "办公区", value: "office" }, { label: "宿舍区", value: "dormitory" }, { label: "无线区", value: "wireless" }, { label: "服务器区", value: "server" }, { label: "物联区", value: "iot" }, { label: "自定义", value: "custom" }]} />
            </Form.Item>
            <Form.Item name="priority" label="优先级">
              <InputNumber min={1} max={10000} style={{ width: "100%" }} />
            </Form.Item>
            <Form.Item name="cidrs_csv" label="网段列表" rules={[{ required: true, message: "请输入至少一个 CIDR" }]}>
              <Input.TextArea rows={3} placeholder="例如：10.10.0.0/24,10.10.1.0/24" />
            </Form.Item>
            <Form.Item name="enabled" label="启用分区" valuePropName="checked">
              <Switch />
            </Form.Item>
            <Button type="primary" htmlType="submit">创建分区</Button>
          </Form>
          <Table
            style={{ marginTop: 16 }}
            rowKey="id"
            dataSource={zones}
            pagination={false}
            size="small"
            columns={[
              { title: "分区", dataIndex: "name" },
              { title: "类型", dataIndex: "zone_type", render: (value: string) => <Tag>{value}</Tag> },
              { title: "网段", dataIndex: "cidrs_json", render: (value: string[]) => (value || []).join(", ") || "-" },
            ]}
          />
        </Card>
      </Col>
      <Col xs={24} xl={14}>
        <Card className="panel-card" title="校园节点与数据源">
          <Space direction="vertical" style={{ width: "100%" }} size={16}>
            <div>
              <Typography.Text strong>当前分区</Typography.Text>
              <Select style={{ width: "100%", marginTop: 8 }} value={selectedZoneId || undefined} onChange={setSelectedZoneId} options={zoneOptions} placeholder="选择分区" />
            </div>

            <Form
              layout="vertical"
              form={nodeForm}
              onFinish={(values) => {
                if (!selectedZoneId) {
                  message.warning("请先选择分区");
                  return;
                }
                void createZoneNode(selectedZoneId, {
                  asset_id: values.asset_id,
                  enabled: values.enabled,
                  priority: values.priority,
                  visible_cidrs_json: [],
                  max_concurrent_jobs: values.max_concurrent_jobs,
                })
                  .then(() => {
                    message.success("扫描节点已绑定");
                    nodeForm.resetFields();
                    nodeForm.setFieldsValue({ priority: 100, enabled: true, max_concurrent_jobs: 1 });
                    return load(selectedZoneId);
                  })
                  .catch((error) => message.error((error as Error).message));
              }}
            >
              <Typography.Text strong>绑定扫描节点</Typography.Text>
              <Row gutter={12}>
                <Col span={12}>
                  <Form.Item name="asset_id" label="资产" rules={[{ required: true, message: "请选择资产" }]}>
                    <Select showSearch options={assetOptions} />
                  </Form.Item>
                </Col>
                <Col span={6}>
                  <Form.Item name="priority" label="优先级">
                    <InputNumber min={1} max={10000} style={{ width: "100%" }} />
                  </Form.Item>
                </Col>
                <Col span={6}>
                  <Form.Item name="max_concurrent_jobs" label="并发">
                    <InputNumber min={1} max={128} style={{ width: "100%" }} />
                  </Form.Item>
                </Col>
              </Row>
              <Form.Item name="enabled" label="启用" valuePropName="checked">
                <Switch />
              </Form.Item>
              <Button type="primary" htmlType="submit" disabled={!selectedZoneId}>绑定节点</Button>
            </Form>

            <Table
              rowKey="id"
              dataSource={nodes}
              pagination={false}
              size="small"
              columns={[
                { title: "资产", dataIndex: "asset_id" },
                { title: "优先级", dataIndex: "priority" },
                { title: "并发", dataIndex: "max_concurrent_jobs" },
                { title: "状态", dataIndex: "enabled", render: (value: boolean) => <Tag color={value ? "green" : "default"}>{value ? "启用" : "停用"}</Tag> },
              ]}
            />

            <Form
              layout="vertical"
              form={sourceForm}
              onFinish={(values) => {
                if (!selectedZoneId) {
                  message.warning("请先选择分区");
                  return;
                }
                let configJson: Record<string, unknown> = {};
                try {
                  configJson = JSON.parse(values.config_json || "{}");
                } catch {
                  message.error("数据源配置必须是合法 JSON");
                  return;
                }
                void createCampusDataSource({
                  scanner_zone_id: selectedZoneId,
                  name: values.name.trim(),
                  source_type: values.source_type,
                  enabled: values.enabled,
                  collection_interval_seconds: values.collection_interval_seconds,
                  config_json: configJson,
                  secret_plaintext: values.secret_plaintext?.trim() || null,
                })
                  .then(() => {
                    message.success("校园数据源已创建");
                    sourceForm.resetFields();
                    sourceForm.setFieldsValue({ source_type: "dhcp_lease", collection_interval_seconds: 1800, enabled: true, config_json: "{}" });
                    return load(selectedZoneId);
                  })
                  .catch((error) => message.error((error as Error).message));
              }}
            >
              <Typography.Text strong>创建校园数据源</Typography.Text>
              <Row gutter={12}>
                <Col span={10}>
                  <Form.Item name="name" label="名称" rules={[{ required: true, message: "请输入名称" }]}>
                    <Input placeholder="例如：宿舍区 DHCP" />
                  </Form.Item>
                </Col>
                <Col span={7}>
                  <Form.Item name="source_type" label="类型">
                    <Select options={[{ label: "DHCP 租约", value: "dhcp_lease" }, { label: "交换机 SNMP", value: "snmp_switch" }]} />
                  </Form.Item>
                </Col>
                <Col span={7}>
                  <Form.Item name="collection_interval_seconds" label="周期">
                    <InputNumber min={60} max={86400} style={{ width: "100%" }} />
                  </Form.Item>
                </Col>
              </Row>
              <Form.Item name="config_json" label="配置 JSON">
                <Input.TextArea rows={4} placeholder='例如：{"lease_file_path":"/var/lib/misc/dnsmasq.leases"}' />
              </Form.Item>
              <Form.Item name="secret_plaintext" label="敏感凭据">
                <Input.Password placeholder="SNMP community 等敏感字段" />
              </Form.Item>
              <Form.Item name="enabled" label="启用" valuePropName="checked">
                <Switch />
              </Form.Item>
              <Button type="primary" htmlType="submit" disabled={!selectedZoneId}>创建数据源</Button>
            </Form>

            <Table
              rowKey="id"
              dataSource={dataSources}
              pagination={false}
              size="small"
              columns={[
                { title: "名称", dataIndex: "name" },
                { title: "类型", dataIndex: "source_type", render: (value: string) => <Tag color="blue">{value}</Tag> },
                { title: "周期", dataIndex: "collection_interval_seconds", render: (value: number) => `${value}s` },
                {
                  title: "操作",
                  key: "actions",
                  render: (_: unknown, record: CampusDataSource) => (
                    <Space>
                      <Button size="small" onClick={() => void testCampusDataSource(record.id).then((result) => message.info(result.message)).catch((error) => message.error((error as Error).message))}>测试</Button>
                    </Space>
                  ),
                },
              ]}
            />
          </Space>
        </Card>
      </Col>
    </Row>
  );
}
