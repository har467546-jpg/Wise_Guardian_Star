"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Alert, Button, Card, Empty, Grid, Input, Pagination, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import StatusTag from "@/components/StatusTag";
import { formatDateTime } from "@/lib/ui-text";
import { buildRemediationAssetPath } from "@/lib/remediation";
import { listRemediationAssets } from "@/services/api";
import type { RemediationAssetCard } from "@/types/remediation";

const PAGE_SIZE = 24;
const SEARCH_DEBOUNCE_MS = 300;

function privilegeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "root":
      return "root";
    case "sudo":
      return "sudo";
    default:
      return "未验证";
  }
}

function privilegeColor(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "root":
      return "volcano";
    case "sudo":
      return "gold";
    default:
      return "default";
  }
}

function workbenchStatusLabel(status: string | null | undefined): string {
  switch (String(status || "").trim().toLowerCase()) {
    case "draft":
      return "待准备";
    case "ready":
      return "可执行";
    case "running":
      return "执行中";
    case "completed":
      return "已完成";
    case "failed":
      return "失败";
    case "canceled":
      return "已中断";
    default:
      return "未创建";
  }
}

function RemediationAssetListCard({
  asset,
  onOpen,
}: {
  asset: RemediationAssetCard;
  onOpen: (asset: RemediationAssetCard) => void;
}) {
  return (
    <div
      className="remediation-asset-list-card"
      role="button"
      tabIndex={0}
      onClick={() => onOpen(asset)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen(asset);
        }
      }}
    >
      <Space direction="vertical" size={10} style={{ width: "100%" }}>
        <Space align="start" style={{ width: "100%", justifyContent: "space-between" }}>
          <div className="ui-cell-stack" style={{ flex: 1 }}>
            <Typography.Text strong className="mono-text">
              {asset.ip}
            </Typography.Text>
            <Typography.Text type="secondary" className="ui-detail-wrap">
              {asset.hostname || "未识别主机名"}
            </Typography.Text>
          </div>
          <Button
            type="primary"
            size="small"
            onClick={(event) => {
              event.stopPropagation();
              onOpen(asset);
            }}
          >
            进入工作台
          </Button>
        </Space>

        <Space wrap>
          <StatusTag value={asset.highest_severity || "unknown"} />
          <Tag color={privilegeColor(asset.effective_privilege)}>{privilegeLabel(asset.effective_privilege)}</Tag>
          <StatusTag value={asset.runner_status || "not_installed"} />
          {asset.active_session_status ? <StatusTag value={asset.active_session_status} /> : <Tag>未创建会话</Tag>}
        </Space>

        <div className="remediation-asset-list-facts">
          <div className="console-keyline">
            <span>系统</span>
            <strong>{asset.os_name || "未识别系统"}</strong>
          </div>
          <div className="console-keyline">
            <span>可修复风险</span>
            <strong>{asset.finding_count} 条</strong>
          </div>
          <div className="console-keyline">
            <span>Runner</span>
            <strong>{asset.runner_status || "not_installed"}</strong>
          </div>
          <div className="console-keyline">
            <span>最近深度检查</span>
            <strong>{formatDateTime(asset.last_collection_at)}</strong>
          </div>
        </div>
      </Space>
    </div>
  );
}

export default function RemediationAssetGalleryView() {
  const screens = Grid.useBreakpoint();
  const router = useRouter();
  const [assetCards, setAssetCards] = useState<RemediationAssetCard[]>([]);
  const [assetCardsTotal, setAssetCardsTotal] = useState(0);
  const [assetCardsLoading, setAssetCardsLoading] = useState(false);
  const [assetCardsError, setAssetCardsError] = useState<string | null>(null);
  const [assetPage, setAssetPage] = useState(1);
  const [assetKeywordInput, setAssetKeywordInput] = useState("");
  const [assetKeyword, setAssetKeyword] = useState("");

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setAssetPage(1);
      setAssetKeyword(assetKeywordInput.trim());
    }, SEARCH_DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [assetKeywordInput]);

  const loadAssetCards = async () => {
    try {
      setAssetCardsLoading(true);
      const result = await listRemediationAssets({
        page: assetPage,
        pageSize: PAGE_SIZE,
        keyword: assetKeyword || undefined,
      });
      setAssetCards(result.items);
      setAssetCardsTotal(result.meta.total);
      setAssetCardsError(null);
    } catch (err) {
      setAssetCardsError((err as Error).message);
    } finally {
      setAssetCardsLoading(false);
    }
  };

  useEffect(() => {
    void loadAssetCards();
  }, [assetKeyword, assetPage]);

  const openAsset = (asset: RemediationAssetCard) => {
    router.push(
      buildRemediationAssetPath(asset.asset_id, {
        findingId: asset.recommended_finding_id,
      }),
    );
  };

  const pageFindings = assetCards.reduce((total, asset) => total + Number(asset.finding_count || 0), 0);
  const pageHighRiskCount = assetCards.filter((asset) => ["high", "critical"].includes(String(asset.highest_severity || "").toLowerCase())).length;
  const pageRunnerOnlineCount = assetCards.filter((asset) => ["online", "busy"].includes(String(asset.runner_status || "").toLowerCase())).length;
  const pageAdminReadyCount = assetCards.filter((asset) => ["root", "sudo"].includes(String(asset.effective_privilege || "").toLowerCase())).length;
  const pageActiveSessionCount = assetCards.filter((asset) => Boolean(asset.active_session_id)).length;

  const columns: ColumnsType<RemediationAssetCard> = [
    {
      title: "资产标识",
      dataIndex: "ip",
      key: "ip",
      render: (_value, record) => (
        <Space direction="vertical" size={2}>
          <Typography.Text strong className="mono-text">
            {record.ip}
          </Typography.Text>
          <Typography.Text type="secondary" className="ui-detail-wrap">
            {record.hostname || "未识别主机名"}
          </Typography.Text>
          <Typography.Text type="secondary" className="ui-detail-wrap">
            {record.os_name || "未识别系统"}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "风险",
      key: "risk",
      width: 180,
      render: (_value, record) => (
        <Space direction="vertical" size={6}>
          <Typography.Text strong>{record.finding_count} 条</Typography.Text>
          {record.highest_severity ? <StatusTag value={record.highest_severity} /> : <Tag>未知风险</Tag>}
        </Space>
      ),
    },
    {
      title: "权限状态",
      key: "privilege",
      width: 160,
      render: (_value, record) => (
        <Space direction="vertical" size={6}>
          <Tag color={privilegeColor(record.effective_privilege)}>{privilegeLabel(record.effective_privilege)}</Tag>
          <Typography.Text type="secondary">
            {record.effective_privilege ? "管理员链路已验证" : "管理员链路待确认"}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "Runner",
      key: "runner",
      width: 180,
      render: (_value, record) => (
        <Space direction="vertical" size={6}>
          <StatusTag value={record.runner_status || "not_installed"} />
          <Typography.Text type="secondary">
            {record.runner_install_status || "未安装"}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "当前会话",
      key: "session",
      width: 160,
      render: (_value, record) => (
        <Space direction="vertical" size={6}>
          {record.active_session_status ? <StatusTag value={record.active_session_status} /> : <Tag>未创建</Tag>}
          <Typography.Text type="secondary">{workbenchStatusLabel(record.active_session_status)}</Typography.Text>
        </Space>
      ),
    },
    {
      title: "最近检查",
      key: "timestamps",
      width: 190,
      render: (_value, record) => (
        <Space direction="vertical" size={4}>
          <Typography.Text type="secondary">
            深度检查：{formatDateTime(record.last_collection_at)}
          </Typography.Text>
          <Typography.Text type="secondary">
            授权验证：{formatDateTime(record.last_verified_at)}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: "操作",
      key: "action",
      width: 140,
      align: "right",
      render: (_value, record) => (
        <Button
          type="primary"
          onClick={(event) => {
            event.stopPropagation();
            openAsset(record);
          }}
        >
          进入工作台
        </Button>
      ),
    },
  ];

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="漏洞修复"
        title="修复工作台"
        description="按权限、Runner 和风险状态快速筛选资产，进入单资产修复工作台。"
        meta={[
          { label: "匹配资产", value: assetCardsTotal, tone: "accent" },
          { label: "当前页", value: assetCards.length, tone: "neutral" },
        ]}
        actions={(
          <Button onClick={() => void loadAssetCards()} loading={assetCardsLoading}>
            刷新资产
          </Button>
        )}
      />

      {assetCardsError ? <Alert type="error" showIcon message={assetCardsError} /> : null}

      <div className="remediation-summary-grid">
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">当前匹配</span>
          <strong className="remediation-summary-value">{assetCardsTotal}</strong>
          <span className="remediation-summary-detail">{assetKeyword ? `关键字：${assetKeyword}` : "当前搜索条件下的资产总数"}</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">当前页风险</span>
          <strong className="remediation-summary-value">{pageFindings}</strong>
          <span className="remediation-summary-detail">{pageHighRiskCount} 台资产包含高危或严重风险</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">当前页管理员链路</span>
          <strong className="remediation-summary-value">{pageAdminReadyCount}</strong>
          <span className="remediation-summary-detail">已验证为 root 或 sudo 的资产数</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">当前页 Runner</span>
          <strong className="remediation-summary-value">{pageRunnerOnlineCount}</strong>
          <span className="remediation-summary-detail">{pageActiveSessionCount} 台资产已有活动会话</span>
        </div>
      </div>

      <Card
        className="panel-card"
        title="可修复资产"
        extra={<Typography.Text type="secondary">表格展示当前结果页，不代表全库聚合统计</Typography.Text>}
      >
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Space wrap className="asset-toolbar">
            <Input.Search
              allowClear
              placeholder="按 IP / 主机名 / 系统搜索可修复资产"
              value={assetKeywordInput}
              onChange={(event) => setAssetKeywordInput(event.target.value)}
              className="asset-search-input"
            />
          </Space>

          {!assetCards.length && !assetCardsLoading ? (
            <Empty description="当前没有同时满足管理员授权、深度检查和可修复风险条件的资产。" />
          ) : screens.md ? (
            <Table
              className="remediation-assets-table"
              rowKey="asset_id"
              loading={assetCardsLoading}
              dataSource={assetCards}
              columns={columns}
              pagination={false}
              onRow={(record) => ({
                onClick: () => openAsset(record),
              })}
            />
          ) : (
            <Space direction="vertical" size={12} style={{ width: "100%" }}>
              {assetCards.map((asset) => (
                <RemediationAssetListCard key={asset.asset_id} asset={asset} onOpen={openAsset} />
              ))}
            </Space>
          )}

          <div className="asset-pagination-wrap">
            <Pagination
              current={assetPage}
              pageSize={PAGE_SIZE}
              total={assetCardsTotal}
              showSizeChanger={false}
              onChange={(nextPage) => setAssetPage(nextPage)}
              showTotal={(count) => `共 ${count} 条`}
            />
          </div>
        </Space>
      </Card>
    </Space>
  );
}
