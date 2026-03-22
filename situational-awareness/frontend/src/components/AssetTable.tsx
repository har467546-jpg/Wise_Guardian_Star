"use client";

import Link from "next/link";
import { memo, useCallback, useEffect, useMemo, useState } from "react";
import { Alert, Button, Card, Checkbox, Empty, Input, Pagination, Popconfirm, Select, Skeleton, Space, Tag, Tooltip, Typography, message } from "antd";

import DesktopPageHeader from "@/components/DesktopPageHeader";
import OverflowText from "@/components/OverflowText";
import {
  deleteAsset,
  deleteAssetsBatch,
  listAssets,
  runAssetCollectionBatch,
  runRiskVerifyBatch,
} from "@/services/api";
import { Asset } from "@/types/asset";
import StatusTag from "@/components/StatusTag";

const PAGE_SIZE = 24;
const SEARCH_DEBOUNCE_MS = 300;

type StatusFilter = "all" | Asset["status"];
type BulkAction = "delete" | "collect" | "verify" | null;

function formatPorts(asset: Asset): string {
  if (!asset.ports.length) {
    return "暂无开放端口";
  }
  return asset.ports
    .slice(0, 4)
    .map((port) => `${port.port}/${port.protocol} ${port.service_name || "未知服务"}`)
    .join(" | ");
}

type AssetSquareCardProps = {
  asset: Asset;
  selected: boolean;
  actionBusy: boolean;
  deleting: boolean;
  onToggleSelect: (assetId: string, checked: boolean) => void;
  onDelete: (assetId: string) => Promise<void>;
};

const AssetSquareCard = memo(function AssetSquareCard({
  asset,
  selected,
  actionBusy,
  deleting,
  onToggleSelect,
  onDelete,
}: AssetSquareCardProps) {
  const portsText = formatPorts(asset);
  return (
    <Card key={asset.id} className={`asset-square-card ${selected ? "asset-square-card-selected" : ""} ${asset.is_local ? "asset-square-card-local" : ""}`} bordered>
      <div className="asset-square-card-content">
        <Space style={{ width: "100%", justifyContent: "space-between", alignItems: "flex-start" }}>
          <div className="ui-cell-stack" style={{ flex: 1 }}>
            <Typography.Text strong className="asset-square-ip mono-text">{asset.ip}</Typography.Text>
            <OverflowText value={asset.hostname || "未识别主机名"} block secondary />
          </div>
          <Space size={6}>
            {asset.is_local ? (
              <Tooltip title={asset.local_hint || "平台所在主机"}>
                <Tag color="magenta">本机</Tag>
              </Tooltip>
            ) : null}
            <StatusTag value={asset.status} />
          </Space>
        </Space>

        <div className="asset-square-facts">
          <div className="console-keyline">
            <span>系统</span>
            <strong>{asset.os_name || "未识别系统"}</strong>
          </div>
          <div className="console-keyline">
            <span>端口</span>
            <strong>{asset.ports.length} 个</strong>
          </div>
          <div className="console-keyline">
            <span>最近发现</span>
            <strong>{new Date(asset.last_seen_at).toLocaleString()}</strong>
          </div>
        </div>

        <div className="asset-service-strip">
          <span className="asset-service-strip-label">服务指纹</span>
          <OverflowText value={portsText} block />
        </div>

        <Space style={{ width: "100%", justifyContent: "space-between", marginTop: "auto" }} wrap>
          <Checkbox checked={selected} onChange={(event) => onToggleSelect(asset.id, event.target.checked)}>
            选择
          </Checkbox>
          <Link href={`/assets/${asset.id}`}>
            <Button size="small" disabled={actionBusy}>查看详情</Button>
          </Link>
          <Popconfirm
            title="确认删除该资产？"
            description="删除后将移除该资产及其关联端口和快照。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => void onDelete(asset.id)}
          >
            <Button size="small" danger loading={deleting} disabled={actionBusy}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      </div>
    </Card>
  );
});

export default function AssetTable() {
  const [items, setItems] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keywordInput, setKeywordInput] = useState("");
  const [keyword, setKeyword] = useState("");
  const [status, setStatus] = useState<StatusFilter>("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [deletingAssetId, setDeletingAssetId] = useState<string | null>(null);
  const [bulkAction, setBulkAction] = useState<BulkAction>(null);
  const [selectAllLoading, setSelectAllLoading] = useState(false);

  const actionBusy = bulkAction !== null || deletingAssetId !== null || selectAllLoading;

  const loadAssets = useCallback(async (targetPage: number) => {
    try {
      setLoading(true);
      const result = await listAssets({
        page: targetPage,
        pageSize: PAGE_SIZE,
        keyword: keyword || undefined,
        status,
      });
      setItems(result.items);
      setTotal(result.meta.total);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, [keyword, status]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setPage(1);
      setKeyword(keywordInput.trim());
    }, SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [keywordInput]);

  useEffect(() => {
    void loadAssets(page);
  }, [loadAssets, page]);

  const currentPageIds = useMemo(() => items.map((item) => item.id), [items]);
  const selectedCount = selectedIds.size;
  const allCurrentPageSelected = currentPageIds.length > 0 && currentPageIds.every((assetId) => selectedIds.has(assetId));

  const onToggleSelect = useCallback((assetId: string, checked: boolean) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (checked) {
        next.add(assetId);
      } else {
        next.delete(assetId);
      }
      return next;
    });
  }, []);

  const onSelectCurrentPage = useCallback(() => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (allCurrentPageSelected) {
        currentPageIds.forEach((assetId) => next.delete(assetId));
      } else {
        currentPageIds.forEach((assetId) => next.add(assetId));
      }
      return next;
    });
  }, [allCurrentPageSelected, currentPageIds]);

  const onSelectAllFiltered = useCallback(async () => {
    if (!total) {
      return;
    }
    try {
      setSelectAllLoading(true);
      const pageSize = 200;
      const pageCount = Math.max(1, Math.ceil(total / pageSize));
      const pages = await Promise.all(
        Array.from({ length: pageCount }, (_, index) =>
          listAssets({
            page: index + 1,
            pageSize,
            keyword: keyword || undefined,
            status,
          }),
        ),
      );
      const filteredIds = Array.from(
        new Set(
          pages.flatMap((result) => result.items.map((item) => item.id)),
        ),
      );
      if (!filteredIds.length) {
        return;
      }
      setSelectedIds((prev) => {
        const next = new Set(prev);
        filteredIds.forEach((assetId) => next.add(assetId));
        return next;
      });
      message.success(`已选中当前筛选结果中的 ${filteredIds.length} 项资产`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setSelectAllLoading(false);
    }
  }, [keyword, status, total]);

  const clearSelected = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const refreshAfterDelete = useCallback((deletedCount: number) => {
    if (deletedCount <= 0) {
      return;
    }
    const shouldFallbackPage = page > 1 && items.length <= deletedCount;
    if (shouldFallbackPage) {
      setPage((prev) => prev - 1);
      return;
    }
    void loadAssets(page);
  }, [items.length, loadAssets, page]);

  const onDeleteSingle = useCallback(async (assetId: string) => {
    try {
      setDeletingAssetId(assetId);
      await deleteAsset(assetId);
      setSelectedIds((prev) => {
        const next = new Set(prev);
        next.delete(assetId);
        return next;
      });
      setItems((prev) => prev.filter((item) => item.id !== assetId));
      setTotal((prev) => Math.max(0, prev - 1));
      message.success("资产已删除");
      refreshAfterDelete(1);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setDeletingAssetId(null);
    }
  }, [refreshAfterDelete]);

  const selectedList = useMemo(() => Array.from(selectedIds), [selectedIds]);

  const onBatchDelete = useCallback(async () => {
    if (!selectedList.length) {
      return;
    }
    try {
      setBulkAction("delete");
      const result = await deleteAssetsBatch(selectedList);
      const deletedSet = new Set(selectedList.filter((assetId) => !result.missing_ids.includes(assetId)));
      setItems((prev) => prev.filter((item) => !deletedSet.has(item.id)));
      setTotal((prev) => Math.max(0, prev - result.deleted));
      setSelectedIds((prev) => {
        const next = new Set(prev);
        selectedList.forEach((assetId) => next.delete(assetId));
        return next;
      });
      if (result.missing_ids.length) {
        message.warning(`批量删除完成，成功 ${result.deleted} 条，缺失 ${result.missing_ids.length} 条`);
      } else {
        message.success(`批量删除完成，共删除 ${result.deleted} 条资产`);
      }
      refreshAfterDelete(result.deleted);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setBulkAction(null);
    }
  }, [refreshAfterDelete, selectedList]);

  const onBatchCollect = useCallback(async () => {
    if (!selectedList.length) {
      return;
    }
    try {
      setBulkAction("collect");
      const result = await runAssetCollectionBatch({ asset_ids: selectedList });
      message.success(`批量采集任务已提交：${result.task_id}`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setBulkAction(null);
    }
  }, [selectedList]);

  const onBatchVerify = useCallback(async () => {
    if (!selectedList.length) {
      return;
    }
    try {
      setBulkAction("verify");
      const result = await runRiskVerifyBatch(selectedList);
      message.success(`批量风险验证已提交，共 ${result.queued} 条任务`);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setBulkAction(null);
    }
  }, [selectedList]);

  const skeletonItems = useMemo(() => Array.from({ length: 8 }, (_, index) => index), []);
  const onlineCount = useMemo(() => items.filter((item) => item.status === "online").length, [items]);
  const collectingCount = useMemo(() => items.filter((item) => item.status === "collecting").length, [items]);

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <DesktopPageHeader
        eyebrow="资产情报"
        title="资产情报面板"
        description="围绕桌面端操作场景聚焦资产筛选、批量动作和高密度服务情报浏览。"
        meta={[
          { label: "资产总数", value: total, tone: "accent" },
          { label: "本页在线", value: onlineCount, tone: onlineCount ? "success" : "neutral" },
          { label: "采集中", value: collectingCount, tone: collectingCount ? "warning" : "neutral" },
          { label: "已选项目", value: selectedCount, tone: selectedCount ? "accent" : "neutral" },
        ]}
      />

      <Card className="panel-card compact-workbench-card">
        <div className="compact-toolbar-stack">
          <div className="compact-toolbar-row">
            <Space className="asset-toolbar" wrap>
              <Input
                placeholder="搜索 IP / 主机名 / 系统"
                className="asset-search-input"
                value={keywordInput}
                onChange={(event) => setKeywordInput(event.target.value)}
                allowClear
              />
              <Select
                value={status}
                onChange={(value) => {
                  setStatus(value);
                  setPage(1);
                }}
                className="asset-status-select"
                options={[
                  { label: "全部状态", value: "all" },
                  { label: "在线", value: "online" },
                  { label: "离线", value: "offline" },
                  { label: "正在采集", value: "collecting" },
                  { label: "未知", value: "unknown" },
                ]}
              />
              <Button onClick={() => void loadAssets(page)} loading={loading}>刷新</Button>
            </Space>
          </div>
          <div className="compact-toolbar-row compact-toolbar-row-secondary">
            <Space className="asset-batch-toolbar" wrap>
              <Typography.Text>已选 {selectedCount} 项</Typography.Text>
              <Button onClick={() => void onSelectAllFiltered()} disabled={!total || actionBusy} loading={selectAllLoading}>
                全选
              </Button>
              <Button onClick={onSelectCurrentPage} disabled={!currentPageIds.length || actionBusy}>
                {allCurrentPageSelected ? "取消全选当前页" : "全选当前页"}
              </Button>
              <Button onClick={clearSelected} disabled={!selectedCount || actionBusy}>清空已选</Button>
              <Popconfirm
                title="确认批量删除选中资产？"
                description="删除后将移除关联端口和快照。"
                okText="删除"
                cancelText="取消"
                okButtonProps={{ danger: true }}
                onConfirm={() => void onBatchDelete()}
              >
                <Button danger disabled={!selectedCount || actionBusy} loading={bulkAction === "delete"}>
                  批量删除
                </Button>
              </Popconfirm>
              <Button type="primary" disabled={!selectedCount || actionBusy} loading={bulkAction === "collect"} onClick={() => void onBatchCollect()}>
                批量采集
              </Button>
              <Button disabled={!selectedCount || actionBusy} loading={bulkAction === "verify"} onClick={() => void onBatchVerify()}>
                批量风险验证
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      <Card className="panel-card" title="资产卡片视图" extra={<Typography.Text type="secondary">总计 {total} 条</Typography.Text>}>
        {error ? <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} /> : null}

        {!items.length && !loading ? (
          <Empty description="暂无资产" />
        ) : (
          <div className="asset-square-grid">
            {loading && !items.length ? skeletonItems.map((value) => (
              <Card key={`asset-skeleton-${value}`} className="asset-square-card">
                <div className="asset-square-card-content">
                  <Skeleton active title={{ width: "72%" }} paragraph={{ rows: 6 }} />
                </div>
              </Card>
            )) : items.map((asset) => (
              <AssetSquareCard
                key={asset.id}
                asset={asset}
                selected={selectedIds.has(asset.id)}
                actionBusy={actionBusy}
                deleting={deletingAssetId === asset.id}
                onToggleSelect={onToggleSelect}
                onDelete={onDeleteSingle}
              />
            ))}
          </div>
        )}

        <div className="asset-pagination-wrap">
          <Pagination
            current={page}
            pageSize={PAGE_SIZE}
            total={total}
            showSizeChanger={false}
            onChange={(nextPage) => setPage(nextPage)}
            showTotal={(count) => `共 ${count} 条`}
          />
        </div>
      </Card>
    </Space>
  );
}
