"use client";

import { useEffect, useMemo, useState, useTransition } from "react";
import { Alert, Card, Col, Empty, List, Progress, Row, Skeleton, Space, Typography } from "antd";

import StatusTag from "@/components/StatusTag";
import { formatDateTime, getTaskTypeLabel, localizeTaskMessage } from "@/lib/ui-text";
import { getDashboardOverview, getPlatformLiveMetrics, listAssets, listAssetRisks, listTasks } from "@/services/api";
import { Asset } from "@/types/asset";
import { MobileOverview } from "@/types/mobile";
import { PlatformLiveMetrics } from "@/types/monitoring";
import { RiskFinding } from "@/types/risk";
import { TaskRun } from "@/types/task";

const DASHBOARD_RISK_ASSET_LIMIT = 20;
const DASHBOARD_RISK_CONCURRENCY = 6;
const LIVE_METRICS_HISTORY_LIMIT = 24;
const LIVE_METRICS_POLL_INTERVAL_MS = 4000;
const LIVE_TREND_WIDTH = 168;
const LIVE_TREND_HEIGHT = 44;

type LiveMetricHistoryPoint = {
  sampledAt: string;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkRate: number;
};

function severityRank(severity: RiskFinding["severity"] | null | undefined) {
  return { critical: 4, high: 3, medium: 2, low: 1 }[severity || "low"] || 0;
}

function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "-";
  }
  if (value === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  const precision = size >= 100 || unitIndex === 0 ? 0 : 1;
  return `${size.toFixed(precision)} ${units[unitIndex]}`;
}

function formatRate(value: number | null | undefined): string {
  return `${formatBytes(value)}/s`;
}

function clampPercent(value: number | null | undefined): number {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 0;
  }
  return Math.max(0, Math.min(value, 100));
}

function toLiveMetricHistoryPoint(metrics: PlatformLiveMetrics): LiveMetricHistoryPoint {
  return {
    sampledAt: metrics.sampled_at,
    cpuUsage: clampPercent(metrics.cpu.usage_percent),
    memoryUsage: clampPercent(metrics.memory.usage_percent),
    diskUsage: clampPercent(metrics.disk.usage_percent),
    networkRate: Math.max(metrics.network.total_bytes_per_sec || 0, 0),
  };
}

function buildTrendCoordinates(series: number[], maxValue: number) {
  if (!series.length) {
    return [];
  }
  return series.map((value, index) => {
    const x = series.length === 1 ? LIVE_TREND_WIDTH / 2 : (index / (series.length - 1)) * LIVE_TREND_WIDTH;
    const ratio = maxValue > 0 ? Math.max(0, Math.min(value / maxValue, 1)) : 0;
    const y = LIVE_TREND_HEIGHT - ratio * LIVE_TREND_HEIGHT;
    return {
      x: Number(x.toFixed(2)),
      y: Number(y.toFixed(2)),
    };
  });
}

function buildTrendLine(coordinates: Array<{ x: number; y: number }>) {
  return coordinates.map(({ x, y }) => `${x},${y}`).join(" ");
}

function buildTrendArea(coordinates: Array<{ x: number; y: number }>) {
  if (!coordinates.length) {
    return "";
  }
  const first = coordinates[0];
  const last = coordinates[coordinates.length - 1];
  return `M ${first.x} ${LIVE_TREND_HEIGHT} L ${coordinates.map(({ x, y }) => `${x} ${y}`).join(" L ")} L ${last.x} ${LIVE_TREND_HEIGHT} Z`;
}

type LiveTrendCardProps = {
  label: string;
  color: string;
  value: string;
  detail: string;
  series: number[];
  scaleLabel: string;
  maxValue?: number;
};

function LiveTrendCard({ label, color, value, detail, series, scaleLabel, maxValue }: LiveTrendCardProps) {
  const normalizedMax = maxValue ?? Math.max(...series, 1);
  const coordinates = buildTrendCoordinates(series, Math.max(normalizedMax, 1));
  const line = buildTrendLine(coordinates);
  const area = buildTrendArea(coordinates);
  const lastPoint = coordinates[coordinates.length - 1] || null;
  const gradientId = `trend-${label.replace(/\s+/g, "-").toLowerCase()}`;

  return (
    <div className="live-trend-card">
      <div className="live-trend-card-header">
        <span className="live-trend-card-label">{label}</span>
        <strong className="live-trend-card-value">{value}</strong>
      </div>
      <div className="live-trend-card-chart">
        {coordinates.length > 1 ? (
          <svg
            aria-hidden="true"
            className="live-trend-svg"
            viewBox={`0 0 ${LIVE_TREND_WIDTH} ${LIVE_TREND_HEIGHT}`}
            preserveAspectRatio="none"
          >
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={color} stopOpacity="0.26" />
                <stop offset="100%" stopColor={color} stopOpacity="0.02" />
              </linearGradient>
            </defs>
            <path d={area} fill={`url(#${gradientId})`} />
            <polyline fill="none" points={line} stroke={color} strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" />
            {lastPoint ? <circle cx={lastPoint.x} cy={lastPoint.y} r="3.1" fill={color} /> : null}
          </svg>
        ) : (
          <div className="live-trend-card-empty">等待趋势样本...</div>
        )}
      </div>
      <div className="live-trend-card-footer">
        <Typography.Text type="secondary" className="live-trend-card-detail" title={detail}>
          {detail}
        </Typography.Text>
        <Typography.Text type="secondary" className="live-trend-card-scale">
          {scaleLabel}
        </Typography.Text>
      </div>
    </div>
  );
}

async function mapWithConcurrency<T, R>(items: T[], limit: number, mapper: (item: T) => Promise<R>): Promise<R[]> {
  if (items.length === 0) {
    return [];
  }
  const results = new Array<R>(items.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const current = nextIndex;
      nextIndex += 1;
      if (current >= items.length) {
        break;
      }
      results[current] = await mapper(items[current]);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

export default function DashboardBoard() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [tasks, setTasks] = useState<TaskRun[]>([]);
  const [riskMap, setRiskMap] = useState<Record<string, RiskFinding[]>>({});
  const [overview, setOverview] = useState<MobileOverview | null>(null);
  const [liveMetrics, setLiveMetrics] = useState<PlatformLiveMetrics | null>(null);
  const [liveMetricHistory, setLiveMetricHistory] = useState<LiveMetricHistoryPoint[]>([]);
  const [liveMetricsError, setLiveMetricsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [, startLiveMetricsTransition] = useTransition();

  useEffect(() => {
    async function load() {
      try {
        setLoading(true);
        const [assetRes, taskRes, overviewRes] = await Promise.all([
          listAssets({ pageSize: 80 }),
          listTasks({ pageSize: 20 }),
          getDashboardOverview().catch(() => null),
        ]);
        setAssets(assetRes.items);
        setTasks(taskRes.items);
        setOverview(overviewRes);
        const riskTargets = assetRes.items.slice(0, DASHBOARD_RISK_ASSET_LIMIT);
        const riskEntries = await mapWithConcurrency(
          riskTargets,
          DASHBOARD_RISK_CONCURRENCY,
          async (asset) => {
            try {
              return [asset.id, (await listAssetRisks(asset.id)).items] as const;
            } catch {
              return [asset.id, []] as const;
            }
          },
        );
        setRiskMap(Object.fromEntries(riskEntries));
        setError(null);
      } catch (err) {
        setError((err as Error).message);
      } finally {
        setLoading(false);
      }
    }
    void load();
  }, []);

  useEffect(() => {
    let disposed = false;

    const applyLiveMetrics = (nextMetrics: PlatformLiveMetrics) => {
      startLiveMetricsTransition(() => {
        setLiveMetrics(nextMetrics);
        setLiveMetricHistory((current) => {
          const nextPoint = toLiveMetricHistoryPoint(nextMetrics);
          const deduped = current[current.length - 1]?.sampledAt === nextPoint.sampledAt ? current.slice(0, -1) : current;
          return [...deduped, nextPoint].slice(-LIVE_METRICS_HISTORY_LIMIT);
        });
        setLiveMetricsError(null);
      });
    };

    const failLiveMetrics = (message: string) => {
      startLiveMetricsTransition(() => {
        setLiveMetricsError(message);
      });
    };

    async function refreshLiveMetrics() {
      try {
        const nextMetrics = await getPlatformLiveMetrics();
        if (disposed) {
          return;
        }
        applyLiveMetrics(nextMetrics);
      } catch (err) {
        if (disposed) {
          return;
        }
        failLiveMetrics((err as Error).message);
      }
    }

    const handleVisibilityRefresh = () => {
      if (!document.hidden) {
        void refreshLiveMetrics();
      }
    };

    void refreshLiveMetrics();
    const intervalId = window.setInterval(() => {
      void refreshLiveMetrics();
    }, LIVE_METRICS_POLL_INTERVAL_MS);

    document.addEventListener("visibilitychange", handleVisibilityRefresh);
    window.addEventListener("focus", handleVisibilityRefresh);

    return () => {
      disposed = true;
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityRefresh);
      window.removeEventListener("focus", handleVisibilityRefresh);
    };
  }, [startLiveMetricsTransition]);

  const metrics = useMemo(() => {
    const onlineAssets = assets.filter((asset) => asset.status === "online").length;
    const allFindings = Object.values(riskMap).flat();
    const highRisk = overview?.high_risk_findings ?? allFindings.filter((finding) => ["high", "critical"].includes(finding.severity)).length;
    const activeTasks = overview?.active_tasks ?? tasks.filter((task) => ["pending", "running", "retry"].includes(task.status)).length;
    const severityTotals = {
      critical: allFindings.filter((finding) => finding.severity === "critical").length,
      high: allFindings.filter((finding) => finding.severity === "high").length,
      medium: allFindings.filter((finding) => finding.severity === "medium").length,
      low: allFindings.filter((finding) => finding.severity === "low").length,
    };
    const riskyAssets = assets
      .map((asset) => {
        const findings = riskMap[asset.id] || [];
        const highest = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))[0]?.severity || null;
        return {
          id: asset.id,
          ip: asset.ip,
          hostname: asset.hostname,
          findingCount: findings.length,
          highest,
        };
      })
      .filter((item) => item.findingCount > 0)
      .sort((a, b) => severityRank(b.highest) - severityRank(a.highest) || b.findingCount - a.findingCount)
      .slice(0, 5);
    const taskHealth = tasks.slice(0, 8).map((task) => ({
      id: task.id,
      label: getTaskTypeLabel(task.task_type),
      status: task.status,
      progress: task.progress,
      detail: localizeTaskMessage(task.message) || task.scope_id || "无附加信息",
    }));
    const coverageRate = assets.length ? Math.round((onlineAssets / assets.length) * 100) : 0;

    return {
      onlineAssets,
      highRisk,
      activeTasks,
      riskyAssets,
      totalFindings: allFindings.length,
      severityTotals,
      taskHealth,
      coverageRate,
    };
  }, [assets, overview, riskMap, tasks]);

  const liveTrendData = useMemo(() => {
    const cpuSeries = liveMetricHistory.map((item) => item.cpuUsage);
    const memorySeries = liveMetricHistory.map((item) => item.memoryUsage);
    const diskSeries = liveMetricHistory.map((item) => item.diskUsage);
    const networkSeries = liveMetricHistory.map((item) => item.networkRate);

    return {
      cpuSeries,
      memorySeries,
      diskSeries,
      networkSeries,
      networkPeak: Math.max(...networkSeries, 1),
    };
  }, [liveMetricHistory]);

  if (loading) {
    return <Skeleton active paragraph={{ rows: 12 }} />;
  }

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      {error ? <Alert type="error" showIcon message={error} /> : null}

      <Row gutter={[14, 14]} className="dashboard-grid-row">
        <Col xs={24} lg={11}>
          <Card
            className="panel-card dashboard-panel-card"
            title="平台实时监控"
            extra={
              <Space size={10} wrap>
                <span className={`live-monitoring-chip${liveMetricsError ? " is-stale" : ""}`}>
                  <span className="live-monitoring-chip-dot" />
                  {liveMetricsError ? "刷新中断" : "实时监控中"}
                </span>
                <Typography.Text type="secondary">
                  {liveMetrics
                    ? `${formatDateTime(liveMetrics.sampled_at)} · ${liveMetrics.sample_window_seconds.toFixed(1)}s 窗口`
                    : "正在采样"}
                </Typography.Text>
              </Space>
            }
          >
            {liveMetrics ? (
              <Space direction="vertical" size={14} style={{ width: "100%" }}>
                <div className="platform-trends-grid">
                  <LiveTrendCard
                    label="CPU"
                    color="#38bdf8"
                    value={`${liveMetrics.cpu.usage_percent.toFixed(1)}%`}
                    detail={`${liveMetrics.cpu.logical_cores || "-"} 核 · 1 分钟负载 ${liveMetrics.cpu.load_avg_1m ?? "-"}`}
                    series={liveTrendData.cpuSeries}
                    scaleLabel={`峰值 ${Math.max(...liveTrendData.cpuSeries, 0).toFixed(0)}%`}
                    maxValue={100}
                  />
                  <LiveTrendCard
                    label="内存"
                    color="#f59e0b"
                    value={`${liveMetrics.memory.usage_percent.toFixed(1)}%`}
                    detail={`已用 ${formatBytes(liveMetrics.memory.used_bytes)} / 总量 ${formatBytes(liveMetrics.memory.total_bytes)}`}
                    series={liveTrendData.memorySeries}
                    scaleLabel={`峰值 ${Math.max(...liveTrendData.memorySeries, 0).toFixed(0)}%`}
                    maxValue={100}
                  />
                  <LiveTrendCard
                    label="磁盘"
                    color="#f87171"
                    value={`${liveMetrics.disk.usage_percent.toFixed(1)}%`}
                    detail={`${liveMetrics.disk.mount_path} · 已用 ${formatBytes(liveMetrics.disk.used_bytes)}`}
                    series={liveTrendData.diskSeries}
                    scaleLabel={`峰值 ${Math.max(...liveTrendData.diskSeries, 0).toFixed(0)}%`}
                    maxValue={100}
                  />
                  <LiveTrendCard
                    label="网络"
                    color="#22c55e"
                    value={formatRate(liveMetrics.network.total_bytes_per_sec)}
                    detail={`接收 ${formatRate(liveMetrics.network.received_bytes_per_sec)} · 发送 ${formatRate(liveMetrics.network.transmitted_bytes_per_sec)}`}
                    series={liveTrendData.networkSeries}
                    scaleLabel={`峰值 ${formatRate(liveTrendData.networkPeak)}`}
                  />
                </div>
                <div className="live-monitoring-footer">
                  <Typography.Text type="secondary">
                    最近 {liveMetricHistory.length || 1} 个样本，按 {LIVE_METRICS_POLL_INTERVAL_MS / 1000} 秒频率刷新。
                  </Typography.Text>
                  <Typography.Text type="secondary">最新采样时间 {formatDateTime(liveMetrics.sampled_at)}</Typography.Text>
                </div>
                {liveMetricsError ? (
                  <Alert
                    showIcon
                    type="warning"
                    message={`实时刷新暂时中断，当前展示最近一次样本：${liveMetricsError}`}
                  />
                ) : null}
              </Space>
            ) : (
              <Alert
                showIcon
                type={liveMetricsError ? "warning" : "info"}
                message={liveMetricsError || "正在建立平台实时监控流，请稍候。"}
              />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={13}>
          <Card
            className="panel-card dashboard-panel-card"
            title="发现队列与最新风险"
          >
            {overview ? (
              <Space direction="vertical" size={14} style={{ width: "100%" }}>
                <div className="dashboard-threat-band">
                  <div className="dashboard-threat-column">
                    <span>待执行发现</span>
                    <strong>{overview.discovery_entry.pending_jobs}</strong>
                  </div>
                  <div className="dashboard-threat-column">
                    <span>执行中发现</span>
                    <strong>{overview.discovery_entry.running_jobs}</strong>
                  </div>
                  <div className="dashboard-threat-column">
                    <span>活跃任务</span>
                    <strong>{overview.active_tasks}</strong>
                  </div>
                  <div className="dashboard-threat-column">
                    <span>全局高危</span>
                    <strong>{overview.high_risk_findings}</strong>
                  </div>
                </div>
                {overview.recent_risks.length ? (
                  <List
                    className="console-list"
                    dataSource={overview.recent_risks}
                    renderItem={(item) => (
                      <List.Item className="console-list-item">
                        <Space direction="vertical" style={{ width: "100%" }} size={6}>
                          <Space style={{ justifyContent: "space-between", width: "100%" }} align="start">
                            <Space direction="vertical" size={2}>
                              <Typography.Text strong className="mono-text">
                                {item.asset_ip || item.asset_id}
                              </Typography.Text>
                              <Typography.Text>{item.title}</Typography.Text>
                            </Space>
                            <StatusTag value={item.severity} />
                          </Space>
                          <Typography.Text type="secondary">{item.asset_hostname || "未识别主机名"}</Typography.Text>
                          <div className="console-keyline">
                            <span>发现时间</span>
                            <strong>{formatDateTime(item.detected_at)}</strong>
                          </div>
                        </Space>
                      </List.Item>
                    )}
                  />
                ) : (
                  <Empty description="暂无全局风险记录" />
                )}
              </Space>
            ) : (
              <Alert showIcon type="info" message="当前未读取到发现队列或风险汇总数据。" />
            )}
          </Card>
        </Col>
      </Row>

      <Row gutter={[14, 14]} className="dashboard-grid-row">
        <Col xs={24} lg={15}>
          <Card className="panel-card dashboard-panel-card" title="风险热点资产" extra={<Typography.Text type="secondary">按最高风险和命中数排序</Typography.Text>}>
            {metrics.riskyAssets.length ? (
              <List
                className="console-list"
                dataSource={metrics.riskyAssets}
                renderItem={(item) => (
                  <List.Item className="console-list-item">
                    <Space direction="vertical" style={{ width: "100%" }} size={8}>
                      <Space style={{ justifyContent: "space-between", width: "100%" }} align="start">
                        <Space direction="vertical" size={2}>
                          <Typography.Text strong className="mono-text">
                            {item.ip}
                          </Typography.Text>
                          <Typography.Text type="secondary">{item.hostname || "未识别主机名"}</Typography.Text>
                        </Space>
                        <StatusTag value={item.highest} />
                      </Space>
                      <div className="console-keyline">
                        <span>风险命中</span>
                        <strong>{item.findingCount} 条</strong>
                      </div>
                      <Progress percent={Math.min(item.findingCount * 20, 100)} showInfo={false} strokeColor="#dc2626" trailColor="rgba(59, 130, 246, 0.08)" />
                    </Space>
                  </List.Item>
                )}
              />
            ) : (
              <Empty description="暂无风险数据" />
            )}
          </Card>
        </Col>
        <Col xs={24} lg={9}>
          <Card className="panel-card dashboard-panel-card" title="风险态势与任务波形">
            <Space direction="vertical" size={18} style={{ width: "100%" }}>
              <div className="dashboard-threat-band">
                <div className="dashboard-threat-column">
                  <span>严重</span>
                  <strong>{metrics.severityTotals.critical}</strong>
                </div>
                <div className="dashboard-threat-column">
                  <span>高危</span>
                  <strong>{metrics.severityTotals.high}</strong>
                </div>
                <div className="dashboard-threat-column">
                  <span>中危</span>
                  <strong>{metrics.severityTotals.medium}</strong>
                </div>
                <div className="dashboard-threat-column">
                  <span>低危</span>
                  <strong>{metrics.severityTotals.low}</strong>
                </div>
              </div>
              {tasks.length ? (
                <List
                  className="console-list"
                  dataSource={metrics.taskHealth}
                  renderItem={(task) => (
                    <List.Item className="console-list-item">
                      <Space direction="vertical" style={{ width: "100%" }} size={6}>
                        <Space style={{ justifyContent: "space-between", width: "100%" }}>
                          <Typography.Text>{task.label}</Typography.Text>
                          <StatusTag value={task.status} />
                        </Space>
                        <Typography.Text type="secondary">{task.detail}</Typography.Text>
                        <Progress percent={task.progress} size="small" trailColor="rgba(59, 130, 246, 0.08)" />
                      </Space>
                    </List.Item>
                  )}
                />
              ) : (
                <Empty description="暂无任务记录" />
              )}
            </Space>
          </Card>
        </Col>
      </Row>
    </Space>
  );
}
