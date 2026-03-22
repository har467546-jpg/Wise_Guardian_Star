import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../core/theme/app_theme.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final overviewProvider = FutureProvider((ref) async {
  return ref.watch(apiClientProvider).fetchOverview();
});

class DashboardPage extends ConsumerWidget {
  const DashboardPage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final overview = ref.watch(overviewProvider);
    final role = ref.watch(sessionControllerProvider).valueOrNull?.role;

    return ScreenScaffold(
      title: '总览',
      contentBottomPadding: 136,
      maxContentWidth: 1120,
      child: AsyncStateView(
        loading: overview.isLoading,
        error: overview.error,
        onRetry: () => ref.invalidate(overviewProvider),
        child: overview.when(
          data: (data) => _OverviewContent(
            data: data,
            showRemediationEntry: role == AppRole.admin,
          ),
          loading: () => const SizedBox.shrink(),
          error: (_, __) => const SizedBox.shrink(),
        ),
      ),
    );
  }
}

class _OverviewContent extends StatelessWidget {
  const _OverviewContent({
    required this.data,
    required this.showRemediationEntry,
  });

  final OverviewSummary data;
  final bool showRemediationEntry;

  @override
  Widget build(BuildContext context) {
    final layout =
        AdaptiveLayoutInfo.fromWidth(MediaQuery.sizeOf(context).width);
    final metrics = [
      _OverviewMetricData(
        id: 'total',
        label: '资产总量',
        compactLabel: '总量',
        value: '${data.assetTotal}',
        tone: StatusTone.info,
        icon: Icons.hub_rounded,
      ),
      _OverviewMetricData(
        id: 'online',
        label: '在线覆盖',
        compactLabel: '在线',
        value: '${data.onlineAssets}',
        tone: StatusTone.success,
        icon: Icons.wifi_tethering_rounded,
      ),
      _OverviewMetricData(
        id: 'high-risk',
        label: '高危风险',
        compactLabel: '高危',
        value: '${data.highRiskFindings}',
        tone: StatusTone.danger,
        icon: Icons.priority_high_rounded,
      ),
      _OverviewMetricData(
        id: 'active-tasks',
        label: '活跃任务',
        compactLabel: '任务',
        value: '${data.activeTasks}',
        tone: StatusTone.warning,
        icon: Icons.bolt_rounded,
      ),
    ];
    final hasPulseData = data.assetTotal > 0 ||
        data.onlineAssets > 0 ||
        data.highRiskFindings > 0 ||
        data.activeTasks > 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        _OverviewHeroCard(
          layout: layout,
          metrics: metrics,
          onDiscoveryTap: () => context.push('/discovery'),
        ),
        const SizedBox(height: 18),
        _OverviewPulsePanel(
          data: data,
          hasPulseData: hasPulseData,
        ),
        const SizedBox(height: 18),
        SectionHeading(
          title: '快捷入口',
          subtitle: '高频入口收成一屏，适合值班时快速跳转。',
          action: TextButton.icon(
            onPressed: () => context.push('/discovery'),
            icon: const Icon(Icons.arrow_outward_rounded, size: 18),
            label: const Text('进入发现'),
          ),
        ),
        const SizedBox(height: 12),
        AdaptiveGrid(
          compactColumns: 2,
          mediumColumns: 2,
          expandedColumns: 4,
          minChildWidth: 168,
          spacing: 14,
          children: [
            _QuickActionCard(
              title: '在线资产',
              message: '优先查看在线节点与详情',
              icon: Icons.dns_rounded,
              onTap: () => context.go('/assets?status=online'),
            ),
            _QuickActionCard(
              title: '活跃任务',
              message: '筛出执行中与待处理任务',
              icon: Icons.assignment_turned_in_rounded,
              onTap: () => context.go('/tasks?status=running'),
            ),
            _QuickActionCard(
              title: '高危风险',
              message: '聚焦高危与严重问题',
              icon: Icons.gpp_bad_rounded,
              onTap: () => context.go('/risks?severity=high'),
            ),
            _QuickActionCard(
              title: '发现任务',
              message: '新建 CIDR 扫描并跟进状态',
              icon: Icons.travel_explore_rounded,
              onTap: () => context.push('/discovery'),
            ),
            if (showRemediationEntry)
              _QuickActionCard(
                title: '修复工作台',
                message: '查看阶段推进、阻塞和当前输出',
                icon: Icons.build_circle_rounded,
                onTap: () => context.push('/remediation'),
              ),
          ],
        ),
        const SizedBox(height: 18),
        const SectionHeading(title: '最近任务'),
        const SizedBox(height: 12),
        if (data.recentTasks.isEmpty)
          const AppEmptyState(title: '暂无任务', message: '当前没有最近任务记录。')
        else
          ...data.recentTasks.map(
            (task) => Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: GlassPanel(
                child: ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(task.taskType.label),
                  subtitle: Text(task.message ?? task.scopeId ?? '无附加说明'),
                  trailing: StatusBadge(
                      label: task.status.label,
                      tone: toneForTaskStatus(task.status.name)),
                  onTap: () => context.push('/tasks/${task.id}'),
                ),
              ),
            ),
          ),
        const SizedBox(height: 6),
        const SectionHeading(title: '最近风险'),
        const SizedBox(height: 12),
        if (data.recentRisks.isEmpty)
          const AppEmptyState(title: '暂无风险', message: '当前没有已发现的近期风险。')
        else
          ...data.recentRisks.map(
            (risk) => Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: GlassPanel(
                child: ListTile(
                  contentPadding: EdgeInsets.zero,
                  title: Text(risk.title),
                  subtitle: Text(
                      '${risk.assetIp} · ${risk.assetHostname ?? '未识别主机名'}'),
                  trailing: StatusBadge(
                      label: risk.severity.label,
                      tone: toneForRiskSeverity(risk.severity.name)),
                  onTap: () => context.push('/risks/${risk.id}', extra: risk),
                ),
              ),
            ),
          ),
      ],
    );
  }
}

class _OverviewMetricData {
  const _OverviewMetricData({
    required this.id,
    required this.label,
    required this.compactLabel,
    required this.value,
    required this.tone,
    required this.icon,
  });

  final String id;
  final String label;
  final String compactLabel;
  final String value;
  final StatusTone tone;
  final IconData icon;
}

class _OverviewHeroCard extends StatelessWidget {
  const _OverviewHeroCard({
    required this.layout,
    required this.metrics,
    required this.onDiscoveryTap,
  });

  final AdaptiveLayoutInfo layout;
  final List<_OverviewMetricData> metrics;
  final VoidCallback onDiscoveryTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final compact = layout.isCompact;

    final metricSection = compact
        ? _CompactOverviewMetricsRow(metrics: metrics)
        : AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 4,
            minChildWidth: 160,
            spacing: 12,
            children: [
              for (final metric in metrics)
                MetricCard(
                  label: metric.label,
                  value: metric.value,
                  tone: metric.tone,
                  trailing: _MetricGlyph(icon: metric.icon, tone: metric.tone),
                  minHeight: 124,
                ),
            ],
          );

    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            palette.accentSurface.withValues(alpha: 0.96),
            theme.colorScheme.primary.withValues(alpha: 0.16),
            Colors.white.withValues(
              alpha: theme.brightness == Brightness.dark ? 0.02 : 0.62,
            ),
          ],
        ),
        borderRadius: BorderRadius.circular(compact ? 30 : 34),
        border: Border.all(
          color: theme.colorScheme.primary.withValues(alpha: 0.10),
        ),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.primary.withValues(alpha: 0.12),
            blurRadius: 30,
            offset: const Offset(0, 14),
          ),
        ],
      ),
      child: Padding(
        padding: EdgeInsets.fromLTRB(
          compact ? 16 : 20,
          compact ? 16 : 20,
          compact ? 16 : 20,
          compact ? 16 : 20,
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '今日态势',
                        style: theme.textTheme.labelLarge?.copyWith(
                          color: theme.colorScheme.primary,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 0.3,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        '围绕资产、风险与任务快速确认当前状态',
                        style: theme.textTheme.headlineSmall?.copyWith(
                          fontWeight: FontWeight.w800,
                          height: 1.12,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        '把高频摘要、发现入口和后续处理路径压进一屏，适合值班巡检和现场确认。',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: palette.textSecondary,
                        ),
                      ),
                    ],
                  ),
                ),
                if (!compact)
                  FilledButton.tonalIcon(
                    onPressed: onDiscoveryTap,
                    icon: const Icon(Icons.travel_explore_rounded, size: 18),
                    label: const Text('进入发现'),
                  ),
              ],
            ),
            const SizedBox(height: 16),
            metricSection,
            if (compact) ...[
              const SizedBox(height: 14),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: onDiscoveryTap,
                  style: FilledButton.styleFrom(
                    backgroundColor: theme.colorScheme.primary,
                    foregroundColor: Colors.white,
                  ),
                  icon: const Icon(Icons.add_rounded, size: 18),
                  label: const Text('进入发现任务'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _CompactOverviewMetricsRow extends StatelessWidget {
  const _CompactOverviewMetricsRow({required this.metrics});

  final List<_OverviewMetricData> metrics;

  @override
  Widget build(BuildContext context) {
    return Row(
      key: const ValueKey('compact-overview-metrics-row'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (var index = 0; index < metrics.length; index++) ...[
          if (index > 0) const SizedBox(width: 8),
          Expanded(
            child: _CompactOverviewMetricCard(metric: metrics[index]),
          ),
        ],
      ],
    );
  }
}

class _CompactOverviewMetricCard extends StatelessWidget {
  const _CompactOverviewMetricCard({required this.metric});

  final _OverviewMetricData metric;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final color = _metricToneColor(context, metric.tone);

    return SizedBox(
      key: ValueKey('compact-overview-metric-${metric.id}'),
      height: 96,
      child: GlassPanel(
        padding: const EdgeInsets.fromLTRB(10, 10, 10, 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Spacer(),
                DecoratedBox(
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Padding(
                    padding: const EdgeInsets.all(5),
                    child: Icon(metric.icon, size: 14, color: color),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              metric.compactLabel,
              key: ValueKey('compact-overview-metric-label-${metric.id}'),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.labelSmall?.copyWith(
                color: palette.textSecondary.withValues(alpha: 0.96),
                fontWeight: FontWeight.w800,
                fontSize: 11,
                letterSpacing: 0.2,
              ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: Align(
                alignment: Alignment.bottomLeft,
                child: FittedBox(
                  fit: BoxFit.scaleDown,
                  alignment: Alignment.centerLeft,
                  child: Text(
                    metric.value,
                    maxLines: 1,
                    style: theme.textTheme.titleLarge?.copyWith(
                      color: color,
                      fontWeight: FontWeight.w800,
                      fontSize: 26,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _OverviewPulsePanel extends StatelessWidget {
  const _OverviewPulsePanel({
    required this.data,
    required this.hasPulseData,
  });

  final OverviewSummary data;
  final bool hasPulseData;

  @override
  Widget build(BuildContext context) {
    final values = [
      data.assetTotal,
      data.onlineAssets,
      data.highRiskFindings,
      data.activeTasks
    ];
    final colors = [
      _metricToneColor(context, StatusTone.info),
      _metricToneColor(context, StatusTone.success),
      _metricToneColor(context, StatusTone.danger),
      _metricToneColor(context, StatusTone.warning),
    ];
    final labels = ['资产', '在线', '高危', '任务'];
    final layout =
        AdaptiveLayoutInfo.fromWidth(MediaQuery.sizeOf(context).width);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '运营脉冲',
            subtitle: '把总量、风险与任务压成一个更紧凑的移动端快照。',
          ),
          const SizedBox(height: 14),
          if (!hasPulseData)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 22),
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .primary
                    .withValues(alpha: 0.06),
                borderRadius: BorderRadius.circular(24),
              ),
              child: Column(
                children: [
                  Icon(
                    Icons.insights_rounded,
                    size: 30,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    '暂无运营脉冲数据',
                    style: Theme.of(context).textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w800,
                        ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    '当前资产、风险和任务都还没有形成可视化样本，先从发现任务或资产采集开始。',
                    textAlign: TextAlign.center,
                    style: Theme.of(context).textTheme.bodySmall,
                  ),
                ],
              ),
            )
          else ...[
            SizedBox(
              height: layout.isCompact ? 156 : 176,
              child: BarChart(
                BarChartData(
                  alignment: BarChartAlignment.spaceAround,
                  maxY:
                      (values.reduce((a, b) => a > b ? a : b).clamp(1, 999999) *
                              1.25)
                          .toDouble(),
                  gridData: FlGridData(
                    show: true,
                    drawVerticalLine: false,
                    horizontalInterval: 1,
                    getDrawingHorizontalLine: (value) => FlLine(
                      color: Theme.of(context)
                          .dividerColor
                          .withValues(alpha: 0.06),
                      strokeWidth: 1,
                    ),
                  ),
                  borderData: FlBorderData(show: false),
                  barTouchData: BarTouchData(enabled: false),
                  titlesData: FlTitlesData(
                    topTitles: const AxisTitles(
                        sideTitles: SideTitles(showTitles: false)),
                    rightTitles: const AxisTitles(
                        sideTitles: SideTitles(showTitles: false)),
                    leftTitles: const AxisTitles(
                        sideTitles: SideTitles(showTitles: false)),
                    bottomTitles: AxisTitles(
                      sideTitles: SideTitles(
                        showTitles: true,
                        getTitlesWidget: (value, meta) {
                          return Padding(
                            padding: const EdgeInsets.only(top: 8),
                            child: Text(
                              labels[value.toInt()],
                              style: Theme.of(context)
                                  .textTheme
                                  .labelMedium
                                  ?.copyWith(
                                    fontWeight: FontWeight.w700,
                                  ),
                            ),
                          );
                        },
                      ),
                    ),
                  ),
                  barGroups: [
                    for (var index = 0; index < values.length; index++)
                      _pulseBar(
                        x: index,
                        value: values[index],
                        color: colors[index],
                        compact: layout.isCompact,
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                for (var index = 0; index < labels.length; index++)
                  _PulseLegendChip(
                    label: labels[index],
                    value: '${values[index]}',
                    color: colors[index],
                  ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  BarChartGroupData _pulseBar({
    required int x,
    required int value,
    required Color color,
    required bool compact,
  }) {
    return BarChartGroupData(
      x: x,
      barRods: [
        BarChartRodData(
          toY: value.toDouble(),
          width: compact ? 18 : 22,
          borderRadius: BorderRadius.circular(10),
          color: color,
          backDrawRodData: BackgroundBarChartRodData(
            show: true,
            toY: value <= 0 ? 0.8 : value.toDouble(),
            color: color.withValues(alpha: 0.10),
          ),
        ),
      ],
    );
  }
}

class _PulseLegendChip extends StatelessWidget {
  const _PulseLegendChip({
    required this.label,
    required this.value,
    required this.color,
  });

  final String label;
  final String value;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(999),
            ),
          ),
          const SizedBox(width: 8),
          Text(
            '$label $value',
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
                  color: color,
                  fontWeight: FontWeight.w700,
                ),
          ),
        ],
      ),
    );
  }
}

class _QuickActionCard extends StatelessWidget {
  const _QuickActionCard({
    required this.title,
    required this.message,
    required this.icon,
    required this.onTap,
  });

  final String title;
  final String message;
  final IconData icon;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;

    return GlassPanel(
      padding: EdgeInsets.zero,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: Row(
                children: [
                  Container(
                    width: 42,
                    height: 42,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          theme.colorScheme.primary,
                          palette.info,
                        ],
                      ),
                      borderRadius: BorderRadius.circular(14),
                    ),
                    child: Icon(icon, color: Colors.white, size: 20),
                  ),
                  const Spacer(),
                  Icon(
                    Icons.arrow_outward_rounded,
                    color: palette.textSecondary,
                    size: 18,
                  ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 18, 16, 16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: theme.textTheme.titleMedium?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    message,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.bodySmall,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _MetricGlyph extends StatelessWidget {
  const _MetricGlyph({
    required this.icon,
    required this.tone,
  });

  final IconData icon;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final color = _metricToneColor(context, tone);

    return DecoratedBox(
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Padding(
        padding: const EdgeInsets.all(10),
        child: Icon(icon, size: 18, color: color),
      ),
    );
  }
}

Color _metricToneColor(BuildContext context, StatusTone tone) {
  final palette = Theme.of(context).extension<AppThemePalette>()!;
  return switch (tone) {
    StatusTone.info => palette.info,
    StatusTone.success => palette.success,
    StatusTone.warning => palette.warning,
    StatusTone.danger => palette.danger,
    StatusTone.neutral => Theme.of(context).colorScheme.primary,
  };
}
