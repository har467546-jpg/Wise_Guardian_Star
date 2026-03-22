import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/network/api_client.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final riskListProvider = FutureProvider.autoDispose.family<
    RiskListPayload,
    ({
      RiskSeverityLevel? severity,
      RiskStatusType? status,
      String keyword
    })>((ref, query) async {
  return ref.watch(apiClientProvider).listRisks(
        severity: query.severity,
        status: query.status,
        keyword: query.keyword,
      );
});

final riskDetailProvider =
    FutureProvider.autoDispose.family<RiskItem, String>((ref, riskId) async {
  return ref.watch(apiClientProvider).fetchRisk(riskId);
});

class RisksPage extends ConsumerStatefulWidget {
  const RisksPage({
    super.key,
    this.initialSeverity,
    this.initialStatus,
  });

  final String? initialSeverity;
  final String? initialStatus;

  @override
  ConsumerState<RisksPage> createState() => _RisksPageState();
}

class _RisksPageState extends ConsumerState<RisksPage> {
  late final TextEditingController _keywordController;
  RiskSeverityLevel? _severity;
  RiskStatusType? _status;

  @override
  void initState() {
    super.initState();
    _keywordController = TextEditingController();
    _severity = _parseSeverity(widget.initialSeverity);
    _status = _parseRiskStatus(widget.initialStatus);
  }

  @override
  void dispose() {
    _keywordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final query = (
      severity: _severity,
      status: _status,
      keyword: _keywordController.text
    );
    final risks = ref.watch(riskListProvider(query));

    return ScreenScaffold(
      title: '风险',
      subtitle: '保留全局风险分页、严重级别与状态筛选，不承载桌面端规则治理。',
      maxContentWidth: 1120,
      child: AdaptivePane(
        leading: _RiskFiltersPanel(
          keywordController: _keywordController,
          severity: _severity,
          status: _status,
          onSeverityChanged: (value) => setState(() => _severity = value),
          onStatusChanged: (value) => setState(() => _status = value),
          onApply: () => setState(() {}),
        ),
        trailing: AsyncStateView(
          loading: risks.isLoading,
          error: risks.error,
          onRetry: () => ref.invalidate(riskListProvider(query)),
          child: risks.when(
            data: (data) {
              if (data.items.isEmpty) {
                return const AppEmptyState(
                    title: '暂无风险', message: '当前没有命中筛选条件的风险。');
              }
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _RiskListSummaryCard(
                    data: data,
                    severity: _severity,
                    status: _status,
                    keyword: _keywordController.text.trim(),
                  ),
                  const SizedBox(height: 12),
                  ListView.separated(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: data.items.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 12),
                    itemBuilder: (context, index) {
                      final risk = data.items[index];
                      return _RiskListCard(
                        risk: risk,
                        onTap: () =>
                            context.push('/risks/${risk.id}', extra: risk),
                      );
                    },
                  ),
                ],
              );
            },
            loading: () => const SizedBox.shrink(),
            error: (_, __) => const SizedBox.shrink(),
          ),
        ),
      ),
    );
  }
}

class RiskDetailPage extends ConsumerStatefulWidget {
  const RiskDetailPage({
    super.key,
    required this.riskId,
    required this.risk,
  });

  final String riskId;
  final RiskItem? risk;

  @override
  ConsumerState<RiskDetailPage> createState() => _RiskDetailPageState();
}

class _RiskDetailPageState extends ConsumerState<RiskDetailPage> {
  void _retry() {
    ref.invalidate(riskDetailProvider(widget.riskId));
  }

  @override
  Widget build(BuildContext context) {
    final riskAsync = ref.watch(riskDetailProvider(widget.riskId));
    final latestRisk = riskAsync.valueOrNull;
    final showingSnapshot = widget.risk != null && latestRisk == null;
    final displayRisk = latestRisk ?? widget.risk;

    return ScreenScaffold(
      title: '风险详情',
      subtitle: widget.riskId,
      maxContentWidth: 1120,
      child: displayRisk == null
          ? _RiskDetailUnavailable(
              isLoading: riskAsync.isLoading,
              onRetry: _retry,
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (showingSnapshot && riskAsync.isLoading)
                  const Padding(
                    padding: EdgeInsets.only(bottom: 14),
                    child: _RiskDetailNotice(
                      icon: Icons.sync_rounded,
                      message: '已显示进入页时的快照，正在刷新最新详情。',
                      loading: true,
                    ),
                  ),
                if (showingSnapshot && riskAsync.hasError)
                  Padding(
                    padding: const EdgeInsets.only(bottom: 14),
                    child: _RiskDetailNotice(
                      icon: Icons.info_outline_rounded,
                      message: '当前展示的是进入页时的快照，最新数据加载失败。',
                      action: TextButton(
                        onPressed: _retry,
                        child: const Text('重试'),
                      ),
                    ),
                  ),
                _RiskDetailContent(risk: displayRisk),
              ],
            ),
    );
  }
}

class _RiskDetailContent extends StatelessWidget {
  const _RiskDetailContent({required this.risk});

  final RiskItem risk;

  @override
  Widget build(BuildContext context) {
    return AdaptivePane(
      breakpoint: 880,
      leadingWidth: 360,
      leading: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _RiskDetailHeroCard(risk: risk),
          const SizedBox(height: 14),
          FilledButton.icon(
            onPressed: () => context.push('/assets/${risk.assetId}'),
            icon: const Icon(Icons.dns_rounded),
            label: const Text('查看所属资产'),
          ),
        ],
      ),
      trailing: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          JsonPreviewCard(
            title: '证据详情',
            subtitle: '结构化证据用于复核命中依据和定位具体服务。',
            data: risk.evidenceJson,
            emptyMessage: '当前没有结构化证据字段。',
          ),
          const SizedBox(height: 12),
          GlassPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const SectionHeading(
                  title: '处置视角',
                  subtitle: '先确认风险等级、状态和资产归属，再决定是否回桌面端做进一步治理。',
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    AppInfoChip(
                      label: risk.severity.label,
                      icon: _riskSeverityIcon(risk.severity),
                      tone: toneForRiskSeverity(risk.severity.name),
                    ),
                    AppInfoChip(
                      label: risk.status.label,
                      icon: Icons.flag_rounded,
                      tone: toneForRiskStatus(risk.status.name),
                    ),
                    AppInfoChip(
                      label: risk.assetIp,
                      icon: Icons.lan_rounded,
                    ),
                    if (risk.assetPortId != null &&
                        risk.assetPortId!.isNotEmpty)
                      AppInfoChip(
                        label: risk.assetPortId!,
                        icon: Icons.usb_rounded,
                      ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RiskDetailUnavailable extends StatelessWidget {
  const _RiskDetailUnavailable({
    required this.isLoading,
    required this.onRetry,
  });

  final bool isLoading;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    if (isLoading) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.symmetric(vertical: 48),
          child: CircularProgressIndicator(),
        ),
      );
    }

    return AppEmptyState(
      title: '风险不可用',
      message: '风险不存在或当前不可用。',
      action: FilledButton(
        onPressed: onRetry,
        child: const Text('重新加载'),
      ),
    );
  }
}

class _RiskDetailNotice extends StatelessWidget {
  const _RiskDetailNotice({
    required this.icon,
    required this.message,
    this.loading = false,
    this.action,
  });

  final IconData icon;
  final String message;
  final bool loading;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final color = theme.colorScheme.primary;

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: color.withValues(alpha: 0.14)),
      ),
      child: Row(
        children: [
          if (loading)
            SizedBox(
              width: 18,
              height: 18,
              child: CircularProgressIndicator(
                strokeWidth: 2,
                valueColor: AlwaysStoppedAnimation<Color>(color),
              ),
            )
          else
            Icon(icon, size: 18, color: color),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurface,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          if (action != null) action!,
        ],
      ),
    );
  }
}

RiskSeverityLevel? _parseSeverity(String? raw) {
  return switch (raw) {
    'critical' => RiskSeverityLevel.critical,
    'high' => RiskSeverityLevel.high,
    'medium' => RiskSeverityLevel.medium,
    'low' => RiskSeverityLevel.low,
    _ => null,
  };
}

class _RiskFiltersPanel extends StatelessWidget {
  const _RiskFiltersPanel({
    required this.keywordController,
    required this.severity,
    required this.status,
    required this.onSeverityChanged,
    required this.onStatusChanged,
    required this.onApply,
  });

  final TextEditingController keywordController;
  final RiskSeverityLevel? severity;
  final RiskStatusType? status;
  final ValueChanged<RiskSeverityLevel?> onSeverityChanged;
  final ValueChanged<RiskStatusType?> onStatusChanged;
  final VoidCallback onApply;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '筛选条件',
            subtitle: '按关键词、级别与状态收敛风险视图，优先锁定高危待处理项。',
          ),
          const SizedBox(height: 12),
          const Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(label: '关键词', icon: Icons.search_rounded),
              AppInfoChip(label: '严重级别', icon: Icons.priority_high_rounded),
              AppInfoChip(label: '处理状态', icon: Icons.flag_rounded),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            controller: keywordController,
            decoration: const InputDecoration(labelText: '标题 / 资产 IP / 描述关键词'),
            onSubmitted: (_) => onApply(),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<RiskSeverityLevel?>(
            initialValue: severity,
            decoration: const InputDecoration(labelText: '严重级别'),
            items: const [
              DropdownMenuItem(value: null, child: Text('全部级别')),
              DropdownMenuItem(
                  value: RiskSeverityLevel.critical, child: Text('严重')),
              DropdownMenuItem(
                  value: RiskSeverityLevel.high, child: Text('高危')),
              DropdownMenuItem(
                  value: RiskSeverityLevel.medium, child: Text('中危')),
              DropdownMenuItem(value: RiskSeverityLevel.low, child: Text('低危')),
            ],
            onChanged: onSeverityChanged,
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<RiskStatusType?>(
            initialValue: status,
            decoration: const InputDecoration(labelText: '风险状态'),
            items: const [
              DropdownMenuItem(value: null, child: Text('全部状态')),
              DropdownMenuItem(value: RiskStatusType.open, child: Text('待处理')),
              DropdownMenuItem(
                  value: RiskStatusType.ignored, child: Text('已忽略')),
              DropdownMenuItem(value: RiskStatusType.fixed, child: Text('已修复')),
            ],
            onChanged: onStatusChanged,
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: FilledButton(
              onPressed: onApply,
              child: const Text('刷新风险'),
            ),
          ),
        ],
      ),
    );
  }
}

RiskStatusType? _parseRiskStatus(String? raw) {
  return switch (raw) {
    'open' => RiskStatusType.open,
    'ignored' => RiskStatusType.ignored,
    'fixed' => RiskStatusType.fixed,
    _ => null,
  };
}

class _RiskListSummaryCard extends StatelessWidget {
  const _RiskListSummaryCard({
    required this.data,
    required this.severity,
    required this.status,
    required this.keyword,
  });

  final RiskListPayload data;
  final RiskSeverityLevel? severity;
  final RiskStatusType? status;
  final String keyword;

  @override
  Widget build(BuildContext context) {
    final criticalCount = data.items
        .where((risk) =>
            risk.severity == RiskSeverityLevel.critical ||
            risk.severity == RiskSeverityLevel.high)
        .length;
    final openCount =
        data.items.where((risk) => risk.status == RiskStatusType.open).length;

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '风险视图',
            subtitle: '先看高危和待处理项，再下钻资产与证据细节。',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: '共 ${data.meta.total} 条',
                icon: Icons.security_rounded,
                tone: StatusTone.info,
              ),
              AppInfoChip(
                label: '高危 $criticalCount',
                icon: Icons.warning_amber_rounded,
                tone:
                    criticalCount > 0 ? StatusTone.danger : StatusTone.neutral,
              ),
              AppInfoChip(
                label: '待处理 $openCount',
                icon: Icons.pending_actions_rounded,
                tone: openCount > 0 ? StatusTone.warning : StatusTone.neutral,
              ),
              if (severity != null)
                AppInfoChip(
                  label: severity!.label,
                  icon: _riskSeverityIcon(severity!),
                  tone: toneForRiskSeverity(severity!.name),
                ),
              if (status != null)
                AppInfoChip(
                  label: status!.label,
                  icon: Icons.flag_rounded,
                  tone: toneForRiskStatus(status!.name),
                ),
              if (keyword.isNotEmpty)
                AppInfoChip(
                  label: keyword,
                  icon: Icons.manage_search_rounded,
                ),
            ],
          ),
        ],
      ),
    );
  }
}

class _RiskListCard extends StatelessWidget {
  const _RiskListCard({
    required this.risk,
    required this.onTap,
  });

  final RiskItem risk;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final severityTone = toneForRiskSeverity(risk.severity.name);
    final statusTone = toneForRiskStatus(risk.status.name);
    final accentColor = _riskToneColor(context, severityTone);

    return GlassPanel(
      padding: EdgeInsets.zero,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(24),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Container(
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: accentColor.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Icon(
                        _riskSeverityIcon(risk.severity),
                        color: accentColor,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            risk.title,
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '${risk.assetIp} · ${risk.assetHostname ?? '未识别主机名'}',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    StatusBadge(label: risk.severity.label, tone: severityTone),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  risk.description.isEmpty
                      ? '当前没有补充描述，进入详情查看证据。'
                      : risk.description,
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    AppInfoChip(
                      label: risk.status.label,
                      icon: Icons.flag_rounded,
                      tone: statusTone,
                    ),
                    if (risk.assetPortId != null &&
                        risk.assetPortId!.isNotEmpty)
                      AppInfoChip(
                        label: risk.assetPortId!,
                        icon: Icons.usb_rounded,
                      ),
                    AppInfoChip(
                      label: formatDateTimeLabel(
                        risk.resolvedAt ?? risk.detectedAt,
                        fallback:
                            risk.resolvedAt == null ? '发现时间未记录' : '修复时间未记录',
                      ),
                      icon: risk.resolvedAt == null
                          ? Icons.schedule_rounded
                          : Icons.task_alt_rounded,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _RiskDetailHeroCard extends StatelessWidget {
  const _RiskDetailHeroCard({required this.risk});

  final RiskItem risk;

  @override
  Widget build(BuildContext context) {
    final severityTone = toneForRiskSeverity(risk.severity.name);
    final statusTone = toneForRiskStatus(risk.status.name);
    final accentColor = _riskToneColor(context, severityTone);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Container(
                width: 50,
                height: 50,
                decoration: BoxDecoration(
                  color: accentColor.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(
                  _riskSeverityIcon(risk.severity),
                  color: accentColor,
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      risk.title,
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.w900,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '${risk.assetIp} · ${risk.assetHostname ?? '未识别主机名'}',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              StatusBadge(label: risk.severity.label, tone: severityTone),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: risk.status.label,
                icon: Icons.flag_rounded,
                tone: statusTone,
              ),
              if (risk.assetPortId != null && risk.assetPortId!.isNotEmpty)
                AppInfoChip(
                  label: risk.assetPortId!,
                  icon: Icons.usb_rounded,
                ),
              AppInfoChip(
                label: risk.assetIp,
                icon: Icons.lan_rounded,
              ),
            ],
          ),
          const SizedBox(height: 14),
          Text(
            risk.description.isEmpty ? '无描述' : risk.description,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 14),
          AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 132,
            spacing: 10,
            children: [
              DetailMetricTile(
                label: '检测时间',
                value: formatDateTimeLabel(risk.detectedAt),
                icon: Icons.schedule_rounded,
                tone: StatusTone.info,
              ),
              DetailMetricTile(
                label: '修复时间',
                value: formatDateTimeLabel(risk.resolvedAt),
                icon: Icons.task_alt_rounded,
                tone: risk.resolvedAt == null
                    ? StatusTone.neutral
                    : StatusTone.success,
              ),
              DetailMetricTile(
                label: '所属资产',
                value: risk.assetHostname ?? '未识别主机名',
                icon: Icons.computer_rounded,
              ),
              DetailMetricTile(
                label: '证据字段',
                value: '${risk.evidenceJson.length} 项',
                icon: Icons.data_object_rounded,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

IconData _riskSeverityIcon(RiskSeverityLevel severity) {
  return switch (severity) {
    RiskSeverityLevel.critical => Icons.dangerous_rounded,
    RiskSeverityLevel.high => Icons.gpp_bad_rounded,
    RiskSeverityLevel.medium => Icons.report_problem_rounded,
    RiskSeverityLevel.low => Icons.info_outline_rounded,
    RiskSeverityLevel.unknown => Icons.shield_outlined,
  };
}

Color _riskToneColor(BuildContext context, StatusTone tone) {
  return switch (tone) {
    StatusTone.success => const Color(0xFF1D8F5A),
    StatusTone.warning => const Color(0xFFC87B1E),
    StatusTone.info => Theme.of(context).colorScheme.primary,
    StatusTone.danger => const Color(0xFFC54242),
    StatusTone.neutral => Theme.of(context).colorScheme.primary,
  };
}
