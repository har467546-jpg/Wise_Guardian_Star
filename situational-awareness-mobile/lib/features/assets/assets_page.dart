import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final assetDetailProvider =
    FutureProvider.autoDispose.family<AssetModel, String>((ref, assetId) async {
  return ref.watch(apiClientProvider).fetchAsset(assetId);
});

final assetRemediationProvider = FutureProvider.autoDispose
    .family<RemediationAssetDetailModel, String>((ref, assetId) async {
  return ref.watch(apiClientProvider).fetchRemediationAsset(assetId);
});

final assetListProvider = FutureProvider.autoDispose
    .family<AssetListPayload, ({String keyword, AssetStatusType? status})>(
        (ref, query) async {
  return ref
      .watch(apiClientProvider)
      .listAssets(keyword: query.keyword, status: query.status);
});

class AssetsPage extends ConsumerStatefulWidget {
  const AssetsPage({
    super.key,
    required this.initialKeyword,
    required this.initialStatus,
  });

  final String initialKeyword;
  final String? initialStatus;

  @override
  ConsumerState<AssetsPage> createState() => _AssetsPageState();
}

class _AssetsPageState extends ConsumerState<AssetsPage> {
  late final TextEditingController _searchController;
  AssetStatusType? _status;

  @override
  void initState() {
    super.initState();
    _searchController = TextEditingController(text: widget.initialKeyword);
    _status = _parseAssetStatus(widget.initialStatus);
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final query = (keyword: _searchController.text, status: _status);
    final assets = ref.watch(assetListProvider(query));

    return ScreenScaffold(
      title: '资产',
      subtitle: '默认舒适密度，保留搜索、状态筛选和资产详情下钻。',
      maxContentWidth: 1120,
      child: AdaptivePane(
        leading: _AssetFiltersPanel(
          searchController: _searchController,
          status: _status,
          onStatusChanged: (value) => setState(() => _status = value),
          onApply: () => setState(() {}),
        ),
        trailing: AsyncStateView(
          loading: assets.isLoading,
          error: assets.error,
          onRetry: () => ref.invalidate(assetListProvider(query)),
          child: assets.when(
            data: (data) {
              if (data.items.isEmpty) {
                return const AppEmptyState(
                  title: '暂无资产',
                  message: '没有命中当前筛选条件的资产。',
                );
              }
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _AssetListSummaryCard(
                    total: data.meta.total,
                    keyword: _searchController.text.trim(),
                    status: _status,
                  ),
                  const SizedBox(height: 12),
                  ListView.separated(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: data.items.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 12),
                    itemBuilder: (context, index) {
                      final asset = data.items[index];
                      return _AssetListCard(
                        asset: asset,
                        onTap: () => context.push('/assets/${asset.id}'),
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

class AssetDetailPage extends ConsumerStatefulWidget {
  const AssetDetailPage({super.key, required this.assetId});

  final String assetId;

  @override
  ConsumerState<AssetDetailPage> createState() => _AssetDetailPageState();
}

class _AssetDetailPageState extends ConsumerState<AssetDetailPage> {
  bool _runningCollection = false;
  bool _runningVerify = false;
  bool _installingRunner = false;

  Future<void> _runCollection() async {
    setState(() => _runningCollection = true);
    try {
      final result =
          await ref.read(apiClientProvider).runAssetCollection(widget.assetId);
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('采集任务已入队：${result.id}')),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _runningCollection = false);
      }
    }
  }

  Future<void> _runVerify() async {
    setState(() => _runningVerify = true);
    try {
      final result =
          await ref.read(apiClientProvider).verifyAssetRisk(widget.assetId);
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('风险验证任务已入队：${result.id}')),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _runningVerify = false);
      }
    }
  }

  Future<void> _installRunner() async {
    setState(() => _installingRunner = true);
    try {
      final result =
          await ref.read(apiClientProvider).installAssetRunner(widget.assetId);
      ref.invalidate(assetRemediationProvider(widget.assetId));
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Runner 安装任务已入队：${result.taskId}')),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _installingRunner = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final asset = ref.watch(assetDetailProvider(widget.assetId));
    final session = ref.watch(sessionControllerProvider).valueOrNull;
    final showRemediation = session?.role == AppRole.admin;
    final AsyncValue<RemediationAssetDetailModel?> remediation = showRemediation
        ? ref
            .watch(assetRemediationProvider(widget.assetId))
            .whenData((value) => value)
        : const AsyncData<RemediationAssetDetailModel?>(null);

    return ScreenScaffold(
      title: '资产详情',
      subtitle: widget.assetId,
      maxContentWidth: 1120,
      child: AsyncStateView(
        loading: asset.isLoading,
        error: asset.error,
        onRetry: () => ref.invalidate(assetDetailProvider(widget.assetId)),
        child: asset.when(
          data: (data) => AdaptivePane(
            breakpoint: 880,
            leadingWidth: 340,
            leading: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _AssetDetailHeroCard(data: data),
                const SizedBox(height: 14),
                AdaptiveButtonGroup(
                  children: [
                    FilledButton.icon(
                      onPressed: _runningCollection ? null : _runCollection,
                      icon: const Icon(Icons.radar_rounded),
                      label: Text(_runningCollection ? '提交中...' : '单资产采集'),
                    ),
                    OutlinedButton.icon(
                      onPressed: _runningVerify ? null : _runVerify,
                      icon: const Icon(Icons.fact_check_rounded),
                      label: Text(_runningVerify ? '提交中...' : '风险验证'),
                    ),
                  ],
                ),
              ],
            ),
            trailing: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _AssetRemediationSection(
                  assetId: widget.assetId,
                  remediation: remediation,
                  showRemediation: showRemediation,
                  installingRunner: _installingRunner,
                  onInstallRunner: _installRunner,
                ),
                const SizedBox(height: 12),
                SectionHeading(
                  title: '端口与服务',
                  subtitle: '共 ${data.ports.length} 项服务指纹，优先看开放端口与版本信息。',
                ),
                const SizedBox(height: 12),
                if (data.ports.isEmpty)
                  const AppEmptyState(title: '暂无端口', message: '当前资产还没有服务指纹信息。')
                else
                  ...data.ports.map(
                    (port) => Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: _AssetPortCard(port: port),
                    ),
                  ),
              ],
            ),
          ),
          loading: () => const SizedBox.shrink(),
          error: (_, __) => const SizedBox.shrink(),
        ),
      ),
    );
  }
}

AssetStatusType? _parseAssetStatus(String? raw) {
  return switch (raw) {
    'online' => AssetStatusType.online,
    'offline' => AssetStatusType.offline,
    'collecting' => AssetStatusType.collecting,
    _ => null,
  };
}

class _AssetFiltersPanel extends StatelessWidget {
  const _AssetFiltersPanel({
    required this.searchController,
    required this.status,
    required this.onStatusChanged,
    required this.onApply,
  });

  final TextEditingController searchController;
  final AssetStatusType? status;
  final ValueChanged<AssetStatusType?> onStatusChanged;
  final VoidCallback onApply;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '筛选条件',
            subtitle: '按状态和关键词快速收敛结果，适合移动端巡检时先看重点资产。',
          ),
          const SizedBox(height: 12),
          const Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(label: 'IP / 主机名', icon: Icons.search_rounded),
              AppInfoChip(label: '在线状态', icon: Icons.tune_rounded),
            ],
          ),
          const SizedBox(height: 12),
          TextField(
            controller: searchController,
            textInputAction: TextInputAction.search,
            decoration: const InputDecoration(labelText: '搜索 IP / 主机名 / OS'),
            onSubmitted: (_) => onApply(),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<AssetStatusType?>(
            initialValue: status,
            items: const [
              DropdownMenuItem(value: null, child: Text('全部状态')),
              DropdownMenuItem(
                  value: AssetStatusType.online, child: Text('在线')),
              DropdownMenuItem(
                  value: AssetStatusType.collecting, child: Text('采集中')),
              DropdownMenuItem(
                  value: AssetStatusType.offline, child: Text('离线')),
            ],
            onChanged: onStatusChanged,
            decoration: const InputDecoration(labelText: '状态筛选'),
          ),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: FilledButton(
              onPressed: onApply,
              child: const Text('应用筛选'),
            ),
          ),
        ],
      ),
    );
  }
}

class _AssetListSummaryCard extends StatelessWidget {
  const _AssetListSummaryCard({
    required this.total,
    required this.keyword,
    required this.status,
  });

  final int total;
  final String keyword;
  final AssetStatusType? status;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '资产列表',
            subtitle: '把主机状态、系统和服务暴露面压缩成更易扫读的卡片流。',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: '共 $total 台',
                icon: Icons.inventory_2_rounded,
                tone: StatusTone.info,
              ),
              AppInfoChip(
                label: status?.label ?? '全部状态',
                icon: Icons.network_check_rounded,
                tone: status == null
                    ? StatusTone.neutral
                    : toneForAssetStatus(status!.name),
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

class _AssetListCard extends StatelessWidget {
  const _AssetListCard({
    required this.asset,
    required this.onTap,
  });

  final AssetModel asset;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final tone = toneForAssetStatus(asset.status.name);
    final color = _assetToneColor(context, tone);

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
                        color: color.withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Icon(Icons.dns_rounded, color: color),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            asset.ip,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            asset.hostname ?? '未识别主机名',
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodyMedium,
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    StatusBadge(label: asset.status.label, tone: tone),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  asset.osName ?? '系统信息尚未识别',
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
                      label: asset.isLocal ? '本地资产' : '外部资产',
                      icon: asset.isLocal
                          ? Icons.home_work_rounded
                          : Icons.public_rounded,
                      tone:
                          asset.isLocal ? StatusTone.info : StatusTone.neutral,
                    ),
                    if (asset.localHint != null && asset.localHint!.isNotEmpty)
                      AppInfoChip(
                        label: asset.localHint!,
                        icon: Icons.place_rounded,
                      ),
                    AppInfoChip(
                      label: '${asset.ports.length} 个端口',
                      icon: Icons.cable_rounded,
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Icon(
                      Icons.schedule_rounded,
                      size: 16,
                      color: theme.colorScheme.primary,
                    ),
                    const SizedBox(width: 6),
                    Expanded(
                      child: Text(
                        '最近发现 ${formatDateTimeLabel(asset.lastSeenAt)}',
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                    Icon(
                      Icons.chevron_right_rounded,
                      color: theme.colorScheme.primary,
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

class _AssetDetailHeroCard extends StatelessWidget {
  const _AssetDetailHeroCard({required this.data});

  final AssetModel data;

  @override
  Widget build(BuildContext context) {
    final tone = toneForAssetStatus(data.status.name);
    final color = _assetToneColor(context, tone);

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
                  color: color.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(Icons.router_rounded, color: color, size: 24),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      data.ip,
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.w900,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      data.hostname ?? '未识别主机名',
                      style: Theme.of(context).textTheme.bodyMedium,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              StatusBadge(label: data.status.label, tone: tone),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: data.osName ?? '系统未识别',
                icon: Icons.memory_rounded,
              ),
              AppInfoChip(
                label: data.isLocal ? '本地资产' : '外部资产',
                icon: data.isLocal
                    ? Icons.home_work_rounded
                    : Icons.public_rounded,
                tone: data.isLocal ? StatusTone.info : StatusTone.neutral,
              ),
              if (data.localHint != null && data.localHint!.isNotEmpty)
                AppInfoChip(
                  label: data.localHint!,
                  icon: Icons.place_rounded,
                ),
            ],
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
                label: '最近发现',
                value: formatDateTimeLabel(data.lastSeenAt),
                icon: Icons.visibility_rounded,
                tone: tone,
              ),
              DetailMetricTile(
                label: '首次发现',
                value: formatDateTimeLabel(data.firstSeenAt),
                icon: Icons.history_rounded,
              ),
              DetailMetricTile(
                label: '服务数量',
                value: '${data.ports.length} 项',
                icon: Icons.hub_rounded,
                tone: StatusTone.info,
              ),
              DetailMetricTile(
                label: '资产归属',
                value: data.isLocal ? '本地' : '外部',
                icon: Icons.apartment_rounded,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _AssetRemediationSection extends ConsumerWidget {
  const _AssetRemediationSection({
    required this.assetId,
    required this.remediation,
    required this.showRemediation,
    required this.installingRunner,
    required this.onInstallRunner,
  });

  final String assetId;
  final AsyncValue<RemediationAssetDetailModel?> remediation;
  final bool showRemediation;
  final bool installingRunner;
  final VoidCallback onInstallRunner;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (!showRemediation) {
      return const _AssetInlineStateCard(
        title: '修复态势',
        message: '修复工作台仅管理员可用，当前账号不会请求 remediation 接口。',
        icon: Icons.lock_outline_rounded,
      );
    }
    if (remediation.isLoading) {
      return const _AssetInlineStateCard(
        title: '修复态势',
        message: '正在同步修复准备度和 Runner 状态。',
        icon: Icons.build_circle_rounded,
      );
    }
    if (remediation.hasError) {
      return _AssetInlineStateCard(
        title: '修复态势',
        message: describeApiError(remediation.error!),
        icon: Icons.error_outline_rounded,
        action: FilledButton(
          onPressed: () => ref.invalidate(assetRemediationProvider(assetId)),
          child: const Text('重试同步'),
        ),
      );
    }

    final data = remediation.requireValue;
    if (data == null) {
      return const _AssetInlineStateCard(
        title: '修复态势',
        message: '当前没有可展示的修复上下文。',
        icon: Icons.build_circle_outlined,
      );
    }
    final runnerTone =
        _runnerTone(data.runner.status, data.runner.installStatus);
    final readyTone = data.authorization.executionReady
        ? StatusTone.success
        : StatusTone.warning;
    final collectionTone = _collectionTone(data.latestCollection?.status);
    final blockedReasons = _combinedBlockedReasons(data);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '修复态势',
            subtitle: '对齐主线 remediation / runner 摘要，移动端保留就绪度、Runner 和待处理发现。',
            action: Wrap(
              spacing: 8,
              children: [
                TextButton.icon(
                  onPressed: () => context.push('/remediation/$assetId'),
                  icon: const Icon(Icons.construction_rounded, size: 16),
                  label: const Text('进入工作台'),
                ),
                if (data.latestTaskId != null)
                  TextButton.icon(
                    onPressed: () => context.push('/tasks/${data.latestTaskId}'),
                    icon: const Icon(Icons.open_in_new_rounded, size: 16),
                    label: const Text('最近任务'),
                  ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: data.authorization.executionReady ? '可执行' : '待补条件',
                icon: Icons.rule_folder_rounded,
                tone: readyTone,
              ),
              AppInfoChip(
                label: '发现 ${data.findings.length} 项',
                icon: Icons.security_rounded,
                tone: data.findings.isEmpty
                    ? StatusTone.neutral
                    : StatusTone.warning,
              ),
              AppInfoChip(
                label: _runnerStatusLabel(data.runner.status),
                icon: Icons.memory_rounded,
                tone: runnerTone,
              ),
              if (data.activeSessionStatus != null &&
                  data.activeSessionStatus!.isNotEmpty)
                AppInfoChip(
                  label: '会话 ${_sessionStatusLabel(data.activeSessionStatus!)}',
                  icon: Icons.forum_rounded,
                ),
            ],
          ),
          const SizedBox(height: 12),
          AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 132,
            spacing: 10,
            children: [
              DetailMetricTile(
                label: '权限级别',
                value: data.authorization.effectivePrivilege ?? '未验证',
                icon: Icons.admin_panel_settings_rounded,
                tone: _privilegeTone(data.authorization.effectivePrivilege),
              ),
              DetailMetricTile(
                label: '最近验证',
                value: formatDateTimeLabel(data.authorization.lastVerifiedAt),
                icon: Icons.verified_user_rounded,
                tone: readyTone,
              ),
              DetailMetricTile(
                label: 'Runner 安装',
                value: _runnerInstallStatusLabel(data.runner.installStatus),
                icon: Icons.download_for_offline_rounded,
                tone: runnerTone,
              ),
              DetailMetricTile(
                label: '最近采集',
                value: formatDateTimeLabel(data.latestCollection?.collectedAt),
                icon: Icons.cloud_sync_rounded,
                tone: collectionTone,
              ),
            ],
          ),
          const SizedBox(height: 14),
          const SectionHeading(
            title: 'Host Runner',
            subtitle: '优先看在线状态、安装状态和最近心跳。',
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: _runnerInstallStatusLabel(data.runner.installStatus),
                icon: Icons.settings_ethernet_rounded,
                tone: runnerTone,
              ),
              if (data.runner.version != null &&
                  data.runner.version!.isNotEmpty)
                AppInfoChip(
                  label: '版本 ${data.runner.version}',
                  icon: Icons.sell_rounded,
                ),
              if (data.runner.lastSeenAt != null)
                AppInfoChip(
                  label: '心跳 ${formatDateTimeLabel(data.runner.lastSeenAt)}',
                  icon: Icons.schedule_rounded,
                ),
              if (data.runner.capabilitiesJson.isNotEmpty)
                AppInfoChip(
                  label: '能力 ${data.runner.capabilitiesJson.length} 项',
                  icon: Icons.extension_rounded,
                ),
            ],
          ),
          if (data.runner.lastError != null &&
              data.runner.lastError!.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(
              '最近错误：${data.runner.lastError}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
          if (data.canInstallRunner ||
              data.runner.installStatus == 'installing' ||
              data.runner.installStatus == 'failed') ...[
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: installingRunner ? null : onInstallRunner,
              icon: const Icon(Icons.download_for_offline_rounded),
              label: Text(installingRunner
                  ? '提交中...'
                  : data.runner.installStatus == 'failed'
                      ? '重新安装 Runner'
                      : '安装 Runner'),
            ),
          ],
          if (blockedReasons.isNotEmpty) ...[
            const SizedBox(height: 14),
            const SectionHeading(
              title: '阻塞原因',
              subtitle: '先补齐授权或 SSH 管理凭据，再执行修复或安装 Runner。',
            ),
            const SizedBox(height: 10),
            ...blockedReasons.asMap().entries.map(
                  (entry) => Padding(
                    padding: EdgeInsets.only(
                      bottom: entry.key == blockedReasons.length - 1 ? 0 : 8,
                    ),
                    child: _BlockedReasonTile(message: entry.value),
                  ),
                ),
          ],
          const SizedBox(height: 14),
          SectionHeading(
            title: '待处理发现',
            subtitle:
                data.findings.isEmpty ? '当前资产没有待进入修复会话的发现。' : '点击条目可直接进入风险详情。',
          ),
          const SizedBox(height: 10),
          if (data.findings.isEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .onSurface
                    .withValues(alpha: 0.03),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(
                  color: Theme.of(context)
                      .colorScheme
                      .onSurface
                      .withValues(alpha: 0.06),
                ),
              ),
              child: Row(
                children: [
                  const Icon(Icons.verified_rounded, size: 18),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      '当前没有待修复发现。',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ),
                ],
              ),
            )
          else ...[
            ...data.findings.take(3).map(
                  (finding) => Padding(
                    padding: const EdgeInsets.only(bottom: 10),
                    child: _RemediationFindingTile(finding: finding),
                  ),
                ),
            if (data.findings.length > 3)
              Text(
                '还有 ${data.findings.length - 3} 项发现未展开。',
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ],
      ),
    );
  }
}

class _AssetInlineStateCard extends StatelessWidget {
  const _AssetInlineStateCard({
    required this.title,
    required this.message,
    required this.icon,
    this.action,
  });

  final String title;
  final String message;
  final IconData icon;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(title: title),
          const SizedBox(height: 12),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(icon,
                  size: 18, color: Theme.of(context).colorScheme.primary),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  message,
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ),
            ],
          ),
          if (action != null) ...[
            const SizedBox(height: 12),
            action!,
          ],
        ],
      ),
    );
  }
}

class _BlockedReasonTile extends StatelessWidget {
  const _BlockedReasonTile({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFFC87B1E).withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: const Color(0xFFC87B1E).withValues(alpha: 0.16),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Icon(Icons.info_outline_rounded,
              size: 18, color: Color(0xFFC87B1E)),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              message,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
        ],
      ),
    );
  }
}

class _RemediationFindingTile extends StatelessWidget {
  const _RemediationFindingTile({required this.finding});

  final RemediationFindingModel finding;

  @override
  Widget build(BuildContext context) {
    final tone = toneForRiskSeverity(finding.severity.name);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: () => context.push('/risks/${finding.findingId}'),
        child: Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: _assetToneColor(context, tone).withValues(alpha: 0.08),
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: _assetToneColor(context, tone).withValues(alpha: 0.14),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(
                    child: Text(
                      finding.title,
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  StatusBadge(label: finding.severity.label, tone: tone),
                ],
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  AppInfoChip(
                    label: finding.serviceName ?? '未识别服务',
                    icon: Icons.hub_rounded,
                  ),
                  AppInfoChip(
                    label: finding.status,
                    icon: Icons.flag_rounded,
                  ),
                  AppInfoChip(
                    label: formatDateTimeLabel(finding.detectedAt),
                    icon: Icons.schedule_rounded,
                  ),
                  if (finding.hasTemplate)
                    const AppInfoChip(
                      label: '可自动化',
                      icon: Icons.auto_fix_high_rounded,
                      tone: StatusTone.info,
                    ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _AssetPortCard extends StatelessWidget {
  const _AssetPortCard({required this.port});

  final AssetPortModel port;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final serviceLabel = port.serviceName ?? '未识别服务';
    final versionLabel = port.serviceVersion ?? '版本未识别';

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  '${port.port}/${port.protocol}',
                  style: theme.textTheme.titleMedium?.copyWith(
                    fontWeight: FontWeight.w800,
                  ),
                ),
              ),
              StatusBadge(label: port.state, tone: StatusTone.info),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            serviceLabel,
            style: theme.textTheme.titleSmall?.copyWith(
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            versionLabel,
            style: theme.textTheme.bodySmall,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: port.protocol.toUpperCase(),
                icon: Icons.swap_horiz_rounded,
              ),
              AppInfoChip(
                label: '最近识别 ${formatDateTimeLabel(port.lastSeenAt)}',
                icon: Icons.schedule_rounded,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

List<String> _combinedBlockedReasons(RemediationAssetDetailModel data) {
  return {
    ...data.authorization.blockedReasons,
    ...data.runnerInstallBlockedReasons,
  }.toList(growable: false);
}

String _runnerStatusLabel(String value) {
  return switch (value) {
    'online' => '在线',
    'offline' => '离线',
    'busy' => '忙碌',
    'not_installed' => '未安装',
    _ => value,
  };
}

String _runnerInstallStatusLabel(String value) {
  return switch (value) {
    'installed' => '已安装',
    'installing' => '安装中',
    'failed' => '安装失败',
    'not_installed' => '未安装',
    _ => value,
  };
}

String _sessionStatusLabel(String value) {
  return switch (value) {
    'pending' => '待确认',
    'running' => '执行中',
    'completed' => '已完成',
    'failed' => '失败',
    'canceled' => '已取消',
    _ => value,
  };
}

StatusTone _runnerTone(String status, String installStatus) {
  if (installStatus == 'failed') {
    return StatusTone.danger;
  }
  if (status == 'online') {
    return StatusTone.success;
  }
  if (status == 'busy' || installStatus == 'installing') {
    return StatusTone.info;
  }
  if (status == 'offline') {
    return StatusTone.warning;
  }
  return StatusTone.neutral;
}

StatusTone _collectionTone(String? value) {
  return switch (value) {
    'success' => StatusTone.success,
    'partial' => StatusTone.warning,
    'failed' => StatusTone.danger,
    'running' => StatusTone.info,
    _ => StatusTone.neutral,
  };
}

StatusTone _privilegeTone(String? value) {
  return switch (value) {
    'root' || 'sudo' => StatusTone.success,
    'user' => StatusTone.warning,
    _ => StatusTone.neutral,
  };
}

Color _assetToneColor(BuildContext context, StatusTone tone) {
  return switch (tone) {
    StatusTone.success => const Color(0xFF1D8F5A),
    StatusTone.warning => const Color(0xFFC87B1E),
    StatusTone.info => Theme.of(context).colorScheme.primary,
    StatusTone.danger => const Color(0xFFC54242),
    StatusTone.neutral => Theme.of(context).colorScheme.primary,
  };
}
