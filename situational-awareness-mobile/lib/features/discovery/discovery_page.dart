import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/network/api_client.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final discoveryListProvider =
    FutureProvider.autoDispose.family<DiscoveryJobListPayload, DiscoveryJobStatusType?>((ref, status) async {
  return ref.watch(apiClientProvider).listDiscoveryJobs(status: status);
});

final discoveryDetailProvider = FutureProvider.family((ref, String jobId) async {
  return ref.watch(apiClientProvider).fetchDiscoveryJob(jobId);
});

class DiscoveryPage extends ConsumerStatefulWidget {
  const DiscoveryPage({super.key});

  @override
  ConsumerState<DiscoveryPage> createState() => _DiscoveryPageState();
}

class _DiscoveryPageState extends ConsumerState<DiscoveryPage> {
  final _cidrController = TextEditingController();
  final _labelController = TextEditingController();
  DiscoveryJobStatusType? _status;
  bool _creating = false;

  @override
  void dispose() {
    _cidrController.dispose();
    _labelController.dispose();
    super.dispose();
  }

  Future<void> _createJob() async {
    setState(() => _creating = true);
    try {
      final job = await ref.read(apiClientProvider).createDiscoveryJob(
            cidr: _cidrController.text.trim(),
            label: _labelController.text.trim(),
          );
      if (!mounted) {
        return;
      }
      ref.invalidate(discoveryListProvider(_status));
      context.push('/discovery/${job.id}');
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(error.toString())));
      }
    } finally {
      if (mounted) {
        setState(() => _creating = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final jobs = ref.watch(discoveryListProvider(_status));

    return ScreenScaffold(
      title: '发现任务',
      subtitle: '发现页不占底部 Tab，通过首页入口和 FAB 进入。',
      maxContentWidth: 1120,
      child: AdaptivePane(
        leading: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            GlassPanel(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const SectionHeading(title: '新建发现任务', subtitle: '输入 CIDR 后立即入队。'),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _cidrController,
                    decoration: const InputDecoration(labelText: 'CIDR，例如 10.0.0.0/24'),
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _labelController,
                    decoration: const InputDecoration(labelText: '标签（可选）'),
                  ),
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: _creating ? null : _createJob,
                      icon: const Icon(Icons.add_task_rounded),
                      label: Text(_creating ? '提交中...' : '创建任务'),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            GlassPanel(
              child: DropdownButtonFormField<DiscoveryJobStatusType?>(
                initialValue: _status,
                decoration: const InputDecoration(labelText: '任务状态'),
                items: const [
                  DropdownMenuItem(value: null, child: Text('全部状态')),
                  DropdownMenuItem(value: DiscoveryJobStatusType.pending, child: Text('待执行')),
                  DropdownMenuItem(value: DiscoveryJobStatusType.running, child: Text('执行中')),
                  DropdownMenuItem(value: DiscoveryJobStatusType.completed, child: Text('已完成')),
                  DropdownMenuItem(value: DiscoveryJobStatusType.failed, child: Text('失败')),
                ],
                onChanged: (value) => setState(() => _status = value),
              ),
            ),
          ],
        ),
        trailing: AsyncStateView(
          loading: jobs.isLoading,
          error: jobs.error,
          onRetry: () => ref.invalidate(discoveryListProvider(_status)),
          child: jobs.when(
            data: (data) {
              if (data.items.isEmpty) {
                return const AppEmptyState(title: '暂无发现任务', message: '可以从上方直接创建一个新的发现任务。');
              }
              return ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: data.items.length,
                separatorBuilder: (_, __) => const SizedBox(height: 12),
                itemBuilder: (context, index) {
                  final job = data.items[index];
                  return GlassPanel(
                    child: ListTile(
                      contentPadding: EdgeInsets.zero,
                      title: Text(job.label ?? job.cidr),
                      subtitle: Text(job.cidr),
                      trailing: StatusBadge(label: job.status.label, tone: toneForDiscoveryStatus(job.status.name)),
                      onTap: () => context.push('/discovery/${job.id}'),
                    ),
                  );
                },
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

class DiscoveryDetailPage extends ConsumerWidget {
  const DiscoveryDetailPage({super.key, required this.jobId});

  final String jobId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final job = ref.watch(discoveryDetailProvider(jobId));

    return ScreenScaffold(
      title: '发现任务详情',
      subtitle: jobId,
      maxContentWidth: 1120,
      child: AsyncStateView(
        loading: job.isLoading,
        error: job.error,
        onRetry: () => ref.invalidate(discoveryDetailProvider(jobId)),
        child: job.when(
          data: (data) => AdaptivePane(
            breakpoint: 880,
            leadingWidth: 340,
            leading: GlassPanel(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(child: Text(data.label ?? data.cidr, style: Theme.of(context).textTheme.titleLarge)),
                      StatusBadge(label: data.status.label, tone: toneForDiscoveryStatus(data.status.name)),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Text('CIDR：${data.cidr}'),
                  Text('创建时间：${data.createdAt ?? '-'}'),
                ],
              ),
            ),
            trailing: GlassPanel(
              child: SelectableText(
                'summary_json: ${data.summaryJson}',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ),
          ),
          loading: () => const SizedBox.shrink(),
          error: (_, __) => const SizedBox.shrink(),
        ),
      ),
    );
  }
}
