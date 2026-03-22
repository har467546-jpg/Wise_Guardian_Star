import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/network/api_client.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final taskListProvider = FutureProvider.autoDispose
    .family<TaskListPayload, TaskStatusType?>((ref, status) async {
  return ref.watch(apiClientProvider).listTasks(status: status);
});

final taskDetailProvider = FutureProvider.autoDispose
    .family<TaskRunModel, String>((ref, taskId) async {
  return ref.watch(apiClientProvider).fetchTask(taskId);
});

final taskEventsProvider = FutureProvider.autoDispose
    .family<TaskEventListPayload, String>((ref, taskId) async {
  return ref.watch(apiClientProvider).fetchTaskEvents(taskId);
});

class TasksPage extends ConsumerStatefulWidget {
  const TasksPage({super.key, this.initialStatus});

  final String? initialStatus;

  @override
  ConsumerState<TasksPage> createState() => _TasksPageState();
}

class _TasksPageState extends ConsumerState<TasksPage> {
  TaskStatusType? _status;

  @override
  void initState() {
    super.initState();
    _status = _parseTaskStatus(widget.initialStatus);
  }

  @override
  Widget build(BuildContext context) {
    final tasks = ref.watch(taskListProvider(_status));

    return ScreenScaffold(
      title: '任务',
      subtitle: '紧凑模式只留任务类型、状态、进度和最近消息。',
      maxContentWidth: 1120,
      child: AdaptivePane(
        breakpoint: 880,
        leadingWidth: 300,
        leading: _TaskFiltersPanel(
          status: _status,
          onStatusChanged: (value) => setState(() => _status = value),
        ),
        trailing: AsyncStateView(
          loading: tasks.isLoading,
          error: tasks.error,
          onRetry: () => ref.invalidate(taskListProvider(_status)),
          child: tasks.when(
            data: (data) {
              if (data.items.isEmpty) {
                return const AppEmptyState(
                    title: '暂无任务', message: '当前筛选条件下没有任务记录。');
              }
              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  _TaskListSummaryCard(
                    data: data,
                    status: _status,
                  ),
                  const SizedBox(height: 12),
                  ListView.separated(
                    shrinkWrap: true,
                    physics: const NeverScrollableScrollPhysics(),
                    itemCount: data.items.length,
                    separatorBuilder: (_, __) => const SizedBox(height: 12),
                    itemBuilder: (context, index) {
                      final task = data.items[index];
                      return _TaskListCard(
                        task: task,
                        onTap: () => Navigator.of(context).push(
                          MaterialPageRoute(
                              builder: (_) => TaskDetailPage(taskId: task.id)),
                        ),
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

class TaskDetailPage extends ConsumerWidget {
  const TaskDetailPage({super.key, required this.taskId});

  final String taskId;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final task = ref.watch(taskDetailProvider(taskId));
    final events = ref.watch(taskEventsProvider(taskId));

    return ScreenScaffold(
      title: '任务详情',
      subtitle: taskId,
      maxContentWidth: 1120,
      child: AsyncStateView(
        loading: task.isLoading,
        error: task.error,
        onRetry: () => ref.invalidate(taskDetailProvider(taskId)),
        child: task.when(
          data: (data) => AdaptivePane(
            breakpoint: 880,
            leadingWidth: 340,
            leading: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _TaskDetailHeroCard(data: data),
                if (data.message != null && data.message!.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _TaskMessageCard(message: data.message!),
                ],
                const SizedBox(height: 12),
                _TaskObservabilityCard(data: data, events: events.valueOrNull),
              ],
            ),
            trailing: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _TaskEventsSection(
                  taskId: taskId,
                  data: data,
                  events: events,
                ),
                const SizedBox(height: 12),
                JsonPreviewCard(
                  title: '执行结果',
                  subtitle: '成功输出、统计值和附加结果会显示在这里。',
                  data: data.resultJson,
                  emptyMessage: '当前没有返回结果字段。',
                ),
                const SizedBox(height: 12),
                JsonPreviewCard(
                  title: '错误详情',
                  subtitle: '失败、重试或异常上下文会保留在这里。',
                  data: data.errorJson,
                  emptyMessage: '当前没有错误字段。',
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

TaskStatusType? _parseTaskStatus(String? raw) {
  return switch (raw) {
    'pending' => TaskStatusType.pending,
    'running' => TaskStatusType.running,
    'retry' => TaskStatusType.retry,
    'success' => TaskStatusType.success,
    'failure' => TaskStatusType.failure,
    'canceled' => TaskStatusType.canceled,
    _ => null,
  };
}

class _TaskFiltersPanel extends StatelessWidget {
  const _TaskFiltersPanel({
    required this.status,
    required this.onStatusChanged,
  });

  final TaskStatusType? status;
  final ValueChanged<TaskStatusType?> onStatusChanged;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '状态筛选',
            subtitle: '优先看待执行、执行中和失败任务，适合手机端快速盯进度。',
          ),
          const SizedBox(height: 12),
          const Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(label: '任务状态', icon: Icons.filter_alt_rounded),
              AppInfoChip(
                  label: '执行进度', icon: Icons.stacked_line_chart_rounded),
            ],
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<TaskStatusType?>(
            initialValue: status,
            items: const [
              DropdownMenuItem(value: null, child: Text('全部状态')),
              DropdownMenuItem(
                  value: TaskStatusType.pending, child: Text('待执行')),
              DropdownMenuItem(
                  value: TaskStatusType.running, child: Text('执行中')),
              DropdownMenuItem(value: TaskStatusType.retry, child: Text('重试中')),
              DropdownMenuItem(
                  value: TaskStatusType.success, child: Text('成功')),
              DropdownMenuItem(
                  value: TaskStatusType.failure, child: Text('失败')),
              DropdownMenuItem(
                  value: TaskStatusType.canceled, child: Text('已取消')),
            ],
            onChanged: onStatusChanged,
            decoration: const InputDecoration(labelText: '任务状态'),
          ),
        ],
      ),
    );
  }
}

class _TaskListSummaryCard extends StatelessWidget {
  const _TaskListSummaryCard({
    required this.data,
    required this.status,
  });

  final TaskListPayload data;
  final TaskStatusType? status;

  @override
  Widget build(BuildContext context) {
    final runningCount = data.items
        .where((task) =>
            task.status == TaskStatusType.running ||
            task.status == TaskStatusType.retry)
        .length;
    final failureCount = data.items
        .where((task) => task.status == TaskStatusType.failure)
        .length;

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '任务流',
            subtitle: '把执行状态、范围和最近消息压成一屏，方便跟进当前队列。',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: '共 ${data.meta.total} 条',
                icon: Icons.assignment_rounded,
                tone: StatusTone.info,
              ),
              AppInfoChip(
                label: '执行中 $runningCount',
                icon: Icons.autorenew_rounded,
                tone: StatusTone.info,
              ),
              AppInfoChip(
                label: '失败 $failureCount',
                icon: Icons.error_outline_rounded,
                tone: failureCount > 0 ? StatusTone.danger : StatusTone.neutral,
              ),
              AppInfoChip(
                label: status?.label ?? '全部状态',
                icon: Icons.tune_rounded,
                tone: status == null
                    ? StatusTone.neutral
                    : toneForTaskStatus(status!.name),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _TaskListCard extends StatelessWidget {
  const _TaskListCard({
    required this.task,
    required this.onTap,
  });

  final TaskRunModel task;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final tone = toneForTaskStatus(task.status.name);
    final progress = (task.progress.clamp(0, 100)) / 100;

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
                        color: _taskToneColor(context, tone)
                            .withValues(alpha: 0.12),
                        borderRadius: BorderRadius.circular(14),
                      ),
                      child: Icon(
                        _taskTypeIcon(task.taskType),
                        color: _taskToneColor(context, tone),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            task.taskType.label,
                            style: theme.textTheme.titleMedium?.copyWith(
                              fontWeight: FontWeight.w800,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _taskScopeLabel(task),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: theme.textTheme.bodySmall,
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    StatusBadge(label: task.status.label, tone: tone),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  task.message ?? '当前没有附加说明，进入详情查看结构化结果。',
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.bodySmall,
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Text(
                      '进度 ${task.progress}%',
                      style: theme.textTheme.labelMedium?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const Spacer(),
                    Text(
                      formatDateTimeLabel(task.createdAt),
                      style: theme.textTheme.bodySmall,
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                LinearProgressIndicator(
                  value: progress,
                  minHeight: 8,
                  borderRadius: BorderRadius.circular(999),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    AppInfoChip(
                      label: task.scopeType ?? '未识别范围',
                      icon: Icons.category_rounded,
                    ),
                    AppInfoChip(
                      label: task.scopeId ?? '未提供范围 ID',
                      icon: Icons.tag_rounded,
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

class _TaskDetailHeroCard extends StatelessWidget {
  const _TaskDetailHeroCard({required this.data});

  final TaskRunModel data;

  @override
  Widget build(BuildContext context) {
    final tone = toneForTaskStatus(data.status.name);
    final progress = (data.progress.clamp(0, 100)) / 100;

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
                  color: _taskToneColor(context, tone).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(16),
                ),
                child: Icon(
                  _taskTypeIcon(data.taskType),
                  color: _taskToneColor(context, tone),
                  size: 24,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      data.taskType.label,
                      style: Theme.of(context).textTheme.titleLarge?.copyWith(
                            fontWeight: FontWeight.w900,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      _taskScopeLabel(data),
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
          Row(
            children: [
              Text(
                '进度 ${data.progress}%',
                style: Theme.of(context).textTheme.titleSmall?.copyWith(
                      fontWeight: FontWeight.w800,
                    ),
              ),
              const Spacer(),
              AppInfoChip(
                label: data.scopeType ?? '未识别范围',
                icon: Icons.adjust_rounded,
              ),
            ],
          ),
          const SizedBox(height: 8),
          LinearProgressIndicator(
            value: progress,
            minHeight: 10,
            borderRadius: BorderRadius.circular(999),
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              if (data.retryCount > 0)
                AppInfoChip(
                  label: '重试 ${data.retryCount} 次',
                  icon: Icons.refresh_rounded,
                  tone: StatusTone.warning,
                ),
              if (data.timing.hasEventLogs)
                AppInfoChip(
                  label: '事件 ${data.eventCount} 条',
                  icon: Icons.stream_rounded,
                  tone: StatusTone.info,
                ),
              if (data.lastEventAt != null)
                AppInfoChip(
                  label: '最近事件 ${formatDateTimeLabel(data.lastEventAt)}',
                  icon: Icons.schedule_rounded,
                ),
            ],
          ),
          if (data.retryCount > 0 ||
              data.timing.hasEventLogs ||
              data.lastEventAt != null) ...[
            const SizedBox(height: 14),
          ],
          AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 132,
            spacing: 10,
            children: [
              DetailMetricTile(
                label: '范围对象',
                value: data.scopeId ?? '未提供',
                icon: Icons.center_focus_strong_rounded,
              ),
              DetailMetricTile(
                label: '当前阶段',
                value: data.timing.currentStageName ?? '未进入阶段',
                icon: Icons.account_tree_rounded,
                tone: data.timing.currentStageName == null
                    ? StatusTone.neutral
                    : StatusTone.info,
              ),
              DetailMetricTile(
                label: '事件日志',
                value:
                    data.timing.hasEventLogs ? '${data.eventCount} 条' : '未采集',
                icon: Icons.stream_rounded,
                tone: data.timing.hasEventLogs
                    ? StatusTone.info
                    : StatusTone.neutral,
              ),
              DetailMetricTile(
                label: '总耗时',
                value: _formatDurationLabel(data.timing.totalDurationMs),
                icon: Icons.timelapse_rounded,
                tone: data.timing.totalDurationMs == null
                    ? StatusTone.neutral
                    : StatusTone.success,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _TaskMessageCard extends StatelessWidget {
  const _TaskMessageCard({required this.message});

  final String message;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '最近消息',
            subtitle: '保留任务最近一次可读描述，便于快速判断是否需要深挖。',
          ),
          const SizedBox(height: 10),
          Text(
            message,
            style: Theme.of(context).textTheme.bodyMedium,
          ),
        ],
      ),
    );
  }
}

class _TaskObservabilityCard extends StatelessWidget {
  const _TaskObservabilityCard({
    required this.data,
    required this.events,
  });

  final TaskRunModel data;
  final TaskEventListPayload? events;

  @override
  Widget build(BuildContext context) {
    final hasEventLogs =
        events != null ? events!.meta.total > 0 : data.timing.hasEventLogs;
    final eventCount =
        events?.meta.total ?? (data.timing.hasEventLogs ? data.eventCount : 0);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '执行观测',
            subtitle: '对齐主线任务可观测字段，移动端先看阶段、耗时和日志密度。',
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
                label: '排队耗时',
                value: _formatDurationLabel(data.timing.queueDurationMs),
                icon: Icons.hourglass_top_rounded,
                tone: data.timing.queueDurationMs == null
                    ? StatusTone.neutral
                    : StatusTone.warning,
              ),
              DetailMetricTile(
                label: '运行耗时',
                value: _formatDurationLabel(data.timing.runDurationMs),
                icon: Icons.play_circle_outline_rounded,
                tone: data.timing.runDurationMs == null
                    ? StatusTone.neutral
                    : StatusTone.info,
              ),
              DetailMetricTile(
                label: '最近事件',
                value: formatDateTimeLabel(
                  events?.items.isNotEmpty == true
                      ? events!.items.last.createdAt
                      : data.lastEventAt,
                ),
                icon: Icons.update_rounded,
                tone: hasEventLogs ? StatusTone.info : StatusTone.neutral,
              ),
              DetailMetricTile(
                label: '日志密度',
                value: hasEventLogs ? '$eventCount 条' : '未记录',
                icon: Icons.toc_rounded,
                tone: hasEventLogs ? StatusTone.info : StatusTone.neutral,
              ),
            ],
          ),
          if (data.stageTimings.isNotEmpty) ...[
            const SizedBox(height: 14),
            const SectionHeading(
              title: '阶段时间线',
              subtitle: '按阶段展示执行顺序和停留时间，适合快速定位卡点。',
            ),
            const SizedBox(height: 10),
            ...data.stageTimings.asMap().entries.map(
                  (entry) => Padding(
                    padding: EdgeInsets.only(
                      bottom:
                          entry.key == data.stageTimings.length - 1 ? 0 : 10,
                    ),
                    child: _TaskStageTimingRow(stage: entry.value),
                  ),
                ),
          ],
        ],
      ),
    );
  }
}

class _TaskEventsSection extends ConsumerWidget {
  const _TaskEventsSection({
    required this.taskId,
    required this.data,
    required this.events,
  });

  final String taskId;
  final TaskRunModel data;
  final AsyncValue<TaskEventListPayload> events;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (events.isLoading) {
      return const _TaskInlineStateCard(
        title: '执行事件',
        message: '正在同步任务事件流。',
        icon: Icons.stream_rounded,
      );
    }
    if (events.hasError) {
      return _TaskInlineStateCard(
        title: '执行事件',
        message: describeApiError(events.error!),
        icon: Icons.error_outline_rounded,
        action: FilledButton(
          onPressed: () => ref.invalidate(taskEventsProvider(taskId)),
          child: const Text('重试事件同步'),
        ),
      );
    }

    final payload = events.requireValue;
    if (payload.items.isEmpty) {
      return GlassPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SectionHeading(
              title: '执行事件',
              subtitle: data.timing.hasEventLogs
                  ? '当前页未拿到事件条目，请稍后刷新。'
                  : '当前任务还没有事件日志，先看结构化结果即可。',
            ),
            const SizedBox(height: 12),
            const AppEmptyState(
              title: '暂无事件',
              message: '任务事件流为空。',
            ),
          ],
        ),
      );
    }

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '执行事件',
            subtitle: '按时间顺序展示阶段、消息和进度变化。',
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: '共 ${payload.meta.total} 条',
                icon: Icons.stream_rounded,
                tone: StatusTone.info,
              ),
              AppInfoChip(
                label: data.timing.currentStageName ?? '当前无阶段',
                icon: Icons.account_tree_rounded,
              ),
            ],
          ),
          const SizedBox(height: 12),
          ...payload.items.asMap().entries.map(
                (entry) => Padding(
                  padding: EdgeInsets.only(
                    bottom: entry.key == payload.items.length - 1 ? 0 : 10,
                  ),
                  child: _TaskEventTile(event: entry.value),
                ),
              ),
        ],
      ),
    );
  }
}

class _TaskInlineStateCard extends StatelessWidget {
  const _TaskInlineStateCard({
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

class _TaskStageTimingRow extends StatelessWidget {
  const _TaskStageTimingRow({required this.stage});

  final TaskStageTimingModel stage;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color:
              Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.06),
        ),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 10,
            height: 10,
            margin: const EdgeInsets.only(top: 6),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primary,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  stage.stageName ?? stage.stageCode ?? '未命名阶段',
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${formatDateTimeLabel(stage.startedAt)} -> ${formatDateTimeLabel(stage.finishedAt)}',
                  style: Theme.of(context).textTheme.bodySmall,
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          StatusBadge(
            label: _formatDurationLabel(stage.durationMs),
            tone: StatusTone.info,
          ),
        ],
      ),
    );
  }
}

class _TaskEventTile extends StatelessWidget {
  const _TaskEventTile({required this.event});

  final TaskEventModel event;

  @override
  Widget build(BuildContext context) {
    final tone = _taskEventTone(event);

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: _taskToneColor(context, tone).withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: _taskToneColor(context, tone).withValues(alpha: 0.14),
        ),
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
                      event.message ??
                          event.stageName ??
                          _taskEventTypeLabel(event.eventType),
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      formatDateTimeLabel(event.createdAt),
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              StatusBadge(
                label: _taskEventTypeLabel(event.eventType),
                tone: tone,
              ),
            ],
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: event.level,
                icon: Icons.flag_rounded,
                tone: tone,
              ),
              if (event.progress != null)
                AppInfoChip(
                  label: '进度 ${event.progress}%',
                  icon: Icons.stacked_line_chart_rounded,
                ),
              if (event.stageName != null && event.stageName!.isNotEmpty)
                AppInfoChip(
                  label: event.stageName!,
                  icon: Icons.account_tree_rounded,
                ),
              if (event.status != TaskStatusType.unknown)
                AppInfoChip(
                  label: event.status.label,
                  icon: Icons.task_alt_rounded,
                  tone: toneForTaskStatus(event.status.name),
                ),
            ],
          ),
          if (event.payloadJson.isNotEmpty) ...[
            const SizedBox(height: 10),
            Text(
              '附加字段 ${event.payloadJson.length} 项',
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    fontWeight: FontWeight.w700,
                  ),
            ),
          ],
        ],
      ),
    );
  }
}

String _taskScopeLabel(TaskRunModel task) {
  final scopeType = task.scopeType;
  final scopeId = task.scopeId;
  if (scopeType == null && scopeId == null) {
    return '未提供范围信息';
  }
  if (scopeType == null) {
    return scopeId!;
  }
  if (scopeId == null) {
    return scopeType;
  }
  return '$scopeType / $scopeId';
}

IconData _taskTypeIcon(TaskTypeModel type) {
  return switch (type) {
    TaskTypeModel.assetScan => Icons.radar_rounded,
    TaskTypeModel.infoCollect => Icons.cloud_sync_rounded,
    TaskTypeModel.riskVerify => Icons.fact_check_rounded,
    TaskTypeModel.reportGenerate => Icons.description_rounded,
    TaskTypeModel.credentialVerify => Icons.verified_user_rounded,
    TaskTypeModel.runnerInstall => Icons.download_for_offline_rounded,
    TaskTypeModel.remediationExecute => Icons.build_circle_rounded,
    TaskTypeModel.agentOrchestrate => Icons.auto_awesome_rounded,
    TaskTypeModel.settingsApply => Icons.tune_rounded,
    TaskTypeModel.unknown => Icons.assignment_rounded,
  };
}

String _formatDurationLabel(int? durationMs) {
  if (durationMs == null) {
    return '未记录';
  }
  if (durationMs < 1000) {
    return '${durationMs}ms';
  }
  final totalSeconds = durationMs ~/ 1000;
  if (totalSeconds < 60) {
    return '${totalSeconds}s';
  }
  final minutes = totalSeconds ~/ 60;
  final seconds = totalSeconds % 60;
  if (minutes < 60) {
    return seconds == 0 ? '${minutes}m' : '${minutes}m ${seconds}s';
  }
  final hours = minutes ~/ 60;
  final remainMinutes = minutes % 60;
  return remainMinutes == 0 ? '${hours}h' : '${hours}h ${remainMinutes}m';
}

String _taskEventTypeLabel(String value) {
  return switch (value) {
    'stage' => '阶段',
    'progress' => '进度',
    'result' => '结果',
    'error' => '错误',
    'log' => '日志',
    _ => value,
  };
}

StatusTone _taskEventTone(TaskEventModel event) {
  if (event.level == 'error' || event.status == TaskStatusType.failure) {
    return StatusTone.danger;
  }
  if (event.level == 'warning') {
    return StatusTone.warning;
  }
  if (event.level == 'success' || event.status == TaskStatusType.success) {
    return StatusTone.success;
  }
  return StatusTone.info;
}

Color _taskToneColor(BuildContext context, StatusTone tone) {
  return switch (tone) {
    StatusTone.success => const Color(0xFF1D8F5A),
    StatusTone.warning => const Color(0xFFC87B1E),
    StatusTone.info => Theme.of(context).colorScheme.primary,
    StatusTone.danger => const Color(0xFFC54242),
    StatusTone.neutral => Theme.of(context).colorScheme.primary,
  };
}
