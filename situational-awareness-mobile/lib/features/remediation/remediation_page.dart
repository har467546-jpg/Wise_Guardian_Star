import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../core/network/websocket_client.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final remediationAssetCardsProvider = FutureProvider.autoDispose.family<
    RemediationAssetListPayload,
    ({
      String keyword,
      int page,
    })>((ref, query) async {
  return ref.watch(apiClientProvider).listRemediationAssets(
        keyword: query.keyword,
        page: query.page,
      );
});

class RemediationAssetGalleryPage extends ConsumerStatefulWidget {
  const RemediationAssetGalleryPage({super.key});

  @override
  ConsumerState<RemediationAssetGalleryPage> createState() =>
      _RemediationAssetGalleryPageState();
}

class _RemediationAssetGalleryPageState
    extends ConsumerState<RemediationAssetGalleryPage> {
  late final TextEditingController _searchController;
  int _page = 1;

  @override
  void initState() {
    super.initState();
    _searchController = TextEditingController();
  }

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final query = (keyword: _searchController.text.trim(), page: _page);
    final assets = ref.watch(remediationAssetCardsProvider(query));

    return ScreenScaffold(
      title: '修复工作台',
      subtitle: '按资产进入移动端修复会话，重点看前置条件、阶段推进和当前输出。',
      maxContentWidth: 1120,
      child: AdaptivePane(
        breakpoint: 920,
        leadingWidth: 300,
        leading: GlassPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionHeading(
                title: '资产筛选',
                subtitle: '按 IP、主机名或系统快速定位待处理资产。',
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _searchController,
                decoration: const InputDecoration(
                  labelText: '搜索资产',
                  hintText: '例如 10.0.0.12 / edge-node',
                ),
                onSubmitted: (_) => setState(() => _page = 1),
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: () => setState(() => _page = 1),
                  icon: const Icon(Icons.search_rounded),
                  label: const Text('应用筛选'),
                ),
              ),
            ],
          ),
        ),
        trailing: AsyncStateView(
          loading: assets.isLoading,
          error: assets.error,
          onRetry: () => ref.invalidate(remediationAssetCardsProvider(query)),
          child: assets.when(
            data: (data) {
              if (data.items.isEmpty) {
                return const AppEmptyState(
                  title: '暂无修复资产',
                  message: '当前没有命中筛选条件的修复资产。',
                );
              }

              final activeSessions = data.items
                  .where((item) => (item.activeSessionId ?? '').isNotEmpty)
                  .length;
              final highRiskAssets = data.items
                  .where((item) => item.highestSeverity == RiskSeverityLevel.high || item.highestSeverity == RiskSeverityLevel.critical)
                  .length;

              return Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  GlassPanel(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const SectionHeading(
                          title: '工作台概览',
                          subtitle: '优先看高危资产、活跃会话和具备授权条件的节点。',
                        ),
                        const SizedBox(height: 12),
                        AdaptiveGrid(
                          compactColumns: 2,
                          mediumColumns: 2,
                          expandedColumns: 4,
                          minChildWidth: 130,
                          children: [
                            DetailMetricTile(
                              label: '资产',
                              value: '${data.meta.total}',
                              icon: Icons.dns_rounded,
                              tone: StatusTone.info,
                            ),
                            DetailMetricTile(
                              label: '活跃会话',
                              value: '$activeSessions',
                              icon: Icons.forum_rounded,
                              tone: activeSessions > 0
                                  ? StatusTone.warning
                                  : StatusTone.neutral,
                            ),
                            DetailMetricTile(
                              label: '高危资产',
                              value: '$highRiskAssets',
                              icon: Icons.warning_amber_rounded,
                              tone: highRiskAssets > 0
                                  ? StatusTone.danger
                                  : StatusTone.success,
                            ),
                            DetailMetricTile(
                              label: '页码',
                              value: '${data.meta.page}',
                              icon: Icons.layers_rounded,
                              tone: StatusTone.neutral,
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: 12),
                  ...data.items.map(
                    (asset) => Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: _RemediationAssetCard(
                        asset: asset,
                        onOpen: () => context.push('/remediation/${asset.assetId}'),
                      ),
                    ),
                  ),
                  if (data.meta.total > data.meta.pageSize) ...[
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        OutlinedButton.icon(
                          onPressed: _page > 1
                              ? () => setState(() => _page -= 1)
                              : null,
                          icon: const Icon(Icons.chevron_left_rounded),
                          label: const Text('上一页'),
                        ),
                        const SizedBox(width: 10),
                        Text(
                          '第 ${data.meta.page} 页 / 共 ${((data.meta.total + data.meta.pageSize - 1) / data.meta.pageSize).ceil()} 页',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                        const SizedBox(width: 10),
                        OutlinedButton.icon(
                          onPressed:
                              data.meta.page * data.meta.pageSize < data.meta.total
                                  ? () => setState(() => _page += 1)
                                  : null,
                          icon: const Icon(Icons.chevron_right_rounded),
                          label: const Text('下一页'),
                        ),
                      ],
                    ),
                  ],
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

class RemediationWorkbenchPage extends ConsumerStatefulWidget {
  const RemediationWorkbenchPage({
    super.key,
    required this.assetId,
  });

  final String assetId;

  @override
  ConsumerState<RemediationWorkbenchPage> createState() =>
      _RemediationWorkbenchPageState();
}

class _RemediationWorkbenchPageState
    extends ConsumerState<RemediationWorkbenchPage> {
  final TextEditingController _noteController = TextEditingController();

  RemediationAssetDetailModel? _assetDetail;
  RemediationSessionModel? _session;
  RemediationTaskModel? _task;
  List<String> _taskOutputLines = const [];
  String? _pageError;
  bool _pageLoading = true;
  bool _runnerLoading = false;
  bool _approveLoading = false;
  bool _messageLoading = false;
  bool _sessionStreamHealthy = false;
  bool _taskStreamHealthy = false;
  Timer? _pollTimer;
  WebSocketConnection? _sessionSocket;
  WebSocketConnection? _taskSocket;
  StreamSubscription<dynamic>? _sessionSubscription;
  StreamSubscription<dynamic>? _taskSubscription;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      unawaited(_loadWorkbench(initial: true));
      _startFallbackPolling();
    });
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _noteController.dispose();
    unawaited(_closeStreams());
    super.dispose();
  }

  Future<void> _closeStreams() async {
    await _sessionSubscription?.cancel();
    await _taskSubscription?.cancel();
    await _sessionSocket?.close();
    await _taskSocket?.close();
    _sessionSubscription = null;
    _taskSubscription = null;
    _sessionSocket = null;
    _taskSocket = null;
    _sessionStreamHealthy = false;
    _taskStreamHealthy = false;
  }

  void _startFallbackPolling() {
    _pollTimer?.cancel();
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!mounted) {
        return;
      }
      if (_session != null && !_sessionStreamHealthy) {
        unawaited(_refreshSession(silent: true));
      }
      if (_task != null && !_taskStreamHealthy) {
        unawaited(_refreshTask(silent: true));
      }
    });
  }

  Future<void> _loadWorkbench({bool initial = false}) async {
    if (initial && mounted) {
      setState(() {
        _pageLoading = true;
        _pageError = null;
      });
    }
    try {
      final api = ref.read(apiClientProvider);
      final assetDetail =
          await api.fetchRemediationAsset(widget.assetId);
      final session = assetDetail.activeSessionId != null &&
              assetDetail.activeSessionId!.isNotEmpty
          ? await api.fetchRemediationSession(assetDetail.activeSessionId!)
          : await api.createRemediationSession(widget.assetId);

      RemediationTaskModel? task;
      final taskId = session.lastTaskId ?? assetDetail.latestTaskId;
      if (taskId != null && taskId.isNotEmpty) {
        task = await api.fetchRemediationTask(taskId);
      }

      if (!mounted) {
        return;
      }
      setState(() {
        _assetDetail = assetDetail;
        _session = session;
        _task = task;
        _pageError = null;
        _pageLoading = false;
      });
      await _connectSessionStream();
      if (task != null) {
        await _connectTaskStream(taskId: task.taskId);
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _pageError = describeApiError(error);
        _pageLoading = false;
      });
    }
  }

  Future<void> _refreshSession({bool silent = false}) async {
    final sessionId = _session?.sessionId ?? _assetDetail?.activeSessionId;
    if (sessionId == null || sessionId.isEmpty) {
      return;
    }
    try {
      final latest =
          await ref.read(apiClientProvider).fetchRemediationSession(sessionId);
      if (!mounted) {
        return;
      }
      _applySessionSnapshot(latest);
    } catch (error) {
      if (!silent && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    }
  }

  Future<void> _refreshTask({bool silent = false}) async {
    final taskId = _task?.taskId ?? _session?.lastTaskId ?? _assetDetail?.latestTaskId;
    if (taskId == null || taskId.isEmpty) {
      return;
    }
    try {
      final latest =
          await ref.read(apiClientProvider).fetchRemediationTask(taskId);
      if (!mounted) {
        return;
      }
      setState(() => _task = latest);
    } catch (error) {
      if (!silent && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    }
  }

  Future<void> _connectSessionStream() async {
    final session = _session;
    final token = ref.read(sessionControllerProvider).valueOrNull?.token;
    if (session == null || token == null || token.isEmpty) {
      return;
    }
    await _sessionSubscription?.cancel();
    await _sessionSocket?.close();
    _sessionStreamHealthy = false;

    try {
      final socket =
          await ref.read(webSocketClientProvider).connectAuthenticated(
                uri: buildApiWebSocketUri(
                  '/api/v1/remediation/sessions/${session.sessionId}/stream',
                ),
                token: token,
              );
      socket.pingInterval = const Duration(seconds: 20);
      _sessionSocket = socket;
      _sessionSubscription = socket.stream.listen(
        (data) {
          _sessionStreamHealthy = true;
          _handleSessionStreamFrame(data);
        },
        onError: (_) {
          _sessionStreamHealthy = false;
        },
        onDone: () {
          _sessionStreamHealthy = false;
        },
        cancelOnError: true,
      );
    } catch (_) {
      _sessionStreamHealthy = false;
    }
  }

  Future<void> _connectTaskStream({required String taskId}) async {
    final token = ref.read(sessionControllerProvider).valueOrNull?.token;
    if (token == null || token.isEmpty || taskId.isEmpty) {
      return;
    }
    await _taskSubscription?.cancel();
    await _taskSocket?.close();
    _taskStreamHealthy = false;

    try {
      final socket =
          await ref.read(webSocketClientProvider).connectAuthenticated(
                uri: buildApiWebSocketUri(
                  '/api/v1/remediation/tasks/$taskId/stream',
                ),
                token: token,
              );
      socket.pingInterval = const Duration(seconds: 20);
      _taskSocket = socket;
      _taskSubscription = socket.stream.listen(
        (data) {
          _taskStreamHealthy = true;
          _handleTaskStreamFrame(data);
        },
        onError: (_) {
          _taskStreamHealthy = false;
        },
        onDone: () {
          _taskStreamHealthy = false;
        },
        cancelOnError: true,
      );
    } catch (_) {
      _taskStreamHealthy = false;
    }
  }

  void _handleSessionStreamFrame(dynamic raw) {
    if (raw is! String) {
      return;
    }
    final payload = jsonDecode(raw);
    if (payload is! Map) {
      return;
    }
    final envelope = payload.cast<String, dynamic>();
    switch (envelope['type']) {
      case 'session_snapshot':
        final sessionJson = envelope['session'];
        if (sessionJson is Map<String, dynamic>) {
          _applySessionSnapshot(RemediationSessionModel.fromJson(sessionJson));
        } else if (sessionJson is Map) {
          _applySessionSnapshot(
            RemediationSessionModel.fromJson(
              sessionJson.cast<String, dynamic>(),
            ),
          );
        }
        return;
      case 'session_message_added':
        final messageJson = envelope['message'];
        if (messageJson is Map<String, dynamic> && mounted) {
          final message = RemediationMessageModel.fromJson(messageJson);
          final session = _session;
          if (session == null) {
            return;
          }
          final hasExisting = session.messages.any((item) => item.id == message.id);
          if (hasExisting) {
            return;
          }
          setState(() {
            _session = RemediationSessionModel(
              sessionId: session.sessionId,
              assetId: session.assetId,
              status: session.status,
              asset: session.asset,
              authorization: session.authorization,
              latestCollection: session.latestCollection,
              runner: session.runner,
              findings: session.findings,
              plan: session.plan,
              messages: [...session.messages, message],
              lastTaskId: session.lastTaskId,
              approvedAt: session.approvedAt,
              approvedBy: session.approvedBy,
            );
          });
        }
        return;
      default:
        return;
    }
  }

  void _handleTaskStreamFrame(dynamic raw) {
    if (raw is! String) {
      return;
    }
    final payload = jsonDecode(raw);
    if (payload is! Map) {
      return;
    }
    final envelope = payload.cast<String, dynamic>();
    switch (envelope['type']) {
      case 'task':
        final taskJson = envelope['task'];
        if (taskJson is Map) {
          final current = _task;
          if (current == null || !mounted) {
            return;
          }
          final taskMap = taskJson.cast<String, dynamic>();
          setState(() {
            _task = RemediationTaskModel(
              taskId: current.taskId,
              status: _taskStatusFromWire(taskMap['status'] as String?),
              progress: taskMap['progress'] as int? ?? current.progress,
              message: taskMap['message'] as String? ?? current.message,
              assetId: current.assetId,
              findingId: current.findingId,
              createdAt: current.createdAt,
              startedAt: current.startedAt,
              finishedAt: current.finishedAt,
              eventCount: current.eventCount,
              lastEventAt: current.lastEventAt,
              executionBoundary: current.executionBoundary,
              context: current.context,
              plan: current.plan,
              execution: current.execution,
              backups: current.backups,
              reverify: current.reverify,
            );
          });
        }
        return;
      case 'event':
        final eventJson = envelope['event'];
        if (eventJson is Map) {
          final event = eventJson.cast<String, dynamic>();
          final payloadJson = _coerceMap(event['payload_json']);
          final eventType = event['event_type'] as String? ?? '';
          String line = '';
          if (eventType == 'stream') {
            line = payloadJson['text']?.toString() ?? '';
          } else if (eventType == 'command') {
            line = payloadJson['submitted_command']?.toString() ?? '';
            if (line.isNotEmpty) {
              line = '\$ $line';
            }
          } else {
            final tag = (event['stage_name'] ?? event['event_type'] ?? 'event')
                .toString()
                .trim();
            final message = (event['message'] ?? '').toString().trim();
            line = message.isEmpty ? tag : '[$tag] $message';
          }
          if (line.isNotEmpty && mounted) {
            setState(() {
              _taskOutputLines = [..._taskOutputLines.take(199), line];
            });
          }
        }
        return;
      case 'complete':
        unawaited(_refreshTask(silent: true));
        return;
      default:
        return;
    }
  }

  void _applySessionSnapshot(RemediationSessionModel snapshot) {
    if (!mounted) {
      return;
    }
    setState(() {
      _session = snapshot;
      final current = _assetDetail;
      if (current != null) {
        _assetDetail = RemediationAssetDetailModel(
          asset: snapshot.asset,
          authorization: snapshot.authorization,
          latestCollection: snapshot.latestCollection,
          findings: snapshot.findings,
          runner: snapshot.runner,
          activeSessionId: snapshot.sessionId,
          activeSessionStatus: snapshot.status,
          latestTaskId: snapshot.lastTaskId ?? current.latestTaskId,
          canInstallRunner: current.canInstallRunner,
          runnerInstallBlockedReasons: current.runnerInstallBlockedReasons,
        );
      }
    });
    final nextTaskId = snapshot.lastTaskId;
    if (nextTaskId != null &&
        nextTaskId.isNotEmpty &&
        nextTaskId != _task?.taskId) {
      unawaited(_loadTaskAndStream(nextTaskId));
    }
  }

  Future<void> _loadTaskAndStream(String taskId) async {
    try {
      final task =
          await ref.read(apiClientProvider).fetchRemediationTask(taskId);
      if (!mounted) {
        return;
      }
      setState(() => _task = task);
      await _connectTaskStream(taskId: taskId);
    } catch (_) {
      // Keep the current page state and rely on fallback refresh.
    }
  }

  Future<void> _installRunner() async {
    setState(() => _runnerLoading = true);
    try {
      final response =
          await ref.read(apiClientProvider).installAssetRunner(widget.assetId);
      if (!mounted) {
        return;
      }
      setState(() => _taskOutputLines = const []);
      await _loadTaskAndStream(response.taskId);
      await _loadWorkbench();
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Runner 安装任务已提交：${response.taskId}')),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _runnerLoading = false);
      }
    }
  }

  Future<void> _approveStage() async {
    final session = _session;
    final stage = _approvableStage(session?.plan);
    if (session == null || stage == null) {
      return;
    }
    setState(() => _approveLoading = true);
    try {
      final response = await ref
          .read(apiClientProvider)
          .approveRemediationSession(
            session.sessionId,
            stageCode: stage.stageCode,
          );
      if (!mounted) {
        return;
      }
      setState(() => _taskOutputLines = const []);
      await _loadTaskAndStream(response.taskId);
      await _refreshSession(silent: true);
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('阶段“${stage.stageName}”已提交执行：${response.taskId}')),
      );
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _approveLoading = false);
      }
    }
  }

  Future<void> _postSessionMessage({
    required String intent,
    String? note,
  }) async {
    final sessionId = _session?.sessionId;
    if (sessionId == null || sessionId.isEmpty) {
      return;
    }
    if (intent == 'note' && (note == null || note.trim().isEmpty)) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('请输入备注后再提交。')),
        );
      }
      return;
    }
    setState(() => _messageLoading = true);
    try {
      final latest =
          await ref.read(apiClientProvider).postRemediationSessionMessage(
                sessionId,
                intent: intent,
                note: note,
              );
      if (!mounted) {
        return;
      }
      _applySessionSnapshot(latest);
      if (intent == 'note') {
        _noteController.clear();
      }
    } catch (error) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(describeApiError(error))),
        );
      }
    } finally {
      if (mounted) {
        setState(() => _messageLoading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final session = _session;
    final assetDetail = _assetDetail;
    final task = _task;
    final currentStage = _currentStage(session?.plan);
    final approvableStage = _approvableStage(session?.plan);

    return ScreenScaffold(
      title: '修复工作台',
      subtitle: widget.assetId,
      maxContentWidth: 1120,
      child: AsyncStateView(
        loading: _pageLoading,
        error: _pageError == null ? null : StateError(_pageError!),
        onRetry: () => _loadWorkbench(initial: true),
        child: assetDetail == null || session == null
            ? const AppEmptyState(
                title: '工作台不可用',
                message: '当前未能建立修复会话。',
              )
            : AdaptivePane(
                breakpoint: 980,
                leadingWidth: 360,
                leading: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    _WorkbenchSummaryCard(
                      assetDetail: assetDetail,
                      session: session,
                      task: task,
                      currentStage: currentStage,
                    ),
                    const SizedBox(height: 12),
                    _WorkbenchActionCard(
                      session: session,
                      approvableStage: approvableStage,
                      task: task,
                      runnerLoading: _runnerLoading,
                      approveLoading: _approveLoading,
                      messageLoading: _messageLoading,
                      canInstallRunner: assetDetail.canInstallRunner ||
                          assetDetail.runner.installStatus == 'failed' ||
                          assetDetail.runner.installStatus == 'installing',
                      onRefresh: () => _loadWorkbench(initial: true),
                      onInstallRunner: _installRunner,
                      onApproveStage: _approveStage,
                      onExplainBlockers: () => _postSessionMessage(
                            intent: 'explain_blockers',
                          ),
                      onRefreshAI: () => _postSessionMessage(
                            intent: 'refresh_ai',
                          ),
                    ),
                    const SizedBox(height: 12),
                    _WorkbenchPreconditionCard(
                      assetDetail: assetDetail,
                      onOpenTask: task == null
                          ? null
                          : () => context.push('/tasks/${task.taskId}'),
                    ),
                    const SizedBox(height: 12),
                    _WorkbenchMessagesCard(
                      session: session,
                      controller: _noteController,
                      messageLoading: _messageLoading,
                      onSubmitNote: () => _postSessionMessage(
                        intent: 'note',
                        note: _noteController.text,
                      ),
                    ),
                  ],
                ),
                trailing: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _WorkbenchStagesCard(plan: session.plan),
                    const SizedBox(height: 12),
                    _WorkbenchOutputCard(
                      task: task,
                      outputLines: _taskOutputLines,
                    ),
                    const SizedBox(height: 12),
                    JsonPreviewCard(
                      title: '执行上下文',
                      subtitle: '当前任务保留的上下文、计划和执行摘要。',
                      data: task == null
                          ? const {}
                          : {
                              'context': task.context,
                              'plan': task.plan,
                              'execution': task.execution,
                            },
                      emptyMessage: '当前没有可展示的任务上下文。',
                    ),
                    const SizedBox(height: 12),
                    JsonPreviewCard(
                      title: '备份与复验',
                      subtitle: '查看备份结果和自动复验摘要。',
                      data: task == null
                          ? const {}
                          : {
                              'backups': task.backups,
                              'reverify': task.reverify,
                            },
                      emptyMessage: '当前没有备份或复验字段。',
                    ),
                  ],
                ),
              ),
      ),
    );
  }
}

class _RemediationAssetCard extends StatelessWidget {
  const _RemediationAssetCard({
    required this.asset,
    required this.onOpen,
  });

  final RemediationAssetCardModel asset;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
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
                      asset.ip,
                      style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      '${asset.hostname ?? '未识别主机名'} · ${asset.osName ?? '未识别系统'}',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              FilledButton.icon(
                onPressed: onOpen,
                icon: const Icon(Icons.open_in_new_rounded),
                label: const Text('进入'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              StatusBadge(
                label: asset.status.label,
                tone: toneForAssetStatus(asset.status.name),
              ),
              if (asset.highestSeverity != null)
                StatusBadge(
                  label: asset.highestSeverity!.label,
                  tone: toneForRiskSeverity(asset.highestSeverity!.name),
                ),
              AppInfoChip(
                label: '发现 ${asset.findingCount} 项',
                icon: Icons.security_rounded,
                tone: asset.findingCount > 0
                    ? StatusTone.warning
                    : StatusTone.neutral,
              ),
              AppInfoChip(
                label: _runnerStatusLabel(asset.runnerStatus),
                icon: Icons.memory_rounded,
                tone: _runnerStatusTone(asset.runnerStatus),
              ),
              if ((asset.activeSessionStatus ?? '').isNotEmpty)
                AppInfoChip(
                  label: _workbenchStatusLabel(asset.activeSessionStatus),
                  icon: Icons.forum_rounded,
                  tone: _workbenchStatusTone(asset.activeSessionStatus),
                ),
            ],
          ),
          const SizedBox(height: 12),
          AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 4,
            minChildWidth: 120,
            children: [
              DetailMetricTile(
                label: '权限',
                value: asset.effectivePrivilege ?? '未验证',
                icon: Icons.admin_panel_settings_rounded,
                tone: _privilegeTone(asset.effectivePrivilege),
              ),
              DetailMetricTile(
                label: '最近验证',
                value: formatDateTimeLabel(asset.lastVerifiedAt),
                icon: Icons.verified_user_rounded,
                tone: StatusTone.neutral,
              ),
              DetailMetricTile(
                label: '最近采集',
                value: formatDateTimeLabel(asset.lastCollectionAt),
                icon: Icons.cloud_sync_rounded,
                tone: StatusTone.info,
              ),
              DetailMetricTile(
                label: 'Runner 安装',
                value: _runnerInstallStatusLabel(asset.runnerInstallStatus),
                icon: Icons.download_for_offline_rounded,
                tone: _runnerStatusTone(asset.runnerInstallStatus),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _WorkbenchSummaryCard extends StatelessWidget {
  const _WorkbenchSummaryCard({
    required this.assetDetail,
    required this.session,
    required this.task,
    required this.currentStage,
  });

  final RemediationAssetDetailModel assetDetail;
  final RemediationSessionModel session;
  final RemediationTaskModel? task;
  final HostRemediationStageModel? currentStage;

  @override
  Widget build(BuildContext context) {
    final taskModel = task;
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '工作台概览',
            subtitle: '优先判断当前是否具备授权、Runner 和阶段推进条件。',
          ),
          const SizedBox(height: 12),
          AdaptiveGrid(
            compactColumns: 2,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 132,
            children: [
              DetailMetricTile(
                label: '当前资产',
                value: assetDetail.asset.hostname ?? assetDetail.asset.ip,
                icon: Icons.dns_rounded,
                tone: StatusTone.info,
              ),
              DetailMetricTile(
                label: '工作台状态',
                value: _workbenchStatusLabel(session.status),
                icon: Icons.dashboard_customize_rounded,
                tone: _workbenchStatusTone(session.status),
              ),
              DetailMetricTile(
                label: '当前阶段',
                value: currentStage?.stageName ?? '未生成',
                icon: Icons.alt_route_rounded,
                tone: _stageTone(currentStage?.gateStatus),
              ),
              DetailMetricTile(
                label: '活动任务',
                value: taskModel?.taskId ?? '无',
                icon: Icons.bolt_rounded,
                tone: taskModel == null
                    ? StatusTone.neutral
                    : toneForTaskStatus(taskModel.status.name),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _WorkbenchActionCard extends StatelessWidget {
  const _WorkbenchActionCard({
    required this.session,
    required this.approvableStage,
    required this.task,
    required this.runnerLoading,
    required this.approveLoading,
    required this.messageLoading,
    required this.canInstallRunner,
    required this.onRefresh,
    required this.onInstallRunner,
    required this.onApproveStage,
    required this.onExplainBlockers,
    required this.onRefreshAI,
  });

  final RemediationSessionModel session;
  final HostRemediationStageModel? approvableStage;
  final RemediationTaskModel? task;
  final bool runnerLoading;
  final bool approveLoading;
  final bool messageLoading;
  final bool canInstallRunner;
  final VoidCallback onRefresh;
  final VoidCallback onInstallRunner;
  final VoidCallback onApproveStage;
  final VoidCallback onExplainBlockers;
  final VoidCallback onRefreshAI;

  @override
  Widget build(BuildContext context) {
    final runningTask = task != null &&
        (task!.status == TaskStatusType.pending ||
            task!.status == TaskStatusType.running ||
            task!.status == TaskStatusType.retry);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '核心操作',
            subtitle: approvableStage == null
                ? '当前没有可直接审批的阶段。'
                : '当前可审批阶段：${approvableStage!.stageName}',
          ),
          const SizedBox(height: 12),
          AdaptiveButtonGroup(
            children: [
              FilledButton.icon(
                onPressed: approveLoading || approvableStage == null || runningTask
                    ? null
                    : onApproveStage,
                icon: const Icon(Icons.play_circle_fill_rounded),
                label: Text(approveLoading ? '提交中...' : '审批当前阶段'),
              ),
              OutlinedButton.icon(
                onPressed: runnerLoading || !canInstallRunner ? null : onInstallRunner,
                icon: const Icon(Icons.download_for_offline_rounded),
                label: Text(runnerLoading ? '提交中...' : '安装 Runner'),
              ),
            ],
          ),
          const SizedBox(height: 10),
          AdaptiveButtonGroup(
            children: [
              OutlinedButton.icon(
                onPressed: messageLoading ? null : onExplainBlockers,
                icon: const Icon(Icons.psychology_alt_rounded),
                label: const Text('解释阻塞'),
              ),
              OutlinedButton.icon(
                onPressed: messageLoading ? null : onRefreshAI,
                icon: const Icon(Icons.auto_awesome_rounded),
                label: const Text('刷新 AI'),
              ),
            ],
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: TextButton.icon(
              onPressed: onRefresh,
              icon: const Icon(Icons.refresh_rounded),
              label: const Text('刷新工作台'),
            ),
          ),
        ],
      ),
    );
  }
}

class _WorkbenchPreconditionCard extends StatelessWidget {
  const _WorkbenchPreconditionCard({
    required this.assetDetail,
    required this.onOpenTask,
  });

  final RemediationAssetDetailModel assetDetail;
  final VoidCallback? onOpenTask;

  @override
  Widget build(BuildContext context) {
    final blockedReasons = <String>[
      ...assetDetail.authorization.blockedReasons,
      ...assetDetail.runnerInstallBlockedReasons,
    ];

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '前置条件',
            subtitle: '优先确认 SSH 授权、Runner 状态和最近深度检查。',
            action: onOpenTask == null
                ? null
                : TextButton.icon(
                    onPressed: onOpenTask,
                    icon: const Icon(Icons.open_in_new_rounded, size: 16),
                    label: const Text('查看任务'),
                  ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: assetDetail.authorization.effectivePrivilege ?? '未验证',
                icon: Icons.admin_panel_settings_rounded,
                tone: _privilegeTone(assetDetail.authorization.effectivePrivilege),
              ),
              AppInfoChip(
                label: _runnerStatusLabel(assetDetail.runner.status),
                icon: Icons.memory_rounded,
                tone: _runnerStatusTone(assetDetail.runner.status),
              ),
              AppInfoChip(
                label: _runnerInstallStatusLabel(assetDetail.runner.installStatus),
                icon: Icons.settings_ethernet_rounded,
                tone: _runnerStatusTone(assetDetail.runner.installStatus),
              ),
              AppInfoChip(
                label: formatDateTimeLabel(assetDetail.latestCollection?.collectedAt),
                icon: Icons.schedule_rounded,
                tone: StatusTone.info,
              ),
            ],
          ),
          const SizedBox(height: 12),
          AdaptiveGrid(
            compactColumns: 1,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 180,
            children: [
              DetailMetricTile(
                label: '运行时',
                value: _runnerRuntimeLabel(assetDetail.runner.runtimeKind),
                icon: Icons.terminal_rounded,
              ),
              DetailMetricTile(
                label: '托管方式',
                value: _runnerServiceModeLabel(assetDetail.runner.serviceMode),
                icon: Icons.hub_rounded,
              ),
              DetailMetricTile(
                label: '安装模式',
                value: _runnerInstallModeLabel(assetDetail.runner.installMode),
                icon: Icons.install_desktop_rounded,
              ),
              DetailMetricTile(
                label: '系统架构',
                value: [
                  assetDetail.runner.detectedOs,
                  assetDetail.runner.detectedArch,
                ].whereType<String>().where((item) => item.isNotEmpty).join(' / ').isEmpty
                    ? '未识别'
                    : [
                        assetDetail.runner.detectedOs,
                        assetDetail.runner.detectedArch,
                      ]
                        .whereType<String>()
                        .where((item) => item.isNotEmpty)
                        .join(' / '),
                icon: Icons.developer_board_rounded,
              ),
            ],
          ),
          if (assetDetail.runner.lastError != null &&
              assetDetail.runner.lastError!.isNotEmpty) ...[
            const SizedBox(height: 12),
            Text(
              '最近错误：${assetDetail.runner.lastError}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
          if (assetDetail.runner.compatibilityIssues.isNotEmpty) ...[
            const SizedBox(height: 12),
            ...assetDetail.runner.compatibilityIssues.map(
              (item) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _InlineWarningTile(message: item),
              ),
            ),
          ],
          if (blockedReasons.isNotEmpty) ...[
            const SizedBox(height: 12),
            const SectionHeading(
              title: '阻塞原因',
              subtitle: '先补齐授权链路或 Runner 运行条件，再推进修复。',
            ),
            const SizedBox(height: 10),
            ...blockedReasons.map(
              (item) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _InlineWarningTile(message: item),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _WorkbenchMessagesCard extends StatelessWidget {
  const _WorkbenchMessagesCard({
    required this.session,
    required this.controller,
    required this.messageLoading,
    required this.onSubmitNote,
  });

  final RemediationSessionModel session;
  final TextEditingController controller;
  final bool messageLoading;
  final VoidCallback onSubmitNote;

  @override
  Widget build(BuildContext context) {
    final messages = session.messages.reversed.take(8).toList(growable: false);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: 'AI 与会话消息',
            subtitle: '保留 AI 解读、审计备注和系统事件。',
          ),
          const SizedBox(height: 12),
          TextField(
            controller: controller,
            minLines: 2,
            maxLines: 4,
            decoration: const InputDecoration(
              labelText: '记录备注',
              hintText: '例如：已在现场确认当前端口暴露由临时联调导致。',
            ),
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: FilledButton.icon(
              onPressed: messageLoading ? null : onSubmitNote,
              icon: const Icon(Icons.note_add_rounded),
              label: Text(messageLoading ? '提交中...' : '写入审计备注'),
            ),
          ),
          const SizedBox(height: 12),
          if (messages.isEmpty)
            const AppEmptyState(
              title: '暂无会话消息',
              message: '当前还没有 AI 解读或管理员备注。',
            )
          else
            ...messages.map(
              (message) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _MessageBubble(message: message),
              ),
            ),
        ],
      ),
    );
  }
}

class _WorkbenchStagesCard extends StatelessWidget {
  const _WorkbenchStagesCard({
    required this.plan,
  });

  final HostRemediationPlanModel plan;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '阶段推进',
            subtitle: plan.summaryText.isEmpty ? '当前没有阶段摘要。' : plan.summaryText,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: _planModeLabel(plan.planMode),
                icon: Icons.route_rounded,
                tone: _planModeTone(plan.planMode),
              ),
              AppInfoChip(
                label: '阶段 ${plan.phaseCount}',
                icon: Icons.timeline_rounded,
              ),
              AppInfoChip(
                label: '可执行 ${plan.readyStageCount}',
                icon: Icons.play_circle_outline_rounded,
                tone: StatusTone.success,
              ),
              AppInfoChip(
                label: '阻塞 ${plan.blockedStageCount}',
                icon: Icons.warning_amber_rounded,
                tone: plan.blockedStageCount > 0
                    ? StatusTone.warning
                    : StatusTone.neutral,
              ),
            ],
          ),
          if (plan.blockedReasons.isNotEmpty) ...[
            const SizedBox(height: 12),
            ...plan.blockedReasons.map(
              (item) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _InlineWarningTile(message: item),
              ),
            ),
          ],
          const SizedBox(height: 12),
          if (plan.stages.isEmpty)
            const AppEmptyState(
              title: '暂无阶段',
              message: '当前会话还没有生成可展示的阶段计划。',
            )
          else
            ...plan.stages.map(
              (stage) => Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: _StageCard(stage: stage),
              ),
            ),
        ],
      ),
    );
  }
}

class _WorkbenchOutputCard extends StatelessWidget {
  const _WorkbenchOutputCard({
    required this.task,
    required this.outputLines,
  });

  final RemediationTaskModel? task;
  final List<String> outputLines;

  @override
  Widget build(BuildContext context) {
    final taskModel = task;
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '任务输出',
            subtitle: '保留最近执行状态、输出尾部和调度结果摘要。',
          ),
          const SizedBox(height: 12),
          if (taskModel == null)
            const AppEmptyState(
              title: '暂无任务输出',
              message: '当前还没有进入 Runner 执行或安装任务。',
            )
          else ...[
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                StatusBadge(
                  label: taskModel.status.label,
                  tone: toneForTaskStatus(taskModel.status.name),
                ),
                AppInfoChip(
                  label: '进度 ${taskModel.progress}%',
                  icon: Icons.pie_chart_outline_rounded,
                  tone: toneForTaskStatus(taskModel.status.name),
                ),
                if ((taskModel.executionBoundary ?? '').isNotEmpty)
                  AppInfoChip(
                    label: taskModel.executionBoundary!,
                    icon: Icons.call_split_rounded,
                  ),
                if (taskModel.lastEventAt != null)
                  AppInfoChip(
                    label: formatDateTimeLabel(taskModel.lastEventAt),
                    icon: Icons.schedule_rounded,
                  ),
              ],
            ),
            if ((taskModel.message ?? '').isNotEmpty) ...[
              const SizedBox(height: 10),
              Text(
                taskModel.message!,
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
            const SizedBox(height: 12),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color:
                    Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.03),
                borderRadius: BorderRadius.circular(18),
                border: Border.all(
                  color: Theme.of(context)
                      .colorScheme
                      .onSurface
                      .withValues(alpha: 0.06),
                ),
              ),
              child: outputLines.isEmpty
                  ? Text(
                      '当前还没有收到流式输出，若连接中断会自动回退到定时刷新。',
                      style: Theme.of(context).textTheme.bodySmall,
                    )
                  : SelectableText(
                      outputLines.join('\n'),
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            height: 1.5,
                          ),
                    ),
            ),
          ],
        ],
      ),
    );
  }
}

class _MessageBubble extends StatelessWidget {
  const _MessageBubble({
    required this.message,
  });

  final RemediationMessageModel message;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color:
              Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.06),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  _messageAuthorLabel(message),
                  style: Theme.of(context).textTheme.labelLarge?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
              ),
              StatusBadge(
                label: _messageTypeLabel(message.messageType),
                tone: _messageTypeTone(message.messageType),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            message.content,
            style: Theme.of(context).textTheme.bodySmall,
          ),
          if (message.actions.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: message.actions
                  .map(
                    (action) => AppInfoChip(
                      label: action.label,
                      icon: Icons.touch_app_rounded,
                    ),
                  )
                  .toList(growable: false),
            ),
          ],
        ],
      ),
    );
  }
}

class _StageCard extends StatelessWidget {
  const _StageCard({
    required this.stage,
  });

  final HostRemediationStageModel stage;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.03),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color:
              Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.06),
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
                      stage.stageName,
                      style: Theme.of(context).textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.w800,
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      stage.summary,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 12),
              StatusBadge(
                label: _stageGateLabel(stage.gateStatus),
                tone: _stageTone(stage.gateStatus),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              AppInfoChip(
                label: '可执行 ${stage.readyStepCount}',
                icon: Icons.play_arrow_rounded,
                tone: StatusTone.success,
              ),
              AppInfoChip(
                label: '阻塞 ${stage.blockedStepCount}',
                icon: Icons.block_rounded,
                tone: stage.blockedStepCount > 0
                    ? StatusTone.warning
                    : StatusTone.neutral,
              ),
              if (stage.relatedServices.isNotEmpty)
                AppInfoChip(
                  label: stage.relatedServices.join(' / '),
                  icon: Icons.hub_rounded,
                ),
            ],
          ),
          if (stage.globalBlockers.isNotEmpty) ...[
            const SizedBox(height: 10),
            ...stage.globalBlockers.map(
              (item) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _InlineWarningTile(message: item.message),
              ),
            ),
          ],
          if (stage.steps.isNotEmpty) ...[
            const SizedBox(height: 10),
            ...stage.steps.take(4).map(
              (step) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _StageStepTile(step: step),
              ),
            ),
            if (stage.steps.length > 4)
              Text(
                '还有 ${stage.steps.length - 4} 个步骤未展开。',
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ],
      ),
    );
  }
}

class _StageStepTile extends StatelessWidget {
  const _StageStepTile({
    required this.step,
  });

  final HostRemediationPlanStepModel step;

  @override
  Widget build(BuildContext context) {
    final tone = step.executionState == 'ready'
        ? StatusTone.success
        : StatusTone.warning;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _stepToneColor(context, tone).withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: _stepToneColor(context, tone).withValues(alpha: 0.14),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  step.title,
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                        fontWeight: FontWeight.w800,
                      ),
                ),
              ),
              StatusBadge(
                label: step.executionState == 'ready' ? '可执行' : '阻塞',
                tone: tone,
              ),
            ],
          ),
          const SizedBox(height: 6),
          if ((step.findingTitle ?? '').isNotEmpty)
            Text(
              step.findingTitle!,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          if ((step.blockedReason ?? '').isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              '阻塞：${step.blockedReason}',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
          if ((step.generatedCommand ?? '').isNotEmpty) ...[
            const SizedBox(height: 6),
            Text(
              step.generatedCommand!,
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ],
      ),
    );
  }
}

class _InlineWarningTile extends StatelessWidget {
  const _InlineWarningTile({
    required this.message,
  });

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
          const Icon(
            Icons.info_outline_rounded,
            size: 18,
            color: Color(0xFFC87B1E),
          ),
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

HostRemediationStageModel? _currentStage(HostRemediationPlanModel? plan) {
  if (plan == null || plan.stages.isEmpty) {
    return null;
  }
  if ((plan.currentStageCode ?? '').isNotEmpty) {
    for (final stage in plan.stages) {
      if (stage.stageCode == plan.currentStageCode) {
        return stage;
      }
    }
  }
  for (final stage in plan.stages) {
    if (stage.gateStatus == 'running' || stage.gateStatus == 'ready') {
      return stage;
    }
  }
  return plan.stages.first;
}

HostRemediationStageModel? _approvableStage(HostRemediationPlanModel? plan) {
  if (plan == null) {
    return null;
  }
  for (final stage in plan.stages) {
    if (stage.gateStatus == 'ready') {
      return stage;
    }
  }
  return null;
}

String _runnerStatusLabel(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'online':
      return 'Runner 在线';
    case 'busy':
      return 'Runner 执行中';
    case 'installing':
      return '安装中';
    case 'failed':
      return 'Runner 异常';
    default:
      return 'Runner 未就绪';
  }
}

String _runnerInstallStatusLabel(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'installed':
      return '已安装';
    case 'installing':
      return '安装中';
    case 'failed':
      return '安装失败';
    default:
      return '未安装';
  }
}

String _runnerRuntimeLabel(String? value) {
  switch ((value ?? '').trim().toLowerCase()) {
    case 'shell_bundle':
    case 'bundled_binary':
      return 'Shell Runner';
    case 'python_script':
      return 'Python Runner';
    default:
      return '未识别';
  }
}

String _runnerInstallModeLabel(String? value) {
  switch ((value ?? '').trim().toLowerCase()) {
    case 'system':
      return '系统级';
    case 'user':
      return '用户态';
    default:
      return '未识别';
  }
}

String _runnerServiceModeLabel(String? value) {
  switch ((value ?? '').trim().toLowerCase()) {
    case 'systemd':
      return 'systemd';
    case 'sysvinit':
      return 'SysV init';
    case 'crontab':
      return 'crontab';
    case 'detached':
      return '后台进程';
    default:
      return '未识别';
  }
}

String _workbenchStatusLabel(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'ready':
      return '可执行';
    case 'running':
      return '执行中';
    case 'completed':
      return '已完成';
    case 'failed':
      return '失败';
    case 'canceled':
      return '已中断';
    default:
      return '待准备';
  }
}

String _planModeLabel(String? mode) {
  switch ((mode ?? '').trim().toLowerCase()) {
    case 'ready':
      return '当前阶段可执行';
    case 'partial':
      return '阶段推进中';
    case 'running':
      return '执行中';
    case 'completed':
      return '阶段完成';
    case 'failed':
      return '阶段失败';
    default:
      return '存在阻塞';
  }
}

String _stageGateLabel(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'ready':
      return '可执行';
    case 'running':
      return '执行中';
    case 'completed':
      return '已完成';
    case 'blocked':
      return '阻塞';
    default:
      return '待解锁';
  }
}

String _messageTypeLabel(String value) {
  switch (value) {
    case 'ai_plan_summary':
      return 'AI 计划';
    case 'ai_blocker_analysis':
      return 'AI 阻塞';
    case 'ai_task_failure':
      return 'AI 故障';
    case 'audit':
      return '系统事件';
    case 'note':
      return '备注';
    default:
      return '消息';
  }
}

String _messageAuthorLabel(RemediationMessageModel message) {
  if (message.role == 'assistant' && message.messageType.startsWith('ai_')) {
    return 'AI 解读';
  }
  if (message.role == 'assistant') {
    return '系统记录';
  }
  return '管理员';
}

StatusTone _messageTypeTone(String value) {
  switch (value) {
    case 'ai_plan_summary':
      return StatusTone.info;
    case 'ai_blocker_analysis':
      return StatusTone.warning;
    case 'ai_task_failure':
      return StatusTone.danger;
    case 'audit':
      return StatusTone.warning;
    default:
      return StatusTone.neutral;
  }
}

StatusTone _runnerStatusTone(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'online':
    case 'installed':
      return StatusTone.success;
    case 'busy':
    case 'installing':
      return StatusTone.info;
    case 'failed':
      return StatusTone.danger;
    default:
      return StatusTone.warning;
  }
}

StatusTone _workbenchStatusTone(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'ready':
    case 'completed':
      return StatusTone.success;
    case 'running':
      return StatusTone.info;
    case 'failed':
      return StatusTone.danger;
    case 'canceled':
      return StatusTone.warning;
    default:
      return StatusTone.neutral;
  }
}

StatusTone _planModeTone(String? mode) {
  switch ((mode ?? '').trim().toLowerCase()) {
    case 'ready':
    case 'completed':
      return StatusTone.success;
    case 'running':
    case 'partial':
      return StatusTone.info;
    case 'failed':
      return StatusTone.danger;
    default:
      return StatusTone.warning;
  }
}

StatusTone _stageTone(String? status) {
  switch ((status ?? '').trim().toLowerCase()) {
    case 'ready':
    case 'completed':
      return StatusTone.success;
    case 'running':
      return StatusTone.info;
    case 'blocked':
      return StatusTone.warning;
    default:
      return StatusTone.neutral;
  }
}

StatusTone _privilegeTone(String? value) {
  switch ((value ?? '').trim().toLowerCase()) {
    case 'root':
      return StatusTone.success;
    case 'sudo':
      return StatusTone.info;
    default:
      return StatusTone.warning;
  }
}

Color _stepToneColor(BuildContext context, StatusTone tone) {
  final theme = Theme.of(context);
  return switch (tone) {
    StatusTone.success => const Color(0xFF198754),
    StatusTone.info => theme.colorScheme.primary,
    StatusTone.warning => const Color(0xFFC87B1E),
    StatusTone.danger => const Color(0xFFB42318),
    StatusTone.neutral => theme.colorScheme.primary,
  };
}

Map<String, dynamic> _coerceMap(Object? raw) {
  if (raw is Map<String, dynamic>) {
    return raw;
  }
  if (raw is Map) {
    return raw.cast<String, dynamic>();
  }
  return const {};
}

TaskStatusType _taskStatusFromWire(String? value) {
  switch ((value ?? '').trim().toLowerCase()) {
    case 'pending':
      return TaskStatusType.pending;
    case 'running':
      return TaskStatusType.running;
    case 'retry':
      return TaskStatusType.retry;
    case 'success':
      return TaskStatusType.success;
    case 'failure':
      return TaskStatusType.failure;
    case 'canceled':
      return TaskStatusType.canceled;
    default:
      return TaskStatusType.unknown;
  }
}
