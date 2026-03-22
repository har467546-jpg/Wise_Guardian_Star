import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../shared/models/agent_models.dart';
import '../../shared/models/app_models.dart';
import 'haor_runtime.dart';

final haorAssistantOpenProvider = StateProvider<bool>((ref) => false);

class MobileHaorAssistantLauncher extends ConsumerStatefulWidget {
  const MobileHaorAssistantLauncher({
    super.key,
    required this.routeUri,
    required this.screenTitle,
    this.screenSubtitle,
  });

  final Uri routeUri;
  final String screenTitle;
  final String? screenSubtitle;

  @override
  ConsumerState<MobileHaorAssistantLauncher> createState() =>
      _MobileHaorAssistantLauncherState();
}

class _MobileHaorAssistantLauncherState
    extends ConsumerState<MobileHaorAssistantLauncher> {
  final ScrollController _feedController = ScrollController();
  final TextEditingController _inputController = TextEditingController();
  final Set<String> _ignoredTurnIds = <String>{};
  final Set<String> _ignoredClientMessageIds = <String>{};
  final Map<String, String> _turnPhases = <String, String>{};

  StreamSubscription<dynamic>? _socketSubscription;
  WebSocket? _socket;
  Timer? _reconnectTimer;
  bool _providerOpen = false;
  int _reconnectAttempts = 0;
  String? _executingPendingTurnId;
  String? _activeTurnId;
  AgentSession? _session;
  TaskRunModel? _task;
  List<TaskEventModel> _taskEvents = const [];
  List<_PendingUserMessage> _pendingUserMessages = const [];
  List<_StreamFeedItem> _streamFeed = const [];
  _PendingUiRequest? _pendingUiRequest;
  _DraftAssistantMessage? _draftAssistantMessage;
  _AssistantPlaceholder? _assistantPlaceholder;
  bool _loading = false;
  bool _sending = false;
  bool _stepping = false;
  bool _approving = false;
  bool _interrupting = false;
  bool _resetting = false;
  String? _errorText;
  String? _streamError;
  _ConnectionState _connectionState = _ConnectionState.disconnected;

  AgentPageContext get _pageContext => buildAgentPageContext(widget.routeUri);

  AgentBrowserContext _browserContextFor(
    Uri uri, {
    String? title,
    String? subtitle,
  }) {
    return buildMobileHaorBrowserContext(
      uri: uri,
      title: title ?? widget.screenTitle,
      subtitle: subtitle ?? widget.screenSubtitle,
      origin: configuredApiBaseUrl,
    );
  }

  AgentBrowserContext get _browserContext =>
      _browserContextFor(widget.routeUri, title: widget.screenTitle);

  bool get _isAdmin =>
      ref.read(sessionControllerProvider).valueOrNull?.role == AppRole.admin;

  bool get _showInterrupt {
    final sessionStatus = _normalizeStatus(_session?.status);
    return sessionStatus == 'running' &&
        (_session?.lastTaskId ?? '').isNotEmpty;
  }

  bool get _hasAttention {
    final sessionStatus = _normalizeStatus(_session?.status);
    final pendingUi = _pendingUiActions.isNotEmpty;
    return sessionStatus == 'waiting_approval' ||
        sessionStatus == 'running' ||
        pendingUi;
  }

  bool get _composerLocked =>
      _sending || _stepping || _approving || _interrupting || _resetting;

  bool get _sendDisabled =>
      _composerLocked || _normalizeStatus(_task?.status.name) == 'running';

  List<AgentProposedAction> get _proposedActions {
    final raw = _session?.pendingPlanJson['proposed_write_actions'];
    if (raw is! List) {
      return const [];
    }
    return raw
        .whereType<Map>()
        .map((item) =>
            AgentProposedAction.fromJson(item.cast<String, dynamic>()))
        .toList(growable: false);
  }

  List<AgentUIAction> get _pendingUiActions {
    if (_pendingUiRequest != null) {
      return _pendingUiRequest!.uiActions;
    }
    final raw = _session?.browserRuntimeJson['pending_ui_actions'];
    if (raw is! List) {
      return const [];
    }
    return raw
        .whereType<Map>()
        .map((item) => AgentUIAction.fromJson(item.cast<String, dynamic>()))
        .toList(growable: false);
  }

  @override
  void initState() {
    super.initState();
    unawaited(_loadSession());
  }

  @override
  void didUpdateWidget(covariant MobileHaorAssistantLauncher oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.routeUri.toString() != widget.routeUri.toString() &&
        _connectionState == _ConnectionState.connected) {
      _sendHello();
    }
  }

  @override
  void dispose() {
    _closeSocket();
    _feedController.dispose();
    _inputController.dispose();
    _reconnectTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadSession({bool silent = false}) async {
    try {
      if (!silent && mounted) {
        setState(() => _loading = true);
      }
      final session = await ref.read(apiClientProvider).fetchHaorSession();
      if (!mounted) {
        return;
      }
      setState(() {
        _session = session;
        _errorText = null;
        _pendingUserMessages = _reconcilePendingUserMessages(
            _pendingUserMessages, session.messages);
      });
      if ((session.lastTaskId ?? '').isNotEmpty) {
        await _loadTask(session.lastTaskId!, silent: true);
      } else if (mounted) {
        setState(() {
          _task = null;
          _taskEvents = const [];
        });
      }
    } catch (error) {
      if (mounted && !silent) {
        setState(() {
          _errorText = describeApiError(error);
        });
      }
    } finally {
      if (mounted && !silent) {
        setState(() => _loading = false);
      }
    }
  }

  Future<void> _loadTask(
    String taskId, {
    bool silent = false,
  }) async {
    try {
      final results = await Future.wait<Object>([
        ref.read(apiClientProvider).fetchTask(taskId),
        ref.read(apiClientProvider).fetchTaskEvents(taskId),
      ]);
      if (!mounted) {
        return;
      }
      setState(() {
        _task = results[0] as TaskRunModel;
        _taskEvents = (results[1] as TaskEventListPayload).items;
        if (!silent) {
          _errorText = null;
        }
      });
    } catch (error) {
      if (!mounted || silent) {
        return;
      }
      setState(() {
        _errorText = describeApiError(error);
      });
    }
  }

  void _handleProviderOpenChange(bool open) {
    if (_providerOpen == open) {
      return;
    }
    _providerOpen = open;
    if (open) {
      _openAssistant();
      return;
    }
    _closeAssistant();
  }

  void _openAssistant() {
    _errorText = null;
    _streamError = null;
    _connectSocket();
    _sendHello();
  }

  void _closeAssistant() {
    _ignoredTurnIds.clear();
    _ignoredClientMessageIds.clear();
    _draftAssistantMessage = null;
    _assistantPlaceholder = null;
    _pendingUiRequest = null;
    _streamFeed = const [];
    _pendingUserMessages = const [];
    _activeTurnId = null;
    _sending = false;
    _stepping = false;
    _approving = false;
    _closeSocket();
    if (mounted) {
      setState(() {});
    }
  }

  Future<void> _connectSocket() async {
    if (!_providerOpen || _socket != null) {
      return;
    }
    final token = ref.read(sessionControllerProvider).valueOrNull?.token;
    if (token == null || token.isEmpty) {
      if (mounted) {
        setState(() {
          _streamError = '登录状态已失效，请重新登录';
          _connectionState = _ConnectionState.disconnected;
        });
      }
      return;
    }

    if (mounted) {
      setState(() {
        _connectionState = _ConnectionState.connecting;
      });
    }

    try {
      final socket = await WebSocket.connect(buildHaorSessionStreamUrl(token));
      if (!_providerOpen) {
        await socket.close();
        return;
      }
      _socket = socket;
      _reconnectAttempts = 0;
      _socketSubscription = socket.listen(
        _handleSocketData,
        onError: (_) {
          if (!mounted) {
            return;
          }
          setState(() {
            _streamError = 'haor 流式连接异常，正在尝试恢复';
          });
        },
        onDone: _handleSocketDone,
        cancelOnError: false,
      );
      if (mounted) {
        setState(() {
          _connectionState = _ConnectionState.connected;
          _streamError = null;
        });
      }
      _sendHello();
    } catch (_) {
      if (!mounted) {
        return;
      }
      setState(() {
        _streamError = 'haor 流式连接异常，正在尝试恢复';
        _connectionState = _ConnectionState.connecting;
      });
      _scheduleReconnect();
    }
  }

  void _closeSocket() {
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _socket?.close();
    _socket = null;
    _connectionState = _ConnectionState.disconnected;
  }

  void _scheduleReconnect() {
    if (!_providerOpen) {
      return;
    }
    _reconnectTimer?.cancel();
    _reconnectAttempts += 1;
    final delay = Duration(
      milliseconds: min(1000 * _reconnectAttempts, 4000),
    );
    _reconnectTimer = Timer(delay, () {
      _reconnectTimer = null;
      unawaited(_connectSocket());
    });
  }

  void _handleSocketDone() {
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _socket = null;
    if (!mounted) {
      return;
    }
    setState(() {
      _connectionState = _providerOpen
          ? _ConnectionState.connecting
          : _ConnectionState.disconnected;
      _streamError = _providerOpen ? 'haor 流式连接已断开，正在尝试恢复' : null;
      _draftAssistantMessage = null;
      _assistantPlaceholder = null;
      _pendingUiRequest = null;
      _pendingUserMessages =
          _markPendingUserMessagesFailed(_pendingUserMessages);
    });
    if (_providerOpen) {
      _scheduleReconnect();
    }
  }

  void _handleSocketData(dynamic event) {
    try {
      final payload = jsonDecode(event as String);
      if (payload is! Map) {
        throw const FormatException('invalid payload');
      }
      _handleStreamEvent(payload.cast<String, dynamic>());
    } catch (_) {
      if (!mounted) {
        return;
      }
      setState(() {
        _streamError = 'haor 流式数据解析失败';
      });
    }
  }

  void _handleStreamEvent(Map<String, dynamic> payload) {
    final type = payload['type'] as String? ?? '';
    switch (type) {
      case 'session_snapshot':
        final rawSession = payload['session'];
        if (rawSession is! Map) {
          return;
        }
        final nextSession =
            AgentSession.fromJson(rawSession.cast<String, dynamic>());
        setState(() {
          _session = nextSession;
          _loading = false;
          _errorText = null;
          _streamError = null;
          _pendingUserMessages = _reconcilePendingUserMessages(
              _pendingUserMessages, nextSession.messages);
          if (_pendingUiActions.isEmpty) {
            _pendingUiRequest = null;
          }
        });
        if ((nextSession.lastTaskId ?? '').isNotEmpty) {
          unawaited(_loadTask(nextSession.lastTaskId!, silent: true));
        } else {
          setState(() {
            _task = null;
            _taskEvents = const [];
          });
        }
        break;
      case 'turn_started':
        final turnId = payload['turn_id'] as String? ?? '';
        final phase = payload['phase'] as String? ?? '';
        final clientMessageId = payload['client_message_id'] as String?;
        if (_ignoredTurnIds.contains(turnId) ||
            (clientMessageId != null &&
                _ignoredClientMessageIds.contains(clientMessageId))) {
          _ignoredTurnIds.add(turnId);
          return;
        }
        _turnPhases[turnId] = phase;
        setState(() {
          _activeTurnId = turnId;
          if (phase == 'message') {
            _sending = true;
            _draftAssistantMessage = null;
            _assistantPlaceholder = _AssistantPlaceholder(
              key: clientMessageId ?? turnId,
              badge: '生成中',
              content: '正在生成...',
            );
          } else if (phase == 'ui_step') {
            _stepping = true;
            _assistantPlaceholder = const _AssistantPlaceholder(
              key: 'ui-step',
              badge: '处理中',
              content: '正在继续处理当前请求...',
              tone: _BubbleTone.action,
            );
          } else if (phase == 'approve') {
            _approving = true;
            _assistantPlaceholder = const _AssistantPlaceholder(
              key: 'approve-step',
              badge: '处理中',
              content: '正在提交计划并启动任务...',
              tone: _BubbleTone.action,
            );
          }
        });
        break;
      case 'assistant_message_start':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.contains(turnId)) {
          return;
        }
        setState(() {
          _draftAssistantMessage = _DraftAssistantMessage(
            turnId: turnId,
            messageType: payload['message_type'] as String? ?? 'text',
            content: '',
          );
        });
        break;
      case 'assistant_message_delta':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.contains(turnId)) {
          return;
        }
        final delta = payload['delta'] as String? ?? '';
        setState(() {
          final current = _draftAssistantMessage;
          if (current == null || current.turnId != turnId) {
            _draftAssistantMessage = _DraftAssistantMessage(
              turnId: turnId,
              messageType: 'text',
              content: delta,
            );
          } else {
            _draftAssistantMessage = current.copyWith(
              content: '${current.content}$delta',
            );
          }
        });
        break;
      case 'assistant_message_done':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.remove(turnId)) {
          return;
        }
        final rawMessage = payload['message'];
        if (rawMessage is! Map) {
          return;
        }
        final message =
            AgentMessage.fromJson(rawMessage.cast<String, dynamic>());
        setState(() {
          _assistantPlaceholder = null;
          _draftAssistantMessage = null;
          _session = _upsertSessionMessage(_session, message);
          _pendingUserMessages = _reconcilePendingUserMessages(
              _pendingUserMessages, _session?.messages ?? const []);
        });
        break;
      case 'action_update':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.contains(turnId)) {
          return;
        }
        final rawMessage = payload['message'];
        if (rawMessage is Map) {
          final message =
              AgentMessage.fromJson(rawMessage.cast<String, dynamic>());
          setState(() {
            _session = _upsertSessionMessage(_session, message);
          });
        } else {
          setState(() {
            _streamFeed = [
              ..._streamFeed,
              _StreamFeedItem(
                id: 'action-$turnId-${DateTime.now().microsecondsSinceEpoch}',
                badge: '动作',
                content: payload['content'] as String? ?? '',
                time: DateTime.now(),
                tone: _BubbleTone.action,
              ),
            ];
          });
        }
        break;
      case 'ui_actions_requested':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.contains(turnId)) {
          return;
        }
        final rawActions = payload['ui_actions'] as List<dynamic>? ?? const [];
        setState(() {
          _pendingUiRequest = _PendingUiRequest(
            turnId: turnId,
            uiActions: rawActions
                .whereType<Map>()
                .map((item) =>
                    AgentUIAction.fromJson(item.cast<String, dynamic>()))
                .toList(growable: false),
            content: payload['content'] as String?,
          );
          _assistantPlaceholder = const _AssistantPlaceholder(
            key: 'ui-request',
            badge: '处理中',
            content: '正在继续处理当前请求...',
            tone: _BubbleTone.action,
          );
        });
        break;
      case 'plan_pending':
        final turnId = payload['turn_id'] as String? ?? '';
        if (_ignoredTurnIds.contains(turnId)) {
          return;
        }
        final rawMessage = payload['message'];
        if (rawMessage is! Map) {
          return;
        }
        final nextMessage =
            AgentMessage.fromJson(rawMessage.cast<String, dynamic>());
        setState(() {
          _assistantPlaceholder = null;
          final updated = _upsertSessionMessage(_session, nextMessage);
          if (updated != null) {
            _session = AgentSession(
              sessionId: updated.sessionId,
              agentId: updated.agentId,
              status: 'waiting_approval',
              routeContextJson: updated.routeContextJson,
              workingContextJson: updated.workingContextJson,
              dialogStateJson: updated.dialogStateJson,
              pendingPlanJson: (payload['pending_plan_json'] is Map)
                  ? (payload['pending_plan_json'] as Map)
                      .cast<String, dynamic>()
                  : updated.pendingPlanJson,
              browserRuntimeJson: updated.browserRuntimeJson,
              lastTaskId: updated.lastTaskId,
              messages: updated.messages,
              createdAt: updated.createdAt,
              updatedAt: updated.updatedAt,
            );
          }
        });
        break;
      case 'task_update':
        final taskId = payload['task_id'] as String? ?? '';
        if (taskId.isNotEmpty) {
          unawaited(_loadTask(taskId, silent: true));
        }
        break;
      case 'error':
        final turnId = payload['turn_id'] as String?;
        if (turnId != null && _ignoredTurnIds.remove(turnId)) {
          return;
        }
        final rawMessage = payload['message'];
        setState(() {
          _assistantPlaceholder = null;
          _pendingUserMessages =
              _markPendingUserMessagesFailed(_pendingUserMessages);
          _errorText = payload['detail'] as String? ?? '处理失败';
          if (rawMessage is Map) {
            _session = _upsertSessionMessage(
              _session,
              AgentMessage.fromJson(rawMessage.cast<String, dynamic>()),
            );
          } else {
            _streamFeed = [
              ..._streamFeed,
              _StreamFeedItem(
                id: 'error-${DateTime.now().microsecondsSinceEpoch}',
                badge: '错误',
                content: _errorText!,
                time: DateTime.now(),
                tone: _BubbleTone.error,
              ),
            ];
          }
        });
        break;
      case 'turn_done':
        final turnId = payload['turn_id'] as String? ?? '';
        final phase = _turnPhases.remove(turnId);
        if (_ignoredTurnIds.remove(turnId)) {
          return;
        }
        setState(() {
          if (phase == 'message') {
            _sending = false;
          } else if (phase == 'ui_step') {
            _stepping = false;
          } else if (phase == 'approve') {
            _approving = false;
          }
          if (_activeTurnId == turnId) {
            _activeTurnId = null;
          }
          _assistantPlaceholder = null;
          _draftAssistantMessage = null;
        });
        break;
      default:
        return;
    }
    _scheduleScrollToBottom();
  }

  void _sendHello() {
    _sendSocketFrame({
      'type': 'hello',
      'page_context': _pageContext.toJson(),
      'browser_context': _browserContext.toJson(),
    });
  }

  bool _sendSocketFrame(Map<String, dynamic> frame) {
    if (_socket == null || _socket!.readyState != WebSocket.open) {
      return false;
    }
    _socket!.add(jsonEncode(frame));
    return true;
  }

  Future<void> _handleSend() async {
    final content = _inputController.text.trim();
    if (content.isEmpty) {
      return;
    }
    final clientMessageId =
        'haor-${DateTime.now().microsecondsSinceEpoch}-${Random().nextInt(999999)}';
    final pendingMessage = _PendingUserMessage(
      clientMessageId: clientMessageId,
      content: content,
      createdAt: DateTime.now(),
      status: _PendingUserMessageStatus.sending,
    );
    if (mounted) {
      setState(() {
        _sending = true;
        _pendingUserMessages = [..._pendingUserMessages, pendingMessage];
        _assistantPlaceholder = _AssistantPlaceholder(
          key: clientMessageId,
          badge: '生成中',
          content: '正在生成...',
        );
        _inputController.clear();
        _errorText = null;
        _streamError = null;
      });
    }

    final usedSocket = _sendSocketFrame({
      'type': 'message',
      'client_message_id': clientMessageId,
      'content': content,
      'page_context': _pageContext.toJson(),
      'browser_context': _browserContext.toJson(),
    });

    if (usedSocket) {
      _scheduleScrollToBottom();
      return;
    }

    try {
      final session = await ref.read(apiClientProvider).postHaorMessage(
            clientMessageId: clientMessageId,
            content: content,
            pageContext: _pageContext,
            browserContext: _browserContext,
          );
      if (!mounted) {
        return;
      }
      setState(() {
        _session = session;
        _sending = false;
        _assistantPlaceholder = _pendingUiActions.isNotEmpty
            ? const _AssistantPlaceholder(
                key: 'http-followup',
                badge: '处理中',
                content: '正在继续处理当前请求...',
                tone: _BubbleTone.action,
              )
            : null;
        _pendingUserMessages = _reconcilePendingUserMessages(
            _pendingUserMessages, session.messages);
      });
      if ((session.lastTaskId ?? '').isNotEmpty) {
        unawaited(_loadTask(session.lastTaskId!, silent: true));
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _sending = false;
        _assistantPlaceholder = null;
        _errorText = describeApiError(error);
        _pendingUserMessages = _pendingUserMessages
            .map(
              (item) => item.clientMessageId == clientMessageId
                  ? item.copyWith(status: _PendingUserMessageStatus.failed)
                  : item,
            )
            .toList(growable: false);
      });
    }
    _scheduleScrollToBottom();
  }

  Future<void> _handleApprove() async {
    final usedSocket = _sendSocketFrame({'type': 'approve_plan'});
    if (usedSocket) {
      if (mounted) {
        setState(() {
          _approving = true;
          _errorText = null;
        });
      }
      return;
    }
    try {
      if (mounted) {
        setState(() => _approving = true);
      }
      final result = await ref.read(apiClientProvider).approveHaorSession();
      await _loadSession(silent: true);
      await _loadTask(result.taskId, silent: true);
      if (!mounted) {
        return;
      }
      setState(() {
        _approving = false;
        _errorText = null;
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _approving = false;
        _errorText = describeApiError(error);
      });
    }
  }

  Future<void> _handleInterrupt() async {
    try {
      if (mounted) {
        setState(() => _interrupting = true);
      }
      final session = await ref.read(apiClientProvider).interruptHaorSession();
      if (!mounted) {
        return;
      }
      setState(() {
        _session = session;
        _interrupting = false;
        _errorText = null;
      });
      if ((session.lastTaskId ?? '').isNotEmpty) {
        await _loadTask(session.lastTaskId!, silent: true);
      } else if (mounted) {
        setState(() {
          _task = null;
          _taskEvents = const [];
        });
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _interrupting = false;
        _errorText = describeApiError(error);
      });
    }
  }

  Future<void> _handleReset() async {
    try {
      if (mounted) {
        setState(() => _resetting = true);
      }
      final session = await ref.read(apiClientProvider).resetHaorSession();
      if (!mounted) {
        return;
      }
      if (_activeTurnId != null) {
        _ignoredTurnIds.add(_activeTurnId!);
      }
      for (final item in _pendingUserMessages) {
        _ignoredClientMessageIds.add(item.clientMessageId);
      }
      setState(() {
        _session = session;
        _task = null;
        _taskEvents = const [];
        _pendingUserMessages = const [];
        _streamFeed = const [];
        _pendingUiRequest = null;
        _draftAssistantMessage = null;
        _assistantPlaceholder = null;
        _activeTurnId = null;
        _sending = false;
        _stepping = false;
        _approving = false;
        _resetting = false;
        _errorText = null;
        _streamError = null;
        _inputController.clear();
      });
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _resetting = false;
        _errorText = describeApiError(error);
      });
    }
  }

  Future<void> _runPendingUiActions() async {
    final request = _pendingUiRequest;
    if (request == null || _executingPendingTurnId == request.turnId) {
      return;
    }
    _executingPendingTurnId = request.turnId;
    try {
      if (mounted) {
        setState(() => _stepping = true);
      }
      final currentContext = _browserContext;
      final results = await executeMobileHaorActions(
        actions: request.uiActions,
        browserContext: currentContext,
        apiClient: ref.read(apiClientProvider),
      );
      final nextPath = _extractNextPath(results);
      final stepContext = nextPath == null
          ? currentContext
          : _browserContextFor(
              Uri.parse(nextPath),
              title: resolveHaorScreenTitle(Uri.parse(nextPath)),
            );

      final usedSocket = _sendSocketFrame({
        'type': 'ui_step',
        'browser_context': stepContext.toJson(),
        'ui_action_results': results.map((item) => item.toJson()).toList(),
      });

      if (!usedSocket) {
        final session = await ref.read(apiClientProvider).postHaorStep(
              browserContext: stepContext,
              uiActionResults: results,
            );
        if (mounted) {
          setState(() {
            _session = session;
            _pendingUiRequest = null;
            _assistantPlaceholder = _pendingUiActions.isNotEmpty
                ? const _AssistantPlaceholder(
                    key: 'ui-chain',
                    badge: '处理中',
                    content: '正在继续处理当前请求...',
                    tone: _BubbleTone.action,
                  )
                : null;
          });
        }
        if ((session.lastTaskId ?? '').isNotEmpty) {
          unawaited(_loadTask(session.lastTaskId!, silent: true));
        }
      } else if (mounted) {
        setState(() {
          _pendingUiRequest = null;
        });
      }

      if (nextPath != null && mounted) {
        GoRouter.of(context).go(nextPath);
      }
    } catch (error) {
      if (!mounted) {
        return;
      }
      setState(() {
        _assistantPlaceholder = null;
        _errorText = describeApiError(error);
      });
    } finally {
      _executingPendingTurnId = null;
      if (mounted) {
        setState(() => _stepping = false);
      }
    }
  }

  String? _extractNextPath(List<AgentUIActionResult> results) {
    for (final item in results.reversed) {
      final nextPath = item.detailJson['next_path'];
      if (nextPath is String && nextPath.trim().isNotEmpty) {
        return nextPath.trim();
      }
    }
    return null;
  }

  void _scheduleScrollToBottom() {
    if (!_providerOpen) {
      return;
    }
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || !_feedController.hasClients) {
        return;
      }
      _feedController.animateTo(
        _feedController.position.maxScrollExtent + 120,
        duration: const Duration(milliseconds: 220),
        curve: Curves.easeOut,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    final mediaQuery = MediaQuery.of(context);
    final screenSize = mediaQuery.size;
    final viewInsets = mediaQuery.viewInsets;
    final isCompactWidth = screenSize.width < 520;
    final feedHorizontalPadding = isCompactWidth ? 12.0 : 16.0;
    final sheetMaxHeight = isCompactWidth
        ? screenSize.height - 18
        : min(screenSize.height * 0.88, screenSize.height - 24);

    final open = ref.watch(haorAssistantOpenProvider);
    if (open != _providerOpen) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          _handleProviderOpenChange(open);
        }
      });
    }

    if (open &&
        _pendingUiRequest != null &&
        !_stepping &&
        !_sending &&
        !_approving &&
        !_interrupting &&
        !_resetting) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          unawaited(_runPendingUiActions());
        }
      });
    }

    final activityBannerText = _buildActivityBannerText();
    final visiblePendingMessages = _reconcilePendingUserMessages(
        _pendingUserMessages, _session?.messages ?? const []);
    final pendingPlanMessageId = _findPendingPlanMessageId(
      _session?.messages ?? const [],
      _proposedActions,
    );
    final pendingPlanDetails = _buildPendingPlanDetails(_proposedActions);
    final taskDigest =
        _task == null ? '' : _buildTaskDigest(_task!, _taskEvents);

    return Stack(
      children: [
        Positioned(
          left: 16,
          bottom: 18,
          child: SafeArea(
            top: false,
            child: _HaorFab(
              active: open,
              showBadge: _hasAttention,
              onTap: () =>
                  ref.read(haorAssistantOpenProvider.notifier).state = true,
            ),
          ),
        ),
        if (open)
          Positioned.fill(
            child: Material(
              color: Colors.black.withValues(alpha: 0.35),
              child: SafeArea(
                minimum: const EdgeInsets.all(12),
                child: Stack(
                  children: [
                    Positioned.fill(
                      child: GestureDetector(
                        onTap: () => ref
                            .read(haorAssistantOpenProvider.notifier)
                            .state = false,
                        behavior: HitTestBehavior.opaque,
                        child: const SizedBox.expand(),
                      ),
                    ),
                    AnimatedPadding(
                      duration: const Duration(milliseconds: 180),
                      curve: Curves.easeOut,
                      padding: EdgeInsets.only(bottom: viewInsets.bottom),
                      child: Align(
                        alignment: Alignment.bottomCenter,
                        child: ConstrainedBox(
                          constraints: BoxConstraints(
                            maxWidth: 980,
                            maxHeight: sheetMaxHeight,
                          ),
                          child: Container(
                            width: double.infinity,
                            decoration: BoxDecoration(
                              color: Theme.of(context).colorScheme.surface,
                              borderRadius: BorderRadius.circular(
                                  isCompactWidth ? 24 : 28),
                              boxShadow: [
                                BoxShadow(
                                  color: Colors.black.withValues(alpha: 0.22),
                                  blurRadius: 28,
                                  offset: const Offset(0, 10),
                                ),
                              ],
                            ),
                            child: Column(
                              children: [
                                Padding(
                                  padding: EdgeInsets.fromLTRB(
                                    feedHorizontalPadding,
                                    12,
                                    feedHorizontalPadding,
                                    8,
                                  ),
                                  child: Row(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      const Expanded(
                                        child: Column(
                                          crossAxisAlignment:
                                              CrossAxisAlignment.start,
                                          children: [
                                            Text(
                                              'Chat Assistant',
                                              style: TextStyle(
                                                fontSize: 11,
                                                fontWeight: FontWeight.w700,
                                                letterSpacing: 0.3,
                                              ),
                                            ),
                                            SizedBox(height: 2),
                                            Text(
                                              'haor',
                                              style: TextStyle(
                                                fontSize: 20,
                                                fontWeight: FontWeight.w900,
                                              ),
                                            ),
                                          ],
                                        ),
                                      ),
                                      const SizedBox(width: 12),
                                      Column(
                                        crossAxisAlignment:
                                            CrossAxisAlignment.end,
                                        children: [
                                          Row(
                                            mainAxisSize: MainAxisSize.min,
                                            children: [
                                              if (_showInterrupt)
                                                _HeaderIconButton(
                                                  icon: Icons
                                                      .stop_circle_outlined,
                                                  tooltip: '中断任务',
                                                  onPressed: _interrupting
                                                      ? null
                                                      : _handleInterrupt,
                                                ),
                                              _HeaderIconButton(
                                                icon: Icons.refresh_rounded,
                                                tooltip: '新会话',
                                                onPressed: _resetting
                                                    ? null
                                                    : _handleReset,
                                              ),
                                              _HeaderIconButton(
                                                icon: Icons.close_rounded,
                                                tooltip: '关闭',
                                                onPressed: () => ref
                                                    .read(
                                                      haorAssistantOpenProvider
                                                          .notifier,
                                                    )
                                                    .state = false,
                                              ),
                                            ],
                                          ),
                                          const SizedBox(height: 6),
                                          _StatusPill(
                                            label: _statusLabel(
                                              _session?.status,
                                            ),
                                          ),
                                        ],
                                      ),
                                    ],
                                  ),
                                ),
                                const Divider(height: 1),
                                Expanded(
                                  child: ListView(
                                    controller: _feedController,
                                    padding: EdgeInsets.fromLTRB(
                                      feedHorizontalPadding,
                                      10,
                                      feedHorizontalPadding,
                                      14,
                                    ),
                                    children: [
                                      if (activityBannerText != null)
                                        _ActivityBanner(
                                          message: activityBannerText,
                                          isError: (_errorText ?? '')
                                                  .isNotEmpty ||
                                              (_streamError ?? '').isNotEmpty,
                                        ),
                                      if (_loading &&
                                          (_session?.messages.isEmpty ?? true))
                                        const _EmptyCard(
                                          title: '正在恢复会话',
                                          message: 'haor 正在同步最近的聊天记录和任务状态。',
                                        ),
                                      if (!_loading &&
                                          (_session?.messages.isEmpty ??
                                              true) &&
                                          _proposedActions.isEmpty &&
                                          _task == null)
                                        const _EmptyCard(
                                          title: '开始聊天',
                                          message:
                                              '直接像聊天一样提问，或告诉 haor 你想在站内执行什么操作。',
                                        ),
                                      for (final message
                                          in _session?.messages ??
                                              const <AgentMessage>[])
                                        _ChatBubble(
                                          role: message.role == 'user'
                                              ? _BubbleRole.user
                                              : _BubbleRole.assistant,
                                          badge: _messageBadge(message),
                                          time: _formatChatTime(
                                              message.createdAt),
                                          content:
                                              pendingPlanMessageId == message.id
                                                  ? _joinSections([
                                                      message.content,
                                                      pendingPlanDetails,
                                                    ])
                                                  : message.content,
                                          tone: _messageTone(
                                            message.messageType,
                                          ),
                                          trailing:
                                              pendingPlanMessageId == message.id
                                                  ? (_isAdmin
                                                      ? FilledButton(
                                                          onPressed: _approving
                                                              ? null
                                                              : _handleApprove,
                                                          child: Text(
                                                            _approving
                                                                ? '提交中...'
                                                                : '确认执行',
                                                          ),
                                                        )
                                                      : const Text(
                                                          '当前账号不是管理员，不能确认执行。',
                                                          style: TextStyle(
                                                            fontSize: 12,
                                                          ),
                                                        ))
                                                  : null,
                                        ),
                                      for (final item in visiblePendingMessages)
                                        _ChatBubble(
                                          role: _BubbleRole.user,
                                          time: _formatChatTime(item.createdAt),
                                          content: item.content,
                                          metaNote: item.status ==
                                                  _PendingUserMessageStatus
                                                      .failed
                                              ? '发送失败'
                                              : '发送中',
                                          stateTone: item.status ==
                                                  _PendingUserMessageStatus
                                                      .failed
                                              ? _BubbleStateTone.failed
                                              : _BubbleStateTone.pending,
                                        ),
                                      for (final item in _streamFeed)
                                        _ChatBubble(
                                          role: _BubbleRole.assistant,
                                          badge: item.badge,
                                          time: _formatChatTime(item.time),
                                          content: item.content,
                                          tone: item.tone,
                                        ),
                                      if (_draftAssistantMessage == null &&
                                          _assistantPlaceholder != null)
                                        _ChatBubble(
                                          role: _BubbleRole.assistant,
                                          badge: _assistantPlaceholder!.badge,
                                          time: _formatChatTime(DateTime.now()),
                                          content:
                                              _assistantPlaceholder!.content,
                                          tone: _assistantPlaceholder!.tone,
                                        ),
                                      if (_draftAssistantMessage != null &&
                                          _draftAssistantMessage!
                                              .content.isNotEmpty)
                                        _ChatBubble(
                                          role: _BubbleRole.assistant,
                                          badge: _draftAssistantMessage!
                                                      .messageType ==
                                                  'clarifying'
                                              ? '追问'
                                              : null,
                                          time: _formatChatTime(DateTime.now()),
                                          content:
                                              _draftAssistantMessage!.content,
                                        ),
                                      if (_proposedActions.isNotEmpty &&
                                          pendingPlanMessageId == null)
                                        _ChatBubble(
                                          role: _BubbleRole.assistant,
                                          badge: '计划',
                                          time: _formatChatTime(
                                            _session?.updatedAt,
                                          ),
                                          content: _joinSections([
                                            _session?.pendingPlanJson[
                                                    'reply_markdown'] is String
                                                ? _session?.pendingPlanJson[
                                                    'reply_markdown'] as String
                                                : null,
                                            pendingPlanDetails,
                                          ]),
                                          tone: _BubbleTone.plan,
                                          trailing: _isAdmin
                                              ? FilledButton(
                                                  onPressed: _approving
                                                      ? null
                                                      : _handleApprove,
                                                  child: Text(
                                                    _approving
                                                        ? '提交中...'
                                                        : '确认执行',
                                                  ),
                                                )
                                              : const Text(
                                                  '当前账号不是管理员，不能确认执行。',
                                                  style:
                                                      TextStyle(fontSize: 12),
                                                ),
                                        ),
                                      if (_task != null &&
                                          !_isTerminalTaskStatus(_task!.status))
                                        _ChatBubble(
                                          role: _BubbleRole.assistant,
                                          badge: '任务',
                                          time: _formatChatTime(
                                            _task!.updatedAt ??
                                                _task!.createdAt,
                                          ),
                                          content: taskDigest,
                                          tone: _BubbleTone.task,
                                          trailing: Wrap(
                                            spacing: 8,
                                            runSpacing: 8,
                                            children: [
                                              if (_showInterrupt)
                                                OutlinedButton(
                                                  onPressed: _interrupting
                                                      ? null
                                                      : _handleInterrupt,
                                                  child: Text(
                                                    _interrupting
                                                        ? '中断中...'
                                                        : '中断任务',
                                                  ),
                                                ),
                                              FilledButton.tonal(
                                                onPressed: () =>
                                                    GoRouter.of(context).go(
                                                  '/tasks/${_task!.id}',
                                                ),
                                                child: const Text('打开任务页'),
                                              ),
                                            ],
                                          ),
                                        ),
                                    ],
                                  ),
                                ),
                                const Divider(height: 1),
                                Padding(
                                  padding: EdgeInsets.fromLTRB(
                                    feedHorizontalPadding,
                                    10,
                                    feedHorizontalPadding,
                                    isCompactWidth ? 10 : 14,
                                  ),
                                  child: Column(
                                    children: [
                                      TextField(
                                        controller: _inputController,
                                        enabled: !_sendDisabled,
                                        minLines: 1,
                                        maxLines: 4,
                                        textInputAction:
                                            TextInputAction.newline,
                                        onChanged: (_) => setState(() {}),
                                        style: const TextStyle(
                                          fontSize: 14,
                                          height: 1.3,
                                        ),
                                        decoration: const InputDecoration(
                                          isDense: true,
                                          contentPadding: EdgeInsets.symmetric(
                                            horizontal: 12,
                                            vertical: 10,
                                          ),
                                        ),
                                      ),
                                      const SizedBox(height: 8),
                                      if (isCompactWidth) ...[
                                        Align(
                                          alignment: Alignment.centerLeft,
                                          child: Text(
                                            _composerHint(),
                                            maxLines: 1,
                                            overflow: TextOverflow.ellipsis,
                                            style: Theme.of(context)
                                                .textTheme
                                                .bodySmall
                                                ?.copyWith(
                                                  fontSize: 11,
                                                  color: Theme.of(context)
                                                      .colorScheme
                                                      .onSurface
                                                      .withValues(alpha: 0.68),
                                                ),
                                          ),
                                        ),
                                        const SizedBox(height: 8),
                                        SizedBox(
                                          width: double.infinity,
                                          child: FilledButton(
                                            onPressed: _sendDisabled ||
                                                    _inputController.text
                                                        .trim()
                                                        .isEmpty
                                                ? null
                                                : _handleSend,
                                            child: Text(
                                              _sending ? '发送中...' : '发送',
                                              style: const TextStyle(
                                                fontSize: 14,
                                              ),
                                            ),
                                          ),
                                        ),
                                      ] else
                                        Row(
                                          children: [
                                            Expanded(
                                              child: Text(
                                                _composerHint(),
                                                style: Theme.of(context)
                                                    .textTheme
                                                    .bodySmall
                                                    ?.copyWith(
                                                      fontSize: 11,
                                                      color: Theme.of(context)
                                                          .colorScheme
                                                          .onSurface
                                                          .withValues(
                                                            alpha: 0.68,
                                                          ),
                                                    ),
                                              ),
                                            ),
                                            const SizedBox(width: 12),
                                            FilledButton(
                                              onPressed: _sendDisabled ||
                                                      _inputController.text
                                                          .trim()
                                                          .isEmpty
                                                  ? null
                                                  : _handleSend,
                                              child: Text(
                                                _sending ? '发送中...' : '发送',
                                                style: const TextStyle(
                                                  fontSize: 14,
                                                ),
                                              ),
                                            ),
                                          ],
                                        ),
                                    ],
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
      ],
    );
  }

  String? _buildActivityBannerText() {
    final status = _normalizeStatus(_session?.status);
    if ((_errorText ?? '').isNotEmpty) {
      return _errorText!;
    }
    if ((_streamError ?? '').isNotEmpty) {
      return _streamError!;
    }
    if (_connectionState == _ConnectionState.connecting) {
      return 'haor 正在连接流式会话通道，恢复后会继续接收动作和回复。';
    }
    if (_stepping || _pendingUiActions.isNotEmpty) {
      return 'haor 正在执行当前页面动作，并会继续把结果沉淀到聊天记录里。';
    }
    if (_normalizeStatus(_task?.status.name) == 'running') {
      return '当前正在执行已批准的编排任务，如需继续输入请先中断。';
    }
    if (status == 'waiting_approval') {
      return _isAdmin ? '已生成待确认计划，确认后才会执行。' : '已生成待确认计划，当前账号无法确认执行。';
    }
    return null;
  }

  String _composerHint() {
    if (_normalizeStatus(_task?.status.name) == 'running') {
      return '当前任务执行中，输入已锁定';
    }
    if (_sending) {
      return 'haor 正在生成回复...';
    }
    if (_stepping) {
      return 'haor 正在继续处理当前请求...';
    }
    return '支持多轮追问、审批和站内动作联动';
  }
}

class _HaorFab extends StatelessWidget {
  const _HaorFab({
    required this.active,
    required this.showBadge,
    required this.onTap,
  });

  final bool active;
  final bool showBadge;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(999),
        child: Stack(
          clipBehavior: Clip.none,
          children: [
            AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              padding: const EdgeInsets.fromLTRB(14, 12, 18, 12),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surface.withValues(
                      alpha: active ? 0.98 : 0.92,
                    ),
                borderRadius: BorderRadius.circular(999),
                border: Border.all(
                  color: active
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context)
                          .colorScheme
                          .onSurface
                          .withValues(alpha: 0.08),
                ),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withValues(alpha: 0.12),
                    blurRadius: 18,
                    offset: const Offset(0, 8),
                  ),
                ],
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  SizedBox(
                    width: 28,
                    height: 28,
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: const LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [Color(0xFFE84D5B), Color(0xFFF6F7FB)],
                          stops: [0.5, 0.5],
                        ),
                        border: Border.all(
                            color: const Color(0xFF101417), width: 2.5),
                      ),
                      child: Center(
                        child: Container(
                          width: 10,
                          height: 10,
                          decoration: BoxDecoration(
                            color: const Color(0xFFF6F7FB),
                            shape: BoxShape.circle,
                            border: Border.all(
                              color: const Color(0xFF101417),
                              width: 2,
                            ),
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  const Text(
                    'haor',
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.2,
                    ),
                  ),
                ],
              ),
            ),
            if (showBadge)
              Positioned(
                right: -2,
                top: -2,
                child: Container(
                  width: 12,
                  height: 12,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE84D5B),
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white, width: 2),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _StatusPill extends StatelessWidget {
  const _StatusPill({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.10),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: Theme.of(context).colorScheme.primary,
          fontWeight: FontWeight.w700,
          fontSize: 12,
        ),
      ),
    );
  }
}

class _HeaderIconButton extends StatelessWidget {
  const _HeaderIconButton({
    required this.icon,
    required this.tooltip,
    required this.onPressed,
  });

  final IconData icon;
  final String tooltip;
  final VoidCallback? onPressed;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.only(left: 4),
      child: Tooltip(
        message: tooltip,
        child: IconButton(
          onPressed: onPressed,
          icon: Icon(icon, size: 18),
          style: IconButton.styleFrom(
            minimumSize: const Size(32, 32),
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
            backgroundColor: scheme.surfaceContainerHighest.withValues(
              alpha: 0.85,
            ),
            foregroundColor: scheme.onSurface,
          ),
        ),
      ),
    );
  }
}

class _ActivityBanner extends StatelessWidget {
  const _ActivityBanner({
    required this.message,
    required this.isError,
  });

  final String message;
  final bool isError;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      decoration: BoxDecoration(
        color: (isError ? scheme.error : scheme.primary).withValues(
          alpha: 0.08,
        ),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Text(
        message,
        style: TextStyle(
          fontSize: 11.5,
          height: 1.3,
          color: isError ? scheme.error : scheme.onSurface,
        ),
      ),
    );
  }
}

class _EmptyCard extends StatelessWidget {
  const _EmptyCard({
    required this.title,
    required this.message,
  });

  final String title;
  final String message;

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.06),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 4),
          Text(
            message,
            style: const TextStyle(
              fontSize: 12.5,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}

enum _BubbleRole { assistant, user }

enum _BubbleTone { action, error, plan, task }

enum _BubbleStateTone { pending, failed }

class _ChatBubble extends StatelessWidget {
  const _ChatBubble({
    required this.role,
    required this.time,
    required this.content,
    this.badge,
    this.tone,
    this.metaNote,
    this.stateTone,
    this.trailing,
  });

  final _BubbleRole role;
  final String time;
  final String content;
  final String? badge;
  final _BubbleTone? tone;
  final String? metaNote;
  final _BubbleStateTone? stateTone;
  final Widget? trailing;

  @override
  Widget build(BuildContext context) {
    final isUser = role == _BubbleRole.user;
    final scheme = Theme.of(context).colorScheme;
    final bubbleColor = switch ((isUser, tone, stateTone)) {
      (true, _, _) => scheme.primary.withValues(alpha: 0.12),
      (_, _BubbleTone.plan, _) => const Color(0xFFE8F2FF),
      (_, _BubbleTone.task, _) => const Color(0xFFEAFBF3),
      (_, _BubbleTone.action, _) => const Color(0xFFFFF7E5),
      (_, _BubbleTone.error, _) => const Color(0xFFFFECEE),
      (_, _, _BubbleStateTone.failed) => const Color(0xFFFFECEE),
      _ => scheme.surfaceContainerHighest.withValues(alpha: 0.62),
    };
    final align = isUser ? CrossAxisAlignment.end : CrossAxisAlignment.start;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(
        crossAxisAlignment: align,
        children: [
          Container(
            constraints: const BoxConstraints(maxWidth: 760),
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
            decoration: BoxDecoration(
              color: bubbleColor,
              borderRadius: BorderRadius.circular(20),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if ((badge ?? '').isNotEmpty)
                  Container(
                    margin: const EdgeInsets.only(bottom: 6),
                    padding:
                        const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.8),
                      borderRadius: BorderRadius.circular(999),
                    ),
                    child: Text(
                      badge!,
                      style: const TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
                Text(
                  content,
                  style: const TextStyle(
                    fontSize: 12.5,
                    height: 1.35,
                  ),
                ),
                if (trailing != null) ...[
                  const SizedBox(height: 8),
                  trailing!,
                ],
              ],
            ),
          ),
          const SizedBox(height: 3),
          Text(
            metaNote == null ? time : '$time · $metaNote',
            style: TextStyle(
              fontSize: 10,
              color: scheme.onSurface.withValues(alpha: 0.58),
            ),
          ),
        ],
      ),
    );
  }
}

class _PendingUiRequest {
  const _PendingUiRequest({
    required this.turnId,
    required this.uiActions,
    this.content,
  });

  final String turnId;
  final List<AgentUIAction> uiActions;
  final String? content;
}

class _DraftAssistantMessage {
  const _DraftAssistantMessage({
    required this.turnId,
    required this.messageType,
    required this.content,
  });

  final String turnId;
  final String messageType;
  final String content;

  _DraftAssistantMessage copyWith({
    String? content,
  }) {
    return _DraftAssistantMessage(
      turnId: turnId,
      messageType: messageType,
      content: content ?? this.content,
    );
  }
}

class _AssistantPlaceholder {
  const _AssistantPlaceholder({
    required this.key,
    required this.badge,
    required this.content,
    this.tone,
  });

  final String key;
  final String badge;
  final String content;
  final _BubbleTone? tone;
}

class _StreamFeedItem {
  const _StreamFeedItem({
    required this.id,
    required this.badge,
    required this.content,
    required this.time,
    this.tone,
  });

  final String id;
  final String badge;
  final String content;
  final DateTime time;
  final _BubbleTone? tone;
}

enum _PendingUserMessageStatus { sending, failed }

class _PendingUserMessage {
  const _PendingUserMessage({
    required this.clientMessageId,
    required this.content,
    required this.createdAt,
    required this.status,
  });

  final String clientMessageId;
  final String content;
  final DateTime createdAt;
  final _PendingUserMessageStatus status;

  _PendingUserMessage copyWith({
    _PendingUserMessageStatus? status,
  }) {
    return _PendingUserMessage(
      clientMessageId: clientMessageId,
      content: content,
      createdAt: createdAt,
      status: status ?? this.status,
    );
  }
}

enum _ConnectionState { disconnected, connecting, connected }

String _normalizeStatus(Object? value) {
  return value?.toString().trim().toLowerCase() ?? '';
}

String _statusLabel(String? status) {
  return switch (_normalizeStatus(status)) {
    'waiting_approval' => '待确认',
    'running' => '执行中',
    'completed' || 'success' => '已完成',
    'failed' || 'failure' => '失败',
    'canceled' => '已取消',
    _ => '会话中',
  };
}

String? _messageBadge(AgentMessage message) {
  if (message.role == 'user') {
    return null;
  }
  return switch (_normalizeStatus(message.messageType)) {
    'clarifying' => '追问',
    'plan' => '计划',
    'task_update' => '任务',
    'action_update' => '动作',
    'error' => '错误',
    _ => null,
  };
}

_BubbleTone? _messageTone(String messageType) {
  return switch (_normalizeStatus(messageType)) {
    'plan' => _BubbleTone.plan,
    'task_update' => _BubbleTone.task,
    'action_update' => _BubbleTone.action,
    'error' => _BubbleTone.error,
    _ => null,
  };
}

String _joinSections(List<String?> parts) {
  return parts
      .map((item) => (item ?? '').trim())
      .where((item) => item.isNotEmpty)
      .join('\n\n');
}

AgentSession? _upsertSessionMessage(AgentSession? session, AgentMessage next) {
  if (session == null) {
    return null;
  }
  final messages = [...session.messages];
  final index = messages.indexWhere((item) => item.id == next.id);
  if (index >= 0) {
    messages[index] = next;
  } else {
    messages.add(next);
  }
  messages.sort((left, right) {
    final leftValue = left.createdAt?.millisecondsSinceEpoch ?? 0;
    final rightValue = right.createdAt?.millisecondsSinceEpoch ?? 0;
    return leftValue.compareTo(rightValue);
  });
  return AgentSession(
    sessionId: session.sessionId,
    agentId: session.agentId,
    status: session.status,
    routeContextJson: session.routeContextJson,
    workingContextJson: session.workingContextJson,
    dialogStateJson: session.dialogStateJson,
    pendingPlanJson: session.pendingPlanJson,
    browserRuntimeJson: session.browserRuntimeJson,
    lastTaskId: session.lastTaskId,
    messages: messages,
    createdAt: session.createdAt,
    updatedAt: next.createdAt ?? session.updatedAt,
  );
}

List<_PendingUserMessage> _reconcilePendingUserMessages(
  List<_PendingUserMessage> pending,
  List<AgentMessage> messages,
) {
  if (pending.isEmpty || messages.isEmpty) {
    return pending;
  }
  final persistedIds = messages
      .where((item) => item.role == 'user')
      .map((item) => item.payloadJson['client_message_id'])
      .whereType<String>()
      .toSet();
  return pending
      .where((item) => !persistedIds.contains(item.clientMessageId))
      .toList(growable: false);
}

List<_PendingUserMessage> _markPendingUserMessagesFailed(
  List<_PendingUserMessage> pending,
) {
  return pending
      .map(
        (item) => item.status == _PendingUserMessageStatus.failed
            ? item
            : item.copyWith(status: _PendingUserMessageStatus.failed),
      )
      .toList(growable: false);
}

String? _findPendingPlanMessageId(
  List<AgentMessage> messages,
  List<AgentProposedAction> actions,
) {
  if (actions.isEmpty || messages.isEmpty) {
    return null;
  }
  for (final message in messages.reversed) {
    if (message.messageType == 'plan') {
      return message.id;
    }
  }
  return null;
}

String _buildPendingPlanDetails(List<AgentProposedAction> actions) {
  if (actions.isEmpty) {
    return '';
  }
  final lines = <String>['待执行动作：'];
  for (var index = 0; index < actions.length; index += 1) {
    final action = actions[index];
    lines.add('${index + 1}. ${action.title}');
    lines.add('动作类型：${action.actionType}');
    if (action.reason.trim().isNotEmpty) {
      lines.add('原因：${action.reason}');
    }
    if (action.params.isNotEmpty) {
      final params = action.params.entries
          .map((item) => '${item.key}=${item.value}')
          .join('，');
      lines.add('参数：$params');
    }
    if (index < actions.length - 1) {
      lines.add('');
    }
  }
  return lines.join('\n');
}

String _buildTaskDigest(TaskRunModel task, List<TaskEventModel> taskEvents) {
  final lines = <String>[
    '${task.taskType.label} · ${task.status.label}',
    '进度：${task.progress}%',
  ];
  if ((task.message ?? '').trim().isNotEmpty) {
    lines.add('当前：${task.message!.trim()}');
  }
  final recentEvents = taskEvents.take(3).toList(growable: false);
  if (recentEvents.isNotEmpty) {
    lines.add('');
    lines.add('最近事件：');
    for (final item in recentEvents) {
      lines.add(
        '- ${item.eventType}：${(item.message ?? item.stageName ?? item.stageCode ?? '-').trim()}',
      );
    }
  }
  return lines.join('\n');
}

bool _isTerminalTaskStatus(TaskStatusType status) {
  return status == TaskStatusType.success ||
      status == TaskStatusType.failure ||
      status == TaskStatusType.canceled;
}

String _formatChatTime(DateTime? value) {
  if (value == null) {
    return '';
  }
  final local = value.toLocal();
  final now = DateTime.now();
  final sameDay = now.year == local.year &&
      now.month == local.month &&
      now.day == local.day;
  final hour = local.hour.toString().padLeft(2, '0');
  final minute = local.minute.toString().padLeft(2, '0');
  if (sameDay) {
    return '$hour:$minute';
  }
  return '${local.month}/${local.day} $hour:$minute';
}
