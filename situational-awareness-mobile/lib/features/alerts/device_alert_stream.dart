import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../../core/network/api_client.dart';
import '../../core/network/websocket_client.dart';
import 'device_abnormal_notifications.dart';

class DeviceAbnormalRealtimeAlert {
  const DeviceAbnormalRealtimeAlert({
    required this.findingId,
    required this.title,
    required this.message,
    required this.route,
    required this.navigateWithGo,
    required this.highRiskFindings,
    this.actionLabel = '查看',
  });

  factory DeviceAbnormalRealtimeAlert.fromJson(Map<String, dynamic> json) {
    return DeviceAbnormalRealtimeAlert(
      findingId: json['finding_id'] as String? ?? '',
      title: json['title'] as String? ?? '设备异常提醒',
      message: json['message'] as String? ?? '',
      route: json['route'] as String? ?? '',
      navigateWithGo: json['navigate_with_go'] as bool? ?? false,
      highRiskFindings: json['high_risk_findings'] as int? ?? 0,
    );
  }

  final String findingId;
  final String title;
  final String message;
  final String route;
  final bool navigateWithGo;
  final int highRiskFindings;
  final String actionLabel;

  bool get isValid => findingId.trim().isNotEmpty && route.trim().isNotEmpty;
}

class DeviceAlertStreamController {
  DeviceAlertStreamController({
    required this.token,
    required this.onAlert,
    required this.webSocketClient,
  });

  final String token;
  final FutureOr<void> Function(DeviceAbnormalRealtimeAlert alert) onAlert;
  final WebSocketClient webSocketClient;

  StreamSubscription<dynamic>? _socketSubscription;
  WebSocketConnection? _socket;
  Timer? _reconnectTimer;
  bool _active = false;
  bool _disposed = false;
  int _reconnectAttempts = 0;

  Future<void> start() async {
    if (_disposed) {
      return;
    }
    _active = true;
    _reconnectTimer?.cancel();
    if (_socket != null || _socketSubscription != null) {
      return;
    }
    await _connect();
  }

  Future<void> stop() async {
    _active = false;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    final subscription = _socketSubscription;
    _socketSubscription = null;
    await subscription?.cancel();
    final socket = _socket;
    _socket = null;
    await socket?.close();
  }

  Future<void> dispose() async {
    _disposed = true;
    await stop();
  }

  Future<void> _connect() async {
    if (!_active || _disposed || _socket != null) {
      return;
    }
    try {
      final socket = await webSocketClient.connectAuthenticated(
        uri: buildAuthenticatedDeviceAlertStreamUri(token),
        token: token,
      );
      socket.pingInterval = const Duration(seconds: 20);
      _socket = socket;
      _reconnectAttempts = 0;
      _socketSubscription = socket.stream.listen(
        (dynamic raw) => unawaited(_handleRawMessage(raw)),
        onDone: () => unawaited(_handleSocketClosed()),
        onError: (_) => unawaited(_handleSocketClosed()),
        cancelOnError: true,
      );
    } catch (_) {
      _scheduleReconnect();
    }
  }

  Future<void> _handleRawMessage(dynamic raw) async {
    Map<String, dynamic>? envelope;
    if (raw is String) {
      try {
        final decoded = jsonDecode(raw);
        if (decoded is Map<String, dynamic>) {
          envelope = decoded;
        } else if (decoded is Map) {
          envelope = decoded.cast<String, dynamic>();
        }
      } catch (_) {
        return;
      }
    } else if (raw is Map<String, dynamic>) {
      envelope = raw;
    } else if (raw is Map) {
      envelope = raw.cast<String, dynamic>();
    }
    if (envelope == null) {
      return;
    }

    if (envelope['type'] != 'device_abnormal_alert') {
      return;
    }
    final rawEvent = envelope['event'];
    if (rawEvent is! Map) {
      return;
    }
    final alert = DeviceAbnormalRealtimeAlert.fromJson(
      rawEvent.cast<String, dynamic>(),
    );
    if (!alert.isValid) {
      return;
    }

    try {
      await rememberDeviceAbnormalRiskAlerted(
        riskId: alert.findingId,
        highRiskFindings: alert.highRiskFindings,
      );
    } catch (_) {
      // Keep the realtime prompt path alive even if local snapshot persistence fails.
    }

    await onAlert(alert);
  }

  Future<void> _handleSocketClosed() async {
    final subscription = _socketSubscription;
    _socketSubscription = null;
    await subscription?.cancel();
    final socket = _socket;
    _socket = null;
    await socket?.close();
    _scheduleReconnect();
  }

  void _scheduleReconnect() {
    if (!_active || _disposed) {
      return;
    }
    _reconnectTimer?.cancel();
    _reconnectAttempts += 1;
    final delaySeconds = min(30, max(2, pow(2, _reconnectAttempts).toInt()));
    _reconnectTimer = Timer(
      Duration(seconds: delaySeconds),
      () => unawaited(_connect()),
    );
  }
}
