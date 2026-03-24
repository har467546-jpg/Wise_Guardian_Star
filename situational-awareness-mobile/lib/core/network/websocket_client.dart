import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

abstract class WebSocketConnection {
  Stream<dynamic> get stream;
  bool get isOpen;
  Duration? get pingInterval;
  set pingInterval(Duration? value);

  void add(dynamic data);
  void addJson(Map<String, Object?> payload);
  Future<void> close([int? code, String? reason]);
}

abstract class WebSocketClient {
  Future<WebSocketConnection> connectAuthenticated({
    required Uri uri,
    required String token,
    Map<String, Object?>? authPayload,
  });
}

class IoWebSocketConnection implements WebSocketConnection {
  IoWebSocketConnection(this._socket);

  final WebSocket _socket;

  @override
  Stream<dynamic> get stream => _socket;

  @override
  bool get isOpen => _socket.readyState == WebSocket.open;

  @override
  Duration? get pingInterval => _socket.pingInterval;

  @override
  set pingInterval(Duration? value) {
    _socket.pingInterval = value;
  }

  @override
  void add(dynamic data) {
    _socket.add(data);
  }

  @override
  void addJson(Map<String, Object?> payload) {
    _socket.add(jsonEncode(payload));
  }

  @override
  Future<void> close([int? code, String? reason]) => _socket.close(code, reason);
}

class DefaultWebSocketClient implements WebSocketClient {
  const DefaultWebSocketClient();

  @override
  Future<WebSocketConnection> connectAuthenticated({
    required Uri uri,
    required String token,
    Map<String, Object?>? authPayload,
  }) async {
    final socket = await WebSocket.connect(uri.toString());
    final connection = IoWebSocketConnection(socket);
    connection.addJson({
      'type': 'auth',
      'token': token,
      ...?authPayload,
    });
    return connection;
  }
}

final webSocketClientProvider = Provider<WebSocketClient>(
  (ref) => const DefaultWebSocketClient(),
);
