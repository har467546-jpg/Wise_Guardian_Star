import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/core/network/api_client.dart';

void main() {
  test('default desktop debug fallback keeps loopback http endpoint', () {
    expect(
      resolveConfiguredApiBaseUrl(
        configured: '',
        isAndroid: false,
        allowInsecureDevTransport: false,
      ),
      'http://127.0.0.1:8000/api/v1',
    );
  });

  test('debug builds keep private network http endpoint without extra opt-in',
      () {
    expect(
      resolveConfiguredApiBaseUrl(
        configured: 'http://10.0.2.2:8000/api/v1',
        isAndroid: true,
        allowInsecureDevTransport: false,
      ),
      'http://10.0.2.2:8000/api/v1',
    );
  });

  test('private network websocket endpoint keeps ws in debug builds', () {
    expect(
      buildApiWebSocketUri(
        '/api/v1/mobile/alerts/stream',
        baseUrl: 'http://192.168.10.131:8000/api/v1',
      ).toString(),
      'ws://192.168.10.131:8000/api/v1/mobile/alerts/stream',
    );
  });

  test('device alert websocket endpoint carries token in query', () {
    expect(
      buildAuthenticatedDeviceAlertStreamUri('token-123').toString(),
      'ws://127.0.0.1:8000/api/v1/mobile/alerts/stream?token=token-123',
    );
  });

  test('public http endpoint falls back without explicit insecure opt-in', () {
    expect(
      resolveConfiguredApiBaseUrl(
        configured: 'http://example.com/api/v1',
        isAndroid: false,
        allowInsecureDevTransport: false,
      ),
      'http://127.0.0.1:8000/api/v1',
    );
  });

  test('explicit insecure opt-in still allows public http endpoint', () {
    expect(
      resolveConfiguredApiBaseUrl(
        configured: 'http://example.com/api/v1',
        isAndroid: false,
        allowInsecureDevTransport: true,
      ),
      'http://example.com/api/v1',
    );
  });
}
