import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/core/storage/app_storage.dart';
import 'package:situational_awareness_mobile/core/theme/app_theme.dart';
import 'package:situational_awareness_mobile/features/login/login_page.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

void main() {
  testWidgets('login page shows friendly bootstrap connection error', (
    tester,
  ) async {
    final error = DioException(
      requestOptions: RequestOptions(
        path: '/auth/bootstrap-status',
        baseUrl: 'http://10.0.2.2:8000/api/v1',
      ),
      type: DioExceptionType.connectionTimeout,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appStorageProvider.overrideWithValue(_FakeAppStorage()),
          bootstrapStatusProvider.overrideWith((ref) async => throw error),
        ],
        child: MaterialApp(
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          home: const LoginPage(),
        ),
      ),
    );

    await tester.pump();
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('bootstrap-error-card')), findsOneWidget);
    expect(find.text('暂时无法连接后端服务'), findsOneWidget);
    expect(find.textContaining('连接服务器超时'), findsOneWidget);
    expect(
      find.textContaining('http://127.0.0.1:8000/api/v1'),
      findsAtLeastNWidgets(1),
    );
    expect(find.text('重试连接'), findsOneWidget);
    expect(find.textContaining('DioException'), findsNothing);
  });

  testWidgets('compact login keeps primary action above the fold', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appStorageProvider.overrideWithValue(_FakeAppStorage()),
          bootstrapStatusProvider.overrideWith(
            (ref) async => const BootstrapStatus(
              bootstrapped: true,
              canBootstrapAdmin: false,
              userCount: 1,
            ),
          ),
        ],
        child: MaterialApp(
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          home: const LoginPage(),
        ),
      ),
    );

    await tester.pump();
    await tester.pumpAndSettle();

    final buttonRect =
        tester.getRect(find.byKey(const ValueKey('login-primary-button')));
    expect(buttonRect.bottom, lessThanOrEqualTo(844));
    expect(find.text('登录态势感知'), findsOneWidget);
    expect(find.text('账号密码登录'), findsOneWidget);
    expect(find.text('内部环境'), findsNothing);
    expect(find.text('当前接口'), findsNothing);
    expect(find.text('普通登录'), findsNothing);
  });
}

class _FakeAppStorage extends AppStorage {
  _FakeAppStorage() : super(const FlutterSecureStorage());

  @override
  Future<String?> readToken() async => null;

  @override
  Future<void> clearToken() async {}

  @override
  Future<void> writeToken(String token) async {}
}
