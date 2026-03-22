import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/core/theme/app_theme.dart';
import 'package:situational_awareness_mobile/features/risks/risks_page.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

const _snapshotRisk = RiskItem(
  id: 'risk-1',
  assetId: 'asset-1',
  assetIp: '10.0.0.12',
  assetHostname: 'edge-node',
  assetPortId: 'port-1',
  severity: RiskSeverityLevel.high,
  status: RiskStatusType.open,
  title: '旧风险标题',
  description: '旧描述',
  evidenceJson: {'source': 'snapshot'},
  detectedAt: null,
  resolvedAt: null,
);

const _freshRisk = RiskItem(
  id: 'risk-1',
  assetId: 'asset-1',
  assetIp: '10.0.0.12',
  assetHostname: 'edge-node',
  assetPortId: 'port-1',
  severity: RiskSeverityLevel.high,
  status: RiskStatusType.open,
  title: 'SSH 弱口令',
  description: '最新详情已刷新',
  evidenceJson: {'source': 'server'},
  detectedAt: null,
  resolvedAt: null,
);

void main() {
  testWidgets('risk detail loads independently without snapshot', (tester) async {
    await _pumpRiskDetailPage(
      tester,
      overrides: [
        riskDetailProvider.overrideWith((ref, riskId) async {
          expect(riskId, 'risk-1');
          return _freshRisk;
        }),
      ],
      child: const RiskDetailPage(riskId: 'risk-1', risk: null),
    );

    expect(find.text('SSH 弱口令'), findsOneWidget);
    expect(find.text('最新详情已刷新'), findsOneWidget);
    expect(find.text('查看所属资产'), findsOneWidget);
    expect(find.text('风险不可用'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('risk detail shows snapshot first and replaces it with fresh data', (tester) async {
    final completer = Completer<RiskItem>();

    await _pumpRiskDetailPage(
      tester,
      settle: false,
      overrides: [
        riskDetailProvider.overrideWith((ref, riskId) => completer.future),
      ],
      child: const RiskDetailPage(riskId: 'risk-1', risk: _snapshotRisk),
    );

    expect(find.text('旧风险标题'), findsOneWidget);
    expect(find.text('已显示进入页时的快照，正在刷新最新详情。'), findsOneWidget);

    completer.complete(_freshRisk);
    await tester.pump();
    await tester.pumpAndSettle();

    expect(find.text('SSH 弱口令'), findsOneWidget);
    expect(find.text('最新详情已刷新'), findsOneWidget);
    expect(find.text('旧风险标题'), findsNothing);
    expect(find.text('已显示进入页时的快照，正在刷新最新详情。'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('risk detail keeps snapshot and exposes retry notice when refresh fails', (tester) async {
    await _pumpRiskDetailPage(
      tester,
      overrides: [
        riskDetailProvider.overrideWith((ref, riskId) async {
          throw StateError('refresh failed');
        }),
      ],
      child: const RiskDetailPage(riskId: 'risk-1', risk: _snapshotRisk),
    );

    expect(find.text('旧风险标题'), findsOneWidget);
    expect(find.text('旧描述'), findsOneWidget);
    expect(find.text('当前展示的是进入页时的快照，最新数据加载失败。'), findsOneWidget);
    expect(find.text('重试'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

Future<void> _pumpRiskDetailPage(
  WidgetTester tester, {
  required List<Override> overrides,
  required Widget child,
  bool settle = true,
}) async {
  tester.view
    ..physicalSize = const Size(390, 844)
    ..devicePixelRatio = 1;

  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  await tester.pumpWidget(
    ProviderScope(
      overrides: overrides,
      child: MaterialApp(
        theme: AppTheme.light(),
        darkTheme: AppTheme.dark(),
        home: child,
      ),
    ),
  );
  await tester.pump();
  if (settle) {
    await tester.pumpAndSettle();
  }
}
