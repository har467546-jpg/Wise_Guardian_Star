import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/core/storage/app_storage.dart';
import 'package:situational_awareness_mobile/core/theme/app_theme.dart';
import 'package:situational_awareness_mobile/features/assets/assets_page.dart';
import 'package:situational_awareness_mobile/features/dashboard/dashboard_page.dart';
import 'package:situational_awareness_mobile/features/profile/profile_page.dart';
import 'package:situational_awareness_mobile/features/risks/risks_page.dart';
import 'package:situational_awareness_mobile/features/tasks/tasks_page.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

const _breakpointSizes = <Size>[
  Size(360, 800),
  Size(600, 960),
  Size(840, 1280),
];

const _sampleOverview = OverviewSummary(
  assetTotal: 128,
  onlineAssets: 64,
  highRiskFindings: 7,
  activeTasks: 3,
  recentTasks: [
    TaskRunModel(
      id: 'task-1',
      taskType: TaskTypeModel.assetScan,
      status: TaskStatusType.running,
      scopeType: 'discovery_job',
      scopeId: 'job-1',
      progress: 52,
      message: '扫描 10.0.0.0/24',
      createdAt: null,
      finishedAt: null,
    ),
  ],
  recentRisks: [
    RiskItem(
      id: 'risk-1',
      assetId: 'asset-1',
      assetIp: '10.0.0.12',
      assetHostname: 'edge-node',
      assetPortId: 'port-1',
      severity: RiskSeverityLevel.high,
      status: RiskStatusType.open,
      title: '弱口令暴露',
      description: '发现远程管理口令强度不足。',
      evidenceJson: {'service': 'ssh'},
      detectedAt: null,
      resolvedAt: null,
    ),
  ],
  discoveryEntry: DiscoveryEntry(
    enabled: true,
    pendingJobs: 1,
    runningJobs: 1,
  ),
);

const _emptyOverview = OverviewSummary(
  assetTotal: 0,
  onlineAssets: 0,
  highRiskFindings: 0,
  activeTasks: 0,
  recentTasks: [],
  recentRisks: [],
  discoveryEntry: DiscoveryEntry(
    enabled: true,
    pendingJobs: 0,
    runningJobs: 0,
  ),
);

const _sampleAssetList = AssetListPayload(
  items: [
    AssetModel(
      id: 'asset-1',
      ip: '10.0.0.12',
      hostname: 'edge-node',
      osName: 'Ubuntu 24.04',
      status: AssetStatusType.online,
      isLocal: true,
      localHint: 'lab-a',
      firstSeenAt: null,
      lastSeenAt: null,
      ports: [],
    ),
    AssetModel(
      id: 'asset-2',
      ip: '10.0.0.23',
      hostname: 'db-node',
      osName: 'Debian 12',
      status: AssetStatusType.collecting,
      isLocal: false,
      localHint: null,
      firstSeenAt: null,
      lastSeenAt: null,
      ports: [],
    ),
  ],
  meta: PageMeta(total: 2, page: 1, pageSize: 20),
);

const _sampleAsset = AssetModel(
  id: 'asset-1',
  ip: '10.0.0.12',
  hostname: 'edge-node',
  osName: 'Ubuntu 24.04',
  status: AssetStatusType.online,
  isLocal: true,
  localHint: 'lab-a',
  firstSeenAt: null,
  lastSeenAt: null,
  ports: [
    AssetPortModel(
      id: 'port-1',
      port: 22,
      protocol: 'tcp',
      serviceName: 'ssh',
      serviceVersion: 'OpenSSH 9.6',
      state: 'open',
      lastSeenAt: null,
    ),
    AssetPortModel(
      id: 'port-2',
      port: 443,
      protocol: 'tcp',
      serviceName: 'https',
      serviceVersion: 'nginx 1.26',
      state: 'open',
      lastSeenAt: null,
    ),
  ],
);

const _sampleTaskList = TaskListPayload(
  items: [
    TaskRunModel(
      id: 'task-1',
      taskType: TaskTypeModel.assetScan,
      status: TaskStatusType.running,
      scopeType: 'discovery_job',
      scopeId: 'job-1',
      progress: 62,
      message: '扫描 10.0.0.0/24',
      createdAt: null,
      finishedAt: null,
      resultJson: {'hosts': 12},
      errorJson: {},
    ),
    TaskRunModel(
      id: 'task-2',
      taskType: TaskTypeModel.riskVerify,
      status: TaskStatusType.failure,
      scopeType: 'asset',
      scopeId: 'asset-1',
      progress: 100,
      message: '弱口令验证超时',
      createdAt: null,
      finishedAt: null,
      resultJson: {},
      errorJson: {'reason': 'timeout'},
    ),
  ],
  meta: PageMeta(total: 2, page: 1, pageSize: 20),
);

const _sampleTask = TaskRunModel(
  id: 'task-1',
  taskType: TaskTypeModel.assetScan,
  status: TaskStatusType.running,
  scopeType: 'discovery_job',
  scopeId: 'job-1',
  progress: 62,
  message: '扫描 10.0.0.0/24',
  createdAt: null,
  finishedAt: null,
  retryCount: 1,
  resultJson: {'hosts': 12},
  errorJson: {'warning': 'slow subnet'},
  timing: TaskTimingModel(
    queueDurationMs: 3200,
    runDurationMs: 18200,
    totalDurationMs: 21400,
    currentStageCode: 'probe',
    currentStageName: '批量探测',
    currentStageDurationMs: 8600,
    hasEventLogs: true,
  ),
  stageTimings: [
    TaskStageTimingModel(
      stageCode: 'prepare',
      stageName: '准备任务',
      startedAt: null,
      finishedAt: null,
      durationMs: 3200,
    ),
    TaskStageTimingModel(
      stageCode: 'probe',
      stageName: '批量探测',
      startedAt: null,
      finishedAt: null,
      durationMs: 18200,
    ),
  ],
  eventCount: 3,
);

const _sampleTaskEvents = TaskEventListPayload(
  items: [
    TaskEventModel(
      id: 'event-1',
      taskRunId: 'task-1',
      taskType: TaskTypeModel.assetScan,
      status: TaskStatusType.running,
      eventType: 'stage',
      level: 'info',
      stageCode: 'prepare',
      stageName: '准备任务',
      message: '初始化资产范围',
      progress: 10,
      payloadJson: {'assets': 12},
      createdAt: null,
    ),
    TaskEventModel(
      id: 'event-2',
      taskRunId: 'task-1',
      taskType: TaskTypeModel.assetScan,
      status: TaskStatusType.running,
      eventType: 'progress',
      level: 'info',
      stageCode: 'probe',
      stageName: '批量探测',
      message: '已完成 6/12 个目标',
      progress: 62,
      payloadJson: {'processed': 6},
      createdAt: null,
    ),
    TaskEventModel(
      id: 'event-3',
      taskRunId: 'task-1',
      taskType: TaskTypeModel.assetScan,
      status: TaskStatusType.running,
      eventType: 'log',
      level: 'warning',
      stageCode: 'probe',
      stageName: '批量探测',
      message: '子网响应较慢',
      progress: 62,
      payloadJson: {'warning': 'slow subnet'},
      createdAt: null,
    ),
  ],
  meta: PageMeta(total: 3, page: 1, pageSize: 50),
);

const _sampleRemediation = RemediationAssetDetailModel(
  asset: RemediationAssetSummary(
    id: 'asset-1',
    ip: '10.0.0.12',
    hostname: 'edge-node',
    osName: 'Ubuntu 24.04',
    status: AssetStatusType.online,
  ),
  authorization: RemediationAuthorizationModel(
    credentialBound: true,
    adminAuthorized: true,
    lastVerifiedAt: null,
    lastVerificationStatus: 'success',
    effectivePrivilege: 'sudo',
    executionReady: true,
    blockedReasons: [],
  ),
  latestCollection: RemediationCollectionModel(
    status: 'success',
    collectedAt: null,
    summaryJson: {'services': 2},
  ),
  findings: [
    RemediationFindingModel(
      findingId: 'risk-1',
      ruleId: 'rule-ssh',
      title: 'SSH 弱口令',
      severity: RiskSeverityLevel.high,
      status: 'open',
      serviceName: 'ssh',
      detectedAt: null,
      hasTemplate: true,
    ),
  ],
  runner: HostRunnerModel(
    runnerId: 'runner-1',
    assetId: 'asset-1',
    status: 'online',
    installStatus: 'installed',
    version: '1.0.0',
    platformUrl: null,
    lastSeenAt: null,
    lastError: null,
    capabilitiesJson: {'shell': true},
  ),
  activeSessionId: 'session-1',
  activeSessionStatus: 'running',
  latestTaskId: 'task-1',
  canInstallRunner: false,
  runnerInstallBlockedReasons: [],
);

const _sampleRiskList = RiskListPayload(
  items: [
    RiskItem(
      id: 'risk-1',
      assetId: 'asset-1',
      assetIp: '10.0.0.12',
      assetHostname: 'edge-node',
      assetPortId: 'port-1',
      severity: RiskSeverityLevel.high,
      status: RiskStatusType.open,
      title: 'SSH 弱口令',
      description: '发现远程管理口令强度不足。',
      evidenceJson: {'service': 'ssh'},
      detectedAt: null,
      resolvedAt: null,
    ),
    RiskItem(
      id: 'risk-2',
      assetId: 'asset-2',
      assetIp: '10.0.0.23',
      assetHostname: 'db-node',
      assetPortId: null,
      severity: RiskSeverityLevel.medium,
      status: RiskStatusType.fixed,
      title: 'HTTP 目录暴露',
      description: '目录索引已修复。',
      evidenceJson: {'service': 'http'},
      detectedAt: null,
      resolvedAt: null,
    ),
  ],
  meta: PageMeta(total: 2, page: 1, pageSize: 20),
);

void main() {
  group('responsive layout', () {
    testWidgets('dashboard stays readable across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            overviewProvider.overrideWith((ref) async => _sampleOverview),
          ],
          child: const DashboardPage(),
        );

        if (size.width < 600) {
          expect(find.byKey(const ValueKey('compact-overview-metrics-row')),
              findsOneWidget);
          expect(
              find.byKey(const ValueKey('compact-overview-metric-label-total')),
              findsOneWidget);
          expect(
              find.byKey(
                  const ValueKey('compact-overview-metric-label-online')),
              findsOneWidget);
          expect(
              find.byKey(
                  const ValueKey('compact-overview-metric-label-high-risk')),
              findsOneWidget);
          expect(
              find.byKey(
                  const ValueKey('compact-overview-metric-label-active-tasks')),
              findsOneWidget);

          final compactCards = [
            find.byKey(const ValueKey('compact-overview-metric-total')),
            find.byKey(const ValueKey('compact-overview-metric-online')),
            find.byKey(const ValueKey('compact-overview-metric-high-risk')),
            find.byKey(const ValueKey('compact-overview-metric-active-tasks')),
          ];
          final firstDy = tester.getTopLeft(compactCards.first).dy;
          for (final card in compactCards.skip(1)) {
            expect((tester.getTopLeft(card).dy - firstDy).abs(), lessThan(1));
          }
        } else {
          expect(find.text('资产总量'), findsOneWidget);
          expect(find.byKey(const ValueKey('compact-overview-metrics-row')),
              findsNothing);
        }
        expect(find.text('今日态势'), findsOneWidget);
        expect(find.text('快捷入口'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets(
        'dashboard shows compact empty pulse state when all overview metrics are zero',
        (tester) async {
      await _pumpPage(
        tester,
        size: const Size(360, 800),
        overrides: [
          overviewProvider.overrideWith((ref) async => _emptyOverview),
        ],
        child: const DashboardPage(),
      );

      expect(find.text('暂无运营脉冲数据'), findsOneWidget);
      expect(find.text('今日态势'), findsOneWidget);
      expect(find.byKey(const ValueKey('compact-overview-metrics-row')),
          findsOneWidget);
      expect(tester.takeException(), isNull);
    });

    testWidgets('asset list adapts across Android breakpoints', (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            assetListProvider
                .overrideWith((ref, query) async => _sampleAssetList),
          ],
          child: const AssetsPage(
            initialKeyword: '',
            initialStatus: null,
          ),
        );

        expect(find.text('筛选条件'), findsOneWidget);
        expect(find.text('10.0.0.12'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets(
        'asset detail buttons and service list adapt across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            assetDetailProvider
                .overrideWith((ref, assetId) async => _sampleAsset),
            assetRemediationProvider
                .overrideWith((ref, assetId) async => _sampleRemediation),
          ],
          child: const AssetDetailPage(assetId: 'asset-1'),
        );

        expect(find.text('单资产采集'), findsOneWidget);
        expect(find.text('端口与服务'), findsOneWidget);
        expect(find.text('修复态势'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets('task list stays readable across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            taskListProvider
                .overrideWith((ref, status) async => _sampleTaskList),
          ],
          child: const TasksPage(initialStatus: null),
        );

        expect(find.text('状态筛选'), findsOneWidget);
        expect(find.text('扫描 10.0.0.0/24'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets('task detail stays readable across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            taskDetailProvider.overrideWith((ref, taskId) async => _sampleTask),
            taskEventsProvider
                .overrideWith((ref, taskId) async => _sampleTaskEvents),
          ],
          child: const TaskDetailPage(taskId: 'task-1'),
        );

        expect(find.text('执行结果'), findsOneWidget);
        expect(find.text('最近消息'), findsOneWidget);
        expect(find.text('执行事件'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets('risk list stays readable across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            riskListProvider
                .overrideWith((ref, query) async => _sampleRiskList),
          ],
          child: const RisksPage(
            initialSeverity: null,
            initialStatus: null,
          ),
        );

        expect(find.text('风险视图'), findsOneWidget);
        expect(find.text('SSH 弱口令'), findsOneWidget);
        expect(tester.takeException(), isNull);
      }
    });

    testWidgets('profile page stays readable across Android breakpoints',
        (tester) async {
      for (final size in _breakpointSizes) {
        await _pumpPage(
          tester,
          size: size,
          overrides: [
            appStorageProvider.overrideWithValue(
              _FakeAppStorage(
                token: 'header.eyJyb2xlIjoiYWRtaW4ifQ.signature',
                themeMode: ThemeMode.dark,
              ),
            ),
          ],
          child: const ProfilePage(),
        );

        expect(find.text('个人中心'), findsOneWidget);
        expect(find.text('界面风格'), findsOneWidget);
        expect(find.text('当前设备'), findsOneWidget);
        expect(find.text('账号安全'), findsOneWidget);
        expect(find.text('管理员'), findsWidgets);
        expect(tester.takeException(), isNull);
      }
    });
  });
}

Future<void> _pumpPage(
  WidgetTester tester, {
  required Size size,
  required List<Override> overrides,
  required Widget child,
}) async {
  tester.view
    ..physicalSize = size
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
  await tester.pumpAndSettle();
}

class _FakeAppStorage extends AppStorage {
  _FakeAppStorage({
    required this.token,
    required this.themeMode,
  }) : super(const FlutterSecureStorage());

  final String? token;
  final ThemeMode themeMode;

  @override
  Future<String?> readToken() async => token;

  @override
  Future<ThemeMode> readThemeMode() async => themeMode;

  @override
  Future<void> clearToken() async {}

  @override
  Future<void> writeThemeMode(ThemeMode mode) async {}

  @override
  Future<void> writeToken(String token) async {}
}
