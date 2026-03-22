import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/core/auth/session_controller.dart';
import 'package:situational_awareness_mobile/core/network/api_client.dart';
import 'package:situational_awareness_mobile/core/theme/app_theme.dart';
import 'package:situational_awareness_mobile/features/assets/assets_page.dart';
import 'package:situational_awareness_mobile/features/dashboard/dashboard_page.dart';
import 'package:situational_awareness_mobile/features/remediation/remediation_page.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

const _adminSession = SessionSnapshot.signedIn(
  token: 'header.eyJyb2xlIjoiYWRtaW4ifQ.signature',
  role: AppRole.admin,
);

const _analystSession = SessionSnapshot.signedIn(
  token: 'header.eyJyb2xlIjoiYW5hbHlzdCJ9.signature',
  role: AppRole.analyst,
);

const _sampleOverview = OverviewSummary(
  assetTotal: 12,
  onlineAssets: 8,
  highRiskFindings: 2,
  activeTasks: 1,
  recentTasks: [],
  recentRisks: [],
  discoveryEntry: DiscoveryEntry(
    enabled: true,
    pendingJobs: 0,
    runningJobs: 1,
  ),
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
  ],
);

const _sampleRemediationAsset = RemediationAssetDetailModel(
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

const _sampleRemediationList = RemediationAssetListPayload(
  items: [
    RemediationAssetCardModel(
      assetId: 'asset-1',
      ip: '10.0.0.12',
      hostname: 'edge-node',
      osName: 'Ubuntu 24.04',
      status: AssetStatusType.online,
      highestSeverity: RiskSeverityLevel.high,
      findingCount: 1,
      effectivePrivilege: 'sudo',
      lastVerifiedAt: null,
      lastCollectionAt: null,
      recommendedFindingId: 'risk-1',
      runnerStatus: 'online',
      runnerInstallStatus: 'installed',
      activeSessionId: 'session-1',
      activeSessionStatus: 'running',
    ),
  ],
  meta: PageMeta(total: 1, page: 1, pageSize: 24),
);

const _sessionPlan = HostRemediationPlanModel(
  executionReady: true,
  planMode: 'ready',
  currentStageCode: 'prepare',
  blockedReasons: [],
  globalBlockers: [],
  stepBlockers: [],
  findingsCoveredCount: 1,
  serviceCount: 1,
  impactedServices: ['ssh'],
  phaseCount: 1,
  readyStageCount: 1,
  blockedStageCount: 0,
  readyStepCount: 1,
  blockedStepCount: 0,
  summaryText: '已生成 1 个可执行阶段。',
  impactSummary: '将调整 SSH 认证配置。',
  precheckItems: ['确认维护窗口'],
  verifyItems: ['验证 SSH 登录'],
  rollbackNotes: ['保留原配置备份'],
  phases: [
    HostRemediationPhaseModel(
      phaseCode: 'phase-1',
      phaseName: '准备',
      order: 1,
      summary: '准备修复命令',
      readyCount: 1,
      blockedCount: 0,
    ),
  ],
  steps: [
    HostRemediationPlanStepModel(
      stepId: 'step-1',
      findingId: 'risk-1',
      findingTitle: 'SSH 弱口令',
      actionType: 'command',
      title: '更新 SSH 配置',
      phaseCode: 'phase-1',
      phaseName: '准备',
      executionState: 'ready',
      blockedReason: null,
      generatedCommand: 'sudoedit /etc/ssh/sshd_config',
      backupPlan: null,
      renderReason: null,
      serviceName: 'ssh',
      targetFiles: ['/etc/ssh/sshd_config'],
      targetServices: ['sshd'],
      targetPaths: ['/etc/ssh'],
      fallbackStrategy: null,
      fallbackCandidates: [],
      verifyItems: ['重载 sshd'],
      rollbackHint: '恢复原配置',
      blockers: [],
      relatedFindings: [],
      relatedRules: ['rule-ssh'],
    ),
  ],
  stages: [
    HostRemediationStageModel(
      stageCode: 'prepare',
      stageName: '准备修复',
      order: 1,
      summary: '准备并验证 SSH 修复步骤。',
      gateStatus: 'ready',
      readyStepCount: 1,
      blockedStepCount: 0,
      globalBlockers: [],
      relatedFindingIds: ['risk-1'],
      relatedRuleIds: ['rule-ssh'],
      relatedServices: ['ssh'],
      steps: [
        HostRemediationPlanStepModel(
          stepId: 'step-1',
          findingId: 'risk-1',
          findingTitle: 'SSH 弱口令',
          actionType: 'command',
          title: '更新 SSH 配置',
          phaseCode: 'phase-1',
          phaseName: '准备',
          executionState: 'ready',
          blockedReason: null,
          generatedCommand: 'sudoedit /etc/ssh/sshd_config',
          backupPlan: null,
          renderReason: null,
          serviceName: 'ssh',
          targetFiles: ['/etc/ssh/sshd_config'],
          targetServices: ['sshd'],
          targetPaths: ['/etc/ssh'],
          fallbackStrategy: null,
          fallbackCandidates: [],
          verifyItems: ['重载 sshd'],
          rollbackHint: '恢复原配置',
          blockers: [],
          relatedFindings: [],
          relatedRules: ['rule-ssh'],
        ),
      ],
    ),
  ],
);

const _createdSession = RemediationSessionModel(
  sessionId: 'session-created',
  assetId: 'asset-1',
  status: 'ready',
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
  plan: _sessionPlan,
  messages: [
    RemediationMessageModel(
      id: 'message-1',
      role: 'assistant',
      messageType: 'ai_plan_summary',
      content: '建议先完成 Runner 检查，再审批当前阶段。',
      payloadJson: {},
      createdAt: null,
      actions: [],
    ),
  ],
  lastTaskId: 'task-1',
  approvedAt: null,
  approvedBy: null,
);

const _taskSnapshot = RemediationTaskModel(
  taskId: 'task-1',
  status: TaskStatusType.running,
  progress: 45,
  message: '正在准备修复命令',
  assetId: 'asset-1',
  findingId: 'risk-1',
  createdAt: null,
  startedAt: null,
  finishedAt: null,
  eventCount: 2,
  lastEventAt: null,
  executionBoundary: 'runner',
  context: {'asset': 'edge-node'},
  plan: {'stage': 'prepare'},
  execution: {'status': 'running'},
  backups: {},
  reverify: {},
);

void main() {
  testWidgets('dashboard shows remediation entry for admin', (tester) async {
    await _pumpPage(
      tester,
      overrides: [
        overviewProvider.overrideWith((ref) async => _sampleOverview),
        sessionControllerProvider.overrideWith(
          () => _FixedSessionController(_adminSession),
        ),
      ],
      child: const DashboardPage(),
    );

    expect(find.text('修复工作台'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dashboard hides remediation entry for analyst', (tester) async {
    await _pumpPage(
      tester,
      overrides: [
        overviewProvider.overrideWith((ref) async => _sampleOverview),
        sessionControllerProvider.overrideWith(
          () => _FixedSessionController(_analystSession),
        ),
      ],
      child: const DashboardPage(),
    );

    expect(find.text('修复工作台'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('asset detail skips remediation requests for analyst', (
    tester,
  ) async {
    var remediationRequested = false;

    await _pumpPage(
      tester,
      overrides: [
        assetDetailProvider.overrideWith((ref, assetId) async => _sampleAsset),
        assetRemediationProvider.overrideWith((ref, assetId) async {
          remediationRequested = true;
          return _sampleRemediationAsset;
        }),
        sessionControllerProvider.overrideWith(
          () => _FixedSessionController(_analystSession),
        ),
      ],
      child: const AssetDetailPage(assetId: 'asset-1'),
    );

    expect(
      find.text('修复工作台仅管理员可用，当前账号不会请求 remediation 接口。'),
      findsOneWidget,
    );
    expect(remediationRequested, isFalse);
    expect(tester.takeException(), isNull);
  });

  testWidgets('remediation asset gallery renders admin workbench entry', (
    tester,
  ) async {
    final api = _FakeRemediationApiClient(
      remediationList: _sampleRemediationList,
    );

    await _pumpPage(
      tester,
      overrides: [
        apiClientProvider.overrideWith((ref) => api),
      ],
      child: const RemediationAssetGalleryPage(),
    );

    expect(find.text('修复工作台'), findsWidgets);
    expect(find.text('10.0.0.12'), findsOneWidget);
    expect(find.text('进入'), findsOneWidget);
    expect(api.listAssetsCalls, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('remediation workbench creates session when asset is idle', (
    tester,
  ) async {
    final api = _FakeRemediationApiClient(
      remediationAsset: const RemediationAssetDetailModel(
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
        activeSessionId: null,
        activeSessionStatus: null,
        latestTaskId: null,
        canInstallRunner: false,
        runnerInstallBlockedReasons: [],
      ),
      createdSession: _createdSession,
      task: _taskSnapshot,
    );

    await _pumpPage(
      tester,
      overrides: [
        apiClientProvider.overrideWith((ref) => api),
      ],
      child: const RemediationWorkbenchPage(assetId: 'asset-1'),
    );

    expect(api.fetchAssetCalls, 1);
    expect(api.createSessionCalls, 1);
    expect(api.fetchSessionCalls, 0);
    expect(api.fetchTaskCalls, 1);
    expect(find.text('核心操作'), findsOneWidget);
    expect(find.text('阶段推进'), findsOneWidget);
    expect(find.text('审批当前阶段'), findsOneWidget);
    expect(find.text('建议先完成 Runner 检查，再审批当前阶段。'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

Future<void> _pumpPage(
  WidgetTester tester, {
  required List<Override> overrides,
  required Widget child,
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
  await tester.pumpAndSettle();
}

class _FixedSessionController extends SessionController {
  _FixedSessionController(this.snapshot);

  final SessionSnapshot snapshot;

  @override
  Future<SessionSnapshot> build() async => snapshot;
}

class _FakeRemediationApiClient extends ApiClient {
  _FakeRemediationApiClient({
    this.remediationList,
    this.remediationAsset,
    this.createdSession,
    this.task,
  }) : super(Dio());

  final RemediationAssetListPayload? remediationList;
  final RemediationAssetDetailModel? remediationAsset;
  final RemediationSessionModel? createdSession;
  final RemediationTaskModel? task;

  int listAssetsCalls = 0;
  int fetchAssetCalls = 0;
  int createSessionCalls = 0;
  int fetchSessionCalls = 0;
  int fetchTaskCalls = 0;

  @override
  Future<RemediationAssetListPayload> listRemediationAssets({
    String? keyword,
    int page = 1,
    int pageSize = 24,
  }) async {
    listAssetsCalls += 1;
    if (remediationList == null) {
      throw StateError('remediationList not configured');
    }
    return remediationList!;
  }

  @override
  Future<RemediationAssetDetailModel> fetchRemediationAsset(
    String assetId,
  ) async {
    fetchAssetCalls += 1;
    if (remediationAsset == null) {
      throw StateError('remediationAsset not configured');
    }
    return remediationAsset!;
  }

  @override
  Future<RemediationSessionModel> createRemediationSession(
    String assetId, {
    String? note,
  }) async {
    createSessionCalls += 1;
    if (createdSession == null) {
      throw StateError('createdSession not configured');
    }
    return createdSession!;
  }

  @override
  Future<RemediationSessionModel> fetchRemediationSession(
    String sessionId,
  ) async {
    fetchSessionCalls += 1;
    throw StateError('session not configured');
  }

  @override
  Future<RemediationTaskModel> fetchRemediationTask(String taskId) async {
    fetchTaskCalls += 1;
    if (task == null) {
      throw StateError('task not configured');
    }
    return task!;
  }
}
