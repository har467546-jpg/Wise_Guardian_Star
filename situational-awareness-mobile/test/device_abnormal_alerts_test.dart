import 'package:flutter_test/flutter_test.dart';

import 'package:situational_awareness_mobile/features/alerts/device_abnormal_alerts.dart';
import 'package:situational_awareness_mobile/shared/models/app_models.dart';

const _highRisk = RiskItem(
  id: 'risk-1',
  assetId: 'asset-1',
  assetIp: '10.0.0.8',
  assetHostname: 'srv-01',
  assetPortId: 'port-1',
  severity: RiskSeverityLevel.high,
  status: RiskStatusType.open,
  title: 'SSH 弱口令',
  description: '检测到弱口令',
  evidenceJson: {'service': 'ssh'},
  detectedAt: null,
  resolvedAt: null,
);

const _mediumRisk = RiskItem(
  id: 'risk-2',
  assetId: 'asset-2',
  assetIp: '10.0.0.9',
  assetHostname: 'srv-02',
  assetPortId: 'port-2',
  severity: RiskSeverityLevel.medium,
  status: RiskStatusType.open,
  title: '信息泄露',
  description: '检测到调试页',
  evidenceJson: {'service': 'http'},
  detectedAt: null,
  resolvedAt: null,
);

void main() {
  test('first sync builds baseline without alert', () {
    final decision = evaluateDeviceAbnormalAlert(
      previous: null,
      overview: _buildOverview(
        highRiskFindings: 1,
        recentRisks: const [_highRisk],
      ),
    );

    expect(decision.alert, isNull);
    expect(decision.nextSnapshot.highRiskFindings, 1);
    expect(decision.nextSnapshot.seenRiskIds, contains('risk-1'));
    expect(decision.nextSnapshot.openedRiskIds, isEmpty);
  });

  test('new high risk finding triggers direct detail alert', () {
    const previous = DeviceAbnormalAlertSnapshot(
      highRiskFindings: 1,
      seenRiskIds: ['risk-0'],
    );

    final decision = evaluateDeviceAbnormalAlert(
      previous: previous,
      overview: _buildOverview(
        highRiskFindings: 2,
        recentRisks: const [_highRisk],
      ),
    );

    expect(decision.alert, isNotNull);
    expect(decision.alert!.route, '/risks/risk-1');
    expect(decision.alert!.navigateWithGo, isFalse);
    expect(decision.alert!.message, contains('10.0.0.8（srv-01）'));
    expect(decision.alert!.message, contains('SSH 弱口令'));
  });

  test('count increase without new high risk detail falls back to list alert',
      () {
    const previous = DeviceAbnormalAlertSnapshot(
      highRiskFindings: 1,
      seenRiskIds: ['risk-2'],
    );

    final decision = evaluateDeviceAbnormalAlert(
      previous: previous,
      overview: _buildOverview(
        highRiskFindings: 3,
        recentRisks: const [_mediumRisk],
      ),
    );

    expect(decision.alert, isNotNull);
    expect(decision.alert!.route, '/risks?status=open');
    expect(decision.alert!.navigateWithGo, isTrue);
    expect(decision.alert!.message, contains('2 条新的设备高危异常'));
  });

  test('existing finding is not pushed repeatedly', () {
    const previous = DeviceAbnormalAlertSnapshot(
      highRiskFindings: 1,
      seenRiskIds: ['risk-1'],
    );

    final decision = evaluateDeviceAbnormalAlert(
      previous: previous,
      overview: _buildOverview(
        highRiskFindings: 1,
        recentRisks: const [_highRisk],
      ),
    );

    expect(decision.alert, isNull);
  });

  test('opened risk ids stay intact across syncs', () {
    const previous = DeviceAbnormalAlertSnapshot(
      highRiskFindings: 1,
      seenRiskIds: ['risk-1'],
      openedRiskIds: ['risk-1'],
    );

    final decision = evaluateDeviceAbnormalAlert(
      previous: previous,
      overview: _buildOverview(
        highRiskFindings: 1,
        recentRisks: const [_highRisk],
      ),
    );

    expect(decision.nextSnapshot.openedRiskIds, contains('risk-1'));
  });

  test('detail route parser only extracts concrete risk route', () {
    expect(extractDeviceAbnormalRiskIdFromRoute('/risks/risk-1'), 'risk-1');
    expect(extractDeviceAbnormalRiskIdFromRoute('/risks?status=open'), isNull);
    expect(extractDeviceAbnormalRiskIdFromRoute('/assets/asset-1'), isNull);
  });
}

OverviewSummary _buildOverview({
  required int highRiskFindings,
  required List<RiskItem> recentRisks,
}) {
  return OverviewSummary(
    assetTotal: 12,
    onlineAssets: 8,
    highRiskFindings: highRiskFindings,
    activeTasks: 2,
    recentTasks: const [],
    recentRisks: recentRisks,
    discoveryEntry: const DiscoveryEntry(
      enabled: true,
      pendingJobs: 0,
      runningJobs: 0,
    ),
  );
}
