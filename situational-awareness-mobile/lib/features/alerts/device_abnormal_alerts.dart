import '../../shared/models/app_models.dart';

class DeviceAbnormalAlertSnapshot {
  const DeviceAbnormalAlertSnapshot({
    required this.highRiskFindings,
    required this.seenRiskIds,
  });

  final int highRiskFindings;
  final List<String> seenRiskIds;
}

class DeviceAbnormalAlert {
  const DeviceAbnormalAlert({
    required this.message,
    required this.route,
    this.actionLabel = '查看',
    this.navigateWithGo = false,
  });

  final String message;
  final String route;
  final String actionLabel;
  final bool navigateWithGo;
}

class DeviceAbnormalAlertDecision {
  const DeviceAbnormalAlertDecision({
    required this.nextSnapshot,
    this.alert,
  });

  final DeviceAbnormalAlertSnapshot nextSnapshot;
  final DeviceAbnormalAlert? alert;
}

DeviceAbnormalAlertDecision evaluateDeviceAbnormalAlert({
  required DeviceAbnormalAlertSnapshot? previous,
  required OverviewSummary overview,
}) {
  final nextSnapshot = DeviceAbnormalAlertSnapshot(
    highRiskFindings: overview.highRiskFindings,
    seenRiskIds: _mergeSeenRiskIds(
      previous?.seenRiskIds ?? const [],
      overview.recentRisks,
    ),
  );

  if (previous == null) {
    return DeviceAbnormalAlertDecision(nextSnapshot: nextSnapshot);
  }

  final seenRiskIds = previous.seenRiskIds.toSet();

  for (final risk in overview.recentRisks) {
    final riskId = risk.id.trim();
    if (riskId.isEmpty ||
        seenRiskIds.contains(riskId) ||
        risk.status != RiskStatusType.open ||
        !_isAbnormalSeverity(risk.severity)) {
      continue;
    }
    return DeviceAbnormalAlertDecision(
      nextSnapshot: nextSnapshot,
      alert: DeviceAbnormalAlert(
        message:
            '${_assetLabel(risk)} 新增${risk.severity.label}异常：${risk.title}',
        route: '/risks/$riskId',
      ),
    );
  }

  final delta = overview.highRiskFindings - previous.highRiskFindings;
  if (delta > 0) {
    return DeviceAbnormalAlertDecision(
      nextSnapshot: nextSnapshot,
      alert: DeviceAbnormalAlert(
        message:
            delta == 1 ? '发现 1 条新的设备高危异常，请及时处理。' : '发现 $delta 条新的设备高危异常，请及时处理。',
        route: '/risks?status=open',
        navigateWithGo: true,
      ),
    );
  }

  return DeviceAbnormalAlertDecision(nextSnapshot: nextSnapshot);
}

bool _isAbnormalSeverity(RiskSeverityLevel value) {
  return value == RiskSeverityLevel.high || value == RiskSeverityLevel.critical;
}

String _assetLabel(RiskItem risk) {
  final hostname = risk.assetHostname?.trim() ?? '';
  if (hostname.isEmpty) {
    return risk.assetIp;
  }
  return '${risk.assetIp}（$hostname）';
}

List<String> _mergeSeenRiskIds(
  List<String> previous,
  List<RiskItem> recentRisks,
) {
  final merged = <String>[];
  for (final risk in recentRisks) {
    final id = risk.id.trim();
    if (id.isNotEmpty && !merged.contains(id)) {
      merged.add(id);
    }
  }
  for (final id in previous) {
    final normalized = id.trim();
    if (normalized.isNotEmpty && !merged.contains(normalized)) {
      merged.add(normalized);
    }
    if (merged.length >= 64) {
      break;
    }
  }
  return merged;
}
