import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:workmanager/workmanager.dart';

import '../../core/network/api_client.dart';
import '../../core/storage/app_storage.dart';
import '../../shared/models/app_models.dart';
import 'device_abnormal_alerts.dart';

const _notificationPermissionPromptedKey =
    'sa.device_abnormal.notification_permission_prompted';
const _highRiskSnapshotKey = 'sa.device_abnormal.high_risk_snapshot';
const _seenRiskIdsSnapshotKey = 'sa.device_abnormal.seen_risk_ids_snapshot';
const _openedRiskIdsSnapshotKey = 'sa.device_abnormal.opened_risk_ids_snapshot';
const _backgroundTaskUniqueName = 'sa.device_abnormal.background_sync';
const _backgroundTaskName = 'device_abnormal_background_sync';
const _notificationChannelId = 'device_abnormal_alerts';
const _notificationChannelName = '设备异常提醒';
const _notificationChannelDescription = '设备高危异常的系统提醒';
const AndroidNotificationChannel _deviceAbnormalNotificationChannel =
    AndroidNotificationChannel(
  _notificationChannelId,
  _notificationChannelName,
  description: _notificationChannelDescription,
  importance: Importance.max,
);

final FlutterLocalNotificationsPlugin _notificationsPlugin =
    FlutterLocalNotificationsPlugin();
final StreamController<DeviceAbnormalNotificationIntent>
    _notificationIntentController =
    StreamController<DeviceAbnormalNotificationIntent>.broadcast();

DeviceAbnormalNotificationIntent? _pendingNotificationIntent;
bool _notificationsInitialized = false;
bool _backgroundSyncRegistered = false;

class DeviceAbnormalNotificationStatus {
  const DeviceAbnormalNotificationStatus({
    required this.initialized,
    required this.permissionPrompted,
    required this.backgroundSyncRegistered,
    required this.backgroundSyncAvailable,
    required this.channelId,
  });

  final bool initialized;
  final bool permissionPrompted;
  final bool backgroundSyncRegistered;
  final bool backgroundSyncAvailable;
  final String channelId;
}

class DeviceAbnormalNotificationIntent {
  const DeviceAbnormalNotificationIntent({
    required this.route,
    required this.navigateWithGo,
  });

  final String route;
  final bool navigateWithGo;
}

Stream<DeviceAbnormalNotificationIntent>
    get deviceAbnormalNotificationIntents =>
        _notificationIntentController.stream;

DeviceAbnormalNotificationIntent?
    takePendingDeviceAbnormalNotificationIntent() {
  final intent = _pendingNotificationIntent;
  _pendingNotificationIntent = null;
  return intent;
}

void dispatchDeviceAbnormalNotificationIntent(
  DeviceAbnormalNotificationIntent intent,
) {
  if (_notificationIntentController.hasListener) {
    _notificationIntentController.add(intent);
    return;
  }
  _pendingNotificationIntent = intent;
}

Future<void> initializeDeviceAbnormalNotifications() async {
  if (_notificationsInitialized) {
    return;
  }

  const settings = InitializationSettings(
    android: AndroidInitializationSettings('@mipmap/ic_launcher'),
    iOS: DarwinInitializationSettings(
      requestAlertPermission: false,
      requestBadgePermission: false,
      requestSoundPermission: false,
    ),
    linux: LinuxInitializationSettings(
      defaultActionName: '查看详情',
    ),
  );

  await _notificationsPlugin.initialize(
    settings: settings,
    onDidReceiveNotificationResponse: (response) {
      final intent = _decodeNotificationIntent(response.payload);
      if (intent == null) {
        return;
      }
      dispatchDeviceAbnormalNotificationIntent(intent);
    },
  );
  await _notificationsPlugin
      .resolvePlatformSpecificImplementation<
          AndroidFlutterLocalNotificationsPlugin>()
      ?.createNotificationChannel(_deviceAbnormalNotificationChannel);

  final launchDetails =
      await _notificationsPlugin.getNotificationAppLaunchDetails();
  if (launchDetails?.didNotificationLaunchApp ?? false) {
    _pendingNotificationIntent = _decodeNotificationIntent(
      launchDetails?.notificationResponse?.payload,
    );
  }

  _notificationsInitialized = true;
}

Future<void> ensureDeviceAbnormalNotificationPermissionPrompted() async {
  final prefs = await SharedPreferences.getInstance();
  if (prefs.getBool(_notificationPermissionPromptedKey) == true) {
    return;
  }

  await requestDeviceAbnormalNotificationPermission();
}

Future<void> requestDeviceAbnormalNotificationPermission() async {
  await initializeDeviceAbnormalNotifications();

  if (Platform.isAndroid) {
    await _notificationsPlugin
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>()
        ?.requestNotificationsPermission();
  } else if (Platform.isIOS) {
    await _notificationsPlugin
        .resolvePlatformSpecificImplementation<
            IOSFlutterLocalNotificationsPlugin>()
        ?.requestPermissions(
          alert: true,
          badge: true,
          sound: true,
        );
  }

  final prefs = await SharedPreferences.getInstance();
  await prefs.setBool(_notificationPermissionPromptedKey, true);
}

Future<void> registerDeviceAbnormalBackgroundSync() async {
  if (!Platform.isAndroid || _backgroundSyncRegistered) {
    return;
  }

  await Workmanager().initialize(deviceAbnormalAlertWorkmanagerDispatcher);
  await Workmanager().registerPeriodicTask(
    _backgroundTaskUniqueName,
    _backgroundTaskName,
    frequency: const Duration(minutes: 15),
    constraints: Constraints(
      networkType: NetworkType.connected,
    ),
    existingWorkPolicy: ExistingPeriodicWorkPolicy.keep,
  );
  _backgroundSyncRegistered = true;
}

Future<DeviceAbnormalNotificationStatus>
    readDeviceAbnormalNotificationStatus() async {
  final prefs = await SharedPreferences.getInstance();
  return DeviceAbnormalNotificationStatus(
    initialized: _notificationsInitialized,
    permissionPrompted:
        prefs.getBool(_notificationPermissionPromptedKey) == true,
    backgroundSyncRegistered: _backgroundSyncRegistered,
    backgroundSyncAvailable: Platform.isAndroid,
    channelId: _notificationChannelId,
  );
}

Future<DeviceAbnormalAlert?> syncDeviceAbnormalAlerts({
  required Future<OverviewSummary> Function() loadOverview,
  bool showSystemNotification = false,
}) async {
  final previousSnapshot = await _readDeviceAbnormalAlertSnapshot();
  final overview = await loadOverview();
  final decision = evaluateDeviceAbnormalAlert(
    previous: previousSnapshot,
    overview: overview,
  );
  await _writeDeviceAbnormalAlertSnapshot(decision.nextSnapshot);

  final alert = decision.alert;
  if (showSystemNotification && alert != null) {
    await showDeviceAbnormalSystemNotification(
      message: alert.message,
      route: alert.route,
      navigateWithGo: alert.navigateWithGo,
    );
  }
  return alert;
}

Future<DeviceAbnormalAlertSnapshot?> _readDeviceAbnormalAlertSnapshot() async {
  final prefs = await SharedPreferences.getInstance();
  final highRiskFindings = prefs.getInt(_highRiskSnapshotKey);
  final seenRiskIds = prefs.getStringList(_seenRiskIdsSnapshotKey);
  if (highRiskFindings == null) {
    return null;
  }
  return DeviceAbnormalAlertSnapshot(
    highRiskFindings: highRiskFindings,
    seenRiskIds: seenRiskIds ?? const [],
    openedRiskIds: prefs.getStringList(_openedRiskIdsSnapshotKey) ?? const [],
  );
}

Future<void> _writeDeviceAbnormalAlertSnapshot(
  DeviceAbnormalAlertSnapshot snapshot,
) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setInt(_highRiskSnapshotKey, snapshot.highRiskFindings);
  await prefs.setStringList(_seenRiskIdsSnapshotKey, snapshot.seenRiskIds);
  await prefs.setStringList(_openedRiskIdsSnapshotKey, snapshot.openedRiskIds);
}

Future<void> rememberDeviceAbnormalRiskAlerted({
  required String riskId,
  int? highRiskFindings,
}) async {
  final normalizedRiskId = riskId.trim();
  if (normalizedRiskId.isEmpty) {
    return;
  }

  final previous = await _readDeviceAbnormalAlertSnapshot();
  await _writeDeviceAbnormalAlertSnapshot(
    DeviceAbnormalAlertSnapshot(
      highRiskFindings: _resolveNextHighRiskFindings(
        previous,
        highRiskFindings,
      ),
      seenRiskIds: _mergeSnapshotRiskIds(
        previous?.seenRiskIds ?? const [],
        [normalizedRiskId],
      ),
      openedRiskIds: previous?.openedRiskIds ?? const [],
    ),
  );
}

Future<void> markDeviceAbnormalRiskSeen({
  required String riskId,
  int? highRiskFindings,
}) async {
  final normalizedRiskId = riskId.trim();
  if (normalizedRiskId.isEmpty) {
    return;
  }

  final previous = await _readDeviceAbnormalAlertSnapshot();
  await _writeDeviceAbnormalAlertSnapshot(
    DeviceAbnormalAlertSnapshot(
      highRiskFindings: _resolveNextHighRiskFindings(
        previous,
        highRiskFindings,
      ),
      seenRiskIds: _mergeSnapshotRiskIds(
        previous?.seenRiskIds ?? const [],
        [normalizedRiskId],
      ),
      openedRiskIds: _mergeSnapshotRiskIds(
        previous?.openedRiskIds ?? const [],
        [normalizedRiskId],
      ),
    ),
  );
}

Future<void> markDeviceAbnormalRouteSeen({
  required String route,
  int? highRiskFindings,
}) async {
  final riskId = extractDeviceAbnormalRiskIdFromRoute(route);
  if (riskId == null) {
    return;
  }
  await markDeviceAbnormalRiskSeen(
    riskId: riskId,
    highRiskFindings: highRiskFindings,
  );
}

int _resolveNextHighRiskFindings(
  DeviceAbnormalAlertSnapshot? previous,
  int? highRiskFindings,
) {
  final previousHighRiskFindings = previous?.highRiskFindings ?? 0;
  if (highRiskFindings == null) {
    return previousHighRiskFindings;
  }
  return highRiskFindings > previousHighRiskFindings
      ? highRiskFindings
      : previousHighRiskFindings;
}

Future<void> showDeviceAbnormalSystemNotification({
  String title = '设备异常提醒',
  required String message,
  required String route,
  bool navigateWithGo = false,
}) async {
  await initializeDeviceAbnormalNotifications();
  await _notificationsPlugin.show(
    id: _notificationIdForRoute(route),
    title: title,
    body: message,
    notificationDetails: NotificationDetails(
      android: AndroidNotificationDetails(
        _deviceAbnormalNotificationChannel.id,
        _deviceAbnormalNotificationChannel.name,
        channelDescription: _notificationChannelDescription,
        importance: Importance.max,
        priority: Priority.high,
      ),
      iOS: const DarwinNotificationDetails(),
      linux: const LinuxNotificationDetails(),
    ),
    payload: _encodeNotificationIntent(
      DeviceAbnormalNotificationIntent(
        route: route,
        navigateWithGo: navigateWithGo,
      ),
    ),
  );
}

int _notificationIdForRoute(String route) {
  return route.hashCode & 0x7fffffff;
}

List<String> _mergeSnapshotRiskIds(
  List<String> previous,
  Iterable<String> incoming,
) {
  final merged = <String>[];
  for (final riskId in incoming) {
    final normalized = riskId.trim();
    if (normalized.isNotEmpty && !merged.contains(normalized)) {
      merged.add(normalized);
    }
  }
  for (final riskId in previous) {
    final normalized = riskId.trim();
    if (normalized.isNotEmpty && !merged.contains(normalized)) {
      merged.add(normalized);
    }
    if (merged.length >= 64) {
      break;
    }
  }
  return merged;
}

String _encodeNotificationIntent(DeviceAbnormalNotificationIntent intent) {
  return jsonEncode({
    'route': intent.route,
    'navigate_with_go': intent.navigateWithGo,
  });
}

DeviceAbnormalNotificationIntent? _decodeNotificationIntent(String? payload) {
  final raw = payload?.trim() ?? '';
  if (raw.isEmpty) {
    return null;
  }
  try {
    final json = jsonDecode(raw);
    if (json is! Map<String, dynamic>) {
      return null;
    }
    final route = json['route'] as String? ?? '';
    if (route.isEmpty) {
      return null;
    }
    return DeviceAbnormalNotificationIntent(
      route: route,
      navigateWithGo: json['navigate_with_go'] as bool? ?? false,
    );
  } catch (_) {
    return null;
  }
}

@pragma('vm:entry-point')
void deviceAbnormalAlertWorkmanagerDispatcher() {
  Workmanager().executeTask((taskName, _) async {
    WidgetsFlutterBinding.ensureInitialized();

    if (taskName != _backgroundTaskName) {
      return true;
    }

    try {
      await initializeConfiguredApiBaseUrl();
      await synchronizeConfiguredApiBaseUrl(forceRescan: false);
      await initializeDeviceAbnormalNotifications();
      final token = await const FlutterSecureStorage().read(
        key: AppStorage.tokenStorageKey,
      );
      if (token == null || token.isEmpty) {
        return true;
      }

      final dio = Dio(
        BaseOptions(
          baseUrl: configuredApiBaseUrl,
          connectTimeout: const Duration(seconds: 12),
          receiveTimeout: const Duration(seconds: 20),
          sendTimeout: const Duration(seconds: 12),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $token',
          },
        ),
      );

      final client = ApiClient(dio);
      await syncDeviceAbnormalAlerts(
        loadOverview: client.fetchOverview,
        showSystemNotification: true,
      );
    } catch (_) {
      return true;
    }

    return true;
  });
}
