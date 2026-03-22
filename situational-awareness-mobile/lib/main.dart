import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'app.dart';
import 'features/alerts/device_abnormal_notifications.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeDeviceAbnormalNotifications();
  if (Platform.isAndroid) {
    await registerDeviceAbnormalBackgroundSync();
  }
  runApp(const ProviderScope(child: SituationalAwarenessMobileApp()));
}
