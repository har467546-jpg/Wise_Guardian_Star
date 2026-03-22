import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AppStorage {
  AppStorage(this._secureStorage);

  static const tokenStorageKey = 'sa.access_token';
  static const _themeKey = 'sa.theme_mode';

  final FlutterSecureStorage _secureStorage;

  Future<String?> readToken() => _secureStorage.read(key: tokenStorageKey);

  Future<void> writeToken(String token) =>
      _secureStorage.write(key: tokenStorageKey, value: token);

  Future<void> clearToken() => _secureStorage.delete(key: tokenStorageKey);

  Future<ThemeMode> readThemeMode() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getString(_themeKey);
    return switch (raw) {
      'light' => ThemeMode.light,
      'dark' => ThemeMode.dark,
      _ => ThemeMode.system,
    };
  }

  Future<void> writeThemeMode(ThemeMode mode) async {
    final prefs = await SharedPreferences.getInstance();
    final raw = switch (mode) {
      ThemeMode.light => 'light',
      ThemeMode.dark => 'dark',
      ThemeMode.system => 'system',
    };
    await prefs.setString(_themeKey, raw);
  }
}

final secureStorageProvider = Provider<FlutterSecureStorage>((ref) {
  return const FlutterSecureStorage();
});

final appStorageProvider = Provider<AppStorage>((ref) {
  return AppStorage(ref.watch(secureStorageProvider));
});
