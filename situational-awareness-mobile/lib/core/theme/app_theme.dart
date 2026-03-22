import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../storage/app_storage.dart';

class AppTheme {
  static const _brand = Color(0xFF3A7BFF);
  static const _success = Color(0xFF22A06B);
  static const _warning = Color(0xFFF4A261);
  static const _danger = Color(0xFFD9485F);
  static const _info = Color(0xFF33A6D8);
  static const _radius = 24.0;

  static ThemeData light() {
    const scheme = ColorScheme.light(
      primary: _brand,
      secondary: Color(0xFF5E8BFF),
      error: _danger,
      surface: Color(0xFFF6F8FC),
    );
    return _buildTheme(
      scheme,
      scaffold: const Color(0xFFF3F6FB),
      elevatedSurface: const Color(0xFFFFFFFF),
      accentSurface: const Color(0xFFEAF1FF),
      textPrimary: const Color(0xFF14213D),
      textSecondary: const Color(0xFF5C6886),
    );
  }

  static ThemeData dark() {
    const scheme = ColorScheme.dark(
      primary: Color(0xFF79A7FF),
      secondary: Color(0xFF8DC9FF),
      error: Color(0xFFFF768A),
      surface: Color(0xFF121B2F),
    );
    return _buildTheme(
      scheme,
      scaffold: const Color(0xFF0A1222),
      elevatedSurface: const Color(0xFF121C31),
      accentSurface: const Color(0xFF162640),
      textPrimary: const Color(0xFFF5F7FB),
      textSecondary: const Color(0xFFA7B2CA),
    );
  }

  static ThemeData _buildTheme(
    ColorScheme scheme, {
    required Color scaffold,
    required Color elevatedSurface,
    required Color accentSurface,
    required Color textPrimary,
    required Color textSecondary,
  }) {
    final base = ThemeData(
      useMaterial3: true,
      colorScheme: scheme,
      scaffoldBackgroundColor: scaffold,
      fontFamily: 'Noto Sans SC',
    );

    return base.copyWith(
      cardTheme: CardThemeData(
        color: elevatedSurface,
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(_radius),
        ),
      ),
      chipTheme: base.chipTheme.copyWith(
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(999),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: accentSurface,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide.none,
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: BorderSide.none,
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(18),
          borderSide: const BorderSide(color: _brand, width: 1.2),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        height: 74,
        backgroundColor: elevatedSurface.withValues(alpha: 0.92),
        indicatorColor: scheme.primary.withValues(alpha: 0.14),
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return TextStyle(
            fontWeight: selected ? FontWeight.w700 : FontWeight.w600,
            fontSize: selected ? 12.5 : 12,
            color: textPrimary,
          );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return IconThemeData(
            size: selected ? 26 : 24,
            color: textPrimary,
          );
        }),
        indicatorShape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
        ),
      ),
      floatingActionButtonTheme: const FloatingActionButtonThemeData(
        backgroundColor: _brand,
        foregroundColor: Colors.white,
      ),
      textTheme: base.textTheme.apply(
        bodyColor: textPrimary,
        displayColor: textPrimary,
      ).copyWith(
        bodyMedium: TextStyle(color: textPrimary, height: 1.35),
        bodySmall: TextStyle(color: textSecondary, height: 1.35),
        titleMedium: TextStyle(color: textPrimary, fontWeight: FontWeight.w700),
        titleLarge: TextStyle(color: textPrimary, fontWeight: FontWeight.w800),
      ),
      extensions: [
        AppThemePalette(
          success: _success,
          warning: _warning,
          danger: _danger,
          info: _info,
          elevatedSurface: elevatedSurface,
          accentSurface: accentSurface,
          textSecondary: textSecondary,
        ),
      ],
    );
  }
}

class AppThemePalette extends ThemeExtension<AppThemePalette> {
  const AppThemePalette({
    required this.success,
    required this.warning,
    required this.danger,
    required this.info,
    required this.elevatedSurface,
    required this.accentSurface,
    required this.textSecondary,
  });

  final Color success;
  final Color warning;
  final Color danger;
  final Color info;
  final Color elevatedSurface;
  final Color accentSurface;
  final Color textSecondary;

  @override
  AppThemePalette copyWith({
    Color? success,
    Color? warning,
    Color? danger,
    Color? info,
    Color? elevatedSurface,
    Color? accentSurface,
    Color? textSecondary,
  }) {
    return AppThemePalette(
      success: success ?? this.success,
      warning: warning ?? this.warning,
      danger: danger ?? this.danger,
      info: info ?? this.info,
      elevatedSurface: elevatedSurface ?? this.elevatedSurface,
      accentSurface: accentSurface ?? this.accentSurface,
      textSecondary: textSecondary ?? this.textSecondary,
    );
  }

  @override
  AppThemePalette lerp(ThemeExtension<AppThemePalette>? other, double t) {
    if (other is! AppThemePalette) {
      return this;
    }
    return AppThemePalette(
      success: Color.lerp(success, other.success, t) ?? success,
      warning: Color.lerp(warning, other.warning, t) ?? warning,
      danger: Color.lerp(danger, other.danger, t) ?? danger,
      info: Color.lerp(info, other.info, t) ?? info,
      elevatedSurface:
          Color.lerp(elevatedSurface, other.elevatedSurface, t) ??
              elevatedSurface,
      accentSurface:
          Color.lerp(accentSurface, other.accentSurface, t) ?? accentSurface,
      textSecondary:
          Color.lerp(textSecondary, other.textSecondary, t) ?? textSecondary,
    );
  }
}

class ThemeModeController extends AsyncNotifier<ThemeMode> {
  @override
  Future<ThemeMode> build() async {
    final storage = ref.read(appStorageProvider);
    return storage.readThemeMode();
  }

  Future<void> setThemeMode(ThemeMode mode) async {
    state = const AsyncLoading();
    await ref.read(appStorageProvider).writeThemeMode(mode);
    state = AsyncData(mode);
  }
}

final themeModeControllerProvider =
    AsyncNotifierProvider<ThemeModeController, ThemeMode>(
  ThemeModeController.new,
);
