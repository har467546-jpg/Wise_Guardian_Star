import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/theme/app_theme.dart';
import '../../features/haor/mobile_haor_assistant.dart';
import 'adaptive_layout.dart';

enum StatusTone { neutral, info, success, warning, danger }

class ScreenScaffold extends StatelessWidget {
  const ScreenScaffold({
    super.key,
    required this.title,
    this.subtitle,
    this.actions,
    this.floatingActionButton,
    this.contentBottomPadding = 24,
    this.maxContentWidth,
    required this.child,
  });

  final String title;
  final String? subtitle;
  final List<Widget>? actions;
  final Widget? floatingActionButton;
  final double contentBottomPadding;
  final double? maxContentWidth;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final routeUri = _resolveRouteUri(context);
    final effectiveBottomPadding =
        contentBottomPadding < 112 ? 112.0 : contentBottomPadding;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.transparent,
        foregroundColor: theme.colorScheme.onSurface,
        surfaceTintColor: Colors.transparent,
        scrolledUnderElevation: 0,
        titleSpacing: 16,
        title: Text(title),
        actions: actions,
      ),
      floatingActionButton: floatingActionButton,
      body: DecoratedBox(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              theme.scaffoldBackgroundColor,
              palette.accentSurface.withValues(alpha: 0.9),
              theme.colorScheme.primary.withValues(alpha: 0.08),
            ],
          ),
        ),
        child: SafeArea(
          top: false,
          child: Stack(
            children: [
              AdaptiveLayoutBuilder(
                builder: (context, layout) {
                  return SingleChildScrollView(
                    padding: EdgeInsets.fromLTRB(
                      layout.horizontalPadding,
                      8,
                      layout.horizontalPadding,
                      effectiveBottomPadding,
                    ),
                    child: Align(
                      alignment: Alignment.topCenter,
                      child: ConstrainedBox(
                        constraints: BoxConstraints(
                          maxWidth: maxContentWidth ?? layout.contentMaxWidth,
                        ),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            if (subtitle != null) ...[
                              ConstrainedBox(
                                constraints:
                                    const BoxConstraints(maxWidth: 560),
                                child: Text(
                                  subtitle!,
                                  style: theme.textTheme.titleMedium?.copyWith(
                                    color: palette.textSecondary,
                                    fontWeight: FontWeight.w500,
                                    height: 1.4,
                                  ),
                                ),
                              ),
                              SizedBox(height: layout.sectionGap),
                            ],
                            child,
                          ],
                        ),
                      ),
                    ),
                  );
                },
              ),
              MobileHaorAssistantLauncher(
                routeUri: routeUri,
                screenTitle: title,
                screenSubtitle: subtitle,
              ),
            ],
          ),
        ),
      ),
    );
  }
}

Uri _resolveRouteUri(BuildContext context) {
  try {
    return GoRouterState.of(context).uri;
  } catch (_) {
    return Uri(path: '/');
  }
}

class GlassPanel extends StatelessWidget {
  const GlassPanel({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(18),
  });

  final Widget child;
  final EdgeInsets padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: palette.elevatedSurface.withValues(alpha: 0.88),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(
          color: theme.colorScheme.onSurface.withValues(alpha: 0.06),
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(
              alpha: theme.brightness == Brightness.dark ? 0.18 : 0.06,
            ),
            blurRadius: 32,
            offset: const Offset(0, 12),
          ),
        ],
      ),
      child: child,
    );
  }
}

class MetricCard extends StatelessWidget {
  const MetricCard({
    super.key,
    required this.label,
    required this.value,
    required this.tone,
    this.trailing,
    this.minHeight = 126,
  });

  final String label;
  final String value;
  final StatusTone tone;
  final Widget? trailing;
  final double minHeight;

  @override
  Widget build(BuildContext context) {
    final color = _toneColor(context, tone);
    return ConstrainedBox(
      constraints: BoxConstraints(minHeight: minHeight),
      child: GlassPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child:
                      Text(label, style: Theme.of(context).textTheme.bodySmall),
                ),
                if (trailing != null) trailing!,
              ],
            ),
            const SizedBox(height: 22),
            Text(
              value,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                    fontWeight: FontWeight.w800,
                    color: color,
                  ),
            ),
          ],
        ),
      ),
    );
  }
}

class StatusBadge extends StatelessWidget {
  const StatusBadge({
    super.key,
    required this.label,
    required this.tone,
  });

  final String label;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final color = _toneColor(context, tone);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelMedium?.copyWith(
              color: color,
              fontWeight: FontWeight.w700,
            ),
      ),
    );
  }
}

class SectionHeading extends StatelessWidget {
  const SectionHeading({
    super.key,
    required this.title,
    this.subtitle,
    this.action,
  });

  final String title;
  final String? subtitle;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: Theme.of(context).textTheme.titleLarge),
              if (subtitle != null) ...[
                const SizedBox(height: 4),
                Text(subtitle!, style: Theme.of(context).textTheme.bodySmall),
              ],
            ],
          ),
        ),
        if (action != null) action!,
      ],
    );
  }
}

String formatDateTimeLabel(DateTime? value, {String fallback = '未记录'}) {
  if (value == null) {
    return fallback;
  }

  final local = value.toLocal();
  final month = local.month.toString().padLeft(2, '0');
  final day = local.day.toString().padLeft(2, '0');
  final hour = local.hour.toString().padLeft(2, '0');
  final minute = local.minute.toString().padLeft(2, '0');
  return '${local.year}-$month-$day $hour:$minute';
}

class AppInfoChip extends StatelessWidget {
  const AppInfoChip({
    super.key,
    required this.label,
    required this.icon,
    this.tone = StatusTone.neutral,
  });

  final String label;
  final IconData icon;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final highlighted = tone != StatusTone.neutral;
    final color =
        highlighted ? _toneColor(context, tone) : palette.textSecondary;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: highlighted
            ? color.withValues(alpha: 0.10)
            : theme.colorScheme.onSurface.withValues(alpha: 0.04),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
          color: highlighted
              ? color.withValues(alpha: 0.14)
              : theme.colorScheme.onSurface.withValues(alpha: 0.06),
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Flexible(
            child: Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: theme.textTheme.labelMedium?.copyWith(
                color: highlighted ? color : theme.colorScheme.onSurface,
                fontWeight: FontWeight.w700,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class DetailMetricTile extends StatelessWidget {
  const DetailMetricTile({
    super.key,
    required this.label,
    required this.value,
    required this.icon,
    this.tone = StatusTone.neutral,
  });

  final String label;
  final String value;
  final IconData icon;
  final StatusTone tone;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final highlighted = tone != StatusTone.neutral;
    final color =
        highlighted ? _toneColor(context, tone) : theme.colorScheme.primary;

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: palette.accentSurface.withValues(alpha: 0.74),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: highlighted
              ? color.withValues(alpha: 0.14)
              : theme.colorScheme.onSurface.withValues(alpha: 0.06),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: color),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  label,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: theme.textTheme.labelMedium?.copyWith(
                    color: palette.textSecondary,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            value,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: theme.textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w800,
              height: 1.15,
            ),
          ),
        ],
      ),
    );
  }
}

class JsonPreviewCard extends StatelessWidget {
  const JsonPreviewCard({
    super.key,
    required this.title,
    required this.data,
    required this.emptyMessage,
    this.subtitle,
  });

  final String title;
  final String? subtitle;
  final Map<String, dynamic> data;
  final String emptyMessage;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    final prettyJson = const JsonEncoder.withIndent('  ').convert(data);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: title,
            subtitle:
                subtitle ?? (data.isEmpty ? '当前没有结构化数据。' : '结构化字段仅供排障与复核。'),
          ),
          const SizedBox(height: 12),
          if (data.isEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 18),
              decoration: BoxDecoration(
                color: palette.accentSurface.withValues(alpha: 0.7),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.06),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.data_object_rounded,
                    size: 18,
                    color: palette.textSecondary,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      emptyMessage,
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: palette.textSecondary,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            )
          else
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: theme.colorScheme.onSurface.withValues(alpha: 0.03),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: theme.colorScheme.onSurface.withValues(alpha: 0.06),
                ),
              ),
              child: SelectableText(
                prettyJson,
                style: theme.textTheme.bodySmall?.copyWith(
                  fontFeatures: const [FontFeature.tabularFigures()],
                  height: 1.5,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

class AppEmptyState extends StatelessWidget {
  const AppEmptyState({
    super.key,
    required this.title,
    required this.message,
    this.action,
  });

  final String title;
  final String message;
  final Widget? action;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        children: [
          Icon(
            Icons.inbox_rounded,
            size: 34,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(height: 12),
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 6),
          Text(
            message,
            style: Theme.of(context).textTheme.bodySmall,
            textAlign: TextAlign.center,
          ),
          if (action != null) ...[
            const SizedBox(height: 14),
            action!,
          ],
        ],
      ),
    );
  }
}

class AsyncStateView extends StatelessWidget { // 封装异步态势图
  const AsyncStateView({
    super.key,
    required this.loading,
    required this.error,
    required this.onRetry,
    required this.child,
  });

  final bool loading;
  final Object? error;
  final VoidCallback onRetry;
  final Widget child;

  @override
  Widget build(BuildContext context) { // 封装通用的加载 - 报错 - 重试组件
    if (loading) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.symmetric(vertical: 48),
          child: CircularProgressIndicator(),
        ),
      );
    }
    if (error != null) {
      return AppEmptyState(
        title: '加载失败',
        message: error.toString(),
        action: FilledButton(onPressed: onRetry, child: const Text('重新加载')),
      );
    }
    return child;
  }
}

StatusTone toneForTaskStatus(String value) {
  return switch (value) {
    'success' => StatusTone.success,
    'running' || 'retry' => StatusTone.info,
    'failure' => StatusTone.danger,
    'pending' => StatusTone.warning,
    'canceled' => StatusTone.neutral,
    _ => StatusTone.neutral,
  };
}

StatusTone toneForRiskStatus(String value) {
  return switch (value) {
    'fixed' => StatusTone.success,
    'ignored' => StatusTone.neutral,
    'open' => StatusTone.warning,
    _ => StatusTone.neutral,
  };
}

StatusTone toneForRiskSeverity(String value) {
  return switch (value) {
    'critical' || 'high' => StatusTone.danger,
    'medium' => StatusTone.warning,
    'low' => StatusTone.info,
    _ => StatusTone.neutral,
  };
}

StatusTone toneForAssetStatus(String value) {
  return switch (value) {
    'online' => StatusTone.success,
    'collecting' => StatusTone.info,
    'offline' => StatusTone.warning,
    _ => StatusTone.neutral,
  };
}

StatusTone toneForDiscoveryStatus(String value) {
  return switch (value) {
    'completed' => StatusTone.success,
    'running' => StatusTone.info,
    'failed' => StatusTone.danger,
    'pending' => StatusTone.warning,
    _ => StatusTone.neutral,
  };
}

Color _toneColor(BuildContext context, StatusTone tone) {
  final theme = Theme.of(context);
  final palette = theme.extension<AppThemePalette>()!;
  return switch (tone) {
    StatusTone.success => palette.success,
    StatusTone.warning => palette.warning,
    StatusTone.danger => palette.danger,
    StatusTone.info => palette.info,
    StatusTone.neutral => theme.colorScheme.primary,
  };
}
