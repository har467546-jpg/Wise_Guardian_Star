import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../features/alerts/device_alert_stream.dart';
import '../../features/alerts/device_abnormal_notifications.dart';
import '../../features/haor/mobile_haor_assistant.dart';

class AppShell extends ConsumerStatefulWidget {
  const AppShell({super.key, required this.navigationShell});

  final StatefulNavigationShell navigationShell;

  static const _destinations = [
    _ShellDestination(
      label: '总览',
      icon: Icons.space_dashboard_outlined,
      selectedIcon: Icons.space_dashboard_rounded,
    ),
    _ShellDestination(
      label: '资产',
      icon: Icons.storage_outlined,
      selectedIcon: Icons.storage_rounded,
    ),
    _ShellDestination(
      label: '任务',
      icon: Icons.assignment_outlined,
      selectedIcon: Icons.assignment_rounded,
    ),
    _ShellDestination(
      label: '风险',
      icon: Icons.shield_outlined,
      selectedIcon: Icons.shield_rounded,
    ),
    _ShellDestination(
      label: '我的',
      icon: Icons.person_outline_rounded,
      selectedIcon: Icons.person_rounded,
    ),
  ];

  @override
  ConsumerState<AppShell> createState() => _AppShellState();
}

class _AppShellState extends ConsumerState<AppShell>
    with WidgetsBindingObserver {
  static const _alertPollingInterval = Duration(seconds: 45);

  Timer? _alertPollingTimer;
  Timer? _deviceAlertHideTimer;
  bool _syncingAlerts = false;
  DeviceAlertStreamController? _deviceAlertStream;
  OverlayEntry? _deviceAlertOverlayEntry;
  StreamSubscription<DeviceAbnormalNotificationIntent>?
      _notificationIntentSubscription;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _notificationIntentSubscription =
        deviceAbnormalNotificationIntents.listen(_handleNotificationIntent);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        final initialIntent = takePendingDeviceAbnormalNotificationIntent();
        if (initialIntent != null) {
          _handleNotificationIntent(initialIntent);
        }
        unawaited(ensureDeviceAbnormalNotificationPermissionPrompted());
        unawaited(_resumeRealtimeAlerts());
        _resumeAlertPolling();
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _notificationIntentSubscription?.cancel();
    _pauseAlertPolling();
    _dismissDeviceAlertPrompt();
    unawaited(_stopRealtimeAlerts());
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.resumed:
        unawaited(_resumeRealtimeAlerts());
        _resumeAlertPolling();
        return;
      case AppLifecycleState.inactive:
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
      case AppLifecycleState.detached:
        unawaited(_stopRealtimeAlerts());
        _pauseAlertPolling();
        return;
    }
  }

  Future<void> _resumeRealtimeAlerts() async {
    final token =
        ref.read(sessionControllerProvider).valueOrNull?.token?.trim() ?? '';
    if (token.isEmpty) {
      await _stopRealtimeAlerts();
      return;
    }

    final currentStream = _deviceAlertStream;
    if (currentStream != null && currentStream.token == token) {
      await currentStream.start();
      return;
    }

    await currentStream?.dispose();
    final stream = DeviceAlertStreamController(
      token: token,
      onAlert: _handleRealtimeDeviceAlert,
    );
    _deviceAlertStream = stream;
    await stream.start();
  }

  Future<void> _stopRealtimeAlerts() async {
    final stream = _deviceAlertStream;
    _deviceAlertStream = null;
    await stream?.dispose();
  }

  void _resumeAlertPolling() {
    if (_alertPollingTimer != null) {
      return;
    }
    unawaited(_syncDeviceAlerts());
    _alertPollingTimer = Timer.periodic(
      _alertPollingInterval,
      (_) => unawaited(_syncDeviceAlerts()),
    );
  }

  void _pauseAlertPolling() {
    _alertPollingTimer?.cancel();
    _alertPollingTimer = null;
  }

  Future<void> _syncDeviceAlerts() async {
    if (!mounted || _syncingAlerts) {
      return;
    }
    _syncingAlerts = true;
    try {
      final alert = await syncDeviceAbnormalAlerts(
        loadOverview: () => ref.read(apiClientProvider).fetchOverview(),
      );
      if (!mounted || alert == null) {
        return;
      }
      _showDeviceAlertPrompt(
        title: '设备异常提醒',
        message: alert.message,
        actionLabel: alert.actionLabel,
        onOpen: () => _openRoute(
          route: alert.route,
          navigateWithGo: alert.navigateWithGo,
        ),
      );
    } catch (_) {
      return;
    } finally {
      _syncingAlerts = false;
    }
  }

  Future<void> _handleRealtimeDeviceAlert(
    DeviceAbnormalRealtimeAlert alert,
  ) async {
    if (!mounted) {
      return;
    }
    _showDeviceAlertPrompt(
      title: alert.title,
      message: alert.message,
      actionLabel: alert.actionLabel,
      onOpen: () => _openRoute(
        route: alert.route,
        navigateWithGo: alert.navigateWithGo,
      ),
    );
  }

  void _showDeviceAlertPrompt({
    required String title,
    required String message,
    required String actionLabel,
    required VoidCallback onOpen,
  }) {
    if (!mounted) {
      return;
    }
    final overlay = Overlay.maybeOf(context, rootOverlay: true);
    if (overlay == null) {
      return;
    }
    _dismissDeviceAlertPrompt();
    _deviceAlertOverlayEntry = OverlayEntry(
      builder: (context) {
        final topPadding = MediaQuery.paddingOf(context).top + 10;
        return Positioned(
          top: topPadding,
          left: 12,
          right: 12,
          child: _DeviceAlertPromptCard(
            title: title,
            message: message,
            actionLabel: actionLabel,
            onDismiss: _dismissDeviceAlertPrompt,
            onOpen: () {
              _dismissDeviceAlertPrompt();
              onOpen();
            },
          ),
        );
      },
    );
    overlay.insert(_deviceAlertOverlayEntry!);
    _deviceAlertHideTimer = Timer(
      const Duration(seconds: 6),
      _dismissDeviceAlertPrompt,
    );
  }

  void _dismissDeviceAlertPrompt() {
    _deviceAlertHideTimer?.cancel();
    _deviceAlertHideTimer = null;
    _deviceAlertOverlayEntry?.remove();
    _deviceAlertOverlayEntry = null;
  }

  void _handleNotificationIntent(DeviceAbnormalNotificationIntent intent) {
    if (!mounted) {
      return;
    }
    _openRoute(
      route: intent.route,
      navigateWithGo: intent.navigateWithGo,
    );
  }

  void _openRoute({
    required String route,
    required bool navigateWithGo,
  }) {
    if (!mounted) {
      return;
    }
    if (navigateWithGo) {
      context.go(route);
      return;
    }
    context.push(route);
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final haorAssistantOpen = ref.watch(haorAssistantOpenProvider);
    final selectedColor = theme.colorScheme.primary;
    final unselectedColor = theme.colorScheme.onSurface.withValues(alpha: 0.72);
    final backgroundColor = theme.brightness == Brightness.dark
        ? theme.colorScheme.surface.withValues(alpha: 0.96)
        : Colors.white;
    final borderColor = theme.colorScheme.onSurface.withValues(alpha: 0.08);

    return Scaffold(
      body: widget.navigationShell,
      floatingActionButtonLocation: FloatingActionButtonLocation.endFloat,
      bottomNavigationBar: SafeArea(
        top: false,
        minimum: EdgeInsets.zero,
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: backgroundColor,
            border: Border(
              top: BorderSide(color: borderColor),
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(8, 6, 8, 8),
            child: Row(
              children: [
                for (var index = 0;
                    index < AppShell._destinations.length;
                    index++)
                  Expanded(
                    child: _ShellNavItem(
                      destination: AppShell._destinations[index],
                      selected: widget.navigationShell.currentIndex == index,
                      selectedColor: selectedColor,
                      unselectedColor: unselectedColor,
                      onTap: () {
                        widget.navigationShell.goBranch(
                          index,
                          initialLocation:
                              index == widget.navigationShell.currentIndex,
                        );
                      },
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
      floatingActionButton:
          widget.navigationShell.currentIndex == 0 && !haorAssistantOpen
              ? Padding(
                  padding: const EdgeInsets.only(right: 4, bottom: 4),
                  child: FloatingActionButton.extended(
                    onPressed: () => context.push('/discovery'),
                    icon: const Icon(Icons.add_rounded, size: 20),
                    label: const Text('发现任务'),
                    extendedPadding: const EdgeInsets.symmetric(horizontal: 20),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(20)),
                  ),
                )
              : null,
    );
  }
}

class _DeviceAlertPromptCard extends StatelessWidget {
  const _DeviceAlertPromptCard({
    required this.title,
    required this.message,
    required this.actionLabel,
    required this.onDismiss,
    required this.onOpen,
  });

  final String title;
  final String message;
  final String actionLabel;
  final VoidCallback onDismiss;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    return TweenAnimationBuilder<double>(
      duration: const Duration(milliseconds: 260),
      curve: Curves.easeOutCubic,
      tween: Tween(begin: -36, end: 0),
      builder: (context, offsetY, child) {
        final opacity = (1 - (-offsetY / 36)).clamp(0.0, 1.0);
        return Transform.translate(
          offset: Offset(0, offsetY),
          child: Opacity(
            opacity: opacity,
            child: child,
          ),
        );
      },
      child: Material(
        color: Colors.transparent,
        child: _DeviceAlertSurface(
          title: title,
          message: message,
          actionLabel: actionLabel,
          onDismiss: onDismiss,
          onOpen: onOpen,
        ),
      ),
    );
  }
}

class _DeviceAlertSurface extends StatelessWidget {
  const _DeviceAlertSurface({
    required this.title,
    required this.message,
    required this.actionLabel,
    required this.onDismiss,
    required this.onOpen,
  });

  final String title;
  final String message;
  final String actionLabel;
  final VoidCallback onDismiss;
  final VoidCallback onOpen;

  @override
  Widget build(BuildContext context) {
    const backgroundColor = Colors.white;
    const primaryTextColor = Color(0xFF18243A);
    const secondaryTextColor = Color(0xFF66758F);
    const accentColor = Color(0xFF2F6BFF);
    const highlightColor = Color(0xFFD9485F);

    final theme = Theme.of(context);

    return DecoratedBox(
      decoration: BoxDecoration(
        color: backgroundColor,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: const Color(0xFFE6EBF2),
        ),
        boxShadow: const [
          BoxShadow(
            color: Color(0x160F172A),
            blurRadius: 26,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(22),
          onTap: onOpen,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(14, 13, 12, 13),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: const Color(0xFFEFF4FF),
                    borderRadius: BorderRadius.circular(15),
                  ),
                  child: Center(
                    child: Text(
                      '风',
                      style: theme.textTheme.titleSmall?.copyWith(
                        color: accentColor,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 11),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Row(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          Expanded(
                            child: Row(
                              children: [
                                Flexible(
                                  child: Text(
                                    '资产态势平台',
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: theme.textTheme.labelLarge?.copyWith(
                                      color: primaryTextColor,
                                      fontWeight: FontWeight.w800,
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Container(
                                  padding: const EdgeInsets.symmetric(
                                    horizontal: 8,
                                    vertical: 4,
                                  ),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFFF3F6FB),
                                    borderRadius: BorderRadius.circular(999),
                                  ),
                                  child: Text(
                                    '风险中心',
                                    style: theme.textTheme.labelSmall?.copyWith(
                                      color: secondaryTextColor,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            '刚刚',
                            style: theme.textTheme.labelSmall?.copyWith(
                              color: const Color(0xFF94A0B4),
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                          const SizedBox(width: 6),
                          _AlertIconButton(
                            icon: Icons.close_rounded,
                            onTap: onDismiss,
                          ),
                        ],
                      ),
                      const SizedBox(height: 6),
                      Text(
                        title,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.titleMedium?.copyWith(
                          color: primaryTextColor,
                          fontWeight: FontWeight.w800,
                          fontSize: 15.5,
                          height: 1.15,
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        message,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: theme.textTheme.bodyMedium?.copyWith(
                          color: secondaryTextColor,
                          height: 1.4,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                      const SizedBox(height: 10),
                      Row(
                        children: [
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xFFFFF1F3),
                              borderRadius: BorderRadius.circular(999),
                            ),
                            child: Text(
                              '新增异常',
                              style: theme.textTheme.labelSmall?.copyWith(
                                color: highlightColor,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                          ),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 8,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: const Color(0xFFF3F6FB),
                              borderRadius: BorderRadius.circular(999),
                            ),
                            child: Text(
                              '待处理',
                              style: theme.textTheme.labelSmall?.copyWith(
                                color: secondaryTextColor,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                          const Spacer(),
                          TextButton(
                            onPressed: onOpen,
                            style: TextButton.styleFrom(
                              backgroundColor: const Color(0xFFF1F6FF),
                              foregroundColor: accentColor,
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 8,
                              ),
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(12),
                              ),
                              textStyle: theme.textTheme.labelMedium?.copyWith(
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                            child: Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Text(actionLabel),
                                const SizedBox(width: 3),
                                const Icon(
                                  Icons.chevron_right_rounded,
                                  size: 18,
                                ),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _AlertIconButton extends StatelessWidget {
  const _AlertIconButton({
    required this.icon,
    required this.onTap,
  });

  final IconData icon;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      color: const Color(0xFFF4F7FB),
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: SizedBox(
          width: 28,
          height: 28,
          child: Center(
            child: Icon(
              icon,
              size: 16,
              color: const Color(0xFF7A889F),
            ),
          ),
        ),
      ),
    );
  }
}

class _ShellDestination {
  const _ShellDestination({
    required this.label,
    required this.icon,
    required this.selectedIcon,
  });

  final String label;
  final IconData icon;
  final IconData selectedIcon;
}

class _ShellNavItem extends StatelessWidget {
  const _ShellNavItem({
    required this.destination,
    required this.selected,
    required this.selectedColor,
    required this.unselectedColor,
    required this.onTap,
  });

  final _ShellDestination destination;
  final bool selected;
  final Color selectedColor;
  final Color unselectedColor;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final color = selected ? selectedColor : unselectedColor;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 4),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                selected ? destination.selectedIcon : destination.icon,
                size: 24,
                color: color,
              ),
              const SizedBox(height: 3),
              Text(
                destination.label,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.labelSmall?.copyWith(
                      color: color,
                      fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
                      fontSize: 11.5,
                    ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
