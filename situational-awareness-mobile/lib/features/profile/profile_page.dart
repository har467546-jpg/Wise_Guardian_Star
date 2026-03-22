import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../core/theme/app_theme.dart';
import '../../features/alerts/device_abnormal_notifications.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

const _profileAppVersion = '0.1.0';

final profileNotificationStatusProvider =
    FutureProvider.autoDispose<DeviceAbnormalNotificationStatus>((ref) async {
  return readDeviceAbnormalNotificationStatus();
});

class ProfilePage extends ConsumerWidget {
  const ProfilePage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(sessionControllerProvider).valueOrNull;
    final themeMode =
        ref.watch(themeModeControllerProvider).valueOrNull ?? ThemeMode.system;

    return ScreenScaffold(
      title: '我的',
      subtitle: '把常用入口、消息提醒和界面偏好放在一起，打开就能继续今天的巡检。',
      maxContentWidth: 1120,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _ProfileHeroCard(
            session: session,
            themeMode: themeMode,
          ),
          const SizedBox(height: 18),
          AdaptiveGrid(
            compactColumns: 1,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 260,
            children: [
              _ProfileAccountPanel(session: session),
              const _ProfileNotificationPanel(),
              _ProfileThemePanel(themeMode: themeMode),
              _ProfileDevicePanel(
                session: session,
                themeMode: themeMode,
              ),
            ],
          ),
          const SizedBox(height: 18),
          AdaptiveGrid(
            compactColumns: 1,
            mediumColumns: 2,
            expandedColumns: 2,
            minChildWidth: 260,
            children: const [
              _ProfileQuickActionsPanel(),
              _ProfileTipsPanel(),
            ],
          ),
          const SizedBox(height: 18),
          _ProfileSignOutPanel(
            onSignOut: () async {
              await ref.read(sessionControllerProvider.notifier).signOut();
              if (context.mounted) {
                context.go('/login');
              }
            },
          ),
        ],
      ),
    );
  }
}

class _ProfileHeroCard extends StatelessWidget {
  const _ProfileHeroCard({
    required this.session,
    required this.themeMode,
  });

  final SessionSnapshot? session;
  final ThemeMode themeMode;

  @override
  Widget build(BuildContext context) {
    final signedIn = session?.isAuthenticated ?? false;
    final role = session?.role ?? AppRole.unknown;
    final palette = Theme.of(context).extension<AppThemePalette>()!;
    final headline = signedIn ? '你好，${role.label}' : '欢迎回来';
    final summary = signedIn
        ? '常用入口、消息提醒和设备偏好都收在这里，开工前看一眼就够了。'
        : '登录后，这里会展示你的账号、通知偏好和当前设备设置。';

    return GlassPanel(
      child: AdaptiveLayoutBuilder(
        builder: (context, layout) {
          final overview = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    width: 68,
                    height: 68,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          Theme.of(context).colorScheme.primary,
                          palette.info,
                        ],
                        begin: Alignment.topLeft,
                        end: Alignment.bottomRight,
                      ),
                      borderRadius: BorderRadius.circular(22),
                    ),
                    child: const Icon(
                      Icons.person_rounded,
                      color: Colors.white,
                      size: 34,
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '个人中心',
                          style:
                              Theme.of(context).textTheme.labelLarge?.copyWith(
                                    color: palette.textSecondary,
                                    fontWeight: FontWeight.w700,
                                  ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          headline,
                          style: Theme.of(context)
                              .textTheme
                              .headlineSmall
                              ?.copyWith(
                                fontWeight: FontWeight.w800,
                              ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          summary,
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  StatusBadge(
                    label: signedIn ? '已登录' : '未登录',
                    tone: signedIn ? StatusTone.success : StatusTone.warning,
                  ),
                  StatusBadge(
                    label: role.label,
                    tone: _roleTone(role),
                  ),
                  _ProfileChip(
                    icon: Icons.notifications_active_outlined,
                    label: '实时提醒',
                  ),
                  _ProfileChip(
                    icon: Icons.phone_android_rounded,
                    label: _platformLabel(defaultTargetPlatform),
                  ),
                  _ProfileChip(
                    icon: Icons.palette_outlined,
                    label: _themeModeLabel(themeMode),
                  ),
                ],
              ),
            ],
          );

          final quickFacts = Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              _ProfileFactCard(
                title: '身份',
                value: signedIn ? role.label : '待登录',
              ),
              const _ProfileFactCard(title: '提醒', value: '实时在线'),
              _ProfileFactCard(
                title: '设备',
                value: _platformLabel(defaultTargetPlatform),
              ),
              _ProfileFactCard(title: '版本', value: _profileAppVersion),
            ],
          );

          if (layout.isCompact) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                overview,
                const SizedBox(height: 16),
                quickFacts,
              ],
            );
          }

          return Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(child: overview),
              const SizedBox(width: 18),
              SizedBox(
                width: 320,
                child: quickFacts,
              ),
            ],
          );
        },
      ),
    );
  }
}

class _ProfileAccountPanel extends StatelessWidget {
  const _ProfileAccountPanel({required this.session});

  final SessionSnapshot? session;

  @override
  Widget build(BuildContext context) {
    final signedIn = session?.isAuthenticated ?? false;
    final role = session?.role ?? AppRole.unknown;

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '我的账号',
            subtitle: '当前身份、登录状态和这台设备上的会话。',
          ),
          const SizedBox(height: 14),
          _ProfileInfoRow(
            title: '当前状态',
            value: signedIn ? '已登录，可继续使用' : '未登录，需要重新进入账号',
          ),
          const SizedBox(height: 12),
          _ProfileInfoRow(
            title: '身份标签',
            value: signedIn ? role.label : '未识别',
          ),
          const SizedBox(height: 12),
          _ProfileInfoRow(
            title: '可用能力',
            value: _roleCapabilitySummary(role),
          ),
          const SizedBox(height: 12),
          _ProfileInfoRow(
            title: '本地会话',
            value: signedIn ? '这台设备已保留登录状态' : '当前没有保留本地会话',
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              StatusBadge(
                label: signedIn ? '继续今天的工作' : '先登录再继续',
                tone: signedIn ? StatusTone.success : StatusTone.warning,
              ),
              StatusBadge(
                label: role == AppRole.admin ? '管理员视角' : '分析视角',
                tone: role == AppRole.admin
                    ? StatusTone.info
                    : StatusTone.neutral,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ProfileNotificationPanel extends ConsumerWidget {
  const _ProfileNotificationPanel();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final statusAsync = ref.watch(profileNotificationStatusProvider);

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '消息与提醒',
            subtitle: '把设备异常放在最容易注意到的位置。',
          ),
          const SizedBox(height: 14),
          const _ProfileBullet(
            icon: Icons.vertical_align_top_rounded,
            title: '顶部横幅提醒',
            message: '应用打开时，新增高危异常会从页面上方弹出白色提示卡片。',
          ),
          const SizedBox(height: 12),
          const _ProfileBullet(
            icon: Icons.notifications_active_rounded,
            title: '系统通知',
            message: '切到后台后，仍会收到系统通知，点一下就能回到对应页面。',
          ),
          const SizedBox(height: 12),
          const _ProfileBullet(
            icon: Icons.schedule_rounded,
            title: '后台兜底同步',
            message: 'Android 端会保留定时同步，尽量避免前台链路中断时漏掉提醒。',
          ),
          const SizedBox(height: 14),
          statusAsync.when(
            data: (status) => Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                StatusBadge(
                  label: status.initialized ? '提醒已就绪' : '提醒待初始化',
                  tone: status.initialized
                      ? StatusTone.success
                      : StatusTone.warning,
                ),
                StatusBadge(
                  label: status.permissionPrompted ? '已请求通知权限' : '建议开启通知权限',
                  tone: status.permissionPrompted
                      ? StatusTone.info
                      : StatusTone.warning,
                ),
                StatusBadge(
                  label: status.backgroundSyncAvailable
                      ? (status.backgroundSyncRegistered
                          ? '后台同步已开启'
                          : '后台同步未开启')
                      : '当前平台无后台同步',
                  tone: status.backgroundSyncAvailable &&
                          status.backgroundSyncRegistered
                      ? StatusTone.success
                      : StatusTone.neutral,
                ),
              ],
            ),
            loading: () => Container(
              height: 6,
              decoration: BoxDecoration(
                color: Theme.of(context)
                    .colorScheme
                    .primary
                    .withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(999),
              ),
            ),
            error: (_, __) => const Text('提醒状态读取失败'),
          ),
          const SizedBox(height: 14),
          AdaptiveButtonGroup(
            children: [
              OutlinedButton.icon(
                onPressed: () async {
                  await requestDeviceAbnormalNotificationPermission();
                  ref.invalidate(profileNotificationStatusProvider);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('已发起通知权限请求。')),
                    );
                  }
                },
                icon: const Icon(Icons.notifications_outlined),
                label: const Text('打开通知权限'),
              ),
              FilledButton.tonalIcon(
                onPressed: () async {
                  await showDeviceAbnormalSystemNotification(
                    title: '测试提醒',
                    message: '这是一条来自个人中心的测试提醒。',
                    route: '/profile',
                  );
                  ref.invalidate(profileNotificationStatusProvider);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('测试通知已发送。')),
                    );
                  }
                },
                icon: const Icon(Icons.send_rounded),
                label: const Text('发一条测试提醒'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ProfileThemePanel extends ConsumerWidget {
  const _ProfileThemePanel({required this.themeMode});

  final ThemeMode themeMode;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '界面风格',
            subtitle: '当前是 ${_themeModeLabel(themeMode)}，你也可以手动切换。',
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              const _ThemePreviewSwatch(
                fill: Color(0xFFF6F8FC),
                accent: Color(0xFF3A7BFF),
                label: '浅色',
              ),
              const SizedBox(width: 10),
              const _ThemePreviewSwatch(
                fill: Color(0xFF121B2F),
                accent: Color(0xFF79A7FF),
                label: '深色',
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Container(
                  height: 54,
                  decoration: BoxDecoration(
                    color: Theme.of(context)
                        .colorScheme
                        .primary
                        .withValues(alpha: 0.08),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  child: Row(
                    children: [
                      Icon(
                        Icons.auto_awesome_rounded,
                        size: 18,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          '跟随系统自动切换',
                          style:
                              Theme.of(context).textTheme.bodySmall?.copyWith(
                                    fontWeight: FontWeight.w600,
                                  ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: SegmentedButton<ThemeMode>(
              segments: const [
                ButtonSegment(value: ThemeMode.system, label: Text('跟随系统')),
                ButtonSegment(value: ThemeMode.light, label: Text('浅色')),
                ButtonSegment(value: ThemeMode.dark, label: Text('深色')),
              ],
              selected: {themeMode},
              onSelectionChanged: (value) {
                ref
                    .read(themeModeControllerProvider.notifier)
                    .setThemeMode(value.first);
              },
            ),
          ),
        ],
      ),
    );
  }
}

class _ProfileDevicePanel extends StatelessWidget {
  const _ProfileDevicePanel({
    required this.session,
    required this.themeMode,
  });

  final SessionSnapshot? session;
  final ThemeMode themeMode;

  @override
  Widget build(BuildContext context) {
    final signedIn = session?.isAuthenticated ?? false;
    final serviceAddress = configuredApiBaseUrl;

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SectionHeading(
            title: '当前设备',
            subtitle: '这台设备上的显示方式和接入信息。',
            action: TextButton(
              onPressed: () async {
                await Clipboard.setData(
                  ClipboardData(text: serviceAddress),
                );
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('服务地址已复制。')),
                  );
                }
              },
              child: const Text('复制服务地址'),
            ),
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              _ProfileFactCard(
                title: '设备',
                value: _platformLabel(defaultTargetPlatform),
              ),
              _ProfileFactCard(
                title: '外观',
                value: _themeModeLabel(themeMode),
              ),
              _ProfileFactCard(
                title: '构建',
                value: kReleaseMode ? '正式版' : '调试版',
              ),
            ],
          ),
          const SizedBox(height: 14),
          _ProfileInfoRow(
            title: '登录保持',
            value: signedIn ? '这台设备已保存登录状态' : '当前没有保存登录状态',
          ),
          const SizedBox(height: 12),
          _ProfileInfoRow(
            title: '服务地址',
            value: serviceAddress,
            selectable: true,
          ),
        ],
      ),
    );
  }
}

class _ProfileTipsPanel extends StatelessWidget {
  const _ProfileTipsPanel();

  @override
  Widget build(BuildContext context) {
    final palette = Theme.of(context).extension<AppThemePalette>()!;

    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '这样用更顺手',
            subtitle: '手机上更适合查看、确认和轻量操作。',
          ),
          const SizedBox(height: 14),
          const _ProfileBullet(
            icon: Icons.radar_rounded,
            title: '值班先看一眼',
            message: '先看总览、高危风险和活跃任务，快速判断现在要不要处理。',
          ),
          const SizedBox(height: 12),
          const _ProfileBullet(
            icon: Icons.search_rounded,
            title: '到现场直接查',
            message: '在机房、实验室或巡检现场，直接打开资产和异常详情继续确认。',
          ),
          const SizedBox(height: 12),
          const _ProfileBullet(
            icon: Icons.flash_on_rounded,
            title: '轻量操作就够了',
            message: '发起发现任务或验证动作很合适，复杂治理建议回到桌面端完成。',
          ),
          const SizedBox(height: 14),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: palette.accentSurface.withValues(alpha: 0.92),
              borderRadius: BorderRadius.circular(18),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  Icons.lightbulb_rounded,
                  size: 18,
                  color: Theme.of(context).colorScheme.primary,
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    '如果你主要依赖异常提醒，建议把通知权限和系统省电限制一起检查一遍。',
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ProfileQuickActionsPanel extends StatelessWidget {
  const _ProfileQuickActionsPanel();

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SectionHeading(
            title: '快捷入口',
            subtitle: '把今天最常打开的页面放在手边。',
          ),
          const SizedBox(height: 14),
          AdaptiveButtonGroup(
            children: [
              _ProfileQuickActionButton(
                icon: Icons.home_rounded,
                title: '今日总览',
                subtitle: '先看全局状态',
                onTap: () => context.go('/overview'),
              ),
              _ProfileQuickActionButton(
                icon: Icons.shield_rounded,
                title: '高危风险',
                subtitle: '查看待处理异常',
                onTap: () => context.go('/risks?severity=high'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          AdaptiveButtonGroup(
            children: [
              _ProfileQuickActionButton(
                icon: Icons.assignment_rounded,
                title: '活跃任务',
                subtitle: '跟进执行进度',
                onTap: () => context.go('/tasks?status=running'),
              ),
              _ProfileQuickActionButton(
                icon: Icons.add_task_rounded,
                title: '发现任务',
                subtitle: '新建一次扫描',
                onTap: () => context.push('/discovery'),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ProfileSignOutPanel extends StatelessWidget {
  const _ProfileSignOutPanel({required this.onSignOut});

  final Future<void> Function() onSignOut;

  @override
  Widget build(BuildContext context) {
    return GlassPanel(
      child: AdaptiveLayoutBuilder(
        builder: (context, layout) {
          final description = Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SectionHeading(
                title: '账号安全',
                subtitle: '需要切换账号或结束使用时，再从这里退出。',
              ),
              const SizedBox(height: 10),
              Text(
                '只是暂时离开，可以直接回到首页；退出会清除这台设备上的登录状态和提醒上下文。',
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          );

          final action = FilledButton.icon(
            onPressed: onSignOut,
            style: FilledButton.styleFrom(
              backgroundColor: Theme.of(context).colorScheme.error,
              foregroundColor: Colors.white,
              padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
            ),
            icon: const Icon(Icons.logout_rounded),
            label: const Text('退出当前账号'),
          );

          if (layout.isCompact) {
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                description,
                const SizedBox(height: 14),
                SizedBox(
                  width: double.infinity,
                  child: action,
                ),
              ],
            );
          }

          return Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              Expanded(child: description),
              const SizedBox(width: 18),
              action,
            ],
          );
        },
      ),
    );
  }
}

class _ProfileQuickActionButton extends StatelessWidget {
  const _ProfileQuickActionButton({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = Theme.of(context).extension<AppThemePalette>()!;

    return Material(
      color: theme.colorScheme.surface
          .withValues(alpha: theme.brightness == Brightness.dark ? 0.72 : 0.98),
      borderRadius: BorderRadius.circular(18),
      child: InkWell(
        borderRadius: BorderRadius.circular(18),
        onTap: onTap,
        child: Ink(
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(18),
            border: Border.all(
              color: theme.colorScheme.onSurface.withValues(alpha: 0.06),
            ),
          ),
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: theme.colorScheme.primary.withValues(alpha: 0.12),
                    borderRadius: BorderRadius.circular(14),
                  ),
                  child: Icon(
                    icon,
                    size: 20,
                    color: theme.colorScheme.primary,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        title,
                        style: theme.textTheme.titleMedium?.copyWith(
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        subtitle,
                        style: theme.textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
                Icon(
                  Icons.chevron_right_rounded,
                  color: palette.textSecondary,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _ProfileChip extends StatelessWidget {
  const _ProfileChip({
    required this.icon,
    required this.label,
  });

  final IconData icon;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(
            icon,
            size: 15,
            color: Theme.of(context).colorScheme.primary,
          ),
          const SizedBox(width: 6),
          Text(
            label,
            style: Theme.of(context).textTheme.labelMedium?.copyWith(
                  fontWeight: FontWeight.w700,
                ),
          ),
        ],
      ),
    );
  }
}

class _ProfileFactCard extends StatelessWidget {
  const _ProfileFactCard({
    required this.title,
    required this.value,
  });

  final String title;
  final String value;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return Container(
      width: 126,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
      decoration: BoxDecoration(
        color: theme.colorScheme.surface.withValues(
          alpha: theme.brightness == Brightness.dark ? 0.72 : 0.98,
        ),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(
          color: theme.colorScheme.onSurface.withValues(alpha: 0.06),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.labelSmall),
          const SizedBox(height: 6),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w800,
                ),
          ),
        ],
      ),
    );
  }
}

class _ThemePreviewSwatch extends StatelessWidget {
  const _ThemePreviewSwatch({
    required this.fill,
    required this.accent,
    required this.label,
  });

  final Color fill;
  final Color accent;
  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 78,
      height: 54,
      decoration: BoxDecoration(
        color: fill,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: accent.withValues(alpha: 0.2),
        ),
      ),
      padding: const EdgeInsets.all(8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  color: accent,
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
              const Spacer(),
              Container(
                width: 18,
                height: 6,
                decoration: BoxDecoration(
                  color: accent.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(999),
                ),
              ),
            ],
          ),
          const Spacer(),
          Text(
            label,
            style: Theme.of(context).textTheme.labelSmall?.copyWith(
                  color: fill.computeLuminance() > 0.5
                      ? const Color(0xFF1D2D4A)
                      : Colors.white,
                  fontWeight: FontWeight.w700,
                ),
          ),
        ],
      ),
    );
  }
}

class _ProfileInfoRow extends StatelessWidget {
  const _ProfileInfoRow({
    required this.title,
    required this.value,
    this.selectable = false,
  });

  final String title;
  final String value;
  final bool selectable;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: Theme.of(context).textTheme.labelMedium?.copyWith(
                color: Theme.of(context)
                    .extension<AppThemePalette>()!
                    .textSecondary,
                fontWeight: FontWeight.w700,
              ),
        ),
        const SizedBox(height: 6),
        if (selectable)
          SelectableText(
            value,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
          )
        else
          Text(
            value,
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
          ),
      ],
    );
  }
}

class _ProfileBullet extends StatelessWidget {
  const _ProfileBullet({
    required this.icon,
    required this.title,
    required this.message,
  });

  final IconData icon;
  final String title;
  final String message;

  @override
  Widget build(BuildContext context) {
    final color = Theme.of(context).colorScheme.primary;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: 34,
          height: 34,
          decoration: BoxDecoration(
            color: color.withValues(alpha: 0.12),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Icon(icon, size: 18, color: color),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 4),
              Text(message, style: Theme.of(context).textTheme.bodySmall),
            ],
          ),
        ),
      ],
    );
  }
}

String _roleCapabilitySummary(AppRole role) {
  return switch (role) {
    AppRole.admin => '可查看风险、任务、发现入口，也能进入修复相关流程',
    AppRole.analyst => '以查看、确认和轻量触发为主，不展示管理员专属治理入口',
    AppRole.unknown => '当前还没有可用权限，请先登录有效账号',
  };
}

StatusTone _roleTone(AppRole role) {
  return switch (role) {
    AppRole.admin => StatusTone.info,
    AppRole.analyst => StatusTone.success,
    AppRole.unknown => StatusTone.neutral,
  };
}

String _themeModeLabel(ThemeMode mode) {
  return switch (mode) {
    ThemeMode.system => '跟随系统',
    ThemeMode.light => '浅色',
    ThemeMode.dark => '深色',
  };
}

String _platformLabel(TargetPlatform platform) {
  return switch (platform) {
    TargetPlatform.android => 'Android',
    TargetPlatform.iOS => 'iOS',
    TargetPlatform.linux => 'Linux',
    TargetPlatform.macOS => 'macOS',
    TargetPlatform.windows => 'Windows',
    TargetPlatform.fuchsia => 'Fuchsia',
  };
}
