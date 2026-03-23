import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/session_controller.dart';
import '../../core/network/api_client.dart';
import '../../core/theme/app_theme.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/adaptive_layout.dart';
import '../../shared/widgets/app_widgets.dart';

final bootstrapStatusProvider = FutureProvider<BootstrapStatus>((ref) async {
  Future<BootstrapStatus> loadStatus() {
    return ref.read(apiClientProvider).fetchBootstrapStatus();
  }

  try {
    return await loadStatus();
  } catch (error) {
    if (!shouldAttemptApiBaseUrlSync(error)) {
      rethrow;
    }
    final resolved = await synchronizeApiBaseUrlForRef(
      ref,
      forceRescan: true,
    );
    if (resolved == null) {
      rethrow;
    }
    return loadStatus();
  }
});

class LoginPage extends ConsumerStatefulWidget {
  const LoginPage({super.key});

  @override
  ConsumerState<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends ConsumerState<LoginPage> {
  final _usernameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();
  bool _bootstrapMode = false;
  bool _obscurePassword = true;
  bool _submitting = false;

  @override
  void dispose() {
    _usernameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() => _submitting = true);
    try {
      if (_bootstrapMode) {
        await ref.read(sessionControllerProvider.notifier).bootstrapAdmin(
              username: _usernameController.text.trim(),
              email: _emailController.text.trim(),
              password: _passwordController.text.trim(),
            );
      } else {
        await ref.read(sessionControllerProvider.notifier).signIn(
              username: _usernameController.text.trim(),
              password: _passwordController.text.trim(),
            );
      }
      if (!mounted) {
        return;
      }
      context.go('/overview');
    } catch (error) {
      if (!mounted) {
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(describeApiError(error))),
      );
    } finally {
      if (mounted) {
        setState(() => _submitting = false);
      }
    }
  }

  Future<void> _syncApiBaseUrl() async {
    final resolved = await synchronizeConfiguredApiBaseUrl(forceRescan: true);
    if (!mounted) {
      return;
    }
    ref.invalidate(dioProvider);
    ref.invalidate(apiClientProvider);
    ref.invalidate(bootstrapStatusProvider);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          resolved == null
              ? '未发现可用后端地址，请确认手机和 Kali 在同一局域网。'
              : '已同步服务地址：$resolved',
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final bootstrap = ref.watch(bootstrapStatusProvider);
    final session = ref.watch(sessionControllerProvider);

    if (session.valueOrNull?.isAuthenticated == true) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) {
          context.go('/overview');
        }
      });
    }

    return Scaffold(
      body: DecoratedBox(
        decoration: const BoxDecoration(color: Color(0xFFFDFEFF)),
        child: SafeArea(
          child: AdaptiveLayoutBuilder(
            builder: (context, layout) {
              final topPadding = layout.isCompact ? 12.0 : 26.0;
              final bottomPadding = layout.isCompact ? 16.0 : 28.0;
              final screenHeight = MediaQuery.sizeOf(context).height;
              final safeVerticalPadding = MediaQuery.paddingOf(context).vertical;
              final compactMinHeight = screenHeight >
                      safeVerticalPadding + topPadding + bottomPadding
                  ? screenHeight -
                      safeVerticalPadding -
                      topPadding -
                      bottomPadding
                  : 0.0;
              final content = layout.isCompact
                  ? _CompactLoginLayout(
                      bootstrap: bootstrap,
                      bootstrapMode: _bootstrapMode,
                      obscurePassword: _obscurePassword,
                      submitting: _submitting,
                      usernameController: _usernameController,
                      emailController: _emailController,
                      passwordController: _passwordController,
                      onModeChanged: (value) =>
                          setState(() => _bootstrapMode = value),
                      onPasswordVisibilityChanged: () {
                        setState(
                          () => _obscurePassword = !_obscurePassword,
                        );
                      },
                      onRetryBootstrap: () =>
                          ref.invalidate(bootstrapStatusProvider),
                      onSyncApiBaseUrl: _syncApiBaseUrl,
                      onSubmit: _submit,
                    )
                  : Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(
                          flex: layout.isExpanded ? 11 : 10,
                          child: _LoginHero(layout: layout),
                        ),
                        const SizedBox(width: 20),
                        Expanded(
                          flex: 9,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            children: [
                              _LoginFormCard(
                                compact: false,
                                bootstrap: bootstrap,
                                bootstrapMode: _bootstrapMode,
                                obscurePassword: _obscurePassword,
                                submitting: _submitting,
                                usernameController: _usernameController,
                                emailController: _emailController,
                                passwordController: _passwordController,
                                onModeChanged: (value) => setState(
                                  () => _bootstrapMode = value,
                                ),
                                onPasswordVisibilityChanged: () {
                                  setState(
                                    () => _obscurePassword = !_obscurePassword,
                                  );
                                },
                                onRetryBootstrap: () =>
                                    ref.invalidate(bootstrapStatusProvider),
                                onSyncApiBaseUrl: _syncApiBaseUrl,
                                onSubmit: _submit,
                              ),
                            ],
                          ),
                        ),
                      ],
                    );

              return SingleChildScrollView(
                padding: EdgeInsets.fromLTRB(
                  layout.horizontalPadding,
                  topPadding,
                  layout.horizontalPadding,
                  bottomPadding,
                ),
                child: Center(
                  child: ConstrainedBox(
                    constraints: BoxConstraints(
                      maxWidth: layout.isExpanded ? 1100 : 920,
                      minHeight: layout.isCompact ? compactMinHeight : 0,
                    ),
                    child: layout.isCompact
                        ? Align(
                            alignment: Alignment.center,
                            child: content,
                          )
                        : content,
                  ),
                ),
              );
            },
          ),
        ),
      ),
    );
  }
}

class _CompactLoginLayout extends StatelessWidget {
  const _CompactLoginLayout({
    required this.bootstrap,
    required this.bootstrapMode,
    required this.obscurePassword,
    required this.submitting,
    required this.usernameController,
    required this.emailController,
    required this.passwordController,
    required this.onModeChanged,
    required this.onPasswordVisibilityChanged,
    required this.onRetryBootstrap,
    required this.onSyncApiBaseUrl,
    required this.onSubmit,
  });

  final AsyncValue<BootstrapStatus> bootstrap;
  final bool bootstrapMode;
  final bool obscurePassword;
  final bool submitting;
  final TextEditingController usernameController;
  final TextEditingController emailController;
  final TextEditingController passwordController;
  final ValueChanged<bool> onModeChanged;
  final VoidCallback onPasswordVisibilityChanged;
  final VoidCallback onRetryBootstrap;
  final Future<void> Function() onSyncApiBaseUrl;
  final Future<void> Function() onSubmit;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Container(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 4),
          child: Row(
            children: [
              const _LoginIllustration(size: 92),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '登录态势感知',
                      style: theme.textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.w900,
                        height: 1.04,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '输入账号密码即可进入移动工作台。',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color:
                            theme.colorScheme.onSurface.withValues(alpha: 0.68),
                        height: 1.35,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        _LoginFormCard(
          compact: true,
          bootstrap: bootstrap,
          bootstrapMode: bootstrapMode,
          obscurePassword: obscurePassword,
          submitting: submitting,
          usernameController: usernameController,
          emailController: emailController,
          passwordController: passwordController,
          onModeChanged: onModeChanged,
          onPasswordVisibilityChanged: onPasswordVisibilityChanged,
          onRetryBootstrap: onRetryBootstrap,
          onSyncApiBaseUrl: onSyncApiBaseUrl,
          onSubmit: onSubmit,
        ),
      ],
    );
  }
}

class _LoginIllustration extends StatelessWidget {
  const _LoginIllustration({
    required this.size,
  });

  final double size;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);

    return SizedBox(
      width: size,
      height: size * 0.88,
      child: Stack(
        clipBehavior: Clip.none,
        alignment: Alignment.center,
        children: [
          Positioned(
            top: size * 0.1,
            child: Container(
              width: size * 0.7,
              height: size * 0.6,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary,
                borderRadius: BorderRadius.circular(size * 0.26),
              ),
            ),
          ),
          Positioned(
            left: size * 0.18,
            top: size * 0.08,
            child: Container(
              width: size * 0.46,
              height: size * 0.54,
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(size * 0.22),
                boxShadow: [
                  BoxShadow(
                    color: theme.colorScheme.primary.withValues(alpha: 0.16),
                    blurRadius: 18,
                    offset: const Offset(0, 10),
                  ),
                ],
              ),
              child: Center(
                child: Icon(
                  Icons.insights_rounded,
                  size: size * 0.18,
                  color: theme.colorScheme.primary,
                ),
              ),
            ),
          ),
          Positioned(
            right: size * 0.16,
            top: 0,
            child: Container(
              width: size * 0.14,
              height: size * 0.14,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withValues(alpha: 0.12),
                shape: BoxShape.circle,
              ),
            ),
          ),
          Positioned(
            left: size * 0.28,
            bottom: size * 0.08,
            child: Container(
              width: size * 0.18,
              height: size * 0.08,
              decoration: BoxDecoration(
                color: theme.colorScheme.primary.withValues(alpha: 0.2),
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _LoginHero extends StatelessWidget {
  const _LoginHero({
    required this.layout,
  });

  final AdaptiveLayoutInfo layout;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final titleStyle = (layout.isCompact
            ? theme.textTheme.headlineMedium
            : theme.textTheme.displaySmall)
        ?.copyWith(
      color: Colors.white,
      fontWeight: FontWeight.w900,
      height: 1.06,
    );

    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: const [
            Color(0xFF0F3FAF),
            Color(0xFF3A7BFF),
            Color(0xFF7EA6FF),
          ],
        ),
        borderRadius: BorderRadius.circular(layout.isCompact ? 30 : 34),
        boxShadow: [
          BoxShadow(
            color: theme.colorScheme.primary.withValues(alpha: 0.26),
            blurRadius: 38,
            offset: const Offset(0, 18),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(layout.isCompact ? 30 : 34),
        child: Stack(
          children: [
            Positioned(
              top: -28,
              right: -12,
              child: Container(
                width: 164,
                height: 164,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: Colors.white.withValues(alpha: 0.08),
                ),
              ),
            ),
            Positioned(
              bottom: -62,
              left: -20,
              child: Container(
                width: 188,
                height: 188,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: Colors.white.withValues(alpha: 0.08),
                ),
              ),
            ),
            Padding(
              padding: EdgeInsets.all(layout.isCompact ? 22 : 28),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                    decoration: BoxDecoration(
                      color: Colors.white.withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(999),
                      border:
                          Border.all(color: Colors.white.withValues(alpha: 0.14)),
                    ),
                    child: Text(
                      '移动端态势入口',
                      style: theme.textTheme.labelLarge?.copyWith(
                        color: Colors.white,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ),
                  SizedBox(height: layout.isCompact ? 18 : 24),
                  Text('流动态势感知', style: titleStyle),
                  const SizedBox(height: 12),
                  ConstrainedBox(
                    constraints: BoxConstraints(
                      maxWidth: layout.isCompact ? double.infinity : 430,
                    ),
                    child: Text(
                      '面向管理员与分析员的移动工作台，支持随时查看总览指标、资产状态、任务推进与高风险告警。',
                      style: theme.textTheme.titleMedium?.copyWith(
                        color: Colors.white.withValues(alpha: 0.84),
                        height: 1.55,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                  SizedBox(height: layout.isCompact ? 18 : 22),
                  Wrap(
                    spacing: 10,
                    runSpacing: 10,
                    children: const [
                      _HeroFeatureTile(
                        icon: Icons.monitor_heart_outlined,
                        title: '总览快照',
                        subtitle: '指标与脉冲一屏查看',
                      ),
                      _HeroFeatureTile(
                        icon: Icons.verified_user_outlined,
                        title: '风险跟进',
                        subtitle: '从列表直达详情页',
                      ),
                      _HeroFeatureTile(
                        icon: Icons.travel_explore_outlined,
                        title: '发现任务',
                        subtitle: '资产发现与任务追踪',
                      ),
                    ],
                  ),
                  SizedBox(height: layout.isCompact ? 18 : 24),
                  Container(
                    width: double.infinity,
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.black.withValues(alpha: 0.14),
                      borderRadius: BorderRadius.circular(22),
                      border: Border.all(
                        color: Colors.white.withValues(alpha: 0.12),
                      ),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(
                              Icons.dns_rounded,
                              size: 18,
                              color: Colors.white.withValues(alpha: 0.86),
                            ),
                            const SizedBox(width: 8),
                            Text(
                              '当前接口',
                              style: theme.textTheme.labelLarge?.copyWith(
                                color: Colors.white.withValues(alpha: 0.86),
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        SelectableText(
                          configuredApiBaseUrl,
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.w700,
                            height: 1.45,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _HeroFeatureTile extends StatelessWidget {
  const _HeroFeatureTile({
    required this.icon,
    required this.title,
    required this.subtitle,
  });

  final IconData icon;
  final String title;
  final String subtitle;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return ConstrainedBox(
      constraints: const BoxConstraints(minWidth: 150, maxWidth: 220),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.14),
          borderRadius: BorderRadius.circular(22),
          border: Border.all(color: Colors.white.withValues(alpha: 0.12)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(icon, size: 18, color: Colors.white),
            const SizedBox(height: 10),
            Text(
              title,
              style: theme.textTheme.titleSmall?.copyWith(
                color: Colors.white,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              subtitle,
              style: theme.textTheme.bodySmall?.copyWith(
                color: Colors.white.withValues(alpha: 0.78),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _LoginFormCard extends StatelessWidget {
  const _LoginFormCard({
    required this.compact,
    required this.bootstrap,
    required this.bootstrapMode,
    required this.obscurePassword,
    required this.submitting,
    required this.usernameController,
    required this.emailController,
    required this.passwordController,
    required this.onModeChanged,
    required this.onPasswordVisibilityChanged,
    required this.onRetryBootstrap,
    required this.onSyncApiBaseUrl,
    required this.onSubmit,
  });

  final bool compact;
  final AsyncValue<BootstrapStatus> bootstrap;
  final bool bootstrapMode;
  final bool obscurePassword;
  final bool submitting;
  final TextEditingController usernameController;
  final TextEditingController emailController;
  final TextEditingController passwordController;
  final ValueChanged<bool> onModeChanged;
  final VoidCallback onPasswordVisibilityChanged;
  final VoidCallback onRetryBootstrap;
  final Future<void> Function() onSyncApiBaseUrl;
  final Future<void> Function() onSubmit;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fieldBorder = OutlineInputBorder(
      borderRadius: BorderRadius.circular(18),
      borderSide: BorderSide(
        color: theme.colorScheme.primary.withValues(alpha: 0.08),
      ),
    );
    final content = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    bootstrapMode ? '创建管理员账号' : (compact ? '账号密码登录' : '欢迎登录'),
                    style: theme.textTheme.headlineSmall?.copyWith(
                      fontWeight: FontWeight.w900,
                      fontSize: compact ? 24 : null,
                    ),
                  ),
                  if (!compact) ...[
                    const SizedBox(height: 6),
                    Text(
                      bootstrapMode
                          ? '系统未初始化时，可先创建首个管理员并直接进入移动端。'
                          : '输入账号和密码后即可进入移动工作台。',
                      style: theme.textTheme.bodySmall?.copyWith(height: 1.5),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
        SizedBox(height: compact ? 12 : 18),
        bootstrap.when(
          data: (status) {
            if (!status.canBootstrapAdmin) {
              return const SizedBox.shrink();
            }
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  '登录方式',
                  style: theme.textTheme.labelLarge?.copyWith(
                    color: theme.colorScheme.onSurface.withValues(alpha: 0.72),
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 8),
                _LoginModeSelector(
                  canBootstrapAdmin: status.canBootstrapAdmin,
                  bootstrapMode: bootstrapMode,
                  onModeChanged: onModeChanged,
                ),
              ],
            );
          },
          loading: () => const _BootstrapLoadingCard(),
          error: (error, _) => _BootstrapConnectionError(
            message: describeApiError(error),
            onRetry: onRetryBootstrap,
            onSyncApiBaseUrl: onSyncApiBaseUrl,
          ),
        ),
        SizedBox(height: compact ? 14 : 22),
        if (!compact) ...[
          Text(
            bootstrapMode ? '管理员信息' : '账号信息',
            style: theme.textTheme.labelLarge?.copyWith(
              color: theme.colorScheme.onSurface.withValues(alpha: 0.72),
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
        ],
        Theme(
          data: theme.copyWith(
            inputDecorationTheme: theme.inputDecorationTheme.copyWith(
              fillColor: Colors.white,
              hintStyle: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurface.withValues(alpha: 0.36),
              ),
              border: fieldBorder,
              enabledBorder: fieldBorder,
              focusedBorder: fieldBorder.copyWith(
                borderSide: BorderSide(
                  color: theme.colorScheme.primary.withValues(alpha: 0.42),
                  width: 1.1,
                ),
              ),
            ),
          ),
          child: AutofillGroup(
            child: Column(
              children: [
                TextField(
                  controller: usernameController,
                  textInputAction: bootstrapMode
                      ? TextInputAction.next
                      : TextInputAction.done,
                  keyboardType: TextInputType.emailAddress,
                  autofillHints: const [AutofillHints.username],
                  decoration: InputDecoration(
                    labelText: bootstrapMode ? '管理员用户名' : '用户名 / 邮箱',
                    hintText: bootstrapMode ? '请输入管理员用户名' : '请输入用户名或邮箱',
                    prefixIcon: const Icon(Icons.person_outline_rounded),
                  ),
                ),
                SizedBox(height: compact ? 10 : 12),
                if (bootstrapMode) ...[
                  TextField(
                    controller: emailController,
                    keyboardType: TextInputType.emailAddress,
                    textInputAction: TextInputAction.next,
                    autofillHints: const [AutofillHints.email],
                    decoration: const InputDecoration(
                      labelText: '管理员邮箱',
                      hintText: '请输入管理员邮箱',
                      prefixIcon: Icon(Icons.alternate_email_rounded),
                    ),
                  ),
                  SizedBox(height: compact ? 10 : 12),
                ],
                TextField(
                  controller: passwordController,
                  obscureText: obscurePassword,
                  textInputAction: TextInputAction.done,
                  autofillHints: bootstrapMode
                      ? const [AutofillHints.newPassword]
                      : const [AutofillHints.password],
                  decoration: InputDecoration(
                    labelText: '密码',
                    hintText: bootstrapMode ? '设置管理员密码' : '请输入密码',
                    prefixIcon: const Icon(Icons.lock_outline_rounded),
                    suffixIcon: IconButton(
                      onPressed: onPasswordVisibilityChanged,
                      icon: Icon(
                        obscurePassword
                            ? Icons.visibility_off_rounded
                            : Icons.visibility_rounded,
                      ),
                    ),
                  ),
                  onSubmitted: (_) => onSubmit(),
                ),
              ],
            ),
          ),
        ),
        SizedBox(height: compact ? 16 : 20),
        SizedBox(
          width: double.infinity,
          child: FilledButton.icon(
            key: const ValueKey('login-primary-button'),
            style: FilledButton.styleFrom(
              backgroundColor: theme.colorScheme.primary,
              foregroundColor: Colors.white,
              minimumSize: Size.fromHeight(compact ? 52 : 56),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(18),
              ),
              textStyle: theme.textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w800,
              ),
            ),
            onPressed: submitting ? null : onSubmit,
            icon: submitting
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2.2,
                      color: Colors.white,
                    ),
                  )
                : Icon(
                    bootstrapMode
                        ? Icons.admin_panel_settings_rounded
                        : Icons.login_rounded,
                  ),
            label: Text(bootstrapMode ? '初始化并进入系统' : '登录进入移动端'),
          ),
        ),
      ],
    );

    if (compact) {
      return Container(
        padding: const EdgeInsets.fromLTRB(18, 18, 18, 18),
        decoration: BoxDecoration(
          color: Colors.white.withValues(alpha: 0.97),
          borderRadius: BorderRadius.circular(30),
          border: Border.all(
            color: theme.colorScheme.primary.withValues(alpha: 0.06),
          ),
          boxShadow: [
            BoxShadow(
              color: Colors.black.withValues(alpha: 0.06),
              blurRadius: 32,
              offset: const Offset(0, 14),
            ),
          ],
        ),
        child: content,
      );
    }

    return GlassPanel(
      padding: const EdgeInsets.all(22),
      child: content,
    );
  }
}

class _LoginModeSelector extends StatelessWidget {
  const _LoginModeSelector({
    required this.canBootstrapAdmin,
    required this.bootstrapMode,
    required this.onModeChanged,
  });

  final bool canBootstrapAdmin;
  final bool bootstrapMode;
  final ValueChanged<bool> onModeChanged;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;

    if (!canBootstrapAdmin) {
      return Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: palette.accentSurface.withValues(alpha: 0.56),
          borderRadius: BorderRadius.circular(18),
        ),
        child: Row(
          children: [
            Icon(Icons.person_rounded,
                size: 18, color: theme.colorScheme.primary),
            const SizedBox(width: 10),
            Text(
              '普通登录',
              style: theme.textTheme.titleSmall
                  ?.copyWith(fontWeight: FontWeight.w800),
            ),
          ],
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: palette.accentSurface.withValues(alpha: 0.72),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        children: [
          Expanded(
            child: _ModeButton(
              label: '普通登录',
              icon: Icons.person_rounded,
              selected: !bootstrapMode,
              onTap: () => onModeChanged(false),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: _ModeButton(
              label: '初始化管理员',
              icon: Icons.admin_panel_settings_rounded,
              selected: bootstrapMode,
              onTap: () => onModeChanged(true),
            ),
          ),
        ],
      ),
    );
  }
}

class _ModeButton extends StatelessWidget {
  const _ModeButton({
    required this.label,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AnimatedContainer(
      duration: const Duration(milliseconds: 180),
      curve: Curves.easeOutCubic,
      decoration: BoxDecoration(
        color: selected ? theme.colorScheme.primary : Colors.transparent,
        borderRadius: BorderRadius.circular(16),
        boxShadow: selected
            ? [
                BoxShadow(
                  color: theme.colorScheme.primary.withValues(alpha: 0.22),
                  blurRadius: 18,
                  offset: const Offset(0, 8),
                ),
              ]
            : null,
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(16),
          onTap: onTap,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  icon,
                  size: 18,
                  color: selected ? Colors.white : theme.colorScheme.primary,
                ),
                const SizedBox(width: 8),
                Flexible(
                  child: Text(
                    label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: theme.textTheme.labelLarge?.copyWith(
                      color:
                          selected ? Colors.white : theme.colorScheme.onSurface,
                      fontWeight: FontWeight.w800,
                    ),
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

class _BootstrapLoadingCard extends StatelessWidget {
  const _BootstrapLoadingCard();

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: palette.accentSurface.withValues(alpha: 0.72),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 18,
            height: 18,
            child: CircularProgressIndicator(
              strokeWidth: 2.2,
              color: theme.colorScheme.primary,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              '正在检查后端服务状态与管理员初始化状态…',
              style: theme.textTheme.bodySmall?.copyWith(height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}

class _BootstrapConnectionError extends StatelessWidget {
  const _BootstrapConnectionError({
    required this.message,
    required this.onRetry,
    required this.onSyncApiBaseUrl,
  });

  final String message;
  final VoidCallback onRetry;
  final Future<void> Function() onSyncApiBaseUrl;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final palette = theme.extension<AppThemePalette>()!;
    return Container(
      key: const ValueKey('bootstrap-error-card'),
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: theme.colorScheme.errorContainer.withValues(alpha: 0.42),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(
          color: theme.colorScheme.error.withValues(alpha: 0.14),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 34,
                height: 34,
                decoration: BoxDecoration(
                  color: palette.danger.withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  Icons.wifi_off_rounded,
                  color: theme.colorScheme.error,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  '暂时无法连接后端服务',
                  style: theme.textTheme.titleSmall?.copyWith(
                    fontWeight: FontWeight.w700,
                    color: theme.colorScheme.onSurface,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            message,
            style: theme.textTheme.bodySmall?.copyWith(
              color: theme.colorScheme.onSurface.withValues(alpha: 0.8),
              height: 1.45,
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: theme.colorScheme.error,
                    side: BorderSide(
                        color: theme.colorScheme.error.withValues(alpha: 0.28)),
                    minimumSize: const Size.fromHeight(46),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16)),
                  ),
                  onPressed: onRetry,
                  icon: const Icon(Icons.refresh_rounded),
                  label: const Text('重试连接'),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  style: OutlinedButton.styleFrom(
                    foregroundColor: theme.colorScheme.primary,
                    side: BorderSide(
                      color: theme.colorScheme.primary.withValues(alpha: 0.28),
                    ),
                    minimumSize: const Size.fromHeight(46),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                    ),
                  ),
                  onPressed: () => unawaited(onSyncApiBaseUrl()),
                  icon: const Icon(Icons.wifi_tethering_rounded),
                  label: const Text('同步地址'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
