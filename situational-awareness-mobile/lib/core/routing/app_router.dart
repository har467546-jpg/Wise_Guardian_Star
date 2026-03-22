import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../features/assets/assets_page.dart';
import '../../features/dashboard/dashboard_page.dart';
import '../../features/discovery/discovery_page.dart';
import '../../features/login/login_page.dart';
import '../../features/profile/profile_page.dart';
import '../../features/remediation/remediation_page.dart';
import '../../features/risks/risks_page.dart';
import '../../features/tasks/tasks_page.dart';
import '../../shared/models/app_models.dart';
import '../../shared/widgets/app_shell.dart';
import '../auth/session_controller.dart';

final appRouterProvider = Provider<GoRouter>((ref) {
  final refreshListenable = ValueNotifier<int>(0);
  ref.onDispose(refreshListenable.dispose);
  ref.listen<AsyncValue<SessionSnapshot>>(
    sessionControllerProvider,
    (_, __) => refreshListenable.value++,
  );

  return GoRouter(
    initialLocation: '/launch',
    refreshListenable: refreshListenable,
    redirect: (context, state) {
      final session = ref.read(sessionControllerProvider);
      final isLoading = session.isLoading;
      final isAuthenticated = session.valueOrNull?.isAuthenticated == true;
      final role = session.valueOrNull?.role;
      final path = state.uri.path;
      final isLaunch = path == '/launch';
      final isLogin = path == '/login';
      final isRemediation =
          path == '/remediation' || path.startsWith('/remediation/');

      if (isLoading) {
        return isLaunch ? null : '/launch';
      }
      if (!isAuthenticated) {
        return isLogin ? null : '/login';
      }
      if (isRemediation && role != AppRole.admin) {
        return '/overview';
      }
      if (isLaunch || isLogin) {
        return '/overview';
      }
      return null;
    },
    routes: [
      GoRoute(
        path: '/launch',
        builder: (context, state) => const LaunchGatePage(),
      ),
      GoRoute(
        path: '/login',
        builder: (context, state) => const LoginPage(),
      ),
      StatefulShellRoute.indexedStack(
        builder: (context, state, navigationShell) {
          return AppShell(navigationShell: navigationShell);
        },
        branches: [
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/overview',
                builder: (context, state) => const DashboardPage(),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/assets',
                builder: (context, state) => AssetsPage(
                  initialKeyword: state.uri.queryParameters['keyword'] ?? '',
                  initialStatus: state.uri.queryParameters['status'],
                ),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/tasks',
                builder: (context, state) => TasksPage(initialStatus: state.uri.queryParameters['status']),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/risks',
                builder: (context, state) => RisksPage(
                  initialSeverity: state.uri.queryParameters['severity'],
                  initialStatus: state.uri.queryParameters['status'],
                ),
              ),
            ],
          ),
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/profile',
                builder: (context, state) => const ProfilePage(),
              ),
            ],
          ),
        ],
      ),
      GoRoute(
        path: '/assets/:assetId',
        builder: (context, state) => AssetDetailPage(assetId: state.pathParameters['assetId']!),
      ),
      GoRoute(
        path: '/tasks/:taskId',
        builder: (context, state) => TaskDetailPage(taskId: state.pathParameters['taskId']!),
      ),
      GoRoute(
        path: '/risks/:riskId',
        builder: (context, state) => RiskDetailPage(
          riskId: state.pathParameters['riskId']!,
          risk: state.extra is RiskItem ? state.extra as RiskItem : null,
        ),
      ),
      GoRoute(
        path: '/discovery',
        builder: (context, state) => const DiscoveryPage(),
      ),
      GoRoute(
        path: '/discovery/:jobId',
        builder: (context, state) => DiscoveryDetailPage(jobId: state.pathParameters['jobId']!),
      ),
      GoRoute(
        path: '/remediation',
        builder: (context, state) => const RemediationAssetGalleryPage(),
      ),
      GoRoute(
        path: '/remediation/:assetId',
        builder: (context, state) => RemediationWorkbenchPage(
          assetId: state.pathParameters['assetId']!,
        ),
      ),
    ],
  );
});

class LaunchGatePage extends ConsumerWidget {
  const LaunchGatePage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final session = ref.watch(sessionControllerProvider);
    final snapshot = session.valueOrNull;

    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!context.mounted) {
        return;
      }
      if (snapshot?.isAuthenticated == true) {
        context.go('/overview');
      } else if (!session.isLoading) {
        context.go('/login');
      }
    });

    return const Scaffold(
      body: Center(child: CircularProgressIndicator()),
    );
  }
}
