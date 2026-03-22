import 'dart:async';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../shared/models/agent_models.dart';
import '../../shared/models/app_models.dart';
import '../auth/session_controller.dart';

const _configuredApiBaseUrlFromEnv = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: '',
);

String get configuredApiBaseUrl {
  final configured = _configuredApiBaseUrlFromEnv.trim();
  if (configured.isNotEmpty) {
    return configured;
  }
  if (Platform.isAndroid) {
    return 'http://10.0.2.2:8000/api/v1';
  }
  return 'http://127.0.0.1:8000/api/v1';
}

String buildHaorSessionStreamUrl(String token) {
  final baseUrl = configuredApiBaseUrl.replaceFirst(RegExp(r'/$'), '');
  final parsed = Uri.parse(baseUrl);
  final scheme = parsed.scheme == 'https' ? 'wss' : 'ws';
  final pathSegments = [
    ...parsed.pathSegments.where((item) => item.isNotEmpty),
    'agent',
    'haor',
    'session',
    'stream',
  ];
  return parsed.replace(
    scheme: scheme,
    pathSegments: pathSegments,
    queryParameters: {'token': token},
  ).toString();
}

String buildDeviceAlertStreamUrl(String token) {
  final baseUrl = configuredApiBaseUrl.replaceFirst(RegExp(r'/$'), '');
  final parsed = Uri.parse(baseUrl);
  final scheme = parsed.scheme == 'https' ? 'wss' : 'ws';
  final pathSegments = [
    ...parsed.pathSegments.where((item) => item.isNotEmpty),
    'mobile',
    'alerts',
    'stream',
  ];
  return parsed.replace(
    scheme: scheme,
    pathSegments: pathSegments,
    queryParameters: {'token': token},
  ).toString();
}

class ApiClient {
  ApiClient(this._dio);

  final Dio _dio;

  Future<BootstrapStatus> fetchBootstrapStatus() async {
    final response =
        await _dio.get<Map<String, dynamic>>('/auth/bootstrap-status');
    return BootstrapStatus.fromJson(response.data ?? const {});
  }

  Future<AuthToken> login({
    required String username,
    required String password,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/auth/login',
      data: {'username': username, 'password': password},
    );
    return AuthToken.fromJson(response.data ?? const {});
  }

  Future<AuthToken> bootstrapAdmin({
    required String username,
    required String email,
    required String password,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/auth/bootstrap-admin',
      data: {'username': username, 'email': email, 'password': password},
    );
    return AuthToken.fromJson(response.data ?? const {});
  }

  Future<OverviewSummary> fetchOverview() async {
    final response = await _dio.get<Map<String, dynamic>>('/mobile/overview');
    return OverviewSummary.fromJson(response.data ?? const {});
  }

  Future<AssetListPayload> listAssets({
    String? keyword,
    AssetStatusType? status,
    int page = 1,
    int pageSize = 20,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/assets',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
        if (keyword != null && keyword.trim().isNotEmpty)
          'keyword': keyword.trim(),
        if (status != null && status != AssetStatusType.unknown)
          'status': status.name,
      },
    );
    return AssetListPayload.fromJson(response.data ?? const {});
  }

  Future<AssetModel> fetchAsset(String assetId) async {
    final response = await _dio.get<Map<String, dynamic>>('/assets/$assetId');
    return AssetModel.fromJson(response.data ?? const {});
  }

  Future<TaskListPayload> listTasks({
    TaskStatusType? status,
    int page = 1,
    int pageSize = 20,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/tasks',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
        if (status != null && status != TaskStatusType.unknown)
          'status': status.name,
      },
    );
    return TaskListPayload.fromJson(response.data ?? const {});
  }

  Future<TaskRunModel> fetchTask(String taskId) async {
    final response = await _dio.get<Map<String, dynamic>>('/tasks/$taskId');
    return TaskRunModel.fromJson(response.data ?? const {});
  }

  Future<TaskRunModel> cancelTask(String taskId) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/tasks/$taskId/cancel',
      data: const {},
    );
    return TaskRunModel.fromJson(response.data ?? const {});
  }

  Future<TaskEventListPayload> fetchTaskEvents(
    String taskId, {
    int page = 1,
    int pageSize = 50,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/tasks/$taskId/events',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
      },
    );
    return TaskEventListPayload.fromJson(response.data ?? const {});
  }

  Future<RemediationAssetDetailModel> fetchRemediationAsset(
    String assetId,
  ) async {
    final response =
        await _dio.get<Map<String, dynamic>>('/remediation/assets/$assetId');
    return RemediationAssetDetailModel.fromJson(response.data ?? const {});
  }

  Future<RemediationAssetListPayload> listRemediationAssets({
    String? keyword,
    int page = 1,
    int pageSize = 24,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/remediation/assets',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
        if (keyword != null && keyword.trim().isNotEmpty)
          'keyword': keyword.trim(),
      },
    );
    return RemediationAssetListPayload.fromJson(response.data ?? const {});
  }

  Future<HostRunnerInstallModel> installAssetRunner(String assetId) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/remediation/assets/$assetId/runner/install',
      data: const {},
    );
    return HostRunnerInstallModel.fromJson(response.data ?? const {});
  }

  Future<RemediationSessionModel> createRemediationSession(
    String assetId, {
    String? note,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/remediation/assets/$assetId/sessions',
      data: {
        if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
      },
    );
    return RemediationSessionModel.fromJson(response.data ?? const {});
  }

  Future<RemediationSessionModel> fetchRemediationSession(
    String sessionId,
  ) async {
    final response = await _dio
        .get<Map<String, dynamic>>('/remediation/sessions/$sessionId');
    return RemediationSessionModel.fromJson(response.data ?? const {});
  }

  Future<RemediationSessionModel> postRemediationSessionMessage(
    String sessionId, {
    required String intent,
    String? note,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/remediation/sessions/$sessionId/messages',
      data: {
        'intent': intent,
        if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
      },
    );
    return RemediationSessionModel.fromJson(response.data ?? const {});
  }

  Future<RemediationSessionApproveModel> approveRemediationSession(
    String sessionId, {
    String? stageCode,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/remediation/sessions/$sessionId/approve',
      data: {
        if (stageCode != null && stageCode.trim().isNotEmpty)
          'stage_code': stageCode.trim(),
      },
    );
    return RemediationSessionApproveModel.fromJson(response.data ?? const {});
  }

  Future<RemediationTaskModel> fetchRemediationTask(String taskId) async {
    final response =
        await _dio.get<Map<String, dynamic>>('/remediation/tasks/$taskId');
    return RemediationTaskModel.fromJson(response.data ?? const {});
  }

  Future<RiskListPayload> listRisks({
    RiskSeverityLevel? severity,
    RiskStatusType? status,
    String? keyword,
    int page = 1,
    int pageSize = 20,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/risks',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
        if (severity != null && severity != RiskSeverityLevel.unknown)
          'severity': severity.name,
        if (status != null && status != RiskStatusType.unknown)
          'status': status.name,
        if (keyword != null && keyword.trim().isNotEmpty)
          'keyword': keyword.trim(),
      },
    );
    return RiskListPayload.fromJson(response.data ?? const {});
  }

  Future<RiskItem> fetchRisk(String riskId) async {
    final response = await _dio.get<Map<String, dynamic>>('/risks/$riskId');
    return RiskItem.fromJson(response.data ?? const {});
  }

  Future<AgentSession> fetchHaorSession() async {
    final response =
        await _dio.get<Map<String, dynamic>>('/agent/haor/session');
    return AgentSession.fromJson(response.data ?? const {});
  }

  Future<AgentSession> resetHaorSession() async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/agent/haor/session/reset',
      data: const {},
    );
    return AgentSession.fromJson(response.data ?? const {});
  }

  Future<AgentSession> postHaorMessage({
    required String content,
    required AgentPageContext pageContext,
    required AgentBrowserContext browserContext,
    String? clientMessageId,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/agent/haor/session/messages',
      data: {
        'client_message_id': clientMessageId,
        'content': content,
        'page_context': pageContext.toJson(),
        'browser_context': browserContext.toJson(),
      },
    );
    return AgentSession.fromJson(response.data ?? const {});
  }

  Future<AgentSession> postHaorStep({
    required AgentBrowserContext browserContext,
    required List<AgentUIActionResult> uiActionResults,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/agent/haor/session/steps',
      data: {
        'browser_context': browserContext.toJson(),
        'ui_action_results':
            uiActionResults.map((item) => item.toJson()).toList(),
      },
    );
    return AgentSession.fromJson(response.data ?? const {});
  }

  Future<AgentApprovalResponse> approveHaorSession({String? note}) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/agent/haor/session/approve',
      data: {
        if (note != null && note.trim().isNotEmpty) 'note': note.trim(),
      },
    );
    return AgentApprovalResponse.fromJson(response.data ?? const {});
  }

  Future<AgentSession> interruptHaorSession() async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/agent/haor/session/interrupt',
      data: const {},
    );
    return AgentSession.fromJson(response.data ?? const {});
  }

  Future<DiscoveryJobListPayload> listDiscoveryJobs({
    DiscoveryJobStatusType? status,
    int page = 1,
    int pageSize = 20,
  }) async {
    final response = await _dio.get<Map<String, dynamic>>(
      '/discovery/jobs',
      queryParameters: {
        'page': page,
        'page_size': pageSize,
        if (status != null && status != DiscoveryJobStatusType.unknown)
          'status': status.name,
      },
    );
    return DiscoveryJobListPayload.fromJson(response.data ?? const {});
  }

  Future<DiscoveryJobModel> fetchDiscoveryJob(String jobId) async {
    final response =
        await _dio.get<Map<String, dynamic>>('/discovery/jobs/$jobId');
    return DiscoveryJobModel.fromJson(response.data ?? const {});
  }

  Future<TaskRunModel> runAssetCollection(String assetId) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/collection/assets/$assetId/run',
      data: const {'credential_id': null},
    );
    return TaskRunModel.fromJson(response.data ?? const {});
  }

  Future<TaskRunModel> verifyAssetRisk(String assetId) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/risks/assets/$assetId/verify',
      data: const {},
    );
    return TaskRunModel.fromJson(response.data ?? const {});
  }

  Future<DiscoveryJobModel> createDiscoveryJob({
    required String cidr,
    String? label,
  }) async {
    final response = await _dio.post<Map<String, dynamic>>(
      '/discovery/jobs',
      data: {
        'cidr': cidr,
        if (label != null && label.trim().isNotEmpty) 'label': label.trim(),
      },
    );
    final job = response.data?['job'];
    if (job is Map<String, dynamic>) {
      return DiscoveryJobModel.fromJson(job);
    }
    if (job is Map) {
      return DiscoveryJobModel.fromJson(job.cast<String, dynamic>());
    }
    throw const ApiException('发现任务创建失败');
  }
}

class ApiException implements Exception {
  const ApiException(this.message);

  final String message;

  @override
  String toString() => message;
}

String describeApiError(Object error) {
  if (error is ApiException) {
    return error.message;
  }
  if (error is DioException) {
    if (error.error is ApiException) {
      return (error.error as ApiException).message;
    }
    return _mapDioException(error).message;
  }
  return '请求失败，请稍后重试。';
}

ApiException _mapDioException(DioException error) {
  final baseUrl = error.requestOptions.baseUrl.isNotEmpty
      ? error.requestOptions.baseUrl
      : configuredApiBaseUrl;
  final statusCode = error.response?.statusCode;
  return switch (error.type) {
    DioExceptionType.connectionTimeout => ApiException(
        '连接服务器超时，请确认后端服务已启动且移动端可访问。当前地址：$baseUrl',
      ),
    DioExceptionType.sendTimeout => ApiException(
        '请求发送超时，请检查当前网络后重试。当前地址：$baseUrl',
      ),
    DioExceptionType.receiveTimeout => ApiException(
        '服务器响应超时，请稍后重试。当前地址：$baseUrl',
      ),
    DioExceptionType.badCertificate => const ApiException(
        '服务器证书校验失败，请检查 HTTPS 配置。',
      ),
    DioExceptionType.badResponse => ApiException(
        statusCode == null
            ? '服务器返回异常响应，请稍后重试。'
            : '服务器返回异常响应（HTTP $statusCode）。',
      ),
    DioExceptionType.cancel => const ApiException('请求已取消。'),
    DioExceptionType.connectionError => ApiException(
        '无法连接到后端服务，请检查 API 地址或网络连通性。当前地址：$baseUrl',
      ),
    DioExceptionType.unknown => ApiException(
        error.message?.trim().isNotEmpty == true
            ? error.message!.trim()
            : '网络请求失败，请检查服务地址和网络状态。',
      ),
  };
}

final dioProvider = Provider<Dio>((ref) {
  final dio = Dio(
    BaseOptions(
      baseUrl: configuredApiBaseUrl,
      connectTimeout: const Duration(seconds: 12),
      receiveTimeout: const Duration(seconds: 20),
      sendTimeout: const Duration(seconds: 12),
      headers: const {'Content-Type': 'application/json'},
    ),
  );

  dio.interceptors.add(
    InterceptorsWrapper(
      onRequest: (options, handler) {
        final session = ref.read(sessionControllerProvider).valueOrNull;
        final token = session?.token;
        if (token != null && token.isNotEmpty) {
          options.headers['Authorization'] = 'Bearer $token';
        }
        handler.next(options);
      },
      onError: (error, handler) {
        final requestPath = error.requestOptions.path;
        final statusCode = error.response?.statusCode;
        final isAuthMutation = requestPath == '/auth/login' ||
            requestPath == '/auth/bootstrap-admin';
        if (statusCode == 401 && !isAuthMutation) {
          unawaited(
              ref.read(sessionControllerProvider.notifier).expireSession());
        }
        final detail = error.response?.data;
        if (detail is Map && detail['detail'] is String) {
          final apiError = ApiException(detail['detail'] as String);
          handler.reject(
            error.copyWith(
              error: apiError,
              message: apiError.message,
            ),
          );
          return;
        }
        final apiError = _mapDioException(error);
        handler.reject(
          error.copyWith(
            error: apiError,
            message: apiError.message,
          ),
        );
        return;
      },
    ),
  );

  return dio;
});

final apiClientProvider = Provider<ApiClient>((ref) {
  return ApiClient(ref.watch(dioProvider));
});
