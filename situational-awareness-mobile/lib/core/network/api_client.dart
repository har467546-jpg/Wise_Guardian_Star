import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../shared/models/agent_models.dart';
import '../../shared/models/app_models.dart';
import '../auth/session_controller.dart';

const _configuredApiBaseUrlFromEnv = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: '',
);
const _apiBaseUrlStorageKey = 'sa.api_base_url';
const _androidEmulatorApiBaseUrl = 'http://10.0.2.2:8000/api/v1';
const _loopbackApiBaseUrl = 'http://127.0.0.1:8000/api/v1';
String _runtimeApiBaseUrl = '';

String _defaultApiBaseUrl() {
  if (Platform.isAndroid) {
    return _androidEmulatorApiBaseUrl;
  }
  return _loopbackApiBaseUrl;
}

String _normalizeApiBaseUrl(String value) {
  final normalized = value.trim().replaceFirst(RegExp(r'/$'), '');
  if (normalized.isEmpty) {
    return _defaultApiBaseUrl();
  }
  final parsed = Uri.tryParse(normalized);
  if (parsed == null || parsed.host.isEmpty || !parsed.hasScheme) {
    return _defaultApiBaseUrl();
  }
  if (parsed.scheme != 'http' && parsed.scheme != 'https') {
    return _defaultApiBaseUrl();
  }
  return parsed.toString();
}

String get configuredApiBaseUrl {
  final runtime = _runtimeApiBaseUrl.trim();
  if (runtime.isNotEmpty) {
    return runtime;
  }
  final configured = _configuredApiBaseUrlFromEnv.trim();
  if (configured.isNotEmpty) {
    return _normalizeApiBaseUrl(configured);
  }
  return _defaultApiBaseUrl();
}

Uri _buildApiUri(
  String baseUrl,
  List<String> trailingSegments, {
  Map<String, String>? queryParameters,
}) {
  final parsed = Uri.parse(_normalizeApiBaseUrl(baseUrl));
  final pathSegments = [
    ...parsed.pathSegments.where((item) => item.isNotEmpty),
    ...trailingSegments,
  ];
  return parsed.replace(
    pathSegments: pathSegments,
    queryParameters: queryParameters,
  );
}

bool _isPrivateIpv4Host(String host) {
  final address = InternetAddress.tryParse(host);
  if (address == null || address.type != InternetAddressType.IPv4) {
    return false;
  }
  final octets = host.split('.');
  if (octets.length != 4) {
    return false;
  }
  final first = int.tryParse(octets[0]) ?? -1;
  final second = int.tryParse(octets[1]) ?? -1;
  if (first == 10) {
    return true;
  }
  if (first == 172 && second >= 16 && second <= 31) {
    return true;
  }
  return first == 192 && second == 168;
}

Future<void> initializeConfiguredApiBaseUrl() async {
  final prefs = await SharedPreferences.getInstance();
  final persisted = prefs.getString(_apiBaseUrlStorageKey) ?? '';
  final nextValue = persisted.trim().isNotEmpty
      ? persisted
      : (_configuredApiBaseUrlFromEnv.trim().isNotEmpty
            ? _configuredApiBaseUrlFromEnv
            : _defaultApiBaseUrl());
  _runtimeApiBaseUrl = _normalizeApiBaseUrl(nextValue);
}

Future<void> persistConfiguredApiBaseUrl(String baseUrl) async {
  final normalized = _normalizeApiBaseUrl(baseUrl);
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString(_apiBaseUrlStorageKey, normalized);
  _runtimeApiBaseUrl = normalized;
}

Future<bool> _isPlatformApiBaseUrlHealthy(String baseUrl) async {
  final client = HttpClient()..connectionTimeout = const Duration(milliseconds: 600);
  try {
    final request = await client
        .getUrl(_buildApiUri(baseUrl, const ['auth', 'bootstrap-status']))
        .timeout(const Duration(milliseconds: 800));
    final response = await request.close().timeout(const Duration(milliseconds: 900));
    if (response.statusCode != 200) {
      return false;
    }
    final body = await response.transform(utf8.decoder).join().timeout(const Duration(milliseconds: 900));
    final decoded = jsonDecode(body);
    return decoded is Map && decoded.containsKey('can_bootstrap_admin');
  } catch (_) {
    return false;
  } finally {
    client.close(force: true);
  }
}

Future<List<String>> _buildDiscoveryCandidates(String seedBaseUrl) async {
  final candidates = <String>[];
  final seenCandidates = <String>{};
  final seed = Uri.parse(_normalizeApiBaseUrl(seedBaseUrl));

  void addCandidate(String host) {
    final value = seed
        .replace(
          host: host,
          pathSegments: seed.pathSegments.where((item) => item.isNotEmpty),
        )
        .toString();
    if (seenCandidates.add(value)) {
      candidates.add(value);
    }
  }

  if (_isPrivateIpv4Host(seed.host)) {
    addCandidate(seed.host);
  }

  final interfaces = await NetworkInterface.list(
    type: InternetAddressType.IPv4,
    includeLoopback: false,
    includeLinkLocal: false,
  );
  for (final interface in interfaces) {
    for (final address in interface.addresses) {
      final host = address.address;
      if (!_isPrivateIpv4Host(host)) {
        continue;
      }
      final octets = host.split('.');
      if (octets.length != 4) {
        continue;
      }
      final self = int.tryParse(octets[3]) ?? -1;
      final prefix = '${octets[0]}.${octets[1]}.${octets[2]}.';
      if (_isPrivateIpv4Host(seed.host) &&
          seed.host.startsWith(prefix) &&
          seed.host != host) {
        addCandidate(seed.host);
      }
      for (var index = 1; index < 255; index += 1) {
        if (index == self) {
          continue;
        }
        addCandidate('$prefix$index');
      }
    }
  }

  return candidates;
}

Future<String?> _discoverApiBaseUrl(String seedBaseUrl) async {
  final candidates = await _buildDiscoveryCandidates(seedBaseUrl);
  if (candidates.isEmpty) {
    return null;
  }

  const concurrency = 48;
  var nextIndex = 0;
  String? found;

  Future<void> worker() async {
    while (found == null) {
      final currentIndex = nextIndex;
      nextIndex += 1;
      if (currentIndex >= candidates.length) {
        return;
      }
      final candidate = candidates[currentIndex];
      if (await _isPlatformApiBaseUrlHealthy(candidate)) {
        found = candidate;
        return;
      }
    }
  }

  final workers = List.generate(
    candidates.length < concurrency ? candidates.length : concurrency,
    (_) => worker(),
  );
  await Future.wait(workers);
  return found;
}

bool shouldAttemptApiBaseUrlSync(Object error) {
  if (error is DioException) {
    return error.type == DioExceptionType.connectionTimeout ||
        error.type == DioExceptionType.connectionError ||
        error.type == DioExceptionType.sendTimeout ||
        error.type == DioExceptionType.receiveTimeout ||
        error.type == DioExceptionType.unknown;
  }
  final message = describeApiError(error);
  return message.contains('无法连接到后端服务') ||
      message.contains('连接服务器超时') ||
      message.contains('请求发送超时') ||
      message.contains('服务器响应超时') ||
      message.contains('当前地址：');
}

Future<String?> synchronizeConfiguredApiBaseUrl({bool forceRescan = false}) async {
  await initializeConfiguredApiBaseUrl();
  final current = configuredApiBaseUrl;
  if (!forceRescan && await _isPlatformApiBaseUrlHealthy(current)) {
    return current;
  }
  final discovered = await _discoverApiBaseUrl(current);
  if (discovered == null) {
    return null;
  }
  await persistConfiguredApiBaseUrl(discovered);
  return discovered;
}

Future<String?> synchronizeApiBaseUrlForRef(
  Ref ref, {
  bool forceRescan = false,
}) async {
  final resolved = await synchronizeConfiguredApiBaseUrl(forceRescan: forceRescan);
  ref.invalidate(dioProvider);
  ref.invalidate(apiClientProvider);
  return resolved;
}

String buildHaorSessionStreamUrl(String token) {
  final parsed = Uri.parse(configuredApiBaseUrl);
  final scheme = parsed.scheme == 'https' ? 'wss' : 'ws';
  return _buildApiUri(
    configuredApiBaseUrl,
    const ['agent', 'haor', 'session', 'stream'],
    queryParameters: {'token': token},
  ).replace(
    scheme: scheme,
  ).toString();
}

String buildDeviceAlertStreamUrl(String token) {
  final parsed = Uri.parse(configuredApiBaseUrl);
  final scheme = parsed.scheme == 'https' ? 'wss' : 'ws';
  return _buildApiUri(
    configuredApiBaseUrl,
    const ['mobile', 'alerts', 'stream'],
    queryParameters: {'token': token},
  ).replace(
    scheme: scheme,
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
