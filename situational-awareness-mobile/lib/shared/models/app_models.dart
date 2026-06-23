// ignore_for_file: prefer_initializing_formals, sort_constructors_first

import 'dart:convert';

enum AppRole { admin, analyst, unknown }

enum AssetStatusType { online, offline, collecting, unknown }

enum TaskStatusType {
  pending,
  running,
  retry,
  success,
  failure,
  canceled,
  unknown
}

enum TaskTypeModel {
  assetScan,
  infoCollect,
  riskVerify,
  reportGenerate,
  credentialVerify,
  runnerInstall,
  remediationExecute,
  agentOrchestrate,
  settingsApply,
  unknown,
}

enum RiskSeverityLevel { critical, high, medium, low, unknown }

enum RiskStatusType { open, ignored, fixed, unknown }

enum DiscoveryJobStatusType { pending, running, completed, failed, unknown }

class BootstrapStatus {
  const BootstrapStatus({
    required this.bootstrapped,
    required this.canBootstrapAdmin,
    required this.userCount,
  });

  final bool bootstrapped;
  final bool canBootstrapAdmin;
  final int userCount;

  factory BootstrapStatus.fromJson(Map<String, dynamic> json) {
    return BootstrapStatus(
      bootstrapped: json['bootstrapped'] as bool? ?? false,
      canBootstrapAdmin: json['can_bootstrap_admin'] as bool? ?? false,
      userCount: json['user_count'] as int? ?? 0,
    );
  }
}

class AuthToken {
  const AuthToken({required this.accessToken, required this.tokenType});

  final String accessToken;
  final String tokenType;

  factory AuthToken.fromJson(Map<String, dynamic> json) {
    return AuthToken(
      accessToken: json['access_token'] as String? ?? '',
      tokenType: json['token_type'] as String? ?? 'bearer',
    );
  }
}

class SessionSnapshot {
  const SessionSnapshot({
    required this.isAuthenticated,
    required this.token,
    required this.role,
  });

  final bool isAuthenticated;
  final String? token;
  final AppRole role;

  const SessionSnapshot.signedOut()
      : isAuthenticated = false,
        token = null,
        role = AppRole.unknown;

  const SessionSnapshot.signedIn({
    required String token,
    required AppRole role,
  })  : isAuthenticated = true,
        token = token,
        role = role;
}

class PageMeta {
  const PageMeta({
    required this.total,
    required this.page,
    required this.pageSize,
  });

  final int total;
  final int page;
  final int pageSize;

  factory PageMeta.fromJson(Map<String, dynamic> json) {
    return PageMeta(
      total: json['total'] as int? ?? 0,
      page: json['page'] as int? ?? 1,
      pageSize: json['page_size'] as int? ?? 20,
    );
  }
}

class OverviewSummary {
  const OverviewSummary({
    required this.assetTotal,
    required this.onlineAssets,
    required this.highRiskFindings,
    required this.activeTasks,
    required this.recentTasks,
    required this.recentRisks,
    required this.discoveryEntry,
  });

  final int assetTotal;
  final int onlineAssets;
  final int highRiskFindings;
  final int activeTasks;
  final List<TaskRunModel> recentTasks;
  final List<RiskItem> recentRisks;
  final DiscoveryEntry discoveryEntry;

  factory OverviewSummary.fromJson(Map<String, dynamic> json) {
    return OverviewSummary(
      assetTotal: json['asset_total'] as int? ?? 0,
      onlineAssets: json['online_assets'] as int? ?? 0,
      highRiskFindings: json['high_risk_findings'] as int? ?? 0,
      activeTasks: json['active_tasks'] as int? ?? 0,
      recentTasks: _decodeList(json['recent_tasks'], TaskRunModel.fromJson),
      recentRisks: _decodeList(json['recent_risks'], RiskItem.fromJson),
      discoveryEntry: DiscoveryEntry.fromJson(
          json['discovery_entry'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class DiscoveryEntry {
  const DiscoveryEntry({
    required this.enabled,
    required this.pendingJobs,
    required this.runningJobs,
  });

  final bool enabled;
  final int pendingJobs;
  final int runningJobs;

  factory DiscoveryEntry.fromJson(Map<String, dynamic> json) {
    return DiscoveryEntry(
      enabled: json['enabled'] as bool? ?? true,
      pendingJobs: json['pending_jobs'] as int? ?? 0,
      runningJobs: json['running_jobs'] as int? ?? 0,
    );
  }
}

class AssetPortModel {
  const AssetPortModel({
    required this.id,
    required this.port,
    required this.protocol,
    required this.serviceName,
    required this.serviceVersion,
    required this.state,
    required this.lastSeenAt,
  });

  final String id;
  final int port;
  final String protocol;
  final String? serviceName;
  final String? serviceVersion;
  final String state;
  final DateTime? lastSeenAt;

  factory AssetPortModel.fromJson(Map<String, dynamic> json) {
    return AssetPortModel(
      id: json['id'] as String? ?? '',
      port: json['port'] as int? ?? 0,
      protocol: json['protocol'] as String? ?? 'tcp',
      serviceName: json['service_name'] as String?,
      serviceVersion: json['service_version'] as String?,
      state: json['state'] as String? ?? 'unknown',
      lastSeenAt: _parseDate(json['last_seen_at']),
    );
  }
}

class AssetModel {
  const AssetModel({
    required this.id,
    required this.ip,
    required this.hostname,
    required this.osName,
    required this.status,
    required this.isLocal,
    required this.localHint,
    required this.firstSeenAt,
    required this.lastSeenAt,
    required this.ports,
  });

  final String id;
  final String ip;
  final String? hostname;
  final String? osName;
  final AssetStatusType status;
  final bool isLocal;
  final String? localHint;
  final DateTime? firstSeenAt;
  final DateTime? lastSeenAt;
  final List<AssetPortModel> ports;

  factory AssetModel.fromJson(Map<String, dynamic> json) {
    return AssetModel(
      id: json['id'] as String? ?? '',
      ip: json['ip']?.toString() ?? '',
      hostname: json['hostname'] as String?,
      osName: json['os_name'] as String?,
      status: _assetStatusFromString(json['status'] as String?),
      isLocal: json['is_local'] as bool? ?? false,
      localHint: json['local_hint'] as String?,
      firstSeenAt: _parseDate(json['first_seen_at']),
      lastSeenAt: _parseDate(json['last_seen_at']),
      ports: _decodeList(json['ports'], AssetPortModel.fromJson),
    );
  }
}

class AssetListPayload {
  const AssetListPayload({required this.items, required this.meta});

  final List<AssetModel> items;
  final PageMeta meta;

  factory AssetListPayload.fromJson(Map<String, dynamic> json) {
    return AssetListPayload(
      items: _decodeList(json['items'], AssetModel.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class TaskTimingModel {
  const TaskTimingModel({
    this.queueDurationMs,
    this.runDurationMs,
    this.totalDurationMs,
    this.currentStageCode,
    this.currentStageName,
    this.currentStageDurationMs,
    this.hasEventLogs = false,
  });

  final int? queueDurationMs;
  final int? runDurationMs;
  final int? totalDurationMs;
  final String? currentStageCode;
  final String? currentStageName;
  final int? currentStageDurationMs;
  final bool hasEventLogs;

  factory TaskTimingModel.fromJson(Map<String, dynamic> json) {
    return TaskTimingModel(
      queueDurationMs: json['queue_duration_ms'] as int?,
      runDurationMs: json['run_duration_ms'] as int?,
      totalDurationMs: json['total_duration_ms'] as int?,
      currentStageCode: json['current_stage_code'] as String?,
      currentStageName: json['current_stage_name'] as String?,
      currentStageDurationMs: json['current_stage_duration_ms'] as int?,
      hasEventLogs: json['has_event_logs'] as bool? ?? false,
    );
  }
}

class TaskStageTimingModel {
  const TaskStageTimingModel({
    required this.stageCode,
    required this.stageName,
    required this.startedAt,
    required this.finishedAt,
    required this.durationMs,
  });

  final String? stageCode;
  final String? stageName;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final int? durationMs;

  factory TaskStageTimingModel.fromJson(Map<String, dynamic> json) {
    return TaskStageTimingModel(
      stageCode: json['stage_code'] as String?,
      stageName: json['stage_name'] as String?,
      startedAt: _parseDate(json['started_at']),
      finishedAt: _parseDate(json['finished_at']),
      durationMs: json['duration_ms'] as int?,
    );
  }
}

class TaskRunModel {
  const TaskRunModel({
    required this.id,
    required this.taskType,
    required this.status,
    required this.scopeType,
    required this.scopeId,
    required this.progress,
    required this.message,
    required this.createdAt,
    required this.finishedAt,
    this.celeryTaskId,
    this.retryCount = 0,
    this.resultJson = const {},
    this.errorJson = const {},
    this.startedAt,
    this.updatedAt,
    this.timing = const TaskTimingModel(),
    this.stageTimings = const [],
    this.eventCount = 0,
    this.lastEventAt,
  });

  final String id;
  final TaskTypeModel taskType;
  final TaskStatusType status;
  final String? scopeType;
  final String? scopeId;
  final int progress;
  final String? message;
  final DateTime? createdAt;
  final DateTime? finishedAt;
  final String? celeryTaskId;
  final int retryCount;
  final Map<String, dynamic> resultJson;
  final Map<String, dynamic> errorJson;
  final DateTime? startedAt;
  final DateTime? updatedAt;
  final TaskTimingModel timing;
  final List<TaskStageTimingModel> stageTimings;
  final int eventCount;
  final DateTime? lastEventAt;

  factory TaskRunModel.fromJson(Map<String, dynamic> json) {
    return TaskRunModel(
      id: json['id'] as String? ?? json['task_id'] as String? ?? '',
      taskType: _taskTypeFromString(json['task_type'] as String?),
      status: _taskStatusFromString(json['status'] as String?),
      scopeType: json['scope_type'] as String?,
      scopeId: json['scope_id'] as String?,
      progress: json['progress'] as int? ?? 0,
      message: json['message'] as String?,
      createdAt: _parseDate(json['created_at']),
      finishedAt: _parseDate(json['finished_at']),
      celeryTaskId: json['celery_task_id'] as String?,
      retryCount: json['retry_count'] as int? ?? 0,
      resultJson: _map(json['result_json']),
      errorJson: _map(json['error_json']),
      startedAt: _parseDate(json['started_at']),
      updatedAt: _parseDate(json['updated_at']),
      timing: TaskTimingModel.fromJson(
        json['timing'] as Map<String, dynamic>? ?? const {},
      ),
      stageTimings: _decodeList(
        json['stage_timings'],
        TaskStageTimingModel.fromJson,
      ),
      eventCount: json['event_count'] as int? ?? 0,
      lastEventAt: _parseDate(json['last_event_at']),
    );
  }
}

class TaskListPayload {
  const TaskListPayload({required this.items, required this.meta});

  final List<TaskRunModel> items;
  final PageMeta meta;

  factory TaskListPayload.fromJson(Map<String, dynamic> json) {
    return TaskListPayload(
      items: _decodeList(json['items'], TaskRunModel.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class TaskEventModel {
  const TaskEventModel({
    required this.id,
    required this.taskRunId,
    required this.taskType,
    required this.status,
    required this.eventType,
    required this.level,
    required this.stageCode,
    required this.stageName,
    required this.message,
    required this.progress,
    required this.payloadJson,
    required this.createdAt,
  });

  final String id;
  final String taskRunId;
  final TaskTypeModel taskType;
  final TaskStatusType status;
  final String eventType;
  final String level;
  final String? stageCode;
  final String? stageName;
  final String? message;
  final int? progress;
  final Map<String, dynamic> payloadJson;
  final DateTime? createdAt;

  factory TaskEventModel.fromJson(Map<String, dynamic> json) {
    return TaskEventModel(
      id: json['id'] as String? ?? '',
      taskRunId: json['task_run_id'] as String? ?? '',
      taskType: _taskTypeFromString(json['task_type'] as String?),
      status: _taskStatusFromString(json['status'] as String?),
      eventType: json['event_type'] as String? ?? 'event',
      level: json['level'] as String? ?? 'info',
      stageCode: json['stage_code'] as String?,
      stageName: json['stage_name'] as String?,
      message: json['message'] as String?,
      progress: json['progress'] as int?,
      payloadJson: _map(json['payload_json']),
      createdAt: _parseDate(json['created_at']),
    );
  }
}

class TaskEventListPayload {
  const TaskEventListPayload({required this.items, required this.meta});

  final List<TaskEventModel> items;
  final PageMeta meta;

  factory TaskEventListPayload.fromJson(Map<String, dynamic> json) {
    return TaskEventListPayload(
      items: _decodeList(json['items'], TaskEventModel.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class RemediationAssetSummary {
  const RemediationAssetSummary({
    required this.id,
    required this.ip,
    required this.hostname,
    required this.osName,
    required this.status,
  });

  final String id;
  final String ip;
  final String? hostname;
  final String? osName;
  final AssetStatusType status;

  factory RemediationAssetSummary.fromJson(Map<String, dynamic> json) {
    return RemediationAssetSummary(
      id: json['id'] as String? ?? '',
      ip: json['ip']?.toString() ?? '',
      hostname: json['hostname'] as String?,
      osName: json['os_name'] as String?,
      status: _assetStatusFromString(json['status'] as String?),
    );
  }
}

class RemediationAuthorizationModel {
  const RemediationAuthorizationModel({
    required this.credentialBound,
    required this.adminAuthorized,
    required this.lastVerifiedAt,
    required this.lastVerificationStatus,
    required this.effectivePrivilege,
    required this.executionReady,
    required this.blockedReasons,
  });

  final bool credentialBound;
  final bool adminAuthorized;
  final DateTime? lastVerifiedAt;
  final String? lastVerificationStatus;
  final String? effectivePrivilege;
  final bool executionReady;
  final List<String> blockedReasons;

  factory RemediationAuthorizationModel.fromJson(Map<String, dynamic> json) {
    return RemediationAuthorizationModel(
      credentialBound: json['credential_bound'] as bool? ?? false,
      adminAuthorized: json['admin_authorized'] as bool? ?? false,
      lastVerifiedAt: _parseDate(json['last_verified_at']),
      lastVerificationStatus: json['last_verification_status'] as String?,
      effectivePrivilege: json['effective_privilege'] as String?,
      executionReady: json['execution_ready'] as bool? ?? false,
      blockedReasons: _stringList(json['blocked_reasons']),
    );
  }
}

class RemediationCollectionModel {
  const RemediationCollectionModel({
    required this.status,
    required this.collectedAt,
    required this.summaryJson,
  });

  final String? status;
  final DateTime? collectedAt;
  final Map<String, dynamic> summaryJson;

  factory RemediationCollectionModel.fromJson(Map<String, dynamic> json) {
    return RemediationCollectionModel(
      status: json['status'] as String?,
      collectedAt: _parseDate(json['collected_at']),
      summaryJson: _map(json['summary_json']),
    );
  }
}

class RemediationFindingModel {
  const RemediationFindingModel({
    required this.findingId,
    required this.ruleId,
    required this.title,
    required this.severity,
    required this.status,
    required this.serviceName,
    required this.detectedAt,
    required this.hasTemplate,
  });

  final String findingId;
  final String? ruleId;
  final String title;
  final RiskSeverityLevel severity;
  final String status;
  final String? serviceName;
  final DateTime? detectedAt;
  final bool hasTemplate;

  factory RemediationFindingModel.fromJson(Map<String, dynamic> json) {
    return RemediationFindingModel(
      findingId: json['finding_id'] as String? ?? '',
      ruleId: json['rule_id'] as String?,
      title: json['title'] as String? ?? '',
      severity: _riskSeverityFromString(json['severity'] as String?),
      status: json['status'] as String? ?? 'unknown',
      serviceName: json['service_name'] as String?,
      detectedAt: _parseDate(json['detected_at']),
      hasTemplate: json['has_template'] as bool? ?? false,
    );
  }
}

class RemediationAssetCardModel {
  const RemediationAssetCardModel({
    required this.assetId,
    required this.ip,
    required this.hostname,
    required this.osName,
    required this.status,
    required this.highestSeverity,
    required this.findingCount,
    required this.effectivePrivilege,
    required this.lastVerifiedAt,
    required this.lastCollectionAt,
    required this.recommendedFindingId,
    required this.runnerStatus,
    required this.runnerInstallStatus,
    required this.activeSessionId,
    required this.activeSessionStatus,
  });

  final String assetId;
  final String ip;
  final String? hostname;
  final String? osName;
  final AssetStatusType status;
  final RiskSeverityLevel? highestSeverity;
  final int findingCount;
  final String? effectivePrivilege;
  final DateTime? lastVerifiedAt;
  final DateTime? lastCollectionAt;
  final String? recommendedFindingId;
  final String? runnerStatus;
  final String? runnerInstallStatus;
  final String? activeSessionId;
  final String? activeSessionStatus;

  factory RemediationAssetCardModel.fromJson(Map<String, dynamic> json) {
    final severityRaw = json['highest_severity'] as String?;
    return RemediationAssetCardModel(
      assetId: json['asset_id'] as String? ?? '',
      ip: json['ip']?.toString() ?? '',
      hostname: json['hostname'] as String?,
      osName: json['os_name'] as String?,
      status: _assetStatusFromString(json['status'] as String?),
      highestSeverity:
          severityRaw == null ? null : _riskSeverityFromString(severityRaw),
      findingCount: json['finding_count'] as int? ?? 0,
      effectivePrivilege: json['effective_privilege'] as String?,
      lastVerifiedAt: _parseDate(json['last_verified_at']),
      lastCollectionAt: _parseDate(json['last_collection_at']),
      recommendedFindingId: json['recommended_finding_id'] as String?,
      runnerStatus: json['runner_status'] as String?,
      runnerInstallStatus: json['runner_install_status'] as String?,
      activeSessionId: json['active_session_id'] as String?,
      activeSessionStatus: json['active_session_status'] as String?,
    );
  }
}

class RemediationAssetListPayload {
  const RemediationAssetListPayload({
    required this.items,
    required this.meta,
  });

  final List<RemediationAssetCardModel> items;
  final PageMeta meta;

  factory RemediationAssetListPayload.fromJson(Map<String, dynamic> json) {
    return RemediationAssetListPayload(
      items: _decodeList(json['items'], RemediationAssetCardModel.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class HostRunnerModel {
  const HostRunnerModel({
    required this.runnerId,
    required this.assetId,
    required this.status,
    required this.installStatus,
    required this.version,
    required this.platformUrl,
    required this.lastSeenAt,
    required this.lastError,
    this.runtimeKind,
    this.installMode,
    this.serviceMode,
    this.detectedOs,
    this.detectedArch,
    this.compatibilityIssues = const [],
    required this.capabilitiesJson,
  });

  final String? runnerId;
  final String assetId;
  final String status;
  final String installStatus;
  final String? version;
  final String? platformUrl;
  final DateTime? lastSeenAt;
  final String? lastError;
  final String? runtimeKind;
  final String? installMode;
  final String? serviceMode;
  final String? detectedOs;
  final String? detectedArch;
  final List<String> compatibilityIssues;
  final Map<String, dynamic> capabilitiesJson;

  factory HostRunnerModel.fromJson(Map<String, dynamic> json) {
    return HostRunnerModel(
      runnerId: json['runner_id'] as String?,
      assetId: json['asset_id'] as String? ?? '',
      status: json['status'] as String? ?? 'not_installed',
      installStatus: json['install_status'] as String? ?? 'not_installed',
      version: json['version'] as String?,
      platformUrl: json['platform_url'] as String?,
      lastSeenAt: _parseDate(json['last_seen_at']),
      lastError: json['last_error'] as String?,
      runtimeKind: json['runtime_kind'] as String?,
      installMode: json['install_mode'] as String?,
      serviceMode: json['service_mode'] as String?,
      detectedOs: json['detected_os'] as String?,
      detectedArch: json['detected_arch'] as String?,
      compatibilityIssues: _stringList(json['compatibility_issues']),
      capabilitiesJson: _map(json['capabilities_json']),
    );
  }
}

class HostRunnerInstallModel {
  const HostRunnerInstallModel({
    required this.taskId,
    required this.status,
    required this.runnerId,
    required this.streamUrl,
  });

  final String taskId;
  final TaskStatusType status;
  final String? runnerId;
  final String streamUrl;

  factory HostRunnerInstallModel.fromJson(Map<String, dynamic> json) {
    return HostRunnerInstallModel(
      taskId: json['task_id'] as String? ?? '',
      status: _taskStatusFromString(json['status'] as String?),
      runnerId: json['runner_id'] as String?,
      streamUrl: json['stream_url'] as String? ?? '',
    );
  }
}

class RemediationAssetDetailModel {
  const RemediationAssetDetailModel({
    required this.asset,
    required this.authorization,
    required this.latestCollection,
    required this.findings,
    required this.runner,
    required this.activeSessionId,
    required this.activeSessionStatus,
    required this.latestTaskId,
    required this.canInstallRunner,
    required this.runnerInstallBlockedReasons,
  });

  final RemediationAssetSummary asset;
  final RemediationAuthorizationModel authorization;
  final RemediationCollectionModel? latestCollection;
  final List<RemediationFindingModel> findings;
  final HostRunnerModel runner;
  final String? activeSessionId;
  final String? activeSessionStatus;
  final String? latestTaskId;
  final bool canInstallRunner;
  final List<String> runnerInstallBlockedReasons;

  factory RemediationAssetDetailModel.fromJson(Map<String, dynamic> json) {
    final latestCollection = json['latest_collection'];
    return RemediationAssetDetailModel(
      asset: RemediationAssetSummary.fromJson(
        json['asset'] as Map<String, dynamic>? ?? const {},
      ),
      authorization: RemediationAuthorizationModel.fromJson(
        json['authorization'] as Map<String, dynamic>? ?? const {},
      ),
      latestCollection: latestCollection is Map<String, dynamic>
          ? RemediationCollectionModel.fromJson(latestCollection)
          : latestCollection is Map
              ? RemediationCollectionModel.fromJson(
                  latestCollection.cast<String, dynamic>(),
                )
              : null,
      findings: _decodeList(json['findings'], RemediationFindingModel.fromJson),
      runner: HostRunnerModel.fromJson(
        json['runner'] as Map<String, dynamic>? ?? const {},
      ),
      activeSessionId: json['active_session_id'] as String?,
      activeSessionStatus: json['active_session_status'] as String?,
      latestTaskId: json['latest_task_id'] as String?,
      canInstallRunner: json['can_install_runner'] as bool? ?? false,
      runnerInstallBlockedReasons: _stringList(
        json['runner_install_blocked_reasons'],
      ),
    );
  }
}

class RemediationBackupPlanModel {
  const RemediationBackupPlanModel({
    required this.kind,
    required this.targets,
    required this.note,
  });

  final String kind;
  final List<String> targets;
  final String? note;

  factory RemediationBackupPlanModel.fromJson(Map<String, dynamic> json) {
    return RemediationBackupPlanModel(
      kind: json['kind'] as String? ?? '',
      targets: _stringList(json['targets']),
      note: json['note'] as String?,
    );
  }
}

class RemediationBlockerModel {
  const RemediationBlockerModel({
    required this.code,
    required this.message,
    required this.scope,
    required this.blocking,
    required this.stageCode,
    required this.stepId,
  });

  final String code;
  final String message;
  final String scope;
  final String blocking;
  final String? stageCode;
  final String? stepId;

  factory RemediationBlockerModel.fromJson(Map<String, dynamic> json) {
    return RemediationBlockerModel(
      code: json['code'] as String? ?? '',
      message: json['message'] as String? ?? '',
      scope: json['scope'] as String? ?? 'global',
      blocking: json['blocking'] as String? ?? 'hard',
      stageCode: json['stage_code'] as String?,
      stepId: json['step_id'] as String?,
    );
  }
}

class HostRemediationRelatedFindingModel {
  const HostRemediationRelatedFindingModel({
    required this.findingId,
    required this.ruleId,
    required this.title,
    required this.severity,
    required this.serviceName,
  });

  final String findingId;
  final String? ruleId;
  final String? title;
  final RiskSeverityLevel? severity;
  final String? serviceName;

  factory HostRemediationRelatedFindingModel.fromJson(
    Map<String, dynamic> json,
  ) {
    final severityRaw = json['severity'] as String?;
    return HostRemediationRelatedFindingModel(
      findingId: json['finding_id'] as String? ?? '',
      ruleId: json['rule_id'] as String?,
      title: json['title'] as String?,
      severity:
          severityRaw == null ? null : _riskSeverityFromString(severityRaw),
      serviceName: json['service_name'] as String?,
    );
  }
}

class HostRemediationPlanStepModel {
  const HostRemediationPlanStepModel({
    required this.stepId,
    required this.findingId,
    required this.findingTitle,
    required this.actionType,
    required this.title,
    required this.phaseCode,
    required this.phaseName,
    required this.executionState,
    required this.blockedReason,
    required this.generatedCommand,
    required this.backupPlan,
    required this.renderReason,
    required this.serviceName,
    required this.targetFiles,
    required this.targetServices,
    required this.targetPaths,
    required this.fallbackStrategy,
    required this.fallbackCandidates,
    required this.verifyItems,
    required this.rollbackHint,
    required this.blockers,
    required this.relatedFindings,
    required this.relatedRules,
  });

  final String stepId;
  final String? findingId;
  final String? findingTitle;
  final String actionType;
  final String title;
  final String phaseCode;
  final String phaseName;
  final String executionState;
  final String? blockedReason;
  final String? generatedCommand;
  final RemediationBackupPlanModel? backupPlan;
  final String? renderReason;
  final String? serviceName;
  final List<String> targetFiles;
  final List<String> targetServices;
  final List<String> targetPaths;
  final String? fallbackStrategy;
  final List<String> fallbackCandidates;
  final List<String> verifyItems;
  final String? rollbackHint;
  final List<RemediationBlockerModel> blockers;
  final List<HostRemediationRelatedFindingModel> relatedFindings;
  final List<String> relatedRules;

  factory HostRemediationPlanStepModel.fromJson(Map<String, dynamic> json) {
    final backupPlan = json['backup_plan'];
    return HostRemediationPlanStepModel(
      stepId: json['step_id'] as String? ?? '',
      findingId: json['finding_id'] as String?,
      findingTitle: json['finding_title'] as String?,
      actionType: json['action_type'] as String? ?? '',
      title: json['title'] as String? ?? '',
      phaseCode: json['phase_code'] as String? ?? '',
      phaseName: json['phase_name'] as String? ?? '',
      executionState: json['execution_state'] as String? ?? 'blocked',
      blockedReason: json['blocked_reason'] as String?,
      generatedCommand: json['generated_command'] as String?,
      backupPlan: backupPlan is Map<String, dynamic>
          ? RemediationBackupPlanModel.fromJson(backupPlan)
          : backupPlan is Map
              ? RemediationBackupPlanModel.fromJson(
                  backupPlan.cast<String, dynamic>(),
                )
              : null,
      renderReason: json['render_reason'] as String?,
      serviceName: json['service_name'] as String?,
      targetFiles: _stringList(json['target_files']),
      targetServices: _stringList(json['target_services']),
      targetPaths: _stringList(json['target_paths']),
      fallbackStrategy: json['fallback_strategy'] as String?,
      fallbackCandidates: _stringList(json['fallback_candidates']),
      verifyItems: _stringList(json['verify_items']),
      rollbackHint: json['rollback_hint'] as String?,
      blockers: _decodeList(
        json['blockers'],
        RemediationBlockerModel.fromJson,
      ),
      relatedFindings: _decodeList(
        json['related_findings'],
        HostRemediationRelatedFindingModel.fromJson,
      ),
      relatedRules: _stringList(json['related_rules']),
    );
  }
}

class HostRemediationPhaseModel {
  const HostRemediationPhaseModel({
    required this.phaseCode,
    required this.phaseName,
    required this.order,
    required this.summary,
    required this.readyCount,
    required this.blockedCount,
  });

  final String phaseCode;
  final String phaseName;
  final int order;
  final String summary;
  final int readyCount;
  final int blockedCount;

  factory HostRemediationPhaseModel.fromJson(Map<String, dynamic> json) {
    return HostRemediationPhaseModel(
      phaseCode: json['phase_code'] as String? ?? '',
      phaseName: json['phase_name'] as String? ?? '',
      order: json['order'] as int? ?? 0,
      summary: json['summary'] as String? ?? '',
      readyCount: json['ready_count'] as int? ?? 0,
      blockedCount: json['blocked_count'] as int? ?? 0,
    );
  }
}

class HostRemediationStageModel {
  const HostRemediationStageModel({
    required this.stageCode,
    required this.stageName,
    required this.order,
    required this.summary,
    required this.gateStatus,
    required this.readyStepCount,
    required this.blockedStepCount,
    required this.globalBlockers,
    required this.relatedFindingIds,
    required this.relatedRuleIds,
    required this.relatedServices,
    required this.steps,
  });

  final String stageCode;
  final String stageName;
  final int order;
  final String summary;
  final String gateStatus;
  final int readyStepCount;
  final int blockedStepCount;
  final List<RemediationBlockerModel> globalBlockers;
  final List<String> relatedFindingIds;
  final List<String> relatedRuleIds;
  final List<String> relatedServices;
  final List<HostRemediationPlanStepModel> steps;

  factory HostRemediationStageModel.fromJson(Map<String, dynamic> json) {
    return HostRemediationStageModel(
      stageCode: json['stage_code'] as String? ?? '',
      stageName: json['stage_name'] as String? ?? '',
      order: json['order'] as int? ?? 0,
      summary: json['summary'] as String? ?? '',
      gateStatus: json['gate_status'] as String? ?? 'locked',
      readyStepCount: json['ready_step_count'] as int? ?? 0,
      blockedStepCount: json['blocked_step_count'] as int? ?? 0,
      globalBlockers: _decodeList(
        json['global_blockers'],
        RemediationBlockerModel.fromJson,
      ),
      relatedFindingIds: _stringList(json['related_finding_ids']),
      relatedRuleIds: _stringList(json['related_rule_ids']),
      relatedServices: _stringList(json['related_services']),
      steps: _decodeList(
        json['steps'],
        HostRemediationPlanStepModel.fromJson,
      ),
    );
  }
}

class HostRemediationPlanModel {
  const HostRemediationPlanModel({
    required this.executionReady,
    required this.planMode,
    required this.currentStageCode,
    required this.blockedReasons,
    required this.globalBlockers,
    required this.stepBlockers,
    required this.findingsCoveredCount,
    required this.serviceCount,
    required this.impactedServices,
    required this.phaseCount,
    required this.readyStageCount,
    required this.blockedStageCount,
    required this.readyStepCount,
    required this.blockedStepCount,
    required this.summaryText,
    required this.impactSummary,
    required this.precheckItems,
    required this.verifyItems,
    required this.rollbackNotes,
    required this.phases,
    required this.steps,
    required this.stages,
  });

  final bool executionReady;
  final String planMode;
  final String? currentStageCode;
  final List<String> blockedReasons;
  final List<RemediationBlockerModel> globalBlockers;
  final List<RemediationBlockerModel> stepBlockers;
  final int findingsCoveredCount;
  final int serviceCount;
  final List<String> impactedServices;
  final int phaseCount;
  final int readyStageCount;
  final int blockedStageCount;
  final int readyStepCount;
  final int blockedStepCount;
  final String summaryText;
  final String? impactSummary;
  final List<String> precheckItems;
  final List<String> verifyItems;
  final List<String> rollbackNotes;
  final List<HostRemediationPhaseModel> phases;
  final List<HostRemediationPlanStepModel> steps;
  final List<HostRemediationStageModel> stages;

  factory HostRemediationPlanModel.fromJson(Map<String, dynamic> json) {
    return HostRemediationPlanModel(
      executionReady: json['execution_ready'] as bool? ?? false,
      planMode: json['plan_mode'] as String? ?? 'blocked',
      currentStageCode: json['current_stage_code'] as String?,
      blockedReasons: _stringList(json['blocked_reasons']),
      globalBlockers: _decodeList(
        json['global_blockers'],
        RemediationBlockerModel.fromJson,
      ),
      stepBlockers: _decodeList(
        json['step_blockers'],
        RemediationBlockerModel.fromJson,
      ),
      findingsCoveredCount: json['findings_covered_count'] as int? ?? 0,
      serviceCount: json['service_count'] as int? ?? 0,
      impactedServices: _stringList(json['impacted_services']),
      phaseCount: json['phase_count'] as int? ?? 0,
      readyStageCount: json['ready_stage_count'] as int? ?? 0,
      blockedStageCount: json['blocked_stage_count'] as int? ?? 0,
      readyStepCount: json['ready_step_count'] as int? ?? 0,
      blockedStepCount: json['blocked_step_count'] as int? ?? 0,
      summaryText: json['summary_text'] as String? ?? '',
      impactSummary: json['impact_summary'] as String?,
      precheckItems: _stringList(json['precheck_items']),
      verifyItems: _stringList(json['verify_items']),
      rollbackNotes: _stringList(json['rollback_notes']),
      phases: _decodeList(
        json['phases'],
        HostRemediationPhaseModel.fromJson,
      ),
      steps: _decodeList(
        json['steps'],
        HostRemediationPlanStepModel.fromJson,
      ),
      stages: _decodeList(
        json['stages'],
        HostRemediationStageModel.fromJson,
      ),
    );
  }
}

class RemediationMessageActionModel {
  const RemediationMessageActionModel({
    required this.actionId,
    required this.label,
    required this.intent,
  });

  final String actionId;
  final String label;
  final String intent;

  factory RemediationMessageActionModel.fromJson(Map<String, dynamic> json) {
    return RemediationMessageActionModel(
      actionId: json['action_id'] as String? ?? '',
      label: json['label'] as String? ?? '',
      intent: json['intent'] as String? ?? '',
    );
  }
}

class RemediationMessageModel {
  const RemediationMessageModel({
    required this.id,
    required this.role,
    required this.messageType,
    required this.content,
    required this.payloadJson,
    required this.createdAt,
    required this.actions,
  });

  final String id;
  final String role;
  final String messageType;
  final String content;
  final Map<String, dynamic> payloadJson;
  final DateTime? createdAt;
  final List<RemediationMessageActionModel> actions;

  factory RemediationMessageModel.fromJson(Map<String, dynamic> json) {
    return RemediationMessageModel(
      id: json['id'] as String? ?? '',
      role: json['role'] as String? ?? '',
      messageType: json['message_type'] as String? ?? '',
      content: json['content'] as String? ?? '',
      payloadJson: _map(json['payload_json']),
      createdAt: _parseDate(json['created_at']),
      actions: _decodeList(
        json['actions'],
        RemediationMessageActionModel.fromJson,
      ),
    );
  }
}

class RemediationSessionModel {
  const RemediationSessionModel({
    required this.sessionId,
    required this.assetId,
    required this.status,
    required this.asset,
    required this.authorization,
    required this.latestCollection,
    required this.runner,
    required this.findings,
    required this.plan,
    required this.messages,
    required this.lastTaskId,
    required this.approvedAt,
    required this.approvedBy,
  });

  final String sessionId;
  final String assetId;
  final String status;
  final RemediationAssetSummary asset;
  final RemediationAuthorizationModel authorization;
  final RemediationCollectionModel? latestCollection;
  final HostRunnerModel runner;
  final List<RemediationFindingModel> findings;
  final HostRemediationPlanModel plan;
  final List<RemediationMessageModel> messages;
  final String? lastTaskId;
  final DateTime? approvedAt;
  final String? approvedBy;

  factory RemediationSessionModel.fromJson(Map<String, dynamic> json) {
    final latestCollection = json['latest_collection'];
    return RemediationSessionModel(
      sessionId: json['session_id'] as String? ?? '',
      assetId: json['asset_id'] as String? ?? '',
      status: json['status'] as String? ?? 'draft',
      asset: RemediationAssetSummary.fromJson(
        json['asset'] as Map<String, dynamic>? ?? const {},
      ),
      authorization: RemediationAuthorizationModel.fromJson(
        json['authorization'] as Map<String, dynamic>? ?? const {},
      ),
      latestCollection: latestCollection is Map<String, dynamic>
          ? RemediationCollectionModel.fromJson(latestCollection)
          : latestCollection is Map
              ? RemediationCollectionModel.fromJson(
                  latestCollection.cast<String, dynamic>(),
                )
              : null,
      runner: HostRunnerModel.fromJson(
        json['runner'] as Map<String, dynamic>? ?? const {},
      ),
      findings: _decodeList(json['findings'], RemediationFindingModel.fromJson),
      plan: HostRemediationPlanModel.fromJson(
        json['plan'] as Map<String, dynamic>? ?? const {},
      ),
      messages: _decodeList(
        json['messages'],
        RemediationMessageModel.fromJson,
      ),
      lastTaskId: json['last_task_id'] as String?,
      approvedAt: _parseDate(json['approved_at']),
      approvedBy: json['approved_by'] as String?,
    );
  }
}

class RemediationSessionApproveModel {
  const RemediationSessionApproveModel({
    required this.sessionId,
    required this.taskId,
    required this.status,
    required this.streamUrl,
  });

  final String sessionId;
  final String taskId;
  final TaskStatusType status;
  final String streamUrl;

  factory RemediationSessionApproveModel.fromJson(Map<String, dynamic> json) {
    return RemediationSessionApproveModel(
      sessionId: json['session_id'] as String? ?? '',
      taskId: json['task_id'] as String? ?? '',
      status: _taskStatusFromString(json['status'] as String?),
      streamUrl: json['stream_url'] as String? ?? '',
    );
  }
}

class RemediationTaskModel {
  const RemediationTaskModel({
    required this.taskId,
    required this.status,
    required this.progress,
    required this.message,
    required this.assetId,
    required this.findingId,
    required this.createdAt,
    required this.startedAt,
    required this.finishedAt,
    required this.eventCount,
    required this.lastEventAt,
    required this.executionBoundary,
    required this.context,
    required this.plan,
    required this.execution,
    required this.backups,
    required this.reverify,
  });

  final String taskId;
  final TaskStatusType status;
  final int progress;
  final String? message;
  final String? assetId;
  final String? findingId;
  final DateTime? createdAt;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final int eventCount;
  final DateTime? lastEventAt;
  final String? executionBoundary;
  final Map<String, dynamic> context;
  final Map<String, dynamic> plan;
  final Map<String, dynamic> execution;
  final Map<String, dynamic> backups;
  final Map<String, dynamic> reverify;

  factory RemediationTaskModel.fromJson(Map<String, dynamic> json) {
    return RemediationTaskModel(
      taskId: json['task_id'] as String? ?? '',
      status: _taskStatusFromString(json['status'] as String?),
      progress: json['progress'] as int? ?? 0,
      message: json['message'] as String?,
      assetId: json['asset_id'] as String?,
      findingId: json['finding_id'] as String?,
      createdAt: _parseDate(json['created_at']),
      startedAt: _parseDate(json['started_at']),
      finishedAt: _parseDate(json['finished_at']),
      eventCount: json['event_count'] as int? ?? 0,
      lastEventAt: _parseDate(json['last_event_at']),
      executionBoundary: json['execution_boundary'] as String?,
      context: _map(json['context']),
      plan: _map(json['plan']),
      execution: _map(json['execution']),
      backups: _map(json['backups']),
      reverify: _map(json['reverify']),
    );
  }
}

class RiskItem {
  const RiskItem({
    required this.id,
    required this.assetId,
    required this.assetIp,
    required this.assetHostname,
    required this.assetPortId,
    required this.severity,
    required this.status,
    required this.title,
    required this.description,
    required this.evidenceJson,
    required this.detectedAt,
    required this.resolvedAt,
  });

  final String id;
  final String assetId;
  final String assetIp;
  final String? assetHostname;
  final String? assetPortId;
  final RiskSeverityLevel severity;
  final RiskStatusType status;
  final String title;
  final String description;
  final Map<String, dynamic> evidenceJson;
  final DateTime? detectedAt;
  final DateTime? resolvedAt;

  factory RiskItem.fromJson(Map<String, dynamic> json) {
    return RiskItem(
      id: json['id'] as String? ?? '',
      assetId: json['asset_id'] as String? ?? '',
      assetIp: json['asset_ip']?.toString() ?? '',
      assetHostname: json['asset_hostname'] as String?,
      assetPortId: json['asset_port_id'] as String?,
      severity: _riskSeverityFromString(json['severity'] as String?),
      status: _riskStatusFromString(json['status'] as String?),
      title: json['title'] as String? ?? '',
      description: json['description'] as String? ?? '',
      evidenceJson: _map(json['evidence_json']),
      detectedAt: _parseDate(json['detected_at']),
      resolvedAt: _parseDate(json['resolved_at']),
    );
  }
}

class RiskListPayload {
  const RiskListPayload({required this.items, required this.meta});

  final List<RiskItem> items;
  final PageMeta meta;

  factory RiskListPayload.fromJson(Map<String, dynamic> json) {
    return RiskListPayload(
      items: _decodeList(json['items'], RiskItem.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

class DiscoveryJobModel {
  const DiscoveryJobModel({
    required this.id,
    required this.cidr,
    required this.status,
    required this.label,
    required this.startedAt,
    required this.finishedAt,
    required this.createdAt,
    required this.summaryJson,
  });

  final String id;
  final String cidr;
  final DiscoveryJobStatusType status;
  final String? label;
  final DateTime? startedAt;
  final DateTime? finishedAt;
  final DateTime? createdAt;
  final Map<String, dynamic> summaryJson;

  factory DiscoveryJobModel.fromJson(Map<String, dynamic> json) {
    return DiscoveryJobModel(
      id: json['id'] as String? ?? '',
      cidr: json['cidr']?.toString() ?? '',
      status: _discoveryStatusFromString(json['status'] as String?),
      label: json['label'] as String?,
      startedAt: _parseDate(json['started_at']),
      finishedAt: _parseDate(json['finished_at']),
      createdAt: _parseDate(json['created_at']),
      summaryJson: _map(json['summary_json']),
    );
  }
}

class DiscoveryJobListPayload {
  const DiscoveryJobListPayload({required this.items, required this.meta});

  final List<DiscoveryJobModel> items;
  final PageMeta meta;

  factory DiscoveryJobListPayload.fromJson(Map<String, dynamic> json) {
    return DiscoveryJobListPayload(
      items: _decodeList(json['items'], DiscoveryJobModel.fromJson),
      meta:
          PageMeta.fromJson(json['meta'] as Map<String, dynamic>? ?? const {}),
    );
  }
}

AppRole decodeRoleFromToken(String token) {
  try {
    final parts = token.split('.');
    if (parts.length < 2) {
      return AppRole.unknown;
    }
    final normalized = base64Url.normalize(parts[1]);
    final payload = jsonDecode(utf8.decode(base64Url.decode(normalized)))
        as Map<String, dynamic>;
    return switch (payload['role']) {
      'admin' => AppRole.admin,
      'analyst' => AppRole.analyst,
      _ => AppRole.unknown,
    };
  } catch (_) {
    return AppRole.unknown;
  }
}

extension AppRoleX on AppRole {
  String get label => switch (this) {
        AppRole.admin => '管理员',
        AppRole.analyst => '分析员',
        AppRole.unknown => '未识别',
      };
}

extension AssetStatusTypeX on AssetStatusType {
  String get label => switch (this) {
        AssetStatusType.online => '在线',
        AssetStatusType.offline => '离线',
        AssetStatusType.collecting => '采集中',
        AssetStatusType.unknown => '未知',
      };
}

extension TaskStatusTypeX on TaskStatusType {
  String get label => switch (this) {
        TaskStatusType.pending => '待执行',
        TaskStatusType.running => '执行中',
        TaskStatusType.retry => '重试中',
        TaskStatusType.success => '成功',
        TaskStatusType.failure => '失败',
        TaskStatusType.canceled => '已取消',
        TaskStatusType.unknown => '未知',
      };
}

extension TaskTypeModelX on TaskTypeModel {
  String get label => switch (this) {
        TaskTypeModel.assetScan => '资产发现',
        TaskTypeModel.infoCollect => '信息采集',
        TaskTypeModel.riskVerify => '风险验证',
        TaskTypeModel.reportGenerate => '报告生成',
        TaskTypeModel.credentialVerify => '凭据验证',
        TaskTypeModel.runnerInstall => 'Runner 安装',
        TaskTypeModel.remediationExecute => '修复执行',
        TaskTypeModel.agentOrchestrate => '玄武执行',
        TaskTypeModel.settingsApply => '设置下发',
        TaskTypeModel.unknown => '未知任务',
      };
}

extension RiskSeverityLevelX on RiskSeverityLevel {
  String get label => switch (this) {
        RiskSeverityLevel.critical => '严重',
        RiskSeverityLevel.high => '高危',
        RiskSeverityLevel.medium => '中危',
        RiskSeverityLevel.low => '低危',
        RiskSeverityLevel.unknown => '未知',
      };
}

extension RiskStatusTypeX on RiskStatusType {
  String get label => switch (this) {
        RiskStatusType.open => '待处理',
        RiskStatusType.ignored => '已忽略',
        RiskStatusType.fixed => '已修复',
        RiskStatusType.unknown => '未知',
      };
}

extension DiscoveryJobStatusTypeX on DiscoveryJobStatusType {
  String get label => switch (this) {
        DiscoveryJobStatusType.pending => '待执行',
        DiscoveryJobStatusType.running => '执行中',
        DiscoveryJobStatusType.completed => '已完成',
        DiscoveryJobStatusType.failed => '失败',
        DiscoveryJobStatusType.unknown => '未知',
      };
}

DateTime? _parseDate(Object? value) {
  final raw = value?.toString();
  if (raw == null || raw.isEmpty) {
    return null;
  }
  return DateTime.tryParse(raw);
}

List<T> _decodeList<T>(Object? raw, T Function(Map<String, dynamic>) mapper) {
  final list = raw as List<dynamic>? ?? const [];
  return list
      .whereType<Map>()
      .map((item) => mapper(item.cast<String, dynamic>()))
      .toList(growable: false);
}

List<String> _stringList(Object? raw) {
  final list = raw as List<dynamic>? ?? const [];
  return list
      .map((item) => item?.toString().trim() ?? '')
      .where((item) => item.isNotEmpty)
      .toList(growable: false);
}

Map<String, dynamic> _map(Object? raw) {
  if (raw is Map<String, dynamic>) {
    return raw;
  }
  if (raw is Map) {
    return raw.cast<String, dynamic>();
  }
  return const {};
}

AssetStatusType _assetStatusFromString(String? value) {
  return switch (value) {
    'online' => AssetStatusType.online,
    'offline' => AssetStatusType.offline,
    'collecting' => AssetStatusType.collecting,
    _ => AssetStatusType.unknown,
  };
}

TaskStatusType _taskStatusFromString(String? value) {
  return switch (value) {
    'pending' => TaskStatusType.pending,
    'running' => TaskStatusType.running,
    'retry' => TaskStatusType.retry,
    'success' => TaskStatusType.success,
    'failure' => TaskStatusType.failure,
    'canceled' => TaskStatusType.canceled,
    _ => TaskStatusType.unknown,
  };
}

TaskTypeModel _taskTypeFromString(String? value) {
  return switch (value) {
    'asset_scan' => TaskTypeModel.assetScan,
    'info_collect' => TaskTypeModel.infoCollect,
    'risk_verify' => TaskTypeModel.riskVerify,
    'report_generate' => TaskTypeModel.reportGenerate,
    'credential_verify' => TaskTypeModel.credentialVerify,
    'runner_install' => TaskTypeModel.runnerInstall,
    'remediation_execute' => TaskTypeModel.remediationExecute,
    'agent_orchestrate' => TaskTypeModel.agentOrchestrate,
    'settings_apply' => TaskTypeModel.settingsApply,
    _ => TaskTypeModel.unknown,
  };
}

RiskSeverityLevel _riskSeverityFromString(String? value) {
  return switch (value) {
    'critical' => RiskSeverityLevel.critical,
    'high' => RiskSeverityLevel.high,
    'medium' => RiskSeverityLevel.medium,
    'low' => RiskSeverityLevel.low,
    _ => RiskSeverityLevel.unknown,
  };
}

RiskStatusType _riskStatusFromString(String? value) {
  return switch (value) {
    'open' => RiskStatusType.open,
    'ignored' => RiskStatusType.ignored,
    'fixed' => RiskStatusType.fixed,
    _ => RiskStatusType.unknown,
  };
}

DiscoveryJobStatusType _discoveryStatusFromString(String? value) {
  return switch (value) {
    'pending' => DiscoveryJobStatusType.pending,
    'running' => DiscoveryJobStatusType.running,
    'completed' => DiscoveryJobStatusType.completed,
    'failed' => DiscoveryJobStatusType.failed,
    _ => DiscoveryJobStatusType.unknown,
  };
}
