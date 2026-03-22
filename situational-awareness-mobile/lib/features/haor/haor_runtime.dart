import '../../core/network/api_client.dart';
import '../../shared/models/agent_models.dart';

AgentPageContext buildAgentPageContext(Uri uri) {
  final segments = uri.pathSegments.where((item) => item.isNotEmpty).toList();
  final query = <String, String>{};
  uri.queryParameters.forEach((key, value) {
    query[key] = value;
  });

  var assetId = query['assetId'] ?? query['asset_id'];
  var findingId = query['findingId'] ?? query['finding_id'];
  var taskId = query['taskId'] ?? query['task_id'];

  if (segments.length >= 2 && segments.first == 'assets') {
    assetId ??= segments[1];
  }
  if (segments.length >= 2 && segments.first == 'remediation') {
    assetId ??= segments[1];
  }
  if (segments.length >= 2 && segments.first == 'tasks') {
    taskId ??= segments[1];
  }
  if (segments.length >= 2 && segments.first == 'risks') {
    findingId ??= segments[1];
  }

  return AgentPageContext(
    pathname: uri.path.isEmpty ? '/' : uri.path,
    query: query,
    assetId: _emptyToNull(assetId),
    findingId: _emptyToNull(findingId),
    taskId: _emptyToNull(taskId),
  );
}

AgentBrowserContext buildMobileHaorBrowserContext({
  required Uri uri,
  required String title,
  String? subtitle,
  required String origin,
}) {
  final pageContext = buildAgentPageContext(uri);
  final selectedEntities = <Map<String, dynamic>>[
    if (pageContext.assetId != null)
      {
        'kind': 'asset',
        'id': pageContext.assetId,
        'label': '资产 ${pageContext.assetId}',
        'source': 'route',
      },
    if (pageContext.findingId != null)
      {
        'kind': 'finding',
        'id': pageContext.findingId,
        'label': '风险 ${pageContext.findingId}',
        'source': 'route',
      },
    if (pageContext.taskId != null)
      {
        'kind': 'task',
        'id': pageContext.taskId,
        'label': '任务 ${pageContext.taskId}',
        'source': 'route',
      },
  ];

  final semantic = _buildSemanticPageContext(
    pageContext: pageContext,
    title: title,
    subtitle: subtitle,
  );

  return AgentBrowserContext(
    pathname: pageContext.pathname,
    origin: origin,
    title: title,
    query: pageContext.query,
    assetId: pageContext.assetId,
    findingId: pageContext.findingId,
    taskId: pageContext.taskId,
    selectedEntities: selectedEntities,
    semanticPageContext: semantic,
    semanticActions: semantic.semanticActions,
  );
}

String resolveHaorScreenTitle(Uri uri) {
  final path = uri.path;
  if (path == '/overview') {
    return '总览';
  }
  if (path == '/assets') {
    return '资产';
  }
  if (path.startsWith('/assets/')) {
    return '资产详情';
  }
  if (path == '/tasks') {
    return '任务';
  }
  if (path.startsWith('/tasks/')) {
    return '任务详情';
  }
  if (path == '/risks') {
    return '风险';
  }
  if (path.startsWith('/risks/')) {
    return '风险详情';
  }
  if (path == '/discovery') {
    return '发现任务';
  }
  if (path.startsWith('/discovery/')) {
    return '发现任务详情';
  }
  if (path == '/remediation') {
    return '修复工作台';
  }
  if (path.startsWith('/remediation/')) {
    return '修复资产详情';
  }
  return path.isEmpty ? '/' : path;
}

Future<List<AgentUIActionResult>> executeMobileHaorActions({
  required List<AgentUIAction> actions,
  required AgentBrowserContext browserContext,
  required ApiClient apiClient,
}) async {
  final results = <AgentUIActionResult>[];
  for (final action in actions) {
    results.add(
      await _executeAction(
        action: action,
        browserContext: browserContext,
        apiClient: apiClient,
      ),
    );
  }
  return results;
}

Future<AgentUIActionResult> _executeAction({
  required AgentUIAction action,
  required AgentBrowserContext browserContext,
  required ApiClient apiClient,
}) async {
  final semanticActionId = action.semanticActionId ?? '';
  final pageKind = browserContext.semanticPageContext.pageKind;
  final assetId = browserContext.assetId;
  final taskId = browserContext.taskId;

  AgentUIActionResult base({
    required bool ok,
    required String message,
    Map<String, dynamic> detailJson = const {},
    Map<String, dynamic> resolvedTarget = const {},
  }) {
    return AgentUIActionResult(
      actionId: action.actionId,
      actionType: action.actionType,
      ok: ok,
      semanticActionId: action.semanticActionId,
      targetNodeId: action.targetNodeId,
      resolvedNodeId: null,
      message: message,
      resolvedTarget: {
        'semantic_action_id': action.semanticActionId,
        'page_kind': pageKind,
        ...resolvedTarget,
      },
      attemptCount: 1,
      detailJson: detailJson,
    );
  }

  try {
    if (action.actionType == 'navigate' && (action.href ?? '').isNotEmpty) {
      return base(
        ok: true,
        message: '已准备跳转到 ${action.href}',
        detailJson: {'next_path': action.href},
        resolvedTarget: {'href': action.href},
      );
    }

    if (semanticActionId == 'overview:open_assets_online') {
      return base(
        ok: true,
        message: '已准备切换到在线资产列表',
        detailJson: const {'next_path': '/assets?status=online'},
      );
    }
    if (semanticActionId == 'overview:open_tasks_running') {
      return base(
        ok: true,
        message: '已准备切换到活跃任务列表',
        detailJson: const {'next_path': '/tasks?status=running'},
      );
    }
    if (semanticActionId == 'overview:open_risks_high') {
      return base(
        ok: true,
        message: '已准备切换到高危风险列表',
        detailJson: const {'next_path': '/risks?severity=high'},
      );
    }
    if (semanticActionId == 'overview:open_discovery') {
      return base(
        ok: true,
        message: '已准备进入发现任务页',
        detailJson: const {'next_path': '/discovery'},
      );
    }
    if (semanticActionId == 'overview:open_remediation') {
      return base(
        ok: true,
        message: '已准备进入修复工作台',
        detailJson: const {'next_path': '/remediation'},
      );
    }

    if (semanticActionId == 'asset_detail:verify_risks' && assetId != null) {
      final task = await apiClient.verifyAssetRisk(assetId);
      return base(
        ok: true,
        message: '已发起风险验证任务 ${task.id}',
        detailJson: {'task_id': task.id},
        resolvedTarget: {'asset_id': assetId},
      );
    }
    if (semanticActionId == 'asset_detail:run_collection' && assetId != null) {
      final task = await apiClient.runAssetCollection(assetId);
      return base(
        ok: true,
        message: '已发起信息采集任务 ${task.id}',
        detailJson: {'task_id': task.id},
        resolvedTarget: {'asset_id': assetId},
      );
    }
    if (semanticActionId == 'asset_detail:open_remediation' &&
        assetId != null) {
      return base(
        ok: true,
        message: '已准备进入资产修复页',
        detailJson: {'next_path': '/remediation/$assetId'},
        resolvedTarget: {'asset_id': assetId},
      );
    }

    if (semanticActionId == 'task_detail:cancel_task' && taskId != null) {
      final task = await apiClient.cancelTask(taskId);
      return base(
        ok: true,
        message: '已中断任务 ${task.id}',
        detailJson: {'task_id': task.id},
        resolvedTarget: {'task_id': taskId},
      );
    }
    if (semanticActionId == 'task_detail:refresh') {
      return base(ok: true, message: '任务详情已刷新');
    }

    if (semanticActionId == 'remediation_asset_detail:install_runner' &&
        assetId != null) {
      final result = await apiClient.installAssetRunner(assetId);
      return base(
        ok: true,
        message: '已发起 Runner 安装任务 ${result.taskId}',
        detailJson: {'task_id': result.taskId},
        resolvedTarget: {'asset_id': assetId},
      );
    }
    if (semanticActionId == 'remediation_asset_detail:back_to_gallery') {
      return base(
        ok: true,
        message: '已准备返回修复资产列表',
        detailJson: const {'next_path': '/remediation'},
      );
    }
    if (semanticActionId == 'remediation_asset_detail:refresh') {
      return base(ok: true, message: '修复页已刷新');
    }

    return base(ok: false, message: '移动端当前不支持该页面动作');
  } catch (error) {
    return base(
      ok: false,
      message: describeApiError(error),
      detailJson: {'page_kind': pageKind},
    );
  }
}

AgentSemanticPageContext _buildSemanticPageContext({
  required AgentPageContext pageContext,
  required String title,
  String? subtitle,
}) {
  final pageKind = _inferPageKind(pageContext.pathname);
  final summaryFallback = [
    title.trim(),
    if ((subtitle ?? '').trim().isNotEmpty) subtitle!.trim(),
  ].join('，');
  final visibleSections = <Map<String, dynamic>>[
    {
      'section_id': '$pageKind:main',
      'label': title,
      'description': subtitle,
    },
  ];

  Map<String, dynamic> buildPrimaryEntity({
    required String kind,
    required String? id,
    required String label,
  }) {
    return {
      'kind': kind,
      'id': id,
      'label': label,
      'source': 'route',
    };
  }

  switch (pageKind) {
    case 'overview':
      final actions = <AgentSemanticAction>[
        const AgentSemanticAction(
          semanticActionId: 'overview:open_assets_online',
          label: '打开在线资产',
          actionType: 'navigate',
          description: '切到在线资产列表',
          href: '/assets?status=online',
          targetEntity: {'kind': 'asset_list', 'status': 'online'},
          keywords: ['打开', '资产', '在线资产', '资产列表'],
        ),
        const AgentSemanticAction(
          semanticActionId: 'overview:open_tasks_running',
          label: '打开活跃任务',
          actionType: 'navigate',
          description: '切到执行中任务列表',
          href: '/tasks?status=running',
          targetEntity: {'kind': 'task_list', 'status': 'running'},
          keywords: ['打开', '任务', '活跃任务', '执行中'],
        ),
        const AgentSemanticAction(
          semanticActionId: 'overview:open_risks_high',
          label: '打开高危风险',
          actionType: 'navigate',
          description: '切到高危风险列表',
          href: '/risks?severity=high',
          targetEntity: {'kind': 'risk_list', 'severity': 'high'},
          keywords: ['打开', '风险', '高危风险'],
        ),
        const AgentSemanticAction(
          semanticActionId: 'overview:open_discovery',
          label: '进入发现任务',
          actionType: 'navigate',
          description: '打开发现任务页',
          href: '/discovery',
          targetEntity: {'kind': 'discovery'},
          keywords: ['发现', '扫描', '进入发现'],
        ),
        const AgentSemanticAction(
          semanticActionId: 'overview:open_remediation',
          label: '进入修复工作台',
          actionType: 'navigate',
          description: '打开修复工作台',
          href: '/remediation',
          targetEntity: {'kind': 'remediation'},
          keywords: ['修复', 'runner', '进入修复'],
        ),
      ];
      return AgentSemanticPageContext(
        pageKind: pageKind,
        primaryEntity: const {},
        secondaryEntities: const [],
        visibleSections: visibleSections,
        semanticActions: actions,
        summary: '总览页，可快速切到资产、任务、风险、发现和修复工作台。',
      );
    case 'asset_detail':
      final label = '资产 ${pageContext.assetId ?? ''}'.trim();
      final actions = <AgentSemanticAction>[
        AgentSemanticAction(
          semanticActionId: 'asset_detail:verify_risks',
          label: '风险验证',
          actionType: 'click',
          description: '为当前资产发起风险验证任务',
          href: null,
          targetEntity: {
            'kind': 'asset',
            'id': pageContext.assetId,
            'label': label
          },
          keywords: ['风险', '验证', '风险验证', '资产'],
        ),
        AgentSemanticAction(
          semanticActionId: 'asset_detail:run_collection',
          label: '单资产采集',
          actionType: 'click',
          description: '为当前资产发起采集任务',
          href: null,
          targetEntity: {
            'kind': 'asset',
            'id': pageContext.assetId,
            'label': label
          },
          keywords: ['采集', '信息采集', '深度检查', '资产'],
        ),
        AgentSemanticAction(
          semanticActionId: 'asset_detail:open_remediation',
          label: '进入修复工作台',
          actionType: 'navigate',
          description: '打开当前资产的修复页',
          href: pageContext.assetId == null
              ? null
              : '/remediation/${pageContext.assetId}',
          targetEntity: {
            'kind': 'asset',
            'id': pageContext.assetId,
            'label': label
          },
          keywords: ['修复', 'runner', '修复工作台'],
        ),
      ];
      return AgentSemanticPageContext(
        pageKind: pageKind,
        primaryEntity: buildPrimaryEntity(
          kind: 'asset',
          id: pageContext.assetId,
          label: label,
        ),
        secondaryEntities: const [],
        visibleSections: visibleSections,
        semanticActions: actions,
        summary: '资产详情页，可直接发起风险验证、信息采集，并进入当前资产的修复工作台。',
      );
    case 'task_detail':
      final label = '任务 ${pageContext.taskId ?? ''}'.trim();
      final actions = <AgentSemanticAction>[
        AgentSemanticAction(
          semanticActionId: 'task_detail:refresh',
          label: '刷新任务详情',
          actionType: 'click',
          description: '刷新当前任务状态和事件',
          href: null,
          targetEntity: {
            'kind': 'task',
            'id': pageContext.taskId,
            'label': label
          },
          keywords: ['刷新', '任务状态', '任务详情'],
        ),
        AgentSemanticAction(
          semanticActionId: 'task_detail:cancel_task',
          label: '中断任务',
          actionType: 'click',
          description: '中断当前任务',
          href: null,
          targetEntity: {
            'kind': 'task',
            'id': pageContext.taskId,
            'label': label
          },
          keywords: ['中断', '取消', '停止', '任务'],
        ),
      ];
      return AgentSemanticPageContext(
        pageKind: pageKind,
        primaryEntity: buildPrimaryEntity(
          kind: 'task',
          id: pageContext.taskId,
          label: label,
        ),
        secondaryEntities: const [],
        visibleSections: visibleSections,
        semanticActions: actions,
        summary: '任务详情页，可查看进度、事件和结果，并对当前任务执行刷新或中断。',
      );
    case 'remediation_asset_detail':
      final label = '资产 ${pageContext.assetId ?? ''}'.trim();
      final actions = <AgentSemanticAction>[
        AgentSemanticAction(
          semanticActionId: 'remediation_asset_detail:install_runner',
          label: '安装 Runner',
          actionType: 'click',
          description: '为当前资产安装 Host Runner',
          href: null,
          targetEntity: {
            'kind': 'asset',
            'id': pageContext.assetId,
            'label': label
          },
          keywords: ['安装', 'Runner', '重装', '修复'],
        ),
        const AgentSemanticAction(
          semanticActionId: 'remediation_asset_detail:back_to_gallery',
          label: '返回修复资产列表',
          actionType: 'navigate',
          description: '回到修复工作台列表',
          href: '/remediation',
          targetEntity: {'kind': 'remediation'},
          keywords: ['返回', '修复列表', '修复工作台'],
        ),
        AgentSemanticAction(
          semanticActionId: 'remediation_asset_detail:refresh',
          label: '刷新修复页',
          actionType: 'click',
          description: '刷新当前修复页信息',
          href: null,
          targetEntity: {
            'kind': 'asset',
            'id': pageContext.assetId,
            'label': label
          },
          keywords: ['刷新', '修复', 'runner'],
        ),
      ];
      return AgentSemanticPageContext(
        pageKind: pageKind,
        primaryEntity: buildPrimaryEntity(
          kind: 'asset',
          id: pageContext.assetId,
          label: label,
        ),
        secondaryEntities: const [],
        visibleSections: visibleSections,
        semanticActions: actions,
        summary: '修复资产详情页，可查看 Runner 和会话状态，并直接安装 Runner 或返回资产列表。',
      );
    default:
      return AgentSemanticPageContext(
        pageKind: pageKind,
        primaryEntity: const {},
        secondaryEntities: const [],
        visibleSections: visibleSections,
        semanticActions: const [],
        summary:
            summaryFallback.isEmpty ? pageContext.pathname : summaryFallback,
      );
  }
}

String _inferPageKind(String pathname) {
  if (pathname == '/overview') {
    return 'overview';
  }
  if (pathname == '/assets') {
    return 'asset_list';
  }
  if (pathname.startsWith('/assets/')) {
    return 'asset_detail';
  }
  if (pathname == '/tasks') {
    return 'task_list';
  }
  if (pathname.startsWith('/tasks/')) {
    return 'task_detail';
  }
  if (pathname == '/remediation') {
    return 'remediation_overview';
  }
  if (pathname.startsWith('/remediation/')) {
    return 'remediation_asset_detail';
  }
  if (pathname == '/risks') {
    return 'risk_entry';
  }
  if (pathname.startsWith('/risks/')) {
    return 'generic';
  }
  if (pathname == '/discovery' || pathname.startsWith('/discovery/')) {
    return 'generic';
  }
  return 'generic';
}

String? _emptyToNull(String? value) {
  final normalized = value?.trim();
  if (normalized == null || normalized.isEmpty) {
    return null;
  }
  return normalized;
}
