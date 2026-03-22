// ignore_for_file: sort_constructors_first

import 'dart:convert';

class AgentProposedAction {
  const AgentProposedAction({
    required this.actionType,
    required this.title,
    required this.reason,
    required this.params,
  });

  final String actionType;
  final String title;
  final String reason;
  final Map<String, dynamic> params;

  factory AgentProposedAction.fromJson(Map<String, dynamic> json) {
    return AgentProposedAction(
      actionType: json['action_type'] as String? ?? '',
      title: json['title'] as String? ?? '',
      reason: json['reason'] as String? ?? '',
      params: _asMap(json['params']),
    );
  }
}

class AgentMessage {
  const AgentMessage({
    required this.id,
    required this.role,
    required this.messageType,
    required this.content,
    required this.payloadJson,
    required this.createdAt,
    required this.proposedWriteActions,
  });

  final String id;
  final String role;
  final String messageType;
  final String content;
  final Map<String, dynamic> payloadJson;
  final DateTime? createdAt;
  final List<AgentProposedAction> proposedWriteActions;

  factory AgentMessage.fromJson(Map<String, dynamic> json) {
    return AgentMessage(
      id: json['id'] as String? ?? '',
      role: json['role'] as String? ?? 'assistant',
      messageType: json['message_type'] as String? ?? 'text',
      content: json['content'] as String? ?? '',
      payloadJson: _asMap(json['payload_json']),
      createdAt: _parseDate(json['created_at']),
      proposedWriteActions: _decodeList(
        json['proposed_write_actions'],
        AgentProposedAction.fromJson,
      ),
    );
  }
}

class AgentSession {
  const AgentSession({
    required this.sessionId,
    required this.agentId,
    required this.status,
    required this.routeContextJson,
    required this.workingContextJson,
    required this.dialogStateJson,
    required this.pendingPlanJson,
    required this.browserRuntimeJson,
    required this.lastTaskId,
    required this.messages,
    required this.createdAt,
    required this.updatedAt,
  });

  final String sessionId;
  final String agentId;
  final String status;
  final Map<String, dynamic> routeContextJson;
  final Map<String, dynamic> workingContextJson;
  final Map<String, dynamic> dialogStateJson;
  final Map<String, dynamic> pendingPlanJson;
  final Map<String, dynamic> browserRuntimeJson;
  final String? lastTaskId;
  final List<AgentMessage> messages;
  final DateTime? createdAt;
  final DateTime? updatedAt;

  factory AgentSession.fromJson(Map<String, dynamic> json) {
    return AgentSession(
      sessionId: json['session_id'] as String? ?? '',
      agentId: json['agent_id'] as String? ?? '',
      status: json['status'] as String? ?? 'active',
      routeContextJson: _asMap(json['route_context_json']),
      workingContextJson: _asMap(json['working_context_json']),
      dialogStateJson: _asMap(json['dialog_state_json']),
      pendingPlanJson: _asMap(json['pending_plan_json']),
      browserRuntimeJson: _asMap(json['browser_runtime_json']),
      lastTaskId: json['last_task_id'] as String?,
      messages: _decodeList(json['messages'], AgentMessage.fromJson),
      createdAt: _parseDate(json['created_at']),
      updatedAt: _parseDate(json['updated_at']),
    );
  }
}

class AgentPageContext {
  const AgentPageContext({
    required this.pathname,
    required this.query,
    this.assetId,
    this.findingId,
    this.taskId,
  });

  final String pathname;
  final Map<String, String> query;
  final String? assetId;
  final String? findingId;
  final String? taskId;

  Map<String, dynamic> toJson() {
    return {
      'pathname': pathname,
      'query': query,
      'asset_id': assetId,
      'finding_id': findingId,
      'task_id': taskId,
    };
  }
}

class AgentSemanticAction {
  const AgentSemanticAction({
    required this.semanticActionId,
    required this.label,
    required this.actionType,
    required this.description,
    required this.href,
    required this.targetEntity,
    required this.keywords,
  });

  final String semanticActionId;
  final String label;
  final String actionType;
  final String? description;
  final String? href;
  final Map<String, dynamic> targetEntity;
  final List<String> keywords;

  Map<String, dynamic> toJson() {
    return {
      'semantic_action_id': semanticActionId,
      'label': label,
      'action_type': actionType,
      'description': description,
      'href': href,
      'text_contains': label,
      'target_entity': targetEntity,
      'keywords': keywords,
    };
  }
}

class AgentSemanticPageContext {
  const AgentSemanticPageContext({
    required this.pageKind,
    required this.primaryEntity,
    required this.secondaryEntities,
    required this.visibleSections,
    required this.semanticActions,
    required this.summary,
  });

  final String pageKind;
  final Map<String, dynamic> primaryEntity;
  final List<Map<String, dynamic>> secondaryEntities;
  final List<Map<String, dynamic>> visibleSections;
  final List<AgentSemanticAction> semanticActions;
  final String summary;

  Map<String, dynamic> toJson() {
    return {
      'page_kind': pageKind,
      'primary_entity': primaryEntity,
      'secondary_entities': secondaryEntities,
      'visible_sections': visibleSections,
      'semantic_actions': semanticActions.map((item) => item.toJson()).toList(),
      'semantic_forms': const <Map<String, dynamic>>[],
      'active_dialog': const <String, dynamic>{},
      'selected_rows': const <Map<String, dynamic>>[],
      'summary': summary,
    };
  }
}

class AgentBrowserContext {
  const AgentBrowserContext({
    required this.pathname,
    required this.origin,
    required this.title,
    required this.query,
    required this.assetId,
    required this.findingId,
    required this.taskId,
    required this.selectedEntities,
    required this.semanticPageContext,
    required this.semanticActions,
  });

  final String pathname;
  final String origin;
  final String title;
  final Map<String, String> query;
  final String? assetId;
  final String? findingId;
  final String? taskId;
  final List<Map<String, dynamic>> selectedEntities;
  final AgentSemanticPageContext semanticPageContext;
  final List<AgentSemanticAction> semanticActions;

  Map<String, dynamic> toJson() {
    return {
      'pathname': pathname,
      'origin': origin,
      'title': title,
      'query': query,
      'asset_id': assetId,
      'finding_id': findingId,
      'task_id': taskId,
      'selected_entities': selectedEntities,
      'open_panels': const <Map<String, dynamic>>[],
      'forms': const <Map<String, dynamic>>[],
      'visible_actions': const <Map<String, dynamic>>[],
      'semantic_page_context': semanticPageContext.toJson(),
      'semantic_actions': semanticActions.map((item) => item.toJson()).toList(),
      'semantic_forms': const <Map<String, dynamic>>[],
      'dom_snapshot': const <Map<String, dynamic>>[],
    };
  }
}

class AgentUIAction {
  const AgentUIAction({
    required this.actionId,
    required this.actionType,
    required this.semanticActionId,
    required this.targetNodeId,
    required this.selector,
    required this.textContains,
    required this.labelContains,
    required this.href,
    required this.value,
    required this.fieldName,
    required this.optionLabel,
    required this.waitMs,
    required this.rationale,
    required this.expectedOutcome,
    required this.expectedPageKind,
    required this.expectedSection,
    required this.expectedEntity,
    required this.retryable,
  });

  final String actionId;
  final String actionType;
  final String? semanticActionId;
  final String? targetNodeId;
  final String? selector;
  final String? textContains;
  final String? labelContains;
  final String? href;
  final String? value;
  final String? fieldName;
  final String? optionLabel;
  final int? waitMs;
  final String? rationale;
  final String? expectedOutcome;
  final String? expectedPageKind;
  final String? expectedSection;
  final Map<String, dynamic> expectedEntity;
  final bool retryable;

  factory AgentUIAction.fromJson(Map<String, dynamic> json) {
    return AgentUIAction(
      actionId: json['action_id'] as String? ?? '',
      actionType: json['action_type'] as String? ?? 'click',
      semanticActionId: json['semantic_action_id'] as String?,
      targetNodeId: json['target_node_id'] as String?,
      selector: json['selector'] as String?,
      textContains: json['text_contains'] as String?,
      labelContains: json['label_contains'] as String?,
      href: json['href'] as String?,
      value: json['value'] as String?,
      fieldName: json['field_name'] as String?,
      optionLabel: json['option_label'] as String?,
      waitMs: json['wait_ms'] as int?,
      rationale: json['rationale'] as String?,
      expectedOutcome: json['expected_outcome'] as String?,
      expectedPageKind: json['expected_page_kind'] as String?,
      expectedSection: json['expected_section'] as String?,
      expectedEntity: _asMap(json['expected_entity']),
      retryable: json['retryable'] as bool? ?? true,
    );
  }
}

class AgentUIActionResult {
  const AgentUIActionResult({
    required this.actionId,
    required this.actionType,
    required this.ok,
    required this.semanticActionId,
    required this.targetNodeId,
    required this.resolvedNodeId,
    required this.message,
    required this.resolvedTarget,
    required this.attemptCount,
    required this.detailJson,
  });

  final String actionId;
  final String actionType;
  final bool ok;
  final String? semanticActionId;
  final String? targetNodeId;
  final String? resolvedNodeId;
  final String? message;
  final Map<String, dynamic> resolvedTarget;
  final int attemptCount;
  final Map<String, dynamic> detailJson;

  Map<String, dynamic> toJson() {
    return {
      'action_id': actionId,
      'action_type': actionType,
      'ok': ok,
      'semantic_action_id': semanticActionId,
      'target_node_id': targetNodeId,
      'resolved_node_id': resolvedNodeId,
      'message': message,
      'resolved_target': resolvedTarget,
      'attempt_count': attemptCount,
      'detail_json': detailJson,
    };
  }
}

class AgentApprovalResponse {
  const AgentApprovalResponse({
    required this.sessionId,
    required this.taskId,
    required this.status,
  });

  final String sessionId;
  final String taskId;
  final String status;

  factory AgentApprovalResponse.fromJson(Map<String, dynamic> json) {
    return AgentApprovalResponse(
      sessionId: json['session_id'] as String? ?? '',
      taskId: json['task_id'] as String? ?? '',
      status: json['status'] as String? ?? 'pending',
    );
  }
}

Map<String, dynamic> _asMap(Object? value) {
  if (value is Map<String, dynamic>) {
    return value;
  }
  if (value is Map) {
    return value.cast<String, dynamic>();
  }
  if (value is String && value.trim().isNotEmpty) {
    try {
      final decoded = jsonDecode(value);
      if (decoded is Map<String, dynamic>) {
        return decoded;
      }
      if (decoded is Map) {
        return decoded.cast<String, dynamic>();
      }
    } catch (_) {
      return const {};
    }
  }
  return const {};
}

List<T> _decodeList<T>(
  Object? value,
  T Function(Map<String, dynamic>) mapper,
) {
  final list = value as List<dynamic>? ?? const [];
  return list
      .whereType<Map>()
      .map((item) => mapper(item.cast<String, dynamic>()))
      .toList(growable: false);
}

DateTime? _parseDate(Object? value) {
  final raw = value?.toString();
  if (raw == null || raw.isEmpty) {
    return null;
  }
  return DateTime.tryParse(raw);
}
