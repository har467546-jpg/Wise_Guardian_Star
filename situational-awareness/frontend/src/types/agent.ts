export type AgentSuggestedReply = {
  label: string;
  text: string;
};

export type AgentMessageType =
  | "text"
  | "clarifying"
  | "plan"
  | "task_update"
  | "action_update"
  | "error"
  | string;

export type AgentUIActionType =
  | "navigate"
  | "click"
  | "input"
  | "select"
  | "toggle"
  | "expand"
  | "scroll_into_view"
  | "submit"
  | "wait_for"
  | string;

export type AgentProposedAction = {
  action_type:
    | "create_discovery_job"
    | "verify_asset_risks"
    | "install_runner"
    | "create_or_resume_remediation_session"
    | "approve_remediation_session"
    | "configure_ssh_credential";
  title: string;
  reason: string;
  params: Record<string, unknown>;
};

export type AgentMessage = {
  id: string;
  role: "system" | "user" | "assistant";
  message_type: AgentMessageType;
  content: string;
  payload_json: Record<string, unknown>;
  created_at: string;
  suggested_replies: AgentSuggestedReply[];
  proposed_write_actions: AgentProposedAction[];
};

export type AgentStateFocus = {
  summary?: string | null;
  focus_type?: string | null;
  resolved?: Record<string, unknown>;
  confidence?: string | null;
  source?: string | null;
};

export type AgentStateExecution = {
  stage?: string | null;
  step_kind?: string | null;
  step_label?: string | null;
  waiting_for?: string | null;
  missing_slots?: string[];
  pending_ui_actions?: Array<Record<string, unknown>>;
};

export type AgentStateExplanation = {
  reason?: string | null;
  decision_summary?: string | null;
  expected_outcome?: string | null;
  next_step?: string | null;
  evidence?: Array<Record<string, unknown>>;
};

export type AgentStateWatch = {
  primary_task_id?: string | null;
  related_task_ids?: string[];
  status?: string | null;
  watching?: boolean;
  last_task_message?: string | null;
};

export type AgentState = {
  focus?: AgentStateFocus;
  execution?: AgentStateExecution;
  explanation?: AgentStateExplanation;
  watch?: AgentStateWatch;
};

export type AgentGoal = {
  id: string;
  user_id: string;
  agent_id: string;
  status: "active" | "blocked" | "completed" | "failed" | "canceled" | string;
  title: string;
  goal_kind: string;
  success_criteria_json: Record<string, unknown>;
  context_json: Record<string, unknown>;
  plan_json: Record<string, unknown>;
  progress_json: Record<string, unknown>;
  blocked_reason: string | null;
  last_session_id: string | null;
  last_task_id: string | null;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
};

export type AgentRecoverableError = {
  code: string;
  message: string;
  retryable: boolean;
};

export type AgentRuntimeSnapshot = {
  phase:
    | "idle"
    | "awaiting_agent_reply"
    | "awaiting_ui_feedback"
    | "awaiting_secure_input"
    | "resolving_ui_feedback"
    | "waiting_approval"
    | "watching_task"
    | "recovering"
    | "failed"
    | string;
  input_state: "enabled" | "locked" | string;
  input_block_reason:
    | "none"
    | "awaiting_reply"
    | "pending_ui"
    | "pending_sensitive_input"
    | "waiting_approval"
    | "recovering"
    | "resetting"
    | string;
  current_turn_id: string | null;
  watch_task_id: string | null;
  active_skill_id: string | null;
  active_skill_title: string | null;
  blocker_summary: string | null;
  recoverable_error: AgentRecoverableError | null;
  can_interrupt: boolean;
  can_resume: boolean;
};

export type AgentSession = {
  session_id: string;
  agent_id: string;
  status: "active" | "waiting_approval" | "running" | "completed" | "failed" | string;
  route_context_json: Record<string, unknown>;
  working_context_json: Record<string, unknown>;
  dialog_state_json: Record<string, unknown>;
  pending_plan_json: Record<string, unknown>;
  browser_runtime_json: Record<string, unknown>;
  agent_state_json: AgentState | Record<string, unknown>;
  runtime_snapshot: AgentRuntimeSnapshot;
  current_goal_id: string | null;
  current_goal_title: string | null;
  last_task_id: string | null;
  messages: AgentMessage[];
  created_at: string;
  updated_at: string;
};

export type AgentPendingSecureInput = {
  kind: string;
  mode: string;
  asset_ids: string[];
  asset_labels: string[];
  auth_type?: "password" | "key" | null | string;
  username?: string | null;
  resume_goal_id?: string | null;
  resume_action?: Record<string, unknown> | null;
  auto_verify?: boolean;
  auto_resume?: boolean;
  blocker_summary?: string | null;
};

export type AgentMessageActionSuggestion = {
  kind: string;
  label: string;
  message_text?: string | null;
  pathname?: string | null;
};

export type AgentAttentionKind = "none" | "waiting_approval" | "running_task" | "pending_ui_action";

export type AgentSessionSummary = {
  has_attention: boolean;
  attention_kind: AgentAttentionKind;
  session_status: AgentSession["status"] | null;
  runtime_phase: AgentRuntimeSnapshot["phase"];
  input_state: AgentRuntimeSnapshot["input_state"];
  input_block_reason: AgentRuntimeSnapshot["input_block_reason"];
  current_goal_id: string | null;
  current_goal_title: string | null;
  active_skill_title: string | null;
  last_task_id: string | null;
  updated_at: string | null;
};

export type AgentPageContext = {
  pathname: string;
  query: Record<string, string>;
  asset_id?: string | null;
  finding_id?: string | null;
  task_id?: string | null;
};

export type AgentBrowserDOMNode = {
  node_id: string;
  tag_name: string;
  role?: string | null;
  text?: string | null;
  label?: string | null;
  href?: string | null;
  value?: string | null;
  is_interactive?: boolean;
  is_visible?: boolean;
  attributes?: Record<string, unknown>;
};

export type AgentBrowserVisibleAction = {
  action_id: string;
  action_type: AgentUIActionType;
  node_id?: string | null;
  label: string;
  description?: string | null;
};

export type AgentBrowserSemanticEntity = {
  kind: string;
  id?: string | null;
  label?: string | null;
  status?: string | null;
  source?: string | null;
  meta?: Record<string, unknown>;
};

export type AgentBrowserSemanticSection = {
  section_id: string;
  label: string;
  node_id?: string | null;
  description?: string | null;
};

export type AgentBrowserSemanticAction = {
  semantic_action_id: string;
  label: string;
  action_type: AgentUIActionType;
  node_id?: string | null;
  description?: string | null;
  section_id?: string | null;
  href?: string | null;
  selector?: string | null;
  text_contains?: string | null;
  target_entity?: Record<string, unknown>;
  keywords?: string[];
};

export type AgentBrowserSemanticForm = {
  semantic_form_id: string;
  label: string;
  node_id?: string | null;
  fields?: Array<Record<string, unknown>>;
  submit_action_id?: string | null;
};

export type AgentSemanticPageContext = {
  page_kind: string;
  primary_entity?: Record<string, unknown>;
  secondary_entities?: Array<Record<string, unknown>>;
  visible_sections?: AgentBrowserSemanticSection[];
  semantic_actions?: AgentBrowserSemanticAction[];
  semantic_forms?: AgentBrowserSemanticForm[];
  active_dialog?: Record<string, unknown>;
  selected_rows?: Array<Record<string, unknown>>;
  summary?: string | null;
};

export type AgentBrowserContextSummary = {
  page_kind: string;
  primary_entity?: Record<string, unknown>;
  secondary_entities?: Array<Record<string, unknown>>;
  visible_sections?: Array<Record<string, unknown>>;
  top_semantic_actions?: Array<Record<string, unknown>>;
  selected_rows?: Array<Record<string, unknown>>;
  active_dialog?: Record<string, unknown>;
  has_modal_or_drawer?: boolean;
  summary?: string | null;
};

export type AgentBrowserContext = {
  pathname: string;
  origin?: string | null;
  title?: string | null;
  query: Record<string, string>;
  asset_id?: string | null;
  finding_id?: string | null;
  task_id?: string | null;
  selected_entities?: Array<Record<string, unknown>>;
  open_panels?: Array<Record<string, unknown>>;
  forms?: Array<Record<string, unknown>>;
  visible_actions?: AgentBrowserVisibleAction[];
  semantic_page_context?: AgentSemanticPageContext;
  semantic_actions?: AgentBrowserSemanticAction[];
  semantic_forms?: AgentBrowserSemanticForm[];
  summary_json?: AgentBrowserContextSummary;
  dom_snapshot?: AgentBrowserDOMNode[];
};

export type AgentUIAction = {
  action_id: string;
  action_type: AgentUIActionType;
  semantic_action_id?: string | null;
  target_node_id?: string | null;
  selector?: string | null;
  text_contains?: string | null;
  label_contains?: string | null;
  href?: string | null;
  value?: string | null;
  field_name?: string | null;
  option_label?: string | null;
  wait_ms?: number | null;
  rationale?: string | null;
  expected_outcome?: string | null;
  expected_page_kind?: string | null;
  expected_section?: string | null;
  expected_entity?: Record<string, unknown>;
  retryable?: boolean | null;
};

export type AgentUIActionResult = {
  action_id: string;
  action_type: AgentUIActionType;
  ok: boolean;
  semantic_action_id?: string | null;
  target_node_id?: string | null;
  resolved_node_id?: string | null;
  message?: string | null;
  resolved_target?: Record<string, unknown>;
  attempt_count?: number | null;
  detail_json?: Record<string, unknown>;
};

export type AgentMessageCreateRequest = {
  client_message_id?: string | null;
  content: string;
  page_context: AgentPageContext;
  browser_context: AgentBrowserContext;
};

export type AgentUIStepRequest = {
  step_request_id?: string | null;
  browser_context: AgentBrowserContext;
  ui_action_results: AgentUIActionResult[];
};

export type AgentApprovalRequest = {
  note?: string | null;
};

export type AgentApprovalResponse = {
  session_id: string;
  task_id: string;
  status: "pending" | "running" | "retry" | "success" | "failure" | "canceled";
};

export type AgentStreamClientType = "hello" | "message" | "ui_step" | "approve_plan" | "ping";

export type AgentStreamServerType =
  | "session_snapshot"
  | "turn_started"
  | "action_update"
  | "assistant_message_start"
  | "assistant_message_delta"
  | "assistant_message_done"
  | "ui_actions_requested"
  | "plan_pending"
  | "task_update"
  | "error"
  | "turn_done";

export type AgentStreamClientEnvelope = {
  type: AgentStreamClientType;
  client_message_id?: string | null;
  step_request_id?: string | null;
  content?: string | null;
  note?: string | null;
  page_context?: AgentPageContext;
  browser_context?: AgentBrowserContext;
  ui_action_results?: AgentUIActionResult[];
};

export type AgentSessionSnapshotEvent = {
  type: "session_snapshot";
  session: AgentSession;
};

export type AgentStateEvent = {
  type: "agent_state";
  agent_state_json: Record<string, unknown>;
  turn_id?: string | null;
};

export type AgentTurnStartedEvent = {
  type: "turn_started";
  turn_id: string;
  phase: "message" | "ui_step" | "approve";
  client_message_id?: string | null;
};

export type AgentAssistantMessageStartEvent = {
  type: "assistant_message_start";
  turn_id: string;
  message_type: AgentMessageType;
};

export type AgentAssistantDeltaEvent = {
  type: "assistant_message_delta";
  turn_id: string;
  delta: string;
};

export type AgentAssistantMessageDoneEvent = {
  type: "assistant_message_done";
  turn_id: string;
  message: AgentMessage;
};

export type AgentActionUpdateEvent = {
  type: "action_update";
  turn_id: string;
  content: string;
  trace?: Record<string, unknown>;
  message?: AgentMessage | null;
};

export type AgentUIActionsRequestedEvent = {
  type: "ui_actions_requested";
  turn_id: string;
  ui_actions: AgentUIAction[];
  content?: string | null;
};

export type AgentPlanPendingEvent = {
  type: "plan_pending";
  turn_id: string;
  message: AgentMessage;
  pending_plan_json: Record<string, unknown>;
};

export type AgentTaskUpdateEvent = {
  type: "task_update";
  task_id: string;
  status: AgentApprovalResponse["status"] | string;
  progress?: number | null;
  message?: string | null;
};

export type AgentErrorEvent = {
  type: "error";
  detail: string;
  turn_id?: string | null;
  status_code?: number | null;
  message?: AgentMessage | null;
};

export type AgentTurnDoneEvent = {
  type: "turn_done";
  turn_id: string;
  status: string;
};

export type AgentStreamServerEnvelope =
  | AgentSessionSnapshotEvent
  | AgentStateEvent
  | AgentTurnStartedEvent
  | AgentAssistantMessageStartEvent
  | AgentAssistantDeltaEvent
  | AgentAssistantMessageDoneEvent
  | AgentActionUpdateEvent
  | AgentUIActionsRequestedEvent
  | AgentPlanPendingEvent
  | AgentTaskUpdateEvent
  | AgentErrorEvent
  | AgentTurnDoneEvent;
