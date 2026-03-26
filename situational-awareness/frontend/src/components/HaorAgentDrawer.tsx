"use client";

import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Alert, Badge, Button, Checkbox, Input, Modal, Radio, message } from "antd";

import { getStoredToken, type StoredUserRole } from "@/lib/auth";
import { collectBrowserContext, executeUIActions } from "@/lib/haor-browser-runtime";
import { formatDateTime, getTaskEventTypeLabel, getTaskTypeLabel, localizeTaskMessage } from "@/lib/ui-text";
import {
  approveHaorSession,
  buildHaorSessionStreamUrl,
  getHaorGoal,
  getHaorSessionSummary,
  getTask,
  getTaskEvents,
  interruptHaorSession,
  postHaorMessage,
  postHaorStep,
  recoverHaorSession,
  resetHaorSession,
  setAssetCredential,
  setAssetCredentialBatch,
  verifyAssetCredential,
} from "@/services/api";
import type {
  AgentActionUpdateEvent,
  AgentAssistantDeltaEvent,
  AgentBrowserContext,
  AgentErrorEvent,
  AgentGoal,
  AgentMessage,
  AgentPendingSecureInput,
  AgentPageContext,
  AgentPlanPendingEvent,
  AgentProposedAction,
  AgentRuntimeSnapshot,
  AgentSession,
  AgentSessionSummary,
  AgentState,
  AgentStreamServerEnvelope,
  AgentTaskUpdateEvent,
  AgentTurnDoneEvent,
  AgentTurnStartedEvent,
  AgentUIAction,
  AgentUIActionResult,
  AgentUIActionsRequestedEvent,
} from "@/types/agent";
import type {
  AssetCredentialBatchResult,
  AssetCredentialUpsertRequest,
  CredentialAuthType,
} from "@/types/collection";
import type { TaskEvent, TaskRunDetail } from "@/types/task";

type HaorAgentDrawerProps = {
  userRole: StoredUserRole;
  initialOpen?: boolean;
};

type StreamFeedItem = {
  id: string;
  badge?: string | null;
  content: string;
  role: "assistant";
  sender: string;
  time: string;
  tone?: "action" | "error" | "plan" | "task";
};

type DraftAssistantMessage = {
  turnId: string;
  content: string;
  messageType: AgentMessage["message_type"];
};

type PendingUserMessage = {
  clientMessageId: string;
  content: string;
  createdAt: string;
  status: "sending" | "failed";
};

type AssistantPlaceholder = {
  key: string;
  badge?: string | null;
  content: string;
  tone?: "action" | "error" | "plan" | "task";
};

type PendingMessageTurnState = {
  clientMessageId: string;
  content: string;
  pageContext: AgentPageContext;
  browserContext: AgentBrowserContext;
  fallbackUsed: boolean;
  acked: boolean;
  timerId: number | null;
};

type PendingUiStepState = {
  stepRequestId: string;
  browserContext: AgentBrowserContext;
  uiActionResults: AgentUIActionResult[];
  fallbackUsed: boolean;
  acked: boolean;
  timerId: number | null;
};

type GoalProgressBlocker =
  | string
  | {
      blocker_code?: string;
      blocker_message?: string;
      recommended_next_step?: string;
    };

type GoalProgressSummary = {
  summary?: string;
  stage?: string;
  blockers?: GoalProgressBlocker[];
  last_result?: string;
  next_step?: string;
  active_skill_id?: string;
  active_skill_title?: string;
  watch_task_id?: string;
};

type SecureInputResultItem = {
  asset_id: string;
  saved: boolean;
  verified: boolean;
  effective_privilege?: string | null;
  error_summary?: string | null;
};

const MESSAGE_TURN_ACK_TIMEOUT_MS = 8_000;
const UI_STEP_ACK_TIMEOUT_MS = 8_000;
const UI_STEP_FAIL_OPEN_TEXT = "上次页面动作未收到继续结果，已结束等待。你可以继续提问、重试，或新开会话。";
const HAOR_SUMMARY_POLL_INTERVAL_MS = 15_000;
const EMPTY_HAOR_SUMMARY: AgentSessionSummary = {
  has_attention: false,
  attention_kind: "none",
  session_status: null,
  runtime_phase: "idle",
  input_state: "enabled",
  input_block_reason: "none",
  current_goal_id: null,
  current_goal_title: null,
  active_skill_title: null,
  last_task_id: null,
  updated_at: null,
};

const EMPTY_RUNTIME_SNAPSHOT: AgentRuntimeSnapshot = {
  phase: "idle",
  input_state: "enabled",
  input_block_reason: "none",
  current_turn_id: null,
  watch_task_id: null,
  active_skill_id: null,
  active_skill_title: null,
  blocker_summary: null,
  recoverable_error: null,
  can_interrupt: false,
  can_resume: false,
};

const EMPTY_SECURE_INPUT: AgentPendingSecureInput = {
  kind: "",
  mode: "single_asset",
  asset_ids: [],
  asset_labels: [],
  auth_type: null,
  username: null,
  resume_goal_id: null,
  resume_action: null,
  auto_verify: true,
  auto_resume: true,
  blocker_summary: null,
};

type ChatBubbleProps = {
  actions?: ReactNode;
  badge?: string | null;
  content: string;
  metaNote?: string | null;
  role: "assistant" | "user";
  sender: string;
  stateTone?: "failed" | "pending";
  time: string;
  tone?: "action" | "error" | "plan" | "task";
};

function ChatBubble({ actions, badge, content, metaNote, role, sender, stateTone, time, tone }: ChatBubbleProps) {
  const bubbleClasses = ["haor-chat-bubble", `haor-chat-bubble-${role}`];
  if (role === "assistant" && tone) {
    bubbleClasses.push(`haor-chat-bubble-${tone}`);
  }
  if (stateTone) {
    bubbleClasses.push(`haor-chat-bubble-is-${stateTone}`);
  }

  return (
    <article className={`haor-chat-row haor-chat-row-${role}`}>
      <div className={`haor-chat-avatar haor-chat-avatar-${role}`}>{role === "user" ? "你" : "H"}</div>
      <div className="haor-chat-stack">
        <div className="haor-chat-sender">{sender}</div>
        <div className={bubbleClasses.join(" ")}>
          {badge ? <span className="haor-chat-badge">{badge}</span> : null}
          <pre className="haor-chat-bubble-body">{content}</pre>
          {actions ? <div className="haor-chat-bubble-actions">{actions}</div> : null}
        </div>
        <div className="haor-chat-bubble-meta">
          <span>{time}</span>
          {metaNote ? (
            <span className={`haor-chat-bubble-meta-note ${stateTone ? `haor-chat-bubble-meta-note-${stateTone}` : ""}`}>
              {metaNote}
            </span>
          ) : null}
        </div>
      </div>
    </article>
  );
}

function normalizeStatus(status: string | null | undefined) {
  return String(status || "").trim().toLowerCase();
}

function isUiFeedbackPhase(phase: string | null | undefined) {
  const normalized = normalizeStatus(phase);
  return normalized === "awaiting_ui_feedback" || normalized === "resolving_ui_feedback";
}

function buildPageContext(pathname: string, searchParams: URLSearchParams | null): AgentPageContext {
  const query: Record<string, string> = {};
  if (searchParams) {
    searchParams.forEach((value, key) => {
      query[key] = value;
    });
  }

  const segments = pathname.split("/").filter(Boolean);
  let assetId = query.assetId || query.asset_id || "";
  let findingId = query.findingId || query.finding_id || "";
  let taskId = query.taskId || query.task_id || "";

  if (!assetId && segments[0] === "assets" && segments[1]) {
    assetId = segments[1];
  }
  if (!assetId && segments[0] === "remediation" && segments[1]) {
    assetId = segments[1];
  }
  if (!taskId && segments[0] === "tasks" && segments[1]) {
    taskId = segments[1];
  }

  return {
    pathname,
    query,
    asset_id: assetId || null,
    finding_id: findingId || null,
    task_id: taskId || null,
  };
}

function buildPageContextFromLocation(): AgentPageContext {
  if (typeof window === "undefined") {
    return { pathname: "/", query: {} };
  }
  return buildPageContext(window.location.pathname || "/", new URLSearchParams(window.location.search));
}

function statusLabel(status: string | null | undefined): string {
  switch (normalizeStatus(status)) {
    case "waiting_approval":
      return "待确认";
    case "running":
      return "执行中";
    case "completed":
    case "success":
      return "已完成";
    case "failed":
    case "failure":
      return "失败";
    case "canceled":
      return "已取消";
    default:
      return "会话中";
  }
}

function toProposedActions(session: AgentSession | null): AgentProposedAction[] {
  const raw = session?.pending_plan_json?.proposed_write_actions;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((item): item is AgentProposedAction => Boolean(item && typeof item === "object" && "action_type" in item)) as AgentProposedAction[];
}

function toPendingUiActions(session: AgentSession | null): AgentUIAction[] {
  const raw = session?.browser_runtime_json?.pending_ui_actions;
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.filter((item): item is AgentUIAction => Boolean(item && typeof item === "object" && "action_type" in item)) as AgentUIAction[];
}

function deriveSessionSummary(session: AgentSession | null): AgentSessionSummary {
  if (!session) {
    return EMPTY_HAOR_SUMMARY;
  }
  const sessionStatus = normalizeStatus(session.status);
  let attentionKind: AgentSessionSummary["attention_kind"] = "none";
  if (sessionStatus === "waiting_approval") {
    attentionKind = "waiting_approval";
  } else if (toPendingUiActions(session).length > 0) {
    attentionKind = "pending_ui_action";
  } else if (sessionStatus === "running" && (session.runtime_snapshot?.watch_task_id || session.last_task_id)) {
    attentionKind = "running_task";
  }
  return {
    has_attention: attentionKind !== "none",
    attention_kind: attentionKind,
    session_status: session.status,
    runtime_phase: session.runtime_snapshot?.phase || "idle",
    input_state: session.runtime_snapshot?.input_state || "enabled",
    input_block_reason: session.runtime_snapshot?.input_block_reason || "none",
    current_goal_id: session.current_goal_id,
    current_goal_title: session.current_goal_title,
    active_skill_title: session.runtime_snapshot?.active_skill_title || null,
    last_task_id: session.last_task_id,
    updated_at: session.updated_at,
  };
}

function toRuntimeSnapshot(session: AgentSession | null): AgentRuntimeSnapshot {
  if (!session?.runtime_snapshot || typeof session.runtime_snapshot !== "object") {
    return EMPTY_RUNTIME_SNAPSHOT;
  }
  return {
    ...EMPTY_RUNTIME_SNAPSHOT,
    ...session.runtime_snapshot,
    recoverable_error:
      session.runtime_snapshot.recoverable_error && typeof session.runtime_snapshot.recoverable_error === "object"
        ? session.runtime_snapshot.recoverable_error
        : null,
  };
}

function toBrowserRuntime(session: AgentSession | null): Record<string, unknown> {
  return session?.browser_runtime_json && typeof session.browser_runtime_json === "object" ? session.browser_runtime_json : {};
}

function toPendingSecureInput(session: AgentSession | null): AgentPendingSecureInput {
  const runtime = toBrowserRuntime(session);
  const raw = runtime.pending_secure_input;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return EMPTY_SECURE_INPUT;
  }
  const record = raw as Record<string, unknown>;
  const assetIds = Array.isArray(record.asset_ids)
    ? record.asset_ids.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
  const assetLabels = Array.isArray(record.asset_labels)
    ? record.asset_labels.filter((item): item is string => typeof item === "string")
    : [];
  return {
    kind: typeof record.kind === "string" ? record.kind : "",
    mode: typeof record.mode === "string" ? record.mode : (assetIds.length > 1 ? "batch_choice" : "single_asset"),
    asset_ids: assetIds,
    asset_labels: assetIds.map((assetId, index) => {
      const label = assetLabels[index];
      return label && label.trim() ? label.trim() : `资产 ${assetId}`;
    }),
    auth_type: typeof record.auth_type === "string" ? record.auth_type : null,
    username: typeof record.username === "string" ? record.username : null,
    resume_goal_id: typeof record.resume_goal_id === "string" ? record.resume_goal_id : null,
    resume_action: record.resume_action && typeof record.resume_action === "object" && !Array.isArray(record.resume_action)
      ? (record.resume_action as Record<string, unknown>)
      : null,
    auto_verify: record.auto_verify !== false,
    auto_resume: record.auto_resume !== false,
    blocker_summary: typeof record.blocker_summary === "string" ? record.blocker_summary : null,
  };
}

function toAgentState(session: AgentSession | null): AgentState {
  return session?.agent_state_json && typeof session.agent_state_json === "object" ? session.agent_state_json : {};
}

function toRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function firstNonEmptyString(values: Array<unknown>): string {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "";
}

function summarizeAgentEvidence(state: AgentState): string {
  const explanation = toRecord(state.explanation);
  const evidence = Array.isArray(explanation.evidence) ? explanation.evidence : [];
  const labels = evidence
    .map((item) => {
      const record = toRecord(item);
      const toolName = typeof record.tool_name === "string" ? record.tool_name.trim() : "";
      const summary = typeof record.summary === "string" ? record.summary.trim() : "";
      return firstNonEmptyString([toolName, summary]);
    })
    .filter(Boolean);
  return labels.slice(0, 3).join(" / ");
}

function buildAgentStatePanel(state: AgentState, task: TaskRunDetail | null): { target: string; stage: string; evidence: string; next: string } {
  const focus = toRecord(state.focus);
  const execution = toRecord(state.execution);
  const explanation = toRecord(state.explanation);
  const watch = toRecord(state.watch);

  const target = firstNonEmptyString([
    focus.summary,
    toRecord(focus.resolved).summary,
    task?.id ? `任务 ${task.id}` : "",
    "当前会话",
  ]);

  const stage = firstNonEmptyString([
    execution.step_label,
    execution.stage,
    typeof task?.status === "string" ? statusLabel(task.status) : "",
    "空闲",
  ]);

  const evidence = firstNonEmptyString([
    explanation.reason,
    typeof explanation.decision_summary === "string" ? explanation.decision_summary : "",
    summarizeAgentEvidence(state),
    "暂无额外依据",
  ]);

  const missingSlots = Array.isArray(execution.missing_slots)
    ? execution.missing_slots.filter((item): item is string => typeof item === "string" && item.trim().length > 0)
    : [];
  const next = firstNonEmptyString([
    execution.waiting_for,
    missingSlots.length ? `缺少字段：${missingSlots.join("、")}` : "",
    explanation.next_step,
    Boolean(watch.watching) && typeof watch.primary_task_id === "string" && watch.primary_task_id.trim().length > 0
      ? `正在跟踪任务 ${watch.primary_task_id.trim()}`
      : "",
    typeof explanation.expected_outcome === "string" ? explanation.expected_outcome : "",
    "等待新的输入",
  ]);

  return { target, stage, evidence, next };
}

function goalStatusLabel(status: string | null | undefined): string {
  switch (normalizeStatus(status)) {
    case "active":
      return "进行中";
    case "blocked":
      return "已阻塞";
    case "completed":
      return "已完成";
    case "failed":
      return "失败";
    case "canceled":
      return "已取消";
    default:
      return "未知";
  }
}

function isTerminalTaskStatus(status: string | null | undefined) {
  const normalized = normalizeStatus(status);
  return normalized === "success" || normalized === "failure" || normalized === "canceled";
}

function isActiveTaskStatus(status: string | null | undefined) {
  const normalized = normalizeStatus(status);
  return normalized === "pending" || normalized === "running" || normalized === "retry";
}

function toGoalProgress(goal: AgentGoal | null): GoalProgressSummary {
  if (!goal?.progress_json || typeof goal.progress_json !== "object") {
    return {};
  }
  return goal.progress_json as GoalProgressSummary;
}

function goalBlockerText(blocker: GoalProgressBlocker | undefined): string {
  if (!blocker) {
    return "";
  }
  if (typeof blocker === "string") {
    return blocker;
  }
  return typeof blocker.blocker_message === "string" ? blocker.blocker_message : "";
}

function messageBadgeText(message: AgentMessage): string | null {
  if (message.role === "user") {
    return null;
  }
  switch (String(message.message_type || "").trim().toLowerCase()) {
    case "clarifying":
      return "追问";
    case "plan":
      return "计划";
    case "task_update":
      return "任务";
    case "action_update":
      return "动作";
    case "error":
      return "错误";
    default:
      return null;
  }
}

function messageTone(message: AgentMessage): "action" | "error" | "plan" | "task" | undefined {
  switch (String(message.message_type || "").trim().toLowerCase()) {
    case "plan":
      return "plan";
    case "task_update":
      return "task";
    case "action_update":
      return "action";
    case "error":
      return "error";
    default:
      return undefined;
  }
}

function actionUpdateTrace(event: AgentActionUpdateEvent): Record<string, unknown> | null {
  if (!event.trace || typeof event.trace !== "object" || Array.isArray(event.trace)) {
    return null;
  }
  return event.trace;
}

function isInternalReadToolProgressEvent(event: AgentActionUpdateEvent): boolean {
  if (event.message) {
    return false;
  }
  const trace = actionUpdateTrace(event);
  return Boolean(trace && typeof trace.tool_name === "string");
}

function isSuccessfulInternalReadToolProgressEvent(event: AgentActionUpdateEvent): boolean {
  const trace = actionUpdateTrace(event);
  return isInternalReadToolProgressEvent(event) && trace?.ok === true;
}

function isFailedInternalReadToolProgressEvent(event: AgentActionUpdateEvent): boolean {
  const trace = actionUpdateTrace(event);
  return isInternalReadToolProgressEvent(event) && trace?.ok === false;
}

function planTargetLabel(action: AgentProposedAction): string | null {
  const params = action.params || {};
  const assetId = typeof params.asset_id === "string" ? params.asset_id : null;
  const findingId = typeof params.finding_id === "string" ? params.finding_id : null;
  const taskId = typeof params.task_id === "string" ? params.task_id : null;
  const sessionId = typeof params.session_id === "string" ? params.session_id : null;
  const cidr = typeof params.cidr === "string" ? params.cidr : null;

  if (findingId && assetId) {
    return `风险 ${findingId} / 资产 ${assetId}`;
  }
  if (findingId) {
    return `风险 ${findingId}`;
  }
  if (assetId) {
    return `资产 ${assetId}`;
  }
  if (taskId) {
    return `任务 ${taskId}`;
  }
  if (sessionId) {
    return `修复会话 ${sessionId}`;
  }
  if (cidr) {
    return `网段 ${cidr}`;
  }
  return null;
}

function isMockSession(session: AgentSession | null): boolean {
  const messages = Array.isArray(session?.messages) ? session.messages : [];
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const item = messages[index];
    if (item?.role !== "assistant") {
      continue;
    }
    if (Object.prototype.hasOwnProperty.call(item.payload_json || {}, "mock_mode")) {
      return item.payload_json?.mock_mode === true;
    }
  }
  return false;
}

function joinSections(parts: Array<string | null | undefined>) {
  return parts.map((item) => String(item || "").trim()).filter(Boolean).join("\n\n");
}

function createClientId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `haor-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

function buildSecureStepBrowserContext(context: AgentPageContext): AgentBrowserContext {
  if (typeof window === "undefined") {
    return {
      pathname: context.pathname,
      query: context.query,
      asset_id: context.asset_id || null,
      finding_id: context.finding_id || null,
      task_id: context.task_id || null,
    };
  }
  return {
    pathname: context.pathname,
    origin: window.location.origin,
    title: document.title || "",
    query: context.query,
    asset_id: context.asset_id || null,
    finding_id: context.finding_id || null,
    task_id: context.task_id || null,
    selected_entities: [],
    open_panels: [],
    forms: [],
    visible_actions: [],
    semantic_page_context: {
      page_kind: "secure_input",
      summary: "haor ssh secure input",
      primary_entity: context.asset_id ? { kind: "asset", id: context.asset_id } : {},
      selected_rows: [],
    },
    semantic_actions: [],
    semantic_forms: [],
    summary_json: {
      page_kind: "secure_input",
      primary_entity: context.asset_id ? { kind: "asset", id: context.asset_id } : {},
      selected_rows: [],
      active_dialog: {},
      has_modal_or_drawer: false,
      summary: "haor ssh secure input",
    },
    dom_snapshot: [],
  };
}

function buildCredentialPayload(
  authType: CredentialAuthType,
  username: string,
  password: string,
  privateKey: string,
  sudoPassword: string,
  adminAuthorized: boolean,
): AssetCredentialUpsertRequest {
  return {
    auth_type: authType,
    username: username.trim(),
    password: authType === "password" ? password : undefined,
    private_key: authType === "key" ? privateKey : undefined,
    sudo_password: username.trim().toLowerCase() === "root" ? undefined : sudoPassword,
    admin_authorized: adminAuthorized,
  };
}

function messageClientMessageId(message: AgentMessage): string | null {
  const value = message.payload_json?.client_message_id;
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function reconcilePendingUserMessages(pendingMessages: PendingUserMessage[], messages: AgentMessage[]): PendingUserMessage[] {
  if (!pendingMessages.length || !messages.length) {
    return pendingMessages;
  }
  const persistedIds = new Set(
    messages
      .filter((item) => item.role === "user")
      .map((item) => messageClientMessageId(item))
      .filter((value): value is string => Boolean(value)),
  );
  return pendingMessages.filter((item) => !persistedIds.has(item.clientMessageId));
}

function markPendingUserMessagesFailed(pendingMessages: PendingUserMessage[]): PendingUserMessage[] {
  return pendingMessages.map((item) => (item.status === "failed" ? item : { ...item, status: "failed" }));
}

function upsertSessionMessage(session: AgentSession | null, nextMessage: AgentMessage): AgentSession | null {
  if (!session) {
    return null;
  }
  const existing = Array.isArray(session.messages) ? session.messages : [];
  const nextMessages = [...existing];
  const index = nextMessages.findIndex((item) => item.id === nextMessage.id);
  if (index >= 0) {
    nextMessages[index] = nextMessage;
  } else {
    nextMessages.push(nextMessage);
  }
  nextMessages.sort((left, right) => new Date(left.created_at).getTime() - new Date(right.created_at).getTime());
  return { ...session, messages: nextMessages, updated_at: nextMessage.created_at || session.updated_at };
}

function isRemediationAutoSubmitAction(action: AgentProposedAction): boolean {
  return action.action_type === "create_or_resume_remediation_session" && action.params?.submit_if_ready === true;
}

function hasRemediationAutoSubmitPlan(actions: AgentProposedAction[]): boolean {
  return actions.some((action) => isRemediationAutoSubmitAction(action));
}

function buildPendingPlanDetails(actions: AgentProposedAction[]) {
  if (!actions.length) {
    return "";
  }

  const lines = ["待执行动作："];
  for (const [index, action] of actions.entries()) {
    lines.push(`${index + 1}. ${action.title}`);
    lines.push(`动作类型：${action.action_type}`);
    const target = planTargetLabel(action);
    if (target) {
      lines.push(`目标：${target}`);
    }
    if (action.reason) {
      lines.push(`原因：${action.reason}`);
    }
    if (isRemediationAutoSubmitAction(action)) {
      lines.push("执行方式：满足条件时直接提交自动修复。");
      lines.push("条件不足时：仅创建修复会话，并在聊天里说明阻塞原因和下一步。");
    }
    const paramsText = Object.entries(action.params || {})
      .filter(([key]) => key !== "submit_if_ready")
      .map(([key, value]) => `${key}=${String(value)}`)
      .join("，");
    if (paramsText) {
      lines.push(`参数：${paramsText}`);
    }
    if (index < actions.length - 1) {
      lines.push("");
    }
  }
  return lines.join("\n");
}

function buildTaskDigest(task: TaskRunDetail, taskEvents: TaskEvent[]) {
  const lines = [
    `${getTaskTypeLabel(task.task_type)} · ${statusLabel(task.status)}`,
    `进度：${task.progress}%`,
  ];
  const taskMessage = localizeTaskMessage(task.message) || "";
  if (taskMessage) {
    lines.push(`当前：${taskMessage}`);
  }
  const recentEvents = taskEvents.slice(-3);
  if (recentEvents.length) {
    lines.push("");
    lines.push("最近事件：");
    for (const item of recentEvents) {
      lines.push(`- ${getTaskEventTypeLabel(item.event_type)}：${localizeTaskMessage(item.message) || item.stage_name || item.stage_code || "-"}`);
    }
  }
  return lines.join("\n");
}

function formatChatTime(value: string | null | undefined): string {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return formatDateTime(value);
  }
  const now = new Date();
  const sameDay = now.toDateString() === date.toDateString();
  if (sameDay) {
    return date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" });
  }
  return date.toLocaleString("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function HaorAgentDrawer({ userRole, initialOpen = false }: HaorAgentDrawerProps) {
  const router = useRouter();
  const pathname = usePathname() || "/";
  const searchParams = useSearchParams();
  const isAdmin = userRole === "admin";

  const feedViewportRef = useRef<HTMLDivElement | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const sessionRef = useRef<AgentSession | null>(null);
  const taskRef = useRef<TaskRunDetail | null>(null);
  const activeTurnIdRef = useRef<string | null>(null);
  const ignoredTurnIdsRef = useRef<Set<string>>(new Set());
  const ignoredClientMessageIdsRef = useRef<Set<string>>(new Set());
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const pendingMessageTurnRef = useRef<PendingMessageTurnState | null>(null);
  const pendingUiRequestRef = useRef<{ turnId: string; uiActions: AgentUIAction[]; content?: string | null } | null>(null);
  const pendingUiStepRef = useRef<PendingUiStepState | null>(null);
  const shouldReconnectRef = useRef(false);
  const turnPhaseRef = useRef<Record<string, "message" | "ui_step" | "approve">>({});

  const [open, setOpen] = useState(initialOpen);
  const [session, setSession] = useState<AgentSession | null>(null);
  const [summary, setSummary] = useState<AgentSessionSummary>(EMPTY_HAOR_SUMMARY);
  const [currentGoal, setCurrentGoal] = useState<AgentGoal | null>(null);
  const [task, setTask] = useState<TaskRunDetail | null>(null);
  const [taskEvents, setTaskEvents] = useState<TaskEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [stepping, setStepping] = useState(false);
  const [approving, setApproving] = useState(false);
  const [interrupting, setInterrupting] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [inputValue, setInputValue] = useState("");
  const [errorText, setErrorText] = useState<string | null>(null);
  const [streamError, setStreamError] = useState<string | null>(null);
  const [connectionState, setConnectionState] = useState<"disconnected" | "connecting" | "connected">("disconnected");
  const [activeTurnId, setActiveTurnId] = useState<string | null>(null);
  const [draftAssistantMessage, setDraftAssistantMessage] = useState<DraftAssistantMessage | null>(null);
  const [assistantPlaceholder, setAssistantPlaceholder] = useState<AssistantPlaceholder | null>(null);
  const [pendingUserMessages, setPendingUserMessages] = useState<PendingUserMessage[]>([]);
  const [streamFeed, setStreamFeed] = useState<StreamFeedItem[]>([]);
  const [pendingUiRequest, setPendingUiRequest] = useState<{ turnId: string; uiActions: AgentUIAction[]; content?: string | null } | null>(null);
  const [sessionInitialized, setSessionInitialized] = useState(false);
  const [secureSubmitting, setSecureSubmitting] = useState(false);
  const [secureAuthType, setSecureAuthType] = useState<CredentialAuthType>("password");
  const [secureUsername, setSecureUsername] = useState("");
  const [securePassword, setSecurePassword] = useState("");
  const [securePrivateKey, setSecurePrivateKey] = useState("");
  const [secureSudoPassword, setSecureSudoPassword] = useState("");
  const [secureAuthorized, setSecureAuthorized] = useState(false);
  const [secureBatchMode, setSecureBatchMode] = useState<"same_credential_batch" | "per_asset_guided" | "">("");
  const [secureGuidedIndex, setSecureGuidedIndex] = useState(0);
  const [secureGuidedResults, setSecureGuidedResults] = useState<SecureInputResultItem[]>([]);
  const [secureErrorText, setSecureErrorText] = useState<string | null>(null);

  const pageContext = useMemo(() => buildPageContext(pathname, searchParams), [pathname, searchParams]);
  const runtimeSnapshot = useMemo(() => toRuntimeSnapshot(session), [session]);
  const browserRuntime = useMemo(() => toBrowserRuntime(session), [session]);
  const pendingSecureInput = useMemo(() => toPendingSecureInput(session), [session]);
  const agentState = useMemo(() => toAgentState(session), [session]);
  const sessionSummary = useMemo(() => deriveSessionSummary(session), [session]);
  const proposedActions = useMemo(() => toProposedActions(session), [session]);
  const remediationAutoSubmitPlan = useMemo(() => hasRemediationAutoSubmitPlan(proposedActions), [proposedActions]);
  const visiblePendingUserMessages = useMemo(
    () => reconcilePendingUserMessages(pendingUserMessages, session?.messages || []),
    [pendingUserMessages, session?.messages],
  );
  const sessionPendingUiActions = useMemo(() => toPendingUiActions(session), [session]);
  const pendingUiActions = useMemo(
    () => (pendingUiRequest?.uiActions?.length ? pendingUiRequest.uiActions : sessionPendingUiActions),
    [pendingUiRequest, sessionPendingUiActions],
  );
  const pendingUiKey = pendingUiActions.map((item) => item.action_id).join("|");
  const mockMode = isMockSession(session);
  const isRunningSession = normalizeStatus(session?.status) === "running";
  const sessionPhase = normalizeStatus(runtimeSnapshot.phase);
  const snapshotAwaitingMessage = sessionPhase === "awaiting_agent_reply";
  const snapshotUiInProgress = sessionPhase === "awaiting_ui_feedback" || sessionPhase === "resolving_ui_feedback" || sessionPendingUiActions.length > 0;
  const runtimeInputLocked = normalizeStatus(runtimeSnapshot.input_state) === "locked";
  const currentWatchTaskId = runtimeSnapshot.watch_task_id || session?.last_task_id || null;
  const rawRunningSession = isRunningSession && Boolean(currentWatchTaskId);
  const linkedTaskLoaded = Boolean(task && currentWatchTaskId && task.id === currentWatchTaskId);
  const confirmedRunningTask = rawRunningSession && linkedTaskLoaded && isActiveTaskStatus(task?.status);
  const runningStateResolving = rawRunningSession && !confirmedRunningTask;
  const showInterrupt = runtimeSnapshot.can_interrupt;
  const hasAttention = open ? (session ? sessionSummary.has_attention : summary.has_attention) : summary.has_attention;
  const composerLocked = runtimeInputLocked || sending || approving || interrupting || resetting;
  const sendDisabled = composerLocked;
  const resetDisabled = resetting || interrupting;
  const approvalActionLabel = remediationAutoSubmitPlan ? "确认并自动修复" : "确认执行";
  const approvalBlockedText = remediationAutoSubmitPlan ? "当前账号不是管理员，不能确认自动修复。" : "当前账号不是管理员，不能确认执行。";
  const currentGoalTitle = currentGoal?.title || session?.current_goal_title || summary.current_goal_title || "当前未绑定目标";
  const agentStatePanel = useMemo(() => buildAgentStatePanel(agentState, task), [agentState, task]);
  const currentGoalProgress = useMemo(() => toGoalProgress(currentGoal), [currentGoal]);
  const currentGoalBlockers = useMemo(
    () => (Array.isArray(currentGoalProgress.blockers) ? currentGoalProgress.blockers : []),
    [currentGoalProgress],
  );
  const sidebarStageText = firstNonEmptyString([
    typeof currentGoalProgress.stage === "string" ? currentGoalProgress.stage : "",
    agentStatePanel.stage,
    runtimeSnapshot.active_skill_title || "",
    "空闲",
  ]);
  const sidebarBlockerText = firstNonEmptyString([
    runtimeSnapshot.blocker_summary,
    goalBlockerText(currentGoalBlockers[0]),
    runtimeSnapshot.recoverable_error?.message || "",
    "当前无阻塞",
  ]);
  const sidebarNextStepText = firstNonEmptyString([
    typeof currentGoalProgress.next_step === "string" ? currentGoalProgress.next_step : "",
    agentStatePanel.next,
    "等待新的输入",
  ]);
  const sidebarRecentTaskText = firstNonEmptyString([
    currentWatchTaskId ? `任务 ${currentWatchTaskId}` : "",
    task?.id ? `任务 ${task.id}` : "",
    "当前无任务跟踪",
  ]);
  const sidebarUpdatedText = currentGoal?.updated_at
    ? formatDateTime(currentGoal.updated_at)
    : session?.updated_at
      ? formatDateTime(session.updated_at)
      : "等待新的会话更新";
  const secureInputVisible = open && pendingSecureInput.kind === "ssh_credential" && pendingSecureInput.asset_ids.length > 0;
  const secureAssetCount = pendingSecureInput.asset_ids.length;
  const secureCurrentAssetId = secureInputVisible && secureBatchMode === "per_asset_guided"
    ? pendingSecureInput.asset_ids[Math.min(secureGuidedIndex, Math.max(0, secureAssetCount - 1))]
    : (pendingSecureInput.asset_ids[0] || "");
  const secureCurrentAssetLabel = secureInputVisible && secureBatchMode === "per_asset_guided"
    ? pendingSecureInput.asset_labels[Math.min(secureGuidedIndex, Math.max(0, secureAssetCount - 1))] || secureCurrentAssetId
    : (pendingSecureInput.asset_labels[0] || secureCurrentAssetId);

  useEffect(() => {
    sessionRef.current = session;
  }, [session]);

  useEffect(() => {
    if (!session) {
      return;
    }
    setSummary(sessionSummary);
  }, [session, sessionSummary]);

  useEffect(() => {
    taskRef.current = task;
  }, [task]);

  useEffect(() => {
    activeTurnIdRef.current = activeTurnId;
  }, [activeTurnId]);

  useEffect(() => {
    pendingUiRequestRef.current = pendingUiRequest;
  }, [pendingUiRequest]);

  useEffect(() => {
    if (!secureInputVisible) {
      setSecureSubmitting(false);
      setSecurePassword("");
      setSecurePrivateKey("");
      setSecureSudoPassword("");
      setSecureGuidedIndex(0);
      setSecureGuidedResults([]);
      setSecureErrorText(null);
      return;
    }
    setSecureSubmitting(false);
    setSecureAuthType(pendingSecureInput.auth_type === "key" ? "key" : "password");
    setSecureUsername(pendingSecureInput.username || "");
    setSecureAuthorized(false);
    setSecurePassword("");
    setSecurePrivateKey("");
    setSecureSudoPassword("");
    setSecureBatchMode(
      secureAssetCount <= 1
        ? "same_credential_batch"
        : pendingSecureInput.mode === "per_asset_guided" || pendingSecureInput.mode === "same_credential_batch"
          ? pendingSecureInput.mode
          : "",
    );
    setSecureGuidedIndex(0);
    setSecureGuidedResults([]);
    setSecureErrorText(null);
  }, [secureInputVisible, pendingSecureInput, secureAssetCount]);

  useEffect(() => {
    if (!session) {
      return;
    }
    if (runtimeInputLocked) {
      return;
    }
    pendingUiRequestRef.current = null;
    setPendingUiRequest(null);
    resetPendingMessageTurnState();
    resetPendingUiStepState();
    setSending(false);
    setStepping(false);
    if (normalizeStatus(session.status) !== "waiting_approval") {
      setApproving(false);
    }
    setAssistantPlaceholder((current) => {
      if (
        current?.content === "正在继续处理当前请求…"
        || current?.content === "正在生成…"
        || current?.content === "正在提交计划并启动任务…"
      ) {
        return null;
      }
      return current;
    });
  }, [session, runtimeInputLocked]);

  useEffect(() => {
    if (!session?.messages?.length) {
      return;
    }
    setPendingUserMessages((current) => reconcilePendingUserMessages(current, session.messages));
  }, [session?.messages]);

  const pendingPlanMessageId = useMemo(() => {
    if (!proposedActions.length || !session?.messages?.length) {
      return null;
    }
    for (let index = session.messages.length - 1; index >= 0; index -= 1) {
      if (session.messages[index]?.message_type === "plan") {
        return session.messages[index]?.id || null;
      }
    }
    return null;
  }, [proposedActions.length, session?.messages]);

  const pendingPlanDetails = useMemo(() => buildPendingPlanDetails(proposedActions), [proposedActions]);
  const liveTaskDigest = useMemo(() => (task ? buildTaskDigest(task, taskEvents) : ""), [task, taskEvents]);

  const headerStatus = useMemo(() => {
    const waitingApproval = sessionPhase === "waiting_approval" || normalizeStatus(session?.status) === "waiting_approval";
    if (errorText || streamError) {
      return {
        text: errorText || streamError,
        tone: "error" as const,
      };
    }
    if (runtimeSnapshot.recoverable_error?.message) {
      return {
        text: runtimeSnapshot.recoverable_error.retryable
          ? `${runtimeSnapshot.recoverable_error.message}。你可以直接恢复会话，或继续输入新的问题。`
          : runtimeSnapshot.recoverable_error.message,
        tone: runtimeSnapshot.recoverable_error.retryable ? "warning" as const : "error" as const,
      };
    }
    if (connectionState === "connecting") {
      return {
        text: "haor 正在连接流式会话通道，恢复后会继续接收动作和回复。",
        tone: "muted" as const,
      };
    }
    if (snapshotUiInProgress || stepping) {
      return {
        text: "haor 正在执行当前页面动作，并会继续把结果沉淀到聊天记录里。",
        tone: "muted" as const,
      };
    }
    if (sessionPhase === "awaiting_secure_input") {
      return {
        text: "当前正在等待通过安全弹层填写 SSH 敏感信息。保存并验证 SSH 后，Haor 会自动续接原目标；若仍缺 Runner 或其他条件，也会继续明确提示。",
        tone: "warning" as const,
      };
    }
    if (snapshotAwaitingMessage || sending) {
      return {
        text: "haor 正在处理上一轮消息，刷新后也会按当前会话快照继续恢复输入状态。",
        tone: "muted" as const,
      };
    }
    if (confirmedRunningTask) {
      return {
        text: "当前正在跟踪最近任务。你可以继续追问结果；如果要切换新的高风险操作，请先中断当前任务。",
        tone: "warning" as const,
      };
    }
    if (runningStateResolving) {
      return {
        text: "正在校验最近任务状态。同步期间仍可继续追问，或直接恢复会话。",
        tone: "warning" as const,
      };
    }
    if (waitingApproval) {
      return {
        text: remediationAutoSubmitPlan
          ? (
              isAdmin
                ? "已生成待确认修复计划。满足条件时会直接自动修复；条件不足时仅创建修复会话并说明阻塞原因。"
                : "已生成待确认修复计划，但当前账号不是管理员，不能确认自动修复。"
            )
          : (isAdmin ? "已生成待确认计划，确认后才会执行。" : "已生成待确认计划，当前账号无法确认执行。"),
        tone: "warning" as const,
      };
    }
    if (mockMode) {
      return {
        text: "当前处于模拟模式，聊天反馈仅用于演示和联调。",
        tone: "muted" as const,
      };
    }
    return {
      text: "全站聊天助手，可直接提问、追问或下达站内操作意图。",
      tone: "muted" as const,
    };
  }, [
    errorText,
    streamError,
    runtimeSnapshot.recoverable_error,
    connectionState,
    snapshotAwaitingMessage,
    snapshotUiInProgress,
    stepping,
    sending,
    confirmedRunningTask,
    runningStateResolving,
    sessionPhase,
    session?.status,
    isAdmin,
    remediationAutoSubmitPlan,
    mockMode,
  ]);

  const composerHint = runtimeInputLocked
    ? (
        snapshotAwaitingMessage || sending
          ? "haor 正在生成回复…"
          : snapshotUiInProgress || stepping
            ? "haor 正在继续处理当前请求…"
            : sessionPhase === "awaiting_secure_input"
              ? "请先在安全弹层中填写 SSH 敏感信息"
            : sessionPhase === "waiting_approval"
              ? "当前计划等待确认，输入暂时锁定"
              : sessionPhase === "recovering"
                ? "正在恢复会话状态…"
                : "当前输入暂时锁定"
      )
    : confirmedRunningTask
      ? "当前正在跟踪任务；可以继续追问结果或下一步"
      : runningStateResolving
        ? "正在校验最近任务状态；可继续输入，或先恢复会话"
        : "Shift+Enter 换行，Enter 发送";

  const clearPendingMessageTurnTimer = () => {
    const current = pendingMessageTurnRef.current;
    if (!current?.timerId) {
      return;
    }
    window.clearTimeout(current.timerId);
    current.timerId = null;
  };

  const markPendingMessageTurnAcked = (clientMessageId?: string | null) => {
    const current = pendingMessageTurnRef.current;
    if (!current) {
      return false;
    }
    if (clientMessageId && current.clientMessageId !== clientMessageId) {
      return false;
    }
    current.acked = true;
    clearPendingMessageTurnTimer();
    return true;
  };

  const resetPendingMessageTurnState = () => {
    clearPendingMessageTurnTimer();
    pendingMessageTurnRef.current = null;
  };

  const settlePendingMessageTurn = (clientMessageId?: string | null) => {
    const current = pendingMessageTurnRef.current;
    if (!current) {
      return false;
    }
    if (clientMessageId && current.clientMessageId !== clientMessageId) {
      return false;
    }
    markPendingMessageTurnAcked(clientMessageId);
    resetPendingMessageTurnState();
    setSending(false);
    setAssistantPlaceholder((currentPlaceholder) =>
      currentPlaceholder?.content === "正在生成…" ? null : currentPlaceholder,
    );
    return true;
  };

  const syncPendingMessageTurnFromSession = (nextSession: AgentSession | null) => {
    const current = pendingMessageTurnRef.current;
    if (!current || !nextSession) {
      return;
    }
    const nextRuntime = toBrowserRuntime(nextSession);
    const nextPhase = typeof nextRuntime.phase === "string" ? nextRuntime.phase.trim() : "";
    const nextCurrentMessageRequestId =
      typeof nextRuntime.current_message_request_id === "string" ? nextRuntime.current_message_request_id.trim() : "";
    const nextLastMessageRequestId =
      typeof nextRuntime.last_message_request_id === "string" ? nextRuntime.last_message_request_id.trim() : "";
    if (nextCurrentMessageRequestId && nextCurrentMessageRequestId === current.clientMessageId) {
      markPendingMessageTurnAcked(current.clientMessageId);
      setSending(true);
      setAssistantPlaceholder((currentPlaceholder) =>
        currentPlaceholder?.content === "正在继续处理当前请求…"
          ? currentPlaceholder
          : {
              key: current.clientMessageId,
              badge: "生成中",
              content: "正在生成…",
            },
      );
      return;
    }
    if (nextLastMessageRequestId && nextLastMessageRequestId === current.clientMessageId && nextPhase !== "awaiting_agent_reply") {
      settlePendingMessageTurn(current.clientMessageId);
      return;
    }
    if (current.acked && !nextCurrentMessageRequestId) {
      settlePendingMessageTurn(current.clientMessageId);
    }
  };

  const clearPendingUiStepTimer = () => {
    const current = pendingUiStepRef.current;
    if (!current?.timerId) {
      return;
    }
    window.clearTimeout(current.timerId);
    current.timerId = null;
  };

  const markPendingUiStepAcked = (stepRequestId?: string | null) => {
    const current = pendingUiStepRef.current;
    if (!current) {
      return false;
    }
    if (stepRequestId && current.stepRequestId !== stepRequestId) {
      return false;
    }
    current.acked = true;
    clearPendingUiStepTimer();
    return true;
  };

  const resetPendingUiStepState = () => {
    clearPendingUiStepTimer();
    pendingUiStepRef.current = null;
  };

  const settlePendingUiStep = (stepRequestId?: string | null) => {
    const current = pendingUiStepRef.current;
    if (!current) {
      return false;
    }
    if (stepRequestId && current.stepRequestId !== stepRequestId) {
      return false;
    }
    markPendingUiStepAcked(stepRequestId);
    resetPendingUiStepState();
    setStepping(false);
    setAssistantPlaceholder((currentPlaceholder) =>
      currentPlaceholder?.content === "正在继续处理当前请求…" ? null : currentPlaceholder,
    );
    return true;
  };

  const failOpenPendingUiStep = (text = UI_STEP_FAIL_OPEN_TEXT) => {
    resetPendingUiStepState();
    setStepping(false);
    setAssistantPlaceholder(null);
    setErrorText(text);
  };

  const syncPendingUiStepFromSession = (nextSession: AgentSession | null) => {
    if (!nextSession) {
      return;
    }
    const nextRuntime = toBrowserRuntime(nextSession);
    const nextPhase = typeof nextRuntime.phase === "string" ? nextRuntime.phase.trim() : "";
    const nextLastStepRequestId =
      typeof nextRuntime.last_step_request_id === "string" ? nextRuntime.last_step_request_id.trim() : "";
    const nextPendingActions = toPendingUiActions(nextSession);
    const uiStepStillActive = isUiFeedbackPhase(nextPhase) || nextPendingActions.length > 0;
    const current = pendingUiStepRef.current;

    if (!current) {
      if (!uiStepStillActive) {
        setStepping(false);
        setAssistantPlaceholder((currentPlaceholder) =>
          currentPlaceholder?.content === "正在继续处理当前请求…" ? null : currentPlaceholder,
        );
      }
      return;
    }

    if (nextLastStepRequestId && nextLastStepRequestId === current.stepRequestId) {
      settlePendingUiStep(current.stepRequestId);
      return;
    }
    if (current.acked && !uiStepStillActive) {
      settlePendingUiStep(current.stepRequestId);
    }
  };

  const syncBrowserContext = (context: AgentPageContext = pageContext) => {
    if (typeof window === "undefined") {
      return { pathname: context.pathname, query: context.query } as AgentBrowserContext;
    }
    try {
      return collectBrowserContext(context);
    } catch {
      return {
        pathname: context.pathname,
        origin: window.location.origin,
        title: document.title,
        query: context.query,
        asset_id: context.asset_id || null,
        finding_id: context.finding_id || null,
        task_id: context.task_id || null,
      };
    }
  };

  const appendStreamFeed = (
    item: Omit<StreamFeedItem, "time" | "sender" | "role"> & { time?: string; sender?: string; role?: "assistant" },
  ) => {
    const nextItem: StreamFeedItem = {
      sender: item.sender || "haor",
      role: "assistant",
      time: item.time || new Date().toISOString(),
      ...item,
    };
    setStreamFeed((current) => [...current.filter((entry) => entry.id !== nextItem.id), nextItem]);
  };

  const sendStreamFrame = (frame: Record<string, unknown>) => {
    const socket = wsRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return false;
    }
    socket.send(JSON.stringify(frame));
    return true;
  };

  const handleStreamTurnStarted = (event: AgentTurnStartedEvent) => {
    if (
      ignoredTurnIdsRef.current.has(event.turn_id) ||
      (event.client_message_id && ignoredClientMessageIdsRef.current.has(event.client_message_id))
    ) {
      ignoredTurnIdsRef.current.add(event.turn_id);
      return;
    }
    turnPhaseRef.current[event.turn_id] = event.phase;
    setActiveTurnId(event.turn_id);
    if (event.phase === "message") {
      markPendingMessageTurnAcked(event.client_message_id);
      setSending(true);
      setDraftAssistantMessage(null);
      setAssistantPlaceholder({
        key: event.client_message_id || event.turn_id,
        badge: "生成中",
        content: "正在生成…",
      });
    }
    if (event.phase === "ui_step") {
      markPendingUiStepAcked();
      setStepping(true);
      setAssistantPlaceholder({
        key: event.turn_id,
        badge: "处理中",
        content: "正在继续处理当前请求…",
        tone: "action",
      });
    }
    if (event.phase === "approve") {
      setApproving(true);
      setAssistantPlaceholder({
        key: event.turn_id,
        badge: "处理中",
        content: "正在提交计划并启动任务…",
        tone: "action",
      });
    }
  };

  const handleStreamTurnDone = (event: AgentTurnDoneEvent) => {
    if (ignoredTurnIdsRef.current.has(event.turn_id)) {
      ignoredTurnIdsRef.current.delete(event.turn_id);
      return;
    }
    const phase = turnPhaseRef.current[event.turn_id];
    delete turnPhaseRef.current[event.turn_id];
    if (phase === "message") {
      settlePendingMessageTurn();
      setSending(false);
    }
    if (phase === "ui_step") {
      settlePendingUiStep();
      setStepping(false);
    }
    if (phase === "approve") {
      setApproving(false);
    }
    if (activeTurnIdRef.current === event.turn_id) {
      setActiveTurnId(null);
    }
    if (event.status !== "ok") {
      setDraftAssistantMessage((current) => (current?.turnId === event.turn_id ? null : current));
    }
    if (!(phase === "message" && pendingUiRequestRef.current)) {
      setAssistantPlaceholder(null);
    }
  };

  const handleTaskUpdateEvent = (event: AgentTaskUpdateEvent) => {
    if (!event.task_id) {
      return;
    }
    const sessionTaskId = sessionRef.current?.runtime_snapshot?.watch_task_id || sessionRef.current?.last_task_id || null;
    if (sessionTaskId && sessionTaskId !== event.task_id) {
      return;
    }
    if (!sessionTaskId && normalizeStatus(sessionRef.current?.status) !== "running") {
      return;
    }
    const currentTask = taskRef.current;
    setTask((current) => {
      if (!current || current.id !== event.task_id) {
        void loadTask(event.task_id, true);
        return current;
      }
      return {
        ...current,
        status: String(event.status || current.status) as TaskRunDetail["status"],
        progress: typeof event.progress === "number" ? event.progress : current.progress,
        message: typeof event.message === "string" ? event.message : current.message,
        updated_at: new Date().toISOString(),
      };
    });
    if (!currentTask || currentTask.id !== event.task_id) {
      void loadTask(event.task_id, true);
    }
  };

  const handleStreamEvent = (event: AgentStreamServerEnvelope) => {
    switch (event.type) {
      case "session_snapshot": {
        if (sessionRef.current && sessionRef.current.session_id !== event.session.session_id) {
          return;
        }
        syncPendingMessageTurnFromSession(event.session);
        syncPendingUiStepFromSession(event.session);
        if (!activeTurnIdRef.current && !pendingMessageTurnRef.current && !pendingUiStepRef.current) {
          setDraftAssistantMessage(null);
          setAssistantPlaceholder(null);
          setStreamFeed([]);
        }
        setSession(event.session);
        setLoading(false);
        setErrorText(null);
        setStreamError(null);
        {
          const watchTaskId = event.session.runtime_snapshot?.watch_task_id || event.session.last_task_id;
          if (watchTaskId) {
            void loadTask(watchTaskId, true);
          } else {
            setTask(null);
            setTaskEvents([]);
          }
        }
        if (!toPendingUiActions(event.session).length) {
          pendingUiRequestRef.current = null;
          setPendingUiRequest(null);
        }
        return;
      }
      case "agent_state":
        setSession((current) => (current ? { ...current, agent_state_json: event.agent_state_json } : current));
        return;
      case "turn_started":
        handleStreamTurnStarted(event);
        return;
      case "assistant_message_start":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          return;
        }
        settlePendingUiStep();
        setDraftAssistantMessage({ turnId: event.turn_id, content: "", messageType: event.message_type });
        return;
      case "assistant_message_delta":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          return;
        }
        settlePendingUiStep();
        setDraftAssistantMessage((current) => {
          if (!current || current.turnId !== event.turn_id) {
            return { turnId: event.turn_id, content: event.delta, messageType: "text" };
          }
          return { ...current, content: `${current.content}${event.delta}` };
        });
        return;
      case "assistant_message_done":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          ignoredTurnIdsRef.current.delete(event.turn_id);
          return;
        }
        settlePendingMessageTurn();
        settlePendingUiStep();
        setAssistantPlaceholder(null);
        setDraftAssistantMessage((current) => (current?.turnId === event.turn_id ? null : current));
        setSession((current) => upsertSessionMessage(current, event.message));
        return;
      case "action_update":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          return;
        }
        settlePendingUiStep();
        if (event.message) {
          setSession((current) => upsertSessionMessage(current, event.message as AgentMessage));
        } else if (isSuccessfulInternalReadToolProgressEvent(event)) {
          return;
        } else if (isFailedInternalReadToolProgressEvent(event)) {
          appendStreamFeed({
            id: `action-${event.turn_id}-${Date.now()}`,
            badge: "错误",
            content: event.content,
            tone: "error",
          });
        } else {
          appendStreamFeed({
            id: `action-${event.turn_id}-${Date.now()}`,
            badge: "动作",
            content: event.content,
            tone: "action",
          });
        }
        return;
      case "ui_actions_requested":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          return;
        }
        settlePendingMessageTurn();
        settlePendingUiStep();
        pendingUiRequestRef.current = { turnId: event.turn_id, uiActions: event.ui_actions, content: event.content || null };
        setPendingUiRequest({ turnId: event.turn_id, uiActions: event.ui_actions, content: event.content || null });
        setAssistantPlaceholder({
          key: event.turn_id,
          badge: "处理中",
          content: "正在继续处理当前请求…",
          tone: "action",
        });
        return;
      case "plan_pending":
        if (ignoredTurnIdsRef.current.has(event.turn_id)) {
          return;
        }
        settlePendingMessageTurn();
        settlePendingUiStep();
        setAssistantPlaceholder(null);
        setSession((current) => {
          if (!current) {
            return current;
          }
          const nextSession = upsertSessionMessage(current, event.message) || current;
          return {
            ...nextSession,
            status: "waiting_approval",
            pending_plan_json: event.pending_plan_json,
          };
        });
        return;
      case "task_update":
        settlePendingUiStep();
        setAssistantPlaceholder(null);
        handleTaskUpdateEvent(event);
        return;
      case "error":
        if (event.turn_id && ignoredTurnIdsRef.current.has(event.turn_id)) {
          ignoredTurnIdsRef.current.delete(event.turn_id);
          return;
        }
        settlePendingMessageTurn();
        settlePendingUiStep();
        setAssistantPlaceholder(null);
        if (event.message) {
          setSession((current) => upsertSessionMessage(current, event.message as AgentMessage));
        } else {
          appendStreamFeed({
            id: `error-${event.turn_id || "global"}-${Date.now()}`,
            badge: "错误",
            content: event.detail,
            tone: "error",
          });
        }
        setPendingUserMessages((current) => markPendingUserMessagesFailed(current));
        setErrorText(event.detail);
        return;
      case "turn_done":
        handleStreamTurnDone(event);
        return;
      default:
        return;
    }
  };

  const applyMessageTurnResult = (result: AgentSession, clientMessageId: string) => {
    syncPendingMessageTurnFromSession(result);
    syncPendingUiStepFromSession(result);
    setSession(result);
    if (toPendingUiActions(result).length) {
      setAssistantPlaceholder({
        key: clientMessageId,
        badge: "处理中",
        content: "正在继续处理当前请求…",
        tone: "action",
      });
    } else {
      const runtime = toBrowserRuntime(result);
      const currentMessageRequestId =
        typeof runtime.current_message_request_id === "string" ? runtime.current_message_request_id.trim() : "";
      setAssistantPlaceholder(
        currentMessageRequestId === clientMessageId
          ? {
              key: clientMessageId,
              badge: "生成中",
              content: "正在生成…",
            }
          : null,
      );
    }
    const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
    if (watchTaskId) {
      void loadTask(watchTaskId, true);
    }
    setErrorText(null);
    setStreamError(null);
  };

  const loadTask = async (taskId: string, silent = false) => {
    try {
      const [taskResult, eventResult] = await Promise.all([
        getTask(taskId),
        getTaskEvents(taskId, { pageSize: 6 }),
      ]);
      setTask(taskResult);
      setTaskEvents(eventResult.items);
      if (!silent) {
        setErrorText(null);
      }
    } catch (error) {
      if (!silent) {
        setErrorText(error instanceof Error ? error.message : "无法读取最近任务");
      }
    }
  };

  const loadCurrentGoal = async (goalId: string, silent = false) => {
    try {
      const result = await getHaorGoal(goalId);
      setCurrentGoal(result);
    } catch {
      if (!silent) {
        setCurrentGoal(null);
      }
    }
  };

  const loadSession = async (silent = false) => {
    try {
      if (!silent) {
        setLoading(true);
      }
      const result = await recoverHaorSession();
      syncPendingMessageTurnFromSession(result);
      syncPendingUiStepFromSession(result);
      setSession(result);
      if (result.current_goal_id) {
        void loadCurrentGoal(result.current_goal_id, true);
      } else {
        setCurrentGoal(null);
      }
      const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
      if (watchTaskId) {
        void loadTask(watchTaskId, true);
      } else {
        setTask(null);
        setTaskEvents([]);
      }
      if (!silent) {
        setErrorText(null);
      }
      setSessionInitialized(true);
    } catch (error) {
      if (!silent) {
        setErrorText(error instanceof Error ? error.message : "无法恢复 haor 会话");
      }
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    if (!open) {
      return;
    }
    void loadSession(sessionInitialized);
  }, [open]);

  useEffect(() => {
    if (!open || !sessionInitialized) {
      return;
    }
    if (!session?.current_goal_id) {
      setCurrentGoal(null);
      return;
    }
    void loadCurrentGoal(session.current_goal_id, true);
  }, [open, sessionInitialized, session?.current_goal_id, session?.updated_at]);

  useEffect(() => {
    if (open) {
      return undefined;
    }
    const token = getStoredToken();
    if (!token) {
      setSummary(EMPTY_HAOR_SUMMARY);
      return undefined;
    }
    let disposed = false;

    const refreshSummary = async () => {
      try {
        const result = await getHaorSessionSummary();
        if (!disposed) {
          setSummary(result);
        }
      } catch {
        return;
      }
    };

    const handleVisibilityRefresh = () => {
      if (!document.hidden) {
        void refreshSummary();
      }
    };

    void refreshSummary();
    const intervalId = window.setInterval(() => {
      void refreshSummary();
    }, HAOR_SUMMARY_POLL_INTERVAL_MS);
    document.addEventListener("visibilitychange", handleVisibilityRefresh);
    window.addEventListener("focus", handleVisibilityRefresh);

    return () => {
      disposed = true;
      window.clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityRefresh);
      window.removeEventListener("focus", handleVisibilityRefresh);
    };
  }, [open]);

  useEffect(() => {
    if (!open) {
      shouldReconnectRef.current = false;
      resetPendingUiStepState();
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setConnectionState("disconnected");
      setAssistantPlaceholder(null);
      setPendingUserMessages([]);
      ignoredTurnIdsRef.current.clear();
      ignoredClientMessageIdsRef.current.clear();
      return undefined;
    }

    const token = getStoredToken();
    if (!token) {
      setStreamError("登录状态已失效，请重新登录");
      setConnectionState("disconnected");
      return undefined;
    }

    shouldReconnectRef.current = true;
    let disposed = false;

    const connect = () => {
      if (disposed || !shouldReconnectRef.current) {
        return;
      }
      setConnectionState("connecting");
      const socket = new WebSocket(buildHaorSessionStreamUrl(token));
      wsRef.current = socket;
      socket.onopen = () => {
        if (disposed) {
          socket.close();
          return;
        }
        reconnectAttemptsRef.current = 0;
        setConnectionState("connected");
        setStreamError(null);
      };
      socket.onmessage = (rawEvent) => {
        try {
          const payload = JSON.parse(rawEvent.data) as AgentStreamServerEnvelope;
          handleStreamEvent(payload);
        } catch {
          setStreamError("haor 流式数据解析失败");
        }
      };
      socket.onerror = () => {
        setStreamError("haor 流式连接异常，正在尝试恢复");
      };
      socket.onclose = () => {
        const hasPendingMessageTurn = Boolean(pendingMessageTurnRef.current);
        const hasPendingUiStep = Boolean(pendingUiStepRef.current);
        if (wsRef.current === socket) {
          wsRef.current = null;
        }
        setLoading(false);
        if (!hasPendingMessageTurn) {
          setSending(false);
        }
        if (!hasPendingUiStep) {
          setStepping(false);
        }
        setApproving(false);
        setActiveTurnId(null);
        if (!hasPendingUiStep && !hasPendingMessageTurn) {
          setAssistantPlaceholder(null);
        }
        if (!hasPendingMessageTurn) {
          setDraftAssistantMessage(null);
        }
        pendingUiRequestRef.current = null;
        setPendingUiRequest(null);
        if (!hasPendingMessageTurn) {
          setPendingUserMessages((current) => markPendingUserMessagesFailed(current));
          setStreamFeed([]);
        }
        if (disposed || !shouldReconnectRef.current) {
          setConnectionState("disconnected");
          return;
        }
        setStreamError("haor 流式连接已断开，正在尝试恢复");
        setConnectionState("connecting");
        const nextAttempt = reconnectAttemptsRef.current + 1;
        reconnectAttemptsRef.current = nextAttempt;
        const delay = Math.min(1000 * nextAttempt, 4000);
        reconnectTimerRef.current = window.setTimeout(() => {
          reconnectTimerRef.current = null;
          connect();
        }, delay);
      };
    };

    connect();

    return () => {
      disposed = true;
      shouldReconnectRef.current = false;
      if (reconnectTimerRef.current) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setConnectionState("disconnected");
    };
  }, [open]);

  useEffect(() => {
    if (!open || connectionState !== "connected") {
      return;
    }
    sendStreamFrame({
      type: "hello",
      page_context: pageContext,
      browser_context: syncBrowserContext(pageContext),
    });
  }, [open, connectionState, pageContext]);

  useEffect(() => {
    if (connectionState === "connected") {
      return undefined;
    }
    if (!open) {
      return undefined;
    }
    if (!currentWatchTaskId) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void loadTask(currentWatchTaskId, true);
      if (normalizeStatus(session?.status) === "running") {
        void loadSession(true);
      }
    }, 4000);
    return () => window.clearInterval(timer);
  }, [open, currentWatchTaskId, session?.status, connectionState]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const timer = window.setTimeout(() => {
      syncBrowserContext(pageContext);
    }, 120);
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.clearTimeout(timer);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [open, pageContext]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const viewport = feedViewportRef.current;
    if (!viewport) {
      return;
    }
    viewport.scrollTo({
      top: viewport.scrollHeight,
      behavior: "smooth",
    });
  }, [
    open,
    session?.messages?.length,
    visiblePendingUserMessages.length,
    streamFeed.length,
    assistantPlaceholder?.content,
    draftAssistantMessage?.content,
    proposedActions.length,
    pendingUiKey,
    task?.id,
    task?.status,
    taskEvents.length,
    errorText,
  ]);

  useEffect(() => {
    if (!open || !pendingUiActions.length || stepping || sending || approving || interrupting || resetting) {
      return;
    }

    let canceled = false;
    let usedStream = false;

    const applyStepResult = (result: AgentSession) => {
      syncPendingUiStepFromSession(result);
      setSession(result);
      setAssistantPlaceholder(
        toPendingUiActions(result).length
          ? {
              key: result.session_id,
              badge: "处理中",
              content: "正在继续处理当前请求…",
              tone: "action",
            }
          : null,
      );
      const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
      if (watchTaskId) {
        void loadTask(watchTaskId, true);
      }
      setErrorText(null);
      setStreamError(null);
    };

    const scheduleUiStepFallback = (stepRequestId: string, refreshedBrowserContext: AgentBrowserContext, results: AgentUIActionResult[]) => {
      const current = pendingUiStepRef.current;
      if (!current || current.acked || current.fallbackUsed) {
        return;
      }
      clearPendingUiStepTimer();
      current.timerId = window.setTimeout(async () => {
        const pendingStep = pendingUiStepRef.current;
        if (
          canceled ||
          !pendingStep ||
          pendingStep.stepRequestId !== stepRequestId ||
          pendingStep.acked ||
          pendingStep.fallbackUsed
        ) {
          return;
        }
        pendingStep.fallbackUsed = true;
        try {
          const result = await postHaorStep({
            step_request_id: stepRequestId,
            browser_context: refreshedBrowserContext,
            ui_action_results: results,
          });
          if (canceled) {
            return;
          }
          const latestPendingStep = pendingUiStepRef.current;
          if (!latestPendingStep || latestPendingStep.stepRequestId !== stepRequestId) {
            return;
          }
          markPendingUiStepAcked(stepRequestId);
          applyStepResult(result);
        } catch {
          if (canceled) {
            return;
          }
          const latestPendingStep = pendingUiStepRef.current;
          if (!latestPendingStep || latestPendingStep.stepRequestId !== stepRequestId) {
            return;
          }
          failOpenPendingUiStep();
          message.warning(UI_STEP_FAIL_OPEN_TEXT);
        }
      }, UI_STEP_ACK_TIMEOUT_MS);
    };

    const runPendingUiActions = async () => {
      try {
        setStepping(true);
        const results = await executeUIActions(pendingUiActions, {
          navigate: (href) => router.push(href),
        });
        if (canceled) {
          return;
        }
        await new Promise((resolve) => window.setTimeout(resolve, 320));
        const refreshedPageContext = buildPageContextFromLocation();
        const refreshedBrowserContext = syncBrowserContext(refreshedPageContext);
        const stepRequestId = createClientId();
        pendingUiStepRef.current = {
          stepRequestId,
          browserContext: refreshedBrowserContext,
          uiActionResults: results,
          fallbackUsed: false,
          acked: false,
          timerId: null,
        };
        usedStream = sendStreamFrame({
          type: "ui_step",
          step_request_id: stepRequestId,
          browser_context: refreshedBrowserContext,
          ui_action_results: results,
        });
        pendingUiRequestRef.current = null;
        setPendingUiRequest(null);
        setErrorText(null);
        if (!usedStream) {
          const result = await postHaorStep({
            step_request_id: stepRequestId,
            browser_context: refreshedBrowserContext,
            ui_action_results: results,
          });
          if (canceled) {
            return;
          }
          markPendingUiStepAcked(stepRequestId);
          applyStepResult(result);
          resetPendingUiStepState();
        } else {
          scheduleUiStepFallback(stepRequestId, refreshedBrowserContext, results);
        }
      } catch (error) {
        if (!canceled) {
          const text = error instanceof Error ? error.message : "站内动作执行失败";
          resetPendingUiStepState();
          setAssistantPlaceholder(null);
          setErrorText(text);
          message.error(text);
        }
      } finally {
        if (!canceled && !usedStream) {
          setStepping(false);
        }
      }
    };

    void runPendingUiActions();

    return () => {
      canceled = true;
    };
  }, [open, pendingUiKey, stepping, sending, approving, interrupting, resetting, router]);

  const handleSend = async (content: string) => {
    const normalized = content.trim();
    if (!normalized) {
      return;
    }
    const clientMessageId = createClientId();
    const createdAt = new Date().toISOString();
    const currentPageContext = { ...pageContext };
    const context = syncBrowserContext(currentPageContext);
    let usedStream = false;

    const scheduleMessageTurnFallback = () => {
      const current = pendingMessageTurnRef.current;
      if (!current || current.acked || current.fallbackUsed) {
        return;
      }
      clearPendingMessageTurnTimer();
      current.timerId = window.setTimeout(async () => {
        const pendingTurn = pendingMessageTurnRef.current;
        if (
          !pendingTurn ||
          pendingTurn.clientMessageId !== clientMessageId ||
          pendingTurn.acked ||
          pendingTurn.fallbackUsed
        ) {
          return;
        }
        pendingTurn.fallbackUsed = true;
        try {
          const result = await postHaorMessage({
            client_message_id: pendingTurn.clientMessageId,
            content: pendingTurn.content,
            page_context: pendingTurn.pageContext,
            browser_context: pendingTurn.browserContext,
          });
          const latestPendingTurn = pendingMessageTurnRef.current;
          if (!latestPendingTurn || latestPendingTurn.clientMessageId !== clientMessageId) {
            return;
          }
          applyMessageTurnResult(result, clientMessageId);
        } catch {
          const latestPendingTurn = pendingMessageTurnRef.current;
          if (!latestPendingTurn || latestPendingTurn.clientMessageId !== clientMessageId) {
            return;
          }
        }
      }, MESSAGE_TURN_ACK_TIMEOUT_MS);
    };

    try {
      setSending(true);
      pendingMessageTurnRef.current = {
        clientMessageId,
        content: normalized,
        pageContext: currentPageContext,
        browserContext: context,
        fallbackUsed: false,
        acked: false,
        timerId: null,
      };
      setPendingUserMessages((current) => [
        ...current.filter((item) => item.clientMessageId !== clientMessageId),
        {
          clientMessageId,
          content: normalized,
          createdAt,
          status: "sending",
        },
      ]);
      setAssistantPlaceholder({
        key: clientMessageId,
        badge: "生成中",
        content: "正在生成…",
      });
      setInputValue("");
      setOpen(true);
      setErrorText(null);
      setStreamError(null);
      usedStream = sendStreamFrame({
        type: "message",
        client_message_id: clientMessageId,
        content: normalized,
        page_context: currentPageContext,
        browser_context: context,
      });
      if (usedStream) {
        scheduleMessageTurnFallback();
        return;
      }
      const result = await postHaorMessage({
        client_message_id: clientMessageId,
        content: normalized,
        page_context: currentPageContext,
        browser_context: context,
      });
      applyMessageTurnResult(result, clientMessageId);
      resetPendingMessageTurnState();
    } catch (error) {
      const text = error instanceof Error ? error.message : "haor 消息发送失败";
      resetPendingMessageTurnState();
      setPendingUserMessages((current) =>
        current.map((item) => (item.clientMessageId === clientMessageId ? { ...item, status: "failed" } : item)),
      );
      setAssistantPlaceholder(null);
      setErrorText(text);
      message.error(text);
    } finally {
      if (!usedStream) {
        setSending(false);
      }
    }
  };

  const handleApprove = async () => {
    let usedStream = false;
    try {
      setApproving(true);
      usedStream = sendStreamFrame({ type: "approve_plan" });
      if (!usedStream) {
        const result = await approveHaorSession({});
        message.success(`haor 编排任务已提交：${result.task_id}`);
        await loadSession(true);
        await loadTask(result.task_id, true);
      }
      setOpen(true);
      setErrorText(null);
    } catch (error) {
      const text = error instanceof Error ? error.message : "haor 计划提交失败";
      setErrorText(text);
      message.error(text);
    } finally {
      if (!usedStream) {
        setApproving(false);
      }
    }
  };

  const handleRecover = async () => {
    try {
      setLoading(true);
      resetPendingMessageTurnState();
      resetPendingUiStepState();
      const result = await recoverHaorSession();
      setSession(result);
      if (result.current_goal_id) {
        await loadCurrentGoal(result.current_goal_id, true);
      } else {
        setCurrentGoal(null);
      }
      const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
      if (watchTaskId) {
        await loadTask(watchTaskId, true);
      } else {
        setTask(null);
        setTaskEvents([]);
      }
      setErrorText(null);
      setStreamError(null);
      setSummary(deriveSessionSummary(result));
      message.success("会话状态已恢复");
    } catch (error) {
      const text = error instanceof Error ? error.message : "haor 会话恢复失败";
      setErrorText(text);
      message.error(text);
    } finally {
      setLoading(false);
    }
  };

  const handleInterrupt = async () => {
    try {
      setInterrupting(true);
      resetPendingMessageTurnState();
      resetPendingUiStepState();
      const result = await interruptHaorSession();
      setSession(result);
      const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
      if (watchTaskId) {
        await loadTask(watchTaskId, true);
      } else {
        setTask(null);
        setTaskEvents([]);
      }
      setErrorText(null);
      message.success("任务已中断");
    } catch (error) {
      const text = error instanceof Error ? error.message : "haor 编排中断失败";
      setErrorText(text);
      message.error(text);
    } finally {
      setInterrupting(false);
    }
  };

  const handleReset = async () => {
    try {
      setResetting(true);
      resetPendingMessageTurnState();
      resetPendingUiStepState();
      const result = await resetHaorSession();
      if (activeTurnIdRef.current) {
        ignoredTurnIdsRef.current.add(activeTurnIdRef.current);
      }
      for (const item of pendingUserMessages) {
        ignoredClientMessageIdsRef.current.add(item.clientMessageId);
      }
      setSession(result);
      setCurrentGoal(null);
      setTask(null);
      setTaskEvents([]);
      setInputValue("");
      setErrorText(null);
      setStreamError(null);
      setAssistantPlaceholder(null);
      setDraftAssistantMessage(null);
      setPendingUserMessages([]);
      setStreamFeed([]);
      pendingUiRequestRef.current = null;
      setPendingUiRequest(null);
      setActiveTurnId(null);
      setSending(false);
      setStepping(false);
      setApproving(false);
      syncBrowserContext(pageContext);
      setSummary(deriveSessionSummary(result));
    } catch (error) {
      const text = error instanceof Error ? error.message : "无法创建新会话";
      setErrorText(text);
      message.error(text);
    } finally {
      setResetting(false);
    }
  };

  const applySecureStepResult = async (result: AgentSession) => {
    setSession(result);
    setSummary(deriveSessionSummary(result));
    if (result.current_goal_id) {
      await loadCurrentGoal(result.current_goal_id, true);
    } else {
      setCurrentGoal(null);
    }
    const watchTaskId = result.runtime_snapshot?.watch_task_id || result.last_task_id;
    if (watchTaskId) {
      await loadTask(watchTaskId, true);
    } else {
      setTask(null);
      setTaskEvents([]);
    }
    setErrorText(null);
    setStreamError(null);
  };

  const submitSecureStep = async (detailJson: Record<string, unknown>) => {
    const result = await postHaorStep({
      step_request_id: createClientId(),
      browser_context: buildSecureStepBrowserContext(pageContext),
      ui_action_results: [
        {
          action_id: createClientId(),
          action_type: "submit",
          ok: true,
          detail_json: detailJson,
        },
      ],
    });
    await applySecureStepResult(result);
  };

  const currentCredentialPayloadError = () => {
    if (!secureUsername.trim()) {
      return "请先填写用户名";
    }
    if (secureAuthType === "password" && !securePassword.trim()) {
      return "认证方式为密码时必须填写密码";
    }
    if (secureAuthType === "key" && !securePrivateKey.trim()) {
      return "认证方式为私钥时必须填写私钥";
    }
    if (secureUsername.trim().toLowerCase() !== "root" && !secureSudoPassword.trim()) {
      return "非 root 用户必须填写 sudo 密码";
    }
    if (!secureAuthorized) {
      return "请先确认已获得管理员授权";
    }
    return "";
  };

  const handleSecureCancel = async () => {
    try {
      setSecureSubmitting(true);
      await submitSecureStep({ kind: "ssh_credential_cancel", canceled: true });
      message.info("已取消 SSH 凭据配置");
    } catch (error) {
      const text = error instanceof Error ? error.message : "取消 SSH 凭据配置失败";
      setSecureErrorText(text);
      message.error(text);
    } finally {
      setSecureSubmitting(false);
    }
  };

  const handleSecureSameBatchSubmit = async () => {
    const validationError = currentCredentialPayloadError();
    if (validationError) {
      setSecureErrorText(validationError);
      message.warning(validationError);
      return;
    }
    try {
      setSecureSubmitting(true);
      setSecureErrorText(null);
      const payload = buildCredentialPayload(
        secureAuthType,
        secureUsername,
        securePassword,
        securePrivateKey,
        secureSudoPassword,
        secureAuthorized,
      );

      if (secureAssetCount <= 1) {
        const assetId = pendingSecureInput.asset_ids[0];
        let saved = false;
        let verified = false;
        let effectivePrivilege: string | null = null;
        let errorSummary: string | null = null;
        try {
          await setAssetCredential(assetId, payload);
          saved = true;
          const verifyResult = await verifyAssetCredential(assetId);
          verified = verifyResult.status === "success";
          effectivePrivilege = verifyResult.effective_privilege || null;
          if (!verified) {
            errorSummary = verifyResult.summary || "未通过管理员权限验证";
          }
        } catch (error) {
          errorSummary = error instanceof Error ? error.message : "保存或验证 SSH 凭据失败";
        }
        await submitSecureStep({
          kind: "ssh_credential_single",
          asset_id: assetId,
          auth_type: secureAuthType,
          username: secureUsername.trim(),
          saved,
          verified,
          effective_privilege: effectivePrivilege,
          resume_goal_id: pendingSecureInput.resume_goal_id,
          resume_action: pendingSecureInput.resume_action,
          error_summary: errorSummary,
        });
        message.success(verified ? "SSH 凭据已保存并验证" : "SSH 凭据已保存，但验证未通过");
        return;
      }

      const batchResult = await setAssetCredentialBatch({
        ...payload,
        asset_ids: pendingSecureInput.asset_ids,
        mode: "same_credential_batch",
        verify_after_save: true,
      });
      await submitSecureStep({
        kind: "ssh_credential_batch",
        mode: "same_credential_batch",
        total_count: batchResult.total_count,
        success_count: batchResult.success_count,
        failure_count: batchResult.failure_count,
        results: batchResult.results,
        resume_goal_id: pendingSecureInput.resume_goal_id,
        resume_action: pendingSecureInput.resume_action,
      });
      message.success(`批量 SSH 凭据处理完成：成功 ${batchResult.success_count} 台`);
    } catch (error) {
      const text = error instanceof Error ? error.message : "SSH 凭据处理失败";
      setSecureErrorText(text);
      message.error(text);
    } finally {
      setSecureSubmitting(false);
    }
  };

  const handleSecureGuidedSubmit = async () => {
    const validationError = currentCredentialPayloadError();
    if (validationError) {
      setSecureErrorText(validationError);
      message.warning(validationError);
      return;
    }
    const assetId = secureCurrentAssetId;
    if (!assetId) {
      return;
    }
    try {
      setSecureSubmitting(true);
      setSecureErrorText(null);
      const payload = buildCredentialPayload(
        secureAuthType,
        secureUsername,
        securePassword,
        securePrivateKey,
        secureSudoPassword,
        secureAuthorized,
      );
      let resultItem: SecureInputResultItem = {
        asset_id: assetId,
        saved: false,
        verified: false,
        effective_privilege: null,
        error_summary: null,
      };
      try {
        await setAssetCredential(assetId, payload);
        resultItem = { ...resultItem, saved: true };
        const verifyResult = await verifyAssetCredential(assetId);
        resultItem = {
          ...resultItem,
          verified: verifyResult.status === "success",
          effective_privilege: verifyResult.effective_privilege || null,
          error_summary: verifyResult.status === "success" ? null : (verifyResult.summary || "未通过管理员权限验证"),
        };
      } catch (error) {
        resultItem = {
          ...resultItem,
          error_summary: error instanceof Error ? error.message : "保存或验证 SSH 凭据失败",
        };
      }
      const nextResults = [...secureGuidedResults, resultItem];
      if (secureGuidedIndex >= secureAssetCount - 1) {
        await submitSecureStep({
          kind: "ssh_credential_batch",
          mode: "per_asset_guided",
          total_count: nextResults.length,
          success_count: nextResults.filter((item) => item.verified).length,
          failure_count: nextResults.filter((item) => !item.verified).length,
          results: nextResults,
          resume_goal_id: pendingSecureInput.resume_goal_id,
          resume_action: pendingSecureInput.resume_action,
        });
        message.success("逐台 SSH 凭据配置已完成");
      } else {
        setSecureGuidedResults(nextResults);
        setSecureGuidedIndex((current) => current + 1);
        setSecurePassword("");
        setSecurePrivateKey("");
        setSecureSudoPassword("");
        setSecureAuthorized(false);
      }
    } catch (error) {
      const text = error instanceof Error ? error.message : "逐台 SSH 凭据配置失败";
      setSecureErrorText(text);
      message.error(text);
    } finally {
      setSecureSubmitting(false);
    }
  };

  const handleSecureGuidedSkip = async () => {
    const assetId = secureCurrentAssetId;
    if (!assetId) {
      return;
    }
    const nextResults = [
      ...secureGuidedResults,
      {
        asset_id: assetId,
        saved: false,
        verified: false,
        effective_privilege: null,
        error_summary: "用户跳过当前资产",
      },
    ];
    if (secureGuidedIndex >= secureAssetCount - 1) {
      try {
        setSecureSubmitting(true);
        await submitSecureStep({
          kind: "ssh_credential_batch",
          mode: "per_asset_guided",
          total_count: nextResults.length,
          success_count: nextResults.filter((item) => item.verified).length,
          failure_count: nextResults.filter((item) => !item.verified).length,
          results: nextResults,
          resume_goal_id: pendingSecureInput.resume_goal_id,
          resume_action: pendingSecureInput.resume_action,
        });
        message.info("已完成逐台 SSH 凭据配置流程");
      } catch (error) {
        const text = error instanceof Error ? error.message : "提交逐台 SSH 配置结果失败";
        setSecureErrorText(text);
        message.error(text);
      } finally {
        setSecureSubmitting(false);
      }
      return;
    }
    setSecureGuidedResults(nextResults);
    setSecureGuidedIndex((current) => current + 1);
    setSecurePassword("");
    setSecurePrivateKey("");
    setSecureSudoPassword("");
    setSecureAuthorized(false);
    setSecureErrorText(null);
  };

  return (
    <>
      <div className={`haor-fab-shell ${open ? "haor-fab-shell-open" : ""} ${hasAttention ? "haor-fab-shell-attention" : ""}`}>
        <Badge dot={hasAttention} color="#dc2626" offset={[-8, 8]}>
          <button type="button" className="haor-fab-button" onClick={() => setOpen(true)} aria-label="打开 haor 智能体">
            <span className="haor-fab-ball">
              <span className="haor-fab-core" />
            </span>
            <span className="haor-fab-label">haor</span>
          </button>
        </Badge>
      </div>

      {open ? (
        <div className="haor-chat-shell" role="dialog" aria-modal="true" aria-label="haor 聊天助手">
          <button type="button" className="haor-chat-backdrop" onClick={() => setOpen(false)} aria-label="关闭 haor 聊天窗口" />

          <Modal
            open={secureInputVisible}
            title="SSH 凭据安全配置"
            onCancel={() => {
              if (!secureSubmitting) {
                void handleSecureCancel();
              }
            }}
            destroyOnClose
            maskClosable={!secureSubmitting}
            keyboard={!secureSubmitting}
            closable={!secureSubmitting}
            okButtonProps={{ style: { display: "none" } }}
            cancelButtonProps={{ style: { display: "none" } }}
            footer={[
              secureBatchMode === "per_asset_guided" && secureAssetCount > 1 ? (
                <Button key="skip" onClick={() => void handleSecureGuidedSkip()} disabled={secureSubmitting}>
                  跳过当前资产
                </Button>
              ) : null,
              <Button key="cancel" onClick={() => void handleSecureCancel()} disabled={secureSubmitting}>
                取消
              </Button>,
              <Button
                key="submit"
                type="primary"
                loading={secureSubmitting}
                disabled={secureAssetCount > 1 && !secureBatchMode}
                onClick={() => {
                  if (secureBatchMode === "per_asset_guided") {
                    void handleSecureGuidedSubmit();
                    return;
                  }
                  void handleSecureSameBatchSubmit();
                }}
              >
                {secureBatchMode === "per_asset_guided"
                  ? (secureGuidedIndex >= secureAssetCount - 1 ? "完成并验证" : "保存并继续下一台")
                  : (secureAssetCount > 1 ? "保存并批量验证" : "保存并验证")}
              </Button>,
            ]}
          >
            <div data-haor-sensitive-input="true">
              <div style={{ display: "grid", gap: 12 }}>
                <Alert
                  type="info"
                  showIcon
                  message={secureAssetCount > 1 ? `目标资产：共 ${secureAssetCount} 台` : `目标资产：${secureCurrentAssetLabel || "当前资产"}`}
                  description={
                    secureAssetCount > 1
                      ? "聊天中只保留非敏感信息；密码、私钥与 sudo 密码只会在这个安全弹层中输入。保存并验证 SSH 后，Haor 会自动续接原目标；若仍缺 Runner 或其他条件，会继续明确提示。"
                      : "聊天中只保留认证方式、用户名与验证结果；密码、私钥与 sudo 密码不会写入会话记录。保存并验证 SSH 后，Haor 会自动续接修复；若仍缺 Runner 或其他条件，会继续明确提示。"
                  }
                />
                {pendingSecureInput.blocker_summary ? (
                  <Alert type="warning" showIcon message={`当前阻塞：${pendingSecureInput.blocker_summary}`} />
                ) : null}
                {secureErrorText ? <Alert type="error" showIcon message={secureErrorText} /> : null}
                {secureAssetCount > 1 ? (
                  <div style={{ display: "grid", gap: 8 }}>
                    <strong>批量模式</strong>
                    <Radio.Group
                      value={secureBatchMode}
                      onChange={(event) => setSecureBatchMode(event.target.value)}
                      disabled={secureSubmitting}
                    >
                      <Radio.Button value="same_credential_batch">同一套凭据批量应用</Radio.Button>
                      <Radio.Button value="per_asset_guided">逐台引导配置</Radio.Button>
                    </Radio.Group>
                    {secureBatchMode === "per_asset_guided" ? (
                      <span style={{ color: "rgba(15,23,42,0.72)", fontSize: 13 }}>
                        当前第 {Math.min(secureGuidedIndex + 1, secureAssetCount)} / {secureAssetCount} 台：{secureCurrentAssetLabel}
                      </span>
                    ) : null}
                  </div>
                ) : null}
                <div style={{ display: "grid", gap: 8 }}>
                  <strong>认证方式</strong>
                  <Radio.Group value={secureAuthType} onChange={(event) => setSecureAuthType(event.target.value)} disabled={secureSubmitting}>
                    <Radio.Button value="password">密码</Radio.Button>
                    <Radio.Button value="key">私钥</Radio.Button>
                  </Radio.Group>
                </div>
                <div style={{ display: "grid", gap: 8 }}>
                  <strong>用户名</strong>
                  <Input
                    value={secureUsername}
                    onChange={(event) => setSecureUsername(event.target.value)}
                    disabled={secureSubmitting}
                    placeholder="例如 root 或 sudo 用户名"
                  />
                </div>
                {secureAuthType === "password" ? (
                  <div style={{ display: "grid", gap: 8 }}>
                    <strong>SSH 密码</strong>
                    <Input.Password
                      value={securePassword}
                      onChange={(event) => setSecurePassword(event.target.value)}
                      disabled={secureSubmitting}
                      placeholder="仅在安全弹层中输入"
                    />
                  </div>
                ) : (
                  <div style={{ display: "grid", gap: 8 }}>
                    <strong>SSH 私钥</strong>
                    <Input.TextArea
                      autoSize={{ minRows: 4, maxRows: 10 }}
                      value={securePrivateKey}
                      onChange={(event) => setSecurePrivateKey(event.target.value)}
                      disabled={secureSubmitting}
                      placeholder="粘贴 PEM/OpenSSH 私钥内容"
                    />
                  </div>
                )}
                <div style={{ display: "grid", gap: 8 }}>
                  <strong>{secureUsername.trim().toLowerCase() === "root" ? "无需 sudo 密码" : "sudo 密码"}</strong>
                  <Input.Password
                    value={secureSudoPassword}
                    onChange={(event) => setSecureSudoPassword(event.target.value)}
                    disabled={secureSubmitting || secureUsername.trim().toLowerCase() === "root"}
                    placeholder={secureUsername.trim().toLowerCase() === "root" ? "root 用户可留空" : "非 root 用户必填"}
                  />
                </div>
                <Checkbox checked={secureAuthorized} onChange={(event) => setSecureAuthorized(event.target.checked)} disabled={secureSubmitting}>
                  我确认已经获得目标主机管理员授权
                </Checkbox>
              </div>
            </div>
          </Modal>

          <section className="haor-chat-window" data-haor-agent-root="true">
            <div className="haor-chat-body">
              <aside className="haor-chat-sidebar" aria-label="haor 会话侧栏">
                <div className="haor-chat-sidebar-top">
                  <div className="haor-chat-header-copy">
                    <span className="haor-chat-kicker">Chat Assistant</span>
                    <div className="haor-chat-title-row">
                      <h2 className="haor-chat-title">haor</h2>
                      <span className={`haor-chat-status haor-chat-status-${normalizeStatus(session?.status) || "active"}`}>
                        {statusLabel(session?.status)}
                      </span>
                    </div>
                    <p className={`haor-chat-subtitle haor-chat-subtitle-${headerStatus.tone}`}>{headerStatus.text}</p>
                  </div>
                </div>

                <div className="haor-chat-sidebar-scroll">
                  <section className="haor-chat-sidebar-section haor-chat-state-panel" aria-label="haor 关键信息">
                    <div className="haor-chat-sidebar-heading">
                      <span className="haor-chat-sidebar-kicker">Overview</span>
                      <strong className="haor-chat-sidebar-title">关键信息</strong>
                    </div>
                    <div className="haor-chat-state-card">
                      <span className="haor-chat-state-label">当前目标</span>
                      <strong className="haor-chat-state-value">{currentGoalTitle}</strong>
                    </div>
                    <div className="haor-chat-state-card">
                      <span className="haor-chat-state-label">当前阶段</span>
                      <strong className="haor-chat-state-value">{sidebarStageText}</strong>
                    </div>
                    <div className="haor-chat-state-card">
                      <span className="haor-chat-state-label">当前阻塞</span>
                      <strong className="haor-chat-state-value">{sidebarBlockerText}</strong>
                    </div>
                    <div className="haor-chat-state-card">
                      <span className="haor-chat-state-label">下一步</span>
                      <strong className="haor-chat-state-value">{sidebarNextStepText}</strong>
                    </div>
                    <div className="haor-chat-state-card">
                      <span className="haor-chat-state-label">最近任务</span>
                      <strong className="haor-chat-state-value">{sidebarRecentTaskText}</strong>
                    </div>
                    <div className="haor-chat-sidebar-note">
                      最近更新 {sidebarUpdatedText}
                    </div>
                  </section>
                </div>
              </aside>

              <section className="haor-chat-main" aria-label="haor 聊天主区">
                <header className="haor-chat-main-header">
                  <div className="haor-chat-main-header-copy">
                    <span className="haor-chat-main-kicker">Conversation</span>
                    <strong className="haor-chat-main-title">聊天主区</strong>
                  </div>

                  <div className="haor-chat-header-actions">
                    <Button
                      size="small"
                      className="haor-chat-header-button"
                      onClick={() => void handleRecover()}
                      loading={loading && !!session}
                      disabled={loading && !session}
                    >
                      恢复会话
                    </Button>
                    <Button
                      danger
                      size="small"
                      className="haor-chat-header-button haor-chat-header-button-danger"
                      onClick={() => void handleInterrupt()}
                      loading={interrupting}
                      disabled={!showInterrupt}
                    >
                      中断任务
                    </Button>
                    <Button
                      size="small"
                      className="haor-chat-header-button haor-chat-header-button-primary"
                      onClick={() => void handleReset()}
                      loading={resetting}
                      disabled={resetDisabled}
                    >
                      新会话
                    </Button>
                    <Button size="small" className="haor-chat-header-button" onClick={() => setOpen(false)}>
                      关闭
                    </Button>
                  </div>
                </header>

                <div ref={feedViewportRef} className="haor-chat-feed">
                  {loading && !session?.messages?.length ? (
                    <div className="haor-chat-empty">
                      <strong>正在恢复会话</strong>
                      <span>haor 正在同步最近的聊天记录和任务状态。</span>
                    </div>
                  ) : null}

                  {!loading && !session?.messages?.length && !proposedActions.length && !task ? (
                    <div className="haor-chat-empty">
                      <strong>开始聊天</strong>
                      <span>直接像聊天一样提问，或告诉 haor 你想在站内执行什么操作。</span>
                    </div>
                  ) : null}

                  {task ? (
                    <section className="haor-chat-task-banner" aria-label="当前任务跟踪">
                      <div className="haor-chat-task-banner-main">
                        <div className="haor-chat-task-banner-copy">
                          <strong>{getTaskTypeLabel(task.task_type)} · {statusLabel(task.status)}</strong>
                          <span>{task.id}</span>
                        </div>
                        <div className="haor-chat-task-banner-actions">
                          {showInterrupt && task.id === currentWatchTaskId ? (
                            <Button danger size="small" onClick={() => void handleInterrupt()} loading={interrupting}>
                              中断任务
                            </Button>
                          ) : null}
                          <Button size="small" onClick={() => router.push(`/tasks/${task.id}`)}>
                            打开任务页
                          </Button>
                        </div>
                      </div>
                      <details className="haor-chat-task-banner-details">
                        <summary>查看任务摘要</summary>
                        <pre className="haor-chat-task-banner-body">{liveTaskDigest}</pre>
                      </details>
                    </section>
                  ) : null}

                  {session?.messages?.map((item) => {
                    const isPendingPlanMessage = Boolean(proposedActions.length && item.id === pendingPlanMessageId);
                    const content = isPendingPlanMessage
                      ? joinSections([item.content, pendingPlanDetails])
                      : item.content;
                    const actions = isPendingPlanMessage ? (
                      isAdmin ? (
                        <Button type="primary" size="small" onClick={() => void handleApprove()} loading={approving}>
                          {approvalActionLabel}
                        </Button>
                      ) : (
                        <span className="haor-chat-inline-note">{approvalBlockedText}</span>
                      )
                    ) : undefined;

                    return (
                      <ChatBubble
                        key={item.id}
                        actions={actions}
                        badge={messageBadgeText(item)}
                        content={content}
                        role={item.role === "user" ? "user" : "assistant"}
                        sender={item.role === "user" ? "你" : "haor"}
                        time={formatChatTime(item.created_at)}
                        tone={messageTone(item)}
                      />
                    );
                  })}

                  {visiblePendingUserMessages.map((item) => (
                    <ChatBubble
                      key={`pending-${item.clientMessageId}`}
                      content={item.content}
                      metaNote={item.status === "failed" ? "发送失败" : "发送中"}
                      role="user"
                      sender="你"
                      stateTone={item.status === "failed" ? "failed" : "pending"}
                      time={formatChatTime(item.createdAt)}
                    />
                  ))}

                  {streamFeed.map((item) => (
                    <ChatBubble
                      key={item.id}
                      badge={item.badge}
                      content={item.content}
                      role="assistant"
                      sender={item.sender}
                      time={formatChatTime(item.time)}
                      tone={item.tone}
                    />
                  ))}

                  {!draftAssistantMessage?.content && assistantPlaceholder ? (
                    <ChatBubble
                      badge={assistantPlaceholder.badge}
                      content={assistantPlaceholder.content}
                      role="assistant"
                      sender="haor"
                      time={formatChatTime(new Date().toISOString())}
                      tone={assistantPlaceholder.tone}
                    />
                  ) : null}

                  {draftAssistantMessage?.content ? (
                    <ChatBubble
                      badge={draftAssistantMessage.messageType === "clarifying" ? "追问" : null}
                      content={draftAssistantMessage.content}
                      role="assistant"
                      sender="haor"
                      time={formatChatTime(new Date().toISOString())}
                      tone={draftAssistantMessage.messageType === "clarifying" ? undefined : undefined}
                    />
                  ) : null}

                  {proposedActions.length && !pendingPlanMessageId ? (
                    <ChatBubble
                      actions={
                        isAdmin ? (
                          <Button type="primary" size="small" onClick={() => void handleApprove()} loading={approving}>
                            {approvalActionLabel}
                          </Button>
                        ) : (
                          <span className="haor-chat-inline-note">{approvalBlockedText}</span>
                        )
                      }
                      badge="计划"
                      content={joinSections([
                        typeof session?.pending_plan_json?.reply_markdown === "string"
                          ? String(session.pending_plan_json.reply_markdown)
                          : "",
                        pendingPlanDetails,
                      ])}
                      role="assistant"
                      sender="haor"
                      time={formatChatTime(session?.updated_at)}
                      tone="plan"
                    />
                  ) : null}

                </div>

                <footer className="haor-chat-composer">
                  <div className="haor-chat-composer-box">
                    <Input.TextArea
                      autoSize={{ minRows: 2, maxRows: 6 }}
                      rootClassName="haor-chat-composer-input"
                      classNames={{ textarea: "haor-chat-composer-textarea" }}
                      value={inputValue}
                      placeholder="发送消息给 haor，像聊天一样提问、追问或描述你想执行的操作。"
                      onChange={(event) => setInputValue(event.target.value)}
                      onPressEnter={(event) => {
                        if (event.shiftKey) {
                          return;
                        }
                        event.preventDefault();
                        void handleSend(inputValue);
                      }}
                      disabled={sendDisabled}
                    />
                    <div className="haor-chat-composer-footer">
                      <span className="haor-chat-composer-hint">{composerHint}</span>
                      <Button
                        type="primary"
                        className="haor-chat-send-button"
                        onClick={() => void handleSend(inputValue)}
                        loading={sending}
                        disabled={sendDisabled || !inputValue.trim()}
                      >
                        发送
                      </Button>
                    </div>
                  </div>
                </footer>
              </section>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}
