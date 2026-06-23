"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Empty,
  Input,
  List,
  Row,
  Space,
  Tag,
  Typography,
  message,
} from "antd";

import CollapsibleJsonBlock from "@/components/CollapsibleJsonBlock";
import RemoteSshTerminal from "@/components/RemoteSshTerminal";
import RollbackArtifactPanel from "@/components/RollbackArtifactPanel";
import StatusTag from "@/components/StatusTag";
import { getStoredToken } from "@/lib/auth";
import {
  buildRemediationAssetPath,
  remediationBusinessStatusLabel,
  remediationExecutionOutcomeLabel,
  remediationResolvedTaskMessage,
} from "@/lib/remediation";
import { formatDateTime, getTaskEventTypeLabel, localizeTaskMessage } from "@/lib/ui-text";
import {
  approveRemediationSession,
  createRemediationSession,
  getRemediationAsset,
  getRemediationSession,
  getRemediationTask,
  getRemediationTaskEvidence,
  installAssetRunner,
  postRemediationSessionMessage,
} from "@/services/api";
import type {
  HostRemediationPlanStep,
  HostRemediationStage,
  RemediationAssetDetail,
  RemediationSession,
  RemediationSessionStreamEnvelope,
  RemediationStreamEnvelope,
  RemediationTask,
  RemediationTaskEvidence,
} from "@/types/remediation";

function toRecord(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return {};
  }
  return input as Record<string, unknown>;
}

function buildRemediationWebSocketUrl(streamPath: string, token: string): string {
  const apiBase = (process.env.NEXT_PUBLIC_API_BASE || "/api/v1").replace(/\/$/, "");
  if (apiBase.startsWith("http://") || apiBase.startsWith("https://")) {
    const parsed = new URL(apiBase);
    const protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
    return `${protocol}//${parsed.host}${streamPath}?token=${encodeURIComponent(token)}`;
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${streamPath}?token=${encodeURIComponent(token)}`;
}

function isTaskRunning(status: string | null | undefined): boolean {
  return ["pending", "running", "retry"].includes(String(status || "").trim().toLowerCase());
}

function workbenchStatusLabel(status: string | null | undefined): string {
  switch (String(status || "").trim().toLowerCase()) {
    case "draft":
      return "待准备";
    case "ready":
      return "可执行";
    case "running":
      return "执行中";
    case "completed":
      return "已完成";
    case "failed":
      return "失败";
    case "canceled":
      return "已中断";
    default:
      return "未知";
  }
}

function remediationBusinessStatusColor(value: string | null | undefined): string {
  switch ((value || "").trim().toLowerCase()) {
    case "verified_closed":
      return "green";
    case "pending_reverify":
      return "blue";
    case "verified_partial":
      return "orange";
    case "verified_failed":
      return "red";
    default:
      return "default";
  }
}

function planModeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "ready":
      return "当前阶段可执行";
    case "partial":
      return "阶段推进中";
    case "blocked":
      return "存在阻塞";
    case "running":
      return "阶段执行中";
    case "completed":
      return "阶段计划完成";
    case "failed":
      return "阶段执行失败";
    default:
      return "未知";
  }
}

function planModeColor(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "ready":
      return "green";
    case "partial":
      return "blue";
    case "running":
      return "processing";
    case "completed":
      return "success";
    case "failed":
      return "error";
    default:
      return "orange";
  }
}

function stageGateLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "ready":
      return "当前可执行";
    case "running":
      return "执行中";
    case "completed":
      return "已完成";
    case "blocked":
      return "当前阻塞";
    case "locked":
      return "等待上一阶段";
    default:
      return "未知";
  }
}

function stageGateColor(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "ready":
      return "green";
    case "running":
      return "processing";
    case "completed":
      return "success";
    case "blocked":
      return "orange";
    case "locked":
      return "default";
    default:
      return "default";
  }
}

function runnerRuntimeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "shell_bundle":
    case "bundled_binary":
      return "Shell Runner";
    case "python_script":
      return "Python Runner";
    default:
      return "-";
  }
}

function runnerInstallModeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "system":
      return "系统级";
    case "user":
      return "用户态";
    default:
      return "-";
  }
}

function runnerServiceModeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "systemd":
      return "systemd";
    case "sysvinit":
      return "SysV init";
    case "crontab":
      return "crontab";
    case "detached":
      return "后台进程";
    default:
      return "-";
  }
}

function remediationMessageTypeLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "ai_plan_summary":
      return "AI 计划解读";
    case "ai_blocker_analysis":
      return "AI 阻塞诊断";
    case "ai_task_failure":
      return "AI 失败诊断";
    case "audit":
      return "系统事件";
    case "note":
      return "备注";
    case "intent":
      return "操作";
    case "summary":
      return "旧摘要";
    default:
      return String(value || "消息");
  }
}

function remediationMessageAuthorLabel(role: string, messageType: string): string {
  if (role === "assistant" && messageType.startsWith("ai_")) {
    return "AI 解读";
  }
  if (role === "assistant") {
    return "系统记录";
  }
  if (messageType === "note") {
    return "管理员备注";
  }
  return "管理员操作";
}

function remediationMessageTagColor(messageType: string): string {
  switch (messageType) {
    case "ai_plan_summary":
      return "blue";
    case "ai_blocker_analysis":
      return "orange";
    case "ai_task_failure":
      return "red";
    case "audit":
      return "gold";
    default:
      return "default";
  }
}

function executionBoundaryLabel(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "template_generated":
      return "模板渲染";
    case "runner_dispatch":
      return "Runner 下发";
    case "dry_run_preview":
      return "修复预演";
    default:
      return "-";
  }
}

function executionModeLabel(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase() === "dry_run" ? "预演" : "正式执行";
}

function toSafeCount(input: unknown): number {
  const parsed = Number(input);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0;
}

type RecentStageOutcome = {
  stage: HostRemediationStage | null;
  stageName: string;
  businessStatus: string;
  openTargetCount: number;
  closedTargetCount: number;
};

function resolveStageFromTask(task: RemediationTask | null, stages: HostRemediationStage[]): HostRemediationStage | null {
  const taskContext = toRecord(task?.context);
  const stageCode = String(taskContext.stage_code || "").trim();
  const stageName = String(taskContext.stage_name || "").trim();
  return stages.find((stage) => stage.stage_code === stageCode)
    || stages.find((stage) => stage.stage_name === stageName)
    || null;
}

function resolveRecentStageOutcome({
  task,
  stages,
}: {
  task: RemediationTask | null;
  stages: HostRemediationStage[];
}): RecentStageOutcome | null {
  const taskWithOutcome = task?.business_status ? task : null;
  const taskContext = toRecord(taskWithOutcome?.context);
  const taskReverifySummary = toRecord(taskWithOutcome?.reverify_summary);
  const fallbackStage = [...stages].reverse().find((stage) => stage.business_status) || null;
  const taskStage = resolveStageFromTask(taskWithOutcome, stages);
  const businessStatus = (taskWithOutcome?.business_status || fallbackStage?.business_status || "").trim().toLowerCase();
  if (!businessStatus) {
    return null;
  }
  return {
    stage: taskStage || fallbackStage,
    stageName: String(taskContext.stage_name || taskStage?.stage_name || fallbackStage?.stage_name || "").trim() || "当前阶段",
    businessStatus,
    openTargetCount: taskWithOutcome
      ? toSafeCount(taskReverifySummary.open_target_count)
      : toSafeCount(fallbackStage?.open_target_count),
    closedTargetCount: taskWithOutcome
      ? toSafeCount(taskReverifySummary.closed_target_count)
      : toSafeCount(fallbackStage?.closed_target_count),
  };
}

function buildRecentStageOutcomeSummary(outcome: RecentStageOutcome | null, findingCount: number): string {
  if (!outcome) {
    return findingCount > 0
      ? `当前资产仍有 ${findingCount} 条开放风险待处理`
      : "当前资产暂无开放风险";
  }
  switch (outcome.businessStatus) {
    case "pending_reverify":
      return `${outcome.stageName}正在复验目标风险`;
    case "verified_closed":
      return outcome.closedTargetCount > 0
        ? `${outcome.stageName}已关闭 ${outcome.closedTargetCount} 项目标风险`
        : `${outcome.stageName}的目标风险已复验关闭`;
    case "verified_partial":
      return outcome.openTargetCount > 0
        ? `${outcome.stageName}仍开放 ${outcome.openTargetCount} 项目标风险`
        : `${outcome.stageName}的目标风险仍未完全闭环`;
    case "verified_failed":
      return `${outcome.stageName}执行或复验失败`;
    default:
      return findingCount > 0
        ? `当前资产仍有 ${findingCount} 条开放风险待处理`
        : "当前资产暂无开放风险";
  }
}

function buildRecentStageOutcomeDetail({
  findingCount,
  task,
  stages,
}: {
  findingCount: number;
  task: RemediationTask | null;
  stages: HostRemediationStage[];
}): string {
  const outcome = resolveRecentStageOutcome({ task, stages });
  if (!outcome) {
    return buildRecentStageOutcomeSummary(null, findingCount);
  }
  switch (outcome.businessStatus) {
    case "pending_reverify":
      return `最近阶段：${outcome.stageName}，正在复验目标风险`;
    case "verified_closed":
      return outcome.closedTargetCount > 0
        ? `最近阶段：${outcome.stageName}，目标风险已关闭 ${outcome.closedTargetCount} 项`
        : `最近阶段：${outcome.stageName}，目标风险已复验关闭`;
    case "verified_partial":
      return outcome.openTargetCount > 0
        ? `最近阶段：${outcome.stageName}，目标风险仍开放 ${outcome.openTargetCount} 项`
        : `最近阶段：${outcome.stageName}，目标风险仍未完全闭环`;
    case "verified_failed":
      return `最近阶段：${outcome.stageName}，执行或复验失败`;
    default:
      return buildRecentStageOutcomeSummary(outcome, findingCount);
  }
}

function stepRiskColor(value: string | null | undefined): string {
  switch (String(value || "").trim().toLowerCase()) {
    case "high":
      return "red";
    case "medium":
      return "orange";
    case "low":
      return "green";
    default:
      return "default";
  }
}

function buildTaskStreamLine(payload: RemediationStreamEnvelope): string {
  if (payload.type !== "event") {
    return "";
  }
  const raw = toRecord(payload.event);
  const eventType = String(raw.event_type || "");
  const payloadJson = toRecord(raw.payload_json);
  if (eventType === "stream") {
    return String(payloadJson.text || "");
  }
  if (eventType === "command") {
    return `$ ${String(payloadJson.submitted_command || payloadJson.generated_command || "")}`.trim();
  }
  return `[${getTaskEventTypeLabel(eventType)}] ${localizeTaskMessage(String(raw.message || ""))}`.trim();
}

function buildAssetDetailPreviewFromSession(
  session: RemediationSession,
  current: RemediationAssetDetail | null,
): RemediationAssetDetail {
  const derivedRunnerInstallBlockedReasons = current?.runner_install_blocked_reasons ?? (
    !session.authorization.credential_bound
      ? ["当前资产未配置 SSH 管理员凭据"]
      : session.authorization.admin_authorized
        ? []
        : ["当前 SSH 凭据尚未确认管理员授权"]
  );
  return {
    asset: session.asset,
    authorization: session.authorization,
    latest_collection: session.latest_collection,
    findings: session.findings,
    runner: session.runner,
    active_session_id: session.session_id,
    active_session_status: session.status,
    latest_task_id: session.last_task_id,
    can_install_runner: current?.can_install_runner ?? derivedRunnerInstallBlockedReasons.length === 0,
    runner_install_blocked_reasons: derivedRunnerInstallBlockedReasons,
  };
}

type WorkbenchViewState = {
  selectedService: string;
  selectedStepState: "all" | "blocked" | "ready";
  expandedStages: Record<string, boolean>;
  planGuideOpen: boolean;
  runnerDetailsOpen: boolean;
  aiOpen: boolean;
  terminalOpen: boolean;
  outputOpen: boolean;
};

const WORKBENCH_STORAGE_PREFIX = "remediation-workbench-v4-single-page";

function buildDefaultWorkbenchViewState(options?: { outputOpen?: boolean }): WorkbenchViewState {
  return {
    selectedService: "",
    selectedStepState: "all",
    expandedStages: {},
    planGuideOpen: false,
    runnerDetailsOpen: false,
    aiOpen: false,
    terminalOpen: false,
    outputOpen: Boolean(options?.outputOpen),
  };
}

function normalizeWorkbenchViewState(rawValue: unknown, fallback: WorkbenchViewState): WorkbenchViewState {
  if (!rawValue || typeof rawValue !== "object" || Array.isArray(rawValue)) {
    return fallback;
  }
  const record = rawValue as Record<string, unknown>;
  return {
    selectedService: typeof record.selectedService === "string" ? record.selectedService : fallback.selectedService,
    selectedStepState: record.selectedStepState === "blocked" || record.selectedStepState === "ready" || record.selectedStepState === "all"
      ? record.selectedStepState
      : fallback.selectedStepState,
    expandedStages: record.expandedStages && typeof record.expandedStages === "object" && !Array.isArray(record.expandedStages)
      ? record.expandedStages as Record<string, boolean>
      : fallback.expandedStages,
    planGuideOpen: typeof record.planGuideOpen === "boolean" ? record.planGuideOpen : fallback.planGuideOpen,
    runnerDetailsOpen: typeof record.runnerDetailsOpen === "boolean" ? record.runnerDetailsOpen : fallback.runnerDetailsOpen,
    aiOpen: typeof record.aiOpen === "boolean" ? record.aiOpen : fallback.aiOpen,
    terminalOpen: typeof record.terminalOpen === "boolean" ? record.terminalOpen : fallback.terminalOpen,
    outputOpen: typeof record.outputOpen === "boolean" ? record.outputOpen : fallback.outputOpen,
  };
}

function readStoredWorkbenchViewState(assetId: string, fallback: WorkbenchViewState): WorkbenchViewState {
  if (typeof window === "undefined") {
    return fallback;
  }
  try {
    const raw = window.localStorage.getItem(`${WORKBENCH_STORAGE_PREFIX}:${assetId}:view`);
    if (!raw) {
      return fallback;
    }
    return normalizeWorkbenchViewState(JSON.parse(raw), fallback);
  } catch {
    return fallback;
  }
}

function writeStoredWorkbenchViewState(assetId: string, state: WorkbenchViewState): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.localStorage.setItem(`${WORKBENCH_STORAGE_PREFIX}:${assetId}:view`, JSON.stringify(state));
  } catch {
    // ignore storage failures
  }
}

export default function HostRemediationSessionView({ assetId }: { assetId: string }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const taskId = searchParams?.get("taskId") || "";
  const focusFindingId = searchParams?.get("findingId") || "";
  const planSectionRef = useRef<HTMLDivElement | null>(null);
  const previousTaskIdRef = useRef("");
  const previousRunningTaskRef = useRef(false);
  const previousStreamVisibleRef = useRef(false);

  const [assetDetail, setAssetDetail] = useState<RemediationAssetDetail | null>(null);
  const [session, setSession] = useState<RemediationSession | null>(null);
  const [task, setTask] = useState<RemediationTask | null>(null);
  const [assetLoading, setAssetLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [taskLoading, setTaskLoading] = useState(false);
  const [taskEvidenceLoading, setTaskEvidenceLoading] = useState(false);
  const [runnerLoading, setRunnerLoading] = useState(false);
  const [approveModeLoading, setApproveModeLoading] = useState<"dry_run" | "apply" | null>(null);
  const [messageLoading, setMessageLoading] = useState(false);
  const [streamLines, setStreamLines] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [aiGenerationPending, setAIGenerationPending] = useState(false);
  const [aiGenerationError, setAIGenerationError] = useState<string | null>(null);
  const [activeTaskId, setActiveTaskId] = useState(taskId);
  const [sessionNote, setSessionNote] = useState("");
  const [changeTicket, setChangeTicket] = useState("");
  const [maintenanceWindowId, setMaintenanceWindowId] = useState("");
  const [taskEvidence, setTaskEvidence] = useState<RemediationTaskEvidence | null>(null);
  const [viewState, setViewState] = useState<WorkbenchViewState>(() => buildDefaultWorkbenchViewState({ outputOpen: Boolean(taskId) }));
  const [expandedCommands, setExpandedCommands] = useState<Record<string, boolean>>({});

  const updateViewState = (updater: (current: WorkbenchViewState) => WorkbenchViewState) => {
    setViewState((current) => updater(current));
  };

  const toggleCommandVisibility = (stepId: string) => {
    setExpandedCommands((current) => ({ ...current, [stepId]: !current[stepId] }));
  };

  const toggleStageVisibility = (stageCode: string) => {
    updateViewState((current) => ({
      ...current,
      expandedStages: {
        ...current.expandedStages,
        [stageCode]: !current.expandedStages[stageCode],
      },
    }));
  };

  const syncRoute = (nextFindingId?: string | null, nextTaskId?: string | null) => {
    router.replace(
      buildRemediationAssetPath(assetId, {
        findingId: nextFindingId || undefined,
        taskId: nextTaskId || undefined,
      }),
    );
  };

  const loadAsset = async (options?: { background?: boolean }) => {
    try {
      setAssetLoading(true);
      const result = await getRemediationAsset(assetId);
      setAssetDetail(result);
      setError(null);
      return result;
    } catch (err) {
      if (!options?.background) {
        setError((err as Error).message);
      }
      return null;
    } finally {
      setAssetLoading(false);
    }
  };

  const applySessionSnapshot = (nextSession: RemediationSession) => {
    setSession(nextSession);
    setAssetDetail((current) => buildAssetDetailPreviewFromSession(nextSession, current));
    if (nextSession.plan.current_stage_code) {
      updateViewState((current) => ({
        ...current,
        expandedStages: {
          ...current.expandedStages,
          [nextSession.plan.current_stage_code as string]: true,
        },
      }));
    }
    if (nextSession.messages.some((item) => item.message_type.startsWith("ai_"))) {
      setAIGenerationPending(false);
      setAIGenerationError(null);
    }
  };

  const loadOrCreateSession = async () => {
    let nextSession: RemediationSession | null = null;
    try {
      setSessionLoading(true);
      nextSession = await createRemediationSession(assetId, {});
      applySessionSnapshot(nextSession);
      setAIGenerationPending(!nextSession.messages.some((item) => item.message_type.startsWith("ai_")));
      setAIGenerationError(null);
      setError(null);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSessionLoading(false);
    }
    if (nextSession && !taskId && !activeTaskId && nextSession.last_task_id) {
      setActiveTaskId(nextSession.last_task_id);
      syncRoute(focusFindingId || undefined, nextSession.last_task_id);
    }
    return nextSession;
  };

  useEffect(() => {
    setActiveTaskId(taskId);
  }, [taskId]);

  useEffect(() => {
    const fallback = buildDefaultWorkbenchViewState({ outputOpen: Boolean(taskId) });
    previousTaskIdRef.current = "";
    previousRunningTaskRef.current = false;
    previousStreamVisibleRef.current = false;
    setAIGenerationPending(false);
    setAIGenerationError(null);
    setExpandedCommands({});
    setViewState(readStoredWorkbenchViewState(assetId, fallback));
  }, [assetId, taskId]);

  useEffect(() => {
    writeStoredWorkbenchViewState(assetId, viewState);
  }, [assetId, viewState]);

  useEffect(() => {
    void loadOrCreateSession().then((nextSession) => {
      if (!nextSession) {
        void loadAsset();
      }
    });
  }, [assetId]);

  useEffect(() => {
    if (!session?.session_id) {
      return undefined;
    }
    const token = getStoredToken();
    if (!token) {
      return undefined;
    }
    const ws = new WebSocket(buildRemediationWebSocketUrl(`/api/v1/remediation/sessions/${session.session_id}/stream`, token));
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as RemediationSessionStreamEnvelope;
        if (payload.type === "session_snapshot") {
          applySessionSnapshot(payload.session);
          if (!activeTaskId && payload.session.last_task_id) {
            setActiveTaskId(payload.session.last_task_id);
          }
          return;
        }
        if (payload.type === "ai_generation_started") {
          setAIGenerationPending(true);
          setAIGenerationError(null);
          return;
        }
        if (payload.type === "session_message_added") {
          setSession((current) => {
            if (!current || current.session_id !== session.session_id) {
              return current;
            }
            if (current.messages.some((item) => item.id === payload.message.id)) {
              return current;
            }
            return {
              ...current,
              messages: [...current.messages, payload.message],
            };
          });
          if (payload.message.message_type.startsWith("ai_")) {
            setAIGenerationPending(false);
            setAIGenerationError(null);
            updateViewState((current) => ({ ...current, aiOpen: true }));
          }
          return;
        }
        if (payload.type === "error") {
          setAIGenerationPending(false);
          setAIGenerationError(payload.message);
        }
      } catch {
        // ignore malformed stream frames
      }
    };
    return () => ws.close();
  }, [session?.session_id, activeTaskId]);

  useEffect(() => {
    if (!activeTaskId) {
      setTask(null);
      setTaskEvidence(null);
      setStreamLines([]);
      return;
    }
    setTaskLoading(true);
    getRemediationTask(activeTaskId)
      .then((result) => {
        setTask(result);
        setError(null);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setTaskLoading(false));
  }, [activeTaskId]);

  useEffect(() => {
    if (!activeTaskId) {
      setTaskEvidence(null);
      return;
    }
    setTaskEvidenceLoading(true);
    getRemediationTaskEvidence(activeTaskId)
      .then((result) => setTaskEvidence(result))
      .catch(() => setTaskEvidence(null))
      .finally(() => setTaskEvidenceLoading(false));
  }, [activeTaskId]);

  useEffect(() => {
    if (!activeTaskId) {
      return undefined;
    }
    const token = getStoredToken();
    if (!token) {
      return undefined;
    }
    const ws = new WebSocket(buildRemediationWebSocketUrl(`/api/v1/remediation/tasks/${activeTaskId}/stream`, token));
    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data) as RemediationStreamEnvelope;
        if (payload.type === "task") {
          setTask((current) =>
            current
              ? {
                  ...current,
                  status: payload.task.status as RemediationTask["status"],
                  progress: payload.task.progress,
                  message: payload.task.message,
                }
              : current,
          );
          return;
        }
        const nextLine = buildTaskStreamLine(payload);
        if (nextLine) {
          setStreamLines((current) => [...current.slice(-199), nextLine]);
          return;
        }
        if (payload.type === "complete") {
          void getRemediationTask(activeTaskId).then((result) => {
            setTask(result);
            void getRemediationTaskEvidence(activeTaskId).then(setTaskEvidence).catch(() => undefined);
            if (!isTaskRunning(result.status)) {
              void loadOrCreateSession();
            }
          });
        }
      } catch {
        // ignore malformed stream frames
      }
    };
    return () => ws.close();
  }, [activeTaskId, assetId, focusFindingId, taskId]);

  useEffect(() => {
    if (!activeTaskId || !task || !isTaskRunning(task.status)) {
      return undefined;
    }
    const timer = window.setInterval(() => {
      void getRemediationTask(activeTaskId)
        .then((result) => {
          setTask(result);
          if (!isTaskRunning(result.status)) {
            void getRemediationTaskEvidence(activeTaskId).then(setTaskEvidence).catch(() => undefined);
          }
          if (!isTaskRunning(result.status)) {
            void loadOrCreateSession();
          }
        })
        .catch(() => undefined);
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activeTaskId, assetId, focusFindingId, task, taskId]);

  const findings = session?.findings || assetDetail?.findings || [];
  const singleFindingId = findings.length === 1 ? findings[0].finding_id : "";
  const effectiveFindingId = findings.some((item) => item.finding_id === focusFindingId)
    ? focusFindingId
    : !focusFindingId && singleFindingId
      ? singleFindingId
      : "";
  const selectedFinding = findings.find((item) => item.finding_id === effectiveFindingId) || null;

  useEffect(() => {
    if (!focusFindingId && singleFindingId) {
      syncRoute(singleFindingId, activeTaskId || undefined);
    }
  }, [activeTaskId, focusFindingId, singleFindingId]);

  useEffect(() => {
    if (!effectiveFindingId || !planSectionRef.current) {
      return;
    }
    window.setTimeout(() => {
      planSectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 80);
  }, [effectiveFindingId]);

  const plan = session?.plan || null;
  const planStages = plan?.stages || [];
  const currentStage =
    planStages.find((item) => item.stage_code === plan?.current_stage_code)
    || planStages.find((item) => item.gate_status === "running")
    || planStages.find((item) => item.gate_status === "ready")
    || planStages.find((item) => item.gate_status === "blocked")
    || planStages[0]
    || null;
  const approvableStage = planStages.find((item) => item.gate_status === "ready") || null;

  useEffect(() => {
    if (!currentStage?.stage_code) {
      return;
    }
    updateViewState((current) => {
      if (current.expandedStages[currentStage.stage_code]) {
        return current;
      }
      return {
        ...current,
        expandedStages: {
          ...current.expandedStages,
          [currentStage.stage_code]: true,
        },
      };
    });
  }, [currentStage?.stage_code]);

  useEffect(() => {
    if (!effectiveFindingId) {
      return;
    }
    const relatedStages = planStages
      .filter((stage) => stage.related_finding_ids.includes(effectiveFindingId))
      .map((stage) => stage.stage_code);
    if (!relatedStages.length) {
      return;
    }
    updateViewState((current) => {
      let changed = false;
      const nextExpandedStages = { ...current.expandedStages };
      for (const stageCode of relatedStages) {
        if (!nextExpandedStages[stageCode]) {
          nextExpandedStages[stageCode] = true;
          changed = true;
        }
      }
      return changed ? { ...current, expandedStages: nextExpandedStages } : current;
    });
  }, [effectiveFindingId, session?.session_id]);

  const availableServices: string[] = [];
  for (const serviceName of plan?.impacted_services || []) {
    const normalized = String(serviceName || "").trim();
    if (normalized && !availableServices.includes(normalized)) {
      availableServices.push(normalized);
    }
  }
  for (const stage of planStages) {
    for (const serviceName of stage.related_services) {
      const normalized = String(serviceName || "").trim();
      if (normalized && !availableServices.includes(normalized)) {
        availableServices.push(normalized);
      }
    }
  }

  const matchesFindingFilter = (step: HostRemediationPlanStep): boolean => {
    if (!effectiveFindingId) {
      return true;
    }
    if (step.finding_id === effectiveFindingId) {
      return true;
    }
    return step.related_findings.some((item) => item.finding_id === effectiveFindingId);
  };

  const matchesServiceFilter = (stage: HostRemediationStage, step: HostRemediationPlanStep): boolean => {
    if (!viewState.selectedService) {
      return true;
    }
    if (String(step.service_name || "").trim() === viewState.selectedService) {
      return true;
    }
    if (step.target_services.includes(viewState.selectedService)) {
      return true;
    }
    return stage.related_services.includes(viewState.selectedService);
  };

  const matchesStateFilter = (step: HostRemediationPlanStep): boolean => {
    if (viewState.selectedStepState === "all") {
      return true;
    }
    return step.execution_state === viewState.selectedStepState;
  };

  const hasStageFilters = Boolean(effectiveFindingId || viewState.selectedService || viewState.selectedStepState !== "all");
  const filteredStages = planStages
    .map((stage) => {
      const filteredStageSteps = stage.steps.filter(
        (step) => matchesFindingFilter(step) && matchesServiceFilter(stage, step) && matchesStateFilter(step),
      );
      const showStage =
        !hasStageFilters
        || filteredStageSteps.length > 0
        || (effectiveFindingId ? stage.related_finding_ids.includes(effectiveFindingId) : false)
        || (viewState.selectedService ? stage.related_services.includes(viewState.selectedService) : false)
        || stage.stage_code === currentStage?.stage_code;
      return {
        ...stage,
        filtered_steps: filteredStageSteps,
        visible: showStage,
      };
    })
    .filter((stage) => stage.visible);

  const filteredStepTotal = filteredStages.reduce((total, stage) => total + stage.filtered_steps.length, 0);
  const filteredReadyStepCount = filteredStages.reduce(
    (total, stage) => total + stage.filtered_steps.filter((step) => step.execution_state === "ready").length,
    0,
  );
  const filteredBlockedStepCount = filteredStages.reduce(
    (total, stage) => total + stage.filtered_steps.filter((step) => step.execution_state === "blocked").length,
    0,
  );
  const filteredBlockedMessages = Array.from(
    new Set(
      filteredStages.flatMap((stage) => [
        ...stage.global_blockers.map((item) => item.message),
        ...stage.filtered_steps.flatMap((step) => step.blockers.map((item) => item.message)),
      ]),
    ),
  );
  const globalBlockedMessages = Array.from(
    new Set([
      ...(assetDetail?.authorization.blocked_reasons || []),
      ...(assetDetail?.runner_install_blocked_reasons || []),
      ...(plan?.global_blockers || []).map((item) => item.message),
    ]),
  );

  const latestMessages = session?.messages || [];
  const latestAiMessage = [...latestMessages].reverse().find((item) => item.message_type.startsWith("ai_")) || null;
  const stepResults = Array.isArray(toRecord(task?.execution).step_results)
    ? (toRecord(task?.execution).step_results as Array<Record<string, unknown>>)
    : [];
  const runningTask = Boolean(task && isTaskRunning(task.status));
  const latestAuditMessage = latestMessages.length ? latestMessages[latestMessages.length - 1] : null;
  const focusedRiskLabel = selectedFinding ? selectedFinding.title : "全部风险";
  const serviceFilterLabel = viewState.selectedService ? `服务筛选：${viewState.selectedService}` : "服务筛选：全部服务";
  const stepStateFilterLabel = viewState.selectedStepState === "all"
    ? "步骤：全部"
    : viewState.selectedStepState === "ready"
      ? "步骤：仅可执行"
      : "步骤：仅阻塞";
  const taskOutputSummary = task
    ? `${localizeTaskMessage(remediationResolvedTaskMessage(task.message, task.execution_status, task.business_status)) || `当前任务状态：${task.status}`}${task.business_status || task.execution_status ? ` · ${remediationExecutionOutcomeLabel(task.execution_status, task.business_status)}` : ""}`
    : activeTaskId
      ? `已关联任务 ${activeTaskId}`
      : "当前暂无任务输出";
  const terminalBlockedReasons = assetDetail
    ? [
        ...(!assetDetail.authorization.credential_bound ? ["当前资产未配置 SSH 管理员凭据"] : []),
        ...(assetDetail.authorization.admin_authorized ? [] : ["当前 SSH 凭据尚未确认管理员授权"]),
        ...(String(assetDetail.authorization.last_verification_status || "").trim().toLowerCase() === "success"
          ? []
          : ["当前 SSH 凭据尚未完成管理员权限验证"]),
        ...(["root", "sudo"].includes(String(assetDetail.authorization.effective_privilege || "").trim().toLowerCase())
          ? []
          : ["当前 SSH 凭据未验证到管理员权限"]),
      ]
    : ["暂无资产上下文"];
  const terminalEnabled = Boolean(assetDetail && terminalBlockedReasons.length === 0);
  const terminalAssetLabel = assetDetail?.asset.hostname || assetDetail?.asset.ip || assetId;

  useEffect(() => {
    if (activeTaskId && previousTaskIdRef.current !== activeTaskId) {
      updateViewState((current) => ({ ...current, outputOpen: true }));
    }
    previousTaskIdRef.current = activeTaskId;
  }, [activeTaskId]);

  useEffect(() => {
    if (runningTask && !previousRunningTaskRef.current) {
      updateViewState((current) => ({ ...current, outputOpen: true }));
    }
    previousRunningTaskRef.current = runningTask;
  }, [runningTask]);

  useEffect(() => {
    const hasVisibleStream = streamLines.length > 0;
    if (hasVisibleStream && !previousStreamVisibleRef.current) {
      updateViewState((current) => ({ ...current, outputOpen: true }));
    }
    previousStreamVisibleRef.current = hasVisibleStream;
  }, [streamLines.length]);

  const onRefresh = async () => {
    const nextSession = await loadOrCreateSession();
    if (!nextSession) {
      await loadAsset();
    }
    if (activeTaskId) {
      try {
        setTaskLoading(true);
        const refreshedTask = await getRemediationTask(activeTaskId);
        setTask(refreshedTask);
        const refreshedEvidence = await getRemediationTaskEvidence(activeTaskId).catch(() => null);
        setTaskEvidence(refreshedEvidence);
      } catch {
        // ignore task refresh failures and keep current task state
      } finally {
        setTaskLoading(false);
      }
    }
  };

  const onInstallRunner = async () => {
    try {
      setRunnerLoading(true);
      const response = await installAssetRunner(assetId);
      message.success(`Host Runner 安装任务已提交：${response.task_id}`);
      setStreamLines([]);
      setActiveTaskId(response.task_id);
      updateViewState((current) => ({ ...current, outputOpen: true }));
      syncRoute(effectiveFindingId || undefined, response.task_id);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setRunnerLoading(false);
    }
  };

  const onApprove = async (
    executionMode: "dry_run" | "apply",
    targetStage?: Pick<HostRemediationStage, "stage_code" | "stage_name"> | null,
  ) => {
    const stageToApprove = targetStage || approvableStage;
    if (!session || !stageToApprove) {
      return;
    }
    try {
      setApproveModeLoading(executionMode);
      const response = await approveRemediationSession(session.session_id, {
        stage_code: stageToApprove.stage_code,
        execution_mode: executionMode,
        change_ticket: changeTicket.trim() || null,
        maintenance_window_id: maintenanceWindowId.trim() || null,
      });
      message.success(
        executionMode === "dry_run"
          ? `阶段“${stageToApprove.stage_name}”预演已生成：${response.task_id}`
          : `阶段“${stageToApprove.stage_name}”修复任务已提交：${response.task_id}`,
      );
      setStreamLines([]);
      setActiveTaskId(response.task_id);
      updateViewState((current) => ({ ...current, outputOpen: true }));
      syncRoute(effectiveFindingId || undefined, response.task_id);
      const refreshedSession = await getRemediationSession(session.session_id);
      applySessionSnapshot(refreshedSession);
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setApproveModeLoading(null);
    }
  };

  const onAppendAuditNote = async () => {
    if (!session || !sessionNote.trim()) {
      return;
    }
    try {
      setMessageLoading(true);
      const result = await postRemediationSessionMessage(session.session_id, {
        intent: "note",
        note: sessionNote.trim(),
      });
      applySessionSnapshot(result);
      setSessionNote("");
      updateViewState((current) => ({ ...current, aiOpen: true }));
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setMessageLoading(false);
    }
  };

  const onExplainBlockers = async () => {
    if (!session) {
      return;
    }
    try {
      setMessageLoading(true);
      setAIGenerationPending(true);
      setAIGenerationError(null);
      updateViewState((current) => ({ ...current, aiOpen: true }));
      const result = await postRemediationSessionMessage(session.session_id, {
        intent: "explain_blockers",
      });
      applySessionSnapshot(result);
    } catch (err) {
      setAIGenerationPending(false);
      message.error((err as Error).message);
    } finally {
      setMessageLoading(false);
    }
  };

  const onRefreshAI = async () => {
    if (!session) {
      return;
    }
    try {
      setMessageLoading(true);
      setAIGenerationPending(true);
      setAIGenerationError(null);
      updateViewState((current) => ({ ...current, aiOpen: true }));
      const result = await postRemediationSessionMessage(session.session_id, {
        intent: "refresh_ai",
      });
      applySessionSnapshot(result);
    } catch (err) {
      setAIGenerationPending(false);
      message.error((err as Error).message);
    } finally {
      setMessageLoading(false);
    }
  };

  const onSelectFinding = (nextFindingId?: string | null) => {
    syncRoute(nextFindingId || undefined, activeTaskId || undefined);
  };

  const canRepairStage = (stage: HostRemediationStage): boolean => (
    Boolean(
      session
      && approvableStage
      && approvableStage.stage_code === stage.stage_code
      && session.status !== "running"
      && !approveModeLoading,
    )
  );

  const stageRepairButtonLabel = (stage: HostRemediationStage): string => {
    if (approvableStage?.stage_code === stage.stage_code) {
      if (session?.status === "running") {
        return "执行中";
      }
      if (approveModeLoading === "apply") {
        return "提交中";
      }
      return "修复该阶段";
    }
    switch (stage.gate_status) {
      case "completed":
        return "阶段已完成";
      case "running":
        return "执行中";
      case "blocked":
        return "存在阻塞";
      case "locked":
        return "等待解锁";
      default:
        return "仅当前阶段可执行";
    }
  };

  const renderStageCard = (stage: HostRemediationStage & { filtered_steps: HostRemediationPlanStep[] }) => {
    const stageExpanded = viewState.expandedStages[stage.stage_code] ?? (
      stage.stage_code === currentStage?.stage_code
      || (effectiveFindingId ? stage.related_finding_ids.includes(effectiveFindingId) : false)
    );

    return (
      <div
        key={stage.stage_code}
        className={`remediation-stage-card${stage.stage_code === currentStage?.stage_code ? " remediation-stage-card-current" : ""}`}
      >
        <div className="remediation-stage-card-header">
          <Space direction="vertical" size={8} style={{ flex: 1 }}>
            <Space wrap>
              <Typography.Text strong>{stage.stage_name}</Typography.Text>
              <Tag color={stageGateColor(stage.gate_status)}>{stageGateLabel(stage.gate_status)}</Tag>
              <Tag color="green">可执行 {stage.ready_step_count}</Tag>
              {stage.blocked_step_count ? <Tag color="orange">阻塞 {stage.blocked_step_count}</Tag> : null}
              {stage.business_status ? (
                <Tag color={remediationBusinessStatusColor(stage.business_status)}>
                  {remediationBusinessStatusLabel(stage.business_status)}
                </Tag>
              ) : null}
            </Space>
            <Typography.Text type="secondary" className="ui-detail-wrap">
              {stage.summary}
            </Typography.Text>
          </Space>
          <Space wrap>
            <Button
              size="small"
              type={canRepairStage(stage) ? "primary" : "default"}
              loading={approveModeLoading === "apply" && approvableStage?.stage_code === stage.stage_code}
              disabled={!canRepairStage(stage)}
              onClick={() => void onApprove("apply", stage)}
            >
              {stageRepairButtonLabel(stage)}
            </Button>
            <Button size="small" onClick={() => toggleStageVisibility(stage.stage_code)}>
              {stageExpanded ? "收起阶段" : "展开阶段"}
            </Button>
          </Space>
        </div>

        <div className="remediation-stage-meta">
          {stage.related_services.length ? <Tag>{`服务：${stage.related_services.join("、")}`}</Tag> : null}
          <Tag>{`${stage.related_finding_ids.length} 条关联风险`}</Tag>
          <Tag>{`${stage.filtered_steps.length} 个匹配步骤`}</Tag>
          {stage.targeted_rule_ids.length ? <Tag>{`目标规则 ${stage.targeted_rule_ids.length}`}</Tag> : null}
          {stage.business_status ? <Tag>{`已关闭 ${stage.closed_target_count} / 仍开放 ${stage.open_target_count}`}</Tag> : null}
        </div>

        {stage.global_blockers.length ? (
          <Alert
            type={stage.gate_status === "locked" ? "info" : "warning"}
            showIcon
            message={stage.gate_status === "locked" ? "该阶段尚未解锁" : "该阶段存在全局阻塞"}
            description={stage.global_blockers.map((item) => item.message).join("；")}
          />
        ) : null}

        {stageExpanded ? (
          stage.filtered_steps.length ? (
            <List
              dataSource={stage.filtered_steps}
              renderItem={(step) => {
                const commandExpanded = Boolean(expandedCommands[step.step_id]);
                const relatedFindingLabels = step.related_findings
                  .map((item) => String(item.title || "").trim())
                  .filter(Boolean);
                return (
                  <List.Item className="remediation-step-list-item">
                    <div className="remediation-step-card">
                      <div className="remediation-step-card-header">
                        <Space wrap>
                          <Typography.Text strong>{step.title}</Typography.Text>
                          <Tag color={step.execution_state === "ready" ? "green" : "orange"}>
                            {step.execution_state === "ready" ? "Runner 可执行" : "阻塞"}
                          </Tag>
                          <Tag color={stepRiskColor(step.risk_level)}>风险 {step.risk_level}</Tag>
                          {step.dry_run_supported ? <Tag color="blue">支持预演</Tag> : null}
                          <Tag color={step.rollback_supported ? "green" : "default"}>
                            {step.rollback_supported ? "支持回滚" : "回滚受限"}
                          </Tag>
                          {step.requires_maintenance_window ? <Tag color="magenta">需维护窗口</Tag> : null}
                          <Tag>{step.phase_name}</Tag>
                          {step.service_name ? <Tag>{step.service_name}</Tag> : null}
                          {step.fallback_strategy === "legacy_debian_auto_guess" ? <Tag color="gold">旧版 Debian 自动解析</Tag> : null}
                          {relatedFindingLabels.slice(0, 2).map((label) => (
                            <Tag key={`${step.step_id}:${label}`} color="blue">
                              {label}
                            </Tag>
                          ))}
                          {relatedFindingLabels.length > 2 ? <Tag color="blue">+{relatedFindingLabels.length - 2} 条风险</Tag> : null}
                        </Space>
                        {step.generated_command ? (
                          <Button size="small" onClick={() => toggleCommandVisibility(step.step_id)}>
                            {commandExpanded ? "收起命令" : "查看命令"}
                          </Button>
                        ) : null}
                      </div>

                      {step.render_reason ? (
                        <Typography.Text type="secondary" className="ui-detail-wrap">
                          {step.render_reason}
                        </Typography.Text>
                      ) : null}

                      {step.blockers.length ? (
                        <Alert
                          type="warning"
                          showIcon
                          message={Array.from(new Set(step.blockers.map((item) => item.message))).join("；")}
                        />
                      ) : null}

                      {!step.apply_supported && step.apply_blocked_reason ? (
                        <Alert
                          type="info"
                          showIcon
                          message={`正式执行前需补齐条件：${step.apply_blocked_reason}`}
                        />
                      ) : null}

                      {step.fallback_strategy === "legacy_debian_auto_guess" && step.fallback_candidates.length ? (
                        <Space direction="vertical" size={4} style={{ width: "100%" }}>
                          <Typography.Text type="secondary" className="ui-detail-wrap">
                            候选包/服务: {step.fallback_candidates.join("、")}
                          </Typography.Text>
                          {step.fallback_candidates.length > 1 ? (
                            <Alert
                              type="info"
                              showIcon
                              message="该步骤可能在同族组件之间自动切换或补装，请先确认老机上的实际组件与配置差异。"
                            />
                          ) : null}
                        </Space>
                      ) : null}

                      {step.backup_plan ? (
                        <Typography.Text type="secondary" className="ui-detail-wrap">
                          备份: {step.backup_plan.kind} / {step.backup_plan.targets.join("、") || "-"}
                        </Typography.Text>
                      ) : null}
                      <Typography.Text type="secondary" className="ui-detail-wrap">
                        适配器: {step.adapter_id || "-"} / {step.adapter_version || "-"}
                      </Typography.Text>
                      {step.evidence_items.length ? (
                        <Typography.Text type="secondary" className="ui-detail-wrap">
                          证据项: {step.evidence_items.join("、")}
                        </Typography.Text>
                      ) : null}

                      <div className="remediation-step-metadata">
                        {step.target_files.length ? (
                          <Typography.Text type="secondary" className="ui-detail-wrap">
                            目标文件: {step.target_files.join("、")}
                          </Typography.Text>
                        ) : null}
                        {step.target_services.length ? (
                          <Typography.Text type="secondary" className="ui-detail-wrap">
                            目标服务: {step.target_services.join("、")}
                          </Typography.Text>
                        ) : null}
                        {step.target_paths.length ? (
                          <Typography.Text type="secondary" className="ui-detail-wrap">
                            目标路径: {step.target_paths.join("、")}
                          </Typography.Text>
                        ) : null}
                      </div>

                      {step.verify_items.length ? (
                        <Space direction="vertical" size={2} style={{ width: "100%" }}>
                          <Typography.Text type="secondary">步骤验证</Typography.Text>
                          {step.verify_items.map((item) => (
                            <Typography.Text key={item} type="secondary" className="ui-detail-wrap">
                              • {item}
                            </Typography.Text>
                          ))}
                        </Space>
                      ) : null}

                      <RollbackArtifactPanel
                        rollbackHint={step.rollback_hint}
                        rollbackCommand={step.rollback_command}
                      />

                      {commandExpanded && step.generated_command ? (
                        <Space direction="vertical" size={8} style={{ width: "100%" }}>
                          <Input.TextArea
                            className="remediation-workbench-command"
                            rows={step.execution_state === "ready" ? 5 : 3}
                            value={step.generated_command}
                            readOnly
                          />
                        </Space>
                      ) : null}
                    </div>
                  </List.Item>
                );
              }}
            />
          ) : (
            <Empty description="当前筛选条件下，该阶段没有匹配步骤。" />
          )
        ) : null}
      </div>
    );
  };

  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      {error ? <Alert type="error" showIcon message={error} /> : null}

      <div className="remediation-summary-grid">
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">资产</span>
          <strong className="remediation-summary-value">{assetDetail?.asset.hostname || assetDetail?.asset.ip || assetId}</strong>
          <span className="remediation-summary-detail">{assetDetail?.asset.os_name || "未识别系统"}</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">工作台状态</span>
          <strong className="remediation-summary-value">{workbenchStatusLabel(session?.status)}</strong>
          <span className="remediation-summary-detail">{plan ? planModeLabel(plan.plan_mode) : "等待会话准备"}</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">当前阶段</span>
          <strong className="remediation-summary-value">{currentStage?.stage_name || "未生成"}</strong>
          <span className="remediation-summary-detail">{currentStage ? stageGateLabel(currentStage.gate_status) : "暂无阶段"}</span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">Runner</span>
          <strong className="remediation-summary-value">{assetDetail?.runner.status || "unknown"}</strong>
          <span className="remediation-summary-detail">
            {assetDetail ? `${runnerRuntimeLabel(assetDetail.runner.runtime_kind)} / ${runnerInstallModeLabel(assetDetail.runner.install_mode)}` : "等待上下文"}
          </span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">SSH 授权</span>
          <strong className="remediation-summary-value">{assetDetail?.authorization.effective_privilege || "未验证"}</strong>
          <span className="remediation-summary-detail">
            {assetDetail ? localizeTaskMessage(assetDetail.authorization.last_verification_status) || assetDetail.authorization.last_verification_status || "未验证" : "等待上下文"}
          </span>
        </div>
        <div className="remediation-summary-card">
          <span className="remediation-summary-label">活动任务</span>
          <strong className="remediation-summary-value">{activeTaskId || "无"}</strong>
          <span className="remediation-summary-detail">{taskOutputSummary}</span>
        </div>
      </div>

      <div className="remediation-workbench-shell">
        <Row gutter={[16, 16]} align="top">
          <Col xs={24} xl={8}>
            <div className="remediation-workbench-sidebar">
              <Card
                className="panel-card"
                loading={assetLoading}
                title="前置条件"
                extra={(
                  <Space wrap className="remediation-workbench-card-extra">
                    <Button
                      size="small"
                      onClick={() => updateViewState((current) => ({ ...current, runnerDetailsOpen: !current.runnerDetailsOpen }))}
                    >
                      {viewState.runnerDetailsOpen ? "收起详细环境" : "展开详细环境"}
                    </Button>
                  </Space>
                )}
              >
                {assetDetail ? (
                  <Space direction="vertical" size={12} style={{ width: "100%" }}>
                    <Descriptions column={1} size="small" bordered>
                      <Descriptions.Item label="资产">{assetDetail.asset.hostname || assetDetail.asset.ip}</Descriptions.Item>
                      <Descriptions.Item label="系统">{assetDetail.asset.os_name || "-"}</Descriptions.Item>
                      <Descriptions.Item label="工作台状态">
                        <StatusTag value={session?.status || assetDetail.active_session_status || "draft"} />
                      </Descriptions.Item>
                      <Descriptions.Item label="SSH 授权">
                        <Space wrap>
                          <StatusTag value={assetDetail.authorization.last_verification_status || "unknown"} />
                          <Typography.Text>{assetDetail.authorization.effective_privilege || "-"}</Typography.Text>
                        </Space>
                      </Descriptions.Item>
                      <Descriptions.Item label="Runner">
                        <Space wrap>
                          <StatusTag value={assetDetail.runner.status} />
                          <Tag>{assetDetail.runner.install_status}</Tag>
                          {assetDetail.runner.version ? <Tag>v{assetDetail.runner.version}</Tag> : null}
                          {assetDetail.runner.install_mode ? (
                            <Tag color={assetDetail.runner.install_mode === "user" ? "gold" : "blue"}>
                              {runnerInstallModeLabel(assetDetail.runner.install_mode)}
                            </Tag>
                          ) : null}
                          {assetDetail.runner.service_mode ? <Tag>{runnerServiceModeLabel(assetDetail.runner.service_mode)}</Tag> : null}
                        </Space>
                      </Descriptions.Item>
                      <Descriptions.Item label="最近深度检查">
                        {formatDateTime(assetDetail.latest_collection?.collected_at || null)}
                      </Descriptions.Item>
                    </Descriptions>

                    {viewState.runnerDetailsOpen ? (
                      <Descriptions column={1} size="small" bordered>
                        <Descriptions.Item label="运行时">{runnerRuntimeLabel(assetDetail.runner.runtime_kind)}</Descriptions.Item>
                        <Descriptions.Item label="安装模式">{runnerInstallModeLabel(assetDetail.runner.install_mode)}</Descriptions.Item>
                        <Descriptions.Item label="托管方式">{runnerServiceModeLabel(assetDetail.runner.service_mode)}</Descriptions.Item>
                        <Descriptions.Item label="系统架构">
                          {[assetDetail.runner.detected_os, assetDetail.runner.detected_arch].filter(Boolean).join(" / ") || "-"}
                        </Descriptions.Item>
                        <Descriptions.Item label="自恢复能力">
                          {assetDetail.runner.install_status === "installed" && assetDetail.runner.service_mode && assetDetail.runner.service_mode !== "detached"
                            ? "支持"
                            : "不保证"}
                        </Descriptions.Item>
                        <Descriptions.Item label="最近验证">{formatDateTime(assetDetail.authorization.last_verified_at)}</Descriptions.Item>
                      </Descriptions>
                    ) : (
                      <div className="remediation-workbench-collapsed-summary">
                        <Tag color={assetDetail.authorization.blocked_reasons.length ? "orange" : "green"}>
                          {assetDetail.authorization.blocked_reasons.length ? "存在阻塞" : "前置条件正常"}
                        </Tag>
                        <Tag>{`Runner：${assetDetail.runner.install_status}`}</Tag>
                        <Typography.Text type="secondary">
                          最近深度检查：{formatDateTime(assetDetail.latest_collection?.collected_at || null)}
                        </Typography.Text>
                      </div>
                    )}

                    {assetDetail.authorization.blocked_reasons.length ? (
                      <Alert
                        type="warning"
                        showIcon
                        message="当前存在修复阻塞"
                        description={assetDetail.authorization.blocked_reasons.join("；")}
                      />
                    ) : null}
                    {assetDetail.runner.install_status === "installed" && assetDetail.runner.install_mode === "user" ? (
                      <Alert
                        type="info"
                        showIcon
                        message="Host Runner 已改用用户态安装"
                        description={`当前托管方式为 ${runnerServiceModeLabel(assetDetail.runner.service_mode)}。`}
                      />
                    ) : null}
                    {assetDetail.runner.compatibility_issues.length ? (
                      <Alert
                        type="info"
                        showIcon
                        message="当前 Runner 兼容性说明"
                        description={assetDetail.runner.compatibility_issues.join("；")}
                      />
                    ) : null}
                    {assetDetail.runner_install_blocked_reasons.length ? (
                      <Alert
                        type="warning"
                        showIcon
                        message="当前无法安装 Host Runner"
                        description={assetDetail.runner_install_blocked_reasons.join("；")}
                      />
                    ) : null}
                  </Space>
                ) : (
                  <Empty description="暂无资产上下文" />
                )}
              </Card>

              <Card
                className="panel-card"
                title="执行动作"
                extra={(
                  <Space wrap className="remediation-workbench-card-extra">
                    {currentStage ? <Tag color={stageGateColor(currentStage.gate_status)}>{stageGateLabel(currentStage.gate_status)}</Tag> : null}
                  </Space>
                )}
              >
                <Space direction="vertical" size={12} style={{ width: "100%" }}>
                  {currentStage ? (
                    <Descriptions column={1} size="small" bordered>
                      <Descriptions.Item label="当前阶段">
                        <Space wrap>
                          <Typography.Text strong>{currentStage.stage_name}</Typography.Text>
                          <Tag color={stageGateColor(currentStage.gate_status)}>{stageGateLabel(currentStage.gate_status)}</Tag>
                        </Space>
                      </Descriptions.Item>
                      <Descriptions.Item label="计划状态">
                        <Tag color={planModeColor(plan?.plan_mode)}>{planModeLabel(plan?.plan_mode)}</Tag>
                      </Descriptions.Item>
                      <Descriptions.Item label="阶段步骤">
                        {`${currentStage.ready_step_count} 个可执行，${currentStage.blocked_step_count} 个阻塞`}
                      </Descriptions.Item>
                      <Descriptions.Item label="关联范围">
                        {currentStage.related_services.length
                          ? currentStage.related_services.join("、")
                          : `${currentStage.related_finding_ids.length} 条风险`}
                      </Descriptions.Item>
                    </Descriptions>
                  ) : (
                    <Empty description="当前尚未生成可执行阶段。" />
                  )}

                  {runningTask ? (
                    <Alert type="info" showIcon message="当前任务正在执行中，可在右侧任务输出中继续查看流式输出。" />
                  ) : null}

                  <Space direction="vertical" size={8} style={{ width: "100%" }}>
                    <Input
                      placeholder="可选：变更单号 / change ticket"
                      value={changeTicket}
                      onChange={(event) => setChangeTicket(event.target.value)}
                    />
                    <Input
                      placeholder="可选：维护窗口 ID（高风险步骤正式执行时建议填写）"
                      value={maintenanceWindowId}
                      onChange={(event) => setMaintenanceWindowId(event.target.value)}
                    />
                  </Space>

                  <Space wrap>
                    <Button onClick={() => router.push("/remediation")}>返回资产选择</Button>
                    <Button
                      type="primary"
                      onClick={() => void onApprove("dry_run")}
                      loading={approveModeLoading === "dry_run"}
                      disabled={!approvableStage || session?.status === "running"}
                    >
                      {approvableStage ? `生成当前阶段预演：${approvableStage.stage_name}` : "暂无可预演阶段"}
                    </Button>
                    <Button
                      onClick={() => void onApprove("apply")}
                      loading={approveModeLoading === "apply"}
                      disabled={!approvableStage || session?.status === "running"}
                    >
                      {approvableStage ? `确认执行当前阶段：${approvableStage.stage_name}` : "暂无可执行阶段"}
                    </Button>
                    <Button
                      onClick={() => void onInstallRunner()}
                      loading={runnerLoading}
                      disabled={!assetDetail?.can_install_runner}
                    >
                      {assetDetail?.runner.install_status === "installed" ? "重装 Runner" : "安装 Runner"}
                    </Button>
                    <Button onClick={() => void onRefresh()} loading={assetLoading || sessionLoading || taskLoading}>
                      刷新计划
                    </Button>
                    <Button onClick={() => activeTaskId && router.push(`/tasks/${activeTaskId}`)} disabled={!activeTaskId}>
                      打开任务页
                    </Button>
                  </Space>

                  {approvableStage ? (
                    <Alert
                      type="success"
                      showIcon
                      message={`当前可审批阶段：${approvableStage.stage_name}`}
                      description={`该阶段包含 ${approvableStage.ready_step_count} 个可执行步骤。你可以先生成预演检查命令、证据项和维护窗口要求；确认后再正式提交当前阶段。`}
                    />
                  ) : currentStage?.gate_status === "blocked" ? (
                    <Alert
                      type="warning"
                      showIcon
                      message={`当前阶段“${currentStage.stage_name}”存在阻塞`}
                      description={[
                        ...currentStage.global_blockers.map((item) => item.message),
                        ...currentStage.steps
                          .filter((step) => step.execution_state === "blocked")
                          .flatMap((step) => step.blockers.map((item) => item.message)),
                      ].join("；") || "请先补齐前置条件后再执行。"}
                    />
                  ) : currentStage?.gate_status === "locked" ? (
                    <Alert
                      type="info"
                      showIcon
                      message={`阶段“${currentStage.stage_name}”尚未解锁`}
                      description="当前仅允许按顺序推进，需等待更早阶段完成后才会开放审批。"
                    />
                  ) : (
                    <Alert
                      type="info"
                      showIcon
                      message="当前整机计划已收口到阶段推进模式"
                      description="系统只允许审批当前最早可执行阶段，避免跨阶段并发执行造成状态漂移。"
                    />
                  )}
                </Space>
              </Card>
            </div>
          </Col>

          <Col xs={24} xl={16}>
            <div className="remediation-workbench-main">
              <div ref={planSectionRef}>
                <Card
                  className="panel-card"
                  loading={sessionLoading}
                  title="整机修复计划"
                  extra={(
                    <Space wrap className="remediation-workbench-card-extra">
                      <Button
                        size="small"
                        onClick={() => updateViewState((current) => ({ ...current, planGuideOpen: !current.planGuideOpen }))}
                      >
                        {viewState.planGuideOpen ? "收起计划说明" : "展开计划说明"}
                      </Button>
                    </Space>
                  )}
                >
                  {!session ? (
                    <Empty description="正在载入当前资产的整机修复计划。" />
                  ) : !findings.length ? (
                    <Empty description="当前资产暂无可自动修复风险，工作台仅保留前置条件和任务输出。" />
                  ) : (
                    <Space direction="vertical" size={12} style={{ width: "100%" }}>
                      <Space wrap>
                        <StatusTag value={session.status} />
                        <Tag color={planModeColor(plan?.plan_mode)}>{planModeLabel(plan?.plan_mode)}</Tag>
                        {currentStage ? <Tag color={stageGateColor(currentStage.gate_status)}>{`当前阶段：${currentStage.stage_name}`}</Tag> : null}
                        <Tag color="blue">{session.plan.findings_covered_count} 条风险</Tag>
                        <Tag color="geekblue">{session.plan.service_count} 类服务</Tag>
                        <Tag color="green">{session.plan.ready_stage_count} 个可执行阶段</Tag>
                        {session.plan.blocked_stage_count ? <Tag color="orange">{session.plan.blocked_stage_count} 个阻塞阶段</Tag> : null}
                      </Space>

                      <Typography.Paragraph className="remediation-plan-summary-text">
                        {session.plan.summary_text}
                      </Typography.Paragraph>

                      <div className="remediation-plan-compact-meta">
                        <Tag>{focusedRiskLabel}</Tag>
                        <Tag>{serviceFilterLabel}</Tag>
                        <Tag>{stepStateFilterLabel}</Tag>
                        <Tag>{`${filteredStepTotal || session.plan.steps.length} 个匹配步骤`}</Tag>
                      </div>

                      <div className="remediation-plan-filter-cluster">
                        <div className="remediation-filter-row">
                          <Typography.Text type="secondary">风险聚焦</Typography.Text>
                          <Space wrap>
                            <Button size="small" type={!effectiveFindingId ? "primary" : "default"} onClick={() => onSelectFinding(null)}>
                              全部风险
                            </Button>
                            {findings.map((item) => (
                              <Button
                                key={item.finding_id}
                                size="small"
                                type={item.finding_id === effectiveFindingId ? "primary" : "default"}
                                onClick={() => onSelectFinding(item.finding_id)}
                              >
                                {item.title}
                              </Button>
                            ))}
                          </Space>
                        </div>

                        <div className="remediation-filter-row">
                          <Typography.Text type="secondary">服务筛选</Typography.Text>
                          <Space wrap>
                            <Tag
                              color={!viewState.selectedService ? "blue" : "default"}
                              style={{ cursor: "pointer" }}
                              onClick={() => updateViewState((current) => ({ ...current, selectedService: "" }))}
                            >
                              全部服务
                            </Tag>
                            {availableServices.map((serviceName) => (
                              <Tag
                                key={serviceName}
                                color={viewState.selectedService === serviceName ? "blue" : "default"}
                                style={{ cursor: "pointer" }}
                                onClick={() => updateViewState((current) => ({
                                  ...current,
                                  selectedService: current.selectedService === serviceName ? "" : serviceName,
                                }))}
                              >
                                {serviceName}
                              </Tag>
                            ))}
                          </Space>
                        </div>

                        <div className="remediation-filter-row">
                          <Typography.Text type="secondary">步骤状态</Typography.Text>
                          <Space wrap>
                            <Tag
                              color={viewState.selectedStepState === "all" ? "blue" : "default"}
                              style={{ cursor: "pointer" }}
                              onClick={() => updateViewState((current) => ({ ...current, selectedStepState: "all" }))}
                            >
                              全部步骤
                            </Tag>
                            <Tag
                              color={viewState.selectedStepState === "ready" ? "green" : "default"}
                              style={{ cursor: "pointer" }}
                              onClick={() => updateViewState((current) => ({ ...current, selectedStepState: "ready" }))}
                            >
                              仅可执行
                            </Tag>
                            <Tag
                              color={viewState.selectedStepState === "blocked" ? "orange" : "default"}
                              style={{ cursor: "pointer" }}
                              onClick={() => updateViewState((current) => ({ ...current, selectedStepState: "blocked" }))}
                            >
                              仅阻塞
                            </Tag>
                          </Space>
                        </div>
                      </div>

                      {selectedFinding ? (
                        <Alert
                          type="info"
                          showIcon
                          message={`当前聚焦：${selectedFinding.title}`}
                          description={`严重度 ${selectedFinding.severity}，服务 ${selectedFinding.service_name || "未识别"}，发现于 ${formatDateTime(selectedFinding.detected_at)}`}
                        />
                      ) : null}

                      {viewState.planGuideOpen ? (
                        <div className="remediation-section-grid">
                          {session.plan.impact_summary ? (
                            <div className="remediation-section-card">
                              <div className="remediation-section-card-header">
                                <Typography.Text strong>影响范围</Typography.Text>
                              </div>
                              <Typography.Text type="secondary" className="ui-detail-wrap">
                                {session.plan.impact_summary}
                              </Typography.Text>
                            </div>
                          ) : null}

                          {session.plan.precheck_items.length ? (
                            <div className="remediation-section-card">
                              <div className="remediation-section-card-header">
                                <Typography.Text strong>执行前检查</Typography.Text>
                              </div>
                              <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                {session.plan.precheck_items.map((item) => (
                                  <Typography.Text key={item} className="ui-detail-wrap">
                                    • {item}
                                  </Typography.Text>
                                ))}
                              </Space>
                            </div>
                          ) : null}

                          {session.plan.verify_items.length ? (
                            <div className="remediation-section-card">
                              <div className="remediation-section-card-header">
                                <Typography.Text strong>执行后验证</Typography.Text>
                              </div>
                              <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                {session.plan.verify_items.map((item) => (
                                  <Typography.Text key={item} className="ui-detail-wrap">
                                    • {item}
                                  </Typography.Text>
                                ))}
                              </Space>
                            </div>
                          ) : null}

                          {session.plan.rollback_notes.length ? (
                            <div className="remediation-section-card">
                              <div className="remediation-section-card-header">
                                <Typography.Text strong>回滚说明</Typography.Text>
                              </div>
                              <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                {session.plan.rollback_notes.map((item) => (
                                  <Typography.Text key={item} type="secondary" className="ui-detail-wrap">
                                    • {item}
                                  </Typography.Text>
                                ))}
                              </Space>
                            </div>
                          ) : null}
                        </div>
                      ) : null}

                      {session.plan.global_blockers.length ? (
                        <Alert
                          type="warning"
                          showIcon
                          message="当前存在全局阻塞"
                          description={session.plan.global_blockers.map((item) => item.message).join("；")}
                        />
                      ) : null}

                      <div className="remediation-stage-scroll">
                        {filteredStages.length ? (
                          <div className="remediation-stage-stack">
                            {filteredStages.map((stage) => renderStageCard(stage))}
                          </div>
                        ) : (
                          <Empty description="当前筛选条件下没有匹配的执行阶段。" />
                        )}
                      </div>

                      {hasStageFilters && filteredBlockedMessages.length ? (
                        <Alert
                          type="info"
                          showIcon
                          message={`当前筛选结果：${filteredReadyStepCount} 个可执行步骤，${filteredBlockedStepCount} 个阻塞步骤`}
                          description={filteredBlockedMessages.join("；")}
                        />
                      ) : null}
                    </Space>
                  )}
                </Card>
              </div>

              <Card
                className="panel-card remediation-ai-card"
                title="AI 解读与会话"
                extra={(
                  <Space wrap className="remediation-workbench-card-extra">
                    <Typography.Text type="secondary">AI 解释仅作辅助诊断，不改变整机计划真源</Typography.Text>
                    <Button size="small" onClick={() => updateViewState((current) => ({ ...current, aiOpen: !current.aiOpen }))}>
                      {viewState.aiOpen ? "收起" : "展开"}
                    </Button>
                  </Space>
                )}
              >
                {!viewState.aiOpen ? (
                  <div className="remediation-workbench-collapsed-summary remediation-ai-card-content">
                    <Tag>{`${latestMessages.length} 条消息`}</Tag>
                    {aiGenerationPending ? <Tag color="processing">生成中</Tag> : null}
                    {aiGenerationError ? <Tag color="orange">已回退</Tag> : null}
                    <Typography.Text type="secondary" className="ui-detail-wrap remediation-ai-summary-text">
                      {latestAiMessage
                        ? latestAiMessage.content
                        : latestAuditMessage
                          ? `最近更新：${formatDateTime(latestAuditMessage.created_at)}`
                          : "暂无 AI 解读与会话消息"}
                    </Typography.Text>
                  </div>
                ) : (
                  <Space className="remediation-ai-card-content" direction="vertical" size={10}>
                    {messageLoading ? <Alert type="info" showIcon message="正在提交会话操作..." /> : null}
                    {aiGenerationPending ? <Alert type="info" showIcon message="正在生成 AI 解读..." /> : null}
                    {aiGenerationError ? (
                      <Alert
                        type="warning"
                        showIcon
                        message="AI 解读已回退为非阻塞模式"
                        description={`${aiGenerationError}。当前整机计划与执行能力不受影响，可手动重试 AI 解读。`}
                      />
                    ) : null}

                    <Space direction="vertical" size={8} style={{ width: "100%" }}>
                      <Input.TextArea
                        rows={2}
                        placeholder="可选：记录本次窗口期、影响说明或审批备注"
                        value={sessionNote}
                        onChange={(event) => setSessionNote(event.target.value)}
                      />
                      <Space wrap>
                        <Button onClick={() => void onRefreshAI()} loading={messageLoading} disabled={!session}>
                          重新生成 AI 解读
                        </Button>
                        <Button
                          onClick={() => void onExplainBlockers()}
                          loading={messageLoading}
                          disabled={!session || !session.plan.blocked_reasons.length}
                        >
                          解释当前阻塞
                        </Button>
                        <Button
                          onClick={() => void onAppendAuditNote()}
                          loading={messageLoading}
                          disabled={!session || !sessionNote.trim()}
                        >
                          写入审计记录
                        </Button>
                      </Space>
                    </Space>

                    {latestMessages.length ? (
                      <div className="remediation-ai-message-scroll">
                        <List
                          dataSource={latestMessages}
                          renderItem={(item) => (
                            <List.Item className="remediation-message-item">
                              <Space direction="vertical" size={6} style={{ width: "100%" }}>
                                <Space wrap>
                                  <Typography.Text strong>{remediationMessageAuthorLabel(item.role, item.message_type)}</Typography.Text>
                                  <Tag color={remediationMessageTagColor(item.message_type)}>
                                    {remediationMessageTypeLabel(item.message_type)}
                                  </Tag>
                                </Space>
                                <Typography.Paragraph className="remediation-ai-message-content">
                                  {item.content}
                                </Typography.Paragraph>
                                <Typography.Text type="secondary">{formatDateTime(item.created_at)}</Typography.Text>
                              </Space>
                            </List.Item>
                          )}
                        />
                      </div>
                    ) : aiGenerationPending ? (
                      <Typography.Text type="secondary">AI 解读将在后台生成完成后自动回补到当前工作台。</Typography.Text>
                    ) : (
                      <Typography.Text type="secondary">暂无 AI 解读与会话消息。</Typography.Text>
                    )}
                  </Space>
                )}
              </Card>

              <Card
                className="panel-card"
                title="交互终端"
                extra={(
                  <Space wrap className="remediation-workbench-card-extra">
                    <Tag color={terminalEnabled ? "green" : "orange"}>{terminalEnabled ? "可连接" : "受限"}</Tag>
                    <Button size="small" onClick={() => updateViewState((current) => ({ ...current, terminalOpen: !current.terminalOpen }))}>
                      {viewState.terminalOpen ? "收起" : "展开"}
                    </Button>
                  </Space>
                )}
              >
                {!viewState.terminalOpen ? (
                  <div className="remediation-workbench-collapsed-summary">
                    <Tag color={terminalEnabled ? "green" : "orange"}>{terminalEnabled ? "SSH 已就绪" : "SSH 未就绪"}</Tag>
                    <Typography.Text type="secondary" className="ui-detail-wrap">
                      {terminalEnabled ? `${terminalAssetLabel} · ${assetDetail?.authorization.effective_privilege}` : terminalBlockedReasons.join("；")}
                    </Typography.Text>
                  </div>
                ) : (
                  <RemoteSshTerminal
                    assetId={assetId}
                    assetLabel={terminalAssetLabel}
                    enabled={terminalEnabled}
                    blockedReasons={terminalBlockedReasons}
                  />
                )}
              </Card>

              <Card
                className="panel-card"
                loading={taskLoading}
                title="任务输出"
                extra={(
                  <Space wrap className="remediation-workbench-card-extra">
                    <Button size="small" onClick={() => updateViewState((current) => ({ ...current, outputOpen: !current.outputOpen }))}>
                      {viewState.outputOpen ? "收起" : "展开"}
                    </Button>
                  </Space>
                )}
              >
                {!viewState.outputOpen ? (
                  <div className="remediation-workbench-collapsed-summary">
                    {task ? <StatusTag value={task.status} /> : null}
                    {streamLines.length ? <Tag>{`${streamLines.length} 行输出`}</Tag> : null}
                    <Typography.Text type="secondary" className="ui-detail-wrap">
                      {taskOutputSummary}
                    </Typography.Text>
                  </div>
                ) : task ? (
                  <Space direction="vertical" size={12} style={{ width: "100%" }}>
                    <Descriptions column={1} size="small" bordered>
                      <Descriptions.Item label="任务状态">
                        <Space wrap>
                          <StatusTag value={task.status} />
                          <Typography.Text>{executionBoundaryLabel(task.execution_boundary)}</Typography.Text>
                          <Tag>{executionModeLabel(task.execution_mode)}</Tag>
                          <Tag>{remediationExecutionOutcomeLabel(task.execution_status, task.business_status)}</Tag>
                          {task.business_status ? (
                            <Tag color={remediationBusinessStatusColor(task.business_status)}>
                              {remediationBusinessStatusLabel(task.business_status)}
                            </Tag>
                          ) : null}
                        </Space>
                      </Descriptions.Item>
                      <Descriptions.Item label="进度">{task.progress}%</Descriptions.Item>
                      <Descriptions.Item label="最近消息">{localizeTaskMessage(task.message)}</Descriptions.Item>
                      <Descriptions.Item label="开始时间">{formatDateTime(task.started_at)}</Descriptions.Item>
                      <Descriptions.Item label="完成时间">{formatDateTime(task.finished_at)}</Descriptions.Item>
                      <Descriptions.Item label="自动复测">{String(task.reverify_task_id || toRecord(task.reverify).reverify_task_id || "-")}</Descriptions.Item>
                      {task.business_status ? (
                        <Descriptions.Item label="业务闭环">{remediationBusinessStatusLabel(task.business_status)}</Descriptions.Item>
                      ) : null}
                      <Descriptions.Item label="证据条目">{taskEvidence?.item_count || 0}</Descriptions.Item>
                    </Descriptions>

                    {Object.keys(task.reverify_summary || {}).length ? (
                      <Alert
                        type={task.business_status === "verified_closed" ? "success" : task.business_status === "verified_failed" ? "error" : "info"}
                        showIcon
                        message={remediationExecutionOutcomeLabel(task.execution_status, task.business_status)}
                        description={localizeTaskMessage(remediationResolvedTaskMessage(task.message, task.execution_status, task.business_status))}
                      />
                    ) : null}

                    <div className="remediation-workbench-task-stream">
                      <pre className="remediation-workbench-task-stream-pre">
                        {(streamLines.length ? streamLines : ["等待任务输出..."]).join("\n")}
                      </pre>
                    </div>

                    {stepResults.length ? (
                      <List
                        dataSource={stepResults}
                        renderItem={(item) => (
                          <List.Item>
                            <List.Item.Meta
                              title={(
                                <Space wrap>
                                  <StatusTag value={String(item.status || "-")} />
                                  {String(item.title || item.step_id || "-")}
                                </Space>
                              )}
                              description={(
                                <Space direction="vertical" size={4}>
                                  <Typography.Text type="secondary">开始: {formatDateTime(String(item.started_at || ""))}</Typography.Text>
                                  <Typography.Text type="secondary">完成: {formatDateTime(String(item.finished_at || ""))}</Typography.Text>
                                  {item.error ? <Typography.Text type="danger">{String(item.error)}</Typography.Text> : null}
                                  <RollbackArtifactPanel
                                    rollbackCommand={String(item.rollback_command || "") || null}
                                    rollbackArtifact={item.rollback_artifact}
                                  />
                                </Space>
                              )}
                            />
                          </List.Item>
                        )}
                      />
                    ) : null}

                    <CollapsibleJsonBlock title="执行结果（JSON）" value={task.execution} />
                    <CollapsibleJsonBlock title={`执行证据（JSON）${taskEvidenceLoading ? " · 加载中" : ""}`} value={taskEvidence || {}} />
                    <CollapsibleJsonBlock title="自动复测（JSON）" value={task.reverify} />
                    <CollapsibleJsonBlock title="业务复验（JSON）" value={task.reverify_summary} />
                  </Space>
                ) : (
                  <div className="remediation-compact-empty">
                    <Typography.Text strong>当前暂无任务输出</Typography.Text>
                    <Typography.Text type="secondary">
                      安装 Runner 或执行整机修复后，会在此显示任务输出。
                    </Typography.Text>
                  </div>
                )}
              </Card>
            </div>
          </Col>
        </Row>
      </div>
    </Space>
  );
}
