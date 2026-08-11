import { Activity, ArrowRight, Bot, Check, ChevronDown, Circle, CircleAlert, Clock3, Copy, FolderOpen, GitBranch, History, KeyRound, LoaderCircle, MessageSquareText, Package, Play, SearchCheck, Send, Settings2, ShieldCheck, Sparkles, Square, Zap } from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { Fragment, useEffect, useMemo, useReducer, useRef, useState, type ReactNode } from "react";
import { ANALYSIS_MODES } from "../analysisModes";
import { DEFAULT_AI_CONTEXT_TOKENS, promptBudgetBytes } from "../aiContextBudget";
import { estimateAnalysisScope, formatContextSize } from "../analysisScope";
import {
  analysisStreamReducer,
  createAnalysisStreamState,
  isGraphActivityPhase,
  type AgentActivityEntry,
} from "../analysisStreamState";
import { buildPreviewSkillPlan, builtInSkillPreview } from "../capabilities";
import { pickReplayExportDirectory } from "../replayExport";
import type { AiAnalysisSettings, AiProviderSettings, AlgorithmReplayExportResult, AnalysisActivity, AnalysisChatMessage, AnalysisGraphRun, AnalysisMode, AnalysisReport, AnalysisStatus, AnalysisStreamEvent, AutonomousAnalysisResult, EvaluationExportResult, RequestListItem, SdkExportResult, SkillPlan, SkillRunAudit } from "../types";

const modes = ANALYSIS_MODES;

const fallbackAiSettings: AiProviderSettings = {
  provider: "claudegpt",
  baseUrl: "https://claudegpt.org/v1",
  model: "gpt-5.5",
  contextTokens: DEFAULT_AI_CONTEXT_TOKENS,
  hasApiKey: false,
};

const fallbackAnalysisSettings: AiAnalysisSettings = {
  twoStageAnalysis: true,
  allowMcpTools: true,
  streamingOutput: true,
  maxAgentTurns: 8,
};

const previewReports: AnalysisReport[] = [
  {
    id: "analysis-preview-login",
    sessionId: "session-live",
    mode: "api",
    status: "complete",
    requestCount: 247,
    keyRequestCount: 18,
    selectedRequestIds: [],
    content: "# 登录链路分析\n\n已识别挑战码、客户端签名和 Token 换取三段调用链。\n\n## 关键结论\n\n- 登录接口使用 `HMAC-SHA256` 生成动态签名。\n- Access Token 由 `/v2/auth/token` 返回，刷新流程独立。\n- 3 条异常响应需要进一步检查设备指纹参数。",
    provider: "claudegpt",
    model: "gpt-5.5",
    createdAt: Date.now() - 24 * 60 * 60 * 1000,
    updatedAt: Date.now() - 2 * 60 * 60 * 1000,
  },
  {
    id: "analysis-preview-security",
    sessionId: "session-live",
    mode: "security",
    status: "complete",
    requestCount: 219,
    keyRequestCount: 12,
    selectedRequestIds: [],
    content: "# 登录安全审计\n\n历史审计发现登录失败响应中暴露了过细的账号状态。\n\n## 修复建议\n\n- 统一登录失败提示。\n- 缩短挑战码有效期并限制重复使用。",
    provider: "claudegpt",
    model: "gpt-5.5",
    createdAt: Date.now() - 4 * 24 * 60 * 60 * 1000,
    updatedAt: Date.now() - 3 * 24 * 60 * 60 * 1000,
  },
  {
    id: "analysis-preview-oauth",
    sessionId: "session-oauth",
    mode: "security",
    status: "complete",
    requestCount: 132,
    keyRequestCount: 9,
    selectedRequestIds: [],
    content: "# OAuth 回调安全审计\n\n回调链路已还原，授权码、state 校验和 Token 换取请求均已定位。\n\n## 关键结论\n\n- 回调入口正确校验了 `state`，但错误响应包含过多内部信息。\n- 授权码仅使用一次，Token 换取请求未发现明文凭据。\n- 建议统一失败响应，并缩短回调错误日志中的参数保留时间。",
    provider: "claudegpt",
    model: "gpt-5.5",
    createdAt: Date.now() - 2 * 24 * 60 * 60 * 1000,
    updatedAt: Date.now() - 26 * 60 * 60 * 1000,
  },
];

function buildPreviewGraphRun(report: AnalysisReport, requests: RequestListItem[]): AnalysisGraphRun {
  const plan = buildPreviewSkillPlan(report.mode, requests);
  const definitions = plan.stages.map((stage) => {
    const skill = builtInSkillPreview.find((item) => item.id === stage.skillId);
    return {
      id: stage.id,
      label: stage.label,
      detail: stage.detail,
      kind: stage.kind,
      skillId: stage.kind === "skill" ? stage.skillId : undefined,
      suggestedTools: skill?.tools ?? [],
      permissions: skill?.permissions ?? [],
      artifactContract: {
        schemaVersion: "1.0.0",
        expectedSkillId: stage.kind === "skill" ? stage.skillId : undefined,
        requiredFields: stage.kind === "skill"
          ? ["skillId", "summary", "findings", "evidenceRefs", "gaps", "outputs"]
          : ["evidenceRefs"],
        requiredOutputs: skill?.outputs ?? [],
        minEvidenceRefs: stage.kind === "skill" ? 1 : 0,
      },
      maxRetries: stage.maxRetries,
    };
  });
  const edges = definitions.slice(0, -1).map((node, index) => ({
    from: node.id,
    to: definitions[index + 1].id,
    condition: "succeeded",
  }));
  const updatedAt = report.updatedAt;
  return {
    analysisId: report.id,
    definition: {
      id: `shownet-analysis-${report.mode}`,
      schemaVersion: "1.0.0",
      mode: report.mode,
      entryNodeId: definitions[0]?.id ?? "report",
      nodes: definitions,
      edges,
    },
    status: "completed",
    maxModelTurns: fallbackAnalysisSettings.maxAgentTurns,
    modelTurnCount: 6,
    nodes: definitions.map((node, index) => ({
      nodeId: node.id,
      status: "succeeded",
      attempt: 1,
      modelTurnCount: node.kind === "skill" ? 2 : 0,
      toolCallCount: node.kind === "skill" ? Math.min(3, node.suggestedTools.length) : 0,
      toolCalls: [],
      artifact: { evidenceRefs: [`preview:${node.id}`] },
      validationErrors: [],
      startedAt: updatedAt - (definitions.length - index) * 1_200,
      finishedAt: updatedAt - (definitions.length - index - 1) * 1_200,
    })),
    events: [
      { sequence: 1, event: "graph-created", detail: "建议分析 Graph 已创建", createdAt: updatedAt - 8_000 },
      { sequence: 2, nodeId: definitions[0]?.id, event: "agent-deviation", detail: "Agent 根据证据自主调整了 Skill 顺序", createdAt: updatedAt - 4_000 },
      { sequence: 3, event: "graph-completed", detail: "建议轨迹与产物已归档", createdAt: updatedAt },
    ],
    createdAt: updatedAt - 8_000,
    updatedAt,
  };
}

interface AnalysisViewProps {
  sessionId: string;
  requests: RequestListItem[];
  onConfigureAi: () => void;
  onNotify: (message: string) => void;
  autoRunId?: number;
  onAutoRunConsumed: () => void;
  initialRequestIds?: string[];
  scopeRequestId?: number;
  onScopeConsumed: () => void;
  onOpenEvidenceRequest: (requestId: string) => void;
  /**
   * The analysis mode is shared with the Skill 编排 view and outlives this
   * component, which unmounts whenever the user navigates away.
   */
  mode: AnalysisMode;
  onModeChange: (mode: AnalysisMode) => void;
  /** True once the user has chosen a mode; a restored report must not override it. */
  modePinned: boolean;
}

type ChatItem = Pick<AnalysisChatMessage, "id" | "role" | "content">;

const replayLanguages = [
  { id: "python", label: "Python" },
  { id: "javascript", label: "JavaScript" },
  { id: "typescript", label: "TypeScript" },
  { id: "go", label: "Go" },
  { id: "java", label: "Java" },
  { id: "csharp", label: "C#" },
] as const;

type ReplayLanguage = (typeof replayLanguages)[number]["id"];

export function AnalysisView({ sessionId, requests, onConfigureAi, onNotify, autoRunId, onAutoRunConsumed, initialRequestIds, scopeRequestId, onScopeConsumed, onOpenEvidenceRequest, mode, onModeChange: setMode, modePinned }: AnalysisViewProps) {
  const [streamState, dispatchStream] = useReducer(analysisStreamReducer, createAnalysisStreamState());
  const {
    status,
    report,
    content,
    phaseMessage,
    error,
    failureKind,
    pendingAnswer,
    sending,
    cancelling,
    streamKeyCount,
    agentActivities,
    firstVisibleLatencyMs,
  } = streamState;
  const [reports, setReports] = useState<AnalysisReport[]>([]);
  const [includeStatic, setIncludeStatic] = useState(false);
  const [includeAnnotations, setIncludeAnnotations] = useState(false);
  const [manualScope, setManualScope] = useState(false);
  const [mobileScopeOpen, setMobileScopeOpen] = useState(false);
  const [scopedRequestIds, setScopedRequestIds] = useState<string[]>([]);
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<ChatItem[]>([]);
  const [aiSettings, setAiSettings] = useState(fallbackAiSettings);
  const [analysisSettings, setAnalysisSettings] = useState(fallbackAnalysisSettings);
  const [aiSettingsLoaded, setAiSettingsLoaded] = useState(!isTauri());
  const [analysisSettingsLoaded, setAnalysisSettingsLoaded] = useState(!isTauri());
  const [historyLoaded, setHistoryLoaded] = useState(!isTauri());
  const [streamListenerSessionId, setStreamListenerSessionId] = useState(isTauri() ? "" : sessionId);
  const [skillPlan, setSkillPlan] = useState<SkillPlan | null>(null);
  const [skillRuns, setSkillRuns] = useState<SkillRunAudit[]>([]);
  const [graphRun, setGraphRun] = useState<AnalysisGraphRun | null>(null);
  const [replayLanguage, setReplayLanguage] = useState<ReplayLanguage>("python");
  const [replayExport, setReplayExport] = useState<AlgorithmReplayExportResult | null>(null);
  const [exportingReplay, setExportingReplay] = useState(false);
  const [evalExport, setEvalExport] = useState<EvaluationExportResult | null>(null);
  const [exportingEval, setExportingEval] = useState(false);
  const evalExportRequestId = useRef(0);
  const [sdkExport, setSdkExport] = useState<SdkExportResult | null>(null);
  const [exportingSdk, setExportingSdk] = useState(false);
  const sdkExportRequestId = useRef(0);
  const [quickScanning, setQuickScanning] = useState(false);
  const [quickScan, setQuickScan] = useState<AutonomousAnalysisResult | null>(null);
  const quickScanRequestId = useRef(0);
  const reportEndRef = useRef<HTMLDivElement | null>(null);
  const activeAnalysisId = useRef("");
  const currentSessionId = useRef(sessionId);
  const analysisCommandRequestId = useRef(0);
  const analysisCommandPending = useRef(false);
  const historyRequestId = useRef(0);
  const streamEventRevision = useRef(0);
  const reportRestoreRequestId = useRef(0);
  const followupRequestId = useRef(0);
  const followupCommandPending = useRef(false);
  const supersededAnalysisIds = useRef(new Set<string>());
  const modePinnedRef = useRef(modePinned);
  const replayExportRequestId = useRef(0);
  const handledAutoRunId = useRef(0);
  const initializedSessionId = useRef("");
  const handledScopeRequestId = useRef(0);
  currentSessionId.current = sessionId;
  modePinnedRef.current = modePinned;

  const apiRequests = useMemo(
    () => requests.filter((request) => request.type === "xhr" || request.type === "fetch"),
    [requests],
  );
  const keyRequests = useMemo(
    () => requests.filter((request) => request.risk !== "none" || request.hasHook || (request.status ?? 0) >= 400),
    [requests],
  );
  const manualRequests = useMemo(() => {
    if (!scopedRequestIds.length) return keyRequests;
    const ids = new Set(scopedRequestIds);
    return requests.filter((request) => ids.has(request.id));
  }, [keyRequests, requests, scopedRequestIds]);
  // The skill plan is fetched for the picker mode, so it only describes the
  // displayed report while the two agree.
  const planDescribesReport = !report || report.mode === mode;
  const hookCount = requests.filter((request) => request.hasHook).length;
  const scopeEstimate = useMemo(() => estimateAnalysisScope(requests, {
    mode, includeStatic, manualScope, manualRequestIds: scopedRequestIds, includeAnnotations,
  }), [includeAnnotations, includeStatic, manualScope, mode, requests, scopedRequestIds]);
  const selectedRequestCount = report?.keyRequestCount || streamKeyCount || (
    scopeEstimate.requestCount
  );
  const running = status === "filtering" || status === "analyzing";
  const requiresApiKey = aiSettings.provider !== "local" && !aiSettings.hasApiKey;
  const smartFilteringEnabled = analysisSettings.twoStageAnalysis && requests.length >= 20 && !manualScope;
  const streamListenerReady = !isTauri() || streamListenerSessionId === sessionId;

  useEffect(() => {
    if (!scopeRequestId || handledScopeRequestId.current === scopeRequestId || !initialRequestIds?.length) return;
    handledScopeRequestId.current = scopeRequestId;
    setScopedRequestIds([...initialRequestIds]);
    setManualScope(true);
    dispatchStream({ type: "notice", message: `已载入 ${initialRequestIds.length} 条选中请求，确认范围后开始分析` });
    onScopeConsumed();
  }, [initialRequestIds, onScopeConsumed, scopeRequestId]);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<AiProviderSettings>("get_ai_provider_settings")
      .then(setAiSettings)
      .catch(() => setAiSettings(fallbackAiSettings))
      .finally(() => setAiSettingsLoaded(true));
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<AiAnalysisSettings>("get_ai_analysis_settings")
      .then(setAnalysisSettings)
      .catch(() => setAnalysisSettings(fallbackAnalysisSettings))
      .finally(() => setAnalysisSettingsLoaded(true));
  }, []);

  useEffect(() => {
    const loadRequestId = ++historyRequestId.current;
    if (initializedSessionId.current !== sessionId) {
      initializedSessionId.current = sessionId;
      activeAnalysisId.current = "";
      supersededAnalysisIds.current.clear();
      streamEventRevision.current = 0;
      analysisCommandRequestId.current += 1;
      analysisCommandPending.current = false;
      reportRestoreRequestId.current += 1;
      followupRequestId.current += 1;
      followupCommandPending.current = false;
      quickScanRequestId.current += 1;
      setScopedRequestIds([]);
      setIncludeAnnotations(false);
      setQuestion("");
      setReports([]);
      setMessages([]);
      setSkillRuns([]);
      setGraphRun(null);
      setReplayExport(null);
      setExportingReplay(false);
      replayExportRequestId.current += 1;
      setEvalExport(null);
      setExportingEval(false);
      evalExportRequestId.current += 1;
      setSdkExport(null);
      setExportingSdk(false);
      sdkExportRequestId.current += 1;
      setQuickScan(null);
      setQuickScanning(false);
      dispatchStream({ type: "reset" });
    }
    setHistoryLoaded(!isTauri());
    // A running report can finish between the history query and listener
    // registration. Load history only after this session's listener is active,
    // so every terminal event after the snapshot has somewhere to land.
    if (isTauri() && !streamListenerReady) return;
    if (!isTauri()) {
      const history = previewReports.filter((item) => item.sessionId === sessionId);
      setReports(history);
      const latest = history[0];
      if (latest) {
        activeAnalysisId.current = latest.id;
        if (!modePinnedRef.current) setMode(latest.mode);
        dispatchStream({ type: "restore", report: latest });
        setGraphRun(buildPreviewGraphRun(latest, requests));
      }
      return;
    }
    if (!sessionId) return;
    let disposed = false;
    const historyStreamRevision = streamEventRevision.current;
    invoke<AnalysisReport[]>("list_analysis_reports", { sessionId })
      .then(async (history) => {
        if (disposed || historyRequestId.current !== loadRequestId) return;
        // The snapshot may have been read before an event that reached this
        // listener. Preserve the event-driven state; terminal events carry the
        // authoritative report, and later events continue the live stream.
        if (streamEventRevision.current !== historyStreamRevision) return;
        setReports(history);
        const latest = history[0];
        if (!latest) return;
        // On a first visit there is no choice to protect, so the report may
        // set the mode; once the user has picked one, it may not.
        await restoreReport(
          latest,
          () => disposed || historyRequestId.current !== loadRequestId,
          !modePinnedRef.current,
        );
      })
      .catch((loadError) => {
        if (!disposed && historyRequestId.current === loadRequestId) {
          dispatchStream({ type: "set-error", message: `读取历史报告失败：${String(loadError)}` });
        }
      })
      .finally(() => {
        if (!disposed && currentSessionId.current === sessionId) setHistoryLoaded(true);
      });
    return () => {
      disposed = true;
    };
  }, [sessionId, streamListenerReady]);

  /**
   * @param adoptMode whether the report should take over the mode selection.
   *   True when the user picks a report from history. False when we merely
   *   restore the last report on mount — that is a convenience, and it must
   *   not overwrite a mode the user chose, possibly over in Skill 编排.
   */
  const restoreReport = async (selected: AnalysisReport, isDisposed: () => boolean = () => false, adoptMode = true) => {
    if (currentSessionId.current !== selected.sessionId) return;
    analysisCommandRequestId.current += 1;
    analysisCommandPending.current = false;
    const restoreRequestId = ++reportRestoreRequestId.current;
    followupRequestId.current += 1;
    followupCommandPending.current = false;
    const isCurrent = () => (
      !isDisposed()
      && reportRestoreRequestId.current === restoreRequestId
      && currentSessionId.current === selected.sessionId
      && activeAnalysisId.current === selected.id
    );
    supersededAnalysisIds.current.delete(selected.id);
    activeAnalysisId.current = selected.id;
    if (adoptMode) setMode(selected.mode);
    dispatchStream({ type: "restore", report: selected });
    setMessages([]);
    setSkillRuns([]);
    setGraphRun(null);
    setReplayExport(null);
    setExportingReplay(false);
    replayExportRequestId.current += 1;
    setEvalExport(null);
    setExportingEval(false);
    evalExportRequestId.current += 1;
    if (!isTauri()) {
      setGraphRun(buildPreviewGraphRun(selected, requests));
      return;
    }
    try {
      const activityHistory = await invoke<AnalysisActivity[]>("list_analysis_activities", {
        analysisId: selected.id,
      });
      if (isCurrent()) {
        dispatchStream({ type: "restore-activities", activities: activityHistory });
      }
    } catch (activityError) {
      if (isCurrent()) {
        dispatchStream({ type: "notice", message: `读取 Agent 执行轨迹失败：${String(activityError)}` });
      }
    }
    try {
      const restoredSkillRuns = await invoke<SkillRunAudit[]>("list_analysis_skill_runs", {
        analysisId: selected.id,
      });
      if (isCurrent()) {
        setSkillRuns(restoredSkillRuns);
      }
    } catch (skillRunError) {
      if (isCurrent()) {
        dispatchStream({ type: "notice", message: `读取 Skill 审计失败：${String(skillRunError)}` });
      }
    }
    try {
      const restoredGraph = await invoke<AnalysisGraphRun | null>("get_analysis_graph_run", {
        analysisId: selected.id,
      });
      if (isCurrent()) {
        setGraphRun(restoredGraph);
      }
    } catch (graphError) {
      if (isCurrent()) {
        dispatchStream({ type: "notice", message: `读取 Graph 轨迹失败：${String(graphError)}` });
      }
    }
    if (selected.status === "complete") {
      try {
        const history = await invoke<AnalysisChatMessage[]>("list_analysis_messages", {
          analysisId: selected.id,
        });
        if (isCurrent()) setMessages(history);
      } catch (historyError) {
        if (isCurrent()) {
          dispatchStream({ type: "notice", message: `读取报告追问记录失败：${String(historyError)}` });
        }
      }
    } else if (selected.status !== "failed") {
      try {
        const isRunning = await invoke<boolean>("is_ai_analysis_running", { analysisId: selected.id });
        if (!isCurrent()) return;
        dispatchStream({ type: "recover", report: selected, running: isRunning });
      } catch (runtimeError) {
        if (isCurrent()) {
          dispatchStream({ type: "recovery-error", message: `读取分析运行状态失败：${String(runtimeError)}` });
        }
      }
    }
  };

  useEffect(() => {
    if (!sessionId) return;
    if (!isTauri()) {
      setSkillPlan(buildPreviewSkillPlan(mode, requests));
      return;
    }
    let disposed = false;
    invoke<SkillPlan>("get_analysis_skill_plan", { sessionId, mode })
      .then((loaded) => { if (!disposed) setSkillPlan(loaded); })
      .catch(() => { if (!disposed) setSkillPlan(null); });
    return () => { disposed = true; };
  }, [mode, sessionId, requests.length]);

  useEffect(() => {
    if (!isTauri()) {
      setStreamListenerSessionId(sessionId);
      return;
    }
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    setStreamListenerSessionId("");
    listen<AnalysisStreamEvent>("analysis://stream", (event) => {
      const update = event.payload;
      if (update.sessionId !== sessionId || currentSessionId.current !== update.sessionId) return;
      if (supersededAnalysisIds.current.has(update.analysisId)) return;
      if (!activeAnalysisId.current) activeAnalysisId.current = update.analysisId;
      if (update.analysisId !== activeAnalysisId.current) return;
      streamEventRevision.current += 1;
      if (isGraphActivityPhase(update.phase) || update.phase === "tool-complete" || update.phase === "tool-error") {
        invoke<AnalysisGraphRun | null>("get_analysis_graph_run", { analysisId: update.analysisId })
          .then((loaded) => {
            if (
              currentSessionId.current === update.sessionId
              && activeAnalysisId.current === update.analysisId
            ) {
              setGraphRun(loaded);
            }
          })
          .catch(() => undefined);
      }
      if (
        update.phase === "analyzing"
        || update.phase === "tool-complete"
        || update.phase === "tool-error"
        || update.phase === "complete"
        || update.phase === "error"
      ) {
        invoke<SkillRunAudit[]>("list_analysis_skill_runs", { analysisId: update.analysisId })
          .then((runs) => {
            if (
              currentSessionId.current === update.sessionId
              && activeAnalysisId.current === update.analysisId
            ) {
              setSkillRuns(runs);
            }
          })
          .catch(() => undefined);
      }
      if ((update.phase === "complete" || update.phase === "error") && update.report) {
        setReports((items) => [update.report!, ...items.filter((item) => item.id !== update.report!.id)]);
      }
      dispatchStream({ type: "event", event: update });
    }).then((handler) => {
      if (disposed) handler();
      else {
        unlisten = handler;
        setStreamListenerSessionId(sessionId);
      }
    }).catch((listenError) => {
      if (!disposed && currentSessionId.current === sessionId) {
        dispatchStream({ type: "set-error", message: `订阅分析进度失败：${String(listenError)}` });
      }
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [sessionId]);

  useEffect(() => {
    if (status === "analyzing" || sending) {
      reportEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [content, pendingAnswer, sending, status]);

  // Deterministic pass: plan skills, aggregate protection evidence, no model
  // call. It is the only way to reach the protection analysis without an AI key
  // configured, which is otherwise a hard requirement for anything on this page.
  const runQuickScan = async () => {
    if (!isTauri() || !sessionId) return;
    const requestId = ++quickScanRequestId.current;
    const requestSessionId = sessionId;
    setQuickScanning(true);
    setQuickScan(null);
    try {
      const result = await invoke<AutonomousAnalysisResult>("run_autonomous_session_analysis", {
        sessionId,
        mode,
      });
      if (
        quickScanRequestId.current === requestId
        && currentSessionId.current === requestSessionId
      ) {
        setQuickScan(result);
      }
    } catch (reason) {
      if (
        quickScanRequestId.current === requestId
        && currentSessionId.current === requestSessionId
      ) {
        dispatchStream({ type: "set-error", message: String(reason) });
      }
    } finally {
      if (quickScanRequestId.current === requestId) setQuickScanning(false);
    }
  };

  const startAnalysis = async (overrides?: { mode?: AnalysisMode; includeStatic?: boolean }) => {
    if (!sessionId || requests.length === 0 || running || analysisCommandPending.current || !streamListenerReady) return;
    const analysisMode = overrides?.mode ?? mode;
    const includeStaticResources = overrides?.includeStatic ?? includeStatic;
    if (overrides?.mode) setMode(overrides.mode);
    if (overrides?.includeStatic !== undefined) setIncludeStatic(overrides.includeStatic);
    if (!isTauri()) {
      dispatchStream({ type: "fail", message: "真实 AI 分析需要在 ShowNet 桌面应用中运行" });
      return;
    }
    if (requiresApiKey) {
      dispatchStream({ type: "fail", message: "尚未配置 AI API Key。加入 QQ 群后可联系管理员申请一次性 5 美金免费额度。" });
      return;
    }
    const commandRequestId = ++analysisCommandRequestId.current;
    analysisCommandPending.current = true;
    const commandSessionId = sessionId;
    historyRequestId.current += 1;
    reportRestoreRequestId.current += 1;
    followupRequestId.current += 1;
    followupCommandPending.current = false;
    if (activeAnalysisId.current) supersededAnalysisIds.current.add(activeAnalysisId.current);
    activeAnalysisId.current = "";
    setMessages([]);
    setSkillRuns([]);
    setGraphRun(null);
    setReplayExport(null);
    setExportingReplay(false);
    replayExportRequestId.current += 1;
    setEvalExport(null);
    setExportingEval(false);
    evalExportRequestId.current += 1;
    dispatchStream({
      type: "start",
      filtering: smartFilteringEnabled,
      message: smartFilteringEnabled ? "正在识别关键请求" : "准备直接进入深度分析",
    });
    try {
      const completed = await invoke<AnalysisReport>("start_ai_analysis", {
        input: {
          sessionId,
          mode: analysisMode,
          includeStatic: includeStaticResources,
          manualRequestIds: manualScope ? manualRequests.map((request) => request.id) : [],
          includeAnnotations,
        },
      });
      if (
        analysisCommandRequestId.current !== commandRequestId
        || currentSessionId.current !== commandSessionId
        || (activeAnalysisId.current && activeAnalysisId.current !== completed.id)
      ) {
        return;
      }
      activeAnalysisId.current = completed.id;
      setReports((items) => [completed, ...items.filter((item) => item.id !== completed.id)]);
      dispatchStream({ type: "command-complete", report: completed });
      const completedGraph = await invoke<AnalysisGraphRun | null>("get_analysis_graph_run", { analysisId: completed.id }).catch(() => null);
      if (
        analysisCommandRequestId.current === commandRequestId
        && currentSessionId.current === commandSessionId
        && activeAnalysisId.current === completed.id
      ) {
        setGraphRun(completedGraph);
      }
    } catch (analysisError) {
      if (
        analysisCommandRequestId.current === commandRequestId
        && currentSessionId.current === commandSessionId
      ) {
        dispatchStream({ type: "command-failed", message: String(analysisError) });
      }
    } finally {
      if (analysisCommandRequestId.current === commandRequestId) {
        analysisCommandPending.current = false;
      }
    }
  };

  const cancelAnalysis = async () => {
    if (!isTauri() || !running || !activeAnalysisId.current || cancelling) return;
    dispatchStream({ type: "cancel-requested" });
    try {
      await invoke("cancel_ai_analysis", { analysisId: activeAnalysisId.current });
    } catch (cancelError) {
      dispatchStream({ type: "cancel-failed", message: String(cancelError) });
    }
  };

  useEffect(() => {
    if (!autoRunId || handledAutoRunId.current === autoRunId) return;
    if (!aiSettingsLoaded || !analysisSettingsLoaded || !historyLoaded || !streamListenerReady || requests.length === 0 || running) return;
    handledAutoRunId.current = autoRunId;
    onAutoRunConsumed();
    void startAnalysis({ mode: "crypto", includeStatic: true });
  }, [aiSettingsLoaded, analysisSettingsLoaded, autoRunId, historyLoaded, onAutoRunConsumed, requests.length, running, streamListenerReady]);

  const ask = async () => {
    const value = question.trim();
    if (!value || sending || !report || followupCommandPending.current) return;
    const requestId = ++followupRequestId.current;
    followupCommandPending.current = true;
    const analysisId = report.id;
    const requestSessionId = sessionId;
    const isCurrent = () => (
      followupRequestId.current === requestId
      && currentSessionId.current === requestSessionId
      && activeAnalysisId.current === analysisId
    );
    const localId = -Date.now();
    setMessages((items) => [...items, { id: localId, role: "user", content: value }]);
    setQuestion("");
    dispatchStream({ type: "followup-requested" });
    try {
      const reply = await invoke<AnalysisChatMessage>("followup_ai_analysis", {
        input: { analysisId, question: value },
      });
      if (!isCurrent()) return;
      setMessages((items) => [...items, reply]);
      dispatchStream({ type: "followup-finished" });
    } catch (askError) {
      if (isCurrent()) dispatchStream({ type: "followup-failed", message: String(askError) });
    } finally {
      if (followupRequestId.current === requestId) {
        followupCommandPending.current = false;
      }
    }
  };

  const copyReport = async () => {
    if (content) await navigator.clipboard?.writeText(content);
  };

  const exportReplayPackage = async () => {
    if (!report || exportingReplay) return;
    if (!isTauri()) {
      onNotify("算法重播包需要在 ShowNet 桌面应用中导出");
      return;
    }
    const requestId = ++replayExportRequestId.current;
    const requestSessionId = sessionId;
    const reportId = report.id;
    const isCurrent = () => (
      replayExportRequestId.current === requestId
      && currentSessionId.current === requestSessionId
      && activeAnalysisId.current === reportId
    );
    setExportingReplay(true);
    setReplayExport(null);

    try {
      // Always ask where to put the package — never silently write under Application Support.
      const picked = await pickReplayExportDirectory(() =>
        openDialog({
          directory: true,
          multiple: false,
          title: "选择算法重播包保存目录",
        }),
      );
      if (!isCurrent()) return;
      if (picked.status === "cancel") {
        onNotify("已取消导出");
        return;
      }
      if (picked.status === "error") {
        onNotify(`无法打开目录选择：${picked.message}`);
        return;
      }
      const exported = await invoke<AlgorithmReplayExportResult>("export_algorithm_replay_package", {
        sessionId: requestSessionId,
        language: replayLanguage,
        reportId,
        outputDir: picked.path,
      });
      if (!isCurrent()) return;
      setReplayExport(exported);
      const label = replayLanguages.find((item) => item.id === exported.language)?.label ?? exported.language;
      onNotify(`${label} 算法包已导出 · 验证门 ${verificationVerdictLabel(exported.gateVerdict)} · ${exported.files.length} 个文件 · ${exported.directory}`);
    } catch (exportError) {
      if (!isCurrent()) return;
      onNotify(`导出算法包失败：${String(exportError)}`);
    } finally {
      if (replayExportRequestId.current === requestId) setExportingReplay(false);
    }
  };

  const exportSdkPackage = async () => {
    if (exportingSdk) return;
    if (!isTauri()) {
      onNotify("API SDK 需要在 ShowNet 桌面应用中生成");
      return;
    }
    const requestId = ++sdkExportRequestId.current;
    const requestSessionId = sessionId;
    const isCurrent = () => (
      sdkExportRequestId.current === requestId
      && currentSessionId.current === requestSessionId
    );
    setExportingSdk(true);
    setSdkExport(null);
    try {
      const picked = await pickReplayExportDirectory(() =>
        openDialog({ directory: true, multiple: false, title: "选择 API SDK 保存目录" }),
      );
      if (!isCurrent()) return;
      if (picked.status === "cancel") {
        onNotify("已取消生成");
        return;
      }
      if (picked.status === "error") {
        onNotify(`无法打开目录选择：${picked.message}`);
        return;
      }
      const exported = await invoke<SdkExportResult>("build_sdk_package", {
        sessionId: requestSessionId,
        outputDir: picked.path,
      });
      if (!isCurrent()) return;
      setSdkExport(exported);
      // The gap count leads, because a package that looks finished and is not
      // is the failure this feature has to avoid.
      const { gapCount, endpointsTotal } = exported.readiness;
      onNotify(
        gapCount > 0
          ? `SDK 已生成 · 验证门 ${verificationVerdictLabel(exported.gateVerdict)} · ${endpointsTotal} 个端点 · ${gapCount} 处未经抓包证实，见 GAPS.md`
          : `SDK 已生成 · 验证门 ${verificationVerdictLabel(exported.gateVerdict)} · ${endpointsTotal} 个端点 · 无未证实项`,
      );
    } catch (exportError) {
      if (!isCurrent()) return;
      onNotify(`生成 SDK 失败：${String(exportError)}`);
    } finally {
      if (sdkExportRequestId.current === requestId) setExportingSdk(false);
    }
  };

  const exportEvaluationPackage = async () => {
    if (!report || exportingEval) return;
    if (!isTauri()) {
      onNotify("评估包需要在 ShowNet 桌面应用中导出");
      return;
    }
    const requestId = ++evalExportRequestId.current;
    const requestSessionId = sessionId;
    const reportId = report.id;
    const isCurrent = () => (
      evalExportRequestId.current === requestId
      && currentSessionId.current === requestSessionId
      && activeAnalysisId.current === reportId
    );
    setExportingEval(true);
    setEvalExport(null);
    try {
      const picked = await pickReplayExportDirectory(() =>
        openDialog({
          directory: true,
          multiple: false,
          title: "选择评估包保存目录",
        }),
      );
      if (!isCurrent()) return;
      if (picked.status === "cancel") {
        onNotify("已取消导出评估包");
        return;
      }
      if (picked.status === "error") {
        onNotify(`无法打开目录选择：${picked.message}`);
        return;
      }
      const exported = await invoke<EvaluationExportResult>("export_evaluation_package", {
        sessionId: requestSessionId,
        analysisId: reportId,
        outputDir: picked.path,
      });
      if (!isCurrent()) return;
      setEvalExport(exported);
      const score = exported.scorecardComposite != null ? ` · scorecard ${exported.scorecardComposite}` : "";
      onNotify(`评估包已导出 · ${exported.files.length} 个文件${score} · ${exported.directory}`);
    } catch (exportError) {
      if (!isCurrent()) return;
      onNotify(`导出评估包失败：${String(exportError)}`);
    } finally {
      if (evalExportRequestId.current === requestId) setExportingEval(false);
    }
  };

  const scopeControls = (
    <>
          <div className="analysis-section-heading"><div><span className="section-kicker">SCOPE</span><h2>分析范围</h2></div><span className="count-pill">{scopeEstimate.requestCount} / {requests.length}</span></div>
          <label className="switch-row"><span><strong>手动聚焦</strong><small>仅分析已标记关键请求</small></span><input type="checkbox" checked={manualScope} onChange={(event) => setManualScope(event.target.checked)} disabled={running} /><i /></label>
          <label className="switch-row"><span><strong>包含静态资源</strong><small>JS 文件用于代码提取</small></span><input type="checkbox" checked={includeStatic} onChange={(event) => setIncludeStatic(event.target.checked)} disabled={running} /><i /></label>
          <label className="switch-row"><span><strong>包含请求备注</strong><small>默认不发送用户备注</small></span><input type="checkbox" checked={includeAnnotations} onChange={(event) => setIncludeAnnotations(event.target.checked)} disabled={running} /><i /></label>
          <div className="key-request-list">
            {manualRequests.slice(0, 4).map((request) => (
              <div key={request.id}><span className={`status-code status-${Math.floor((request.status ?? 0) / 100)}`}>{request.method}</span><span><strong>{request.path}</strong><small>{request.host}</small></span></div>
            ))}
          </div>
          <div className="analysis-context-summary"><header><span>首轮上下文</span><strong>约 {formatContextSize(scopeEstimate.estimatedBytes)}</strong></header><div><span>正文<em>完整值包含</em></span><span>Hook<em>{scopeEstimate.hookCount} 条请求</em></span><span>代码<em>{scopeEstimate.codeCount} 段</em></span><span>备注<em>{includeAnnotations ? `${scopeEstimate.annotationCount} 条` : "不包含"}</em></span></div><footer><ShieldCheck size={11} />正文单项最多 16 KiB，总提示受 {formatContextSize(promptBudgetBytes(aiSettings.contextTokens))} 上限保护</footer></div>
    </>
  );

  return (
    <section className="analysis-view">
      <aside className="analysis-config">
        <div className="analysis-config__section">
          <span className="section-kicker">ANALYSIS MODE</span>
          <h2>分析模式</h2>
          <div className="analysis-mode-list">
            {modes.map((item) => {
              const Icon = item.icon;
              return (
                <button key={item.id} className={mode === item.id ? "is-active" : ""} onClick={() => setMode(item.id)} disabled={running}>
                  <span className="analysis-mode__icon"><Icon size={17} /></span>
                  <span><strong>{item.label}</strong><small>{item.focus}</small></span>
                  {mode === item.id ? <Check size={15} /> : <Circle size={12} />}
                </button>
              );
            })}
          </div>
        </div>

        <div className="analysis-config__section analysis-scope">{scopeControls}</div>

        <div className="analysis-config__section agent-skill-plan">
          <div className="analysis-section-heading"><div><span className="section-kicker">AGENT PLAN</span><h2>内置 Agent 编排</h2></div><span className="count-pill">{skillPlan?.selectedSkillIds.length ?? 0}</span></div>
          <div className="agent-skill-chips">
            {(skillPlan?.selectedSkillIds ?? []).map((skillId) => <span key={skillId}><Sparkles size={11} />{skillLabel(skillId)}</span>)}
          </div>
          <small className="agent-tool-count">{analysisSettings.allowMcpTools ? `${skillPlan?.toolNames.length ?? 0} 个本地工具按需取证` : "MCP 工具调用已关闭"}</small>
        </div>

        <div className="analysis-launch">
          <button className="model-select" onClick={onConfigureAi} title="配置 AI 服务">
            <Bot size={16} /><span><small>{providerLabel(aiSettings.provider)} · 内置 Agent</small><strong>{aiSettings.model}</strong></span><Settings2 size={14} />
          </button>
          <button className={`analysis-start-button ${running ? "is-running" : ""}`} onClick={() => running ? void cancelAnalysis() : void startAnalysis()} disabled={requests.length === 0 || cancelling || (!running && !streamListenerReady) || (running && !activeAnalysisId.current)}>
            {running ? (cancelling ? <LoaderCircle className="spin" size={17} /> : <Square size={14} fill="currentColor" />) : <Play size={15} fill="currentColor" />}
            {requests.length === 0 ? "暂无可分析请求" : cancelling ? "正在停止" : running ? "停止分析" : status === "complete" ? "重新分析" : "开始分析"}
          </button>
          <button
            className="analysis-quick-scan"
            onClick={() => void runQuickScan()}
            disabled={requests.length === 0 || running || quickScanning}
            title="不调用 AI：规划技能并汇总防护证据，无需配置 API key"
          >
            <Zap size={13} />{quickScanning ? "正在快速分析" : "免 AI 快速分析"}
          </button>
          {quickScan && <div className="analysis-quick-scan__result">
            <strong>已完成 {quickScan.stages.length} 个阶段</strong>
            <span>{quickScan.stages.join(" → ")}</span>
            {quickScan.notes.slice(0, 4).map((note, index) => <small key={index}>{note}</small>)}
          </div>}
        </div>
      </aside>

      <div className="analysis-report">
        <header className="report-header">
          {/* A displayed report describes its own mode. The picker below is
              what the next run will use, and the two can legitimately differ
              once the user starts setting up a different analysis. */}
          <div><span className="section-kicker">AI REPORT</span><h2>{modeLabel(report?.mode ?? mode)}报告</h2></div>
          <div className="report-header__actions">
            {reports.length > 0 && (
              <label className="report-history-select" title="切换历史分析报告">
                <History size={14} />
                <span><small>历史报告</small><strong>{reports.length} 份</strong></span>
                <select
                  value={report?.id ?? ""}
                  onChange={(event) => {
                    const selected = reports.find((item) => item.id === event.target.value);
                    if (selected) void restoreReport(selected);
                  }}
                  disabled={running}
                  aria-label="选择历史分析报告"
                >
                  {!report && <option value="">当前分析</option>}
                  {reports.map((item) => (
                    <option key={item.id} value={item.id}>
                      {formatReportTime(item.updatedAt)} · {modeLabel(item.mode)} · {statusLabel(item.status)} · {item.model}
                    </option>
                  ))}
                </select>
                <ChevronDown size={13} />
              </label>
            )}
            {status === "complete" && <><span className="complete-pill"><Check size={13} />已完成</span><button className="icon-button" title="复制报告" onClick={copyReport}><Copy size={16} /></button></>}
          </div>
        </header>

        <div className="analysis-mobile-launch">
          <label><span>模式</span><select value={mode} onChange={(event) => setMode(event.target.value as AnalysisMode)} disabled={running}>{modes.map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}</select><ChevronDown size={13} /></label>
          <button
            className={`analysis-mobile-scope-toggle ${mobileScopeOpen ? "is-active" : ""}`}
            onClick={() => setMobileScopeOpen((open) => !open)}
            aria-label="调整分析范围"
            aria-expanded={mobileScopeOpen}
            title="调整分析范围"
          >
            <Settings2 size={15} />
          </button>
          <button className={running ? "is-running" : ""} onClick={() => running ? void cancelAnalysis() : void startAnalysis()} disabled={requests.length === 0 || cancelling || (!running && !streamListenerReady) || (running && !activeAnalysisId.current)}>{running ? (cancelling ? <LoaderCircle className="spin" size={15} /> : <Square size={12} fill="currentColor" />) : <Play size={14} fill="currentColor" />}{cancelling ? "停止中" : running ? "停止分析" : status === "complete" ? "重新分析" : "开始分析"}</button>
        </div>

        <section className={`analysis-mobile-scope ${mobileScopeOpen ? "is-open" : ""}`} aria-label="移动端分析范围">{scopeControls}</section>

        {status === "idle" ? (
          <div className="analysis-idle">
            <div className="analysis-idle__mark"><Sparkles size={26} /></div>
            <div className="analysis-preview-flow">
              <div><span>01</span><SearchCheck size={19} /><strong>{smartFilteringEnabled ? "智能过滤" : "直接分析"}</strong><small>{smartFilteringEnabled ? `${requests.length} 条请求` : "已跳过 Phase 1"}</small></div>
              <ArrowRight size={16} />
              <div><span>02</span><Activity size={19} /><strong>Skill 与工具编排</strong><small>{skillPlan?.selectedSkillIds.length ?? 0} Skills{analysisSettings.allowMcpTools ? "" : " · 工具关闭"}</small></div>
              <ArrowRight size={16} />
              <div><span>03</span><MessageSquareText size={19} /><strong>可追问报告</strong><small>保留会话上下文</small></div>
            </div>
            <div className="analysis-idle__stats">
              <span><strong>{apiRequests.length}</strong> API 请求</span>
              <span><strong>{hookCount}</strong> Hook 调用</span>
              <span><strong>{keyRequests.length}</strong> 关键项</span>
            </div>
          </div>
        ) : (
          <div className="report-body">
            {status !== "failed" && <AnalysisProgress status={status} requestCount={requests.length} keyCount={selectedRequestCount} message={phaseMessage} filteringEnabled={smartFilteringEnabled} />}
            {graphRun && <AnalysisGraphPanel run={graphRun} />}
            {agentActivities.length > 0 && <AgentActivityPanel activities={agentActivities} skillRuns={skillRuns} running={running} firstVisibleLatencyMs={firstVisibleLatencyMs} />}
            {status === "failed" && (
              <div className="analysis-error">
                <span><CircleAlert size={20} /></span>
                <div><strong>{failureKind === "cancelled" ? "分析已停止" : "分析未完成"}</strong><p>{error}</p></div>
                {(requiresApiKey || error.includes("API Key")) && <button onClick={onConfigureAi}><KeyRound size={14} />配置 AI</button>}
              </div>
            )}
            {content && (
              <article className="generated-report">
                <div className="report-meta"><Clock3 size={13} />{report?.keyRequestCount ?? selectedRequestCount} 条关键请求 · {report?.model ?? aiSettings.model} · 内置 Agent{planDescribesReport && skillPlan ? ` · ${skillPlan.selectedSkillIds.length} Skills` : ""}</div>
                {report?.selectedRequestIds.length ? <div className="report-evidence-links"><span>证据请求</span>{report.selectedRequestIds.slice(0, 24).map((requestId) => { const request = requests.find((candidate) => candidate.id === requestId); return <button key={requestId} onClick={() => onOpenEvidenceRequest(requestId)}>{request ? `#${request.order} ${request.method} ${request.host}${request.path}` : requestId}</button>; })}{report.selectedRequestIds.length > 24 && <small>另有 {report.selectedRequestIds.length - 24} 条</small>}</div> : null}
                <MarkdownReport content={content} />
                {status === "analyzing" && analysisSettings.streamingOutput && <span className="stream-caret" />}
                <div ref={reportEndRef} />
              </article>
            )}
            {status === "complete" && report && (
              <div className={`replay-export-toolbar ${replayExport ? "is-exported" : ""}`}>
                <span className="replay-export-toolbar__mark" aria-hidden>
                  {replayExport ? <Check size={17} /> : <FolderOpen size={17} />}
                </span>
                <div className="replay-export-toolbar__body">
                  <div className="replay-export-toolbar__heading">
                    <strong>算法还原与重播</strong>
                    <span className="replay-export-pill">{replayExport ? "已写入所选目录" : "先选目录"}</span>
                  </div>
                  <small title={replayExport?.directory}>
                    {replayExport
                      ? `${replayLanguages.find((item) => item.id === replayExport.language)?.label ?? replayExport.language} · 验证门 ${verificationVerdictLabel(replayExport.gateVerdict)} · ${replayExport.files.length} 个文件 · ${replayExport.directory}`
                      : "点击导出将打开系统目录选择；取消不会写入任何文件。包内含报告、算法规格、协议证据与可校验重播实现。"}
                  </small>
                </div>
                <label className="replay-language-select">
                  <select value={replayLanguage} disabled={exportingReplay} onChange={(event) => setReplayLanguage(event.target.value as ReplayLanguage)} aria-label="选择算法重播语言">
                    {replayLanguages.map((language) => <option key={language.id} value={language.id}>{language.label}</option>)}
                  </select>
                  <ChevronDown size={13} />
                </label>
                <button
                  className="replay-export-button"
                  onClick={() => void exportReplayPackage()}
                  disabled={exportingReplay}
                  title="先选择保存目录，再写入算法重播包；取消则不写入"
                >
                  {exportingReplay ? <LoaderCircle className="spin" size={14} /> : <FolderOpen size={14} />}
                  {exportingReplay ? "正在导出" : "选择目录并导出"}
                </button>
              </div>
            )}
            <div className={`replay-export-toolbar ${sdkExport ? "is-exported" : ""}`}>
              <span className="replay-export-toolbar__mark" aria-hidden>
                {sdkExport ? <Check size={17} /> : <Package size={17} />}
              </span>
              <div className="replay-export-toolbar__body">
                <div className="replay-export-toolbar__heading">
                  <strong>API SDK（Python）</strong>
                  <span className="replay-export-pill">
                    {sdkExport
                      ? sdkExport.readiness.gapCount > 0
                        ? `${sdkExport.readiness.gapCount} 处未证实`
                        : "无未证实项"
                      : "curl_cffi + 指纹自检"}
                  </span>
                </div>
                <small title={sdkExport?.directory}>
                  {sdkExport
                    ? `${sdkExport.readiness.endpointsTotal} 个端点（${sdkExport.readiness.endpointsConfirmed} 个路径参数已互证）· 加解密已验证 ${sdkExport.readiness.cryptoVerified} 个 · 验证门 ${verificationVerdictLabel(sdkExport.gateVerdict)} · ${sdkExport.directory}`
                    : "把这次抓包归纳成端点，生成可直接调用的 Python 客户端：凭据由调用方传入，指纹目标可实测比对，未经证实的部分写在 GAPS.md 并标在对应方法上。"}
                </small>
              </div>
              <button
                className="replay-export-button"
                onClick={() => void exportSdkPackage()}
                disabled={exportingSdk}
                title="选择目录并生成 Python SDK"
              >
                {exportingSdk ? <LoaderCircle className="spin" size={14} /> : <Package size={14} />}
                {exportingSdk ? "正在生成" : "生成 SDK"}
              </button>
            </div>
            {status === "complete" && report && (
              <div className={`replay-export-toolbar ${evalExport ? "is-exported" : ""}`}>
                <span className="replay-export-toolbar__mark" aria-hidden>
                  {evalExport ? <Check size={17} /> : <Package size={17} />}
                </span>
                <div className="replay-export-toolbar__body">
                  <div className="replay-export-toolbar__heading">
                    <strong>评估包（一键导出）</strong>
                    <span className="replay-export-pill">{evalExport ? "已写入所选目录" : "scorecard + schema"}</span>
                  </div>
                  <small title={evalExport?.directory}>
                    {evalExport
                      ? `${evalExport.files.length} 个文件 · L0 ${evalExport.scorecardComposite ?? "—"} · ${evalExport.directory}`
                      : "导出 evidenceHeader、protocolSchemas、fidelity、scorecard L0/L1/L2 与当前分析报告，便于对照与归档。"}
                  </small>
                </div>
                <button
                  className="replay-export-button"
                  onClick={() => void exportEvaluationPackage()}
                  disabled={exportingEval}
                  title="选择目录并导出评估包"
                >
                  {exportingEval ? <LoaderCircle className="spin" size={14} /> : <Package size={14} />}
                  {exportingEval ? "正在导出" : "导出评估包"}
                </button>
              </div>
            )}
            {status === "complete" && report && (
              <div className="followup-area">
                {messages.map((message) => (
                  <div key={message.id} className={`chat-message chat-message--${message.role}`}>
                    <span>{message.role === "assistant" ? <Bot size={15} /> : "你"}</span><div><MarkdownReport content={message.content} compact /></div>
                  </div>
                ))}
                {(sending || pendingAnswer) && <div className="chat-message chat-message--assistant"><span><Bot size={15} /></span>{pendingAnswer ? <div><MarkdownReport content={pendingAnswer} compact /><span className="stream-caret" /></div> : <p className="typing"><i /><i /><i /></p>}</div>}
                {phaseMessage.startsWith("追问失败") && <div className="followup-error"><CircleAlert size={14} />{phaseMessage}</div>}
                <div className="followup-input">
                  <MessageSquareText size={17} />
                  <input value={question} onChange={(event) => setQuestion(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void ask(); }} placeholder="继续追问报告细节" />
                  <button onClick={ask} disabled={!question.trim() || sending} title="发送"><Send size={16} /></button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

function AnalysisGraphPanel({ run }: { run: AnalysisGraphRun }) {
  const definitions = new Map(run.definition.nodes.map((node) => [node.id, node]));
  const current = run.currentNodeId ? definitions.get(run.currentNodeId) : undefined;
  const finished = run.nodes.filter((node) => node.status === "succeeded" || node.status === "failed" || node.status === "skipped").length;
  const deviations = run.events.filter((event) => event.event === "agent-deviation" || event.event === "dynamic-branch-created");
  const tone = run.status === "failed" || run.status === "completedWithGaps"
    ? "warning"
    : run.status === "completed"
      ? "complete"
      : "running";

  return (
    <section className={`analysis-graph-runtime is-${tone}`} aria-label="Agent Graph 轨迹">
      <header>
        <span className="analysis-graph-runtime__mark"><GitBranch size={15} /></span>
        <div>
          <span className="section-kicker">ADVISORY GRAPH</span>
          <strong>{current ? `当前建议：${current.label}` : graphRunLabel(run.status)}</strong>
        </div>
        <div className="analysis-graph-runtime__metrics">
          <span>完整能力</span>
          <span>用户上限 {run.maxModelTurns} 轮</span>
          {deviations.length > 0 && <span>{deviations.length} 次动态切换</span>}
        </div>
      </header>
      <details>
        <summary>
          <span>实际轨迹</span>
          <small>{finished} / {run.nodes.length} 节点</small>
          <ChevronDown size={13} />
        </summary>
        <ol className="analysis-graph-runtime__nodes">
          {run.nodes.map((node) => {
            const definition = definitions.get(node.nodeId);
            return (
              <li key={node.nodeId} className={`is-${node.status} ${node.nodeId === "dynamic-evidence" ? "is-dynamic" : ""}`}>
                <span className="analysis-graph-runtime__node-status">
                  {node.status === "running"
                    ? <LoaderCircle className="spin" size={12} />
                    : node.status === "succeeded"
                      ? <Check size={12} />
                      : node.status === "failed"
                        ? <CircleAlert size={12} />
                        : <Circle size={9} />}
                </span>
                <div>
                  <strong>{definition?.label ?? node.nodeId}</strong>
                  <small>{node.error || definition?.detail || graphNodeStatusLabel(node.status)}</small>
                </div>
                <span>{node.toolCallCount > 0 ? `${node.toolCallCount} 次工具` : graphNodeStatusLabel(node.status)}{node.attempt > 1 ? ` · ${node.attempt} 次尝试` : ""}</span>
              </li>
            );
          })}
        </ol>
        {deviations.length > 0 && (
          <div className="analysis-graph-runtime__deviations">
            {deviations.slice(-3).map((event) => <p key={event.sequence}>{event.detail}</p>)}
          </div>
        )}
      </details>
    </section>
  );
}

function graphRunLabel(status: AnalysisGraphRun["status"]) {
  if (status === "completed") return "建议路径已完成";
  if (status === "completedWithGaps") return "建议路径已完成，存在证据缺口";
  if (status === "failed") return "建议路径未完成";
  if (status === "cancelled") return "分析已停止";
  return "GrokBuild 正在自主推进";
}

function graphNodeStatusLabel(status: AnalysisGraphRun["nodes"][number]["status"]) {
  return ({
    pending: "等待",
    running: "进行中",
    succeeded: "完成",
    failed: "存在缺口",
    skipped: "已跳过",
  })[status];
}

function AgentActivityPanel({ activities, skillRuns, running, firstVisibleLatencyMs }: { activities: AgentActivityEntry[]; skillRuns: SkillRunAudit[]; running: boolean; firstVisibleLatencyMs?: number }) {
  const current = activities.at(-1)!;
  const recent = activities.slice(0, -1).slice(-3).reverse();
  const stateLabel = running ? "实时执行中" : current.status === "error" ? "执行中断" : "本次已完成";
  return (
    <section className={`agent-activity ${running ? "is-live" : ""}`} aria-live="polite" aria-label="内置 Agent 执行轨迹">
      <header>
        <span className="agent-activity__mark"><Activity size={15} /></span>
        <div><span className="section-kicker">AGENT ACTIVITY</span><strong>内置 Agent 执行轨迹</strong></div>
        <span className={`agent-activity__state is-${running ? "running" : current.status}`}><i />{stateLabel} · {activities.length} 步{firstVisibleLatencyMs !== undefined ? ` · 首段 ${formatMetricDuration(firstVisibleLatencyMs)}` : ""}</span>
      </header>
      <div className={`agent-activity__current is-${current.status}`}>
        <span className="agent-activity__status-icon">
          {current.status === "running" ? <LoaderCircle className="spin" size={16} /> : current.status === "error" ? <CircleAlert size={16} /> : <Check size={16} />}
        </span>
        <div><small>当前步骤</small><strong>{current.title}</strong><p>{current.detail}</p></div>
        <time>{formatActivityTime(current.updatedAt)}</time>
      </div>
      {recent.length > 0 && (
        <ol className="agent-activity__recent">
          {recent.map((item) => (
            <li key={item.id} className={`is-${item.status}`}>
              <span>{item.status === "error" ? <CircleAlert size={12} /> : <Check size={12} />}</span>
              <div><strong>{item.title}</strong><small>{item.detail}</small></div>
              <time>{formatActivityTime(item.updatedAt)}</time>
            </li>
          ))}
        </ol>
      )}
      {skillRuns.length > 0 && (
        <div className="agent-skill-runs">
          <div className="agent-skill-runs__heading"><span>SKILL RUNS</span><strong>{skillRuns.length} 个执行单元</strong></div>
          <ul>
            {skillRuns.map((run) => (
              <li key={run.id}>
                <span className={`agent-skill-runs__status is-${run.status}`}>
                  {run.status === "running" ? <LoaderCircle className="spin" size={12} /> : run.status === "failed" ? <CircleAlert size={12} /> : <Check size={12} />}
                </span>
                <div><strong>{run.skillName}<small>v{run.skillVersion}</small></strong><span>{run.actualToolCalls.length} 次工具调用 · {run.permissions.length} 项权限</span>{run.error && <span className="agent-skill-runs__error" title={run.error}>{run.error}</span>}</div>
                <time>{formatDuration(run.durationMs, run.status)}</time>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function formatDuration(durationMs: number | undefined, status: SkillRunAudit["status"]) {
  if (status === "running") return "执行中";
  if (durationMs === undefined) return "--";
  if (durationMs < 1_000) return `${durationMs} ms`;
  return `${(durationMs / 1_000).toFixed(durationMs < 10_000 ? 1 : 0)} s`;
}

function formatMetricDuration(durationMs: number) {
  if (durationMs < 1_000) return `${durationMs} ms`;
  return `${(durationMs / 1_000).toFixed(durationMs < 10_000 ? 1 : 0)} s`;
}

function formatActivityTime(value: number) {
  return new Date(value).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function formatReportTime(value: number) {
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return "未知时间";
  return timestamp.toLocaleString("zh-CN", {
    month: "numeric",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

function modeLabel(mode: AnalysisMode) {
  return modes.find((item) => item.id === mode)?.label ?? mode;
}

function statusLabel(status: AnalysisReport["status"]) {
  if (status === "complete") return "已完成";
  if (status === "failed") return "失败";
  return "未完成";
}

function verificationVerdictLabel(verdict: AlgorithmReplayExportResult["gateVerdict"]) {
  if (verdict === "verified") return "已验证";
  if (verdict === "failed") return "失败";
  return "不可验证";
}

function AnalysisProgress({ status, requestCount, keyCount, message, filteringEnabled }: { status: AnalysisStatus; requestCount: number; keyCount: number; message: string; filteringEnabled: boolean }) {
  const filteringDone = status === "analyzing" || status === "complete";
  const analysisDone = status === "complete";
  const filteringSkipped = !filteringEnabled;
  return (
    <div className="analysis-progress">
      <div className={`progress-step ${filteringDone ? "is-done" : "is-running"}`}>
        <span>{filteringDone ? <Check size={14} /> : <LoaderCircle className="spin" size={14} />}</span>
        <div><strong>Phase 1 · 智能过滤</strong><small>{filteringDone ? filteringSkipped ? `本次直接分析，保留 ${keyCount} 条` : `${requestCount} 条中选出 ${keyCount} 条关键请求` : message || `正在评估 ${requestCount} 条请求`}</small></div>
        {filteringDone && <em>{filteringSkipped ? "跳过" : "完成"}</em>}
      </div>
      <div className={`progress-line ${filteringDone ? "is-done" : ""}`} />
      <div className={`progress-step ${status === "analyzing" ? "is-running" : analysisDone ? "is-done" : "is-pending"}`}>
        <span>{analysisDone ? <Check size={14} /> : status === "analyzing" ? <LoaderCircle className="spin" size={14} /> : <Circle size={11} />}</span>
        <div><strong>Phase 2 · 深度分析</strong><small>{status === "analyzing" ? message || "正在生成报告" : analysisDone ? "协议与风险结论已生成" : "等待过滤结果"}</small></div>
        {analysisDone && <em>完成</em>}
      </div>
    </div>
  );
}

function MarkdownReport({ content, compact = false }: { content: string; compact?: boolean }) {
  const lines = content.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) {
      index += 1;
      continue;
    }
    if (line.trimStart().startsWith("```")) {
      const language = line.trim().slice(3);
      const code: string[] = [];
      index += 1;
      while (index < lines.length && !lines[index].trimStart().startsWith("```")) {
        code.push(lines[index]);
        index += 1;
      }
      index += 1;
      blocks.push(<pre className="report-code" data-language={language || undefined} key={`code-${index}`}>{code.join("\n")}</pre>);
      continue;
    }
    const heading = /^(#{1,3})\s+(.+)$/.exec(line.trim());
    if (heading) {
      blocks.push(<h3 key={`heading-${index}`} className={heading[1].length === 1 ? "is-primary" : undefined}>{renderInline(heading[2])}</h3>);
      index += 1;
      continue;
    }
    if (line.trim().startsWith("|") && index + 1 < lines.length && /^\s*\|?\s*:?-+/.test(lines[index + 1])) {
      const rows: string[][] = [];
      while (index < lines.length && lines[index].trim().startsWith("|")) {
        if (!/^\s*\|?\s*:?-+/.test(lines[index])) rows.push(splitTableRow(lines[index]));
        index += 1;
      }
      const [header, ...body] = rows;
      blocks.push(<div className="report-table-wrap" key={`table-${index}`}><table><thead><tr>{header.map((cell, cellIndex) => <th key={cellIndex}>{renderInline(cell)}</th>)}</tr></thead><tbody>{body.map((row, rowIndex) => <tr key={rowIndex}>{row.map((cell, cellIndex) => <td key={cellIndex}>{renderInline(cell)}</td>)}</tr>)}</tbody></table></div>);
      continue;
    }
    if (/^\s*[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^\s*[-*]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*[-*]\s+/, ""));
        index += 1;
      }
      blocks.push(<ul key={`list-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ul>);
      continue;
    }
    if (/^\s*\d+[.)]\s+/.test(line)) {
      const items: string[] = [];
      while (index < lines.length && /^\s*\d+[.)]\s+/.test(lines[index])) {
        items.push(lines[index].replace(/^\s*\d+[.)]\s+/, ""));
        index += 1;
      }
      blocks.push(<ol key={`ordered-${index}`}>{items.map((item, itemIndex) => <li key={itemIndex}>{renderInline(item)}</li>)}</ol>);
      continue;
    }
    if (line.trimStart().startsWith(">")) {
      blocks.push(<blockquote key={`quote-${index}`}>{renderInline(line.replace(/^\s*>\s?/, ""))}</blockquote>);
      index += 1;
      continue;
    }
    const paragraph = [line.trim()];
    index += 1;
    while (index < lines.length && lines[index].trim() && !/^(#{1,3})\s+|^\s*```|^\s*[-*]\s+|^\s*\d+[.)]\s+|^\s*>/.test(lines[index])) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push(<p key={`paragraph-${index}`}>{renderInline(paragraph.join(" "))}</p>);
  }
  return <div className={`markdown-report ${compact ? "is-compact" : ""}`}>{blocks}</div>;
}

function renderInline(value: string): ReactNode {
  return value.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((part, index) => {
    if (part.startsWith("**") && part.endsWith("**")) return <strong key={index}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`")) return <code key={index}>{part.slice(1, -1)}</code>;
    return <Fragment key={index}>{part}</Fragment>;
  });
}

function splitTableRow(row: string) {
  return row.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function providerLabel(provider: AiProviderSettings["provider"]) {
  if (provider === "claudegpt") return "ClaudeGPT.org";
  if (provider === "local") return "本地模型";
  return "OpenAI 兼容服务";
}

function skillLabel(skillId: string) {
  return builtInSkillPreview.find((skill) => skill.id === skillId)?.name ?? "未命名能力";
}
