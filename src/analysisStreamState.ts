import type {
  AnalysisActivity,
  AnalysisReport,
  AnalysisStatus,
  AnalysisStreamEvent,
} from "./types";

export type AgentActivityPhase =
  | "filtering"
  | "analyzing"
  | "runtime"
  | "reasoning"
  | "tool"
  | "tool-complete"
  | "tool-error"
  | "graph-node"
  | "graph-retry"
  | "artifact-valid"
  | "artifact-invalid"
  | "graph-complete"
  | "generating"
  | "first-visible"
  | "complete"
  | "error";

export type AgentActivityStatus = "running" | "complete" | "error";

export interface AgentActivityEntry {
  id: string;
  phase: AgentActivityPhase;
  status: AgentActivityStatus;
  title: string;
  detail: string;
  toolKey?: string;
  startedAt: number;
  updatedAt: number;
}

export interface AnalysisStreamState {
  status: AnalysisStatus;
  report: AnalysisReport | null;
  content: string;
  phaseMessage: string;
  error: string;
  failureKind: "none" | "cancelled" | "error";
  pendingAnswer: string;
  sending: boolean;
  cancelling: boolean;
  streamKeyCount: number;
  agentActivities: AgentActivityEntry[];
  firstVisibleLatencyMs?: number;
}

export type AnalysisStreamAction =
  | { type: "reset" }
  | { type: "notice"; message: string }
  | { type: "set-error"; message: string }
  | { type: "fail"; message: string; occurredAt?: number }
  | { type: "restore"; report: AnalysisReport }
  | { type: "recover"; report: AnalysisReport; running: boolean }
  | { type: "recovery-error"; message: string }
  | { type: "restore-activities"; activities: AnalysisActivity[] }
  | { type: "start"; filtering: boolean; message: string; occurredAt?: number }
  | { type: "event"; event: AnalysisStreamEvent; occurredAt?: number }
  | { type: "command-complete"; report: AnalysisReport; occurredAt?: number }
  | { type: "command-failed"; message: string; occurredAt?: number }
  | { type: "cancel-requested" }
  | { type: "cancel-failed"; message: string }
  | { type: "followup-requested" }
  | { type: "followup-finished" }
  | { type: "followup-failed"; message: string };

const maxAgentActivities = 12;

export function createAnalysisStreamState(): AnalysisStreamState {
  return {
    status: "idle",
    report: null,
    content: "",
    phaseMessage: "",
    error: "",
    failureKind: "none",
    pendingAnswer: "",
    sending: false,
    cancelling: false,
    streamKeyCount: 0,
    agentActivities: [],
    firstVisibleLatencyMs: undefined,
  };
}

export function analysisStreamReducer(
  state: AnalysisStreamState,
  action: AnalysisStreamAction,
): AnalysisStreamState {
  if (action.type === "reset") return createAnalysisStreamState();
  if (action.type === "notice") return { ...state, phaseMessage: action.message };
  if (action.type === "set-error") return { ...state, error: action.message };
  if (action.type === "restore") return restoreReportState(state, action.report);
  if (action.type === "recover") {
    if (
      state.report?.id !== action.report.id
      || state.status === "complete"
      || state.status === "failed"
    ) {
      return state;
    }
    if (action.running) {
      return {
        ...state,
        status: action.report.status,
        error: "",
        failureKind: "none",
        cancelling: false,
      };
    }
    return failState(state, "这次分析未正常结束，可重新开始分析", Date.now());
  }
  if (action.type === "recovery-error") {
    if (state.status === "complete" || state.status === "failed") return state;
    return failState(state, action.message, Date.now());
  }
  if (action.type === "restore-activities") {
    const restored = restoreAgentActivities(action.activities);
    const latencyActivity = [...action.activities]
      .reverse()
      .find((activity) => activity.phase === "first-visible" && activity.elapsedMs !== undefined);
    return {
      ...state,
      agentActivities: restored,
      firstVisibleLatencyMs: latencyActivity?.elapsedMs ?? state.firstVisibleLatencyMs,
      phaseMessage: state.status === "complete"
        ? state.phaseMessage
        : restored.at(-1)?.title ?? state.phaseMessage,
    };
  }
  if (action.type === "start") {
    const phase: AgentActivityPhase = action.filtering ? "filtering" : "analyzing";
    const occurredAt = action.occurredAt ?? Date.now();
    return {
      ...createAnalysisStreamState(),
      status: action.filtering ? "filtering" : "analyzing",
      phaseMessage: action.message,
      agentActivities: updateAgentActivities([], phase, action.message, occurredAt),
    };
  }
  if (action.type === "event") {
    return reduceStreamEvent(state, action.event, action.occurredAt ?? Date.now());
  }
  if (action.type === "command-complete") {
    return completeState(state, action.report, action.occurredAt ?? Date.now());
  }
  if (action.type === "command-failed") {
    if (state.status === "complete" || state.status === "failed") return state;
    return failState(state, action.message, action.occurredAt ?? Date.now());
  }
  if (action.type === "fail") {
    return failState(state, action.message, action.occurredAt ?? Date.now());
  }
  if (action.type === "cancel-requested") {
    return { ...state, cancelling: true, phaseMessage: "正在停止分析" };
  }
  if (action.type === "cancel-failed") {
    if (!state.cancelling) return state;
    return {
      ...state,
      cancelling: false,
      error: action.message,
      phaseMessage: `停止分析失败：${action.message}`,
    };
  }
  if (action.type === "followup-requested") {
    return { ...state, pendingAnswer: "", phaseMessage: "", sending: true };
  }
  if (action.type === "followup-finished") {
    return { ...state, pendingAnswer: "", phaseMessage: "", sending: false };
  }
  return {
    ...state,
    sending: false,
    phaseMessage: action.message.startsWith("追问失败")
      ? action.message
      : `追问失败：${action.message}`,
  };
}

function restoreReportState(
  state: AnalysisStreamState,
  report: AnalysisReport,
): AnalysisStreamState {
  const cancelled = isCancellation(report.error);
  return {
    ...state,
    status: report.status,
    report,
    content: report.content,
    phaseMessage: "",
    error: report.status === "failed" ? report.error ?? "分析未完成" : "",
    failureKind: report.status === "failed" ? (cancelled ? "cancelled" : "error") : "none",
    pendingAnswer: "",
    sending: false,
    cancelling: false,
    streamKeyCount: report.keyRequestCount,
    agentActivities: [],
    firstVisibleLatencyMs: undefined,
  };
}

function reduceStreamEvent(
  state: AnalysisStreamState,
  event: AnalysisStreamEvent,
  occurredAt: number,
): AnalysisStreamState {
  if (!state.sending && isFollowupStreamPhase(event.phase)) return state;
  if (
    state.report?.status === "complete"
    && (
      isReportOnlyPhase(event.phase)
      || (!state.sending && isReportGenerationPhase(event.phase))
    )
  ) {
    return state;
  }

  let next = state;
  if (isAgentActivityPhase(event.phase)) {
    next = {
      ...next,
      agentActivities: updateAgentActivities(
        next.agentActivities,
        event.phase,
        event.message,
        occurredAt,
      ),
    };
  }

  if (event.phase === "filtering") {
    return {
      ...next,
      status: "filtering",
      phaseMessage: event.message ?? "正在识别关键请求",
    };
  }
  if (isAnalysisWorkPhase(event.phase)) {
    const descriptor = isAgentActivityPhase(event.phase)
      ? describeAgentActivity(event.phase, event.message)
      : undefined;
    const completedReport = next.report?.status === "complete";
    return {
      ...next,
      status: completedReport ? "complete" : "analyzing",
      phaseMessage: descriptor?.title ?? event.message ?? "正在分析",
      streamKeyCount: event.keyRequestCount,
      firstVisibleLatencyMs: event.phase === "first-visible"
        ? event.elapsedMs ?? next.firstVisibleLatencyMs
        : next.firstVisibleLatencyMs,
    };
  }
  if (event.phase === "content-reset") {
    return { ...next, status: "analyzing", content: "" };
  }
  if (event.phase === "delta") {
    return { ...next, status: "analyzing", content: next.content + event.delta };
  }
  if (event.phase === "complete" && event.report) {
    return completeState(next, event.report, occurredAt, false);
  }
  if (event.phase === "error") {
    const report = event.report ?? next.report;
    return {
      ...failState(next, event.message ?? "AI 分析失败", occurredAt, false),
      report,
      content: report?.content ?? next.content,
      streamKeyCount: report?.keyRequestCount ?? next.streamKeyCount,
    };
  }
  if (event.phase === "followup-start") {
    return { ...next, pendingAnswer: "", sending: true };
  }
  if (event.phase === "followup-delta") {
    return { ...next, pendingAnswer: next.pendingAnswer + event.delta, sending: true };
  }
  if (event.phase === "followup-complete") {
    return { ...next, phaseMessage: "", sending: false };
  }
  if (event.phase === "followup-error") {
    return {
      ...next,
      sending: false,
      phaseMessage: `追问失败：${event.message ?? "模型未返回回答"}`,
    };
  }
  return next;
}

function completeState(
  state: AnalysisStreamState,
  report: AnalysisReport,
  occurredAt: number,
  appendActivity = true,
): AnalysisStreamState {
  return {
    ...state,
    status: "complete",
    report,
    content: report.content,
    phaseMessage: "",
    error: "",
    failureKind: "none",
    cancelling: false,
    streamKeyCount: report.keyRequestCount,
    agentActivities: appendActivity
      ? updateAgentActivities(state.agentActivities, "complete", "分析报告已生成", occurredAt)
      : state.agentActivities,
  };
}

function failState(
  state: AnalysisStreamState,
  message: string,
  occurredAt: number,
  appendActivity = true,
): AnalysisStreamState {
  return {
    ...state,
    status: "failed",
    error: message,
    failureKind: isCancellation(message) ? "cancelled" : "error",
    cancelling: false,
    agentActivities: appendActivity
      ? updateAgentActivities(state.agentActivities, "error", message, occurredAt)
      : state.agentActivities,
  };
}

function isCancellation(message?: string) {
  return Boolean(message && (message.includes("已取消") || message.includes("已停止")));
}

function isAnalysisWorkPhase(phase: AnalysisStreamEvent["phase"]) {
  return phase === "analyzing"
    || phase === "runtime"
    || phase === "reasoning"
    || phase === "tool"
    || phase === "tool-complete"
    || phase === "tool-error"
    || isGraphActivityPhase(phase)
    || phase === "generating"
    || phase === "first-visible";
}

function isReportGenerationPhase(phase: AnalysisStreamEvent["phase"]) {
  return phase === "filtering"
    || phase === "content-reset"
    || phase === "delta"
    || phase === "complete"
    || phase === "error"
    || isAnalysisWorkPhase(phase);
}

function isReportOnlyPhase(phase: AnalysisStreamEvent["phase"]) {
  return phase === "filtering"
    || phase === "analyzing"
    || phase === "runtime"
    || phase === "reasoning"
    || phase === "generating"
    || phase === "first-visible"
    || phase === "content-reset"
    || phase === "delta"
    || phase === "complete"
    || phase === "error"
    || isGraphActivityPhase(phase);
}

function isFollowupStreamPhase(phase: AnalysisStreamEvent["phase"]) {
  return phase === "followup-start"
    || phase === "followup-delta"
    || phase === "followup-complete"
    || phase === "followup-error";
}

export function isAgentActivityPhase(phase: string): phase is AgentActivityPhase {
  return phase === "filtering"
    || phase === "analyzing"
    || phase === "runtime"
    || phase === "reasoning"
    || phase === "tool"
    || phase === "tool-complete"
    || phase === "tool-error"
    || phase === "graph-node"
    || phase === "graph-retry"
    || phase === "artifact-valid"
    || phase === "artifact-invalid"
    || phase === "graph-complete"
    || phase === "generating"
    || phase === "first-visible"
    || phase === "complete"
    || phase === "error";
}

export function isGraphActivityPhase(phase: string) {
  return phase === "graph-node"
    || phase === "graph-retry"
    || phase === "artifact-valid"
    || phase === "artifact-invalid"
    || phase === "graph-complete";
}

const toolActivityLabels: Record<string, string> = {
  shownet_list_requests: "读取请求索引",
  shownet_get_request: "读取请求证据",
  shownet_get_hooks: "关联 JS Hook",
  shownet_get_crypto_snippets: "读取加密代码",
  shownet_get_tls_fingerprints: "读取 TLS 指纹",
  shownet_get_outbound_tls_status: "读取出站 TLS 状态",
  shownet_list_px_evidence: "列出 PX 证据",
  shownet_decode_px_payload: "解码 PX 结构",
  shownet_analyze_dynamic_protection: "聚合动态防护证据",
  shownet_get_websocket_frames: "读取 WebSocket 消息",
  shownet_get_sse_events: "读取 SSE 事件流",
  shownet_build_signature_harness: "生成动态签名适配器",
  shownet_build_algorithm_replay: "生成多语言算法重播包",
  shownet_export_analysis_artifacts: "导出报告与算法重播包",
  shownet_list_js_debug_profiles: "列出 JS 调试固定参数档",
  shownet_build_web_risk_lab: "构建 Web 风控研究 Lab",
  shownet_eval_js_sandbox: "JS 虚拟沙箱求值",
  shownet_build_request_hijack_script: "生成请求体劫持脚本",
  shownet_build_object_dump_script: "生成对象自吐脚本",
  shownet_plan_physical_interactions: "规划物理点击 CDP 序列",
  shownet_build_vision_captcha_package: "生成视觉验证码 VLM 包",
  shownet_run_offline_lab_probe: "离线 Lab 探针（objectDump）",
  shownet_map_vision_captcha_indices: "视觉验证码索引映射坐标",
  shownet_seed_web_risk_fixture: "种子 Web 风控 fixture 会话",
  shownet_solve_vision_captcha: "视觉验证码 VLM 求解",
  shownet_decode_challenge_js: "沙箱解码 challenge.js",
  shownet_eval_scorecard: "机检 scorecard L0/L1/L2",
  shownet_browser_status: "Browser 总线状态",
  shownet_browser_evaluate: "Browser 总线 evaluate",
  shownet_browser_click: "Browser 总线点击",
  shownet_browser_screenshot: "Browser 总线截图",
  shownet_browser_navigate: "Browser 总线导航",
  shownet_browser_insert_text: "Browser 总线输入文本",
  shownet_browser_install_lab: "Browser 一键注入风控 Lab",
  shownet_generate_code: "生成调用代码",
  shownet_get_report: "读取历史分析报告",
  shownet_get_skill_runs: "读取 Skill 执行审计",
  shownet_list_sessions: "读取会话索引",
  shownet_list_skills: "读取 Skill 能力",
  shownet_plan_analysis: "编排分析计划",
};

function activityToolKey(message?: string) {
  if (!message) return undefined;
  const known = Object.keys(toolActivityLabels).find((name) => message.includes(name));
  if (known) return known;
  return /(?:调用\s*|^)([a-zA-Z][a-zA-Z0-9_.:-]+)(?:\s|已|$)/.exec(message)?.[1];
}

export function describeAgentActivity(phase: AgentActivityPhase, message?: string) {
  const toolKey = activityToolKey(message);
  const toolTitle = toolKey ? toolActivityLabels[toolKey] ?? "调用 MCP 扩展工具" : undefined;
  if (phase === "filtering") return { title: "筛选关键请求", detail: message || "正在从会话流量中识别有效证据" };
  if (phase === "analyzing") return { title: "编排分析任务", detail: message || "正在选择 Skill 并建立证据范围" };
  if (phase === "runtime") return { title: "启动内置 Agent", detail: message || "正在创建隔离运行环境并加载分析能力" };
  if (phase === "reasoning") return { title: "关联会话证据", detail: message || "正在核对请求、Hook、指纹与 Skill 证据" };
  if (phase === "generating") return { title: "生成分析报告", detail: message || "证据收集完成，正在组织结论与依据" };
  if (phase === "first-visible") return { title: "首段报告已显示", detail: message || "第一段可见正文已送达界面" };
  if (phase === "tool") return { title: toolTitle || "按需收集分析证据", detail: toolKey ? "正在通过本地 MCP 读取证据" : message || "内置 Agent 正在补充会话证据", toolKey };
  if (phase === "tool-complete") return { title: toolTitle || "分析证据已返回", detail: "工具调用完成，证据已加入当前上下文", toolKey };
  if (phase === "tool-error") return { title: toolTitle || "分析工具调用失败", detail: "未取得可用结果，内置 Agent 将继续评估现有证据", toolKey };
  if (phase === "graph-node") return { title: "调整建议路径", detail: message || "Agent 正在根据证据选择下一项工作" };
  if (phase === "graph-retry") return { title: "重新校验产物", detail: message || "产物未满足契约，正在补全" };
  if (phase === "artifact-valid") return { title: "产物校验通过", detail: message || "当前 Skill 产物已经可供报告使用" };
  if (phase === "artifact-invalid") return { title: "产物存在缺口", detail: message || "当前缺口将如实进入最终报告" };
  if (phase === "graph-complete") return { title: "建议路径已收束", detail: message || "Graph 轨迹与 Skill 产物已归档" };
  if (phase === "complete") return { title: "分析报告已生成", detail: "取证过程与报告内容已完成" };
  if (isCancellation(message)) return { title: "分析已停止", detail: message || "用户已停止本次分析" };
  return { title: "内置 Agent 执行未完成", detail: message || "执行已中断，请查看下方错误信息" };
}

export function updateAgentActivities(
  activities: AgentActivityEntry[],
  phase: AgentActivityPhase,
  message?: string,
  occurredAt = Date.now(),
) {
  const descriptor = describeAgentActivity(phase, message);
  const terminalStatus: AgentActivityStatus = phase === "error" || phase === "tool-error" || phase === "artifact-invalid"
    ? "error"
    : phase === "tool-complete" || phase === "artifact-valid" || phase === "graph-complete" || phase === "first-visible" || phase === "complete"
      ? "complete"
      : "running";

  const last = activities.at(-1);
  if (last?.phase === phase && last.status === terminalStatus && terminalStatus !== "running") {
    return [...activities.slice(0, -1), { ...last, detail: descriptor.detail, updatedAt: occurredAt }];
  }

  if (phase === "tool-complete" || phase === "tool-error") {
    let matchingIndex = -1;
    for (let index = activities.length - 1; index >= 0; index -= 1) {
      const item = activities[index];
      if (item.status === "running" && item.phase === "tool" && (!descriptor.toolKey || item.toolKey === descriptor.toolKey)) {
        matchingIndex = index;
        break;
      }
    }
    if (matchingIndex >= 0) {
      return activities.map((item, index) => index === matchingIndex ? {
        ...item,
        status: terminalStatus,
        detail: descriptor.detail,
        updatedAt: occurredAt,
      } : item).slice(-maxAgentActivities);
    }
  }

  if (
    last?.status === "running"
    && last.phase === phase
    && (
      (Boolean(descriptor.toolKey) && last.toolKey === descriptor.toolKey)
      || phase === "filtering"
      || phase === "analyzing"
      || phase === "runtime"
      || phase === "reasoning"
      || phase === "generating"
    )
  ) {
    return [...activities.slice(0, -1), { ...last, detail: descriptor.detail, updatedAt: occurredAt }];
  }

  const settled = activities.map((item) => item.status === "running" ? {
    ...item,
    status: phase === "error" ? "error" as const : "complete" as const,
    updatedAt: occurredAt,
  } : item);
  return [...settled, {
    id: `${occurredAt}-${phase}-${settled.length}`,
    phase,
    status: terminalStatus,
    title: descriptor.title,
    detail: descriptor.detail,
    toolKey: descriptor.toolKey,
    startedAt: occurredAt,
    updatedAt: occurredAt,
  }].slice(-maxAgentActivities);
}

export function restoreAgentActivities(activities: AnalysisActivity[]) {
  return activities.reduce<AgentActivityEntry[]>((restored, activity) => {
    if (!isAgentActivityPhase(activity.phase)) return restored;
    return updateAgentActivities(restored, activity.phase, activity.message, activity.createdAt);
  }, []);
}
