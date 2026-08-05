import {
  Activity,
  Bot,
  Braces,
  Globe2 as Browser,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleDot,
  Command,
  Copy,
  Download,
  FileArchive,
  FileJson,
  FileSearch,
  FlaskConical,
  FolderOpen,
  KeyRound,
  Laptop,
  Menu,
  MoreHorizontal,
  Network,
  Pause,
  Pencil,
  Plus,
  Radio,
  Route,
  Save,
  Search,
  ServerCog,
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { open, save } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import shownetAppIcon from "./assets/shownet-app-icon.png";
import { isShownetSessionPath } from "./browserDrag";
import { clientAccessModeSummary } from "./clientAccess";
import { AdvancedConsoleView } from "./components/AdvancedConsoleView";
import { AnalysisView } from "./components/AnalysisView";
import { BrowserView } from "./components/BrowserView";
import { RequestWorkbench, type WorkbenchMode } from "./components/RequestWorkbench";
import { SkillsView } from "./components/SkillsView";
import { SettingsView, type SettingsTab } from "./components/SettingsView";
import { TrafficView } from "./components/TrafficView";
import { createPreviewRequestWindow, initialRequestListItems, initialSessions, sourceLabels } from "./data";
import {
  createLiveCaptureDisplayController,
  LIVE_CAPTURE_DISPLAY_PREFERENCES_KEY,
  parseLiveCaptureDisplayPreferences,
  type LiveCaptureDisplaySnapshot,
} from "./liveCaptureDisplay";
import { addCreatedItemsToFacets, createRefreshCoalescer, createRequestListBatcher, createRequestQueryId, isRequestQueryCancelled, mergeRequestWindowItems, queryPreviewRequestList, REQUEST_LIST_WINDOW_SIZE, requiresLiveQueryRefresh } from "./requestList";
import { defaultCaptureSessionName } from "./sessionPresentation";
import type { AnalysisStreamEvent, BreakpointQueueSnapshot, ConnectionDiagnostics, FilterExpression, ProxyTerminalLaunchResult, RequestFacets, RequestListEvent, RequestListItem, RequestListPage, RequestListWindow, RequestQueryCancellationAck, RequestQueryIdleMeasurement, RequestSort, ReverseProxySettingsInput, ReverseProxyStatus, RuntimeStatus, Session, SoakDiagnosticsStatus, SourceType, ViewId } from "./types";
import { useDismissibleLayer } from "./useDismissibleLayer";

const hasNativeRuntime = isTauri();
const defaultRequestSort: RequestSort[] = [{ field: "order", direction: "asc" }];
const emptyRequestFacets: RequestFacets = {
  hosts: [],
  methods: [],
  sources: [],
  protocols: [],
  statuses: [],
  types: [],
  risks: [],
};
const previewRequestWindowEnabled = !hasNativeRuntime
  && import.meta.env.DEV
  && new URLSearchParams(globalThis.location?.search ?? "").get("fixture") === "request-window-100k";
const previewRequestWindowTotal = 100_000;
const previewRequestWindowItems = previewRequestWindowEnabled
  ? createPreviewRequestWindow(0, REQUEST_LIST_WINDOW_SIZE, previewRequestWindowTotal)
  : initialRequestListItems;
const previewRequestListPage: RequestListPage | null = previewRequestWindowEnabled ? {
  items: previewRequestWindowItems,
  nextCursor: "preview:500",
  totalCount: previewRequestWindowTotal,
  filteredCount: previewRequestWindowTotal,
  hookCount: Math.floor(previewRequestWindowTotal / initialRequestListItems.length)
    * initialRequestListItems.filter((request) => request.hasHook).length,
  bookmarkedCount: 0,
  facets: emptyRequestFacets,
} : null;
const REQUEST_QUERY_IDLE_EVENT = "shownet:request-query-idle";

function waitForNextPaint() {
  return new Promise<void>((resolve) => {
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
  });
}

function waitForRequestQueryIdle(queryId: string, timeoutMs = 3_000) {
  return new Promise<RequestQueryIdleMeasurement>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      window.removeEventListener(REQUEST_QUERY_IDLE_EVENT, onIdle as EventListener);
      reject(new Error("request query idle event timed out"));
    }, timeoutMs);
    const onIdle = (event: Event) => {
      const detail = (event as CustomEvent<RequestQueryIdleMeasurement>).detail;
      if (detail.queryId !== queryId) return;
      window.clearTimeout(timeout);
      window.removeEventListener(REQUEST_QUERY_IDLE_EVENT, onIdle as EventListener);
      resolve(detail);
    };
    window.addEventListener(REQUEST_QUERY_IDLE_EVENT, onIdle as EventListener);
  });
}

async function waitForRequestQueryCancelButton(timeoutMs = 1_000) {
  const deadline = performance.now() + timeoutMs;
  while (performance.now() < deadline) {
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
    const button = document.querySelector<HTMLButtonElement>("[data-testid='cancel-request-query']");
    if (button && !button.disabled) return button;
  }
  return undefined;
}

const viewMeta: Record<ViewId, { label: string; title: string; icon: typeof Network }> = {
  traffic: { label: "流量", title: "实时流量", icon: Network },
  browser: { label: "浏览器", title: "内嵌浏览器", icon: Browser },
  lab: { label: "实验室", title: "请求实验室", icon: FlaskConical },
  advanced: { label: "高级", title: "MITM 高级控制台", icon: ShieldCheck },
  analysis: { label: "AI 分析", title: "AI 智能分析", icon: Sparkles },
  skills: { label: "能力", title: "Skill 与 MCP", icon: Braces },
  settings: { label: "设置", title: "抓包与系统设置", icon: Settings },
};

const primaryNavigationGroups: Array<{ label: string; views: ViewId[] }> = [
  { label: "抓包", views: ["traffic", "browser"] },
  { label: "请求工具", views: ["lab", "advanced"] },
  { label: "智能能力", views: ["analysis", "skills"] },
];

const sourceIcons: Record<SourceType, typeof Browser> = {
  browser: Browser,
  desktop: Laptop,
  terminal: Terminal,
  script: Braces,
  mobile: Wifi,
  iot: Radio,
  reverse: Route,
};

const fallbackRuntime: RuntimeStatus = {
  appVersion: "0.1.0",
  platform: navigator.platform.toLowerCase().includes("mac") ? "macos" : "windows",
  proxyPort: 8888,
  listenHost: "127.0.0.1",
  lanEnabled: false,
  accessMode: "private",
  accessRules: [],
  lanAddresses: [],
  proxyRunning: false,
  caInstalled: false,
  transparentModeAvailable: false,
  systemProxyEnabled: false,
  systemProxyActive: false,
  systemProxyRecoveryPending: false,
};

function withClientAccessDefaults(status: RuntimeStatus): RuntimeStatus {
  return {
    ...status,
    accessMode: status.accessMode ?? "private",
    accessRules: Array.isArray(status.accessRules) ? status.accessRules : [],
  };
}

const loadingSession: Session = {
  id: "",
  name: "准备会话",
  createdAt: new Date().toISOString(),
  requestCount: 0,
  errorCount: 0,
  active: false,
  sources: [],
  analysisReportCount: 0,
};

type SessionExportFormat = "har" | "postman" | "openapi";

interface FileExportResult {
  path: string;
  format: string;
  bytes: number;
}

type SessionDropState = {
  status: "idle" | "ready" | "invalid" | "blocked" | "importing";
  path?: string;
};

type ConnectScriptRuntime = "python" | "node" | "go";
type ProxyTerminalPreference = "auto" | "terminal" | "iterm2" | "powershell" | "pwsh" | "cmd" | "gnome-terminal" | "konsole" | "x-terminal-emulator";
const PROXY_TERMINAL_PREFERENCE_KEY = "shownet.proxy-terminal.preference.v1";

function proxyTerminalOptions(platform: string): Array<{ value: ProxyTerminalPreference; label: string }> {
  if (platform === "macos") return [
    { value: "auto", label: "自动（Terminal）" },
    { value: "terminal", label: "Terminal" },
    { value: "iterm2", label: "iTerm2" },
  ];
  if (platform === "windows") return [
    { value: "auto", label: "自动（PowerShell）" },
    { value: "powershell", label: "PowerShell" },
    { value: "pwsh", label: "PowerShell 7" },
    { value: "cmd", label: "CMD" },
  ];
  return [
    { value: "auto", label: "自动选择" },
    { value: "gnome-terminal", label: "GNOME Terminal" },
    { value: "konsole", label: "Konsole" },
    { value: "x-terminal-emulator", label: "系统终端" },
  ];
}

interface WorkbenchLaunchContext {
  id: number;
  mode: WorkbenchMode;
  sessionId: string;
  selected: RequestListItem[];
  createFromSelection: boolean;
}

function formatSessionTime(value: string) {
  if (value === "刚刚" || value.includes("今天") || value.includes("昨天") || value.includes("月")) {
    return value;
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return value;
  const now = new Date();
  const elapsed = now.getTime() - timestamp.getTime();
  if (elapsed >= 0 && elapsed < 60_000) return "刚刚";
  if (timestamp.toDateString() === now.toDateString()) {
    return `今天 ${timestamp.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (timestamp.toDateString() === yesterday.toDateString()) {
    return `昨天 ${timestamp.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false })}`;
  }
  return `${timestamp.getMonth() + 1}月${timestamp.getDate()}日`;
}

async function runLocalEditCommand(action: string, active: Element | null = document.activeElement) {
  if (!(active instanceof HTMLElement)) return;
  if (action === "selectAll") {
    if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) active.select();
    else if (active.isContentEditable) document.execCommand("selectAll");
    return;
  }
  if (action === "undo" || action === "redo") {
    document.execCommand(action);
    return;
  }

  const editable = active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement;
  const start = editable ? active.selectionStart ?? 0 : 0;
  const end = editable ? active.selectionEnd ?? start : 0;
  const selection = editable
    ? active.value.slice(start, end)
    : globalThis.getSelection?.()?.toString() ?? "";
  if (action === "copy" || action === "cut") {
    if (selection) await writeText(selection);
    if (action === "cut" && selection) {
      if (editable) {
        active.setRangeText("", start, end, "end");
        active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "deleteByCut" }));
      } else if (active.isContentEditable) {
        document.execCommand("delete");
      }
    }
    return;
  }
  if (action !== "paste") return;
  const text = await readText();
  if (!text) return;
  if (editable) {
    active.setRangeText(text, start, end, "end");
    active.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste", data: text }));
  } else if (active.isContentEditable) {
    document.execCommand("insertText", false, text);
  }
}

function App() {
  const [activeView, setActiveView] = useState<ViewId>("traffic");
  const [sessions, setSessions] = useState<Session[]>(hasNativeRuntime ? [] : initialSessions);
  const [activeSessionId, setActiveSessionId] = useState(hasNativeRuntime ? "" : initialSessions[0].id);
  const [requests, setRequests] = useState<RequestListItem[]>(hasNativeRuntime ? [] : previewRequestWindowItems);
  const [requestListPage, setRequestListPage] = useState<RequestListPage | null>(previewRequestListPage);
  const [requestWindowOffset, setRequestWindowOffset] = useState(0);
  const [requestWindowTargetOffset, setRequestWindowTargetOffset] = useState<number>();
  const [requestFilter, setRequestFilter] = useState<FilterExpression | undefined>();
  const [requestSort, setRequestSort] = useState<RequestSort[]>(defaultRequestSort);
  const [requestListLoading, setRequestListLoading] = useState(false);
  const [requestQueryCancelling, setRequestQueryCancelling] = useState(false);
  const [capturing, setCapturing] = useState(!hasNativeRuntime);
  const [runtime, setRuntime] = useState<RuntimeStatus>(fallbackRuntime);
  const [connectOpen, setConnectOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const [sessionToolsOpen, setSessionToolsOpen] = useState(false);
  const [renamingSessionId, setRenamingSessionId] = useState("");
  const [sessionNameDraft, setSessionNameDraft] = useState("");
  const [renamingSession, setRenamingSession] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [transferring, setTransferring] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [compactSessions, setCompactSessions] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("capture");
  const [analysisAutoRun, setAnalysisAutoRun] = useState<{ id: number; sessionId: string } | null>(null);
  const [analysisRequestScope, setAnalysisRequestScope] = useState<{ id: number; sessionId: string; requestIds: string[] } | null>(null);
  const [workbenchLaunch, setWorkbenchLaunch] = useState<WorkbenchLaunchContext>();
  const [breakpointQueue, setBreakpointQueue] = useState<BreakpointQueueSnapshot>({ tasks: [], capacity: 32, skippedCount: 0, generatedAt: Date.now() });
  const [evidenceRequestId, setEvidenceRequestId] = useState<string>();
  const [sessionDrop, setSessionDrop] = useState<SessionDropState>({ status: "idle" });
  const sessionToolsRef = useRef<HTMLDivElement>(null);
  const lastLocalEditableRef = useRef<HTMLElement | null>(null);
  const transferringRef = useRef(transferring);
  const requestLoadGenerationRef = useRef(0);
  const requestWindowLoadGenerationRef = useRef(0);
  const requestWindowOffsetRef = useRef(0);
  const requestWindowTargetRef = useRef<number | undefined>(undefined);
  const requestQuerySequenceRef = useRef(0);
  const activeRequestQueryIdRef = useRef<string | undefined>(undefined);
  const liveDisplayPreferences = useMemo(
    () => parseLiveCaptureDisplayPreferences(globalThis.localStorage?.getItem(LIVE_CAPTURE_DISPLAY_PREFERENCES_KEY)),
    [],
  );
  const liveDisplayController = useMemo(
    () => createLiveCaptureDisplayController({ autoProtection: liveDisplayPreferences.autoProtection }),
    [liveDisplayPreferences.autoProtection],
  );
  const [liveDisplay, setLiveDisplay] = useState<LiveCaptureDisplaySnapshot>(() => liveDisplayController.snapshot(Date.now()));
  const liveDisplayPausedRef = useRef(false);
  const liveDisplaySyncingRef = useRef(false);
  const liveDisplaySyncBufferRef = useRef(new Map<string, { item: RequestListItem; created: boolean }>());
  const lastProxyErrorToastAt = useRef(0);

  useDismissibleLayer(sessionToolsOpen, sessionToolsRef, () => setSessionToolsOpen(false));

  const activeSession = sessions.find((session) => session.id === activeSessionId) ?? sessions[0] ?? loadingSession;

  const cancelBackendRequestQuery = useCallback((queryId: string) => {
    if (!hasNativeRuntime) return;
    void invoke<boolean>("cancel_request_query", { queryId }).catch(() => undefined);
  }, []);

  const beginRequestQuery = useCallback(() => {
    const previousQueryId = activeRequestQueryIdRef.current;
    if (previousQueryId) cancelBackendRequestQuery(previousQueryId);
    requestQuerySequenceRef.current += 1;
    const queryId = createRequestQueryId(requestQuerySequenceRef.current);
    activeRequestQueryIdRef.current = queryId;
    return queryId;
  }, [cancelBackendRequestQuery]);

  const finishRequestQuery = useCallback((queryId: string) => {
    if (activeRequestQueryIdRef.current === queryId) activeRequestQueryIdRef.current = undefined;
  }, []);

  const cancelActiveRequestQuery = useCallback(async (notify = false, waitForIdle = false) => {
    const queryId = activeRequestQueryIdRef.current;
    activeRequestQueryIdRef.current = undefined;
    requestLoadGenerationRef.current += 1;
    requestWindowLoadGenerationRef.current += 1;
    requestWindowTargetRef.current = undefined;
    setRequestWindowTargetOffset(undefined);
    if (!queryId || !waitForIdle || !hasNativeRuntime) {
      if (queryId) cancelBackendRequestQuery(queryId);
      setRequestQueryCancelling(false);
      setRequestListLoading(false);
      if (notify && queryId) setToast("查询已取消，仍显示上一次结果");
      return undefined;
    }
    const clickedAt = performance.now();
    setRequestQueryCancelling(true);
    let acknowledgement: RequestQueryCancellationAck;
    try {
      acknowledgement = await invoke<RequestQueryCancellationAck>("cancel_request_query_and_wait", { queryId });
    } catch (error) {
      acknowledgement = {
        queryId,
        accepted: false,
        settled: false,
        backendWaitMs: performance.now() - clickedAt,
      };
      if (notify) setToast(`取消查询失败：${String(error)}`);
    }
    setRequestListLoading(false);
    setRequestQueryCancelling(false);
    if (notify && acknowledgement.settled) setToast("查询已取消，仍显示上一次结果");
    if (notify && !acknowledgement.settled) setToast("查询取消超时，界面已停止等待");
    await waitForNextPaint();
    const measurement: RequestQueryIdleMeasurement = {
      ...acknowledgement,
      clickToIdleMs: performance.now() - clickedAt,
    };
    window.dispatchEvent(new CustomEvent<RequestQueryIdleMeasurement>(REQUEST_QUERY_IDLE_EVENT, { detail: measurement }));
    return measurement;
  }, [cancelBackendRequestQuery]);

  const refreshSessions = useCallback(async () => {
    if (!hasNativeRuntime) return;
    const loaded = await invoke<Session[]>("list_sessions");
    setSessions(loaded);
    setActiveSessionId((current) =>
      loaded.some((session) => session.id === current) ? current : (loaded[0]?.id ?? ""),
    );
  }, []);

  const refreshRequests = useCallback(async (sessionId: string) => {
    if (!hasNativeRuntime || !sessionId) return;
    const generation = ++requestLoadGenerationRef.current;
    requestWindowLoadGenerationRef.current += 1;
    requestWindowTargetRef.current = undefined;
    setRequestWindowTargetOffset(undefined);
    setRequestListLoading(true);
    setRequestQueryCancelling(false);
    const queryId = beginRequestQuery();
    try {
      const loaded = await invoke<RequestListPage>("query_request_list", {
        queryId,
        query: { sessionId, filter: requestFilter, sort: requestSort, limit: REQUEST_LIST_WINDOW_SIZE },
      });
      if (generation !== requestLoadGenerationRef.current) return;
      setRequests(loaded.items);
      setRequestListPage(loaded);
      requestWindowOffsetRef.current = 0;
      setRequestWindowOffset(0);
    } catch (error) {
      if (generation !== requestLoadGenerationRef.current || isRequestQueryCancelled(error)) return;
      throw error;
    } finally {
      finishRequestQuery(queryId);
      if (generation === requestLoadGenerationRef.current) setRequestListLoading(false);
    }
  }, [beginRequestQuery, finishRequestQuery, requestFilter, requestSort]);

  const loadRequestWindow = useCallback(async (sessionId: string, offset: number) => {
    if (!sessionId || (!hasNativeRuntime && !previewRequestWindowEnabled)) return;
    const normalizedOffset = Math.max(0, Math.floor(offset));
    if (normalizedOffset === requestWindowOffsetRef.current) {
      if (requestWindowTargetRef.current !== undefined && requestWindowTargetRef.current !== normalizedOffset) {
        void cancelActiveRequestQuery();
      }
      return;
    }
    if (normalizedOffset === requestWindowTargetRef.current) return;
    const queryGeneration = requestLoadGenerationRef.current;
    const windowGeneration = ++requestWindowLoadGenerationRef.current;
    requestWindowTargetRef.current = normalizedOffset;
    setRequestWindowTargetOffset(normalizedOffset);
    setRequestListLoading(true);
    setRequestQueryCancelling(false);
    const queryId = beginRequestQuery();
    try {
      const loaded = hasNativeRuntime
        ? await invoke<RequestListWindow>("query_request_window", {
          queryId,
          query: {
            sessionId,
            filter: requestFilter,
            sort: requestSort,
            offset: normalizedOffset,
            limit: REQUEST_LIST_WINDOW_SIZE,
          },
        })
        : await new Promise<RequestListWindow>((resolve) => window.setTimeout(() => resolve({
          offset: normalizedOffset,
          items: createPreviewRequestWindow(normalizedOffset, REQUEST_LIST_WINDOW_SIZE, previewRequestWindowTotal),
        }), 140));
      if (queryGeneration !== requestLoadGenerationRef.current || windowGeneration !== requestWindowLoadGenerationRef.current) return;
      requestWindowOffsetRef.current = loaded.offset;
      setRequestWindowOffset(loaded.offset);
      setRequests(loaded.items);
      setRequestListPage((current) => current ? { ...current, items: loaded.items, nextCursor: undefined } : current);
    } catch (error) {
      if (!isRequestQueryCancelled(error) && queryGeneration === requestLoadGenerationRef.current && windowGeneration === requestWindowLoadGenerationRef.current) {
        setToast(`读取流量窗口失败：${String(error)}`);
      }
    } finally {
      finishRequestQuery(queryId);
      if (windowGeneration === requestWindowLoadGenerationRef.current) {
        requestWindowTargetRef.current = undefined;
        setRequestWindowTargetOffset(undefined);
        setRequestListLoading(false);
      }
    }
  }, [beginRequestQuery, cancelActiveRequestQuery, finishRequestQuery, requestFilter, requestSort]);

  const updateRequestQuery = useCallback((filter: FilterExpression | undefined, sort: RequestSort[]) => {
    setRequestFilter(filter);
    setRequestSort(sort.length ? sort : defaultRequestSort);
  }, []);

  const runSoakCancellationProbe = useCallback(async (status: SoakDiagnosticsStatus) => {
    if (!status.sessionId || activeRequestQueryIdRef.current) return undefined;
    const generation = ++requestLoadGenerationRef.current;
    requestWindowLoadGenerationRef.current += 1;
    requestWindowTargetRef.current = undefined;
    setRequestWindowTargetOffset(undefined);
    setRequestQueryCancelling(false);
    setRequestListLoading(true);
    const queryId = beginRequestQuery();
    const marker = `__shownet_soak_cancel_${status.samplesRecorded}_${status.requestCount}__`;
    const filter: FilterExpression = {
      kind: "group",
      operator: "or",
      children: ["responseBody", "responseBody", "responseBody", "requestHeader", "responseHeader", "hook"].map((field, index) => ({
        kind: "predicate" as const,
        field: field as "responseBody" | "requestHeader" | "responseHeader" | "hook",
        operator: "contains" as const,
        value: `${marker}${index}`,
      })),
    };
    const queryTask = invoke<RequestListPage>("query_request_list", {
      queryId,
      query: {
        sessionId: status.sessionId,
        filter,
        sort: defaultRequestSort,
        limit: REQUEST_LIST_WINDOW_SIZE,
      },
    }).catch(() => undefined).finally(() => {
      finishRequestQuery(queryId);
      if (generation === requestLoadGenerationRef.current) {
        setRequestQueryCancelling(false);
        setRequestListLoading(false);
      }
    });
    const button = await waitForRequestQueryCancelButton();
    if (!button) {
      await queryTask;
      return undefined;
    }
    const idle = waitForRequestQueryIdle(queryId);
    button.click();
    let measurement: RequestQueryIdleMeasurement | undefined;
    try {
      measurement = await idle;
    } catch {
      // A timed-out probe is retried at the next request-count stride.
    }
    await queryTask;
    if (!measurement) return undefined;
    return invoke<SoakDiagnosticsStatus>("record_soak_cancellation_sample", {
      input: {
        queryId: measurement.queryId,
        clickToIdleMs: measurement.clickToIdleMs,
        backendWaitMs: measurement.backendWaitMs,
        accepted: measurement.accepted,
        settled: measurement.settled,
      },
    });
  }, [beginRequestQuery, finishRequestQuery]);

  useEffect(() => {
    if (!hasNativeRuntime) return;
    let disposed = false;
    let nextRequestCount = 0;
    const pause = () => new Promise<void>((resolve) => window.setTimeout(resolve, 500));
    const collect = async () => {
      while (!disposed) {
        let status: SoakDiagnosticsStatus;
        try {
          status = await invoke<SoakDiagnosticsStatus>("get_soak_diagnostics_status");
        } catch {
          return;
        }
        if (!status.enabled || status.samplesRecorded >= status.targetSamples) return;
        if (!status.sessionId || status.sessionId !== activeSessionId) {
          await pause();
          continue;
        }
        if (nextRequestCount === 0) {
          nextRequestCount = status.minimumRequestCount + status.samplesRecorded * status.requestStride;
        }
        if (status.requestCount < nextRequestCount || activeRequestQueryIdRef.current) {
          await pause();
          continue;
        }
        nextRequestCount = status.requestCount + status.requestStride;
        await runSoakCancellationProbe(status).catch(() => undefined);
        await pause();
      }
    };
    void collect();
    return () => { disposed = true; };
  }, [activeSessionId, runSoakCancellationProbe]);

  const sessionRefreshCoalescer = useMemo(
    () => createRefreshCoalescer(() => void refreshSessions(), 250),
    [refreshSessions],
  );
  const scheduleSessionRefresh = useCallback(
    () => sessionRefreshCoalescer.trigger(),
    [sessionRefreshCoalescer],
  );
  const requestListBatcher = useMemo(
    () => createRequestListBatcher((entries) => {
      if (requiresLiveQueryRefresh(requestFilter, requestSort)) {
        void refreshRequests(activeSessionId);
        return;
      }
      const offset = requestWindowOffsetRef.current;
      setRequests((current) => mergeRequestWindowItems(current, entries, offset));
      setRequestListPage((current) => {
        if (!current) return current;
        const createdCount = entries.filter((entry) => entry.created).length;
        return {
          ...current,
          totalCount: current.totalCount + createdCount,
          filteredCount: current.filteredCount + createdCount,
          hookCount: current.hookCount + entries.filter((entry) => entry.created && entry.item.hasHook).length,
          items: mergeRequestWindowItems(current.items, entries, offset),
          facets: addCreatedItemsToFacets(current.facets, entries),
        };
      });
    }, 100),
    [activeSessionId, refreshRequests, requestFilter, requestSort],
  );

  const publishLiveDisplay = useCallback((snapshot: LiveCaptureDisplaySnapshot) => {
    liveDisplayPausedRef.current = snapshot.paused;
    liveDisplaySyncingRef.current = snapshot.syncing;
    setLiveDisplay(snapshot);
  }, []);

  const bufferLiveDisplaySyncEntry = useCallback((item: RequestListItem, created: boolean) => {
    const buffer = liveDisplaySyncBufferRef.current;
    const previous = buffer.get(item.id);
    if (!previous && buffer.size >= 10_000) return;
    buffer.set(item.id, { item, created: created || previous?.created === true });
  }, []);

  const synchronizeLiveDisplay = useCallback(async () => {
    const current = liveDisplayController.snapshot(Date.now());
    if (!current.paused || current.syncing) return;
    liveDisplaySyncBufferRef.current.clear();
    publishLiveDisplay(liveDisplayController.startSync(Date.now()));
    try {
      if (activeSessionId) await refreshRequests(activeSessionId);
      const buffered = [...liveDisplaySyncBufferRef.current.values()];
      liveDisplaySyncBufferRef.current.clear();
      publishLiveDisplay(liveDisplayController.finishSync(Date.now()));
      for (const entry of buffered) requestListBatcher.enqueue(entry.item, entry.created);
    } catch (error) {
      publishLiveDisplay(liveDisplayController.failSync(Date.now()));
      setToast(`同步最新流量失败：${String(error)}`);
    }
  }, [activeSessionId, liveDisplayController, publishLiveDisplay, refreshRequests, requestListBatcher]);

  const toggleLiveDisplay = useCallback(() => {
    const current = liveDisplayController.snapshot(Date.now());
    if (current.paused) {
      void synchronizeLiveDisplay();
      return;
    }
    requestListBatcher.flushNow();
    publishLiveDisplay(liveDisplayController.pause("manual", Date.now()));
  }, [liveDisplayController, publishLiveDisplay, requestListBatcher, synchronizeLiveDisplay]);

  const setLiveDisplayAutoProtection = useCallback((enabled: boolean) => {
    globalThis.localStorage?.setItem(
      LIVE_CAPTURE_DISPLAY_PREFERENCES_KEY,
      JSON.stringify({ version: 1, autoProtection: enabled }),
    );
    publishLiveDisplay(liveDisplayController.setAutoProtection(enabled, Date.now()));
  }, [liveDisplayController, publishLiveDisplay]);

  const importSessionPath = useCallback(async (path: string) => {
    if (capturing) {
      setToast("请先停止抓包，再打开其他会话");
      return;
    }
    setTransferring(true);
    try {
      const imported = await invoke<Session>("import_session_file", { path });
      await refreshSessions();
      setActiveSessionId(imported.id);
      setActiveView("traffic");
      setToast(`已打开 ${imported.name}`);
    } catch (error) {
      setToast(`打开会话失败：${String(error)}`);
    } finally {
      setTransferring(false);
    }
  }, [capturing, refreshSessions]);

  useEffect(() => {
    transferringRef.current = transferring;
  }, [transferring]);

  const analyzeCryptoLab = useCallback(async (sessionId: string) => {
    try {
      await refreshRequests(sessionId);
      setAnalysisAutoRun({ id: Date.now(), sessionId });
      setActiveView("analysis");
      setToast("Crypto Lab 已完成，内置 Agent 正在分析加密链路");
    } catch (error) {
      setToast(`读取 Crypto Lab 证据失败：${String(error)}`);
    }
  }, [refreshRequests]);

  useEffect(() => {
    if (!hasNativeRuntime) return;
    let unlisten: UnlistenFn | undefined;
    const rememberEditable = (event: FocusEvent) => {
      const target = event.target;
      if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || (target instanceof HTMLElement && target.isContentEditable)) {
        lastLocalEditableRef.current = target;
      }
    };
    document.addEventListener("focusin", rememberEditable, true);
    listen<string>("app://edit-command", (event) => {
      const active = document.activeElement;
      if (active && document.querySelector(".browser-screencast")?.contains(active)) return;
      const editable = active instanceof HTMLInputElement
        || active instanceof HTMLTextAreaElement
        || (active instanceof HTMLElement && active.isContentEditable)
        ? active
        : lastLocalEditableRef.current;
      void runLocalEditCommand(event.payload, editable).catch((error) => {
        setToast(`系统编辑命令失败：${String(error)}`);
      });
    }).then((dispose) => { unlisten = dispose; });
    return () => {
      document.removeEventListener("focusin", rememberEditable, true);
      void unlisten?.();
    };
  }, []);

  useEffect(() => {
    if (!hasNativeRuntime) return;
    let disposed = false;
    Promise.all([
      invoke<RuntimeStatus>("get_runtime_status"),
      invoke<Session[]>("list_sessions"),
    ])
      .then(([status, loadedSessions]) => {
        if (disposed) return;
        setRuntime(withClientAccessDefaults(status));
        setCapturing(status.proxyRunning);
        setSessions(loadedSessions);
        setActiveSessionId(
          status.activeSessionId && loadedSessions.some((item) => item.id === status.activeSessionId)
            ? status.activeSessionId
            : (loadedSessions[0]?.id ?? ""),
        );
      })
      .catch((error) => {
        if (!disposed) setToast(`原生服务初始化失败：${String(error)}`);
      });
    return () => {
      disposed = true;
    };
  }, []);

  useEffect(() => {
    if (!hasNativeRuntime) {
      const session = sessions.find((item) => item.id === activeSessionId);
      if (previewRequestWindowEnabled) {
        setRequests(previewRequestWindowItems);
        setRequestListPage(previewRequestListPage);
      } else {
        const page = queryPreviewRequestList(session?.requestCount ? initialRequestListItems : [], requestFilter, requestSort);
        setRequests(page.items);
        setRequestListPage(page);
      }
      requestWindowOffsetRef.current = 0;
      requestWindowTargetRef.current = undefined;
      setRequestWindowTargetOffset(undefined);
      setRequestWindowOffset(0);
      return;
    }
    requestWindowOffsetRef.current = 0;
    setRequestWindowOffset(0);
    refreshRequests(activeSessionId).catch((error) => setToast(`读取流量失败：${String(error)}`));
  }, [activeSessionId, refreshRequests, requestFilter, requestSort, sessions]);

  useEffect(() => {
    liveDisplaySyncBufferRef.current.clear();
    publishLiveDisplay(liveDisplayController.reset(Date.now()));
  }, [activeSessionId, liveDisplayController, publishLiveDisplay]);

  useEffect(() => {
    const tick = () => {
      const wasPaused = liveDisplayPausedRef.current;
      const snapshot = liveDisplayController.tick(Date.now());
      if (!wasPaused && snapshot.paused) requestListBatcher.flushNow();
      publishLiveDisplay(snapshot);
    };
    tick();
    const timer = window.setInterval(tick, 500);
    return () => window.clearInterval(timer);
  }, [liveDisplayController, publishLiveDisplay, requestListBatcher]);

  useEffect(() => {
    if (!hasNativeRuntime) return;
    let disposed = false;
    const unlisteners: UnlistenFn[] = [];
    const refreshBreakpointQueue = () => invoke<BreakpointQueueSnapshot>("get_breakpoint_queue")
      .then((snapshot) => { if (!disposed) setBreakpointQueue(snapshot); })
      .catch((error) => { if (!disposed) setToast(`读取人工断点失败：${String(error)}`); });

    const subscribe = async () => {
      void refreshBreakpointQueue();
      const listeners = await Promise.all([
        listen<RequestListEvent>("capture://request-created", (event) => {
          scheduleSessionRefresh();
          if (event.payload.sessionId !== activeSessionId) return;
          liveDisplayController.recordCreated(Date.now());
          if (liveDisplayPausedRef.current) {
            if (liveDisplaySyncingRef.current) bufferLiveDisplaySyncEntry(event.payload.item, true);
            return;
          }
          requestListBatcher.enqueue(event.payload.item, true);
        }),
        listen<RequestListEvent>("capture://request-updated", (event) => {
          if (event.payload.sessionId !== activeSessionId) return;
          liveDisplayController.recordUpdated();
          if (liveDisplayPausedRef.current) {
            if (liveDisplaySyncingRef.current) bufferLiveDisplaySyncEntry(event.payload.item, false);
            return;
          }
          requestListBatcher.enqueue(event.payload.item, false);
        }),
        listen<RuntimeStatus>("capture://status", (event) => {
          setRuntime(withClientAccessDefaults(event.payload));
          setCapturing(event.payload.proxyRunning);
          void refreshSessions();
        }),
        listen<Session>("session://created", () => void refreshSessions()),
        listen<Session>("session://updated", () => void refreshSessions()),
        listen<string>("session://deleted", () => void refreshSessions()),
        listen("storage://changed", () => {
          void refreshSessions();
          if (activeSessionId) void refreshRequests(activeSessionId);
          else {
            setRequests([]);
            setRequestListPage(null);
            requestWindowOffsetRef.current = 0;
            requestWindowTargetRef.current = undefined;
            setRequestWindowTargetOffset(undefined);
            setRequestWindowOffset(0);
          }
        }),
        listen<AnalysisStreamEvent>("analysis://stream", (event) => {
          if (event.payload.phase === "complete" || event.payload.phase === "error") {
            void refreshSessions();
          }
        }),
        listen("capture://breakpoints-changed", () => void refreshBreakpointQueue()),
        listen<string>("capture://proxy-error", (event) => {
          const message = String(event.payload ?? "").trim();
          if (!message || disposed) return;
          // Surface full egress / connect failures (e.g. 连接 host:port 超时) without flooding.
          const now = Date.now();
          if (now - lastProxyErrorToastAt.current < 2500) return;
          lastProxyErrorToastAt.current = now;
          setToast(message.length > 220 ? `${message.slice(0, 220)}…` : message);
        }),
      ]);
      if (disposed) listeners.forEach((unlisten) => unlisten());
      else unlisteners.push(...listeners);
    };

    subscribe().catch((error) => setToast(`事件订阅失败：${String(error)}`));
    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, [activeSessionId, bufferLiveDisplaySyncEntry, liveDisplayController, refreshRequests, refreshSessions, requestListBatcher, scheduleSessionRefresh]);

  useEffect(() => () => sessionRefreshCoalescer.dispose(), [sessionRefreshCoalescer]);
  useEffect(() => () => requestListBatcher.dispose(), [requestListBatcher]);
  useEffect(() => () => {
    const queryId = activeRequestQueryIdRef.current;
    if (queryId) cancelBackendRequestQuery(queryId);
  }, [cancelBackendRequestQuery]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setCommandOpen((open) => !open);
      }
      if (event.key === "Escape") {
        setCommandOpen(false);
        setConnectOpen(false);
        setSessionToolsOpen(false);
        setRenamingSessionId("");
        setExportOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 2600);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const toggleCapture = async () => {
    if (!activeSession.id) return false;
    const next = !capturing;
    if (!hasNativeRuntime) {
      setCapturing(next);
      setSessions((items) =>
        items.map((session) =>
          session.id === activeSessionId ? { ...session, active: next } : { ...session, active: false },
        ),
      );
      setRuntime((status) => ({
        ...status,
        proxyRunning: next,
        activeSessionId: next ? activeSessionId : undefined,
      }));
    } else {
      try {
        const status = await invoke<RuntimeStatus>("set_capture_running", {
          running: next,
          sessionId: next ? activeSessionId : null,
        });
        setRuntime(withClientAccessDefaults(status));
        setCapturing(status.proxyRunning);
        await refreshSessions();
      } catch (error) {
        setToast(`抓包状态切换失败：${String(error)}`);
        return false;
      }
    }
    setToast(next ? "抓包已开始，流量正在汇入当前会话" : "抓包已暂停");
    return next;
  };

  const createSession = async () => {
    const name = defaultCaptureSessionName();
    if (hasNativeRuntime) {
      try {
        const created = await invoke<Session>("create_session", {
          name,
        });
        setSessions((items) => [created, ...items.filter((item) => item.id !== created.id)]);
        setActiveSessionId(created.id);
        setRequests([]);
        setRequestListPage(null);
        requestWindowOffsetRef.current = 0;
        requestWindowTargetRef.current = undefined;
        setRequestWindowTargetOffset(undefined);
        setRequestWindowOffset(0);
        setActiveView("traffic");
        setToast("新会话已创建");
      } catch (error) {
        setToast(`创建会话失败：${String(error)}`);
      }
      return;
    }
    const id = `session-${Date.now()}`;
    const newSession: Session = {
      id,
      name,
      createdAt: "刚刚",
      requestCount: 0,
      errorCount: 0,
      active: false,
      sources: [],
      analysisReportCount: 0,
    };
    setSessions((items) => [newSession, ...items]);
    setActiveSessionId(id);
    setActiveView("traffic");
    setToast("新会话已创建");
  };

  const beginSessionRename = (session: Session) => {
    setActiveSessionId(session.id);
    setRenamingSessionId(session.id);
    setSessionNameDraft(session.name);
  };

  const cancelSessionRename = () => {
    if (renamingSession) return;
    setRenamingSessionId("");
    setSessionNameDraft("");
  };

  const saveSessionName = async (sessionId: string) => {
    const name = sessionNameDraft.trim();
    if (!name) {
      setToast("会话名称不能为空");
      return;
    }
    setRenamingSession(true);
    try {
      if (hasNativeRuntime) {
        const renamed = await invoke<Session>("rename_session", { sessionId, name });
        setSessions((items) => items.map((item) => item.id === sessionId ? renamed : item));
      } else {
        setSessions((items) => items.map((item) => item.id === sessionId ? { ...item, name } : item));
      }
      setRenamingSessionId("");
      setSessionNameDraft("");
      setToast(`会话已重命名为 ${name}`);
    } catch (error) {
      setToast(`重命名失败：${String(error)}`);
    } finally {
      setRenamingSession(false);
    }
  };

  const exportSession = async (format: "shownet" | SessionExportFormat) => {
    setSessionToolsOpen(false);
    if (!activeSession.id) return;
    if (!hasNativeRuntime) {
      setExportOpen(false);
      setToast(`${format === "shownet" ? "会话包" : format.toUpperCase()} 导出已准备`);
      return;
    }
    const config = {
      shownet: { extension: "shownet", label: "ShowNet Session" },
      har: { extension: "har", label: "HAR 1.2" },
      postman: { extension: "json", label: "Postman Collection" },
      openapi: { extension: "json", label: "OpenAPI 3.1" },
    }[format];
    const path = await save({
      defaultPath: `${safeFileName(activeSession.name)}.${config.extension}`,
      filters: [{ name: config.label, extensions: [config.extension] }],
    });
    if (!path) return;
    setTransferring(true);
    try {
      const result = await invoke<FileExportResult>("export_session_file", {
        sessionId: activeSession.id,
        format,
        path,
      });
      setExportOpen(false);
      setToast(`${result.format} 已导出 · ${formatFileSize(result.bytes)}`);
    } catch (error) {
      setToast(`导出失败：${String(error)}`);
    } finally {
      setTransferring(false);
    }
  };

  const openSessionFile = async () => {
    setSessionToolsOpen(false);
    if (!hasNativeRuntime) {
      setToast("桌面版可打开 .shownet 会话包");
      return;
    }
    if (capturing) {
      setToast("请先停止抓包，再打开其他会话");
      return;
    }
    const path = await open({
      multiple: false,
      directory: false,
      filters: [{ name: "ShowNet Session", extensions: ["shownet"] }],
    });
    if (!path) return;
    await importSessionPath(path);
  };

  useEffect(() => {
    if (!hasNativeRuntime) return;
    let unlisten: UnlistenFn | undefined;
    let disposed = false;
    getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload;
      if (payload.type === "leave") {
        setSessionDrop({ status: "idle" });
        return;
      }
      if (payload.type === "over") return;
      const path = payload.paths.length === 1 ? payload.paths[0] : undefined;
      const containsSession = payload.paths.some(isShownetSessionPath);
      const supported = Boolean(path && isShownetSessionPath(path));
      if (payload.type === "enter") {
        if (!containsSession) {
          setSessionDrop({ status: "idle" });
          return;
        }
        setSessionDrop({
          status: capturing || transferringRef.current ? "blocked" : supported ? "ready" : "invalid",
          path,
        });
        return;
      }
      if (!containsSession) {
        setSessionDrop({ status: "idle" });
        return;
      }
      if (capturing || transferringRef.current) {
        setSessionDrop({ status: "idle" });
        setToast(capturing ? "请先停止抓包，再打开其他会话" : "正在处理会话文件，请稍候");
        return;
      }
      if (!supported || !path) {
        setSessionDrop({ status: "idle" });
        if (containsSession) setToast("一次只能打开一个 .shownet 会话文件");
        return;
      }
      setSessionDrop({ status: "importing", path });
      void importSessionPath(path).finally(() => {
        if (!disposed) setSessionDrop({ status: "idle" });
      });
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    }).catch((error) => setToast(`文件拖放不可用：${String(error)}`));
    return () => {
      disposed = true;
      void unlisten?.();
    };
  }, [capturing, importSessionPath]);

  const navigate = (view: ViewId) => {
    if (view === "lab") {
      setWorkbenchLaunch({
        id: Date.now(),
        mode: "lab",
        sessionId: activeSession.id,
        selected: [],
        createFromSelection: false,
      });
    }
    setActiveView(view);
    setCommandOpen(false);
  };

  const copyConnectValue = async (value: string, label: string) => {
    try {
      if (hasNativeRuntime) await writeText(value);
      else await navigator.clipboard.writeText(value);
      setToast(`${label}已复制`);
    } catch (error) {
      setToast(`复制失败：${String(error)}`);
    }
  };

  const openBreakpointConsole = () => {
    setWorkbenchLaunch({
      id: Date.now(),
      mode: "rules",
      sessionId: activeSession.id,
      selected: [],
      createFromSelection: false,
    });
    setActiveView("lab");
  };

  return (
    <div className="app-shell">
      <nav className="nav-rail" aria-label="主导航">
        <button className="brand-mark" title="ShowNet" onClick={() => navigate("traffic")}>
          <img src={shownetAppIcon} alt="" aria-hidden="true" />
        </button>
        <div className="nav-rail__items">
          {primaryNavigationGroups.map((group) => (
            <div className="nav-rail__group" role="group" aria-label={group.label} key={group.label}>
              {group.views.map((view) => {
                const Icon = viewMeta[view].icon;
                return (
                  <button
                    key={view}
                    className={`nav-rail__item ${view === "lab" ? "nav-rail__item--lab" : ""} ${activeView === view ? "is-active" : ""}`}
                    onClick={() => navigate(view)}
                    title={viewMeta[view].label}
                    aria-label={viewMeta[view].label}
                  >
                    <Icon size={20} />
                    <span>{viewMeta[view].label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </div>
        <div className="nav-rail__bottom">
          <button
            className="nav-rail__item command-button"
            onClick={() => setCommandOpen(true)}
            title="快捷命令"
          >
            <Command size={19} />
            <span>命令</span>
          </button>
          <button
            className={`nav-rail__item ${activeView === "settings" ? "is-active" : ""}`}
            onClick={() => navigate("settings")}
            title="设置"
          >
            <Settings size={20} />
            <span>设置</span>
          </button>
        </div>
      </nav>

      <aside className={`sessions-panel ${compactSessions ? "is-compact" : ""} ${activeView === "lab" ? "is-workbench-hidden" : ""}`}>
        <div className="sessions-panel__header">
          <div>
            <span className="product-name">ShowNet</span>
            <span className="product-channel">DESKTOP</span>
          </div>
          <button className="icon-button" title="收起会话" onClick={() => setCompactSessions((value) => !value)}>
            <Menu size={17} />
          </button>
        </div>

        <button className="new-session-button" onClick={createSession}>
          <Plus size={16} />
          <span>新建会话</span>
        </button>

        <div className="sessions-label">
          <span>会话</span>
          <div className="session-tools" ref={sessionToolsRef}>
            <button className="icon-button icon-button--small" title="会话菜单" onClick={() => setSessionToolsOpen((open) => !open)}>
              <MoreHorizontal size={16} />
            </button>
            {sessionToolsOpen && (
              <div className="session-tools-menu">
                <button onClick={openSessionFile}><FolderOpen size={14} /><span><strong>打开会话</strong><small>.shownet</small></span></button>
                <button onClick={() => void exportSession("shownet")} disabled={!activeSession.id || transferring}><Save size={14} /><span><strong>保存会话包</strong><small>完整流量 · 完整规则</small></span></button>
                <i />
                <button onClick={() => { setSessionToolsOpen(false); setExportOpen(true); }} disabled={!activeSession.id}><Download size={14} /><span><strong>导出为其他格式</strong><small>HAR · Postman · OpenAPI</small></span></button>
              </div>
            )}
          </div>
        </div>

        <div className="session-list">
          {sessions.map((session) => {
            const editing = renamingSessionId === session.id;
            return (
            <div className={`session-entry ${editing ? "is-editing" : ""}`} key={session.id}>
              {editing ? (
                <form className="session-rename-editor" onSubmit={(event) => { event.preventDefault(); void saveSessionName(session.id); }}>
                  <span className={`session-status ${session.active ? "is-live" : ""}`} />
                  <input
                    autoFocus
                    maxLength={60}
                    value={sessionNameDraft}
                    onChange={(event) => setSessionNameDraft(event.target.value)}
                    onFocus={(event) => event.currentTarget.select()}
                    onKeyDown={(event) => {
                      if (event.key === "Escape") {
                        event.preventDefault();
                        cancelSessionRename();
                      }
                    }}
                    aria-label={`重命名 ${session.name}`}
                  />
                  <span className="session-rename-editor__actions">
                    <button type="submit" title="保存名称" disabled={renamingSession || !sessionNameDraft.trim()}><Check size={13} /></button>
                    <button type="button" title="取消重命名" disabled={renamingSession} onClick={cancelSessionRename}><X size={13} /></button>
                  </span>
                </form>
              ) : (
                <>
                  <button
                    className={`session-item ${session.id === activeSessionId ? "is-active" : ""}`}
                    onClick={() => {
                      setActiveSessionId(session.id);
                      setActiveView("traffic");
                    }}
                    title={`打开 ${session.name} 的抓包记录`}
                  >
                    <span className={`session-status ${session.active ? "is-live" : ""}`} />
                    <span className="session-item__body">
                      <strong>{session.name}</strong>
                      <span className="session-item__meta">
                        <span>{formatSessionTime(session.createdAt)} · {session.requestCount} 条</span>
                        <span className="session-sources">
                          {session.sources.slice(0, 4).map((source) => {
                            const Icon = sourceIcons[source];
                            return <Icon key={source} size={11} aria-label={sourceLabels[source]} />;
                          })}
                        </span>
                        {session.errorCount > 0 && <i className="error-count">{session.errorCount}</i>}
                      </span>
                    </span>
                  </button>
                  <button className="session-rename-button" onClick={() => beginSessionRename(session)} title="重命名会话" aria-label={`重命名 ${session.name}`}><Pencil size={12} /></button>
                </>
              )}
              {!editing && session.analysisReportCount > 0 && (
                <button
                  className={`session-report-shortcut ${session.id === activeSessionId && activeView === "analysis" ? "is-active" : ""}`}
                  onClick={() => {
                    setActiveSessionId(session.id);
                    setActiveView("analysis");
                  }}
                  title={`打开最近 AI 报告${session.latestAnalysisUpdatedAt ? ` · ${formatSessionTime(new Date(session.latestAnalysisUpdatedAt).toISOString())}` : ""}`}
                  aria-label={`打开 ${session.name} 的最近 AI 报告`}
                >
                  <Sparkles size={11} />
                  <span>{session.latestAnalysisStatus === "failed" ? "失败" : `${session.analysisReportCount} 份报告`}</span>
                </button>
              )}
            </div>
            );
          })}
        </div>

        <div className="proxy-mini-status">
          <div className="proxy-mini-status__top">
            <span className={`live-dot ${capturing ? "is-on" : ""}`} />
            <strong>代理 :{runtime.proxyPort}</strong>
            <span>{capturing ? "运行中" : "已暂停"}</span>
          </div>
          <div className="proxy-mini-status__meta">
            <span>{runtime.caInstalled ? "CA 已信任" : "CA 待安装"}</span>
            <button onClick={() => navigate("settings")}>管理</button>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar" data-tauri-drag-region>
          <div className="topbar__title">
            <span className="topbar__eyebrow">{activeSession.name}</span>
            <h1>{viewMeta[activeView].title}</h1>
          </div>
          <div className="topbar__actions">
            {breakpointQueue.tasks.length > 0 && <button className="breakpoint-alert-button" onClick={openBreakpointConsole} title="打开人工断点队列"><Pause size={13} fill="currentColor" /><span>{breakpointQueue.tasks.length} 条断点</span><strong>待处理</strong></button>}
            <button className="ai-service-entry" onClick={() => navigate("analysis")} title="ClaudeGPT.org · gpt-5.5">
              <Sparkles size={16} />
              <span className="ai-service-entry__desktop"><small>首选 AI 服务 · 加群申请 $5 免费额度</small><strong>ClaudeGPT.org · gpt-5.5</strong></span>
              <span className="ai-service-entry__mobile"><strong>ClaudeGPT.org</strong><small>申请 $5 免费额度</small></span>
            </button>
            <button className="status-button" onClick={() => setConnectOpen(true)}>
              <span className="source-stack">
                <Browser size={14} />
                <Wifi size={14} />
                <Terminal size={14} />
              </span>
              <span>{activeSession.sources.length} 个来源</span>
              <ChevronDown size={14} />
            </button>
            <button className={`capture-button ${capturing ? "is-capturing" : ""}`} onClick={toggleCapture}>
              {capturing ? <Square size={13} fill="currentColor" /> : <CircleDot size={15} />}
              <span>{capturing ? "停止抓包" : "开始抓包"}</span>
            </button>
          </div>
        </header>

        <main className="workspace__content">
          {activeView === "traffic" && (
            <TrafficView
              requests={requests}
              totalCount={requestListPage?.totalCount ?? requests.length}
              filteredCount={requestListPage?.filteredCount ?? requests.length}
              hookCount={requestListPage?.hookCount ?? requests.filter((request) => request.hasHook).length}
              bookmarkedCount={requestListPage?.bookmarkedCount ?? requests.filter((request) => request.annotation?.bookmarked).length}
              requestWindowOffset={requestWindowOffset}
              requestWindowTargetOffset={requestWindowTargetOffset}
              facets={requestListPage?.facets ?? emptyRequestFacets}
              loading={requestListLoading}
              cancelling={requestQueryCancelling}
              capturing={capturing}
              liveDisplay={liveDisplay}
              sessionId={activeSession.id}
              focusRequestId={evidenceRequestId}
              onFocusRequestConsumed={() => setEvidenceRequestId(undefined)}
              onQueryChange={updateRequestQuery}
              onRequestWindowChange={(offset) => void loadRequestWindow(activeSession.id, offset)}
              onCancelRequestQuery={() => void cancelActiveRequestQuery(true, true)}
              onOpenAnalysis={() => setActiveView("analysis")}
              onAnalyzeSelection={(requestIds) => {
                setAnalysisRequestScope({ id: Date.now(), sessionId: activeSession.id, requestIds });
                setActiveView("analysis");
              }}
              onOpenWorkbench={(mode, selected, options) => {
                setWorkbenchLaunch({
                  id: Date.now(),
                  mode,
                  sessionId: activeSession.id,
                  selected,
                  createFromSelection: options?.createFromSelection === true,
                });
                setActiveView("lab");
              }}
              onToggleLiveDisplay={toggleLiveDisplay}
              onLiveDisplayAutoProtectionChange={setLiveDisplayAutoProtection}
              onConnect={() => setConnectOpen(true)}
              onOpenBrowser={() => setActiveView("browser")}
              onOpenSettingsCapture={() => {
                setSettingsTab("capture");
                setActiveView("settings");
              }}
            />
          )}
          {activeView === "lab" && (
            <RequestWorkbench
              key={workbenchLaunch?.id ?? `lab-${activeSession.id}`}
              sessionId={workbenchLaunch?.sessionId === activeSession.id ? workbenchLaunch.sessionId : activeSession.id}
              selected={workbenchLaunch?.sessionId === activeSession.id ? workbenchLaunch.selected : []}
              initialMode={workbenchLaunch?.sessionId === activeSession.id ? workbenchLaunch.mode : "lab"}
              autoCreateFromSelection={workbenchLaunch?.sessionId === activeSession.id && workbenchLaunch.createFromSelection}
              onBack={() => setActiveView("traffic")}
              onOpenRequest={(requestId) => {
                setEvidenceRequestId(requestId);
                setActiveView("traffic");
              }}
            />
          )}
          {activeView === "advanced" && (
            <AdvancedConsoleView
              sessionId={activeSession.id}
              requests={requests}
              hookCount={requestListPage?.hookCount ?? requests.filter((request) => request.hasHook).length}
              runtime={runtime}
              onOpenTraffic={() => setActiveView("traffic")}
              onOpenBrowser={() => setActiveView("browser")}
              onOpenRules={() => {
                setWorkbenchLaunch({
                  id: Date.now(),
                  mode: "rules",
                  sessionId: activeSession.id,
                  selected: [],
                  createFromSelection: false,
                });
                setActiveView("lab");
              }}
              onOpenSettings={() => {
                setSettingsTab("capture");
                setActiveView("settings");
              }}
              onOpenAnalysis={() => setActiveView("analysis")}
              onNotify={setToast}
            />
          )}
          {activeView === "analysis" && <AnalysisView sessionId={activeSession.id} requests={requests} initialRequestIds={analysisRequestScope?.sessionId === activeSession.id ? analysisRequestScope.requestIds : undefined} scopeRequestId={analysisRequestScope?.sessionId === activeSession.id ? analysisRequestScope.id : undefined} onScopeConsumed={() => setAnalysisRequestScope(null)} onOpenEvidenceRequest={(requestId) => { setEvidenceRequestId(requestId); setActiveView("traffic"); }} onConfigureAi={() => { setSettingsTab("ai"); setActiveView("settings"); }} onNotify={setToast} autoRunId={analysisAutoRun?.sessionId === activeSession.id ? analysisAutoRun.id : undefined} onAutoRunConsumed={() => setAnalysisAutoRun(null)} />}
          {/* Keep BrowserView mounted so switching nav tabs does not stop proxy Chrome / drop CDP state. */}
          <div
            className={`workspace-view-keep-alive ${activeView === "browser" ? "is-active" : "is-hidden"}`}
            hidden={activeView !== "browser"}
            aria-hidden={activeView !== "browser"}
          >
            <BrowserView
              active={activeView === "browser"}
              capturing={capturing}
              sessionId={activeSession.id}
              onAnalyzeCryptoLab={() => void analyzeCryptoLab(activeSession.id)}
            />
          </div>
          {activeView === "skills" && <SkillsView sessionId={activeSession.id} requests={requests} />}
          {activeView === "settings" && (
            <SettingsView
              runtime={runtime}
              onRuntimeChange={(status) => setRuntime(withClientAccessDefaults(status))}
              onNotify={setToast}
              initialTab={settingsTab}
            />
          )}
        </main>
      </section>

      {connectOpen && (
        <ConnectDialog
          sessionId={activeSession.id}
          runtime={runtime}
          capturing={capturing}
          onClose={() => setConnectOpen(false)}
          onNavigate={(view) => {
            setConnectOpen(false);
            navigate(view);
          }}
          onCopy={(value, label) => void copyConnectValue(value, label)}
          onSettings={() => {
            setConnectOpen(false);
            setSettingsTab("capture");
            setActiveView("settings");
          }}
          onStartCapture={() => capturing ? Promise.resolve(true) : toggleCapture()}
        />
      )}
      {commandOpen && <CommandPalette onClose={() => setCommandOpen(false)} onNavigate={navigate} />}
      {exportOpen && (
        <SessionExportDialog
          session={activeSession}
          busy={transferring}
          onClose={() => setExportOpen(false)}
          onExport={(format) => void exportSession(format)}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          <Check size={16} />
          {toast}
        </div>
      )}
      {sessionDrop.status !== "idle" && (
        <div className={`session-drop-overlay is-${sessionDrop.status}`} role="status" aria-live="polite">
          <span><FileArchive size={26} /></span>
          <strong>{sessionDrop.status === "ready" ? "松开以打开会话" : sessionDrop.status === "importing" ? "正在打开会话" : sessionDrop.status === "blocked" ? "请先停止抓包" : "不支持此文件"}</strong>
          <small>{sessionDrop.path ? droppedFileName(sessionDrop.path) : "请选择单个 .shownet 文件"}</small>
        </div>
      )}
    </div>
  );
}

function SessionExportDialog({
  session,
  busy,
  onClose,
  onExport,
}: {
  session: Session;
  busy: boolean;
  onClose: () => void;
  onExport: (format: SessionExportFormat) => void;
}) {
  const [format, setFormat] = useState<SessionExportFormat>("har");
  const formats: Array<{ id: SessionExportFormat; name: string; detail: string; icon: typeof FileJson }> = [
    { id: "har", name: "HAR 1.2", detail: "浏览器与主流抓包工具", icon: FileArchive },
    { id: "postman", name: "Postman 2.1", detail: "导入 API Collection", icon: FileJson },
    { id: "openapi", name: "OpenAPI 3.1", detail: "生成接口文档与客户端", icon: FileJson },
  ];
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="export-dialog" role="dialog" aria-modal="true" aria-labelledby="session-export-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="dialog-header">
          <div><span className="section-kicker">SESSION EXPORT</span><h2 id="session-export-dialog-title">导出会话</h2><p>{session.name} · {session.requestCount} 条请求</p></div>
          <button className="icon-button" onClick={onClose} title="关闭"><X size={18} /></button>
        </header>
        <div className="export-format-list">
          {formats.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={format === item.id ? "is-active" : ""} onClick={() => setFormat(item.id)}><span><Icon size={18} /></span><div><strong>{item.name}</strong><small>{item.detail}</small></div>{format === item.id && <Check size={15} />}</button>;
          })}
        </div>
        <footer className="dialog-footer"><div><ShieldCheck size={15} /><span>请求、响应与认证信息按目标格式完整保留</span></div><span className="dialog-actions"><button className="secondary-button" onClick={onClose}>取消</button><button className="primary-button" disabled={busy} onClick={() => onExport(format)}><Download size={14} />{busy ? "导出中" : "选择位置"}</button></span></footer>
      </section>
    </div>
  );
}

function safeFileName(value: string) {
  return value.replace(/[\\/:*?"<>|]/g, "-").trim() || "shownet-session";
}

function droppedFileName(path: string) {
  return path.split(/[\\/]/).pop() || path;
}

function formatFileSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function ConnectDialog({
  sessionId,
  runtime,
  capturing,
  onClose,
  onNavigate,
  onCopy,
  onSettings,
  onStartCapture,
}: {
  sessionId: string;
  runtime: RuntimeStatus;
  capturing: boolean;
  onClose: () => void;
  onNavigate: (view: ViewId) => void;
  onCopy: (value: string, label: string) => void;
  onSettings: () => void;
  onStartCapture: () => Promise<boolean>;
}) {
  const [selectedSource, setSelectedSource] = useState<SourceType>("browser");
  const [scriptRuntime, setScriptRuntime] = useState<ConnectScriptRuntime>("python");
  const [terminalPreference, setTerminalPreference] = useState<ProxyTerminalPreference>(() => {
    const saved = globalThis.localStorage?.getItem(PROXY_TERMINAL_PREFERENCE_KEY) as ProxyTerminalPreference | null;
    return saved && proxyTerminalOptions(runtime.platform).some((option) => option.value === saved) ? saved : "auto";
  });
  const [terminalLaunching, setTerminalLaunching] = useState(false);
  const [terminalStatus, setTerminalStatus] = useState<{ tone: "success" | "error"; text: string }>();
  const [diagnostics, setDiagnostics] = useState<ConnectionDiagnostics>();
  const [diagnosing, setDiagnosing] = useState(false);
  const [diagnosticError, setDiagnosticError] = useState("");
  const [reverseProxyStatus, setReverseProxyStatus] = useState<ReverseProxyStatus>();
  const localProxyUrl = `http://127.0.0.1:${runtime.proxyPort}`;
  const lanEndpoint = runtime.lanAddresses[0]
    ? `${runtime.lanAddresses[0]}:${runtime.proxyPort}`
    : "";
  const sources: Array<{
    source: SourceType;
    detail: string;
    status: "active" | "available" | "manual";
    activeLabel?: string;
  }> = [
    { source: "browser", detail: "代理 Chrome · CDP / JS Hook", status: runtime.proxyRunning ? "available" : "manual" },
    { source: "desktop", detail: runtime.systemProxyEnabled ? `系统代理 · 127.0.0.1:${runtime.proxyPort}` : `手动代理 · 127.0.0.1:${runtime.proxyPort}`, status: runtime.systemProxyActive ? "active" : "manual" },
    { source: "terminal", detail: "一键启动 · 自动 HTTPS 信任", status: runtime.proxyRunning && runtime.activeSessionId === sessionId ? "active" : "available", activeLabel: "已就绪" },
    { source: "script", detail: "SDK 或代理参数", status: "manual" },
    {
      source: "mobile",
      detail: runtime.lanEnabled && lanEndpoint ? `Wi-Fi 代理 · ${lanEndpoint}` : "需开启局域网设备接入",
      status: runtime.lanEnabled && lanEndpoint ? (runtime.proxyRunning ? "active" : "available") : "manual",
      activeLabel: "已监听",
    },
    {
      source: "iot",
      detail: runtime.lanEnabled && lanEndpoint ? `网关代理 · ${lanEndpoint}` : "需开启局域网设备接入",
      status: runtime.lanEnabled && lanEndpoint ? (runtime.proxyRunning ? "active" : "available") : "manual",
      activeLabel: "已监听",
    },
    {
      source: "reverse",
      detail: reverseProxyStatus?.running ? `${reverseProxyStatus.targetUrl} · ${reverseProxyStatus.localUrl}` : "只改请求地址 · 无需客户端 CA",
      status: reverseProxyStatus?.running ? "active" : "available",
      activeLabel: "运行中",
    },
  ];
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    invoke<ReverseProxyStatus>("get_reverse_proxy_status")
      .then((status) => { if (!disposed) setReverseProxyStatus(status); })
      .catch((error) => { if (!disposed) setDiagnosticError(`读取免代理入口失败：${String(error)}`); });
    listen<ReverseProxyStatus>("reverse-proxy://status", (event) => {
      if (!disposed) setReverseProxyStatus(event.payload);
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    }).catch(() => undefined);
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, []);
  const runDiagnostics = async () => {
    setDiagnosing(true);
    setDiagnosticError("");
    try {
      if (isTauri()) setDiagnostics(await invoke<ConnectionDiagnostics>("run_connection_diagnostics"));
      else setDiagnosticError("自动诊断需要在 ShowNet 桌面应用中运行");
    } catch (error) { setDiagnosticError(String(error)); } finally { setDiagnosing(false); }
  };
  const launchProxyTerminal = async () => {
    setTerminalLaunching(true);
    setTerminalStatus(undefined);
    try {
      if (!isTauri()) throw new Error("代理终端需要在 ShowNet 桌面应用中打开");
      if (!capturing && !await onStartCapture()) throw new Error("当前会话未能开始抓包");
      const launched = await invoke<ProxyTerminalLaunchResult>("launch_proxy_terminal", {
        sessionId,
        terminal: terminalPreference,
      });
      setTerminalStatus({ tone: "success", text: `${launched.terminal} 已打开，代理与 HTTPS 信任已就绪` });
    } catch (error) {
      setTerminalStatus({ tone: "error", text: String(error).replace(/^Error:\s*/, "") });
    } finally {
      setTerminalLaunching(false);
    }
  };
  const updateTerminalPreference = (preference: ProxyTerminalPreference) => {
    setTerminalPreference(preference);
    globalThis.localStorage?.setItem(PROXY_TERMINAL_PREFERENCE_KEY, preference);
    setTerminalStatus(undefined);
  };
  const repairDiagnostic = (action?: string) => {
    if (!action) return;
    if (action === "start-capture") { void onStartCapture(); return; }
    if (action === "device-guide") { setDiagnostics(undefined); setSelectedSource("mobile"); return; }
    onSettings();
  };

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="connect-dialog" role="dialog" aria-modal="true" aria-labelledby="connect-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="dialog-header">
          <div>
            <span className="section-kicker">CAPTURE SOURCES</span>
            <h2 id="connect-dialog-title">{diagnostics ? "连接诊断" : "流量来源"}</h2>
          </div>
          <div className="connect-dialog__header-actions"><button className="secondary-button" onClick={() => diagnostics ? setDiagnostics(undefined) : void runDiagnostics()} disabled={diagnosing}><Activity className={diagnosing ? "spin" : ""} size={14} />{diagnostics ? "返回来源" : diagnosing ? "诊断中" : "运行诊断"}</button><button className="icon-button" onClick={onClose} title="关闭"><X size={18} /></button></div>
        </header>
        {diagnostics ? <div className="connection-diagnostics">
          <div className="diagnostic-summary"><strong>{diagnostics.checks.filter((check) => check.status === "healthy").length} 项正常</strong><span>{diagnostics.checks.filter((check) => check.status === "warning" || check.status === "error").length} 项需处理</span><small>{new Date(diagnostics.generatedAt).toLocaleTimeString()}</small></div>
          {diagnostics.checks.map((check) => <div key={check.id} className={"diagnostic-row is-" + check.status}><i /><span><strong>{check.label}</strong><small>{check.summary}</small><em>{check.detail}</em></span>{check.repairAction && <button className="secondary-button" onClick={() => repairDiagnostic(check.repairAction)}>{diagnosticActionLabel(check.repairAction)}</button>}</div>)}
        </div> : <>
        <div className="source-grid">
          {sources.map(({ source, detail, status, activeLabel }) => {
            const Icon = sourceIcons[source];
            return (
              <button
                key={source}
                className={`source-option ${source === "reverse" ? "source-option--wide" : ""} ${selectedSource === source ? "is-active" : ""}`}
                onClick={() => setSelectedSource(source)}
                aria-pressed={selectedSource === source}
              >
                <span className="source-option__icon">
                  <Icon size={20} />
                </span>
                <span className="source-option__content">
                  <strong>{sourceLabels[source]}</strong>
                  <span>{detail}</span>
                </span>
                <span className={`source-option__status ${status === "active" ? "is-ready" : ""}`}>
                  {status === "active" ? (activeLabel || "已接管") : status === "available" ? "可使用" : "配置"}
                </span>
                <ChevronRight className="source-option__arrow" size={14} />
              </button>
            );
          })}
        </div>
        {selectedSource === "reverse" ? <ReverseProxySetup
          sessionId={sessionId}
          runtime={runtime}
          status={reverseProxyStatus}
          capturing={capturing}
          onStatus={setReverseProxyStatus}
          onStartCapture={onStartCapture}
          onCopy={onCopy}
        /> : <ConnectSourceSetup
          source={selectedSource}
          runtime={runtime}
          capturing={capturing}
          localProxyUrl={localProxyUrl}
          lanEndpoint={lanEndpoint}
          scriptRuntime={scriptRuntime}
          onScriptRuntimeChange={setScriptRuntime}
          terminalPreference={terminalPreference}
          onTerminalPreferenceChange={updateTerminalPreference}
          terminalLaunching={terminalLaunching}
          terminalStatus={terminalStatus}
          onLaunchProxyTerminal={() => void launchProxyTerminal()}
          onNavigate={onNavigate}
          onStartCapture={onStartCapture}
          onCopy={onCopy}
          onSettings={onSettings}
        />}
        </>}
        {diagnosticError && <div className="diagnostic-error"><CircleDot size={14} /><span>{diagnosticError}</span></div>}
        <footer className="dialog-footer">
          <div>
            <ShieldCheck size={16} />
            <span>{selectedSource === "reverse" ? "远程 HTTPS 由 ShowNet 校验，客户端无需安装 CA" : "HTTPS 解密由 ShowNet CA 提供"}</span>
          </div>
          <button className="secondary-button" onClick={onSettings}>代理设置</button>
        </footer>
      </section>
    </div>
  );
}

function ReverseProxySetup({
  sessionId,
  runtime,
  status,
  capturing,
  onStatus,
  onStartCapture,
  onCopy,
}: {
  sessionId: string;
  runtime: RuntimeStatus;
  status?: ReverseProxyStatus;
  capturing: boolean;
  onStatus: (status: ReverseProxyStatus) => void;
  onStartCapture: () => Promise<boolean>;
  onCopy: (value: string, label: string) => void;
}) {
  const [draft, setDraft] = useState<ReverseProxySettingsInput>({ targetUrl: "", localPort: 0, lanEnabled: false, preserveHost: false });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!status) return;
    setDraft({
      targetUrl: status.targetUrl,
      localPort: status.localPort,
      lanEnabled: status.lanEnabled,
      preserveHost: status.preserveHost,
    });
  }, [status]);

  const start = async () => {
    setBusy(true);
    setError("");
    try {
      if (!isTauri()) throw new Error("免代理接入需要在 ShowNet 桌面应用中运行");
      if (!capturing && !await onStartCapture()) throw new Error("当前会话未能开始抓包");
      onStatus(await invoke<ReverseProxyStatus>("start_reverse_proxy", { settings: draft, sessionId }));
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    setBusy(true);
    setError("");
    try {
      if (!isTauri()) throw new Error("免代理接入需要在 ShowNet 桌面应用中运行");
      onStatus(await invoke<ReverseProxyStatus>("stop_reverse_proxy"));
    } catch (reason) {
      setError(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setBusy(false);
    }
  };

  const running = status?.running === true;
  return (
    <div className="source-setup reverse-proxy-setup">
      <div className="source-setup__heading">
        <div><span>免代理接入</span><strong>{running ? status.targetUrl : "本地入口直达远程服务"}</strong></div>
        <i className={running ? "is-ready" : ""}>{running ? "正在转发" : "未启动"}</i>
      </div>
      <div className="reverse-proxy-fields">
        <label><span>远程地址</span><input autoComplete="off" disabled={running || busy} value={draft.targetUrl} onChange={(event) => setDraft((current) => ({ ...current, targetUrl: event.target.value }))} placeholder="https://api.example.com" /></label>
        <label><span>本地端口</span><input type="number" min="0" max="65535" disabled={running || busy} value={draft.localPort || ""} onChange={(event) => setDraft((current) => ({ ...current, localPort: Number(event.target.value) || 0 }))} placeholder="自动" /></label>
      </div>
      <div className="reverse-proxy-options">
        <label><input type="checkbox" disabled={running || busy} checked={draft.lanEnabled} onChange={(event) => setDraft((current) => ({ ...current, lanEnabled: event.target.checked }))} /><span><strong>局域网可访问</strong><small>遵循设置：{clientAccessModeSummary(runtime.accessMode ?? "private", runtime.accessRules?.length ?? 0)}</small></span></label>
        <label><input type="checkbox" disabled={running || busy} checked={draft.preserveHost} onChange={(event) => setDraft((current) => ({ ...current, preserveHost: event.target.checked }))} /><span><strong>保留原 Host</strong><small>仅服务端明确要求时开启</small></span></label>
      </div>
      {running && <div className="reverse-proxy-endpoints">
        <span><small>本机入口</small><code>{status.localUrl}</code><button onClick={() => status.localUrl && onCopy(status.localUrl, "本机入口")} title="复制本机入口"><Copy size={13} /></button></span>
        {status.lanUrls[0] && <span><small>设备入口</small><code>{status.lanUrls[0]}</code><button onClick={() => onCopy(status.lanUrls[0], "设备入口")} title="复制设备入口"><Copy size={13} /></button></span>}
      </div>}
      {error && <div className="reverse-proxy-error"><CircleAlert size={14} /><span>{error}</span></div>}
      <div className="source-setup__actions">
        <span className="source-setup__note">{running ? "路径、查询参数和请求体保持不变" : "端口留空时自动选择可用端口"}</span>
        {running ? <button className="secondary-button" onClick={() => void stop()} disabled={busy}><Square size={12} />{busy ? "正在停止" : "停止入口"}</button> : <button className="primary-button" onClick={() => void start()} disabled={busy || !draft.targetUrl.trim()}><Route size={14} />{busy ? "正在启动" : capturing ? "启动入口" : "启动抓包与入口"}</button>}
      </div>
    </div>
  );
}

function ConnectSourceSetup({
  source,
  runtime,
  capturing,
  localProxyUrl,
  lanEndpoint,
  scriptRuntime,
  onScriptRuntimeChange,
  terminalPreference,
  onTerminalPreferenceChange,
  terminalLaunching,
  terminalStatus,
  onLaunchProxyTerminal,
  onNavigate,
  onStartCapture,
  onCopy,
  onSettings,
}: {
  source: SourceType;
  runtime: RuntimeStatus;
  capturing: boolean;
  localProxyUrl: string;
  lanEndpoint: string;
  scriptRuntime: ConnectScriptRuntime;
  onScriptRuntimeChange: (runtime: ConnectScriptRuntime) => void;
  terminalPreference: ProxyTerminalPreference;
  onTerminalPreferenceChange: (terminal: ProxyTerminalPreference) => void;
  terminalLaunching: boolean;
  terminalStatus?: { tone: "success" | "error"; text: string };
  onLaunchProxyTerminal: () => void;
  onNavigate: (view: ViewId) => void;
  onStartCapture: () => Promise<boolean>;
  onCopy: (value: string, label: string) => void;
  onSettings: () => void;
}) {
  const endpoint = localProxyUrl.replace("http://", "");
  const terminalCommand = runtime.platform === "windows"
    ? `$env:HTTP_PROXY="${localProxyUrl}"\n$env:HTTPS_PROXY="${localProxyUrl}"\n$env:NO_PROXY="localhost,127.0.0.1,::1"`
    : `export HTTP_PROXY="${localProxyUrl}"\nexport HTTPS_PROXY="${localProxyUrl}"\nexport NO_PROXY="localhost,127.0.0.1,::1"`;
  const scriptTemplates: Record<ConnectScriptRuntime, string> = {
    python: `import requests\n\nproxy = "${localProxyUrl}"\nproxies = {"http": proxy, "https": proxy}\nresponse = requests.get("https://example.com", proxies=proxies)`,
    node: `import { ProxyAgent, fetch } from "undici";\n\nconst proxy = new ProxyAgent("${localProxyUrl}");\nconst response = await fetch("https://example.com", { dispatcher: proxy });`,
    go: `proxyURL, _ := url.Parse("${localProxyUrl}")\nclient := &http.Client{Transport: &http.Transport{\n    Proxy: http.ProxyURL(proxyURL),\n}}\nresponse, err := client.Get("https://example.com")`,
  };
  const openBrowserCapture = async () => {
    if (!capturing && !await onStartCapture()) return;
    onNavigate("browser");
  };

  if (source === "browser") {
    return (
      <div className="source-setup">
        <div className="source-setup__heading"><div><span>内嵌浏览器</span><strong>CDP + JS Hook</strong></div><i className={capturing ? "is-ready" : ""}>{capturing ? "代理已就绪" : "抓包已暂停"}</i></div>
        <div className="source-setup__facts"><span><small>代理</small><code>{endpoint}</code></span><span><small>HTTPS</small><strong>{runtime.caInstalled ? "CA 已信任" : "需安装 CA"}</strong></span><span><small>会话</small><strong>自动汇入当前 Session</strong></span></div>
        <div className="source-setup__actions"><button className="secondary-button" onClick={() => onCopy(localProxyUrl, "代理地址")}><Copy size={14} />复制代理</button><button className="primary-button" onClick={() => void openBrowserCapture()}><Browser size={14} />{capturing ? "打开浏览器" : "开始并打开"}</button></div>
      </div>
    );
  }

  if (source === "desktop") {
    return (
      <div className="source-setup">
        <div className="source-setup__heading"><div><span>桌面应用</span><strong>{runtime.systemProxyActive ? "系统代理已由 ShowNet 接管" : "使用应用代理或系统代理"}</strong></div><i className={runtime.systemProxyActive ? "is-ready" : ""}>{runtime.systemProxyActive ? "已接管" : "手动"}</i></div>
        <div className="source-setup__facts"><span><small>HTTP / HTTPS</small><code>{endpoint}</code></span><span><small>适用</small><strong>Postman · Electron · 客户端</strong></span><span><small>HTTPS</small><strong>{runtime.caInstalled ? "CA 已信任" : "需安装 CA"}</strong></span></div>
        <div className="source-setup__actions"><button className="secondary-button" onClick={() => onCopy(endpoint, "代理地址")}><Copy size={14} />复制地址</button><button className="primary-button" onClick={onSettings}><Settings size={14} />代理设置</button></div>
      </div>
    );
  }

  if (source === "terminal") {
    return (
      <div className="source-setup source-setup--terminal">
        <div className="source-setup__heading">
          <div><span>代理终端</span><strong>自动配置命令行代理与证书信任</strong></div>
          <select className="proxy-terminal-select" aria-label="终端应用" value={terminalPreference} onChange={(event) => onTerminalPreferenceChange(event.target.value as ProxyTerminalPreference)}>{proxyTerminalOptions(runtime.platform).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select>
        </div>
        <div className="source-setup__facts"><span><small>HTTP / HTTPS</small><code>{endpoint}</code></span><span><small>证书</small><strong>自动注入 CA · 保持 TLS 校验</strong></span><span><small>兼容</small><strong>Node.js · Python · Ruby · curl</strong></span></div>
        <div className="source-setup__actions">
          <span className={`source-setup__note ${terminalStatus ? `is-${terminalStatus.tone}` : ""}`}>{terminalStatus?.text ?? (capturing ? "当前会话抓包已就绪" : "打开时将自动开始当前会话抓包")}</span>
          <button className="secondary-button" onClick={() => onCopy(terminalCommand, "代理变量")}><Copy size={14} />复制代理变量</button>
          <button className="primary-button" onClick={onLaunchProxyTerminal} disabled={terminalLaunching}><Terminal size={14} />{terminalLaunching ? "正在打开" : capturing ? "打开代理终端" : "启动并打开"}</button>
        </div>
      </div>
    );
  }

  if (source === "script") {
    return (
      <div className="source-setup">
        <div className="source-setup__heading"><div><span>脚本程序</span><strong>代码级代理配置</strong></div><div className="source-runtime-tabs">{(["python", "node", "go"] as ConnectScriptRuntime[]).map((item) => <button key={item} className={scriptRuntime === item ? "is-active" : ""} onClick={() => onScriptRuntimeChange(item)}>{item === "node" ? "Node.js" : item === "go" ? "Go" : "Python"}</button>)}</div></div>
        <pre className="source-setup__code">{scriptTemplates[scriptRuntime]}</pre>
        <div className="source-setup__actions"><span className="source-setup__note">请求自动归入当前 Session</span><button className="primary-button" onClick={() => onCopy(scriptTemplates[scriptRuntime], `${scriptRuntime === "node" ? "Node.js" : scriptRuntime === "go" ? "Go" : "Python"} 模板`)}><Copy size={14} />复制代码</button></div>
      </div>
    );
  }

  const deviceEndpoint = runtime.lanEnabled && lanEndpoint
    ? lanEndpoint
    : `局域网 IP:${runtime.proxyPort}`;
  const setupUrl = runtime.lanEnabled && lanEndpoint ? `http://${lanEndpoint}/device` : "";
  return (
    <div className="source-setup">
      <div className="source-setup__heading"><div><span>{source === "mobile" ? "手机 / 平板" : "IoT / 其他设备"}</span><strong>{runtime.lanEnabled ? deviceEndpoint : "需要开启局域网设备接入"}</strong></div><i className={runtime.lanEnabled && capturing ? "is-ready" : ""}>{runtime.lanEnabled ? (capturing ? "正在监听" : "等待抓包") : "未开启"}</i></div>
      <div className="source-setup__facts"><span><small>{source === "mobile" ? "Wi-Fi 代理" : "网关代理"}</small><code>{deviceEndpoint}</code></span><span><small>HTTPS</small><strong>设备安装 ShowNet CA</strong></span><span><small>接入范围</small><strong>仅私网设备</strong></span></div>
      <div className="source-setup__actions">{setupUrl && <button className="secondary-button" onClick={() => onCopy(setupUrl, "设备接入地址")}><Copy size={14} />复制接入地址</button>}<button className="primary-button" onClick={onSettings}><Wifi size={14} />设备接入</button></div>
    </div>
  );
}

function diagnosticActionLabel(action: string) {
  const labels: Record<string, string> = {
    "start-capture": "开始抓包",
    "capture-settings": "监听设置",
    "recover-system-proxy": "恢复代理",
    "system-proxy-settings": "代理设置",
    "install-ca": "安装 CA",
    "export-ca": "导出 CA",
    "browser-ca-guide": "证书指引",
    "lan-settings": "LAN 设置",
    "device-guide": "设备引导",
    "upstream-settings": "上游设置",
  };
  return labels[action] ?? "处理";
}

function CommandPalette({
  onClose,
  onNavigate,
}: {
  onClose: () => void;
  onNavigate: (view: ViewId) => void;
}) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const actions = useMemo(
    () => [
      { label: "查看实时流量", hint: "流量", icon: Network, view: "traffic" as ViewId },
      { label: "打开内嵌浏览器", hint: "CDP", icon: Browser, view: "browser" as ViewId },
      { label: "打开请求实验室", hint: "Lab", icon: FlaskConical, view: "lab" as ViewId },
      { label: "开始 AI 分析", hint: "智能过滤", icon: Sparkles, view: "analysis" as ViewId },
      { label: "管理 Skill 与 MCP", hint: "能力", icon: ServerCog, view: "skills" as ViewId },
      { label: "安装 HTTPS 证书", hint: "CA", icon: KeyRound, view: "settings" as ViewId },
    ],
    [],
  );
  const filtered = useMemo(
    () => actions.filter((action) => action.label.toLowerCase().includes(query.toLowerCase())),
    [actions, query],
  );

  useEffect(() => setActiveIndex(0), [query]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (!filtered.length) return;
        const offset = event.key === "ArrowDown" ? 1 : -1;
        setActiveIndex((current) => (current + offset + filtered.length) % filtered.length);
      } else if (event.key === "Enter" && filtered[activeIndex]) {
        event.preventDefault();
        onNavigate(filtered[activeIndex].view);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [activeIndex, filtered, onNavigate]);

  return (
    <div className="modal-backdrop command-backdrop" onMouseDown={onClose}>
      <section className="command-palette" role="dialog" aria-modal="true" aria-label="快捷命令" onMouseDown={(event) => event.stopPropagation()}>
        <div className="command-search">
          <Search size={18} />
          <input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索操作" />
          <kbd>ESC</kbd>
        </div>
        <div className="command-results" role="listbox" aria-label="命令结果">
          <span className="command-group-label">快速前往</span>
          {filtered.map((action, index) => {
            const Icon = action.icon;
            return (
              <button
                key={action.view}
                className={index === activeIndex ? "is-selected" : ""}
                role="option"
                aria-selected={index === activeIndex}
                onPointerMove={() => setActiveIndex(index)}
                onClick={() => onNavigate(action.view)}
              >
                <Icon size={17} />
                <span>{action.label}</span>
                <small>{action.hint}</small>
              </button>
            );
          })}
          {filtered.length === 0 && (
            <div className="command-empty">
              <FileSearch size={20} />
              <span>没有匹配的操作</span>
            </div>
          )}
        </div>
        <div className="command-footer">
          <span><Zap size={13} /> ShowNet Command</span>
          <span>↑↓ 选择 · ↵ 打开</span>
        </div>
      </section>
    </div>
  );
}

export default App;
