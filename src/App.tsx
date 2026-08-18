import {
  Activity,
  Braces,
  Globe2 as Browser,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleDot,
  Command,
  Compass,
  Copy,
  Download,
  FileArchive,
  FileJson,
  FileSearch,
  FlaskConical,
  FolderOpen,
  Info,
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
  Settings,
  ShieldCheck,
  Sparkles,
  Square,
  Terminal,
  Trash2,
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
import { forgetStoredBrowserUrl } from "./browserSessionUrl";
import { getProxyBrowserStatus } from "./browserBus";
import { ensureCaptureSession } from "./captureSession";
import { clientAccessModeSummary } from "./clientAccess";
import {
  filterCommands,
  flattenCommands,
  groupCommands,
  moveCommandCursor,
  type CommandAction,
} from "./commandRegistry";
import { AboutDialog } from "./components/AboutDialog";
import { AdvancedConsoleView } from "./components/AdvancedConsoleView";
import { AnalysisView } from "./components/AnalysisView";
import { BrowserView } from "./components/BrowserView";
import { RequestWorkbench, type WorkbenchMode } from "./components/RequestWorkbench";
import { SkillsView } from "./components/SkillsView";
import { SettingsView, type SettingsTab } from "./components/SettingsView";
import { useConfirm } from "./components/ConfirmDialog";
import { SetupGuide } from "./components/SetupGuide";
import { ShortcutsSheet } from "./components/ShortcutsSheet";
import { TrafficView } from "./components/TrafficView";
import { createPreviewRequestWindow, initialRequestListItems, initialSessions, sourceLabels } from "./data";
import {
  createLiveCaptureDisplayController,
  LIVE_CAPTURE_DISPLAY_PREFERENCES_KEY,
  parseLiveCaptureDisplayPreferences,
  type LiveCaptureDisplaySnapshot,
} from "./liveCaptureDisplay";
import { addCreatedItemsToFacets, createRefreshCoalescer, createRequestListBatcher, createRequestQueryId, isRequestQueryCancelled, mergeRequestWindowItems, queryPreviewRequestList, REQUEST_LIST_WINDOW_SIZE, requiresLiveQueryRefresh } from "./requestList";
import { formatBytes } from "./format";
import { activateUiLocale, createTranslator, resolveUiLocale, t, writeStoredUiLocale, type Translate } from "./i18n.ts";
import { LocaleSwitcher } from "./components/LocaleSwitcher";
import { chromeLabel, chromeTitle, NAV_VIEWS } from "./navChrome";
import { toastTone } from "./toastTone";
import { createProxyErrorQueue, type ProxyErrorQueue } from "./proxyErrorQueue";
import { defaultCaptureSessionName } from "./sessionPresentation";
import {
  buildSetupSteps,
  SETUP_DISMISSED_KEY,
  setupProgress,
  shouldAutoOpenSetup,
  type SetupStepId,
} from "./setupChecklist";
import type { AnalysisMode, AnalysisStreamEvent, BreakpointQueueSnapshot, ConnectionDiagnostics, FilterExpression, ProxyTerminalLaunchResult, RequestFacets, RequestListEvent, RequestListItem, RequestListPage, RequestListWindow, RequestQueryCancellationAck, RequestQueryIdleMeasurement, RequestSort, ReverseProxySettingsInput, ReverseProxyStatus, RuntimeStatus, Session, SoakDiagnosticsStatus, SourceType, UpdateCheckResult, ViewId } from "./types";
import { useDismissibleLayer } from "./useDismissibleLayer";
import { sourceIcons } from "./sourceIcons";

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

/** True while focus is in a text field, where "?" is a character, not a shortcut. */
function isEditableTarget(target: EventTarget | null) {
  return target instanceof HTMLInputElement
    || target instanceof HTMLTextAreaElement
    || target instanceof HTMLSelectElement
    || (target instanceof HTMLElement && target.isContentEditable);
}

/** Opens a link in the user's browser; falls back to a new tab in preview. */
async function openExternalUrl(url: string) {
  if (!hasNativeRuntime) {
    globalThis.open?.(url, "_blank", "noopener");
    return;
  }
  const { openUrl } = await import("@tauri-apps/plugin-opener");
  await openUrl(url);
}

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

const viewIcons: Record<ViewId, typeof Network> = {
  traffic: Network,
  browser: Browser,
  lab: FlaskConical,
  advanced: ShieldCheck,
  analysis: Sparkles,
  skills: Braces,
  settings: Settings,
};

function viewMeta(t: Translate): Record<ViewId, { label: string; title: string; icon: typeof Network }> {
  return Object.fromEntries(
    NAV_VIEWS.map((view) => [
      view,
      { label: chromeLabel(t, view), title: chromeTitle(t, view), icon: viewIcons[view] },
    ]),
  ) as Record<ViewId, { label: string; title: string; icon: typeof Network }>;
}

function primaryNavigationGroups(t: Translate): Array<{ label: string; views: ViewId[] }> {
  return [
    { label: t("navGroup.capture"), views: ["traffic", "browser"] },
    { label: t("navGroup.tools"), views: ["lab", "advanced"] },
    { label: t("navGroup.intelligence"), views: ["analysis", "skills"] },
  ];
}


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

/**
 * One or two characters that stand for a session in the collapsed rail.
 * Latin names read better with two letters; CJK is dense enough at one.
 */
function sessionInitial(name: string) {
  const trimmed = name.trim();
  if (!trimmed) return "?";
  const first = [...trimmed][0];
  if (/[a-zA-Z0-9]/.test(first)) return trimmed.slice(0, 2).toUpperCase();
  return first;
}

function formatSessionTime(value: string, t: Translate, intlLocale: string) {
  // Preview fixtures store preformatted Chinese clocks. Re-translate them.
  if (value === "刚刚" || value === t("clock.justNow")) return t("clock.justNow");
  if (value.startsWith("今天 ")) return `${t("clock.today")} ${value.slice("今天 ".length)}`;
  if (value.startsWith("昨天 ")) return `${t("clock.yesterday")} ${value.slice("昨天 ".length)}`;
  if (value === t("clock.justNow") || value.includes(t("clock.today")) || value.includes(t("clock.yesterday"))) {
    return value;
  }
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) return value;
  const now = new Date();
  const elapsed = now.getTime() - timestamp.getTime();
  if (elapsed >= 0 && elapsed < 60_000) return t("clock.justNow");
  const clock = timestamp.toLocaleTimeString(intlLocale, { hour: "2-digit", minute: "2-digit", hour12: false });
  if (timestamp.toDateString() === now.toDateString()) {
    return `${t("clock.today")} ${clock}`;
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (timestamp.toDateString() === yesterday.toDateString()) {
    return `${t("clock.yesterday")} ${clock}`;
  }
  return timestamp.toLocaleDateString(intlLocale, { month: "numeric", day: "numeric" });
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
  const [uiLocale, setUiLocale] = useState(() => resolveUiLocale());
  const { t, intlLocale } = useMemo(() => {
    const pack = activateUiLocale(uiLocale);
    return createTranslator(pack.id);
  }, [uiLocale]);
  const applyUiLocale = (locale: string) => {
    const pack = activateUiLocale(locale);
    writeStoredUiLocale(pack.id);
    setUiLocale(pack.id);
  };
  const views = viewMeta(t);
  const navGroups = primaryNavigationGroups(t);
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
  const [captureTransitioning, setCaptureTransitioning] = useState(false);
  const [sessionCatalogReady, setSessionCatalogReady] = useState(!hasNativeRuntime);
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
  // AI 分析 and Skill 编排 are two views onto the same pipeline. Holding the
  // mode here keeps them agreeing, and stops the selection resetting every
  // time AnalysisView unmounts on navigation.
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>("auto");
  /**
   * Whether the user has actually picked a mode. Until they have, restoring the
   * last report may adopt its mode; afterwards it must not, or opening 分析
   * would silently undo a choice made over in Skill 编排.
   */
  const [analysisModePinned, setAnalysisModePinned] = useState(false);
  const chooseAnalysisMode = useCallback((mode: AnalysisMode) => {
    setAnalysisMode(mode);
    setAnalysisModePinned(true);
  }, []);
  const [setupOpen, setSetupOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [aboutOpen, setAboutOpen] = useState(false);
  const { confirm, dialog: confirmDialog } = useConfirm();
  const [setupDismissed, setSetupDismissed] = useState(
    () => globalThis.localStorage?.getItem(SETUP_DISMISSED_KEY) === "1",
  );
  const [aiConfigured, setAiConfigured] = useState(false);
  const setupAutoOpenedRef = useRef(false);
  const captureTransitioningRef = useRef(false);
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
  const proxyErrorQueueRef = useRef<ProxyErrorQueue | null>(null);

  useDismissibleLayer(sessionToolsOpen, sessionToolsRef, () => setSessionToolsOpen(false));

  const activeSession = sessions.find((session) => session.id === activeSessionId) ?? sessions[0] ?? { ...loadingSession, name: t("shell.loadingSession") };
  const captureSessionId = capturing
    ? (runtime.activeSessionId ?? sessions.find((session) => session.active)?.id ?? "")
    : "";
  const captureSession = sessions.find((session) => session.id === captureSessionId);
  const browserSession = capturing
    ? (captureSession ?? { ...loadingSession, id: captureSessionId, name: t("shell.activeCaptureSession") })
    : activeSession;
  const viewingCaptureSession = Boolean(captureSessionId && activeSession.id === captureSessionId);

  const setupSteps = useMemo(() => buildSetupSteps({
    capturing,
    requestCount: activeSession.requestCount,
    caInstalled: runtime.caInstalled,
    aiConfigured,
    sourceCount: activeSession.sources.length,
  }), [activeSession.requestCount, activeSession.sources.length, aiConfigured, capturing, runtime.caInstalled]);
  const setupState = useMemo(() => setupProgress(setupSteps), [setupSteps]);

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
      if (notify && queryId) setToast(t("shell.queryCancelled"));
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
      if (notify) setToast(t("shell.queryCancelFailed", { error: String(error) }));
    }
    setRequestListLoading(false);
    setRequestQueryCancelling(false);
    if (notify && acknowledgement.settled) setToast(t("shell.queryCancelled"));
    if (notify && !acknowledgement.settled) setToast(t("shell.queryCancelTimeout"));
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
    setSessions((current) => {
      const loadedIds = new Set(loaded.map((session) => session.id));
      current.forEach((session) => {
        if (!loadedIds.has(session.id)) forgetStoredBrowserUrl(session.id);
      });
      return loaded;
    });
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
        setToast(t("shell.windowFailed", { error: String(error) }));
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
      setToast(t("shell.syncFailed", { error: String(error) }));
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
      setToast(t("shell.openStopFirst"));
      return;
    }
    setTransferring(true);
    try {
      const imported = await invoke<Session>("import_session_file", { path });
      await refreshSessions();
      setActiveSessionId(imported.id);
      setActiveView("traffic");
      setToast(t("shell.openedSession", { name: imported.name }));
    } catch (error) {
      setToast(t("shell.openFailed", { error: String(error) }));
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
      setToast(t("shell.cryptoLabDone"));
    } catch (error) {
      setToast(t("shell.cryptoLabFailed", { error: String(error) }));
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
        setToast(t("shell.editCmdFailed", { error: String(error) }));
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
        if (!disposed) setToast(t("shell.nativeInitFailed", { error: String(error) }));
      })
      .finally(() => {
        if (!disposed) setSessionCatalogReady(true);
      });
    return () => {
      disposed = true;
    };
  }, []);

  // Preview seeding needs `sessions`; the desktop path must not depend on it.
  // `refreshSessions()` runs on every capture://request-created (coalesced to
  // 250 ms) and hands back a fresh array, so a shared effect re-ran ~4x/s during
  // capture — resetting the scroll window to 0 and cancelling the in-flight
  // query each time.
  useEffect(() => {
    if (hasNativeRuntime) return;
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
  }, [activeSessionId, requestFilter, requestSort, sessions]);

  useEffect(() => {
    if (!hasNativeRuntime) return;
    requestWindowOffsetRef.current = 0;
    setRequestWindowOffset(0);
    refreshRequests(activeSessionId).catch((error) => setToast(t("shell.readTrafficFailed", { error: String(error) })));
  }, [activeSessionId, refreshRequests]);

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
      .catch((error) => { if (!disposed) setToast(t("shell.readBreakpointsFailed", { error: String(error) })); });

    const proxyErrors = createProxyErrorQueue({
      show: (message) => setToast(message),
      now: () => Date.now(),
      schedule: (callback, delayMs) => window.setTimeout(callback, delayMs),
      cancel: (handle) => window.clearTimeout(handle),
    });
    proxyErrorQueueRef.current = proxyErrors;

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
        // Sent when the capture stopped but reading the full status failed —
        // typically the same storage fault that broke the stop in the first
        // place. Carries no payload because anything it could carry comes from
        // the read that just failed; it exists so the shell cannot be left
        // showing 抓包中 for a capture that is down, with the takeover switch
        // greyed out behind that stale flag.
        listen("capture://stopped", () => {
          // Known for certain: the capture is down, and restore_system_proxy
          // gives up `active` on both its branches.
          setCapturing(false);
          setRuntime((current) => ({ ...current, proxyRunning: false, systemProxyActive: false }));
          // Not known: whether a recovery is now outstanding — that lives in the
          // read which just failed. Ask again; by now the contention may have
          // cleared, and without it 设置 shows no 重试恢复 button while starting
          // a capture refuses and tells the user to press it.
          void invoke<RuntimeStatus>("get_runtime_status")
            .then((status) => setRuntime(withClientAccessDefaults(status)))
            .catch(() => undefined);
          void refreshSessions().catch(() => undefined);
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
          if (disposed) return;
          // Surface full egress / connect failures (e.g. 连接 host:port 超时)
          // without flooding — and without dropping one failure because a
          // different one happened to arrive moments earlier.
          proxyErrors.push(String(event.payload ?? ""));
        }),
      ]);
      if (disposed) listeners.forEach((unlisten) => unlisten());
      else unlisteners.push(...listeners);
    };

    subscribe().catch((error) => setToast(t("shell.subscribeFailed", { error: String(error) })));
    return () => {
      disposed = true;
      // A held failure must not fire into a view that is gone.
      proxyErrors.dispose();
      if (proxyErrorQueueRef.current === proxyErrors) proxyErrorQueueRef.current = null;
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
      if (event.key === "?" && !isEditableTarget(event.target)) {
        event.preventDefault();
        setShortcutsOpen((open) => !open);
      }
      if (event.key === "Escape") {
        setCommandOpen(false);
        setConnectOpen(false);
        setSessionToolsOpen(false);
        setRenamingSessionId("");
        setExportOpen(false);
        setSetupOpen(false);
        setShortcutsOpen(false);
        setAboutOpen(false);
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

  useEffect(() => {
    if (!hasNativeRuntime) return;
    const timer = window.setTimeout(() => {
      void invoke<UpdateCheckResult>("check_for_updates")
        .then((result) => {
          if (result.available) setToast(t("shell.updateAvailable", { version: result.latestVersion }));
        })
        .catch(() => {
          // Startup checks are best-effort; the explicit Settings action exposes errors.
        });
    }, 3_000);
    return () => window.clearTimeout(timer);
  }, []);

  // The setup panel needs to know whether analysis is usable, and that lives
  // behind the same IPC the AI settings tab reads. Re-checked whenever the user
  // returns from Settings so a freshly saved key ticks the step immediately.
  useEffect(() => {
    if (!hasNativeRuntime) return;
    let disposed = false;
    invoke<{ provider: string; hasApiKey: boolean }>("get_ai_provider_settings")
      .then((settings) => {
        if (!disposed) setAiConfigured(settings.hasApiKey || settings.provider === "local");
      })
      .catch(() => undefined);
    return () => { disposed = true; };
  }, [activeView]);

  useEffect(() => {
    if (setupAutoOpenedRef.current) return;
    // Wait for the first runtime probe so the checklist never flashes an
    // all-empty state that immediately corrects itself.
    if (hasNativeRuntime && !sessions.length) return;
    setupAutoOpenedRef.current = true;
    if (shouldAutoOpenSetup(setupState, setupDismissed)) setSetupOpen(true);
  }, [sessions.length, setupDismissed, setupState]);

  const createSession = async (announce = true): Promise<Session | null> => {
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
        if (announce) setToast(capturing && captureSession
          ? t("shell.sessionCreatedKeep", { name: captureSession.name })
          : t("shell.sessionCreated"));
        return created;
      } catch (error) {
        setToast(t("shell.createFailed", { error: String(error) }));
        return null;
      }
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
    if (announce) setToast(capturing && captureSession
      ? t("shell.sessionCreatedKeep", { name: captureSession.name })
      : t("shell.sessionCreated"));
    return newSession;
  };

  const toggleCapture = async () => {
    if (captureTransitioningRef.current) return false;
    if (!sessionCatalogReady) {
      setToast(t("shell.sessionLoading"));
      return false;
    }
    captureTransitioningRef.current = true;
    setCaptureTransitioning(true);
    const next = !capturing;
    if (!next && hasNativeRuntime) {
      const browser = await getProxyBrowserStatus().catch(() => null);
      if (browser?.running && !await confirm({
        title: t("shell.stopCaptureNamed", { name: captureSession?.name ?? t("shell.currentSession") }),
        detail: t("shell.stopCaptureDetail"),
        confirmLabel: t("shell.stopAndClear"),
        tone: "danger",
      })) {
        captureTransitioningRef.current = false;
        setCaptureTransitioning(false);
        return false;
      }
    }
    try {
      const target = next
        ? await ensureCaptureSession(activeSession.id, async () => {
          setToast(t("shell.captureNoSession"));
          return createSession(false);
        })
        : { sessionId: captureSessionId || activeSession.id, created: false };
      if (!target) return false;
      const sessionId = target.sessionId;

      if (!hasNativeRuntime) {
        setCapturing(next);
        setSessions((items) =>
          items.map((session) =>
            session.id === sessionId ? { ...session, active: next } : { ...session, active: false },
          ),
        );
        setRuntime((status) => ({
          ...status,
          proxyRunning: next,
          activeSessionId: next ? sessionId : undefined,
        }));
      } else {
        const status = await invoke<RuntimeStatus>("set_capture_running", {
          running: next,
          sessionId: next ? sessionId : null,
        });
        setRuntime(withClientAccessDefaults(status));
        setCapturing(status.proxyRunning);
        await refreshSessions();
      }
      setToast(target.created
        ? t("shell.captureCreated")
        : next ? t("shell.captureStarted") : t("shell.capturePaused"));
      return next;
    } catch (error) {
      setToast(t("shell.captureToggleFailed", { error: String(error) }));
      return false;
    } finally {
      captureTransitioningRef.current = false;
      setCaptureTransitioning(false);
    }
  };

  const deleteSession = async (session: Session) => {
    setSessionToolsOpen(false);
    if (capturing && session.id === captureSessionId) {
      setToast(t("shell.deleteStopFirst"));
      return;
    }
    if (!await confirm({
      title: t("shell.deleteSessionTitle", { name: session.name }),
      detail: t("shell.deleteSessionBody", { count: session.requestCount }),
      confirmLabel: t("shell.deleteSession"),
      tone: "danger",
    })) return;

    if (!hasNativeRuntime) {
      setSessions((items) => items.filter((item) => item.id !== session.id));
      forgetStoredBrowserUrl(session.id);
      setToast(t("shell.sessionDeleted", { name: session.name }));
      return;
    }
    setTransferring(true);
    try {
      await invoke("delete_session", { sessionId: session.id });
      forgetStoredBrowserUrl(session.id);
      await refreshSessions();
      setToast(t("shell.sessionDeleted", { name: session.name }));
    } catch (error) {
      setToast(t("shell.deleteFailed", { error: String(error) }));
    } finally {
      setTransferring(false);
    }
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
      setToast(t("shell.renameEmpty"));
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
      setToast(t("shell.renamed", { name }));
    } catch (error) {
      setToast(t("shell.renameFailed", { error: String(error) }));
    } finally {
      setRenamingSession(false);
    }
  };

  const exportSession = async (format: "shownet" | SessionExportFormat) => {
    setSessionToolsOpen(false);
    if (!activeSession.id) return;
    if (!hasNativeRuntime) {
      setExportOpen(false);
      setToast(t("shell.exportReady", { format: format === "shownet" ? t("shell.packLabel") : format.toUpperCase() }));
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
      setToast(t("shell.exported", { format: result.format, size: formatBytes(result.bytes) }));
    } catch (error) {
      setToast(t("shell.exportFailed", { error: String(error) }));
    } finally {
      setTransferring(false);
    }
  };

  const openSessionFile = async () => {
    setSessionToolsOpen(false);
    if (!hasNativeRuntime) {
      setToast(t("shell.desktopOpenPack"));
      return;
    }
    if (capturing) {
      setToast(t("shell.openStopFirst"));
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
        setToast(capturing ? t("shell.openStopFirst") : t("shell.dropProcessing"));
        return;
      }
      if (!supported || !path) {
        setSessionDrop({ status: "idle" });
        if (containsSession) setToast(t("shell.oneSessionFile"));
        return;
      }
      setSessionDrop({ status: "importing", path });
      void importSessionPath(path).finally(() => {
        if (!disposed) setSessionDrop({ status: "idle" });
      });
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    }).catch((error) => setToast(t("shell.dropUnavailable", { error: String(error) })));
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
      setToast(t("common.copiedLabel", { label }));
    } catch (error) {
      setToast(t("common.copyFailed", { error: String(error) }));
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

  const openSettingsTab = (tab: SettingsTab) => {
    setSettingsTab(tab);
    setActiveView("settings");
    setCommandOpen(false);
  };

  const openWorkbench = (mode: WorkbenchMode) => {
    setWorkbenchLaunch({
      id: Date.now(),
      mode,
      sessionId: activeSession.id,
      selected: [],
      createFromSelection: false,
    });
    setActiveView("lab");
    setCommandOpen(false);
  };

  const runSetupStep = (id: SetupStepId) => {
    setSetupOpen(false);
    if (id === "capture") {
      if (capturing) openSettingsTab("capture");
      else void toggleCapture();
      return;
    }
    if (id === "source") {
      if (activeSession.requestCount > 0) setActiveView("traffic");
      else setActiveView("browser");
      return;
    }
    openSettingsTab(id === "certificate" ? "capture" : "ai");
  };

  const dismissSetupForever = () => {
    globalThis.localStorage?.setItem(SETUP_DISMISSED_KEY, "1");
    setSetupDismissed(true);
    setSetupOpen(false);
  };

  /**
   * Every action the app can perform, in one index. Views own their own
   * controls too, but this is the path that does not require knowing which
   * view owns what.
   */
  const commandActions: CommandAction[] = [
    {
      id: "setup-guide",
      title: t("cmd.setup.title"),
      subtitle: setupState.ready ? t("cmd.setup.subtitleReady") : t("cmd.setup.subtitleLeft", { count: setupState.total - setupState.done }),
      group: "start",
      keywords: ["setup", "guide", "onboarding", "getting started", "xssy", "yindao"],
      badge: setupState.ready ? t("common.ready") : `${setupState.done}/${setupState.total}`,
      badgeTone: setupState.ready ? "ok" : "warn",
      run: () => { setCommandOpen(false); setSetupOpen(true); },
    },
    {
      id: "shortcuts",
      title: t("cmd.shortcuts.title"),
      subtitle: t("cmd.shortcuts.subtitle"),
      group: "start",
      keywords: ["shortcut", "keyboard", "keys", "hotkey", "kjj", "kuaijiejian"],
      shortcut: "?",
      run: () => { setCommandOpen(false); setShortcutsOpen(true); },
    },
    {
      id: "about",
      title: t("cmd.about.title"),
      subtitle: t("cmd.about.subtitle"),
      group: "start",
      keywords: ["about", "version", "license", "gpl", "gy", "banben"],
      badge: runtime.appVersion,
      run: () => { setCommandOpen(false); setAboutOpen(true); },
    },
    {
      id: "capture-toggle",
      title: capturing ? t("shell.stopCapture") : t("shell.startCapture"),
      subtitle: capturing ? t("cmd.capture.stopSubtitle", { port: runtime.proxyPort }) : t("cmd.capture.startSubtitle"),
      group: "capture",
      keywords: ["capture", "start", "stop", "proxy", "record", "kbz", "zbb"],
      badge: capturing ? t("common.running") : t("common.paused"),
      badgeTone: capturing ? "ok" : "neutral",
      disabled: captureTransitioning || !sessionCatalogReady,
      disabledReason: captureTransitioning ? t("cmd.capture.switching") : t("cmd.capture.loading"),
      run: () => { setCommandOpen(false); void toggleCapture(); },
    },
    {
      id: "connect-sources",
      title: t("cmd.connect.title"),
      subtitle: t("cmd.connect.subtitle"),
      group: "capture",
      keywords: ["connect", "source", "device", "mobile", "terminal", "lljr", "ly"],
      run: () => { setCommandOpen(false); setConnectOpen(true); },
    },
    {
      id: "open-browser-capture",
      title: t("cmd.browserCapture.title"),
      subtitle: runtime.caInstalled ? t("cmd.browserCapture.ready") : t("cmd.browserCapture.needCa"),
      group: "capture",
      keywords: ["browser", "chrome", "embedded", "cdp", "llq"],
      run: () => navigate("browser"),
    },
    {
      id: "proxy-terminal",
      title: t("cmd.terminal.title"),
      subtitle: t("cmd.terminal.subtitle"),
      group: "capture",
      keywords: ["terminal", "shell", "curl", "cli", "dlzd"],
      run: () => { setCommandOpen(false); setConnectOpen(true); },
    },
    {
      id: "copy-proxy",
      title: t("cmd.copyProxy.title"),
      subtitle: `127.0.0.1:${runtime.proxyPort}`,
      group: "capture",
      keywords: ["copy", "proxy", "address", "endpoint", "fzdl"],
      run: () => {
        setCommandOpen(false);
        void copyConnectValue(`127.0.0.1:${runtime.proxyPort}`, t("settings.route.copyProxy"));
      },
    },
    {
      id: "session-new",
      title: capturing ? t("shell.newEmptySession") : t("shell.newSession"),
      subtitle: capturing && captureSession
        ? t("cmd.session.keepWriting", { name: captureSession.name })
        : t("cmd.session.newClean"),
      group: "session",
      keywords: ["new", "session", "create", "xjhh"],
      disabled: captureTransitioning,
      disabledReason: t("cmd.capture.switching"),
      run: () => { setCommandOpen(false); void createSession(); },
    },
    {
      id: "session-open",
      title: t("shell.openSessionFile"),
      subtitle: t("cmd.session.pack"),
      group: "session",
      keywords: ["open", "import", "session", "file", "dkhh"],
      disabled: capturing,
      disabledReason: t("cmd.session.stopFirst"),
      run: () => { setCommandOpen(false); void openSessionFile(); },
    },
    {
      id: "session-save",
      title: t("shell.saveSession"),
      subtitle: t("cmd.session.saveDetail"),
      group: "session",
      keywords: ["save", "export", "shownet", "backup", "bchh"],
      disabled: !activeSession.id || transferring,
      disabledReason: transferring ? t("cmd.session.busy") : t("cmd.session.none"),
      run: () => { setCommandOpen(false); void exportSession("shownet"); },
    },
    {
      id: "session-delete",
      title: t("cmd.session.deleteCurrent"),
      subtitle: t("cmd.session.deleteMeta", { name: activeSession.name, count: activeSession.requestCount }),
      group: "session",
      keywords: ["delete", "remove", "drop", "schh", "shanchu"],
      disabled: !activeSession.id || (capturing && activeSession.id === captureSessionId),
      disabledReason: capturing && activeSession.id === captureSessionId ? t("cmd.session.stopFirst") : t("cmd.session.none"),
      run: () => { setCommandOpen(false); void deleteSession(activeSession); },
    },
    {
      id: "session-export",
      title: t("cmd.session.exportTitle"),
      subtitle: t("cmd.session.exportSubtitle"),
      group: "session",
      keywords: ["export", "har", "postman", "openapi", "swagger", "dc"],
      disabled: !activeSession.id,
      disabledReason: t("cmd.session.none"),
      run: () => { setCommandOpen(false); setExportOpen(true); },
    },
    { id: "go-traffic", title: chromeLabel(t, "traffic"), subtitle: t("cmd.go.traffic"), group: "navigate", keywords: ["traffic", "requests", "list", "ll", "流量"], run: () => navigate("traffic") },
    { id: "go-browser", title: chromeLabel(t, "browser"), subtitle: t("cmd.go.browser"), group: "navigate", keywords: ["browser", "chrome", "embedded", "llq", "浏览器"], run: () => navigate("browser") },
    { id: "go-lab", title: chromeLabel(t, "lab"), subtitle: t("cmd.go.lab"), group: "navigate", keywords: ["lab", "request", "replay", "build", "sys", "实验室"], run: () => navigate("lab") },
    { id: "go-collections", title: t("cmd.go.collections"), subtitle: t("cmd.go.collectionsSub"), group: "navigate", keywords: ["collection", "folder", "postman", "openapi", "qqjh"], run: () => openWorkbench("collections") },
    { id: "go-rules", title: t("cmd.go.rules"), subtitle: t("cmd.go.rulesSub"), group: "navigate", keywords: ["rules", "breakpoint", "rewrite", "map remote", "gz"], badge: breakpointQueue.tasks.length ? t("cmd.go.waiting", { count: breakpointQueue.tasks.length }) : undefined, badgeTone: "warn", run: () => openWorkbench("rules") },
    { id: "go-environment", title: t("cmd.go.environment"), subtitle: t("cmd.go.environmentSub"), group: "navigate", keywords: ["environment", "variable", "secret", "env", "hjbl"], run: () => openWorkbench("environment") },
    { id: "go-analysis", title: chromeLabel(t, "analysis"), subtitle: t("cmd.go.analysis"), group: "navigate", keywords: ["ai", "analysis", "reverse", "agent", "fx", "分析"], run: () => navigate("analysis") },
    { id: "go-skills", title: chromeLabel(t, "skills"), subtitle: t("cmd.go.skills"), group: "navigate", keywords: ["skill", "mcp", "agent", "tools", "nl", "能力"], run: () => navigate("skills") },
    { id: "go-advanced", title: chromeLabel(t, "advanced"), subtitle: t("cmd.go.advanced"), group: "navigate", keywords: ["advanced", "mitm", "tls", "ja3", "px", "gj", "高级"], run: () => navigate("advanced") },
    { id: "go-settings", title: chromeLabel(t, "settings"), subtitle: t("cmd.go.settings"), group: "navigate", keywords: ["settings", "preferences", "sz", "设置"], run: () => navigate("settings") },
    {
      id: "install-ca",
      title: t("cmd.ca.title"),
      subtitle: t("cmd.ca.subtitle"),
      group: "config",
      keywords: ["ca", "cert", "certificate", "https", "trust", "root", "azzs"],
      badge: runtime.caInstalled ? t("common.trusted") : t("common.notInstalled"),
      badgeTone: runtime.caInstalled ? "ok" : "warn",
      run: () => openSettingsTab("capture"),
    },
    {
      id: "device-access",
      title: t("cmd.device.title"),
      subtitle: t("cmd.device.subtitle"),
      group: "config",
      keywords: ["device", "mobile", "phone", "android", "qr", "lan", "sjjr"],
      badge: runtime.lanEnabled ? t("common.enabled") : t("common.disabled"),
      badgeTone: runtime.lanEnabled ? "ok" : "neutral",
      run: () => openSettingsTab("capture"),
    },
    {
      id: "ai-settings",
      title: t("cmd.ai.title"),
      subtitle: t("cmd.ai.subtitle"),
      group: "config",
      keywords: ["ai", "model", "api key", "openai", "provider", "pzai"],
      badge: aiConfigured ? t("common.configured") : t("common.notConfigured"),
      badgeTone: aiConfigured ? "ok" : "warn",
      run: () => openSettingsTab("ai"),
    },
    { id: "mcp-settings", title: t("cmd.mcp.title"), subtitle: t("cmd.mcp.subtitle"), group: "config", keywords: ["mcp", "claude", "cursor", "codex", "client"], run: () => openSettingsTab("mcp") },
    { id: "data-settings", title: t("cmd.data.title"), subtitle: t("cmd.data.subtitle"), group: "config", keywords: ["data", "storage", "database", "cleanup", "sj"], run: () => openSettingsTab("data") },
    { id: "capture-settings", title: t("cmd.captureSettings.title"), subtitle: t("cmd.captureSettings.subtitle"), group: "config", keywords: ["settings", "proxy", "port", "upstream", "decrypt", "sz"], run: () => openSettingsTab("capture") },
  ];

  return (
    <div className="app-shell">
      <nav className="nav-rail" aria-label={t("shell.mainNav")}>
        <button className="brand-mark" title={t("shell.aboutTitle", { version: runtime.appVersion })} onClick={() => setAboutOpen(true)}>
          <img src={shownetAppIcon} alt="" aria-hidden="true" />
        </button>
        <div className="nav-rail__items">
          {navGroups.map((group) => (
            <div className="nav-rail__group" role="group" aria-label={group.label} key={group.label}>
              {group.views.map((view) => {
                const Icon = views[view].icon;
                return (
                  <button
                    key={view}
                    data-nav={view}
                    className={`nav-rail__item ${view === "lab" ? "nav-rail__item--lab" : ""} ${activeView === view ? "is-active" : ""}`}
                    onClick={() => navigate(view)}
                    title={views[view].label}
                    aria-label={views[view].label}
                  >
                    <Icon size={20} />
                    <span>{views[view].label}</span>
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
            title={t("shell.commandTitle")}
          >
            <Command size={19} />
            <span>{t("shell.command")}</span>
          </button>
          <button
            data-nav="settings"
            className={`nav-rail__item ${activeView === "settings" ? "is-active" : ""}`}
            onClick={() => navigate("settings")}
            title={t("nav.settings")}
            aria-label={t("nav.settings")}
          >
            <Settings size={20} />
            <span>{t("nav.settings")}</span>
          </button>
        </div>
      </nav>

      <aside className={`sessions-panel ${compactSessions ? "is-compact" : ""} ${activeView === "lab" ? "is-workbench-hidden" : ""}`}>
        <div className="sessions-panel__header">
          <div>
            <span className="product-name">ShowNet</span>
            <span className="product-channel">DESKTOP</span>
          </div>
          <button className="icon-button" title={t("shell.collapseSessions")} onClick={() => setCompactSessions((value) => !value)}>
            <Menu size={17} />
          </button>
        </div>

        <button className="new-session-button" onClick={() => void createSession()} disabled={captureTransitioning} title={capturing && captureSession ? t("shell.newEmptyHint", { name: captureSession.name }) : t("shell.newSession")}>
          <Plus size={16} />
          <span>{capturing ? t("shell.newEmptySession") : t("shell.newSession")}</span>
        </button>

        <div className="sessions-label">
          <span>{t("shell.sessions")}</span>
          <div className="session-tools" ref={sessionToolsRef}>
            <button className="icon-button icon-button--small" title={t("shell.sessionMenu")} onClick={() => setSessionToolsOpen((open) => !open)}>
              <MoreHorizontal size={16} />
            </button>
            {sessionToolsOpen && (
              <div className="session-tools-menu">
                <button onClick={openSessionFile}><FolderOpen size={14} /><span><strong>{t("shell.openSession")}</strong><small>.shownet</small></span></button>
                <button onClick={() => void exportSession("shownet")} disabled={!activeSession.id || transferring}><Save size={14} /><span><strong>{t("shell.saveSession")}</strong><small>{t("shell.saveSessionDetail")}</small></span></button>
                <i />
                <button onClick={() => { setSessionToolsOpen(false); setExportOpen(true); }} disabled={!activeSession.id}><Download size={14} /><span><strong>{t("shell.exportOther")}</strong><small>{t("shell.exportOtherDetail")}</small></span></button>
                <i />
                <button className="is-danger" onClick={() => void deleteSession(activeSession)} disabled={!activeSession.id || transferring}><Trash2 size={14} /><span><strong>{t("shell.deleteSession")}</strong><small>{t("shell.deleteSessionDetail", { count: activeSession.requestCount })}</small></span></button>
              </div>
            )}
          </div>
        </div>

        <div className="session-list">
          {sessions.map((session) => {
            const editing = renamingSessionId === session.id;
            const isCaptureTarget = capturing && session.id === captureSessionId;
            return (
            <div className={`session-entry ${editing ? "is-editing" : ""}`} key={session.id}>
              {editing ? (
                <form className="session-rename-editor" onSubmit={(event) => { event.preventDefault(); void saveSessionName(session.id); }}>
                  <span className={`session-status ${isCaptureTarget ? "is-live" : ""}`} />
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
                    aria-label={t("shell.renameNamed", { name: session.name })}
                  />
                  <span className="session-rename-editor__actions">
                    <button type="submit" title={t("shell.saveName")} disabled={renamingSession || !sessionNameDraft.trim()}><Check size={13} /></button>
                    <button type="button" title={t("shell.cancelRename")} disabled={renamingSession} onClick={cancelSessionRename}><X size={13} /></button>
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
                    title={isCaptureTarget ? t("shell.captureTarget", { name: session.name }) : t("shell.openCapture", { name: session.name })}
                  >
                    <span className={`session-status ${isCaptureTarget ? "is-live" : ""}`} />
                    {/* Collapsed, the row is 72px wide and the body is hidden;
                        without this the sessions are indistinguishable dots. */}
                    <span className="session-item__initial" aria-hidden="true">{sessionInitial(session.name)}</span>
                    <span className="session-item__body">
                      <span className="session-item__title"><strong>{session.name}</strong>{isCaptureTarget && <em>{t("shell.capturing")}</em>}</span>
                      <span className="session-item__meta">
                        <span>{formatSessionTime(session.createdAt, t, intlLocale)} · {t("shell.requestsMeta", { count: session.requestCount })}</span>
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
                  <button
                    className="session-delete-button"
                    onClick={(event) => {
                      event.stopPropagation();
                      void deleteSession(session);
                    }}
                    title={t("shell.deleteSession")}
                    aria-label={t("shell.deleteSession") + " " + session.name}
                    disabled={transferring}
                  >
                    <Trash2 size={12} />
                  </button>
                  <button
                    className="session-rename-button"
                    onClick={(event) => {
                      event.stopPropagation();
                      beginSessionRename(session);
                    }}
                    title={t("shell.renameSession")}
                    aria-label={t("shell.renameNamed", { name: session.name })}
                  >
                    <Pencil size={12} />
                  </button>
                </>
              )}
              {!editing && session.analysisReportCount > 0 && (
                <button
                  className={`session-report-shortcut ${session.id === activeSessionId && activeView === "analysis" ? "is-active" : ""}`}
                  onClick={() => {
                    setActiveSessionId(session.id);
                    setActiveView("analysis");
                  }}
                  title={`${t("shell.openReport")}${session.latestAnalysisUpdatedAt ? ` · ${formatSessionTime(new Date(session.latestAnalysisUpdatedAt).toISOString(), t, intlLocale)}` : ""}`}
                  aria-label={t("shell.openReportNamed", { name: session.name })}
                >
                  <Sparkles size={11} />
                  <span>{session.latestAnalysisStatus === "failed" ? t("common.failed") : t("shell.reports", { count: session.analysisReportCount })}</span>
                </button>
              )}
            </div>
            );
          })}
        </div>

        <div className="proxy-mini-status">
          <div className="proxy-mini-status__top">
            <span className={`live-dot ${capturing ? "is-on" : ""}`} />
            <strong><span className="proxy-mini-status__label">{t("shell.proxy")} :</span>{runtime.proxyPort}</strong>
            <span title={captureSession?.name}>{capturing ? t("shell.writing", { name: captureSession?.name ?? t("shell.sessions") }) : t("shell.paused")}</span>
          </div>
          <div className="proxy-mini-status__meta">
            <span>{runtime.caInstalled ? t("shell.caTrusted") : t("shell.caPending")}</span>
            <button onClick={() => navigate("settings")}>{t("common.manage")}</button>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar" data-tauri-drag-region>
          <div className="topbar__title">
            <span className="topbar__eyebrow">
              {activeView === "browser" && captureSession
                ? t("shell.browserWriting", { name: captureSession.name })
                : viewingCaptureSession ? t("shell.viewingLive", { name: activeSession.name }) : t("shell.viewing", { name: activeSession.name })}
            </span>
            <h1>{views[activeView].title}</h1>
          </div>
          <div className="topbar__actions">
            {capturing && captureSession && !viewingCaptureSession && (
              <button className="capture-context-button" onClick={() => { setActiveSessionId(captureSession.id); setActiveView("traffic"); }} title={t("shell.returnCapture", { name: captureSession.name })}>
                <Radio size={14} />
                <span><small>{t("shell.captureWrite")}</small><strong>{captureSession.name}</strong></span>
                <ChevronRight size={13} />
              </button>
            )}
            {!setupState.ready && (
              <button className="setup-pill" onClick={() => setSetupOpen(true)} title={t("shell.setupTitle")}>
                <Compass size={14} />
                <span>{t("shell.setupPill", { count: setupState.total - setupState.done })}</span>
              </button>
            )}
            {breakpointQueue.tasks.length > 0 && <button className="breakpoint-alert-button" onClick={openBreakpointConsole} title={t("shell.breakpoints", { count: breakpointQueue.tasks.length })}><Pause size={13} fill="currentColor" /><span>{t("shell.breakpoints", { count: breakpointQueue.tasks.length })}</span><strong>{t("common.pending")}</strong></button>}
            <button className="ai-service-entry" onClick={() => navigate("analysis")} title="ClaudeGPT.org · gpt-5.5">
              <Sparkles size={16} />
              <span className="ai-service-entry__desktop"><small>{t("shell.aiEntrySmall")}</small><strong>ClaudeGPT.org · gpt-5.5</strong></span>
              <span className="ai-service-entry__mobile"><strong>ClaudeGPT.org</strong><small>{t("shell.aiEntryMobile")}</small></span>
            </button>
            <button className="status-button" onClick={() => setConnectOpen(true)}>
              <span className="source-stack">
                <Browser size={14} />
                <Wifi size={14} />
                <Terminal size={14} />
              </span>
              <span>{t("shell.sourcesCount", { count: (captureSession ?? activeSession).sources.length })}</span>
              <ChevronDown size={14} />
            </button>
            <button className={`capture-button ${capturing ? "is-capturing" : ""}`} onClick={() => void toggleCapture()} disabled={captureTransitioning || !sessionCatalogReady} title={capturing && captureSession ? t("shell.stopCaptureNamed", { name: captureSession.name }) : t("shell.startCapture")}>
              {capturing ? <Square size={13} fill="currentColor" /> : <CircleDot size={15} />}
              <span>{!sessionCatalogReady ? t("shell.loadSession") : captureTransitioning ? t("common.processing") : capturing ? t("shell.stopCapture") : t("shell.startCapture")}</span>
            </button>
            <LocaleSwitcher onChange={applyUiLocale} />
          </div>
        </header>

        <main className="workspace__content">
          {/* Keep TrafficView mounted so leaving for Request Lab preserves the
              user's filters, sort, selection and inspector context. */}
          <div
            className={`workspace-view-keep-alive ${activeView === "traffic" ? "is-active" : "is-hidden"}`}
            hidden={activeView !== "traffic"}
            aria-hidden={activeView !== "traffic"}
          >
            <TrafficView
              key={activeSession.id}
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
              capturing={capturing && viewingCaptureSession}
              captureElsewhere={capturing && !viewingCaptureSession}
              captureSessionName={captureSession?.name}
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
          </div>
          {activeView === "lab" && (
            <RequestWorkbench
              key={workbenchLaunch?.id ?? `lab-${activeSession.id}`}
              breakpointCount={breakpointQueue.tasks.length}
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
          {activeView === "analysis" && <AnalysisView sessionId={activeSession.id} requests={requests} initialRequestIds={analysisRequestScope?.sessionId === activeSession.id ? analysisRequestScope.requestIds : undefined} scopeRequestId={analysisRequestScope?.sessionId === activeSession.id ? analysisRequestScope.id : undefined} onScopeConsumed={() => setAnalysisRequestScope(null)} onOpenEvidenceRequest={(requestId) => { setEvidenceRequestId(requestId); setActiveView("traffic"); }} onConfigureAi={() => { setSettingsTab("ai"); setActiveView("settings"); }} onNotify={setToast} autoRunId={analysisAutoRun?.sessionId === activeSession.id ? analysisAutoRun.id : undefined} onAutoRunConsumed={() => setAnalysisAutoRun(null)} mode={analysisMode} onModeChange={chooseAnalysisMode} modePinned={analysisModePinned} />}
          {/* Keep BrowserView mounted so switching nav tabs does not stop proxy Chrome / drop CDP state. */}
          <div
            className={`workspace-view-keep-alive ${activeView === "browser" ? "is-active" : "is-hidden"}`}
            hidden={activeView !== "browser"}
            aria-hidden={activeView !== "browser"}
          >
            <BrowserView
              active={activeView === "browser"}
              capturing={capturing}
              sessionId={browserSession.id}
              sessionName={browserSession.name}
              onAnalyzeCryptoLab={() => void analyzeCryptoLab(browserSession.id)}
            />
          </div>
          {activeView === "skills" && <SkillsView sessionId={activeSession.id} requests={requests} onOpenMcpSettings={() => openSettingsTab("mcp")} mode={analysisMode} onModeChange={chooseAnalysisMode} />}
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
          sessionId={browserSession.id}
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
      {commandOpen && <CommandPalette actions={commandActions} onClose={() => setCommandOpen(false)} />}
      {confirmDialog}
      {shortcutsOpen && <ShortcutsSheet onClose={() => setShortcutsOpen(false)} />}
      {aboutOpen && (
        <AboutDialog
          runtime={runtime}
          native={hasNativeRuntime}
          onClose={() => setAboutOpen(false)}
          onCopy={(value, label) => void copyConnectValue(value, label)}
          onOpenExternal={(url) => {
            void openExternalUrl(url).catch((error) => setToast(t("shell.openLinkFailed", { error: String(error) })));
          }}
        />
      )}
      {setupOpen && (
        <SetupGuide
          steps={setupSteps}
          progress={setupState}
          onRunStep={runSetupStep}
          onClose={() => setSetupOpen(false)}
          onDismissForever={dismissSetupForever}
        />
      )}
      {exportOpen && (
        <SessionExportDialog
          session={activeSession}
          busy={transferring}
          onClose={() => setExportOpen(false)}
          onExport={(format) => void exportSession(format)}
        />
      )}
      {toast && (() => {
        // The tick used to be unconditional, so every failure in the app —
        // "转发目标请求失败", "无法连接" — arrived wearing a success mark and the
        // user had to read the sentence to discover otherwise.
        const tone = toastTone(toast);
        return (
          <div className={`toast is-${tone}`} role={tone === "error" ? "alert" : "status"}>
            {tone === "error" ? <CircleAlert size={16} /> : tone === "success" ? <Check size={16} /> : <Info size={16} />}
            {toast}
          </div>
        );
      })()}
      {sessionDrop.status !== "idle" && (
        <div className={`session-drop-overlay is-${sessionDrop.status}`} role="status" aria-live="polite">
          <span><FileArchive size={26} /></span>
          <strong>{sessionDrop.status === "ready" ? t("shell.dropReady") : sessionDrop.status === "importing" ? t("shell.dropImporting") : sessionDrop.status === "blocked" ? t("shell.dropBlocked") : t("shell.dropUnsupported")}</strong>
          <small>{sessionDrop.path ? droppedFileName(sessionDrop.path) : t("shell.dropHint")}</small>
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
    { id: "har", name: "HAR 1.2", detail: t("export.har"), icon: FileArchive },
    { id: "postman", name: "Postman 2.1", detail: t("export.postman"), icon: FileJson },
    { id: "openapi", name: "OpenAPI 3.1", detail: t("export.openapi"), icon: FileJson },
  ];
  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <section className="export-dialog" role="dialog" aria-modal="true" aria-labelledby="session-export-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
        <header className="dialog-header">
          <div><span className="section-kicker">SESSION EXPORT</span><h2 id="session-export-dialog-title">{t("export.title")}</h2><p>{t("export.meta", { name: session.name, count: session.requestCount })}</p></div>
          <button className="icon-button" onClick={onClose} title={t("common.close")}><X size={18} /></button>
        </header>
        <div className="export-format-list">
          {formats.map((item) => {
            const Icon = item.icon;
            return <button key={item.id} className={format === item.id ? "is-active" : ""} onClick={() => setFormat(item.id)}><span><Icon size={18} /></span><div><strong>{item.name}</strong><small>{item.detail}</small></div>{format === item.id && <Check size={15} />}</button>;
          })}
        </div>
        <footer className="dialog-footer"><div><ShieldCheck size={15} /><span>{t("export.keep")}</span></div><span className="dialog-actions"><button className="secondary-button" onClick={onClose}>{t("common.cancel")}</button><button className="primary-button" disabled={busy} onClick={() => onExport(format)}><Download size={14} />{busy ? t("export.exporting") : t("export.choose")}</button></span></footer>
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
    { source: "browser", detail: t("connect.browserDetail"), status: runtime.proxyRunning ? "available" : "manual" },
    { source: "desktop", detail: runtime.systemProxyEnabled ? `系统代理 · 127.0.0.1:${runtime.proxyPort}` : `手动代理 · 127.0.0.1:${runtime.proxyPort}`, status: runtime.systemProxyActive ? "active" : "manual" },
    { source: "terminal", detail: t("connect.terminalDetail"), status: runtime.proxyRunning && runtime.activeSessionId === sessionId ? "active" : "available", activeLabel: t("connect.ready") },
    { source: "script", detail: t("connect.scriptDetail"), status: "manual" },
    {
      source: "mobile",
      detail: runtime.lanEnabled && lanEndpoint ? `Wi-Fi 代理 · ${lanEndpoint}` : t("connect.needLan"),
      status: runtime.lanEnabled && lanEndpoint ? (runtime.proxyRunning ? "active" : "available") : "manual",
      activeLabel: t("connect.listening"),
    },
    {
      source: "iot",
      detail: runtime.lanEnabled && lanEndpoint ? `网关代理 · ${lanEndpoint}` : t("connect.needLan"),
      status: runtime.lanEnabled && lanEndpoint ? (runtime.proxyRunning ? "active" : "available") : "manual",
      activeLabel: t("connect.listening"),
    },
    {
      source: "reverse",
      detail: reverseProxyStatus?.running ? `${reverseProxyStatus.targetUrl} · ${reverseProxyStatus.localUrl}` : t("connect.reverseDetail"),
      status: reverseProxyStatus?.running ? "active" : "available",
      activeLabel: t("connect.runningLabel"),
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
            <h2 id="connect-dialog-title">{diagnostics ? t("connect.diagnostics") : t("connect.title")}</h2>
          </div>
          <div className="connect-dialog__header-actions"><button className="secondary-button" onClick={() => diagnostics ? setDiagnostics(undefined) : void runDiagnostics()} disabled={diagnosing}><Activity className={diagnosing ? "spin" : ""} size={14} />{diagnostics ? t("connect.back") : diagnosing ? t("connect.running") : t("connect.run")}</button><button className="icon-button" onClick={onClose} title={t("common.close")}><X size={18} /></button></div>
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
                  {status === "active" ? (activeLabel || t("connect.active")) : status === "available" ? t("connect.available") : t("connect.configure")}
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
            <span>{selectedSource === "reverse" ? t("connect.caByReverse") : t("connect.caByShownet")}</span>
          </div>
          <button className="secondary-button" onClick={onSettings}>{t("connect.settings")}</button>
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

  // Depends on the saved values themselves, not on the status object. The
  // backend re-emits this status on unrelated events — stopping a capture, for
  // one — and a fresh object identity each time meant a user part-way through
  // typing a target URL had the field blanked out from under them by the
  // stored value, which for a first-time user is empty.
  const hasStatus = Boolean(status);
  const savedTargetUrl = status?.targetUrl ?? "";
  const savedLocalPort = status?.localPort ?? 0;
  const savedLanEnabled = status?.lanEnabled ?? false;
  const savedPreserveHost = status?.preserveHost ?? false;
  useEffect(() => {
    if (!hasStatus) return;
    setDraft({
      targetUrl: savedTargetUrl,
      localPort: savedLocalPort,
      lanEnabled: savedLanEnabled,
      preserveHost: savedPreserveHost,
    });
  }, [hasStatus, savedTargetUrl, savedLocalPort, savedLanEnabled, savedPreserveHost]);

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

const commandGroupIcons: Record<string, typeof Network> = {
  start: Compass,
  capture: Radio,
  session: FileArchive,
  navigate: Network,
  config: Settings,
};

function CommandPalette({
  actions,
  onClose,
}: {
  actions: CommandAction[];
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const groups = useMemo(
    () => groupCommands(filterCommands(actions, query), query.trim().length > 0),
    [actions, query],
  );
  const flattened = useMemo(() => flattenCommands(groups), [groups]);
  const listRef = useRef<HTMLDivElement>(null);

  // A new query invalidates the old cursor; land it on the first runnable row.
  useEffect(() => {
    const firstEnabled = flattened.findIndex((action) => !action.disabled);
    setActiveIndex(firstEnabled === -1 ? 0 : firstEnabled);
  }, [flattened]);

  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(".is-selected")?.scrollIntoView({ block: "nearest" });
  }, [activeIndex]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (!flattened.length) return;
        setActiveIndex((current) => moveCommandCursor(flattened, current, event.key === "ArrowDown" ? 1 : -1));
        return;
      }
      if (event.key !== "Enter") return;
      const action = flattened[activeIndex];
      if (!action || action.disabled) return;
      event.preventDefault();
      action.run();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [activeIndex, flattened]);

  let rowIndex = -1;
  return (
    <div className="modal-backdrop command-backdrop" onMouseDown={onClose}>
      <section className="command-palette" role="dialog" aria-modal="true" aria-label={t("shell.commandTitle")} onMouseDown={(event) => event.stopPropagation()}>
        <div className="command-search">
          <Search size={18} />
          <input
            autoFocus
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("shell.paletteSearch")}
            aria-label={t("shell.paletteSearchLabel")}
          />
          <kbd>ESC</kbd>
        </div>
        <div className="command-results" role="listbox" aria-label={t("shell.paletteResults")} ref={listRef}>
          {groups.map((group) => {
            const GroupIcon = commandGroupIcons[group.id] ?? Network;
            return (
              <div className="command-group" key={group.id} role="group" aria-label={group.label}>
                <span className="command-group-label"><GroupIcon size={12} />{group.label}</span>
                {group.actions.map((action) => {
                  rowIndex += 1;
                  const index = rowIndex;
                  return (
                    <button
                      key={action.id}
                      className={`command-row ${index === activeIndex ? "is-selected" : ""}`}
                      role="option"
                      aria-selected={index === activeIndex}
                      disabled={action.disabled}
                      title={action.disabled ? action.disabledReason : action.subtitle}
                      onClick={() => { if (!action.disabled) action.run(); }}
                    >
                      <span className="command-row__body">
                        <strong>{action.title}</strong>
                        <small>{action.disabled ? action.disabledReason ?? action.subtitle : action.subtitle}</small>
                      </span>
                      {action.badge && <em className={`command-row__badge is-${action.badgeTone ?? "neutral"}`}>{action.badge}</em>}
                      {action.shortcut && <kbd>{action.shortcut}</kbd>}
                    </button>
                  );
                })}
              </div>
            );
          })}
          {flattened.length === 0 && (
            <div className="command-empty">
              <FileSearch size={20} />
              <span>{t("shell.paletteEmpty")}</span>
            </div>
          )}
        </div>
        <div className="command-footer">
          <span><Zap size={13} /> ShowNet Command</span>
          <span>{t("shell.paletteHint")}</span>
        </div>
      </section>
    </div>
  );
}

export default App;
