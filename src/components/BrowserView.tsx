import {
  ArrowLeft,
  ArrowRight,
  Braces,
  Check,
  ChevronDown,
  Chrome,
  CircleAlert,
  CircleDot,
  Code2,
  Copy,
  Cookie,
  ExternalLink,
  Eye,
  EyeOff,
  FileUp,
  FlaskConical,
  Globe2,
  KeyRound,
  Lock,
  MoreHorizontal,
  MousePointer2,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  X,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { openUrl } from "@tauri-apps/plugin-opener";
import { CompositionEvent, FormEvent, KeyboardEvent, PointerEvent, WheelEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { cdpInsertTextPayload, shouldForwardRawKeyToCdp } from "../browserIme.ts";
import { buildCdpFileDragData, isShownetSessionPath, mapScreencastPoint } from "../browserDrag";
import { DEFAULT_BROWSER_URL, readStoredBrowserUrl, writeStoredBrowserUrl } from "../browserSessionUrl";
import { userAgentMetadataFor } from "../browserIdentity";
import {
  BROWSER_LANGUAGE_STORAGE_KEY,
  BROWSER_LANGUAGE_SUGGESTIONS,
  cloudflareChallengeHost,
  initialBrowserLanguage,
  normalizeBrowserLanguage,
} from "../browserLanguage";
import { t } from "../i18n.ts";
import { useDismissibleLayer } from "../useDismissibleLayer";
import { useConfirm } from "./ConfirmDialog";
import {
  browserInstallLab,
  browserReload,
  getProxyBrowserStatus,
  runWebRiskFixtureProbe,
  tryBrowserNavigate,
  type WebRiskFixtureProbeResult,
} from "../browserBus";
import { formatClock } from "../format";
import { trackNavigation } from "../reloadLoop";
import { DEFAULT_PAGE_HOOKS_ENABLED } from "../browserCompatibility";
import type { BrowserHookEvent, OutboundTlsProfileStatus, ProxyBrowserStatus } from "../types";

interface BrowserViewProps {
  /** When false the view stays mounted (keep-alive) but is not the active workspace. */
  active: boolean;
  capturing: boolean;
  /** The capture session that owns this browser, not the session selected for history viewing. */
  sessionId: string;
  sessionName: string;
  onAnalyzeCryptoLab: () => void;
}

const previewHookEvents: BrowserHookEvent[] = [];
/**
 * What `navigator.platform` should report — a different vocabulary from UA-CH.
 *
 * Passing the UA-CH name here set `navigator.platform = "macOS"`, a value no
 * real browser produces, and platform-vs-UA agreement is among the first things
 * a detection suite checks. That made the override more detectable than sending
 * no override at all.
 */
function navigatorPlatform(): string {
  const reported = navigator.platform;
  if (reported) return reported;
  const ua = navigator.userAgent;
  if (/Mac/i.test(ua)) return "MacIntel";
  if (/Win/i.test(ua)) return "Win32";
  return "Linux x86_64";
}

function isBrowserLabUrl(candidate: string | undefined, labUrl: string): boolean {
  if (!candidate || !labUrl) return false;
  try {
    const current = new URL(candidate);
    const lab = new URL(labUrl);
    return current.origin === lab.origin && current.pathname === lab.pathname;
  } catch {
    return false;
  }
}

const CDP_BINDING = "__SHOWNET_CDP_BINDING__";
const LAB_BINDING = "__SHOWNET_LAB_BINDING__";
/** Must match `browser.rs` SCREEN_WIDTH / SCREEN_HEIGHT and `--screen-info`. */
const BROWSER_SCREEN_WIDTH = 1920;
const BROWSER_SCREEN_HEIGHT = 1080;
const REMOTE_SELECTION_EXPRESSION = `(() => {
  const active = document.activeElement;
  if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
    const start = active.selectionStart ?? 0;
    const end = active.selectionEnd ?? start;
    return active.value.slice(start, end);
  }
  return globalThis.getSelection?.().toString() ?? "";
})()`;
const REMOTE_SELECT_ALL_EXPRESSION = `(() => {
  const active = document.activeElement;
  if (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement) {
    active.setSelectionRange(0, active.value.length);
    return true;
  }
  return document.execCommand("selectAll");
})()`;

interface ScreencastFrame {
  dataUrl: string;
  width: number;
  height: number;
}

type CdpResultHandler = (result: Record<string, unknown>, error?: { message?: string }) => void;
type CdpSend = (method: string, params?: Record<string, unknown>, onResult?: CdpResultHandler) => number;
type PageBridgeMode = "none" | "hooks" | "lab";
type LabStatusPayload = { phase?: string; status?: number; endpoint?: string; message?: string };
type BrowserFileDropState = { phase: "ready" | "delivered"; count: number } | null;

export function BrowserView({ active, capturing, sessionId, sessionName, onAnalyzeCryptoLab }: BrowserViewProps) {
  const { confirm, dialog: confirmDialog } = useConfirm();
  const [address, setAddress] = useState(() => readStoredBrowserUrl(sessionId) ?? DEFAULT_BROWSER_URL);
  const [currentUrl, setCurrentUrl] = useState(() => readStoredBrowserUrl(sessionId) ?? DEFAULT_BROWSER_URL);
  const [externalPage, setExternalPage] = useState<string | null>(null);
  const [hookPanel, setHookPanel] = useState(false);
  const [hookFilter, setHookFilter] = useState("all");
  const [hookQuery, setHookQuery] = useState("");
  const [hookEvents, setHookEvents] = useState<BrowserHookEvent[]>(previewHookEvents);
  const [receiverReady, setReceiverReady] = useState(false);
  const [proxyBrowser, setProxyBrowser] = useState<ProxyBrowserStatus | null>(null);
  const [browserConnecting, setBrowserConnecting] = useState(false);
  const [browserError, setBrowserError] = useState("");
  const [browserLoading, setBrowserLoading] = useState(false);
  const [pageTitle, setPageTitle] = useState(() => t("browser.newTab"));
  const [screencastFrame, setScreencastFrame] = useState<ScreencastFrame | null>(null);
  const [labState, setLabState] = useState<"idle" | "running" | "complete" | "error">("idle");
  const [fileDropState, setFileDropState] = useState<BrowserFileDropState>(null);
  const [pausedDisplay, setPausedDisplay] = useState(false);
  const [reloading, setReloading] = useState(false);
  const [labInstalling, setLabInstalling] = useState(false);
  const [fixtureProbing, setFixtureProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<WebRiskFixtureProbeResult | null>(null);
  const [probePanelOpen, setProbePanelOpen] = useState(false);
  const [probeJsonOpen, setProbeJsonOpen] = useState(false);
  const [browserMenuOpen, setBrowserMenuOpen] = useState(false);
  const [browserLanguage, setBrowserLanguage] = useState(() => initialBrowserLanguage(globalThis.localStorage));
  const [browserLanguageDraft, setBrowserLanguageDraft] = useState(() => initialBrowserLanguage(globalThis.localStorage));
  const [browserLanguageError, setBrowserLanguageError] = useState("");
  const [challengeHost, setChallengeHost] = useState("");
  const [selectedHookId, setSelectedHookId] = useState("");
  const [busNote, setBusNote] = useState("");
  const [reloadLoopHost, setReloadLoopHost] = useState("");
  const [hooksEnabled, setHooksEnabled] = useState(DEFAULT_PAGE_HOOKS_ENABLED);
  // Read inside the CDP attach, which is not re-created when the toggle flips.
  const hooksEnabledRef = useRef(DEFAULT_PAGE_HOOKS_ENABLED);
  const navigationLogRef = useRef<Array<{ url: string; at: number }>>([]);
  const iframeRef = useRef<HTMLIFrameElement | null>(null);
  const browserSurfaceRef = useRef<HTMLDivElement | null>(null);
  const screencastFrameRef = useRef<ScreencastFrame | null>(null);
  const imeInputRef = useRef<HTMLTextAreaElement | null>(null);
  const addressRef = useRef<HTMLInputElement | null>(null);
  const browserMenuRef = useRef<HTMLDivElement | null>(null);
  const cdpSocketRef = useRef<WebSocket | null>(null);
  const cdpSendRef = useRef<CdpSend | null>(null);
  const cdpPendingRef = useRef(new Map<number, CdpResultHandler>());
  const cdpConnectionGenerationRef = useRef(0);
  const pageBridgeScriptIdRef = useRef<string | null>(null);
  const pageBindingsInstalledRef = useRef(false);
  const pageBridgeGenerationRef = useRef(0);
  const pageBridgeQueueRef = useRef<Promise<void>>(Promise.resolve());
  const navigationGenerationRef = useRef(0);
  const cdpMessageId = useRef(0);
  const lastFrameAt = useRef(0);
  const analyzeAfterLab = useRef(false);
  const hookToggleInFlightRef = useRef(false);
  const composingRef = useRef(false);
  const skipCompositionInputRef = useRef(false);
  const suppressedCompositionKeys = useRef(new Set<string>());
  const activePointerRef = useRef<number | null>(null);
  const activePointerButtonRef = useRef<"left" | "middle" | "right">("left");
  const lastPointerPointRef = useRef<{ x: number; y: number } | null>(null);
  const nativeDropPathsRef = useRef<string[]>([]);
  const nativeDropPointRef = useRef<{ x: number; y: number } | null>(null);
  const nativeDropClearTimerRef = useRef(0);
  const challengeProbeTimerRef = useRef(0);
  const windowScaleFactorRef = useRef(window.devicePixelRatio || 1);
  const desktop = isTauri();

  useDismissibleLayer(browserMenuOpen, browserMenuRef, () => setBrowserMenuOpen(false));

  const requireMatchingBrowserOwner = (status: ProxyBrowserStatus) => {
    if (status.ownerSessionId !== sessionId) {
      throw new Error(`内嵌浏览器属于其他抓包会话，已拒绝连接`);
    }
    return status;
  };

  const confirmBrowserReset = (reason: string) => confirm({
    title: reason,
    detail: "Chrome 将以新的临时环境重启；当前登录状态、表单内容、页面历史和长连接会被清除。",
    confirmLabel: "重启并清除",
    tone: "danger",
  });

  const confirmHookModeChange = (next: boolean) => confirm({
    title: `${next ? "开启" : "关闭"}深度 JS Hook？`,
    detail: next
      ? "ShowNet 会在当前 Chrome 会话中启用深度分析，并改写部分页面 API。当前登录状态和 Cookie 会保留。"
      : "当前页面会刷新以恢复原生页面 API。Cookie、Storage、登录状态和页面历史会保留，但未提交的表单与页面内存状态会丢失。",
    confirmLabel: next ? "开启分析" : "关闭并刷新",
    tone: next ? "default" : "danger",
  });

  const confirmBrowserStop = () => confirm({
    title: "停止内嵌浏览器？",
    detail: "Chrome 将关闭；当前登录状态、表单内容、页面历史和长连接会被清除。",
    confirmLabel: "停止并清除",
    tone: "danger",
  });

  const sendCdpCommand = (
    send: CdpSend,
    method: string,
    params: Record<string, unknown> = {},
  ) => new Promise<Record<string, unknown>>((resolve, reject) => {
    const timeout = window.setTimeout(
      () => reject(new Error(`${method} 等待 Chrome 响应超时`)),
      3_000,
    );
    send(method, params, (result, error) => {
      window.clearTimeout(timeout);
      if (error) reject(new Error(error.message || `${method} 被 Chrome 拒绝`));
      else resolve(result);
    });
  });

  const configurePageBridge = (
    send: CdpSend,
    mode: PageBridgeMode,
    labUrl: string,
    options?: { installCurrent?: boolean; hookRuntime?: string },
  ) => {
    const apply = async () => {
    const generation = ++pageBridgeGenerationRef.current;
    const previousScriptId = pageBridgeScriptIdRef.current;
    if (previousScriptId) {
      await sendCdpCommand(send, "Page.removeScriptToEvaluateOnNewDocument", { identifier: previousScriptId });
      pageBridgeScriptIdRef.current = null;
    }
    if (mode === "none") {
      // The socket may have been replaced while the target kept its binding;
      // always remove both names on the native-page path instead of trusting a
      // frontend ref that only describes the previous CDP connection.
      await Promise.all([
        sendCdpCommand(send, "Runtime.removeBinding", { name: CDP_BINDING }),
        sendCdpCommand(send, "Runtime.removeBinding", { name: LAB_BINDING }),
      ]);
      pageBindingsInstalledRef.current = false;
      return;
    }

    if (!pageBindingsInstalledRef.current) {
      await Promise.all([
        sendCdpCommand(send, "Runtime.addBinding", { name: CDP_BINDING }),
        sendCdpCommand(send, "Runtime.addBinding", { name: LAB_BINDING }),
      ]);
      pageBindingsInstalledRef.current = true;
    }
    let labOrigin = "";
    let labPath = "";
    try {
      const parsedLabUrl = new URL(labUrl);
      labOrigin = parsedLabUrl.origin;
      labPath = parsedLabUrl.pathname;
    } catch {
      // `lab` mode is only selected for a validated local Lab URL. Keep the
      // source empty if a malformed status ever reaches this boundary.
    }
    const bridge = `Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", { configurable: true, value: (payload) => globalThis.${CDP_BINDING}(payload) });\nObject.defineProperty(globalThis, "__SHOWNET_LAB_BRIDGE__", { configurable: true, value: (payload) => globalThis.${LAB_BINDING}(payload) });`;
    const source = mode === "hooks"
      ? `${bridge}\n${options?.hookRuntime ?? ""}`
      : `if (location.origin === ${JSON.stringify(labOrigin)} && location.pathname === ${JSON.stringify(labPath)}) {\n${bridge}\n}`;
    const result = await sendCdpCommand(send, "Page.addScriptToEvaluateOnNewDocument", { source });
    const identifier = typeof result.identifier === "string" ? result.identifier : "";
    if (!identifier) throw new Error("Chrome 未返回页面脚本标识");
    // A mode switch may have superseded this command before Chrome returned
    // its identifier. Remove the stale script instead of leaving it active.
    if (pageBridgeGenerationRef.current !== generation) {
      await sendCdpCommand(send, "Page.removeScriptToEvaluateOnNewDocument", { identifier });
      return;
    }
    pageBridgeScriptIdRef.current = identifier;
    if (options?.installCurrent) {
      await sendCdpCommand(send, "Runtime.evaluate", {
        expression: source,
        awaitPromise: false,
        returnByValue: false,
      });
    }
    };
    const pending = pageBridgeQueueRef.current.catch(() => undefined).then(apply);
    pageBridgeQueueRef.current = pending;
    return pending;
  };

  useEffect(() => {
    const stored = readStoredBrowserUrl(sessionId);
    const nextUrl = stored ?? DEFAULT_BROWSER_URL;
    setAddress(nextUrl);
    setCurrentUrl(nextUrl);
    setExternalPage(null);
    setPageTitle(t("browser.newTab"));
    setChallengeHost("");
    setReloadLoopHost("");
    navigationGenerationRef.current += 1;
    hooksEnabledRef.current = DEFAULT_PAGE_HOOKS_ENABLED;
    setHooksEnabled(DEFAULT_PAGE_HOOKS_ENABLED);
    navigationLogRef.current = [];
  }, [sessionId]);

  const handleLabStatus = useCallback((payload: LabStatusPayload) => {
    if (payload.phase !== "running" && payload.phase !== "complete" && payload.phase !== "error") return;
    setLabState(payload.phase);
    if (payload.phase === "complete" && analyzeAfterLab.current) {
      analyzeAfterLab.current = false;
      onAnalyzeCryptoLab();
    } else if (payload.phase === "error") {
      analyzeAfterLab.current = false;
    }
  }, [onAnalyzeCryptoLab]);

  useEffect(() => {
    setReceiverReady(false);
    if (!desktop || !sessionId) {
      setHookEvents([]);
      setReceiverReady(true);
      return;
    }
    let disposed = false;
    let unlisten: UnlistenFn | undefined;
    invoke<BrowserHookEvent[]>("list_browser_hooks", { sessionId, limit: 500 })
      .then((events) => { if (!disposed) setHookEvents(events); })
      .finally(() => { if (!disposed) setReceiverReady(true); });
    listen<BrowserHookEvent>("browser://hook", (event) => {
      if (event.payload.sessionId !== sessionId || pausedDisplay) return;
      setHookEvents((current) => [event.payload, ...current.filter((item) => item.id !== event.payload.id)].slice(0, 500));
    }).then((dispose) => { unlisten = dispose; });
    return () => { disposed = true; void unlisten?.(); };
  }, [desktop, pausedDisplay, sessionId]);

  // True unmount only (app exit): stop Chrome. View switches keep this
  // component mounted, so this must have no dependencies at all — a dep would
  // let the cleanup fire mid-session and take the user's page down with it.
  const desktopRef = useRef(desktop);
  desktopRef.current = desktop;
  useEffect(() => () => {
    cdpConnectionGenerationRef.current += 1;
    window.clearTimeout(challengeProbeTimerRef.current);
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    pageBridgeGenerationRef.current += 1;
    pageBridgeScriptIdRef.current = null;
    pageBindingsInstalledRef.current = false;
    if (desktopRef.current) void invoke("stop_proxy_browser").catch(() => undefined);
  }, []);

  // The backend owns capture-stop teardown. Release only this UI's CDP state here;
  // sending a second async stop can arrive after a fast restart and kill the new browser.
  useEffect(() => {
    if (capturing || !proxyBrowser?.running) return;
    cdpConnectionGenerationRef.current += 1;
    window.clearTimeout(challengeProbeTimerRef.current);
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    pageBridgeGenerationRef.current += 1;
    pageBridgeScriptIdRef.current = null;
    pageBindingsInstalledRef.current = false;
    setProxyBrowser(null);
    screencastFrameRef.current = null;
    setScreencastFrame(null);
  }, [capturing, proxyBrowser?.running]);

  useEffect(() => {
    if (!active || !proxyBrowser?.running || !browserSurfaceRef.current) return;
    const surface = browserSurfaceRef.current;
    let resizeTimer = 0;
    const syncSize = () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => {
        // A hidden surface measures 0; clamping that to the minimum would
        // resize the real page instead of leaving it alone.
        if (!surface.clientWidth || !surface.clientHeight) return;
        const width = Math.max(320, Math.floor(surface.clientWidth));
        const height = Math.max(240, Math.floor(surface.clientHeight));
        // Viewport follows the ShowNet pane; screen stays a common desktop size
        // (matches browser.rs SCREEN_* / --screen-info). Feeding the small pane
        // into screenWidth/Height undoes that override and reintroduces the
        // 800x600-class automation tell Cloudflare-class detectors score.
        cdpSendRef.current?.("Emulation.setDeviceMetricsOverride", {
          width,
          height,
          deviceScaleFactor: 1,
          mobile: false,
          screenWidth: BROWSER_SCREEN_WIDTH,
          screenHeight: BROWSER_SCREEN_HEIGHT,
        });
      }, 80);
    };
    const observer = new ResizeObserver(syncSize);
    observer.observe(surface);
    syncSize();
    // Returning to the browser tab after keep-alive hide: re-assert screencast so frames resume.
    if (cdpSendRef.current) {
      cdpSendRef.current("Page.startScreencast", {
        format: "jpeg",
        quality: 78,
        maxWidth: 1800,
        maxHeight: 1200,
        everyNthFrame: 1,
      });
    }
    return () => {
      window.clearTimeout(resizeTimer);
      observer.disconnect();
    };
  }, [active, proxyBrowser?.running]);

  // Keep-alive: if Chrome is still running but CDP socket died, reattach when the tab is shown again.
  const cdpReattachInFlight = useRef(false);
  useEffect(() => {
    if (!active || !desktop || !capturing || browserConnecting) return;
    if (cdpSendRef.current || cdpReattachInFlight.current) return;
    let cancelled = false;
    cdpReattachInFlight.current = true;
    void (async () => {
      try {
        const status = await getProxyBrowserStatus().catch(() => null);
        if (cancelled || !status?.running || !status.webSocketDebuggerUrl) return;
        requireMatchingBrowserOwner(status);
        if (cdpSendRef.current) return;
        setProxyBrowser(status);
        setBusNote("正在重连 CDP…");
        await attachCdpSession(status, undefined, { navigate: false });
        if (!cancelled) setBusNote("CDP 已重连");
      } catch (error) {
        if (!cancelled) {
          setBrowserError(String(error));
          setBusNote("CDP 重连失败");
        }
      } finally {
        cdpReattachInFlight.current = false;
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [active, capturing, desktop, browserConnecting, proxyBrowser?.running]);

  useEffect(() => {
    const receiveHook = (message: MessageEvent) => {
      if (message.origin !== window.location.origin || message.source !== iframeRef.current?.contentWindow) return;
      const data = message.data as { type?: string; payload?: Record<string, unknown> } & LabStatusPayload;
      if (data.type === "shownet-lab-status") {
        handleLabStatus(data);
        return;
      }
      if (data.type !== "shownet-browser-hook" || !data.payload) return;
      const payload = { ...data.payload, sessionId, sourceInstanceId: "crypto-lab" };
      if (desktop) {
        void invoke<BrowserHookEvent>("record_browser_hook", { event: payload }).catch(() => undefined);
      } else if (!pausedDisplay) {
        const preview = payload as unknown as Omit<BrowserHookEvent, "id" | "sequence" | "correlation">;
        setHookEvents((current) => [{
          ...preview,
          id: `preview-hook-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          sequence: current.length + 1,
          correlation: "unmatched" as const,
        }, ...current].slice(0, 500));
      }
    };
    window.addEventListener("message", receiveHook);
    return () => window.removeEventListener("message", receiveHook);
  }, [desktop, handleLabStatus, pausedDisplay, sessionId]);

  /**
   * Clears the verdict *and* the evidence behind it. Dropping only the verdict
   * left the log full, so the very next navigation re-derived the same loop and
   * the notice reappeared — a dismiss button that did nothing.
   */
  const dismissReloadLoop = () => {
    navigationLogRef.current = [];
    setReloadLoopHost("");
  };

  const navigate = (event: FormEvent) => {
    event.preventDefault();
    let target = address.trim();
    if (!target) return;
    if (target !== DEFAULT_BROWSER_URL && !/^https?:\/\//i.test(target)) target = `https://${target}`;
    setAddress(target);
    setCurrentUrl(target);
    setExternalPage(target);
    // A deliberate navigation is the user's answer to the warning; give the
    // new destination a clean slate rather than carrying the old verdict over.
    dismissReloadLoop();
    if (!desktop) return;
    const navigationGeneration = ++navigationGenerationRef.current;
    setBrowserLoading(true);
    void (async () => {
      // Keep bridge configuration and navigation on the same CDP socket. The
      // Browser bus uses a separate connection, so it cannot provide ordering
      // against Page.addScriptToEvaluateOnNewDocument.
      if (proxyBrowser?.running) {
        const send = cdpSendRef.current;
        if (send) {
          try {
            await configureBridgeForNavigation(send, target, proxyBrowser.labUrl);
            if (navigationGenerationRef.current !== navigationGeneration) return;
            send("Page.navigate", { url: target });
            setBusNote("导航经 UI CDP（页面通道已配置）");
            return;
          } catch (error) {
            setBrowserError(`配置浏览器页面通道失败：${error instanceof Error ? error.message : String(error)}`);
            setBusNote("页面通道配置失败");
            return;
          }
        }
        const viaBus = await tryBrowserNavigate(target);
        if (viaBus) {
          setBusNote("导航经 Browser 总线（无页面桥接）");
          return;
        }
      }
      if (cdpSendRef.current) {
        cdpSendRef.current("Page.navigate", { url: target });
        setBusNote("导航经 UI CDP（总线不可用）");
      } else if (capturing) {
        // The socket is gone but the browser is still marked running, so the
        // toggle would stop it here instead of reviving it.
        void startProxyChrome(target);
      } else {
        setBrowserLoading(false);
        setBrowserError("请先开始抓包，再启动内嵌浏览器");
      }
    })();
  };

  const configureBridgeForNavigation = async (
    send: CdpSend,
    target: string,
    labUrl: string,
  ) => {
    const mode: PageBridgeMode = hooksEnabledRef.current
      ? "hooks"
      : isBrowserLabUrl(target, labUrl)
        ? "lab"
        : "none";
    const hookRuntime = mode === "hooks"
      ? await invoke<string>("get_browser_hook_script")
      : "";
    await configurePageBridge(send, mode, labUrl, { hookRuntime });
  };

  const navigateHistory = (offset: -1 | 1) => {
    const send = cdpSendRef.current;
    if (!send) return;
    send("Page.getNavigationHistory", {}, (result) => {
      const currentIndex = Number(result.currentIndex ?? -1);
      const entries = Array.isArray(result.entries) ? result.entries : [];
      const entry = entries[currentIndex + offset] as { id?: number; url?: string } | undefined;
      if (entry?.id == null) return;
      const target = typeof entry.url === "string" ? entry.url : currentUrl;
      const navigationGeneration = ++navigationGenerationRef.current;
      void (async () => {
        try {
          await configureBridgeForNavigation(send, target, proxyBrowser?.labUrl ?? "");
          if (navigationGenerationRef.current !== navigationGeneration) return;
          send("Page.navigateToHistoryEntry", { entryId: entry.id });
        } catch (error) {
          setBrowserError(`配置浏览器页面通道失败：${error instanceof Error ? error.message : String(error)}`);
          setBusNote("页面通道配置失败");
        }
      })();
    });
  };

  const reload = () => {
    setReloading(true);
    setBrowserLoading(true);
    // A refresh the user asked for is not the page refreshing itself. Without
    // this, four impatient clicks on a slow page accuse the site of a failed
    // bot-management challenge.
    dismissReloadLoop();
    void (async () => {
      if (proxyBrowser?.running && desktop) {
        try {
          await browserReload();
          setBusNote("刷新经 Browser 总线");
          window.setTimeout(() => setReloading(false), 650);
          return;
        } catch {
          // fall through to UI CDP
        }
      }
      if (cdpSendRef.current) cdpSendRef.current("Page.reload", { ignoreCache: false });
      else if (iframeRef.current) iframeRef.current.src = iframeRef.current.src;
      window.setTimeout(() => setReloading(false), 650);
    })();
  };

  const installRiskLab = async () => {
    if (!desktop || !proxyBrowser?.running || labInstalling) return;
    setLabInstalling(true);
    setBrowserError("");
    try {
      const result = await browserInstallLab(sessionId, "chrome-desktop-stable");
      if (!result.ok) {
        setBrowserError(result.error || "风控 Lab 注入失败");
        setBusNote("Lab 注入失败");
      } else {
        const dumpKeys = result.objectDump && typeof result.objectDump === "object"
          ? Object.keys(result.objectDump as object).length
          : 0;
        setBusNote(`Lab 已注入 · dump ${dumpKeys} 键`);
      }
    } catch (error) {
      setBrowserError(error instanceof Error ? error.message : String(error));
      setBusNote("Lab 注入异常");
    } finally {
      setLabInstalling(false);
    }
  };

  /** One-click: seed fixture → offline objectDump → vision dry-run; live install if browser up. */
  const runFixtureProbe = async () => {
    if (!desktop || fixtureProbing) return;
    setFixtureProbing(true);
    setBrowserError("");
    setProbeResult(null);
    setProbeJsonOpen(false);
    setProbePanelOpen(true);
    try {
      const result = await runWebRiskFixtureProbe({
        profileId: "chrome-desktop-stable",
        installLive: Boolean(proxyBrowser?.running),
      });
      setProbeResult(result);
      const keys = result.summary?.objectDumpKeys?.length ?? 0;
      const points = result.summary?.visionPointCount ?? 0;
      if (result.ok) {
        const livePart = result.summary?.liveOk
          ? " · 实页注入完成"
          : result.summary?.liveSkipped
            ? " · 离线完成"
            : " · 实页注入失败";
        setBusNote(`样本探针通过 · 导出 ${keys} 键 · 视觉点 ${points}${livePart}`);
      } else {
        setBrowserError("样本离线探针失败，见探针结果面板");
        setBusNote("样本探针失败");
      }
    } catch (error) {
      setProbeResult(null);
      setBrowserError(error instanceof Error ? error.message : String(error));
      setBusNote("样本探针异常");
    } finally {
      setFixtureProbing(false);
    }
  };

  const openCryptoLab = () => {
    analyzeAfterLab.current = true;
    setLabState("running");
    if (proxyBrowser?.labUrl && desktop) {
      const labUrl = proxyBrowser.labUrl;
      setAddress(labUrl);
      setCurrentUrl(labUrl);
      setBrowserLoading(true);
      void (async () => {
        if (proxyBrowser.running) {
          const send = cdpSendRef.current;
          if (send) {
            await configureBridgeForNavigation(send, labUrl, labUrl);
            send("Page.navigate", { url: labUrl });
            setBusNote("Crypto Lab 经 UI CDP（页面通道已配置）");
            return;
          }
          const viaBus = await tryBrowserNavigate(labUrl);
          if (viaBus) {
            setBusNote("Crypto Lab 经 Browser 总线（无页面桥接）");
            return;
          }
        }
        if (cdpSendRef.current) {
          cdpSendRef.current("Page.navigate", { url: labUrl });
          setBusNote("Crypto Lab 经 UI CDP");
        } else {
          // No CDP socket: this means start, not toggle.
          void startProxyChrome("__shownet_lab__");
        }
      })();
    } else if (desktop) {
      void startProxyChrome("__shownet_lab__");
    } else {
      const target = `${window.location.origin}/lab/index.html?autorun=1`;
      setAddress(target);
      setCurrentUrl(target);
      setExternalPage(target);
    }
  };

  async function attachCdpSession(
    status: ProxyBrowserStatus,
    destination?: string,
    options?: { navigate?: boolean },
  ) {
    const navigate = options?.navigate !== false;
    const connectionGeneration = ++cdpConnectionGenerationRef.current;
    const previousSocket = cdpSocketRef.current;
    if (previousSocket) previousSocket.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    const stored = readStoredBrowserUrl(sessionId);
    // Reattaches do not receive a destination from the caller. The stored URL
    // is enough to identify ShowNet's own Lab without putting a bridge into an
    // arbitrary third-party document.
    const navigateUrl =
      destination === "__shownet_lab__"
        ? status.labUrl
        : destination
          ? destination
          : (stored ?? DEFAULT_BROWSER_URL);
    const hooksForAttach = hooksEnabledRef.current;
    // The runtime rewrites fetch, XHR, document.cookie and SubtleCrypto. Keep it
    // out of the default capture path so authentication and device-risk pages
    // retain native browser semantics; users can enable it for deep JS analysis.
    const hookRuntime = hooksForAttach
      ? await invoke<string>("get_browser_hook_script")
      : "";
    await new Promise<void>((resolve, reject) => {
      const socket = new WebSocket(status.webSocketDebuggerUrl);
      if (cdpConnectionGenerationRef.current !== connectionGeneration) {
        socket.close();
        reject(new Error("CDP 连接已被新的连接取代"));
        return;
      }
      cdpSocketRef.current = socket;
      let opened = false;
      const isCurrentSocket = () =>
        cdpConnectionGenerationRef.current === connectionGeneration && cdpSocketRef.current === socket;
      socket.addEventListener("open", () => {
        if (!isCurrentSocket()) {
          socket.close();
          reject(new Error("CDP 连接已被新的连接取代"));
          return;
        }
        opened = true;
        const send: CdpSend = (method, params = {}, onResult) => {
          const id = ++cdpMessageId.current;
          if (!isCurrentSocket() || socket.readyState !== WebSocket.OPEN) return id;
          if (onResult) cdpPendingRef.current.set(id, onResult);
          try {
            socket.send(JSON.stringify({ id, method, params }));
          } catch (error) {
            setBrowserError(`CDP 发送失败：${error instanceof Error ? error.message : String(error)}`);
            setBusNote("CDP 发送失败");
          }
          return id;
        };
        cdpSendRef.current = send;
        send("Runtime.enable");
        send("Page.enable");
        // Network.enable is deliberately absent. It shipped in the first release
        // and nothing ever consumed it: the packet handler below dispatches only
        // Page.* and Runtime.bindingCalled, so every Network event was parsed and
        // dropped. Measured against one bing.com load it emits 246 events and
        // 464KB of JSON, and this socket is the same one Page.screencastFrame
        // rides, so that dead traffic competed with the live view. Enable it
        // again only alongside a handler that reads the events.
        // Resolved before the socket was opened, so this goes out ahead of the
        // Page.navigate below — Chrome runs commands in arrival order, and doing
        // it in a getVersion callback let the main document, the one request a
        // bot manager actually scores, leave announcing HeadlessChrome.
        if (status.honestUserAgent) {
          send("Emulation.setUserAgentOverride", {
            userAgent: status.honestUserAgent,
            // A versioned Chrome preset intentionally differs from the installed
            // binary, so default client hints would expose the installed major.
            // Keep navigator.userAgentData and request hints on the selected major.
            userAgentMetadata: userAgentMetadataFor(status),
            //
            // The UA string itself still needs overriding here because Chrome
            // exposes no way to read back the --user-agent launch flag, so this
            // stays as the per-target backstop. The flag is what actually covers
            // subresources and workers; this covers only the attached page.
            // Language is intentionally absent. The launch profile stores an
            // unweighted preference and Chrome generates the HTTP q-values. A
            // weighted CDP override made Chrome append a second `;q=0.9`.
            platform: navigatorPlatform(),
          });
        }
        const finishAttach = async (effectiveUrl: string) => {
          if (!isCurrentSocket()) return;
          const effectiveLab = isBrowserLabUrl(effectiveUrl, status.labUrl);
          await configurePageBridge(
            send,
            hooksForAttach ? "hooks" : effectiveLab ? "lab" : "none",
            status.labUrl,
            { installCurrent: !navigate, hookRuntime },
          );
          if (!navigate) {
            setAddress(effectiveUrl);
            setCurrentUrl(effectiveUrl);
            writeStoredBrowserUrl(sessionId, effectiveUrl);
          }
          send("Emulation.setFocusEmulationEnabled", { enabled: true });
          const surface = browserSurfaceRef.current;
          if (surface) {
            const width = Math.max(320, Math.floor(surface.clientWidth));
            const height = Math.max(240, Math.floor(surface.clientHeight));
            send("Emulation.setDeviceMetricsOverride", {
              width,
              height,
              deviceScaleFactor: 1,
              mobile: false,
              screenWidth: BROWSER_SCREEN_WIDTH,
              screenHeight: BROWSER_SCREEN_HEIGHT,
            });
          }
          send("Page.startScreencast", { format: "jpeg", quality: 78, maxWidth: 1800, maxHeight: 1200, everyNthFrame: 1 });
          if (navigate) {
            setAddress(navigateUrl);
            setCurrentUrl(navigateUrl);
            writeStoredBrowserUrl(sessionId, navigateUrl);
            setBrowserLoading(true);
            send("Page.navigate", { url: navigateUrl });
          }
          setProxyBrowser(status);
          setBrowserConnecting(false);
          resolve();
        };
        if (navigate) {
          void finishAttach(navigateUrl).catch(reject);
        } else {
          let settled = false;
          const fallback = window.setTimeout(() => {
            if (settled) return;
            settled = true;
            void finishAttach(navigateUrl).catch(reject);
          }, 1200);
          send("Runtime.evaluate", { expression: "location.href", returnByValue: true }, (result) => {
            if (settled) return;
            settled = true;
            window.clearTimeout(fallback);
            const value = (result.result as { value?: unknown } | undefined)?.value;
            void finishAttach(typeof value === "string" && value ? value : navigateUrl).catch(reject);
          });
        }
      });
      socket.addEventListener("message", (message) => {
        if (!isCurrentSocket()) return;
        let packet: { id?: number; method?: string; result?: Record<string, unknown>; params?: Record<string, unknown>; error?: { message?: string } };
        try { packet = JSON.parse(String(message.data)); } catch { return; }
        if (packet.id != null) {
          // A rejected command used to be indistinguishable from a successful
          // one returning nothing, so `Emulation.setUserAgentOverride` being
          // refused for a malformed payload left the browser announcing itself
          // as headless with nothing anywhere saying why.
          if (packet.error) {
            const detail = packet.error.message ?? "未知错误";
            setBusNote(`CDP 命令被拒绝：${detail}`);
          }
          const pending = cdpPendingRef.current.get(packet.id);
          if (pending) {
            cdpPendingRef.current.delete(packet.id);
            pending(packet.result ?? {}, packet.error);
          }
          return;
        }
        if (packet.method === "Page.screencastFrame") {
          const data = typeof packet.params?.data === "string" ? packet.params.data : "";
          const frameSessionId = Number(packet.params?.sessionId ?? 0);
          const metadata = (packet.params?.metadata ?? {}) as Record<string, unknown>;
          cdpSendRef.current?.("Page.screencastFrameAck", { sessionId: frameSessionId });
          const now = performance.now();
          if (data && now - lastFrameAt.current >= 32) {
            lastFrameAt.current = now;
            const frame = {
              dataUrl: `data:image/jpeg;base64,${data}`,
              width: Math.max(1, Number(metadata.deviceWidth ?? browserSurfaceRef.current?.clientWidth ?? 1)),
              height: Math.max(1, Number(metadata.deviceHeight ?? browserSurfaceRef.current?.clientHeight ?? 1)),
            };
            screencastFrameRef.current = frame;
            setScreencastFrame(frame);
          }
          return;
        }
        if (packet.method === "Page.frameStartedLoading") {
          setBrowserLoading(true);
          return;
        }
        if (packet.method === "Page.loadEventFired") {
          setBrowserLoading(false);
          setReloading(false);
          const send = cdpSendRef.current;
          send?.("Runtime.evaluate", { expression: "document.title", returnByValue: true }, (result) => {
            const value = (result.result as { value?: unknown } | undefined)?.value;
            if (typeof value === "string" && value.trim()) setPageTitle(value.trim());
          });
          window.clearTimeout(challengeProbeTimerRef.current);
          const inspectChallenge = (attempt: number) => {
            if (!isCurrentSocket()) return;
            send?.("Runtime.evaluate", {
              expression: `JSON.stringify({
                url: location.href,
                title: document.title,
                text: (document.body?.innerText || "").slice(0, 4000),
                cloudflareMarker: !!document.querySelector('script[src*="/cdn-cgi/challenge-platform/"], iframe[src*="challenges.cloudflare.com"], .cf-turnstile')
              })`,
              returnByValue: true,
            }, (result) => {
              const value = (result.result as { value?: unknown } | undefined)?.value;
              if (typeof value !== "string") return;
              try {
                const host = cloudflareChallengeHost(JSON.parse(value));
                setChallengeHost(host);
                if (!host && attempt < 3) {
                  challengeProbeTimerRef.current = window.setTimeout(() => inspectChallenge(attempt + 1), 900);
                }
              } catch {
                setChallengeHost("");
              }
            });
          };
          challengeProbeTimerRef.current = window.setTimeout(() => inspectChallenge(1), 700);
          return;
        }
        if (packet.method === "Page.frameNavigated") {
          const frame = packet.params?.frame as { url?: unknown; parentId?: unknown } | undefined;
          if (frame && !frame.parentId && typeof frame.url === "string") {
            setChallengeHost("");
            setAddress(frame.url);
            setCurrentUrl(frame.url);
            writeStoredBrowserUrl(sessionId, frame.url);
            const tracked = trackNavigation(navigationLogRef.current, frame.url, Date.now());
            navigationLogRef.current = tracked.log;
            setReloadLoopHost(tracked.loopHost);
            if (!hooksEnabledRef.current) {
              const send = cdpSendRef.current;
              if (send) void configureBridgeForNavigation(send, frame.url, status.labUrl);
            }
          }
          return;
        }
        if (packet.method !== "Runtime.bindingCalled" || typeof packet.params?.payload !== "string") return;
        if (packet.params.name === LAB_BINDING) {
          try { handleLabStatus(JSON.parse(packet.params.payload) as LabStatusPayload); } catch { handleLabStatus({ phase: "error", message: "Lab 状态数据无效" }); }
          return;
        }
        if (packet.params.name !== CDP_BINDING) return;
        try {
          const payload = JSON.parse(packet.params.payload) as Record<string, unknown>;
          if (payload.type === "shownet-lab-status") {
            handleLabStatus((payload.payload ?? {}) as LabStatusPayload);
            return;
          }
          void invoke<BrowserHookEvent>("record_browser_hook", {
            event: { ...payload, sessionId, sourceInstanceId: status.sourceInstanceId },
          }).then((stored) => {
            if (stored.kind !== "network") return;
            return invoke<BrowserHookEvent[]>("list_browser_hooks", { sessionId, limit: 500 })
              .then(setHookEvents);
          }).catch((error) => {
            setBrowserError(String(error));
            setBusNote("Hook 上报失败");
          });
        } catch {
          setBrowserError("CDP Hook 数据格式无效");
          setBusNote("CDP Hook 数据无效");
        }
      });
      socket.addEventListener("error", () => {
        if (!isCurrentSocket()) return;
        setBrowserError("无法连接 Chrome CDP");
        setBusNote("CDP 连接错误");
        setBrowserConnecting(false);
        if (!opened) reject(new Error("无法连接 Chrome CDP"));
      });
      socket.addEventListener("close", () => {
        if (!isCurrentSocket()) return;
        window.clearTimeout(challengeProbeTimerRef.current);
        cdpConnectionGenerationRef.current += 1;
        cdpSendRef.current = null;
        cdpSocketRef.current = null;
        cdpPendingRef.current.clear();
        pageBindingsInstalledRef.current = false;
        // Keep proxyBrowser running state so keep-alive can reattach; clear frames only.
        screencastFrameRef.current = null;
        setScreencastFrame(null);
        setBrowserLoading(false);
        setBrowserConnecting(false);
        setBusNote("CDP 已断开");
      });
    });
  }

  /** Toolbar toggle: stop when running, start otherwise. */
  async function launchProxyChrome(destination?: string) {
    if (!desktop || browserConnecting) return;
    if (proxyBrowser?.running) {
      if (!await confirmBrowserStop()) return;
      await stopProxyChrome();
      return;
    }
    await startProxyChrome(destination);
  }

  /** Tears the embedded browser down. Safe to call when it is not running. */
  async function stopProxyChrome() {
    window.clearTimeout(challengeProbeTimerRef.current);
    cdpConnectionGenerationRef.current += 1;
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    pageBridgeGenerationRef.current += 1;
    pageBridgeScriptIdRef.current = null;
    pageBindingsInstalledRef.current = false;
    await invoke("stop_proxy_browser", { expectedInstanceId: proxyBrowser?.sourceInstanceId ?? null });
    setProxyBrowser(null);
    screencastFrameRef.current = null;
    setScreencastFrame(null);
    setBrowserError("");
    setChallengeHost("");
    setBusNote("已停止内嵌浏览器");
  }

  /**
   * Starts the browser unconditionally.
   *
   * Split out from the toggle because a restart cannot be expressed as two
   * toggle calls: both close over the same render's `proxyBrowser`, so the
   * second one saw a still-running browser and stopped it again instead of
   * starting it — leaving the user on a dead surface, which is exactly the
   * bug the restart was meant to avoid.
   */
  async function startProxyChrome(
    destination?: string,
    options?: { browserLanguage?: string },
  ) {
    if (!desktop || browserConnecting) return;
    setBrowserConnecting(true);
    setBrowserError("");
    try {
      const status = await invoke<ProxyBrowserStatus>("launch_proxy_browser", {
        sessionId,
        browserLanguage: options?.browserLanguage ?? browserLanguage,
      });
      const busStatus = await getProxyBrowserStatus().catch(() => null);
      const resolved = requireMatchingBrowserOwner(busStatus?.running ? busStatus : status);
      setProxyBrowser(resolved);
      setBusNote(busStatus?.running ? "Browser 总线已就绪" : "Browser 已启动");
      await attachCdpSession(resolved, destination, { navigate: true });
    } catch (error) {
      if (destination === "__shownet_lab__") analyzeAfterLab.current = false;
      setBrowserError(String(error));
      setBusNote("浏览器启动失败");
      setBrowserConnecting(false);
    }
  }

  const framePoint = (clientX: number, clientY: number, clampToFrame = false) => {
    const surface = browserSurfaceRef.current;
    const frame = screencastFrameRef.current;
    if (!surface || !frame) return null;
    const bounds = surface.getBoundingClientRect();
    return mapScreencastPoint(clientX, clientY, bounds, frame, clampToFrame);
  };

  /** Keep page focus in CDP so clicks + keyboard land on the remote document (P5). */
  const ensureRemotePageFocus = () => {
    const send = cdpSendRef.current;
    if (!send) return;
    send("Emulation.setFocusEmulationEnabled", { enabled: true });
    send("Runtime.evaluate", {
      expression: `(() => { try { if (document.body && document.activeElement === document.body) return; document.body?.focus?.({ preventScroll: true }); } catch (_) {} })()`,
      returnByValue: true,
    });
  };

  const dispatchPointer = (type: "mousePressed" | "mouseMoved" | "mouseReleased", event: PointerEvent<HTMLDivElement>) => {
    const pointerActive = activePointerRef.current === event.pointerId || event.buttons !== 0;
    const point = framePoint(event.clientX, event.clientY, type === "mouseReleased" || pointerActive);
    if (!point || !cdpSendRef.current) return;
    lastPointerPointRef.current = point;
    event.preventDefault();
    if (type === "mousePressed") {
      // Focus remote document (CDP) + local IME capture surface for Chinese composition (P5).
      ensureRemotePageFocus();
      imeInputRef.current?.focus({ preventScroll: true });
      event.currentTarget.setPointerCapture(event.pointerId);
      activePointerRef.current = event.pointerId;
      activePointerButtonRef.current = event.button === 2 ? "right" : event.button === 1 ? "middle" : "left";
    }
    const button = type === "mouseMoved"
      ? pointerActive ? activePointerButtonRef.current : "none"
      : type === "mouseReleased"
        ? activePointerButtonRef.current
        : event.button === 2 ? "right" : event.button === 1 ? "middle" : "left";
    const pressedButtonMask = activePointerButtonRef.current === "right" ? 2 : activePointerButtonRef.current === "middle" ? 4 : 1;
    cdpSendRef.current("Input.dispatchMouseEvent", {
      type,
      x: point.x,
      y: point.y,
      button,
      buttons: type === "mouseReleased" ? 0 : event.buttons || (pointerActive || type === "mousePressed" ? pressedButtonMask : 0),
      clickCount: type === "mouseMoved" ? 0 : Math.max(1, event.detail || 1),
      modifiers: eventModifiers(event),
      pointerType: event.pointerType === "pen" ? "pen" : "mouse",
    });
    if (type === "mouseReleased") {
      activePointerRef.current = null;
      if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  useEffect(() => {
    if (!desktop) return;
    const releaseRemotePointer = (event?: globalThis.MouseEvent) => {
      if (activePointerRef.current == null) return;
      const point = event
        ? framePoint(event.clientX, event.clientY, true) ?? lastPointerPointRef.current
        : lastPointerPointRef.current;
      const send = cdpSendRef.current;
      activePointerRef.current = null;
      if (!send || !point) return;
      send("Input.dispatchMouseEvent", {
        type: "mouseReleased",
        ...point,
        button: activePointerButtonRef.current,
        buttons: 0,
        clickCount: 1,
        modifiers: event ? eventModifiers(event) : 0,
        pointerType: "mouse",
      });
    };
    const cancelRemotePointer = () => {
      releaseRemotePointer();
      cdpSendRef.current?.("Input.dispatchKeyEvent", {
        type: "rawKeyDown",
        key: "Escape",
        code: "Escape",
        windowsVirtualKeyCode: 27,
        nativeVirtualKeyCode: 27,
      });
      cdpSendRef.current?.("Input.dispatchKeyEvent", {
        type: "keyUp",
        key: "Escape",
        code: "Escape",
        windowsVirtualKeyCode: 27,
        nativeVirtualKeyCode: 27,
      });
    };
    window.addEventListener("pointerup", releaseRemotePointer);
    window.addEventListener("pointercancel", releaseRemotePointer);
    window.addEventListener("mouseup", releaseRemotePointer);
    window.addEventListener("blur", cancelRemotePointer);
    return () => {
      window.removeEventListener("pointerup", releaseRemotePointer);
      window.removeEventListener("pointercancel", releaseRemotePointer);
      window.removeEventListener("mouseup", releaseRemotePointer);
      window.removeEventListener("blur", cancelRemotePointer);
      cancelRemotePointer();
    };
  }, [desktop]);

  useEffect(() => {
    if (!desktop) return;
    let unlisten: UnlistenFn | undefined;
    let disposed = false;
    void getCurrentWindow().scaleFactor()
      .then((factor) => { if (Number.isFinite(factor) && factor > 0) windowScaleFactorRef.current = factor; })
      .catch(() => undefined);

    const clearNativeDrop = (cancelRemote: boolean) => {
      window.clearTimeout(nativeDropClearTimerRef.current);
      if (cancelRemote && nativeDropPointRef.current && cdpSendRef.current) {
        cdpSendRef.current("Input.dispatchDragEvent", {
          type: "dragCancel",
          ...nativeDropPointRef.current,
        });
      }
      nativeDropPathsRef.current = [];
      nativeDropPointRef.current = null;
      setFileDropState(null);
    };

    getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload;
      if (payload.type === "leave") {
        clearNativeDrop(true);
        return;
      }

      const logical = payload.position.toLogical(windowScaleFactorRef.current);
      const point = framePoint(logical.x, logical.y);
      if (payload.type === "enter" || payload.type === "drop") {
        if (payload.paths.some(isShownetSessionPath)) {
          clearNativeDrop(true);
          return;
        }
        nativeDropPathsRef.current = buildCdpFileDragData(payload.paths).files;
      }
      const paths = nativeDropPathsRef.current;
      if (!point || !cdpSendRef.current || paths.length === 0) {
        clearNativeDrop(true);
        return;
      }
      nativeDropPointRef.current = point;
      const data = buildCdpFileDragData(paths);
      if (payload.type === "enter") {
        cdpSendRef.current("Input.dispatchDragEvent", { type: "dragEnter", ...point, data });
        setFileDropState({ phase: "ready", count: paths.length });
      } else if (payload.type === "over") {
        cdpSendRef.current("Input.dispatchDragEvent", { type: "dragOver", ...point, data });
        setFileDropState({ phase: "ready", count: paths.length });
      } else {
        cdpSendRef.current("Input.dispatchDragEvent", { type: "dragOver", ...point, data });
        cdpSendRef.current("Input.dispatchDragEvent", { type: "drop", ...point, data });
        setFileDropState({ phase: "delivered", count: paths.length });
        nativeDropPathsRef.current = [];
        nativeDropPointRef.current = null;
        nativeDropClearTimerRef.current = window.setTimeout(() => setFileDropState(null), 1400);
      }
    }).then((dispose) => {
      if (disposed) dispose();
      else unlisten = dispose;
    }).catch((error) => setBrowserError(`文件投放不可用：${String(error)}`));
    return () => {
      disposed = true;
      window.clearTimeout(nativeDropClearTimerRef.current);
      void unlisten?.();
    };
  }, [desktop]);

  const dispatchWheel = (event: WheelEvent<HTMLDivElement>) => {
    const point = framePoint(event.clientX, event.clientY);
    if (!point || !cdpSendRef.current) return;
    event.preventDefault();
    cdpSendRef.current("Input.dispatchMouseEvent", {
      type: "mouseWheel",
      x: point.x,
      y: point.y,
      deltaX: event.deltaX,
      deltaY: event.deltaY,
      modifiers: eventModifiers(event),
    });
  };

  const readRemoteSelection = () => new Promise<string>((resolve) => {
    const send = cdpSendRef.current;
    if (!send) {
      resolve("");
      return;
    }
    let settled = false;
    const timer = window.setTimeout(() => {
      if (!settled) resolve("");
    }, 800);
    send("Runtime.evaluate", {
      expression: REMOTE_SELECTION_EXPRESSION,
      returnByValue: true,
      awaitPromise: false,
    }, (result) => {
      settled = true;
      window.clearTimeout(timer);
      const value = (result.result as { value?: unknown } | undefined)?.value;
      resolve(typeof value === "string" ? value : "");
    });
  });

  const handleClipboardShortcut = async (action: "copy" | "cut" | "paste") => {
    const send = cdpSendRef.current;
    if (!send) return;
    try {
      if (action === "paste") {
        const text = await readText();
        if (text) send("Input.insertText", { text });
        return;
      }
      const selection = await readRemoteSelection();
      if (selection) await writeText(selection);
      if (action === "cut") {
        send("Input.dispatchKeyEvent", {
          type: "rawKeyDown",
          key: "Backspace",
          code: "Backspace",
          windowsVirtualKeyCode: 8,
          nativeVirtualKeyCode: 8,
          modifiers: 0,
        });
        send("Input.dispatchKeyEvent", {
          type: "keyUp",
          key: "Backspace",
          code: "Backspace",
          windowsVirtualKeyCode: 8,
          nativeVirtualKeyCode: 8,
          modifiers: 0,
        });
      }
    } catch (error) {
      setBrowserError(`系统剪贴板不可用：${String(error)}`);
    }
  };

  const commitComposition = (event: CompositionEvent<HTMLTextAreaElement>) => {
    composingRef.current = false;
    const text = event.data;
    const payload = cdpInsertTextPayload(text);
    if (payload && cdpSendRef.current) cdpSendRef.current(payload.method, payload.params);
    skipCompositionInputRef.current = true;
    window.setTimeout(() => { skipCompositionInputRef.current = false; }, 0);
    event.currentTarget.value = "";
    imeInputRef.current?.focus({ preventScroll: true });
  };

  const dispatchKey = (type: "keyDown" | "keyUp", event: KeyboardEvent<HTMLDivElement>) => {
    if (!cdpSendRef.current) return;
    const composing = event.nativeEvent.isComposing || composingRef.current;
    const imeSurfaceFocused = event.target === imeInputRef.current;
    if (type === "keyDown" && composing) {
      suppressedCompositionKeys.current.add(event.code);
      event.stopPropagation();
      return;
    }
    if (type === "keyUp" && suppressedCompositionKeys.current.delete(event.code)) {
      event.stopPropagation();
      return;
    }
    const withCommand = event.metaKey || event.ctrlKey;
    const shortcut = event.key.toLowerCase();
    if (withCommand && (shortcut === "c" || shortcut === "x" || shortcut === "v")) {
      event.preventDefault();
      event.stopPropagation();
      if (type === "keyDown") {
        void handleClipboardShortcut(shortcut === "c" ? "copy" : shortcut === "x" ? "cut" : "paste");
      }
      return;
    }
    if (withCommand && shortcut === "a") {
      event.preventDefault();
      event.stopPropagation();
      if (type === "keyDown") {
        cdpSendRef.current("Runtime.evaluate", {
          expression: REMOTE_SELECT_ALL_EXPRESSION,
          returnByValue: true,
        });
      }
      return;
    }
    if (withCommand && shortcut === "z") {
      event.preventDefault();
      event.stopPropagation();
      if (type === "keyDown") {
        cdpSendRef.current("Runtime.evaluate", {
          expression: `document.execCommand(${JSON.stringify(event.shiftKey ? "redo" : "undo")})`,
          returnByValue: true,
        });
      }
      return;
    }
    if (withCommand && shortcut === "l") {
      event.preventDefault();
      event.stopPropagation();
      if (type === "keyDown") {
        addressRef.current?.focus();
        addressRef.current?.select();
      }
      return;
    }
    if (withCommand && shortcut === "r") {
      event.preventDefault();
      event.stopPropagation();
      if (type === "keyDown") reload();
      return;
    }
    if (!shouldForwardRawKeyToCdp({
      composing,
      key: event.key,
      metaKey: event.metaKey,
      ctrlKey: event.ctrlKey,
      imeSurfaceFocused,
    })) {
      event.stopPropagation();
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const text = type === "keyDown" && event.key.length === 1 && !event.metaKey && !event.ctrlKey ? event.key : undefined;
    cdpSendRef.current("Input.dispatchKeyEvent", {
      type: type === "keyDown" && !text ? "rawKeyDown" : type,
      key: event.key,
      code: event.code,
      text,
      unmodifiedText: text,
      windowsVirtualKeyCode: event.keyCode,
      nativeVirtualKeyCode: event.keyCode,
      autoRepeat: event.repeat,
      isKeypad: event.location === 3,
      modifiers: eventModifiers(event),
    });
  };

  useEffect(() => {
    if (!desktop) return;
    let unlisten: UnlistenFn | undefined;
    listen<string>("app://edit-command", (event) => {
      const surface = browserSurfaceRef.current;
      const active = document.activeElement;
      if (!surface || !active || !surface.contains(active)) return;
      if (event.payload === "copy" || event.payload === "cut" || event.payload === "paste") {
        void handleClipboardShortcut(event.payload);
      } else if (event.payload === "selectAll") {
        cdpSendRef.current?.("Runtime.evaluate", {
          expression: REMOTE_SELECT_ALL_EXPRESSION,
          returnByValue: true,
        });
      } else if (event.payload === "undo" || event.payload === "redo") {
        cdpSendRef.current?.("Runtime.evaluate", {
          expression: `document.execCommand(${JSON.stringify(event.payload)})`,
          returnByValue: true,
        });
      }
    }).then((dispose) => { unlisten = dispose; });
    return () => { void unlisten?.(); };
  }, [desktop]);

  const filteredHooks = useMemo(() => hookEvents.filter((event) => {
    if (hookFilter !== "all" && event.kind !== hookFilter) return false;
    const query = hookQuery.trim().toLowerCase();
    return !query || `${event.name} ${event.method ?? ""} ${event.url ?? ""}`.toLowerCase().includes(query);
  }), [hookEvents, hookFilter, hookQuery]);

  const applyBrowserLanguage = async (event: FormEvent) => {
    event.preventDefault();
    const normalized = normalizeBrowserLanguage(browserLanguageDraft);
    if (!normalized) {
      setBrowserLanguageError("请输入有效语言，例如 th-TH");
      return;
    }
    if (proxyBrowser?.running && !await confirmBrowserReset(`应用浏览器语言 ${normalized}？`)) return;
    setBrowserLanguage(normalized);
    setBrowserLanguageDraft(normalized);
    setBrowserLanguageError("");
    globalThis.localStorage?.setItem(BROWSER_LANGUAGE_STORAGE_KEY, normalized);
    setBrowserMenuOpen(false);
    if (!proxyBrowser?.running) {
      setBusNote(`浏览器语言已设为 ${normalized}`);
      return;
    }
    const destination = currentUrl;
    try {
      await stopProxyChrome();
      await startProxyChrome(destination, { browserLanguage: normalized });
    } catch (error) {
      setBrowserError(`应用浏览器语言失败：${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const retryCloudflareChallenge = async () => {
    const host = challengeHost;
    if (!host || browserConnecting) return;
    const previousHooksEnabled = hooksEnabledRef.current;
    // Keep MITM decryption. Outbound is always wreq Chrome when the stack is
    // linked (no rustls product path). Challenge retry only drops page Hooks
    // that rewrite SubtleCrypto / fetch (Turnstile-hostile), then reloads.
    setBusNote(`正在检查 ${host} 的 Chrome 出站状态`);
    try {
      const status = await invoke<OutboundTlsProfileStatus>("get_outbound_tls_profile");
      if (!status.realImpersonateStackAvailable || status.engine !== "impersonate") {
        setBrowserError(
          `当前构建未提供浏览器级出站（engine=${status.engine ?? "unknown"}）。请使用带 impersonate-boring 的正式包；产品路径已移除 rustls 出站回退。`,
        );
        return;
      }
      const send = cdpSendRef.current;
      if (!send) {
        setBrowserError("浏览器通道已断开，无法在保留登录状态的前提下关闭 Hook；请等待通道重连后重试");
        setBusNote("Hook 未切换：等待浏览器通道重连");
        return;
      }
      if (proxyBrowser?.running && !await confirmHookModeChange(false)) return;
      hooksEnabledRef.current = false;
      setHooksEnabled(false);
      setBusNote(`正在为 ${host} 关闭 Hook 后重试（MITM + Chrome 出站 JA4 保持）`);
      await configurePageBridge(send, "none", proxyBrowser?.labUrl ?? "");
      send("Page.reload", { ignoreCache: false });
      setBusNote(`${host}：Hook 已关 · 保留当前 Chrome 会话并刷新，请再完成真人验证`);
    } catch (error) {
      hooksEnabledRef.current = previousHooksEnabled;
      setHooksEnabled(previousHooksEnabled);
      setBrowserError(`验证兼容重试失败：${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const copyCurrentAddress = async () => {
    if (!currentUrl) return;
    if (desktop) await writeText(currentUrl);
    else await navigator.clipboard?.writeText(currentUrl);
    setBrowserMenuOpen(false);
    setBusNote("当前地址已复制");
  };

  const openInSystemBrowser = async () => {
    const target = currentUrl.trim();
    if (!target) {
      setBrowserError("当前没有可打开的地址");
      return;
    }
    try {
      if (desktop) {
        await openUrl(target);
      } else {
        // Preview / non-desktop: opener is unavailable; keep a best-effort fallback.
        window.open(target, "_blank", "noopener,noreferrer");
      }
      setBusNote("已在系统浏览器中打开");
    } catch (error) {
      setBrowserError(`无法在系统浏览器中打开：${error instanceof Error ? error.message : String(error)}`);
    }
  };

  const closeBrowserWorkspace = () => {
    setBrowserMenuOpen(false);
    if (desktop && proxyBrowser?.running) {
      void launchProxyChrome();
      return;
    }
    setExternalPage(null);
    setCurrentUrl("");
    setAddress("");
    setPageTitle(t("browser.newTab"));
  };

  const toggleHooks = async () => {
    const next = !hooksEnabled;
    if (hookToggleInFlightRef.current) return;
    if (proxyBrowser?.running && !await confirmHookModeChange(next)) return;
    hooksEnabledRef.current = next;
    setHooksEnabled(next);
    if (next) setHookPanel(true);
    if (!proxyBrowser?.running) return;
    const send = cdpSendRef.current;
    if (!send) {
      setBrowserError("浏览器通道尚未连接，请稍后重试");
      hooksEnabledRef.current = !next;
      setHooksEnabled(!next);
      return;
    }
    hookToggleInFlightRef.current = true;
    setBrowserConnecting(true);
    try {
      const hookRuntime = next ? await invoke<string>("get_browser_hook_script") : "";
      await configurePageBridge(send, next ? "hooks" : "none", proxyBrowser.labUrl, {
        installCurrent: next,
        hookRuntime,
      });
      if (!next) {
        // The old wrapper functions live in the current document realm. A
        // reload removes them while the same Chrome target keeps its profile.
        send("Page.reload", { ignoreCache: false });
        setBusNote("页面刷新中，恢复原生页面 API");
      } else {
        setBusNote("当前页面已启用深度 Hook；后续文档完整采集");
      }
    } catch (error) {
      setBrowserError(`切换深度 Hook 失败：${String(error)}`);
      hooksEnabledRef.current = !next;
      setHooksEnabled(!next);
    } finally {
      hookToggleInFlightRef.current = false;
      setBrowserConnecting(false);
    }
  };

  return (
    <section className={`browser-view ${probePanelOpen ? "has-probe" : hookPanel ? "has-hooks" : ""}`}>
      <div className="embedded-browser">
        <div className="browser-tabs">
          <div className="browser-tab is-active"><span className="target-favicon">{pageTitle.trim().charAt(0).toUpperCase() || "S"}</span><span>{pageTitle}</span></div>
          <div className="browser-tabs__spacer" />
          <span className="browser-owner" title={t("browser.writeTitle", { name: sessionName })}><CircleDot size={13} />{t("browser.writeTo", { name: sessionName })}</span>
          <span className={`cdp-state ${receiverReady ? "is-connected" : ""}`}><CircleDot size={13} />{t("browser.channel")} {receiverReady ? t("browser.ready") : t("browser.connecting")}</span>
          <div className="browser-menu-anchor" ref={browserMenuRef}>
            <button className={`icon-button ${browserMenuOpen ? "is-active" : ""}`} onClick={() => setBrowserMenuOpen((open) => !open)} title={t("browser.menu")} aria-expanded={browserMenuOpen}><MoreHorizontal size={17} /></button>
            {browserMenuOpen && <div className="browser-menu-popover" role="menu">
              <button role="menuitem" onClick={() => void copyCurrentAddress()} disabled={!currentUrl}><Copy size={14} />复制当前地址</button>
              <button role="menuitem" onClick={() => { setHookPanel((open) => !open); setProbePanelOpen(false); setBrowserMenuOpen(false); }}><Braces size={14} />{hookPanel && !probePanelOpen ? "收起 Hook 面板" : "打开 Hook 面板"}</button>
              <form className="browser-language-control" onSubmit={(event) => void applyBrowserLanguage(event)}>
                <label htmlFor="browser-language"><Globe2 size={14} />浏览器语言</label>
                <span>
                  <input
                    id="browser-language"
                    list="browser-language-suggestions"
                    value={browserLanguageDraft}
                    onChange={(event) => { setBrowserLanguageDraft(event.target.value); setBrowserLanguageError(""); }}
                    aria-invalid={Boolean(browserLanguageError)}
                    placeholder="th-TH"
                  />
                  <button type="submit" title="应用浏览器语言" aria-label="应用浏览器语言"><Check size={14} /></button>
                </span>
                {browserLanguageError && <small>{browserLanguageError}</small>}
                <datalist id="browser-language-suggestions">
                  {BROWSER_LANGUAGE_SUGGESTIONS.map((language) => <option key={language} value={language} />)}
                </datalist>
              </form>
              <button role="menuitem" onClick={closeBrowserWorkspace} disabled={!proxyBrowser?.running && !externalPage}><X size={14} />停止内嵌浏览器</button>
            </div>}
          </div>
        </div>
        <div className="browser-toolbar">
          <button className="icon-button" onClick={() => navigateHistory(-1)} disabled={!proxyBrowser?.running} title={t("browser.back")}><ArrowLeft size={17} /></button>
          <button className="icon-button" onClick={() => navigateHistory(1)} disabled={!proxyBrowser?.running} title={t("browser.forward")}><ArrowRight size={17} /></button>
          <button className="icon-button" onClick={reload} disabled={!proxyBrowser?.running && desktop} title={t("browser.reload")}><RefreshCw className={reloading ? "spin" : ""} size={16} /></button>
          <form className="address-bar" onSubmit={navigate}>
            <Lock size={13} />
            <input ref={addressRef} value={address} onChange={(event) => setAddress(event.target.value)} aria-label={t("browser.address")} />
            <ShieldCheck size={14} />
          </form>
          <button className="hook-toggle" onClick={openCryptoLab} disabled={!capturing || browserConnecting} title={t("browser.cryptoLabHint")}><FlaskConical size={16} /><span>{t("browser.cryptoLab")}</span></button>
          <button
            className={`hook-toggle ${labInstalling ? "is-active" : ""}`}
            onClick={() => void installRiskLab()}
            disabled={!proxyBrowser?.running || labInstalling || !capturing}
            title={t("browser.riskLabHint")}
          >
            <ShieldCheck size={16} />
            <span>{labInstalling ? t("common.processing") : t("browser.riskLab")}</span>
          </button>
          <button
            className={`hook-toggle ${fixtureProbing || probePanelOpen ? "is-active" : ""}`}
            onClick={() => void runFixtureProbe()}
            disabled={!desktop || fixtureProbing}
            title={t("browser.probeHint")}
          >
            <FlaskConical size={16} />
            <span>{fixtureProbing ? t("common.processing") : t("browser.probe")}</span>
          </button>
          <button className={`hook-toggle ${proxyBrowser?.running ? "is-active" : ""}`} onClick={() => void launchProxyChrome()} disabled={browserConnecting || !capturing} title={proxyBrowser?.running ? t("browser.stop") : t("browser.startEmbedded")}><Chrome size={16} /><span>{browserConnecting ? t("browser.connecting") : proxyBrowser?.running ? t("browser.stopShort") : "Chrome"}</span></button>
          <button
            className={`hook-toggle ${hooksEnabled ? "is-active" : ""}`}
            disabled={browserConnecting}
            onClick={() => void toggleHooks()}
            aria-pressed={hooksEnabled}
            title={hooksEnabled ? t("browser.deepOffHint") : t("browser.deepOnHint")}
          >
            <Code2 size={16} /><span>{hooksEnabled ? t("browser.deepOn") : t("browser.deepOff")}</span>
          </button>
          <button className={`hook-toggle ${hookPanel && !probePanelOpen ? "is-active" : ""}`} onClick={() => { if (probePanelOpen) { setProbePanelOpen(false); setHookPanel(true); } else { setHookPanel((open) => !open); } }} title={hooksEnabled ? t("browser.hookPanel") : t("browser.hookPanelOff")}><Braces size={16} /><span>{hooksEnabled ? hookEvents.length : 0}</span></button>
          <button className="icon-button" onClick={() => void openInSystemBrowser()} disabled={!currentUrl.trim()} title={t("browser.openSystem")} aria-label={t("browser.openSystem")}><ExternalLink size={16} /></button>
        </div>
        <div className="browser-viewport">
          {desktop ? (
            <div
              ref={browserSurfaceRef}
              className={`browser-screencast ${screencastFrame ? "is-live" : ""}`}
              tabIndex={0}
              aria-label="内嵌浏览器页面"
              onPointerDown={(event) => dispatchPointer("mousePressed", event)}
              onPointerMove={(event) => dispatchPointer("mouseMoved", event)}
              onPointerUp={(event) => dispatchPointer("mouseReleased", event)}
              onPointerCancel={(event) => dispatchPointer("mouseReleased", event)}
              onLostPointerCapture={(event) => {
                if (activePointerRef.current === event.pointerId) dispatchPointer("mouseReleased", event);
              }}
              onWheel={dispatchWheel}
              onKeyDownCapture={(event) => dispatchKey("keyDown", event)}
              onKeyUpCapture={(event) => dispatchKey("keyUp", event)}
              onContextMenu={(event) => event.preventDefault()}
            >
              <textarea
                ref={imeInputRef}
                className="browser-ime-input"
                aria-label="内嵌浏览器输入"
                autoCapitalize="off"
                autoComplete="off"
                spellCheck={false}
                onCompositionStart={() => { composingRef.current = true; }}
                onCompositionEnd={commitComposition}
                onInput={(event) => {
                  if (composingRef.current) return;
                  if (skipCompositionInputRef.current) {
                    skipCompositionInputRef.current = false;
                    event.currentTarget.value = "";
                    return;
                  }
                  const payload = cdpInsertTextPayload(event.currentTarget.value);
                  if (payload && cdpSendRef.current) cdpSendRef.current(payload.method, payload.params);
                  event.currentTarget.value = "";
                }}
              />
              {screencastFrame ? (
                <img src={screencastFrame.dataUrl} alt={pageTitle} draggable={false} />
              ) : (
                <div className="browser-launch-state">
                  <span><Chrome size={24} /></span>
                  <strong>{browserConnecting ? t("browser.connecting") : capturing ? t("browser.notStarted") : t("common.paused")}</strong>
                  {browserError && <small>{browserError}</small>}
                  <button type="button" onClick={() => void launchProxyChrome()} disabled={!capturing || browserConnecting}><Chrome size={15} />{t("browser.launch")}</button>
                </div>
              )}
              {browserLoading && proxyBrowser?.running && <div className="browser-loading-indicator"><RefreshCw className="spin" size={13} /></div>}
              {challengeHost ? (
                <div className="browser-reload-loop browser-challenge" role="alert">
                  <span><ShieldCheck size={18} /></span>
                  <div>
                    <strong>检测到 Cloudflare 真人验证</strong>
                    <small>
                      {challengeHost}：保持 HTTPS 解密抓包，确认正式包使用已验证的 Chrome 出站配置，并关闭页面 Hook
                      （Hook 会改写 SubtleCrypto/fetch，干扰 Turnstile）。不会临时绕过 TLS 拦截。
                    </small>
                  </div>
                  <button type="button" onClick={() => void retryCloudflareChallenge()} disabled={browserConnecting}>
                    关闭 Hook 并重试
                  </button>
                </div>
              ) : reloadLoopHost && (
                <div className="browser-reload-loop" role="alert">
                  <span><CircleAlert size={18} /></span>
                  <div>
                    <strong>{reloadLoopHost} 正在反复刷新</strong>
                    <small>
                      该站点的风控挑战没有通过。优先在高级控制台核对逐字节 Chrome 出站状态，
                      并关闭页面 Hook；不要用 TLS 绕行换验证通过，否则会丢解密正文。单次连接未实测时不会声称 JA4 已匹配。
                    </small>
                  </div>
                  <button type="button" onClick={dismissReloadLoop}>知道了</button>
                </div>
              )}
              {fileDropState && (
                <div className={`browser-file-drop is-${fileDropState.phase}`} aria-live="polite">
                  <span><FileUp size={20} /></span>
                  <div><strong>{fileDropState.phase === "delivered" ? "已投放至当前页面" : "网页文件投放"}</strong><small>{fileDropState.count} 个本地文件</small></div>
                </div>
              )}
            </div>
          ) : externalPage ? (
            <iframe ref={iframeRef} src={externalPage} title="ShowNet embedded browser" sandbox="allow-forms allow-scripts allow-same-origin" />
          ) : (
            <MockTargetPage />
          )}
          {capturing && proxyBrowser?.running && <div className="capture-corner"><span /><strong>REC</strong><small>{hooksEnabled ? `${hookEvents.length} hooks` : "原生页面"}</small></div>}
        </div>
        <div className="browser-statusbar">
          {hooksEnabled ? (
            <>
              <span>{hookEvents.length > 0 ? <Check size={13} /> : <CircleDot size={13} />}{hookEvents.length > 0 ? "页面 Hook 已连接" : "等待页面 Hook"}</span>
              <span><Braces size={13} />{hookEvents.length} 条事件</span>
            </>
          ) : (
            <span title={t("browser.nativeMitm")}><ShieldCheck size={13} />{t("browser.nativeMitm")}</span>
          )}
          <span><FlaskConical size={13} />{labState === "complete" ? "已转交内置 Agent" : labState === "error" ? "场景验证失败" : labState === "running" ? "加密场景运行中" : "Crypto Lab"}</span>
          <span title={browserError || undefined}><Chrome size={13} />{browserError ? "CDP 异常" : screencastFrame ? "内嵌画面实时" : proxyBrowser?.running ? "等待首帧" : t("browser.notStarted")}</span>
          <span title={t("browser.busShared")}><MousePointer2 size={13} />{proxyBrowser?.running ? (busNote || t("browser.busReady")) : busNote || t("browser.busOff")}</span>
          <span title={t("browser.sameLanguage")}><Globe2 size={13} />{proxyBrowser?.browserLanguage || browserLanguage}</span>
          {(reloadLoopHost || /baidu\.com|bdstatic\.com|bcebos\.com/i.test(currentUrl)) && (
            <span className="browser-statusbar__hint" title={reloadLoopHost ? "确认逐字节 Chrome 出站并关闭 Hook；图裂时才用静态 CDN 绕行" : "图裂时：设置 → HTTPS 解密 → 静态 CDN 绕行"}>
              {reloadLoopHost ? `${reloadLoopHost} 反复刷新：查 JA4/关 Hook` : "图裂时启用静态 CDN 绕行"}
            </span>
          )}
          <span className="browser-statusbar__right">100%</span>
        </div>
      </div>

      {probePanelOpen && (
        <aside className={`fixture-probe-panel ${probeResult?.ok ? "is-success" : probeResult ? "is-error" : "is-pending"}`} role="region" aria-label="样本探针结果">
            <header className="fixture-probe-panel__header">
              <div className="fixture-probe-panel__title">
                <span className="fixture-probe-panel__icon" aria-hidden><Sparkles size={15} /></span>
                <div>
                  <span className="section-kicker">网页风控实验室</span>
                  <h3>样本探针结果</h3>
                </div>
                {probeResult && (
                  <span className={`fixture-probe-badge ${probeResult.ok ? "is-ok" : "is-fail"}`}>
                    {probeResult.ok ? "离线通过" : "失败"}
                  </span>
                )}
              </div>
              <button className="icon-button" onClick={() => setProbePanelOpen(false)} title="关闭"><X size={16} /></button>
            </header>
            {fixtureProbing && !probeResult ? (
              <div className="fixture-probe-panel__empty">
                <RefreshCw className="spin" size={16} />
                <p>正在创建样本会话并运行离线对象导出…</p>
              </div>
            ) : probeResult ? (
              <div className="fixture-probe-panel__body">
                <ul className="fixture-probe-panel__stats">
                  <li>
                    <strong>样本会话</strong>
                    <span className="mono" title={probeResult.fixtureSessionId}>{probeResult.fixtureSessionId ?? "—"}</span>
                  </li>
                  <li>
                    <strong>环境配置</strong>
                    <span>{probeResult.profileId ?? "—"}</span>
                  </li>
                  <li>
                    <strong>对象导出</strong>
                    <span className="fixture-probe-stat-value">{probeResult.summary?.objectDumpKeys?.length ?? 0}<small> 键</small></span>
                  </li>
                  <li>
                    <strong>视觉试运行</strong>
                    <span className="fixture-probe-stat-value">
                      {probeResult.summary?.visionPointCount ?? 0}<small> 点</small>
                      <kbd>[{(probeResult.visionDryRun?.indices ?? []).join(", ")}]</kbd>
                    </span>
                  </li>
                  <li>
                    <strong>实页注入</strong>
                    <span>
                      {probeResult.liveInstall == null
                        ? "未请求"
                        : probeResult.liveInstall.skipped
                          ? "已跳过（浏览器未运行）"
                          : probeResult.liveInstall.ok
                            ? "成功"
                            : `失败：${probeResult.liveInstall.error ?? "未知错误"}`}
                    </span>
                  </li>
                </ul>
                {probeResult.summary?.objectDumpKeys && probeResult.summary.objectDumpKeys.length > 0 && (
                  <details className="fixture-probe-panel__details">
                    <summary>对象导出路径<span>{probeResult.summary.objectDumpKeys.length} 项</span></summary>
                    <div className="fixture-probe-panel__keys" aria-label="对象导出路径">
                      <div className="fixture-probe-chips">
                        {probeResult.summary.objectDumpKeys.map((key) => (
                          <span key={key} className="fixture-probe-chip" title={key}>{key}</span>
                        ))}
                      </div>
                    </div>
                  </details>
                )}
                <details
                  className="fixture-probe-panel__details"
                  open={probeJsonOpen}
                  onToggle={(event) => setProbeJsonOpen((event.target as HTMLDetailsElement).open)}
                >
                  <summary>技术摘要 JSON</summary>
                  <pre className="fixture-probe-panel__json">{JSON.stringify({
                    summary: probeResult.summary,
                    visionDryRun: probeResult.visionDryRun,
                    liveInstall: probeResult.liveInstall
                      ? {
                          ok: probeResult.liveInstall.ok,
                          skipped: probeResult.liveInstall.skipped,
                          error: probeResult.liveInstall.error,
                          note: probeResult.liveInstall.note,
                        }
                      : null,
                  }, null, 2)}</pre>
                </details>
              </div>
            ) : (
              <div className="fixture-probe-panel__empty"><p>尚无结果</p></div>
            )}
        </aside>
      )}

      {hookPanel && !probePanelOpen && (
        <aside className="hook-panel">
          <header className="hook-panel__header">
            <div><span className="section-kicker">LIVE EVENTS</span><h2>JS Hook</h2></div>
            <button className="icon-button" onClick={() => setHookPanel(false)} title="关闭"><X size={16} /></button>
          </header>
          {hooksEnabled ? (
            <>
              <div className="hook-panel__filters">
                <div className="search-field search-field--compact"><Search size={14} /><input value={hookQuery} onChange={(event) => setHookQuery(event.target.value)} placeholder="筛选调用" /></div>
                <label className="select-field select-field--compact"><select value={hookFilter} onChange={(event) => setHookFilter(event.target.value)}><option value="all">全部</option><option value="crypto">加密</option><option value="network">网络</option><option value="encoding">编码</option><option value="storage">存储</option><option value="interaction">交互</option></select><ChevronDown size={13} /></label>
              </div>
              <div className="hook-event-list">
                {filteredHooks.map((event) => (
                  <button key={event.id} className={`hook-event ${selectedHookId === event.id ? "is-selected" : ""}`} onClick={() => setSelectedHookId((current) => current === event.id ? "" : event.id)} aria-expanded={selectedHookId === event.id}>
                    <span className={`hook-event__mark tone-${hookTone(event.kind)}`}>{event.kind === "crypto" ? <KeyRound size={14} /> : event.kind === "storage" ? <Cookie size={14} /> : event.kind === "interaction" ? <MousePointer2 size={14} /> : <Code2 size={14} />}</span>
                    <span className="hook-event__content"><strong>{event.name}</strong><small>{hookDetail(event)}</small><em>{formatClock(event.timestamp, true)} · {event.correlation === "unmatched" ? "未关联请求" : "已关联"}</em>{selectedHookId === event.id && <span className="hook-event__details"><span><b>输入</b><code>{hookValuePreview(event.input)}</code></span><span><b>输出</b><code>{hookValuePreview(event.output)}</code></span>{event.durationMs != null && <span><b>耗时</b><code>{event.durationMs.toFixed(2)} ms</code></span>}</span>}</span>
                  </button>
                ))}
              </div>
              <footer className="hook-panel__footer"><span><span className={`live-dot ${pausedDisplay ? "" : "is-on"}`} />{pausedDisplay ? "显示已暂停" : "实时记录"}</span><button onClick={() => setPausedDisplay((paused) => !paused)}>{pausedDisplay ? <Eye size={14} /> : <EyeOff size={14} />}{pausedDisplay ? "继续显示" : "暂停显示"}</button></footer>
            </>
          ) : (
            <div className="hook-panel__disabled" role="status">
              <Code2 size={20} />
              <strong>深度分析未开启</strong>
              <small>当前页面保持原生 API，网络流量仍由 MITM 抓取。</small>
              <button type="button" onClick={() => void toggleHooks()} disabled={browserConnecting}><Code2 size={14} />开启深度分析</button>
            </div>
          )}
        </aside>
      )}
      {confirmDialog}
    </section>
  );
}

function eventModifiers(event: { altKey: boolean; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean }) {
  return (event.altKey ? 1 : 0)
    | (event.ctrlKey ? 2 : 0)
    | (event.metaKey ? 4 : 0)
    | (event.shiftKey ? 8 : 0);
}

function hookTone(kind: BrowserHookEvent["kind"]) {
  if (kind === "crypto" || kind === "encoding") return "purple";
  if (kind === "storage") return "amber";
  if (kind === "interaction") return "green";
  return "blue";
}

function hookDetail(event: BrowserHookEvent) {
  if (event.kind === "network") {
    const output = event.output as { status?: number } | null;
    let path = event.url ?? "";
    try { path = new URL(path).pathname; } catch {}
    return `${event.method ?? "GET"} ${path || "/"}${output?.status ? ` · ${output.status}` : ""}`;
  }
  if (event.durationMs != null) return `${event.kind} · ${event.durationMs} ms`;
  return event.kind;
}

function hookValuePreview(value: unknown) {
  let text: string;
  try {
    text = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    text = String(value);
  }
  if (!text) return "-";
  return text.length > 180 ? `${text.slice(0, 177)}...` : text;
}

function MockTargetPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [signedIn, setSignedIn] = useState(false);
  return (
    <div className="mock-target">
      <header className="mock-site-header"><div className="mock-logo">NOVA<span>+</span></div><nav><a>发现</a><a>新品</a><a>会员</a></nav><div className="mock-site-actions"><Search size={17} /><span className="mock-avatar">LC</span></div></header>
      <main className="mock-login">
        <section className="mock-login__visual">
          <span className="mock-visual-index">N / 08</span>
          <div className="mock-product">
            <div className="mock-lamp"><span /><i /></div>
            <div><small>OBJECT 019</small><strong>Air Lamp</strong><span>智能环境光</span></div>
          </div>
          <p>精确控制每一束光。</p>
        </section>
        <section className="mock-login__form">
          {!signedIn ? (
            <form onSubmit={(event) => { event.preventDefault(); setSignedIn(true); }}>
              <span className="mock-form-kicker">NOVA ID</span><h1>欢迎回来</h1>
              <label><span>手机号</span><input defaultValue="138 0013 5072" /></label>
              <label><span>密码</span><div><input type={showPassword ? "text" : "password"} defaultValue="shownet-demo" /><button type="button" onClick={() => setShowPassword((show) => !show)}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button></div></label>
              <button className="mock-submit" type="submit">登录<ArrowRight size={16} /></button>
              <div className="mock-form-meta"><label><input type="checkbox" defaultChecked />保持登录</label><a>忘记密码</a></div>
            </form>
          ) : (
            <div className="mock-success"><span><Check size={28} /></span><h1>登录成功</h1><p>NOVA ID 已完成验证</p><button onClick={() => setSignedIn(false)}>返回登录</button></div>
          )}
        </section>
      </main>
    </div>
  );
}
