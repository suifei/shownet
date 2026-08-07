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
import { buildCdpFileDragData, isShownetSessionPath, mapScreencastPoint } from "../browserDrag";
import { useDismissibleLayer } from "../useDismissibleLayer";
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
import type { BrowserHookEvent, ProxyBrowserStatus } from "../types";

interface BrowserViewProps {
  /** When false the view stays mounted (keep-alive) but is not the active workspace. */
  active: boolean;
  capturing: boolean;
  sessionId: string;
  onAnalyzeCryptoLab: () => void;
}

const previewHookEvents: BrowserHookEvent[] = [];
/** Chromium's UA-CH platform name — used for userAgentMetadata.platform only. */
function uaPlatform(): string {
  const platform = navigator.platform || "";
  if (/Mac/i.test(platform)) return "macOS";
  if (/Win/i.test(platform)) return "Windows";
  if (/Linux|X11/i.test(platform)) return "Linux";
  return "Windows";
}

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

/** CPU architecture as UA-CH reports it; Apple Silicon is "arm". */
function uaArchitecture(): string {
  return /arm|aarch64/i.test(navigator.userAgent) || /Mac/i.test(navigator.platform)
    ? "arm"
    : "x86";
}

/** A weighted Accept-Language list, the shape a real browser sends. */
function acceptLanguageHeader(): string {
  const primary = navigator.language || "en-US";
  const base = primary.split("-")[0];
  const parts = [primary];
  if (base && base !== primary) parts.push(`${base};q=0.9`);
  if (base !== "en") parts.push("en;q=0.8");
  return parts.join(",");
}

const CDP_BINDING = "__SHOWNET_CDP_BINDING__";
const LAB_BINDING = "__SHOWNET_LAB_BINDING__";
/** sessionStorage key for last navigated URL (P2 optional keep-alive restore). */
const LAST_URL_STORAGE_KEY = "shownet.browser.lastUrl";

function readStoredBrowserUrl(): string | null {
  try {
    const value = sessionStorage.getItem(LAST_URL_STORAGE_KEY)?.trim() ?? "";
    if (/^https?:\/\//i.test(value) && !/^chrome/i.test(value)) return value;
  } catch {
    /* private mode / SSR */
  }
  return null;
}

function writeStoredBrowserUrl(url: string) {
  try {
    if (/^https?:\/\//i.test(url) && !/^chrome/i.test(url)) {
      sessionStorage.setItem(LAST_URL_STORAGE_KEY, url);
    }
  } catch {
    /* ignore */
  }
}
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

type CdpResultHandler = (result: Record<string, unknown>) => void;
type CdpSend = (method: string, params?: Record<string, unknown>, onResult?: CdpResultHandler) => number;
type LabStatusPayload = { phase?: string; status?: number; endpoint?: string; message?: string };
type BrowserFileDropState = { phase: "ready" | "delivered"; count: number } | null;

export function BrowserView({ active, capturing, sessionId, onAnalyzeCryptoLab }: BrowserViewProps) {
  const [address, setAddress] = useState(() => readStoredBrowserUrl() ?? "https://example.com");
  const [currentUrl, setCurrentUrl] = useState(() => readStoredBrowserUrl() ?? "https://example.com");
  const [externalPage, setExternalPage] = useState<string | null>(null);
  const [hookPanel, setHookPanel] = useState(true);
  const [hookFilter, setHookFilter] = useState("all");
  const [hookQuery, setHookQuery] = useState("");
  const [hookEvents, setHookEvents] = useState<BrowserHookEvent[]>(previewHookEvents);
  const [receiverReady, setReceiverReady] = useState(false);
  const [proxyBrowser, setProxyBrowser] = useState<ProxyBrowserStatus | null>(null);
  const [browserConnecting, setBrowserConnecting] = useState(false);
  const [browserError, setBrowserError] = useState("");
  const [browserLoading, setBrowserLoading] = useState(false);
  const [pageTitle, setPageTitle] = useState("新标签页");
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
  const [selectedHookId, setSelectedHookId] = useState("");
  const [busNote, setBusNote] = useState("");
  const [reloadLoopHost, setReloadLoopHost] = useState("");
  const [hooksEnabled, setHooksEnabled] = useState(true);
  // Read inside the CDP attach, which is not re-created when the toggle flips.
  const hooksEnabledRef = useRef(true);
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
  const cdpMessageId = useRef(0);
  const lastFrameAt = useRef(0);
  const analyzeAfterLab = useRef(false);
  const composingRef = useRef(false);
  const skipCompositionInputRef = useRef(false);
  const suppressedCompositionKeys = useRef(new Set<string>());
  const activePointerRef = useRef<number | null>(null);
  const activePointerButtonRef = useRef<"left" | "middle" | "right">("left");
  const lastPointerPointRef = useRef<{ x: number; y: number } | null>(null);
  const nativeDropPathsRef = useRef<string[]>([]);
  const nativeDropPointRef = useRef<{ x: number; y: number } | null>(null);
  const nativeDropClearTimerRef = useRef(0);
  const windowScaleFactorRef = useRef(window.devicePixelRatio || 1);
  const desktop = isTauri();

  useDismissibleLayer(browserMenuOpen, browserMenuRef, () => setBrowserMenuOpen(false));

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
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    if (desktopRef.current) void invoke("stop_proxy_browser").catch(() => undefined);
  }, []);

  // Stop capture tears down the isolated proxy Chrome (documented default). Switching nav tabs does not.
  useEffect(() => {
    if (capturing || !proxyBrowser?.running) return;
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    setProxyBrowser(null);
    screencastFrameRef.current = null;
    setScreencastFrame(null);
    void invoke("stop_proxy_browser").catch((error) => setBrowserError(String(error)));
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
        cdpSendRef.current?.("Emulation.setDeviceMetricsOverride", {
          width,
          height,
          deviceScaleFactor: 1,
          mobile: false,
          screenWidth: width,
          screenHeight: height,
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
    if (!/^https?:\/\//i.test(target)) target = `https://${target}`;
    setAddress(target);
    setCurrentUrl(target);
    setExternalPage(target);
    // A deliberate navigation is the user's answer to the warning; give the
    // new destination a clean slate rather than carrying the old verdict over.
    dismissReloadLoop();
    if (!desktop) return;
    setBrowserLoading(true);
    void (async () => {
      // Prefer unified browser bus when the proxy browser is already running.
      if (proxyBrowser?.running) {
        const viaBus = await tryBrowserNavigate(target);
        if (viaBus) {
          setBusNote("导航经 Browser 总线");
          return;
        }
      }
      if (cdpSendRef.current) {
        cdpSendRef.current("Page.navigate", { url: target });
        setBusNote("导航经 UI CDP（总线不可用）");
      } else if (capturing) {
        void launchProxyChrome(target);
      } else {
        setBrowserLoading(false);
        setBrowserError("请先开始抓包，再启动内嵌浏览器");
      }
    })();
  };

  const navigateHistory = (offset: -1 | 1) => {
    cdpSendRef.current?.("Page.getNavigationHistory", {}, (result) => {
      const currentIndex = Number(result.currentIndex ?? -1);
      const entries = Array.isArray(result.entries) ? result.entries : [];
      const entry = entries[currentIndex + offset] as { id?: number } | undefined;
      if (entry?.id != null) cdpSendRef.current?.("Page.navigateToHistoryEntry", { entryId: entry.id });
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
          const viaBus = await tryBrowserNavigate(labUrl);
          if (viaBus) {
            setBusNote("Crypto Lab 经 Browser 总线");
            return;
          }
        }
        if (cdpSendRef.current) {
          cdpSendRef.current("Page.navigate", { url: labUrl });
          setBusNote("Crypto Lab 经 UI CDP");
        } else {
          void launchProxyChrome("__shownet_lab__");
        }
      })();
    } else if (desktop) {
      void launchProxyChrome("__shownet_lab__");
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
    // Skipped entirely when injection is off: the runtime rewrites fetch, XHR,
    // document.cookie and SubtleCrypto on every page, which is what makes the
    // analysis possible and also the most legible automation tell a site can
    // read. Turning it off costs the JS Hook feed and nothing else — traffic is
    // still captured at the proxy.
    const hookRuntime = hooksEnabledRef.current
      ? await invoke<string>("get_browser_hook_script")
      : "";
    await new Promise<void>((resolve, reject) => {
      const socket = new WebSocket(status.webSocketDebuggerUrl);
      cdpSocketRef.current = socket;
      let opened = false;
      socket.addEventListener("open", () => {
        opened = true;
        // The bridges are always installed; only the hook runtime is optional.
        // Bundling them meant turning hooks off also removed
        // __SHOWNET_LAB_BRIDGE__, so Crypto Lab could never report back and its
        // status sat at "running" forever.
        const bridgeSource = `Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", { configurable: true, value: (payload) => globalThis.${CDP_BINDING}(payload) });\nObject.defineProperty(globalThis, "__SHOWNET_LAB_BRIDGE__", { configurable: true, value: (payload) => globalThis.${LAB_BINDING}(payload) });\n${hookRuntime}`;
        const send: CdpSend = (method, params = {}, onResult) => {
          const id = ++cdpMessageId.current;
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
        send("Network.enable");
        // Resolved before the socket was opened, so this goes out ahead of the
        // Page.navigate below — Chrome runs commands in arrival order, and doing
        // it in a getVersion callback let the main document, the one request a
        // bot manager actually scores, leave announcing HeadlessChrome.
        if (status.honestUserAgent) {
          const version = /Chrome\/(\d+)/.exec(status.honestUserAgent)?.[1] ?? "";
          send("Emulation.setUserAgentOverride", {
            userAgent: status.honestUserAgent,
            // Without this the UA string says Chrome while Sec-CH-UA and
            // navigator.userAgentData still say HeadlessChrome. Two sources
            // disagreeing is a stronger signal than one honest headless UA, so
            // omitting it made the disguise worse than no disguise.
            userAgentMetadata: {
              brands: [
                { brand: "Not_A Brand", version: "24" },
                { brand: "Chromium", version },
                { brand: "Google Chrome", version },
              ],
              fullVersionList: [
                { brand: "Not_A Brand", version: "24.0.0.0" },
                { brand: "Chromium", version: `${version}.0.0.0` },
                { brand: "Google Chrome", version: `${version}.0.0.0` },
              ],
              platform: uaPlatform(),
              platformVersion: "",
              architecture: uaArchitecture(),
              model: "",
              mobile: false,
            },
            // A bare single token with no q-values is itself anomalous; real
            // Chrome always sends a weighted list.
            acceptLanguage: acceptLanguageHeader(),
            platform: navigatorPlatform(),
          });
        }
        send("Runtime.addBinding", { name: CDP_BINDING });
        send("Runtime.addBinding", { name: LAB_BINDING });
        send("Page.addScriptToEvaluateOnNewDocument", { source: bridgeSource });
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
            screenWidth: width,
            screenHeight: height,
          });
        }
        send("Page.startScreencast", { format: "jpeg", quality: 78, maxWidth: 1800, maxHeight: 1200, everyNthFrame: 1 });
        if (navigate) {
          const stored = readStoredBrowserUrl();
          // Explicit destination wins; lab override; else restore last URL; else lab home.
          const navigateUrl =
            destination === "__shownet_lab__"
              ? status.labUrl
              : destination
                ? destination
                : (stored ?? status.labUrl);
          setAddress(navigateUrl);
          setCurrentUrl(navigateUrl);
          writeStoredBrowserUrl(navigateUrl);
          setBrowserLoading(true);
          send("Page.navigate", { url: navigateUrl });
        }
        setProxyBrowser(status);
        setBrowserConnecting(false);
        resolve();
      });
      socket.addEventListener("message", (message) => {
        let packet: { id?: number; method?: string; result?: Record<string, unknown>; params?: Record<string, unknown> };
        try { packet = JSON.parse(String(message.data)); } catch { return; }
        if (packet.id != null) {
          const pending = cdpPendingRef.current.get(packet.id);
          if (pending) {
            cdpPendingRef.current.delete(packet.id);
            pending(packet.result ?? {});
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
          cdpSendRef.current?.("Runtime.evaluate", { expression: "document.title", returnByValue: true }, (result) => {
            const value = (result.result as { value?: unknown } | undefined)?.value;
            if (typeof value === "string" && value.trim()) setPageTitle(value.trim());
          });
          return;
        }
        if (packet.method === "Page.frameNavigated") {
          const frame = packet.params?.frame as { url?: unknown; parentId?: unknown } | undefined;
          if (frame && !frame.parentId && typeof frame.url === "string") {
            setAddress(frame.url);
            setCurrentUrl(frame.url);
            writeStoredBrowserUrl(frame.url);
            const tracked = trackNavigation(navigationLogRef.current, frame.url, Date.now());
            navigationLogRef.current = tracked.log;
            setReloadLoopHost(tracked.loopHost);
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
        setBrowserError("无法连接 Chrome CDP");
        setBusNote("CDP 连接错误");
        setBrowserConnecting(false);
        if (!opened) reject(new Error("无法连接 Chrome CDP"));
      });
      socket.addEventListener("close", () => {
        cdpSendRef.current = null;
        cdpSocketRef.current = null;
        cdpPendingRef.current.clear();
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
      await stopProxyChrome();
      return;
    }
    await startProxyChrome(destination);
  }

  /** Tears the embedded browser down. Safe to call when it is not running. */
  async function stopProxyChrome() {
    cdpSendRef.current?.("Page.stopScreencast");
    cdpSocketRef.current?.close();
    cdpSocketRef.current = null;
    cdpSendRef.current = null;
    cdpPendingRef.current.clear();
    await invoke("stop_proxy_browser");
    setProxyBrowser(null);
    screencastFrameRef.current = null;
    setScreencastFrame(null);
    setBrowserError("");
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
  async function startProxyChrome(destination?: string) {
    if (!desktop || browserConnecting) return;
    setBrowserConnecting(true);
    setBrowserError("");
    try {
      const status = await invoke<ProxyBrowserStatus>("launch_proxy_browser", { sessionId });
      const busStatus = await getProxyBrowserStatus().catch(() => null);
      const resolved = busStatus?.running ? busStatus : status;
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
      event.currentTarget.focus({ preventScroll: true });
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
    if (text && cdpSendRef.current) cdpSendRef.current("Input.insertText", { text });
    skipCompositionInputRef.current = true;
    window.setTimeout(() => { skipCompositionInputRef.current = false; }, 0);
    event.currentTarget.value = "";
  };

  const dispatchKey = (type: "keyDown" | "keyUp", event: KeyboardEvent<HTMLDivElement>) => {
    if (!cdpSendRef.current) return;
    if (type === "keyDown" && (event.nativeEvent.isComposing || composingRef.current)) {
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

  const closeCurrentPage = () => {
    setBrowserMenuOpen(false);
    if (desktop && proxyBrowser?.running) {
      void launchProxyChrome();
      return;
    }
    setExternalPage(null);
    setCurrentUrl("");
    setAddress("");
    setPageTitle("新标签页");
  };

  return (
    <section className={`browser-view ${probePanelOpen ? "has-probe" : hookPanel ? "has-hooks" : ""}`}>
      <div className="embedded-browser">
        <div className="browser-tabs">
          <div className="browser-tab is-active"><span className="target-favicon">{pageTitle.trim().charAt(0).toUpperCase() || "S"}</span><span>{pageTitle}</span><button type="button" onClick={closeCurrentPage} disabled={!proxyBrowser?.running && !externalPage} title="关闭当前页面" aria-label="关闭当前页面"><X size={13} /></button></div>
          <div className="browser-tabs__spacer" />
          <span className={`cdp-state ${receiverReady ? "is-connected" : ""}`}><CircleDot size={13} />Hook 接收器 {receiverReady ? "已就绪" : "连接中"}</span>
          <div className="browser-menu-anchor" ref={browserMenuRef}>
            <button className={`icon-button ${browserMenuOpen ? "is-active" : ""}`} onClick={() => setBrowserMenuOpen((open) => !open)} title="浏览器菜单" aria-expanded={browserMenuOpen}><MoreHorizontal size={17} /></button>
            {browserMenuOpen && <div className="browser-menu-popover" role="menu">
              <button role="menuitem" onClick={() => void copyCurrentAddress()} disabled={!currentUrl}><Copy size={14} />复制当前地址</button>
              <button role="menuitem" onClick={() => { setHookPanel((open) => !open); setProbePanelOpen(false); setBrowserMenuOpen(false); }}><Braces size={14} />{hookPanel && !probePanelOpen ? "收起 Hook 面板" : "打开 Hook 面板"}</button>
              <button role="menuitem" onClick={closeCurrentPage} disabled={!proxyBrowser?.running && !externalPage}><X size={14} />关闭当前页面</button>
            </div>}
          </div>
        </div>
        <div className="browser-toolbar">
          <button className="icon-button" onClick={() => navigateHistory(-1)} disabled={!proxyBrowser?.running} title="后退"><ArrowLeft size={17} /></button>
          <button className="icon-button" onClick={() => navigateHistory(1)} disabled={!proxyBrowser?.running} title="前进"><ArrowRight size={17} /></button>
          <button className="icon-button" onClick={reload} disabled={!proxyBrowser?.running && desktop} title="刷新"><RefreshCw className={reloading ? "spin" : ""} size={16} /></button>
          <form className="address-bar" onSubmit={navigate}>
            <Lock size={13} />
            <input ref={addressRef} value={address} onChange={(event) => setAddress(event.target.value)} aria-label="地址" />
            <ShieldCheck size={14} />
          </form>
          <button className="hook-toggle" onClick={openCryptoLab} disabled={!capturing || browserConnecting} title="运行 Crypto Lab 并自动分析"><FlaskConical size={16} /><span>验证分析</span></button>
          <button
            className={`hook-toggle ${labInstalling ? "is-active" : ""}`}
            onClick={() => void installRiskLab()}
            disabled={!proxyBrowser?.running || labInstalling || !capturing}
            title="经统一 Browser 总线注入固定参数 + 请求劫持 + 对象自吐"
          >
            <ShieldCheck size={16} />
            <span>{labInstalling ? "注入中" : "风控 Lab"}</span>
          </button>
          <button
            className={`hook-toggle ${fixtureProbing || probePanelOpen ? "is-active" : ""}`}
            onClick={() => void runFixtureProbe()}
            disabled={!desktop || fixtureProbing}
            title="一键：创建样本会话 → 离线对象导出 → 视觉试运行映射；浏览器运行时同步执行实页注入"
          >
            <FlaskConical size={16} />
            <span>{fixtureProbing ? "探针中" : "样本探针"}</span>
          </button>
          <button className={`hook-toggle ${proxyBrowser?.running ? "is-active" : ""}`} onClick={() => void launchProxyChrome()} disabled={browserConnecting || !capturing} title={proxyBrowser?.running ? "停止内嵌浏览器" : "启动内嵌浏览器"}><Chrome size={16} /><span>{browserConnecting ? "连接中" : proxyBrowser?.running ? "CDP" : "Chrome"}</span></button>
          <button
            className={`hook-toggle ${hooksEnabled ? "is-active" : ""}`}
            onClick={() => {
              const next = !hooksEnabled;
              hooksEnabledRef.current = next;
              setHooksEnabled(next);
              // addScriptToEvaluateOnNewDocument is registered at document
              // creation, so the choice only reaches a fresh browser.
              // launchProxyChrome is a toggle — calling it once on a running
              // browser only stopped it and dropped the user on a dead surface.
              if (proxyBrowser?.running) {
                const destination = currentUrl;
                void (async () => {
                  await stopProxyChrome();
                  await startProxyChrome(destination);
                })();
              }
            }}
            title={hooksEnabled ? "关闭 JS Hook 注入（风控站点可先关掉验证；流量仍在代理侧抓取）" : "开启 JS Hook 注入"}
          >
            <Code2 size={16} /><span>{hooksEnabled ? "Hook 开" : "Hook 关"}</span>
          </button>
          <button className={`hook-toggle ${hookPanel && !probePanelOpen ? "is-active" : ""}`} onClick={() => { if (probePanelOpen) { setProbePanelOpen(false); setHookPanel(true); } else { setHookPanel((open) => !open); } }} title="脚本 Hook 面板"><Braces size={16} /><span>{hookEvents.length}</span></button>
          <button className="icon-button" onClick={() => void openInSystemBrowser()} disabled={!currentUrl.trim()} title="在系统浏览器中打开" aria-label="在系统浏览器中打开"><ExternalLink size={16} /></button>
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
                  const text = event.currentTarget.value;
                  if (text && cdpSendRef.current) cdpSendRef.current("Input.insertText", { text });
                  event.currentTarget.value = "";
                }}
              />
              {screencastFrame ? (
                <img src={screencastFrame.dataUrl} alt={pageTitle} draggable={false} />
              ) : (
                <div className="browser-launch-state">
                  <span><Chrome size={24} /></span>
                  <strong>{browserConnecting ? "正在连接" : capturing ? "浏览器未启动" : "抓包已暂停"}</strong>
                  {browserError && <small>{browserError}</small>}
                  <button type="button" onClick={() => void launchProxyChrome()} disabled={!capturing || browserConnecting}><Chrome size={15} />启动浏览器</button>
                </div>
              )}
              {browserLoading && proxyBrowser?.running && <div className="browser-loading-indicator"><RefreshCw className="spin" size={13} /></div>}
              {reloadLoopHost && (
                <div className="browser-reload-loop" role="alert">
                  <span><CircleAlert size={18} /></span>
                  <div>
                    <strong>{reloadLoopHost} 正在反复刷新</strong>
                    <small>该站点的风控挑战没有通过。多数情况是 MITM 解密改变了 TLS 指纹：在「设置 → HTTPS 解密」把该域名加入绕行清单后重试，绕行域名仍会被抓包，只是不再解密正文。</small>
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
          {capturing && proxyBrowser?.running && <div className="capture-corner"><span /><strong>REC</strong><small>{hookEvents.length} hooks</small></div>}
        </div>
        <div className="browser-statusbar">
          <span>{hookEvents.length > 0 ? <Check size={13} /> : <CircleDot size={13} />}{hookEvents.length > 0 ? "页面 Hook 已连接" : "等待页面 Hook"}</span>
          <span><Braces size={13} />{hookEvents.length} 条事件</span>
          <span><FlaskConical size={13} />{labState === "complete" ? "已转交内置 Agent" : labState === "error" ? "场景验证失败" : labState === "running" ? "加密场景运行中" : "Crypto Lab"}</span>
          <span title={browserError || undefined}><Chrome size={13} />{browserError ? "CDP 异常" : screencastFrame ? "内嵌画面实时" : proxyBrowser?.running ? "等待首帧" : "浏览器未启动"}</span>
          <span title="统一 Browser 执行总线（Agent/UI 共用）"><MousePointer2 size={13} />{proxyBrowser?.running ? (busNote || "总线就绪") : busNote || "总线未连接"}</span>
          {(reloadLoopHost || /baidu\.com|bdstatic\.com|bcebos\.com/i.test(currentUrl)) && (
            <span className="browser-statusbar__hint" title="若页面反复刷新或图裂：设置 → HTTPS 解密 → 为该域名启用绕行">
              {reloadLoopHost ? `${reloadLoopHost} 反复刷新，试试解密绕行` : "图裂时启用静态 CDN 绕行"}
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
        </aside>
      )}
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
