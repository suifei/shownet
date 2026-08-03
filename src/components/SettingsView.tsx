import {
  Bot,
  Braces,
  Check,
  ChevronDown,
  CircleAlert,
  Code2,
  Copy,
  Database,
  Download,
  Eye,
  EyeOff,
  ExternalLink,
  FolderOpen,
  Globe2,
  HardDrive,
  KeyRound,
  ListFilter,
  LockKeyhole,
  MessageCircle,
  Network,
  PlugZap,
  Plus,
  QrCode,
  RadioTower,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  ShieldOff,
  Smartphone,
  Sparkles,
  SquareTerminal,
  Trash2,
  Wifi,
  X,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { save } from "@tauri-apps/plugin-dialog";
import { QRCodeCanvas } from "qrcode.react";
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { AiAnalysisSettings, CaptureListenerSettings, ClientAccessMode, DataStorageSettings, McpClientSettings, McpClientTestResult, McpServerStatus, OutboundTlsProfileStatus, ReverseProxyStatus, RuntimeStatus, StorageStats, SystemProxySettings, TlsInterceptionMode, TlsInterceptionSettings, UpdateCheckResult, UpstreamProxyMode, UpstreamProxySettings } from "../types";
import { clientAccessModeLabel, parseClientAccessRules, validateClientAccessSettings } from "../clientAccess";
import { buildMcpClientGuide, MCP_GUIDE_CLIENTS, type McpGuideClientId } from "../mcpClientGuide";
import qqGroupQr from "../assets/qq-group-fridare.jpg";
import { useEscapeDismiss } from "../useDismissibleLayer";

export type SettingsTab = "capture" | "ai" | "data" | "mcp";
type AiProvider = "claudegpt" | "compatible" | "local";
type ModelDiscoveryStatus = "idle" | "loading" | "ready" | "fallback";

interface McpClientDraft {
  id?: string;
  name: string;
  endpoint: string;
  enabled: boolean;
  accessToken: string;
  clearAccessToken: boolean;
}

const DEFAULT_AI_MODEL = "gpt-5.5";
const emptyMcpClientDraft: McpClientDraft = {
  name: "",
  endpoint: "http://127.0.0.1:9000/mcp",
  enabled: true,
  accessToken: "",
  clearAccessToken: false,
};

interface SettingsViewProps {
  runtime: RuntimeStatus;
  onRuntimeChange: (runtime: RuntimeStatus) => void;
  onNotify: (message: string) => void;
  initialTab?: SettingsTab;
}

interface CertificateAuthorityStatus {
  generated: boolean;
  installed: boolean;
  fingerprint: string;
  certificatePath: string;
  createdAt: number;
}

interface AndroidDevice {
  serial: string;
  state: string;
  model: string;
  product?: string;
  device?: string;
  transportId?: string;
  ready: boolean;
}

interface AndroidSetupStatus {
  adbAvailable: boolean;
  adbPath?: string;
  devices: AndroidDevice[];
  message?: string;
}

interface AndroidSetupResult {
  serial: string;
  model: string;
  proxyEndpoint: string;
  certificatePath: string;
  installerOpened: boolean;
  confirmationRequired: boolean;
}

interface AiProviderSettings {
  provider: AiProvider;
  baseUrl: string;
  model: string;
  hasApiKey: boolean;
}

const defaultUpstream: UpstreamProxySettings = {
  mode: "direct",
  host: "",
  port: 7890,
  username: "",
  hasPassword: false,
  bypass: ["localhost", "127.0.0.1", "::1", "*.local"],
};

const defaultSystemProxy: SystemProxySettings = {
  enabled: false,
  active: false,
  recoveryPending: false,
  bypass: ["localhost", "127.0.0.1", "::1", "*.local"],
};

const defaultTlsInterception: TlsInterceptionSettings = {
  mode: "intercept_all",
  bypass: [],
  showBypassedConnections: true,
};

const defaultMcpStatus: McpServerStatus = {
  enabled: true,
  running: false,
  starting: false,
  host: "127.0.0.1",
  port: 8899,
  endpoint: "http://127.0.0.1:8899/mcp",
  protocolVersion: "2025-06-18",
  toolCount: 28,
  allowWrites: false,
  hasAccessToken: false,
  recentClients: [],
};

function McpGuideClientIcon({ id, size = 16 }: { id: McpGuideClientId; size?: number }) {
  if (id === "codex") return <SquareTerminal size={size} />;
  if (id === "claude-code") return <Bot size={size} />;
  if (id === "cursor") return <Braces size={size} />;
  return <Code2 size={size} />;
}

const defaultDataStorageSettings: DataStorageSettings = {
  autoCleanupEnabled: true,
  retentionDays: 30,
  saveBinaryResponses: false,
};

const defaultAiAnalysisSettings: AiAnalysisSettings = {
  twoStageAnalysis: true,
  allowMcpTools: true,
  streamingOutput: true,
  maxAgentTurns: 8,
};

const defaultStorageStats: StorageStats = {
  databaseBytes: 0,
  responseBodyBytes: 0,
  sessionCount: 0,
  requestCount: 0,
  databasePath: "shownet.sqlite3",
  dataDirectory: "--",
};

export function SettingsView({ runtime, onRuntimeChange, onNotify, initialTab = "capture" }: SettingsViewProps) {
  const effectiveRuntimeAccessMode = runtime.accessMode ?? "private";
  const effectiveRuntimeAccessRules = runtime.accessRules ?? [];
  const [tab, setTab] = useState<SettingsTab>(initialTab);
  const [routingMode, setRoutingMode] = useState<"proxy" | "transparent">("proxy");
  const [systemProxy, setSystemProxy] = useState(defaultSystemProxy);
  const [systemProxyBypass, setSystemProxyBypass] = useState(defaultSystemProxy.bypass.join(", "));
  const [savingSystemProxy, setSavingSystemProxy] = useState(false);
  const [lanEnabled, setLanEnabled] = useState(runtime.lanEnabled);
  const [accessMode, setAccessMode] = useState<ClientAccessMode>(effectiveRuntimeAccessMode);
  const [accessRulesDraft, setAccessRulesDraft] = useState(effectiveRuntimeAccessRules.join("\n"));
  const [savingLanAccess, setSavingLanAccess] = useState(false);
  const [deviceSetupOpen, setDeviceSetupOpen] = useState(false);
  const [deviceSetupMode, setDeviceSetupMode] = useState<"android" | "scan">("android");
  const [androidStatus, setAndroidStatus] = useState<AndroidSetupStatus | null>(null);
  const [selectedAndroidSerial, setSelectedAndroidSerial] = useState("");
  const [scanningAndroid, setScanningAndroid] = useState(false);
  const [preparingAndroid, setPreparingAndroid] = useState(false);
  const [androidResult, setAndroidResult] = useState<AndroidSetupResult | null>(null);
  const [androidError, setAndroidError] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [showProxyPassword, setShowProxyPassword] = useState(false);
  const [provider, setProvider] = useState<AiProvider>("claudegpt");
  const [endpoint, setEndpoint] = useState("https://claudegpt.org/v1");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(DEFAULT_AI_MODEL);
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [modelDiscoveryStatus, setModelDiscoveryStatus] = useState<ModelDiscoveryStatus>("idle");
  const [modelDiscoveryError, setModelDiscoveryError] = useState("");
  const [aiSettingsLoaded, setAiSettingsLoaded] = useState(false);
  const modelDiscoveryRequestId = useRef(0);
  const [qrOpen, setQrOpen] = useState(false);
  const [upstream, setUpstream] = useState(defaultUpstream);
  const [upstreamPassword, setUpstreamPassword] = useState("");
  const [outboundTls, setOutboundTls] = useState<OutboundTlsProfileStatus | null>(null);
  const [savingOutboundTls, setSavingOutboundTls] = useState(false);
  const [tlsInterception, setTlsInterception] = useState(defaultTlsInterception);
  const [tlsBypassRules, setTlsBypassRules] = useState("");
  const [savingTlsInterception, setSavingTlsInterception] = useState(false);
  const [savingUpstream, setSavingUpstream] = useState(false);
  const [caStatus, setCaStatus] = useState<CertificateAuthorityStatus | null>(null);
  const [installingCa, setInstallingCa] = useState(false);
  const [certificateError, setCertificateError] = useState("");
  const [hasSavedApiKey, setHasSavedApiKey] = useState(false);
  const [aiAnalysisSettings, setAiAnalysisSettings] = useState(defaultAiAnalysisSettings);
  const [savingAi, setSavingAi] = useState(false);
  const [mcpStatus, setMcpStatus] = useState(defaultMcpStatus);
  const [mcpToken, setMcpToken] = useState("");
  const [showMcpToken, setShowMcpToken] = useState(false);
  const [savingMcp, setSavingMcp] = useState(false);
  const [mcpGuideClient, setMcpGuideClient] = useState<McpGuideClientId>("codex");
  const [mcpGuideIncludeToken, setMcpGuideIncludeToken] = useState(false);
  const [loadingMcpGuideToken, setLoadingMcpGuideToken] = useState(false);
  const [mcpClients, setMcpClients] = useState<McpClientSettings[]>([]);
  const [mcpClientDraft, setMcpClientDraft] = useState<McpClientDraft | null>(null);
  const [savingMcpClient, setSavingMcpClient] = useState(false);
  const [testingMcpClientId, setTestingMcpClientId] = useState("");
  const [mcpClientTools, setMcpClientTools] = useState<Record<string, string[]>>({});
  const [dataStorageSettings, setDataStorageSettings] = useState(defaultDataStorageSettings);
  const [storageStats, setStorageStats] = useState(defaultStorageStats);
  const [storageStatsLoading, setStorageStatsLoading] = useState(false);
  const [savingDataStorage, setSavingDataStorage] = useState(false);
  const [clearDataOpen, setClearDataOpen] = useState(false);
  const [clearingData, setClearingData] = useState(false);
  const [updateDialogOpen, setUpdateDialogOpen] = useState(false);
  const [checkingForUpdates, setCheckingForUpdates] = useState(false);
  const [updateResult, setUpdateResult] = useState<UpdateCheckResult | null>(null);
  const [updateError, setUpdateError] = useState("");

  useEscapeDismiss(
    deviceSetupOpen || qrOpen || clearDataOpen || updateDialogOpen,
    () => {
      if (deviceSetupOpen) setDeviceSetupOpen(false);
      else if (qrOpen) setQrOpen(false);
      else if (clearDataOpen && !clearingData) setClearDataOpen(false);
      else if (updateDialogOpen && !checkingForUpdates) setUpdateDialogOpen(false);
    },
  );

  const refreshAiModels = async (
    notifyResult = false,
    override?: { baseUrl?: string; apiKey?: string },
  ) => {
    const requestId = ++modelDiscoveryRequestId.current;
    const requestedEndpoint = (override?.baseUrl ?? endpoint).trim();
    const requestedApiKey = override?.apiKey ?? apiKey;
    if (!requestedEndpoint) {
      setAvailableModels([]);
      setModelDiscoveryStatus("fallback");
      setModelDiscoveryError("请先填写 API Base URL");
      setModel((current) => current.trim() || DEFAULT_AI_MODEL);
      return;
    }
    if (!isTauri()) {
      setAvailableModels([]);
      setModelDiscoveryStatus("fallback");
      setModelDiscoveryError("桌面版可读取远程模型列表");
      setModel((current) => current.trim() || DEFAULT_AI_MODEL);
      return;
    }
    setModelDiscoveryStatus("loading");
    setModelDiscoveryError("");
    try {
      const discovered = await invoke<string[]>("list_ai_models", {
        settings: {
          baseUrl: requestedEndpoint,
          apiKey: requestedApiKey.trim() || null,
        },
      });
      if (requestId !== modelDiscoveryRequestId.current) return;
      setAvailableModels(discovered);
      setModel((current) => {
        const selected = current.trim();
        if (discovered.includes(selected)) return selected;
        return discovered.includes(DEFAULT_AI_MODEL) ? DEFAULT_AI_MODEL : discovered[0];
      });
      setModelDiscoveryStatus("ready");
      if (notifyResult) onNotify(`已读取 ${discovered.length} 个模型`);
    } catch (error) {
      if (requestId !== modelDiscoveryRequestId.current) return;
      setAvailableModels([]);
      setModelDiscoveryStatus("fallback");
      setModelDiscoveryError(String(error));
      setModel((current) => current.trim() || DEFAULT_AI_MODEL);
      if (notifyResult) onNotify("模型列表不可用，已切换为手动输入");
    }
  };

  useEffect(() => {
    if (!isTauri()) return;
    invoke<UpstreamProxySettings>("get_upstream_proxy_settings")
      .then(setUpstream)
      .catch((error) => onNotify(`读取出口代理失败：${String(error)}`));
    invoke<OutboundTlsProfileStatus>("get_outbound_tls_profile")
      .then(setOutboundTls)
      .catch(() => setOutboundTls(null));
    invoke<TlsInterceptionSettings>("get_tls_interception_settings")
      .then((settings) => {
        setTlsInterception(settings);
        setTlsBypassRules(settings.bypass.join("\n"));
      })
      .catch((error) => onNotify(`读取 HTTPS 解密策略失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<AiAnalysisSettings>("get_ai_analysis_settings")
      .then(setAiAnalysisSettings)
      .catch((error) => onNotify(`读取 AI 分析策略失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<SystemProxySettings>("get_system_proxy_settings")
      .then((settings) => {
        setSystemProxy(settings);
        setSystemProxyBypass(settings.bypass.join(", "));
      })
      .catch((error) => onNotify(`读取系统代理设置失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    setSystemProxy((current) => ({
      ...current,
      enabled: runtime.systemProxyEnabled,
      active: runtime.systemProxyActive,
      recoveryPending: runtime.systemProxyRecoveryPending,
    }));
  }, [runtime.systemProxyActive, runtime.systemProxyEnabled, runtime.systemProxyRecoveryPending]);

  const runtimeAccessRulesText = effectiveRuntimeAccessRules.join("\n");

  useEffect(() => {
    setLanEnabled(runtime.lanEnabled);
    setAccessMode(effectiveRuntimeAccessMode);
    setAccessRulesDraft(runtimeAccessRulesText);
  }, [effectiveRuntimeAccessMode, runtimeAccessRulesText, runtime.lanEnabled]);

  useEffect(() => {
    if (!runtime.transparentModeAvailable) setRoutingMode("proxy");
  }, [runtime.transparentModeAvailable]);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<McpServerStatus>("get_mcp_server_status")
      .then(setMcpStatus)
      .catch((error) => onNotify(`读取 MCP 服务状态失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let stopListening: (() => void) | undefined;
    void listen<McpServerStatus>("settings://mcp-server", (event) => {
      if (!disposed) setMcpStatus(event.payload);
    }).then((unlisten) => {
      if (disposed) unlisten();
      else stopListening = unlisten;
    });
    return () => {
      disposed = true;
      stopListening?.();
    };
  }, []);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<McpClientSettings[]>("list_external_mcp_servers")
      .then(setMcpClients)
      .catch((error) => onNotify(`读取外部 MCP Server 失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    if (!isTauri()) {
      setAiSettingsLoaded(true);
      return;
    }
    invoke<AiProviderSettings>("get_ai_provider_settings")
      .then((settings) => {
        setProvider(settings.provider);
        setEndpoint(settings.baseUrl);
        setModel(settings.model);
        setHasSavedApiKey(settings.hasApiKey);
        setAiSettingsLoaded(true);
      })
      .catch((error) => {
        setAiSettingsLoaded(true);
        onNotify(`读取 AI 配置失败：${String(error)}`);
      });
  }, [onNotify]);

  useEffect(() => {
    if (tab !== "ai" || !aiSettingsLoaded) return;
    if (!endpoint.trim()) {
      modelDiscoveryRequestId.current += 1;
      setAvailableModels([]);
      setModelDiscoveryStatus("fallback");
      setModelDiscoveryError("请先填写 API Base URL");
      setModel((current) => current.trim() || DEFAULT_AI_MODEL);
      return;
    }
    setAvailableModels([]);
    setModelDiscoveryStatus("idle");
    setModelDiscoveryError("");
    const timeout = window.setTimeout(() => void refreshAiModels(), 600);
    return () => {
      window.clearTimeout(timeout);
      modelDiscoveryRequestId.current += 1;
    };
  }, [tab, aiSettingsLoaded, endpoint, provider]);

  useEffect(() => {
    if (!isTauri()) return;
    invoke<CertificateAuthorityStatus>("get_ca_status")
      .then(setCaStatus)
      .catch((error) => onNotify(`读取 Root CA 状态失败：${String(error)}`));
  }, [onNotify]);

  useEffect(() => {
    if (tab !== "data" || !isTauri()) return;
    let disposed = false;
    setStorageStatsLoading(true);
    Promise.all([
      invoke<DataStorageSettings>("get_data_storage_settings"),
      invoke<StorageStats>("get_storage_stats"),
    ])
      .then(([settings, stats]) => {
        if (disposed) return;
        setDataStorageSettings(settings);
        setStorageStats(stats);
      })
      .catch((error) => {
        if (!disposed) onNotify(`读取存储信息失败：${String(error)}`);
      })
      .finally(() => {
        if (!disposed) setStorageStatsLoading(false);
      });
    const timer = window.setInterval(() => {
      invoke<StorageStats>("get_storage_stats")
        .then((stats) => {
          if (!disposed) setStorageStats(stats);
        })
        .catch(() => undefined);
    }, 5_000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [tab, onNotify]);

  const saveSystemProxy = async () => {
    const bypass = systemProxyBypass.split(",").map((value) => value.trim()).filter(Boolean);
    if (!isTauri()) {
      const saved = { ...systemProxy, bypass };
      setSystemProxy(saved);
      setSystemProxyBypass(saved.bypass.join(", "));
      onNotify("系统代理接管设置已保存");
      return;
    }
    setSavingSystemProxy(true);
    try {
      const saved = await invoke<SystemProxySettings>("save_system_proxy_settings", {
        settings: { enabled: systemProxy.enabled, bypass },
      });
      setSystemProxy(saved);
      setSystemProxyBypass(saved.bypass.join(", "));
      onRuntimeChange({
        ...runtime,
        systemProxyEnabled: saved.enabled,
        systemProxyActive: saved.active,
        systemProxyRecoveryPending: saved.recoveryPending,
      });
      onNotify(saved.enabled ? "系统代理将在抓包启动时接管" : "系统代理接管已关闭");
    } catch (error) {
      onNotify(`保存系统代理设置失败：${String(error)}`);
    } finally {
      setSavingSystemProxy(false);
    }
  };

  const retrySystemProxyRecovery = async () => {
    if (!isTauri()) return;
    setSavingSystemProxy(true);
    try {
      const restored = await invoke<SystemProxySettings>("retry_system_proxy_recovery");
      setSystemProxy(restored);
      onRuntimeChange({
        ...runtime,
        systemProxyEnabled: restored.enabled,
        systemProxyActive: restored.active,
        systemProxyRecoveryPending: restored.recoveryPending,
      });
      onNotify("系统代理原设置已恢复");
    } catch (error) {
      onNotify(`恢复系统代理失败：${String(error)}`);
    } finally {
      setSavingSystemProxy(false);
    }
  };

  const syncClientAccessStatus = (status: RuntimeStatus) => {
    const normalizedStatus: RuntimeStatus = {
      ...status,
      accessMode: status.accessMode ?? "private",
      accessRules: Array.isArray(status.accessRules) ? status.accessRules : [],
    };
    setLanEnabled(normalizedStatus.lanEnabled);
    setAccessMode(normalizedStatus.accessMode);
    setAccessRulesDraft(normalizedStatus.accessRules.join("\n"));
    onRuntimeChange(normalizedStatus);
  };

  const restartReverseProxy = async (status: ReverseProxyStatus | undefined, fallbackSessionId?: string) => {
    if (!status?.running) return;
    const sessionId = status.sessionId ?? fallbackSessionId;
    if (!sessionId) throw new Error("免代理入口缺少原会话，无法自动恢复");
    await invoke<ReverseProxyStatus>("start_reverse_proxy", {
      settings: {
        targetUrl: status.targetUrl,
        localPort: status.localPort,
        lanEnabled: status.lanEnabled,
        preserveHost: status.preserveHost,
      },
      sessionId,
    });
  };

  const saveClientAccess = async (
    next: CaptureListenerSettings,
    successMessage: string,
  ): Promise<RuntimeStatus | null> => {
    const validationError = validateClientAccessSettings(next);
    if (validationError) {
      onNotify(validationError);
      return null;
    }
    const previous: CaptureListenerSettings = {
      lanEnabled: runtime.lanEnabled,
      accessMode: effectiveRuntimeAccessMode,
      accessRules: effectiveRuntimeAccessRules,
    };
    setLanEnabled(next.lanEnabled);
    if (!isTauri()) {
      const saved = {
        ...runtime,
        ...next,
        listenHost: next.lanEnabled ? "0.0.0.0" : "127.0.0.1",
      };
      syncClientAccessStatus(saved);
      onNotify(successMessage);
      return saved;
    }
    setSavingLanAccess(true);
    let captureStopped = false;
    let listenerSaved = false;
    let captureRestarted = false;
    let reverseBefore: ReverseProxyStatus | undefined;
    const activeSessionId = runtime.activeSessionId;
    try {
      if (runtime.proxyRunning) {
        if (!activeSessionId) throw new Error("当前抓包会话状态不完整");
        reverseBefore = await invoke<ReverseProxyStatus>("get_reverse_proxy_status");
        await invoke<RuntimeStatus>("set_capture_running", { running: false, sessionId: null });
        captureStopped = true;
      }
      let saved = await invoke<RuntimeStatus>("save_capture_listener_settings", {
        settings: next,
      });
      listenerSaved = true;
      if (captureStopped && activeSessionId) {
        saved = await invoke<RuntimeStatus>("set_capture_running", {
          running: true,
          sessionId: activeSessionId,
        });
        captureRestarted = true;
        await restartReverseProxy(reverseBefore, activeSessionId);
      }
      syncClientAccessStatus(saved);
      const restoredRuntime = reverseBefore?.running ? "，抓包与免代理入口已恢复" : captureStopped ? "，抓包已自动恢复" : "";
      onNotify(`${successMessage}${restoredRuntime}`);
      return saved;
    } catch (error) {
      const recoveryErrors: string[] = [];
      let restored: RuntimeStatus | undefined;
      try {
        if (listenerSaved && captureRestarted) {
          await invoke<RuntimeStatus>("set_capture_running", { running: false, sessionId: null });
          captureRestarted = false;
        }
        if (listenerSaved) {
          await invoke<RuntimeStatus>("save_capture_listener_settings", { settings: previous });
        }
        if (captureStopped && activeSessionId) {
          restored = await invoke<RuntimeStatus>("set_capture_running", {
            running: true,
            sessionId: activeSessionId,
          });
          await restartReverseProxy(reverseBefore, activeSessionId);
        } else {
          restored = await invoke<RuntimeStatus>("get_runtime_status");
        }
      } catch (recoveryError) {
        recoveryErrors.push(String(recoveryError));
      }
      if (!restored) {
        try {
          restored = await invoke<RuntimeStatus>("get_runtime_status");
        } catch (statusError) {
          recoveryErrors.push(String(statusError));
        }
      }
      if (restored) syncClientAccessStatus(restored);
      else {
        setLanEnabled(previous.lanEnabled);
        setAccessMode(previous.accessMode);
        setAccessRulesDraft(previous.accessRules.join("\n"));
      }
      const recoveryMessage = recoveryErrors.length
        ? `；自动恢复未完成：${recoveryErrors.join("；")}`
        : "；原设置与运行状态已恢复";
      onNotify(`修改设备访问范围失败：${String(error)}${recoveryMessage}`);
      return null;
    } finally {
      setSavingLanAccess(false);
    }
  };

  const saveLanAccess = (enabled: boolean) => saveClientAccess({
    lanEnabled: enabled,
    accessMode,
    accessRules: parseClientAccessRules(accessRulesDraft),
  }, enabled ? "局域网设备接入已开启" : "局域网设备接入已关闭");

  const saveAccessPolicy = () => saveClientAccess({
    lanEnabled,
    accessMode,
    accessRules: parseClientAccessRules(accessRulesDraft),
  }, `${clientAccessModeLabel(accessMode)}已应用`);

  const saveUpstream = async () => {
    setSavingUpstream(true);
    try {
      if (!isTauri()) {
        setUpstream((current) => ({ ...current, hasPassword: current.hasPassword || Boolean(upstreamPassword) }));
        setUpstreamPassword("");
        onNotify("出口代理配置已保存");
        return;
      }
      const saved = await invoke<UpstreamProxySettings>("save_upstream_proxy_settings", {
        settings: {
          mode: upstream.mode,
          host: upstream.host,
          port: upstream.port,
          username: upstream.username,
          password: upstreamPassword || null,
          clearPassword: false,
          bypass: upstream.bypass,
        },
      });
      setUpstream(saved);
      setUpstreamPassword("");
      onNotify("出口代理配置已加密保存");
    } catch (error) {
      onNotify(`保存出口代理失败：${String(error)}`);
    } finally {
      setSavingUpstream(false);
    }
  };

  const selectTlsInterceptionMode = (mode: TlsInterceptionMode) => {
    setTlsInterception((current) => ({ ...current, mode }));
  };

  const saveTlsInterception = async () => {
    const bypass = tlsBypassRules
      .split(/[\n,]+/)
      .map((rule) => rule.trim())
      .filter(Boolean);
    if (tlsInterception.mode === "bypass_selected" && bypass.length === 0) {
      onNotify("请至少填写一个需要保持原始 TLS 连接的域名");
      return;
    }
    if (tlsInterception.mode === "bypass_all") {
      const impact = tlsInterception.showBypassedConnections
        ? "全部 HTTPS 将不再解密，只显示连接信息。"
        : "全部 HTTPS 将不再解密，成功连接也不会出现在流量列表中；失败仍保留。";
      if (!window.confirm(`${impact}确认启用全部绕行？`)) return;
    }
    const next: TlsInterceptionSettings = {
      mode: tlsInterception.mode,
      bypass,
      showBypassedConnections: tlsInterception.showBypassedConnections,
    };
    setSavingTlsInterception(true);
    try {
      if (!isTauri()) {
        setTlsInterception(next);
        setTlsBypassRules(next.bypass.join("\n"));
        onNotify("HTTPS 解密策略已保存，新连接立即生效");
        return;
      }
      const saved = await invoke<TlsInterceptionSettings>("save_tls_interception_settings", { settings: next });
      setTlsInterception(saved);
      setTlsBypassRules(saved.bypass.join("\n"));
      onNotify(saved.mode === "intercept_all" ? "已恢复解密全部 HTTPS" : saved.mode === "bypass_all" ? "全部 HTTPS 已改为原样隧道" : `已启用 ${saved.bypass.length} 条 HTTPS 绕行规则`);
    } catch (error) {
      onNotify(`保存 HTTPS 解密策略失败：${String(error)}`);
    } finally {
      setSavingTlsInterception(false);
    }
  };

  const clearUpstreamPassword = async () => {
    if (!upstream.hasPassword) return;
    if (!isTauri()) {
      setUpstream((current) => ({ ...current, hasPassword: false }));
      setUpstreamPassword("");
      onNotify("出口代理密码已清除");
      return;
    }
    try {
      const saved = await invoke<UpstreamProxySettings>("save_upstream_proxy_settings", {
        settings: {
          mode: upstream.mode,
          host: upstream.host,
          port: upstream.port,
          username: upstream.username,
          password: null,
          clearPassword: true,
          bypass: upstream.bypass,
        },
      });
      setUpstream(saved);
      setUpstreamPassword("");
      onNotify("出口代理密码已清除");
    } catch (error) {
      onNotify(`清除出口代理密码失败：${String(error)}`);
    }
  };

  const installCertificate = async () => {
    setCertificateError("");
    if (!isTauri()) {
      onRuntimeChange({ ...runtime, caInstalled: true });
      setCaStatus((current) => current ? { ...current, installed: true } : current);
      onNotify("桌面版将请求系统确认后安装 ShowNet Root CA");
      return;
    }
    setInstallingCa(true);
    try {
      const status = await invoke<CertificateAuthorityStatus>("install_ca_certificate");
      setCaStatus(status);
      onRuntimeChange({ ...runtime, caInstalled: status.installed });
      onNotify("ShowNet Root CA 已加入当前用户信任存储");
    } catch (error) {
      setCertificateError(String(error));
      onNotify(`安装 Root CA 失败：${String(error)}`);
    } finally {
      setInstallingCa(false);
    }
  };

  const refreshAndroidDevices = async () => {
    setScanningAndroid(true);
    setAndroidError("");
    try {
      const status = isTauri()
        ? await invoke<AndroidSetupStatus>("get_android_setup_status")
        : {
            adbAvailable: true,
            adbPath: "/Library/Android/sdk/platform-tools/adb",
            devices: [{ serial: "R58M-SHOWNET", state: "device", model: "Pixel 8", ready: true }],
          };
      setAndroidStatus(status);
      setSelectedAndroidSerial((current) => status.devices.some((device) => device.serial === current && device.ready)
        ? current
        : status.devices.find((device) => device.ready)?.serial ?? "");
    } catch (error) {
      setAndroidStatus(null);
      setAndroidError(String(error));
    } finally {
      setScanningAndroid(false);
    }
  };

  useEffect(() => {
    if (deviceSetupOpen && deviceSetupMode === "android") void refreshAndroidDevices();
  }, [deviceSetupOpen, deviceSetupMode]);

  const prepareAndroidDevice = async () => {
    if (!selectedAndroidSerial) return;
    if (!runtime.proxyRunning && isTauri()) {
      setAndroidError("请先开始抓包，再一键配置 Android 设备。");
      return;
    }
    setPreparingAndroid(true);
    setAndroidError("");
    setAndroidResult(null);
    try {
      if (!lanEnabled) {
        const enabled = await saveLanAccess(true);
        if (!enabled?.lanEnabled) return;
      }
      const selected = androidStatus?.devices.find((device) => device.serial === selectedAndroidSerial);
      const result = isTauri()
        ? await invoke<AndroidSetupResult>("prepare_android_device", { serial: selectedAndroidSerial })
        : {
            serial: selectedAndroidSerial,
            model: selected?.model ?? "Android",
            proxyEndpoint: `${runtime.lanAddresses[0] ?? "192.168.1.8"}:${runtime.proxyPort}`,
            certificatePath: "/sdcard/Download/shownet-root-ca.crt",
            installerOpened: true,
            confirmationRequired: true,
          };
      setAndroidResult(result);
      onNotify("Android 证书与代理已准备，请在手机上确认安装");
    } catch (error) {
      setAndroidError(String(error));
    } finally {
      setPreparingAndroid(false);
    }
  };

  const resetAndroidProxy = async () => {
    if (!selectedAndroidSerial) return;
    setPreparingAndroid(true);
    setAndroidError("");
    try {
      if (isTauri()) await invoke("reset_android_device_proxy", { serial: selectedAndroidSerial });
      setAndroidResult(null);
      onNotify("Android 设备代理已恢复，网络将恢复直连");
    } catch (error) {
      setAndroidError(String(error));
    } finally {
      setPreparingAndroid(false);
    }
  };

  const exportCertificate = async () => {
    if (!isTauri()) {
      onNotify("桌面版可导出 ShowNet Root CA");
      return;
    }
    const path = await save({
      defaultPath: "shownet-root-ca.pem",
      filters: [{ name: "PEM Certificate", extensions: ["pem", "crt"] }],
    });
    if (!path) return;
    try {
      await invoke("export_ca_certificate", { path });
      onNotify("ShowNet Root CA 已导出");
    } catch (error) {
      onNotify(`导出 Root CA 失败：${String(error)}`);
    }
  };

  const selectProvider = (nextProvider: AiProvider) => {
    setProvider(nextProvider);
    if (nextProvider === "claudegpt") {
      setEndpoint("https://claudegpt.org/v1");
    } else if (nextProvider === "local") {
      setEndpoint("http://127.0.0.1:11434/v1");
    } else {
      setEndpoint("");
    }
    setApiKey("");
    setModel(DEFAULT_AI_MODEL);
    setAvailableModels([]);
    setModelDiscoveryStatus("fallback");
    setModelDiscoveryError("");
  };

  const saveAiSettings = async () => {
    if (!endpoint.trim() || !model.trim()) {
      onNotify("请填写 AI Base URL 和模型");
      return;
    }
    if (!isTauri()) {
      setHasSavedApiKey(hasSavedApiKey || Boolean(apiKey));
      setApiKey("");
      onNotify("AI 配置与分析策略已保存");
      return;
    }
    setSavingAi(true);
    try {
      const [saved, savedAnalysisSettings] = await Promise.all([
        invoke<AiProviderSettings>("save_ai_provider_settings", {
          settings: {
            provider,
            baseUrl: endpoint,
            model,
            apiKey: apiKey || null,
            clearApiKey: false,
          },
        }),
        invoke<AiAnalysisSettings>("save_ai_analysis_settings", {
          settings: aiAnalysisSettings,
        }),
      ]);
      setProvider(saved.provider);
      setEndpoint(saved.baseUrl);
      setModel(saved.model);
      setHasSavedApiKey(saved.hasApiKey);
      setAiAnalysisSettings(savedAnalysisSettings);
      setApiKey("");
      onNotify("AI 配置、凭据与分析策略已保存");
      void refreshAiModels(false, { baseUrl: saved.baseUrl, apiKey: "" });
    } catch (error) {
      onNotify(`保存 AI 配置失败：${String(error)}`);
    } finally {
      setSavingAi(false);
    }
  };

  const clearAiKey = async () => {
    if (!hasSavedApiKey) return;
    if (!isTauri()) {
      setHasSavedApiKey(false);
      setApiKey("");
      onNotify("AI API Key 已清除");
      return;
    }
    try {
      const saved = await invoke<AiProviderSettings>("save_ai_provider_settings", {
        settings: {
          provider,
          baseUrl: endpoint,
          model,
          apiKey: null,
          clearApiKey: true,
        },
      });
      setHasSavedApiKey(saved.hasApiKey);
      setApiKey("");
      onNotify("AI API Key 已清除");
    } catch (error) {
      onNotify(`清除 AI API Key 失败：${String(error)}`);
    }
  };

  const saveDataStorage = async () => {
    if (dataStorageSettings.retentionDays < 1 || dataStorageSettings.retentionDays > 3650) {
      onNotify("会话保留天数必须在 1 到 3650 天之间");
      return;
    }
    if (!isTauri()) {
      onNotify("数据存储设置已保存");
      return;
    }
    setSavingDataStorage(true);
    try {
      const saved = await invoke<DataStorageSettings>("save_data_storage_settings", {
        settings: dataStorageSettings,
      });
      setDataStorageSettings(saved);
      setStorageStats(await invoke<StorageStats>("get_storage_stats"));
      onNotify("数据存储策略已保存并生效");
    } catch (error) {
      onNotify(`保存数据存储设置失败：${String(error)}`);
    } finally {
      setSavingDataStorage(false);
    }
  };

  const openStorageDirectory = async () => {
    if (!isTauri()) {
      onNotify("桌面版可打开 ShowNet 数据目录");
      return;
    }
    try {
      await invoke("open_data_directory");
    } catch (error) {
      onNotify(`打开数据目录失败：${String(error)}`);
    }
  };

  const clearAllSessionData = async () => {
    if (runtime.proxyRunning) {
      setClearDataOpen(false);
      onNotify("请先停止抓包，再清除会话数据");
      return;
    }
    if (!isTauri()) {
      setStorageStats({ ...defaultStorageStats, sessionCount: 1 });
      setClearDataOpen(false);
      onNotify("所有会话数据已清除");
      return;
    }
    setClearingData(true);
    try {
      const stats = await invoke<StorageStats>("clear_all_session_data");
      setStorageStats(stats);
      setClearDataOpen(false);
      onNotify("所有会话数据已清除，应用设置与凭据已保留");
    } catch (error) {
      onNotify(`清除会话数据失败：${String(error)}`);
    } finally {
      setClearingData(false);
    }
  };

  const saveMcpSettings = async () => {
    if (mcpStatus.port < 1024 || mcpStatus.port > 65535) {
      onNotify("MCP 服务端口必须在 1024 到 65535 之间");
      return;
    }
    if (!isTauri()) {
      onNotify("桌面版可启动 ShowNet MCP Server");
      return;
    }
    setSavingMcp(true);
    try {
      const status = await invoke<McpServerStatus>("save_mcp_server_settings", {
        settings: {
          enabled: mcpStatus.enabled,
          port: mcpStatus.port,
          allowWrites: mcpStatus.allowWrites,
        },
      });
      setMcpStatus(status);
      onNotify(status.running ? "MCP 服务配置已保存并生效" : status.lastError ? `MCP 服务启动失败：${status.lastError}` : "MCP 服务已停止");
    } catch (error) {
      onNotify(`保存 MCP 服务配置失败：${String(error)}`);
    } finally {
      setSavingMcp(false);
    }
  };

  const revealMcpToken = async (): Promise<string | null> => {
    if (!isTauri()) {
      onNotify("桌面版可查看 MCP 访问令牌");
      return null;
    }
    try {
      const token = await invoke<string>("reveal_mcp_access_token");
      setMcpToken(token);
      setShowMcpToken(true);
      return token;
    } catch (error) {
      onNotify(`读取 MCP 访问令牌失败：${String(error)}`);
      return null;
    }
  };

  const setMcpGuideTokenMode = async (includeToken: boolean) => {
    if (!includeToken) {
      setMcpGuideIncludeToken(false);
      return;
    }
    setLoadingMcpGuideToken(true);
    const token = mcpToken || await revealMcpToken();
    setLoadingMcpGuideToken(false);
    if (token) setMcpGuideIncludeToken(true);
  };

  const rotateMcpToken = async () => {
    if (!window.confirm("轮换后，已配置的 MCP 客户端需要使用新令牌重新连接。确认继续？")) return;
    if (!isTauri()) {
      onNotify("桌面版可轮换 MCP 访问令牌");
      return;
    }
    try {
      const token = await invoke<string>("rotate_mcp_access_token");
      setMcpToken(token);
      setShowMcpToken(true);
      setMcpGuideIncludeToken(false);
      setMcpStatus((current) => ({ ...current, hasAccessToken: true }));
      onNotify("MCP 访问令牌已轮换");
    } catch (error) {
      onNotify(`轮换 MCP 访问令牌失败：${String(error)}`);
    }
  };

  const upsertMcpClient = (server: McpClientSettings) => {
    setMcpClients((current) => {
      const index = current.findIndex((item) => item.id === server.id);
      if (index < 0) return [...current, server];
      return current.map((item) => item.id === server.id ? server : item);
    });
  };

  const editMcpClient = (server: McpClientSettings) => {
    setMcpClientDraft({
      id: server.id,
      name: server.name,
      endpoint: server.endpoint,
      enabled: server.enabled,
      accessToken: "",
      clearAccessToken: false,
    });
  };

  const testMcpClient = async (serverId: string, notifyResult = true) => {
    if (!isTauri()) {
      onNotify("桌面版可连接外部 MCP Server");
      return null;
    }
    setTestingMcpClientId(serverId);
    try {
      const result = await invoke<McpClientTestResult>("test_external_mcp_server", { serverId });
      upsertMcpClient(result.server);
      setMcpClientTools((current) => ({ ...current, [serverId]: result.tools }));
      if (notifyResult) onNotify(`已连接 ${result.serverName}，发现 ${result.tools.length} 个工具`);
      return result;
    } catch (error) {
      const servers = await invoke<McpClientSettings[]>("list_external_mcp_servers").catch(() => null);
      if (servers) setMcpClients(servers);
      if (notifyResult) onNotify(`外部 MCP 连接失败：${String(error)}`);
      return null;
    } finally {
      setTestingMcpClientId("");
    }
  };

  const saveMcpClient = async () => {
    if (!mcpClientDraft) return;
    if (!mcpClientDraft.name.trim() || !mcpClientDraft.endpoint.trim()) {
      onNotify("请填写 Server 名称和 Streamable HTTP 地址");
      return;
    }
    if (!isTauri()) {
      onNotify("桌面版可保存外部 MCP Server");
      return;
    }
    setSavingMcpClient(true);
    try {
      const server = await invoke<McpClientSettings>("save_external_mcp_server", {
        settings: {
          id: mcpClientDraft.id ?? null,
          name: mcpClientDraft.name,
          endpoint: mcpClientDraft.endpoint,
          enabled: mcpClientDraft.enabled,
          accessToken: mcpClientDraft.accessToken.trim() || null,
          clearAccessToken: mcpClientDraft.clearAccessToken,
        },
      });
      upsertMcpClient(server);
      setMcpClientDraft(null);
      const tested = await testMcpClient(server.id, false);
      onNotify(tested ? `MCP Server 已保存，发现 ${tested.tools.length} 个工具` : "MCP Server 已保存，连接测试未通过");
    } catch (error) {
      onNotify(`保存外部 MCP Server 失败：${String(error)}`);
    } finally {
      setSavingMcpClient(false);
    }
  };

  const toggleMcpClient = async (server: McpClientSettings, enabled: boolean) => {
    if (!isTauri()) return;
    try {
      const updated = await invoke<McpClientSettings>("save_external_mcp_server", {
        settings: {
          id: server.id,
          name: server.name,
          endpoint: server.endpoint,
          enabled,
          accessToken: null,
          clearAccessToken: false,
        },
      });
      upsertMcpClient(updated);
      onNotify(enabled ? `${server.name} 已允许供内置 Agent 使用` : `${server.name} 已停用`);
    } catch (error) {
      onNotify(`更新外部 MCP Server 失败：${String(error)}`);
    }
  };

  const deleteMcpClient = async (server: McpClientSettings) => {
    if (!window.confirm(`删除外部 MCP Server「${server.name}」及其加密 Token？`)) return;
    if (!isTauri()) return;
    try {
      await invoke("delete_external_mcp_server", { serverId: server.id });
      setMcpClients((current) => current.filter((item) => item.id !== server.id));
      setMcpClientTools((current) => {
        const next = { ...current };
        delete next[server.id];
        return next;
      });
      if (mcpClientDraft?.id === server.id) setMcpClientDraft(null);
      onNotify("外部 MCP Server 已删除");
    } catch (error) {
      onNotify(`删除外部 MCP Server 失败：${String(error)}`);
    }
  };

  const copyText = async (value: string, label: string) => {
    try {
      if (isTauri()) await writeText(value);
      else if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value);
      else throw new Error("当前环境不支持剪贴板");
      onNotify(`${label}已复制`);
    } catch (error) {
      onNotify(`复制失败：${String(error)}`);
    }
  };

  const copyMcpAccessToken = async () => {
    const token = mcpToken || await revealMcpToken();
    if (token) await copyText(token, "MCP 访问令牌");
  };

  const checkForUpdates = async () => {
    setUpdateDialogOpen(true);
    setCheckingForUpdates(true);
    setUpdateResult(null);
    setUpdateError("");
    if (!isTauri()) {
      setCheckingForUpdates(false);
      setUpdateError("请在 ShowNet 桌面版中检查更新");
      return;
    }
    try {
      const result = await invoke<UpdateCheckResult>("check_for_updates");
      setUpdateResult(result);
      onNotify(result.available ? `发现 ShowNet ${result.latestVersion}` : "当前已是最新版本");
    } catch (error) {
      setUpdateError(String(error));
    } finally {
      setCheckingForUpdates(false);
    }
  };

  const draftedAccessRules = parseClientAccessRules(accessRulesDraft);
  const accessPolicyDirty = accessMode !== effectiveRuntimeAccessMode
    || draftedAccessRules.join("\n") !== runtimeAccessRulesText;
  const deviceSetupUrl = runtime.lanEnabled && runtime.lanAddresses[0]
    ? `http://${runtime.lanAddresses[0]}:${runtime.proxyPort}/device`
    : "";
  const androidCaptureReady = runtime.proxyRunning || !isTauri();
  const storageFileName = storageStats.databasePath.split(/[\\/]/).pop() || "shownet.sqlite3";
  const mcpGuide = buildMcpClientGuide(
    mcpGuideClient,
    mcpStatus.endpoint,
    mcpGuideIncludeToken ? mcpToken : undefined,
  );
  const latestMcpClient = mcpStatus.recentClients[0];

  return (
    <>
    <section className="settings-view">
      <aside className="settings-nav">
        <span className="section-kicker">PREFERENCES</span>
        {[
          { id: "capture", label: "抓包与 HTTPS", icon: Network },
          { id: "ai", label: "AI 模型", icon: Sparkles },
          { id: "data", label: "数据与存储", icon: Database },
          { id: "mcp", label: "MCP 服务", icon: RadioTower },
        ].map((item) => {
          const Icon = item.icon;
          return <button key={item.id} className={tab === item.id ? "is-active" : ""} onClick={() => setTab(item.id as SettingsTab)}><Icon size={16} />{item.label}</button>;
        })}
        <div className="settings-version"><strong>ShowNet {runtime.appVersion}</strong><span>Tauri 2 · {runtime.platform}</span><button onClick={() => void checkForUpdates()} disabled={checkingForUpdates}><RefreshCw className={checkingForUpdates ? "spin" : ""} size={13} />{checkingForUpdates ? "检查中" : "检查更新"}</button></div>
      </aside>

      <div className="settings-content">
        {tab === "capture" && (
          <>
            <SettingsHeader kicker="CAPTURE ENGINE" title="抓包与 HTTPS" />
            <SettingsSection title="流量路由" defaultOpen>
              <div className={`routing-modes ${runtime.transparentModeAvailable ? "" : "is-single"}`}>
                <button className={routingMode === "proxy" ? "is-active" : ""} onClick={() => setRoutingMode("proxy")}><span><PlugZap size={19} /></span><div><strong>标准代理</strong><small>系统代理 / 手动代理 / Wi-Fi 代理</small></div>{routingMode === "proxy" && <Check size={15} />}</button>
                {runtime.transparentModeAvailable && <button className={routingMode === "transparent" ? "is-active" : ""} onClick={() => setRoutingMode("transparent")} title="透明导流"><span><Network size={19} /></span><div><strong>透明模式</strong><small>TUN 自动导流到本机代理</small></div>{routingMode === "transparent" && <Check size={15} />}</button>}
              </div>
              {routingMode === "transparent" && <div className="settings-notice"><CircleAlert size={15} /><span>TUN 负责透明导流，HTTPS 内容仍由本地 CA 与 MITM 解密。</span></div>}
              <label className="settings-switch-row"><span><strong>接管系统代理</strong><small>{systemProxy.active ? "已接管 · 停止抓包或退出时自动恢复" : "启动抓包时生效 · 默认关闭"}</small></span><input type="checkbox" checked={systemProxy.enabled} disabled={runtime.proxyRunning || savingSystemProxy} onChange={(event) => setSystemProxy((current) => ({ ...current, enabled: event.target.checked }))} /><i /></label>
              {systemProxy.recoveryPending && <div className="settings-notice settings-notice--recovery"><CircleAlert size={15} /><span>{systemProxy.lastError || "检测到尚未完成的系统代理恢复记录"}</span><button type="button" onClick={() => void retrySystemProxyRecovery()} disabled={savingSystemProxy}>重试恢复</button></div>}
              <div className="settings-field-row"><label><span>监听地址</span><input value={runtime.listenHost} readOnly /></label><label><span>代理端口</span><input type="number" value={runtime.proxyPort} readOnly /></label></div>
              <label className="settings-text-field"><span>绕过域名</span><input value={systemProxyBypass} disabled={runtime.proxyRunning || savingSystemProxy} onChange={(event) => setSystemProxyBypass(event.target.value)} /></label>
              <button className="save-settings-button" onClick={saveSystemProxy} disabled={runtime.proxyRunning || savingSystemProxy}><Save size={15} />{savingSystemProxy ? "保存中" : "保存路由设置"}</button>
            </SettingsSection>

            <SettingsSection title="出口代理">
              <div className="upstream-proxy-heading">
                <div className="upstream-mode-control" aria-label="出口代理类型">
                  {([
                    ["direct", "直连"],
                    ["http", "HTTP"],
                    ["https", "HTTPS"],
                    ["socks5", "SOCKS5"],
                  ] as Array<[UpstreamProxyMode, string]>).map(([mode, label]) => (
                    <button
                      key={mode}
                      className={upstream.mode === mode ? "is-active" : ""}
                      onClick={() => setUpstream((current) => ({ ...current, mode }))}
                    >
                      {label}
                    </button>
                  ))}
                </div>
                <span className={`credential-state ${upstream.hasPassword ? "is-set" : ""}`}>
                  <LockKeyhole size={12} />
                  {upstream.hasPassword ? "凭据已保存" : "无凭据"}
                </span>
              </div>
              <div className="upstream-proxy-heading" style={{ marginTop: 12 }}>
                <div className="upstream-mode-control" aria-label="出站 TLS 粗档位">
                  {([
                    ["default", "默认 rustls"],
                    ["chrome-like", "Chrome-like"],
                    ["firefox-like", "Firefox-like"],
                    ["safari-ios-like", "Safari/iOS-like"],
                  ] as Array<[string, string]>).map(([profile, label]) => (
                    <button
                      key={profile}
                      className={outboundTls?.profile === profile || (!outboundTls && profile === "default") ? "is-active" : ""}
                      disabled={savingOutboundTls}
                      onClick={() => {
                        void (async () => {
                          setSavingOutboundTls(true);
                          try {
                            const status = await invoke<OutboundTlsProfileStatus>("set_outbound_tls_profile", { profile });
                            setOutboundTls(status);
                            onNotify(
                              `出站 TLS 已切换为 ${status.presetId ?? status.profile}（${status.fidelityLabel}）`,
                            );
                          } catch (error) {
                            onNotify(`切换出站 TLS 失败：${String(error)}`);
                          } finally {
                            setSavingOutboundTls(false);
                          }
                        })();
                      }}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <label className="settings-text-field" style={{ marginTop: 12 }}>
                <span>ClientHello 版本预置（浏览器 · 大版本）</span>
                <select
                  disabled={savingOutboundTls}
                  value={outboundTls?.presetId ?? "chrome150"}
                  onChange={(event) => {
                    const presetId = event.target.value;
                    void (async () => {
                      setSavingOutboundTls(true);
                      try {
                        const status = await invoke<OutboundTlsProfileStatus>("set_outbound_tls_profile", {
                          profile: presetId,
                        });
                        setOutboundTls(status);
                        onNotify(
                          `ClientHello 预置 → ${status.presetId ?? presetId} · ${status.browserFamily ?? ""} ${status.browserMajorVersion ?? ""}`,
                        );
                      } catch (error) {
                        onNotify(`切换 ClientHello 预置失败：${String(error)}`);
                      } finally {
                        setSavingOutboundTls(false);
                      }
                    })();
                  }}
                >
                  {(outboundTls?.presets ?? []).length > 0
                    ? (outboundTls?.presets ?? []).map((preset) => (
                        <option key={preset.id} value={preset.id}>
                          {preset.label} ({preset.id}) · {preset.family}
                          {preset.majorVersion > 0 ? ` v${preset.majorVersion}` : ""}
                        </option>
                      ))
                    : (outboundTls?.profiles ?? ["default", "chrome150", "firefox136", "safari-ios18"]).map(
                        (id) => (
                          <option key={id} value={id}>
                            {id}
                          </option>
                        ),
                      )}
                </select>
              </label>
              {outboundTls && (
                <small style={{ display: "block", marginTop: 8, opacity: 0.8 }}>
                  当前: <code>{outboundTls.presetId ?? outboundTls.profile}</code>
                  {outboundTls.browserFamily
                    ? ` · ${outboundTls.browserFamily}${outboundTls.browserMajorVersion ? ` ${outboundTls.browserMajorVersion}` : ""}`
                    : ""}{" "}
                  · {outboundTls.note} · engine={outboundTls.engine ?? "rustls"} · 浏览器 JA3
                  全量对齐：
                  {outboundTls.supportsFullBrowserJa3 && outboundTls.ja3Parity
                    ? "是"
                    : "否（rustls 配方差异化；非 BoringSSL/curl-impersonate）"}
                </small>
              )}
              <label style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8, fontSize: 12 }}>
                <input
                  type="checkbox"
                  checked={Boolean(outboundTls?.autoFromInbound)}
                  onChange={(event) => {
                    void (async () => {
                      try {
                        const status = await invoke<OutboundTlsProfileStatus>(
                          "set_outbound_tls_auto_from_inbound",
                          { enabled: event.target.checked },
                        );
                        setOutboundTls(status);
                        onNotify(`入站自动选档：${event.target.checked ? "开" : "关"}`);
                      } catch (error) {
                        onNotify(String(error));
                      }
                    })();
                  }}
                />
                根据入站 JA3/JA4 自动选择出站 ClientHello 预置（改变 rustls 密码套件/ALPN 顺序）
              </label>
              <div className="settings-field-row">
                <label><span>代理主机</span><input disabled={upstream.mode === "direct"} value={upstream.host} onChange={(event) => setUpstream((current) => ({ ...current, host: event.target.value }))} placeholder="proxy.example.com" /></label>
                <label><span>端口</span><input disabled={upstream.mode === "direct"} type="number" min="1" max="65535" value={upstream.port} onChange={(event) => setUpstream((current) => ({ ...current, port: Number(event.target.value) || 0 }))} /></label>
              </div>
              <div className="settings-field-row">
                <label><span>用户名</span><input disabled={upstream.mode === "direct"} value={upstream.username} onChange={(event) => setUpstream((current) => ({ ...current, username: event.target.value }))} /></label>
                <label className="settings-text-field"><span>密码</span><div className="secret-input"><input disabled={upstream.mode === "direct"} type={showProxyPassword ? "text" : "password"} value={upstreamPassword} onChange={(event) => setUpstreamPassword(event.target.value)} placeholder={upstream.hasPassword ? "已保存" : "可选"} /><button disabled={upstream.mode === "direct"} onClick={() => setShowProxyPassword((show) => !show)} title={showProxyPassword ? "隐藏密码" : "显示密码"}>{showProxyPassword ? <EyeOff size={15} /> : <Eye size={15} />}</button>{upstream.hasPassword && <button onClick={clearUpstreamPassword} title="清除已保存密码"><Trash2 size={14} /></button>}</div></label>
              </div>
              <label className="settings-text-field"><span>直连域名</span><input value={upstream.bypass.join(", ")} onChange={(event) => setUpstream((current) => ({ ...current, bypass: event.target.value.split(",").map((item) => item.trim()) }))} /></label>
              <div className="upstream-actions">
                <span><Database size={13} />SQLite · AES-256-GCM</span>
                <button className="save-settings-button" onClick={saveUpstream} disabled={savingUpstream}><Save size={15} />{savingUpstream ? "保存中" : "保存出口代理"}</button>
              </div>
            </SettingsSection>

            <SettingsSection title="HTTPS 解密">
              <div className={`certificate-status ${runtime.caInstalled ? "is-installed" : ""}`}>
                <span className="certificate-status__icon">{runtime.caInstalled ? <ShieldCheck size={22} /> : <KeyRound size={22} />}</span>
                <div><strong>ShowNet Root CA</strong><small>{runtime.caInstalled ? "已安装并受系统信任" : "已生成，安装后可解密 HTTPS"}</small><code>SHA256 {caStatus?.fingerprint ?? "正在读取证书指纹"}</code></div>
                <span className="certificate-status__actions"><button className="secondary-button" onClick={exportCertificate}><Download size={14} />手动导出</button><button className={runtime.caInstalled ? "secondary-button" : "primary-button"} onClick={installCertificate} disabled={installingCa}>{runtime.caInstalled ? <><RefreshCw size={14} />重新安装</> : <><ShieldCheck size={14} />{installingCa ? "安装中" : "一键安装"}</>}</button></span>
              </div>
              {certificateError && <div className="certificate-install-error"><CircleAlert size={14} /><span><strong>自动安装未完成</strong><small>{certificateError}</small></span><button className="secondary-button" onClick={exportCertificate}><Download size={13} />手动安装</button></div>}
              <div className="tls-interception-policy">
                <header>
                  <div><strong>解密策略</strong><small>只影响新建立的 HTTPS 连接，保存后立即生效</small></div>
                  <span className={tlsInterception.mode === "intercept_all" ? "is-active" : ""}><LockKeyhole size={12} />{tlsInterception.mode === "intercept_all" ? "正在解密" : "绕行已开启"}</span>
                </header>
                <div className="tls-interception-modes" role="group" aria-label="HTTPS 解密策略">
                  <button type="button" className={tlsInterception.mode === "intercept_all" ? "is-active" : ""} aria-pressed={tlsInterception.mode === "intercept_all"} onClick={() => selectTlsInterceptionMode("intercept_all")} title="解密所有 HTTPS"><ShieldCheck size={14} />解密全部</button>
                  <button type="button" className={tlsInterception.mode === "bypass_selected" ? "is-active" : ""} aria-pressed={tlsInterception.mode === "bypass_selected"} onClick={() => selectTlsInterceptionMode("bypass_selected")} title="只绕行指定域名"><ListFilter size={14} />绕行指定</button>
                  <button type="button" className={tlsInterception.mode === "bypass_all" ? "is-active is-danger" : "is-danger"} aria-pressed={tlsInterception.mode === "bypass_all"} onClick={() => selectTlsInterceptionMode("bypass_all")} title="不解密任何 HTTPS"><ShieldOff size={14} />全部绕行</button>
                </div>
                <p>{tlsInterception.mode === "intercept_all" ? "适合已安装 CA 的浏览器和普通应用。" : tlsInterception.mode === "bypass_selected" ? "命中规则的连接保持原始 TLS，其余连接继续解密。" : "所有 HTTPS 只保留连接信息，无法查看请求与响应正文。"}</p>
                {tlsInterception.mode === "bypass_selected" && <label className="tls-bypass-editor"><span>保持原始 TLS 的域名</span><textarea aria-label="HTTPS 绕行域名" value={tlsBypassRules} onChange={(event) => setTlsBypassRules(event.target.value)} placeholder={"*.bank.example\napi.secure.example"} spellCheck={false} /><small>每行一个，支持 * 和 ?。也会匹配 ClientHello 中的 SNI。</small></label>}
                {tlsInterception.mode === "bypass_all" && <div className="tls-bypass-warning"><CircleAlert size={14} /><span>这会关闭 HTTPS 正文分析；HTTP 抓包不受影响。</span></div>}
                {tlsInterception.mode !== "intercept_all" && <label className="settings-switch-row tls-bypass-visibility"><span><strong>在流量列表显示绕行连接</strong><small>{tlsInterception.showBypassedConnections ? "连接会标记为“未解密”，正文不可见" : "只隐藏成功连接；连接失败仍会保留用于排查"}</small></span><input type="checkbox" checked={tlsInterception.showBypassedConnections} onChange={(event) => setTlsInterception((current) => ({ ...current, showBypassedConnections: event.target.checked }))} /><i /></label>}
                <footer><span><LockKeyhole size={12} />{tlsInterception.mode === "intercept_all" ? "解密失败的连接仍会保留诊断信息" : tlsInterception.showBypassedConnections ? "绕行连接仍会显示，并标记为“未解密”" : "成功绕行连接将隐藏，失败仍保留"}</span><button className="save-settings-button" onClick={() => void saveTlsInterception()} disabled={savingTlsInterception}><Save size={14} />{savingTlsInterception ? "保存中" : "保存解密策略"}</button></footer>
              </div>
              <div className="https-matrix">
                <div><span><Globe2 size={16} /></span><strong>浏览器 / 桌面应用</strong><em className="is-good">可解密</em></div>
                <div><span><Smartphone size={16} /></span><strong>手机 / 平板</strong><em className="is-good">安装 CA 后可解密</em></div>
                <div><span><LockKeyhole size={16} /></span><strong>证书锁定应用</strong><em className="is-limited">绕行后可连接</em></div>
              </div>
            </SettingsSection>

            <SettingsSection title="设备接入">
              <label className="settings-switch-row"><span><strong>允许局域网设备接入</strong><small>{lanEnabled ? `当前范围：${clientAccessModeLabel(effectiveRuntimeAccessMode)}` : "开启时会自动恢复当前抓包与运行入口"}</small></span><input type="checkbox" checked={lanEnabled} disabled={savingLanAccess} onChange={(event) => void saveLanAccess(event.target.checked)} /><i /></label>
              <div className="client-access-policy">
                <header><div><strong>设备访问范围</strong><small>代理、免代理入口与证书安装页共用</small></div><span className={lanEnabled ? "is-active" : ""}><ShieldCheck size={12} />{lanEnabled ? "已启用" : "未监听"}</span></header>
                <div className="client-access-modes" role="radiogroup" aria-label="设备访问范围">
                  <button type="button" role="radio" aria-checked={accessMode === "private"} className={accessMode === "private" ? "is-active" : ""} disabled={savingLanAccess} onClick={() => setAccessMode("private")}><Wifi size={14} />所有私网设备</button>
                  <button type="button" role="radio" aria-checked={accessMode === "allow"} className={accessMode === "allow" ? "is-active" : ""} disabled={savingLanAccess} onClick={() => setAccessMode("allow")}><ShieldCheck size={14} />仅受信设备</button>
                  <button type="button" role="radio" aria-checked={accessMode === "deny"} className={accessMode === "deny" ? "is-active" : ""} disabled={savingLanAccess} onClick={() => setAccessMode("deny")}><ShieldOff size={14} />除已阻止设备外</button>
                </div>
                <p>{accessMode === "private" ? "当前私网和链路本地设备可接入，公网来源始终拒绝。" : accessMode === "allow" ? "只有命中名单的设备可接入；本机始终可用。" : "命中名单的设备会被拒绝，其余私网设备可接入。"}</p>
                {accessMode !== "private" && <label className="client-access-rules"><span>{accessMode === "allow" ? "受信设备" : "已阻止设备"}<em>{draftedAccessRules.length}/128</em></span><textarea aria-label={accessMode === "allow" ? "受信设备 IP 或 CIDR" : "已阻止设备 IP 或 CIDR"} value={accessRulesDraft} disabled={savingLanAccess} onChange={(event) => setAccessRulesDraft(event.target.value)} placeholder={accessMode === "allow" ? "192.168.1.23\n192.168.20.0/24" : "192.168.1.66\nfd12:3456::9"} spellCheck={false} /><small>每行一个私网 IPv4、IPv6 或 CIDR，最多 128 条。</small></label>}
                <footer><span><LockKeyhole size={12} />规则会规范化、去重，并拒绝公网范围</span><button className="save-settings-button" onClick={() => void saveAccessPolicy()} disabled={savingLanAccess || !accessPolicyDirty}><Save size={14} />{savingLanAccess ? "应用中" : accessPolicyDirty ? "保存访问范围" : "已保存"}</button></footer>
              </div>
              <div className="device-access-row">
                <span><Wifi size={18} /></span>
                <div>
                  <strong>{lanEnabled ? (runtime.lanAddresses[0] ? `${runtime.lanAddresses[0]}:${runtime.proxyPort}` : "未检测到局域网地址") : `127.0.0.1:${runtime.proxyPort}`}</strong>
                  <small>{lanEnabled ? (runtime.lanAddresses.length ? `${runtime.proxyRunning ? "正在监听" : "开始抓包后监听"} · ${clientAccessModeLabel(effectiveRuntimeAccessMode)}` : "请检查 Wi-Fi 或有线网络连接") : "开启后可供手机、平板和 IoT 设备使用"}</small>
                </div>
                <span className="device-access-actions">
                  <button className="primary-button" onClick={() => setDeviceSetupOpen(true)}><Smartphone size={14} />一键接入</button>
                  <button className="secondary-button" onClick={exportCertificate}><Download size={14} />导出 CA</button>
                </span>
              </div>
            </SettingsSection>
          </>
        )}

        {tab === "ai" && (
          <>
            <SettingsHeader kicker="AI ENGINE" title="AI 模型" />
            <SettingsSection title="分析提供商" defaultOpen>
              <div className="recommended-service">
                <span className="recommended-service__mark"><Sparkles size={20} /></span>
                <div className="recommended-service__body"><span>SHOWNET 首选 · 免费 AI 服务</span><strong>ClaudeGPT.org <em>一次性 $5 免费额度</em></strong><small>加入 QQ 群 553354813，联系管理员申请一次性 5 美金免费额度</small><code>默认模型 gpt-5.5 · https://claudegpt.org/v1</code></div>
                <div className="recommended-service__actions"><button className="is-primary" onClick={() => setQrOpen(true)}><MessageCircle size={14} />申请 $5 免费额度</button><a href="https://claudegpt.org/" target="_blank" rel="noreferrer">访问服务站<ExternalLink size={14} /></a></div>
              </div>
              <div className="provider-list">
                {([
                  { id: "claudegpt", name: "ClaudeGPT API", tag: "推荐", detail: "gpt-5.5 · 加群联系管理员申请 $5 免费额度" },
                  { id: "compatible", name: "其他兼容厂商", tag: "API", detail: "OpenAI / Azure / 自定义服务" },
                  { id: "local", name: "本地模型", tag: "LOCAL", detail: "Ollama / LM Studio" },
                ] as Array<{ id: AiProvider; name: string; tag: string; detail: string }>).map((item) => <button key={item.id} className={`${provider === item.id ? "is-active" : ""} ${item.id === "claudegpt" ? "is-featured" : ""}`} onClick={() => selectProvider(item.id)}><span className="provider-icon">{item.id === "local" ? <HardDrive size={18} /> : <Bot size={18} />}</span><span><strong>{item.name}<em>{item.tag}</em></strong><small>{item.detail}</small></span>{provider === item.id && <Check size={15} />}</button>)}
              </div>
              {provider === "claudegpt" && (
                <div className="recommended-endpoint">
                  <span className="recommended-endpoint__icon"><Server size={19} /></span>
                  <div><strong>ClaudeGPT OpenAI 兼容服务</strong><small>推荐接入 · 使用个人 API Key</small><code>https://claudegpt.org/v1</code></div>
                  <span className="recommended-endpoint__actions"><button onClick={() => void copyText("https://claudegpt.org/v1", "API 端点")} title="复制端点"><Copy size={14} /></button><a href="https://claudegpt.org/" target="_blank" rel="noreferrer" title="访问服务站"><ExternalLink size={14} /></a></span>
                </div>
              )}
              <label className="settings-text-field"><span>API Base URL</span><div className="secret-input"><input value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="https://api.example.com/v1" /><button onClick={() => void copyText(endpoint, "API 端点")} title="复制端点"><Copy size={15} /></button></div></label>
              <label className="settings-text-field"><span>API Key</span><div className="secret-input"><input type={showKey ? "text" : "password"} value={apiKey} onChange={(event) => { setApiKey(event.target.value); setAvailableModels([]); setModelDiscoveryStatus("idle"); setModelDiscoveryError(""); }} onBlur={() => { if (apiKey.trim()) void refreshAiModels(); }} placeholder={hasSavedApiKey ? "已加密保存；留空表示不更改" : provider === "local" ? "本地服务通常无需填写" : provider === "claudegpt" ? "领取额度后粘贴 API Key" : "sk-..."} autoComplete="off" /><button onClick={() => setShowKey((show) => !show)} title={showKey ? "隐藏 API Key" : "显示 API Key"}>{showKey ? <EyeOff size={15} /> : <Eye size={15} />}</button>{hasSavedApiKey && <button onClick={clearAiKey} title="清除已保存 API Key"><Trash2 size={14} /></button>}</div></label>
              <div className="settings-field-row">
                <label className="model-discovery-field">
                  <span>模型 <em className={`model-discovery-state is-${modelDiscoveryStatus}`} title={modelDiscoveryError || undefined}>{modelDiscoveryStatus === "ready" ? `${availableModels.length} 个可用` : modelDiscoveryStatus === "loading" ? "读取中" : modelDiscoveryStatus === "fallback" ? "手动输入" : "待读取"}</em></span>
                  <div className="model-discovery-control">
                    {modelDiscoveryStatus === "ready" ? (
                      <div className="select-input"><select value={model} onChange={(event) => setModel(event.target.value)}>{availableModels.map((item) => <option key={item} value={item}>{item}</option>)}</select><ChevronDown size={14} /></div>
                    ) : (
                      <input value={model} onChange={(event) => setModel(event.target.value)} placeholder={DEFAULT_AI_MODEL} />
                    )}
                    <button type="button" onClick={() => void refreshAiModels(true)} disabled={modelDiscoveryStatus === "loading"} title="从 /models 读取模型列表" aria-label="读取模型列表"><RefreshCw className={modelDiscoveryStatus === "loading" ? "is-spinning" : ""} size={14} /></button>
                  </div>
                  <small className={`model-discovery-help is-${modelDiscoveryStatus}`} title={modelDiscoveryError || undefined} aria-live="polite">{modelDiscoveryStatus === "ready" ? "模型列表已从 /models 同步" : modelDiscoveryStatus === "loading" ? "正在读取 /models" : modelDiscoveryStatus === "fallback" ? "无法读取 /models，已切换为手动输入" : "等待自动读取 /models"}</small>
                </label>
                <label><span>上下文上限</span><input value="128K" readOnly /></label>
              </div>
            </SettingsSection>
            <SettingsSection title="分析策略">
              <div className="settings-field-row agent-turn-limit-row">
                <label><span>Agent 最大分析轮次</span><input type="number" min="1" step="1" value={aiAnalysisSettings.maxAgentTurns} disabled={savingAi} onChange={(event) => setAiAnalysisSettings((current) => ({ ...current, maxAgentTurns: Math.max(1, Math.trunc(Number(event.target.value)) || 1) }))} /></label>
                <div><strong>单次最多 {aiAnalysisSettings.maxAgentTurns} 轮</strong><small>不设固定上限；提高轮次可能增加分析时长与模型费用</small></div>
              </div>
              <label className="settings-switch-row"><span><strong>两阶段分析</strong><small>大于 20 条请求时先执行智能过滤</small></span><input type="checkbox" checked={aiAnalysisSettings.twoStageAnalysis} disabled={savingAi} onChange={(event) => setAiAnalysisSettings((current) => ({ ...current, twoStageAnalysis: event.target.checked }))} /><i /></label>
              <label className="settings-switch-row"><span><strong>允许 MCP 工具调用</strong><small>模型可按需回查请求详情与外部数据</small></span><input type="checkbox" checked={aiAnalysisSettings.allowMcpTools} disabled={savingAi} onChange={(event) => setAiAnalysisSettings((current) => ({ ...current, allowMcpTools: event.target.checked }))} /><i /></label>
              <label className="settings-switch-row"><span><strong>流式输出</strong><small>分析内容实时写入报告</small></span><input type="checkbox" checked={aiAnalysisSettings.streamingOutput} disabled={savingAi} onChange={(event) => setAiAnalysisSettings((current) => ({ ...current, streamingOutput: event.target.checked }))} /><i /></label>
              <button className="save-settings-button" onClick={saveAiSettings} disabled={savingAi}><Save size={15} />{savingAi ? "保存中" : "保存设置"}</button>
            </SettingsSection>
            <SettingsSection title="服务与支持">
              <div className="support-channel">
                <button className="support-channel__qr" onClick={() => setQrOpen(true)} title="查看QQ群二维码"><img src={qqGroupQr} alt="QQ群 553354813 二维码" /></button>
                <div className="support-channel__body"><span className="support-channel__label"><MessageCircle size={13} />免费 AI 服务申请</span><strong>QQ 群 553354813</strong><small>加群后联系管理员，申请一次性 5 美金免费额度</small></div>
                <span className="support-channel__actions"><button className="secondary-button" onClick={() => void copyText("553354813", "QQ群号")}><Copy size={14} />复制群号</button><button className="primary-button" onClick={() => setQrOpen(true)}><MessageCircle size={14} />查看二维码</button></span>
              </div>
              <div className="service-site-row"><span><Globe2 size={16} /></span><div><strong>claudegpt.org</strong><small>API 服务、余额与模型列表</small></div><a href="https://claudegpt.org/" target="_blank" rel="noreferrer">访问服务站<ExternalLink size={13} /></a></div>
            </SettingsSection>
          </>
        )}

        {tab === "data" && (
          <>
            <SettingsHeader kicker="DATA & STORAGE" title="数据与存储" />
            <SettingsSection title="会话数据库" defaultOpen>
              <div className="storage-path"><span><Database size={19} /></span><div><strong>{storageFileName}</strong><code title={storageStats.dataDirectory}>{storageStats.dataDirectory}</code></div><button className="icon-button" onClick={openStorageDirectory} title="打开数据目录" aria-label="打开数据目录"><FolderOpen size={16} /></button></div>
              <div className={`storage-metrics ${storageStatsLoading ? "is-loading" : ""}`}><div><strong>{storageStatsLoading ? "读取中" : formatStorageBytes(storageStats.databaseBytes)}</strong><span>SQLite 总占用</span></div><div><strong>{storageStatsLoading ? "读取中" : formatStorageBytes(storageStats.responseBodyBytes)}</strong><span>已存响应正文</span></div><div><strong>{storageStatsLoading ? "读取中" : storageStats.sessionCount}</strong><span>{storageStats.requestCount} 条请求</span></div></div>
              <label className="settings-switch-row"><span><strong>自动清理</strong><small>按会话最后活动时间执行保留策略</small></span><input type="checkbox" checked={dataStorageSettings.autoCleanupEnabled} onChange={(event) => setDataStorageSettings((current) => ({ ...current, autoCleanupEnabled: event.target.checked }))} /><i /></label>
              <div className="settings-field-row storage-retention-row"><label><span>会话保留天数</span><input type="number" min="1" max="3650" step="1" disabled={!dataStorageSettings.autoCleanupEnabled} value={dataStorageSettings.retentionDays} onChange={(event) => setDataStorageSettings((current) => ({ ...current, retentionDays: Number(event.target.value) || 0 }))} /></label><div><strong>保留最近 {dataStorageSettings.retentionDays || 0} 天</strong><small>启动、保存策略及后台维护时清理空闲会话</small></div></div>
              <label className="settings-switch-row"><span><strong>保存二进制响应</strong><small>图片、字体与媒体正文；关闭后仍保留标头、大小与策略标记</small></span><input type="checkbox" checked={dataStorageSettings.saveBinaryResponses} onChange={(event) => setDataStorageSettings((current) => ({ ...current, saveBinaryResponses: event.target.checked }))} /><i /></label>
              <button className="save-settings-button" onClick={saveDataStorage} disabled={savingDataStorage}><Save size={15} />{savingDataStorage ? "正在应用" : "保存存储策略"}</button>
            </SettingsSection>
            <SettingsSection title="危险操作">
              <div className="danger-row"><span><Trash2 size={18} /></span><div><strong>清除所有会话数据</strong><small>删除请求、WebSocket 消息、SSE 事件、Hook 与分析报告；保留应用设置和凭据</small></div><button onClick={() => setClearDataOpen(true)} disabled={runtime.proxyRunning || clearingData} title={runtime.proxyRunning ? "停止抓包后才能清除" : "清除所有会话数据"}>{runtime.proxyRunning ? "抓包中" : "清除数据"}</button></div>
            </SettingsSection>
          </>
        )}

        {tab === "mcp" && (
          <>
            <SettingsHeader kicker="MODEL CONTEXT PROTOCOL" title="MCP 服务" />
            <SettingsSection title="ShowNet MCP Server">
              <div className="mcp-settings-status"><span className="server-emblem"><RadioTower size={20} /></span><div><strong>Streamable HTTP</strong><small>{mcpStatus.toolCount} Tools · MCP {mcpStatus.protocolVersion}</small></div><span className={`server-running ${mcpStatus.running ? "" : "is-stopped"}`}><span className={`live-dot ${mcpStatus.running ? "is-on" : ""}`} />{mcpStatus.starting ? "启动中" : mcpStatus.running ? "运行中" : "已停止"}</span></div>
              {mcpStatus.lastError && <div className="settings-notice"><CircleAlert size={15} /><span>{mcpStatus.lastError}</span></div>}
              <div className="settings-field-row"><label><span>监听地址</span><input value={mcpStatus.host} readOnly /></label><label><span>端口</span><input type="number" min="1024" max="65535" value={mcpStatus.port} onChange={(event) => setMcpStatus((current) => ({ ...current, port: Number(event.target.value) || 0, endpoint: `http://127.0.0.1:${Number(event.target.value) || 0}/mcp` }))} /></label></div>
              <label className="settings-text-field"><span>服务地址</span><div className="secret-input"><input value={mcpStatus.endpoint} readOnly /><button onClick={() => void copyText(mcpStatus.endpoint, "MCP 服务地址")} title="复制服务地址"><Copy size={14} /></button></div></label>
              <label className="settings-switch-row"><span><strong>随应用启动</strong><small>本机服务仅监听回环地址</small></span><input type="checkbox" checked={mcpStatus.enabled} onChange={(event) => setMcpStatus((current) => ({ ...current, enabled: event.target.checked }))} /><i /></label>
              <label className="settings-switch-row"><span><strong>允许写入型工具</strong><small>开放创建、删除会话与运行 AI 分析</small></span><input type="checkbox" checked={mcpStatus.allowWrites} onChange={(event) => setMcpStatus((current) => ({ ...current, allowWrites: event.target.checked, toolCount: event.target.checked ? 36 : 28 }))} /><i /></label>
              <button className="save-settings-button" onClick={saveMcpSettings} disabled={savingMcp}><Save size={15} />{savingMcp ? "正在应用" : "保存并应用"}</button>
            </SettingsSection>
            <SettingsSection title="认证">
              <label className="settings-text-field"><span>访问令牌</span><div className="secret-input"><input type={showMcpToken ? "text" : "password"} value={showMcpToken ? mcpToken : mcpStatus.hasAccessToken ? "shownet_mcp_••••••••••" : ""} readOnly /><button onClick={showMcpToken ? () => setShowMcpToken(false) : revealMcpToken} title={showMcpToken ? "隐藏访问令牌" : "显示访问令牌"}>{showMcpToken ? <EyeOff size={15} /> : <Eye size={15} />}</button><button onClick={() => void copyMcpAccessToken()} title="复制访问令牌"><Copy size={14} /></button><button onClick={rotateMcpToken} title="轮换访问令牌"><RefreshCw size={15} /></button></div></label>
              <div className="settings-notice settings-notice--safe"><ShieldCheck size={15} /><span>Bearer 令牌使用 AES-256-GCM 加密保存在 SQLite；服务仅监听本机。</span></div>
            </SettingsSection>
            <SettingsSection title="连接 AI 客户端" defaultOpen>
              <div className="mcp-guide-tabs" role="tablist" aria-label="选择 AI 客户端">
                {MCP_GUIDE_CLIENTS.map((client) => <button key={client.id} role="tab" aria-selected={mcpGuideClient === client.id} className={mcpGuideClient === client.id ? "is-active" : ""} onClick={() => { setMcpGuideClient(client.id); setMcpGuideIncludeToken(false); }}><McpGuideClientIcon id={client.id} />{client.name}</button>)}
              </div>
              <div className="mcp-guide-service">
                <span className={`mcp-guide-service__icon ${mcpStatus.running ? "is-ready" : ""}`}><RadioTower size={18} /></span>
                <div><strong>{mcpStatus.running ? "ShowNet 服务已就绪" : mcpStatus.starting ? "ShowNet 服务启动中" : "ShowNet 服务尚未运行"}</strong><code>{mcpStatus.endpoint}</code></div>
                <span className={`mcp-guide-service__scope ${mcpStatus.allowWrites ? "has-writes" : ""}`}>{mcpStatus.allowWrites ? "含写入工具" : "只读工具"}</span>
              </div>
              <div className="mcp-guide-layout">
                <ol className="mcp-guide-steps">
                  <li><span>1</span><div><strong>保存配置</strong><code>{mcpGuide.configPath}</code></div></li>
                  <li><span>2</span><div><strong>设置访问令牌</strong><small>{mcpGuide.authSummary}</small></div></li>
                  <li><span>3</span><div><strong>{mcpGuide.reloadHint}</strong><small>{mcpGuide.verifyHint}</small></div></li>
                </ol>
                <div className="mcp-guide-code">
                  <header><div><strong>{mcpGuide.configLabel}</strong><small>{mcpGuide.embedsToken ? "完整配置" : "安全配置"}</small></div><span><label className="mcp-guide-token-switch" title="将访问令牌直接写入生成的配置"><input type="checkbox" checked={mcpGuideIncludeToken} disabled={loadingMcpGuideToken || !mcpStatus.hasAccessToken} onChange={(event) => void setMcpGuideTokenMode(event.target.checked)} /><i /><b>{loadingMcpGuideToken ? "读取中" : "带入令牌"}</b></label><button className="icon-button" onClick={() => void copyText(mcpGuide.config, `${mcpGuide.name} 配置`)} title="复制配置"><Copy size={15} /></button></span></header>
                  <pre><code>{mcpGuide.config}</code></pre>
                </div>
              </div>
              <div className={`mcp-guide-auth ${mcpGuide.embedsToken ? "has-secret" : ""}`}>
                <span>{mcpGuide.embedsToken ? <CircleAlert size={16} /> : <LockKeyhole size={16} />}</span>
                <div><strong>{mcpGuide.embedsToken ? "配置中包含访问令牌" : "默认不把令牌写入配置"}</strong><small>{mcpGuide.embedsToken ? "请使用个人配置并避免提交到 Git；轮换令牌后需要重新生成。" : "Codex、Claude Code、Cursor 使用环境变量；VS Code 首次启动时安全询问。"}</small></div>
                <button className="secondary-button" onClick={() => void copyMcpAccessToken()}><Copy size={14} />复制令牌</button>
              </div>
              <div className="mcp-guide-activity">
                <span className={`live-dot ${latestMcpClient ? "is-on" : ""}`} />
                {latestMcpClient ? <><strong>最近接入 {latestMcpClient.name}{latestMcpClient.version ? ` ${latestMcpClient.version}` : ""}</strong><small>{new Date(latestMcpClient.connectedAt).toLocaleString()}</small></> : <><strong>等待客户端首次连接</strong><small>合法握手后会在这里显示客户端与时间</small></>}
              </div>
            </SettingsSection>
            <SettingsSection title="外部 MCP Servers">
              <div className="mcp-clients-toolbar"><div><strong>{mcpClients.length} 个连接</strong><small>{mcpClients.filter((server) => server.enabled).length} 个供内置 Agent 使用</small></div><button className="secondary-button" onClick={() => setMcpClientDraft({ ...emptyMcpClientDraft })}><Plus size={14} />添加 Server</button></div>
              {mcpClients.length === 0 && !mcpClientDraft && <div className="mcp-clients-empty"><PlugZap size={20} /><span>尚未连接外部 MCP Server</span></div>}
              {mcpClients.length > 0 && <div className="mcp-client-list">{mcpClients.map((server) => {
                const tools = mcpClientTools[server.id] ?? [];
                return <div className={`mcp-client-row ${server.lastError ? "has-error" : ""}`} key={server.id}>
                  <span className="mcp-client-row__icon"><Server size={17} /></span>
                  <div className="mcp-client-row__main"><span><strong>{server.name}</strong><small>{server.toolCount} Tools</small></span><code title={server.endpoint}>{server.endpoint}</code>{server.lastError ? <em title={server.lastError}>{server.lastError}</em> : tools.length > 0 ? <small>{tools.slice(0, 4).join(" · ")}{tools.length > 4 ? ` · +${tools.length - 4}` : ""}</small> : server.lastConnectedAt ? <small>最近连接 {new Date(server.lastConnectedAt).toLocaleString()}</small> : null}</div>
                  <div className="mcp-client-row__actions"><label className="compact-switch" title={server.enabled ? "停用 Agent 工具" : "启用 Agent 工具"}><input type="checkbox" checked={server.enabled} onChange={(event) => void toggleMcpClient(server, event.target.checked)} /><i /></label><button className="icon-button" onClick={() => void testMcpClient(server.id)} disabled={testingMcpClientId === server.id} title="测试连接"><RefreshCw className={testingMcpClientId === server.id ? "spin" : ""} size={15} /></button><button className="icon-button" onClick={() => editMcpClient(server)} title="编辑 Server"><PlugZap size={15} /></button><button className="icon-button is-danger" onClick={() => void deleteMcpClient(server)} title="删除 Server"><Trash2 size={15} /></button></div>
                </div>;
              })}</div>}
              {mcpClientDraft && <div className="mcp-client-editor">
                <div className="settings-field-row"><label><span>名称</span><input value={mcpClientDraft.name} maxLength={64} onChange={(event) => setMcpClientDraft((current) => current && ({ ...current, name: event.target.value }))} placeholder="例如：本地知识库" /></label><label><span>Streamable HTTP 地址</span><input value={mcpClientDraft.endpoint} onChange={(event) => setMcpClientDraft((current) => current && ({ ...current, endpoint: event.target.value }))} placeholder="http://127.0.0.1:9000/mcp" /></label></div>
                <label className="settings-text-field"><span>Bearer Token</span><div className="secret-input"><input type="password" value={mcpClientDraft.accessToken} onChange={(event) => setMcpClientDraft((current) => current && ({ ...current, accessToken: event.target.value, clearAccessToken: false }))} placeholder={mcpClientDraft.id && mcpClients.find((server) => server.id === mcpClientDraft.id)?.hasAccessToken ? "已加密保存；留空表示不更改" : "可选"} />{mcpClientDraft.id && mcpClients.find((server) => server.id === mcpClientDraft.id)?.hasAccessToken && <button className={mcpClientDraft.clearAccessToken ? "is-active" : ""} onClick={() => setMcpClientDraft((current) => current && ({ ...current, accessToken: "", clearAccessToken: !current.clearAccessToken }))} title={mcpClientDraft.clearAccessToken ? "保留已保存 Token" : "清除已保存 Token"}><Trash2 size={14} /></button>}</div></label>
                <label className="settings-switch-row"><span><strong>供内置 Agent 使用</strong><small>工具定义会加入允许的分析与追问流程</small></span><input type="checkbox" checked={mcpClientDraft.enabled} onChange={(event) => setMcpClientDraft((current) => current && ({ ...current, enabled: event.target.checked }))} /><i /></label>
                <div className="mcp-client-editor__footer"><div><LockKeyhole size={14} /><span>Token 加密保存；远程地址必须使用 HTTPS</span></div><span><button className="secondary-button" onClick={() => setMcpClientDraft(null)} disabled={savingMcpClient}>取消</button><button className="save-settings-button" onClick={() => void saveMcpClient()} disabled={savingMcpClient}><PlugZap size={14} />{savingMcpClient ? "连接中" : "保存并测试"}</button></span></div>
              </div>}
              <div className="settings-notice settings-notice--safe"><ShieldCheck size={15} /><span>外部工具使用独立命名空间；调用参数与结果受大小限制并写入审计日志。</span></div>
            </SettingsSection>
          </>
        )}
      </div>
    </section>
    {updateDialogOpen && (
      <div className="modal-backdrop" onMouseDown={() => !checkingForUpdates && setUpdateDialogOpen(false)}>
        <section className="update-dialog" role="dialog" aria-modal="true" aria-labelledby="update-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
          <header className="dialog-header"><div><span className="section-kicker">SOFTWARE UPDATE</span><h2 id="update-dialog-title">ShowNet 软件更新</h2><p>{runtime.platform} · 当前版本 {runtime.appVersion}</p></div><button className="icon-button" onClick={() => setUpdateDialogOpen(false)} disabled={checkingForUpdates} title="关闭"><X size={18} /></button></header>
          <div className={`update-dialog__body ${updateError ? "has-error" : updateResult?.available ? "has-update" : ""}`}>
            <span className="update-dialog__icon">{checkingForUpdates ? <RefreshCw className="spin" size={24} /> : updateError ? <CircleAlert size={24} /> : updateResult?.available ? <Download size={24} /> : <ShieldCheck size={24} />}</span>
            <div className="update-dialog__content">
              {checkingForUpdates ? <><strong>正在连接更新服务</strong><p>正在为当前平台读取最新稳定版本。</p></> : updateError ? <><strong>暂时无法检查更新</strong><p>当前版本可以继续正常使用。请检查网络或出口代理设置后重试。</p><code>{updateError}</code></> : updateResult?.available ? <><strong>ShowNet {updateResult.latestVersion} 可用</strong><p>可从 {updateResult.currentVersion} 更新到 {updateResult.latestVersion}。</p><div className="update-dialog__meta"><span>目标平台</span><b>{updateResult.platform}</b>{updateResult.publishedAt && <><span>发布时间</span><b>{formatUpdateDate(updateResult.publishedAt)}</b></>}</div>{updateResult.notes && <div className="update-dialog__notes"><span>版本说明</span><p>{updateResult.notes}</p></div>}</> : updateResult ? <><strong>当前已是最新版本</strong><p>ShowNet {updateResult.currentVersion} 已是当前平台的最新稳定版本。</p><div className="update-dialog__meta"><span>目标平台</span><b>{updateResult.platform}</b><span>最新版本</span><b>{updateResult.latestVersion}</b></div></> : null}
            </div>
          </div>
          <footer className="dialog-footer"><div><ShieldCheck size={15} /><span>安装包仍由 macOS 或 Windows 验证发布者签名</span></div><span className="dialog-actions">{updateError && <button className="secondary-button" onClick={() => void checkForUpdates()} disabled={checkingForUpdates}><RefreshCw size={14} />重试</button>}{updateResult?.available && updateResult.downloadUrl && <a className="primary-button" href={updateResult.downloadUrl} target="_blank" rel="noreferrer"><Download size={14} />下载更新<ExternalLink size={13} /></a>}<button className="secondary-button" onClick={() => setUpdateDialogOpen(false)} disabled={checkingForUpdates}>关闭</button></span></footer>
        </section>
      </div>
    )}
    {clearDataOpen && (
      <div className="modal-backdrop" onMouseDown={() => !clearingData && setClearDataOpen(false)}>
        <section className="clear-data-dialog" role="alertdialog" aria-modal="true" aria-labelledby="clear-data-title" onMouseDown={(event) => event.stopPropagation()}>
          <header className="dialog-header"><div><span className="section-kicker">IRREVERSIBLE ACTION</span><h2 id="clear-data-title">确认清除会话数据</h2><p>此操作无法撤销</p></div><button className="icon-button" onClick={() => setClearDataOpen(false)} disabled={clearingData} title="关闭"><X size={18} /></button></header>
          <div className="clear-data-dialog__body">
            <span className="clear-data-dialog__icon"><CircleAlert size={22} /></span>
            <div><strong>将删除 {storageStats.sessionCount} 个会话和 {storageStats.requestCount} 条请求</strong><p>相关 WebSocket 消息、SSE 事件、JS Hook 证据、加密代码片段和 AI 分析报告也会一并删除。</p></div>
            <div className="clear-data-preserved"><ShieldCheck size={15} /><span>Root CA、AI 配置、出口代理、MCP 设置及加密凭据会保留。</span></div>
          </div>
          <footer className="dialog-footer"><div><Database size={15} /><span>完成后自动创建一个空白会话</span></div><span className="dialog-actions"><button className="secondary-button" onClick={() => setClearDataOpen(false)} disabled={clearingData}>取消</button><button className="danger-confirm-button" onClick={clearAllSessionData} disabled={clearingData}>{clearingData ? "正在清除" : "确认清除"}</button></span></footer>
        </section>
      </div>
    )}
    {qrOpen && (
      <div className="modal-backdrop" onMouseDown={() => setQrOpen(false)}>
        <section className="qr-dialog" role="dialog" aria-modal="true" aria-labelledby="qr-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
          <header className="dialog-header"><div><span className="section-kicker">FREE AI CREDIT</span><h2 id="qr-dialog-title">申请一次性 5 美金免费额度</h2><p>加入 QQ 群 553354813 后联系管理员</p></div><button className="icon-button" onClick={() => setQrOpen(false)} title="关闭"><X size={18} /></button></header>
          <div className="qr-dialog__image"><img src={qqGroupQr} alt="QQ群 553354813 完整二维码" /></div>
          <footer className="dialog-footer"><div><MessageCircle size={15} /><span>扫码加群后联系管理员申请</span></div><span className="dialog-actions"><button className="secondary-button" onClick={() => void copyText("553354813", "QQ群号")}><Copy size={14} />复制群号</button><button className="primary-button" onClick={() => setQrOpen(false)}>完成</button></span></footer>
        </section>
      </div>
    )}
    {deviceSetupOpen && (
      <div className="modal-backdrop" onMouseDown={() => setDeviceSetupOpen(false)}>
        <section className="device-setup-dialog" role="dialog" aria-modal="true" aria-labelledby="device-setup-dialog-title" onMouseDown={(event) => event.stopPropagation()}>
          <header className="dialog-header"><div><span className="section-kicker">DEVICE ONBOARDING</span><h2 id="device-setup-dialog-title">设备证书与代理</h2><p>Android 可由电脑自动配置，其他设备可扫码接入</p></div><button className="icon-button" onClick={() => setDeviceSetupOpen(false)} title="关闭"><X size={18} /></button></header>
          <div className="device-setup-modes" aria-label="设备接入方式"><button className={deviceSetupMode === "android" ? "is-active" : ""} onClick={() => setDeviceSetupMode("android")}><Smartphone size={14} />Android 一键</button><button className={deviceSetupMode === "scan" ? "is-active" : ""} onClick={() => setDeviceSetupMode("scan")}><QrCode size={14} />扫码安装</button></div>
          {deviceSetupMode === "android" ? <div className="android-setup-panel">
            <div className="android-setup-toolbar">
              <span className={`android-adb-status ${androidStatus?.adbAvailable ? "is-ready" : ""}`}><i /><span><strong>{androidStatus?.adbAvailable ? "ADB 已就绪" : scanningAndroid ? "正在查找 ADB" : "未找到 ADB"}</strong><small>{androidStatus?.adbPath ?? "自动查找 Android Platform Tools"}</small></span></span>
              <button className="icon-button" onClick={() => void refreshAndroidDevices()} disabled={scanningAndroid} title="重新检测 Android 设备"><RefreshCw className={scanningAndroid ? "spin" : ""} size={15} /></button>
            </div>
            {!androidStatus?.adbAvailable ? <div className="android-setup-empty"><Smartphone size={24} /><strong>安装一次 Android Platform Tools</strong><small>ShowNet 会自动找到 ADB，之后只需连接手机并允许 USB 调试。</small><a href="https://developer.android.com/tools/releases/platform-tools" target="_blank" rel="noreferrer">下载官方工具<ExternalLink size={13} /></a></div> : <>
              <div className="android-device-list">
                {androidStatus.devices.map((device) => <button key={device.serial} className={selectedAndroidSerial === device.serial ? "is-active" : ""} disabled={!device.ready} onClick={() => { setSelectedAndroidSerial(device.serial); setAndroidResult(null); setAndroidError(""); }}><span><Smartphone size={17} /></span><span><strong>{device.model}</strong><small>{device.serial}</small></span><em className={device.ready ? "is-ready" : ""}>{device.ready ? "可配置" : device.state === "unauthorized" ? "等待手机授权" : "设备离线"}</em>{selectedAndroidSerial === device.serial && <Check size={15} />}</button>)}
                {!androidStatus.devices.length && <div className="android-device-empty"><span>未发现设备</span><small>连接 USB，打开开发者选项和 USB 调试后重新检测。</small></div>}
              </div>
              {androidStatus.message && <p className="android-setup-message"><CircleAlert size={13} />{androidStatus.message}</p>}
            </>}
            {androidResult && <div className="android-setup-result"><ShieldCheck size={18} /><span><strong>电脑端配置已完成</strong><small>{androidResult.model} 已设置代理 {androidResult.proxyEndpoint}，证书已推送。请在手机系统页面确认安装 CA。</small></span></div>}
            {androidError && <div className="android-setup-error"><CircleAlert size={14} /><span>{androidError}</span></div>}
            <div className="android-setup-scope"><LockKeyhole size={13} /><span>无需 Root，不写系统分区。Android 7+ 的 App 仍需调试包允许用户证书；证书锁定应用只能采集连接元数据。</span></div>
          </div> : deviceSetupUrl ? <div className="device-setup-dialog__body">
            <div className="device-setup-dialog__qr"><QRCodeCanvas value={deviceSetupUrl} size={208} level="M" marginSize={4} bgColor="#ffffff" fgColor="#183b37" title="ShowNet 设备接入二维码" /></div>
            <div className="device-setup-dialog__details">
              <span className={`device-setup-dialog__status ${runtime.proxyRunning ? "is-online" : ""}`}>{runtime.proxyRunning ? "引导服务在线" : "等待抓包启动"}</span>
              <strong>{runtime.lanAddresses[0]}:{runtime.proxyPort}</strong>
              <small>用 Android 或 iPhone 相机扫码。页面会自动提供对应证书格式，以及当前 Wi-Fi 代理参数。</small>
              <code>{deviceSetupUrl}</code>
            </div>
          </div> : <div className="device-setup-enable"><Wifi size={25} /><strong>开启设备接入</strong><small>ShowNet 将监听当前私网地址；若正在抓包，会自动重启并继续使用当前 Session。</small><button className="primary-button" onClick={() => void saveLanAccess(true)} disabled={savingLanAccess}>{savingLanAccess ? "正在开启" : "开启并生成二维码"}</button></div>}
          <footer className="dialog-footer"><div><ShieldCheck size={15} /><span>{deviceSetupMode === "android" ? "仅配置当前选中的 USB 设备" : `设备范围：${clientAccessModeLabel(effectiveRuntimeAccessMode)}`}</span></div><span className="dialog-actions">{deviceSetupMode === "android" ? <>{androidResult && <button className="secondary-button" onClick={() => void resetAndroidProxy()} disabled={preparingAndroid}><RefreshCw size={14} />恢复设备代理</button>}<button className="primary-button" onClick={() => void prepareAndroidDevice()} disabled={preparingAndroid || scanningAndroid || !selectedAndroidSerial || !androidCaptureReady}>{preparingAndroid ? "正在配置" : !androidCaptureReady ? "先开始抓包" : "一键配置并安装"}</button></> : <>{deviceSetupUrl && <button className="secondary-button" onClick={() => void copyText(deviceSetupUrl, "设备接入地址")}><Copy size={14} />复制地址</button>}<button className="secondary-button" onClick={exportCertificate}><Download size={14} />手动导出</button><button className="primary-button" onClick={() => setDeviceSetupOpen(false)}>完成</button></>}</span></footer>
        </section>
      </div>
    )}
    </>
  );
}

function SettingsHeader({ kicker, title }: { kicker: string; title: string }) {
  return <header className="settings-content__header"><span className="section-kicker">{kicker}</span><h2>{title}</h2></header>;
}

function SettingsSection({ title, children, defaultOpen = false }: { title: string; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return <details className="settings-section" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}><summary><h3>{title}</h3><ChevronDown size={15} /></summary><div className="settings-section__body">{children}</div></details>;
}

function formatStorageBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatUpdateDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}
