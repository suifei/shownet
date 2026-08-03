import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Fingerprint,
  GitCompare,
  KeyRound,
  LayoutDashboard,
  Network,
  RefreshCw,
  Settings2,
  Shield,
  Shuffle,
  Sparkles,
  Workflow,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  CAPABILITY_CATALOG,
  CONSOLE_TAB_GUIDES,
  WORKFLOW_STAGES,
  honestyBanner,
  suggestWorkflowStage,
  tabGuide,
  type ConsoleTabId,
  type WorkflowPhaseId,
} from "../advancedConsoleCapabilities";
import type {
  BrowserHookEvent,
  OutboundTlsProfileStatus,
  PxDecodeResult,
  PxEvidenceItem,
  PxSettings,
  RequestListItem,
  RuntimeStatus,
  TlsFingerprintRecord,
} from "../types";

const TAB_ICONS: Record<ConsoleTabId, typeof Network> = {
  overview: LayoutDashboard,
  capture: Network,
  hooks: Workflow,
  rules: Shuffle,
  fingerprint: Fingerprint,
  "px-replay": RefreshCw,
  "px-compare": GitCompare,
  "px-tamper": KeyRound,
  recaptcha: Shield,
  config: Settings2,
};

/** Ordered tabs for the console nav (overview first). */
const TAB_ORDER: ConsoleTabId[] = [
  "overview",
  "capture",
  "hooks",
  "rules",
  "fingerprint",
  "px-replay",
  "px-compare",
  "px-tamper",
  "recaptcha",
  "config",
];

interface AdvancedConsoleViewProps {
  sessionId?: string | null;
  requests: RequestListItem[];
  hookCount: number;
  runtime?: RuntimeStatus | null;
  onOpenTraffic: () => void;
  onOpenBrowser: () => void;
  onOpenRules: () => void;
  onOpenSettings: () => void;
  onOpenAnalysis?: () => void;
  onNotify: (message: string) => void;
}

export function AdvancedConsoleView({
  sessionId,
  requests,
  hookCount,
  runtime,
  onOpenTraffic,
  onOpenBrowser,
  onOpenRules,
  onOpenSettings,
  onOpenAnalysis,
  onNotify,
}: AdvancedConsoleViewProps) {
  const [tab, setTab] = useState<ConsoleTabId>("overview");
  const [pxSettings, setPxSettings] = useState<PxSettings>({ decryptEnabled: false, interceptEcData: false });
  const [outboundTls, setOutboundTls] = useState<OutboundTlsProfileStatus | null>(null);
  const [hooks, setHooks] = useState<BrowserHookEvent[]>([]);
  const [pxEvidence, setPxEvidence] = useState<PxEvidenceItem[]>([]);
  const [selectedPx, setSelectedPx] = useState<string | null>(null);
  const [compareA, setCompareA] = useState<string | null>(null);
  const [compareB, setCompareB] = useState<string | null>(null);
  const [decode, setDecode] = useState<PxDecodeResult | null>(null);
  const [fingerprints, setFingerprints] = useState<TlsFingerprintRecord[]>([]);
  const [saving, setSaving] = useState(false);

  const packetCount = requests.length;
  const proxyPort = runtime?.proxyPort ?? 8888;
  const activeHookCount = hookCount || hooks.length;
  const guide = tabGuide(tab);

  const suggestedPhase = useMemo(
    () =>
      suggestWorkflowStage({
        requestCount: packetCount,
        hookCount: activeHookCount,
        fingerprintCount: fingerprints.length,
        pxCount: pxEvidence.length,
      }),
    [packetCount, activeHookCount, fingerprints.length, pxEvidence.length],
  );

  const load = useCallback(async () => {
    if (!isTauri()) return;
    try {
      const [px, tls] = await Promise.all([
        invoke<PxSettings>("get_px_settings"),
        invoke<OutboundTlsProfileStatus>("get_outbound_tls_profile"),
      ]);
      setPxSettings(px);
      setOutboundTls(tls);
      if (sessionId) {
        const [hookList, evidence, fps] = await Promise.all([
          invoke<BrowserHookEvent[]>("list_browser_hooks", { sessionId, limit: 500 }),
          invoke<PxEvidenceItem[]>("list_px_evidence", { sessionId, limit: 200 }),
          invoke<{
            inboundFingerprints?: Array<{ fingerprint: TlsFingerprintRecord }>;
          }>("get_tls_fingerprints", { sessionId }),
        ]);
        setHooks(hookList);
        setPxEvidence(evidence);
        setFingerprints(
          (fps.inboundFingerprints ?? []).map(
            (row: { fingerprint: TlsFingerprintRecord }) => row.fingerprint,
          ),
        );
      }
    } catch (error) {
      onNotify(`高级控制台加载失败：${String(error)}`);
    }
  }, [sessionId, onNotify]);

  useEffect(() => {
    void load();
  }, [load]);

  const recaptchaHits = useMemo(
    () =>
      requests.filter((r) => {
        const blob = `${r.host} ${r.path}`.toLowerCase();
        return blob.includes("recaptcha") || blob.includes("grecaptcha");
      }),
    [requests],
  );

  const updatePx = async (patch: Partial<PxSettings>) => {
    if (!isTauri()) return;
    setSaving(true);
    try {
      const next = await invoke<PxSettings>("set_px_settings", {
        decryptEnabled: patch.decryptEnabled,
        interceptEcData: patch.interceptEcData,
      });
      setPxSettings(next);
      onNotify(
        `PX 设置已更新：解密=${next.decryptEnabled ? "开" : "关"} · 拦截ecData=${next.interceptEcData ? "开" : "关"}`,
      );
    } catch (error) {
      onNotify(`更新 PX 设置失败：${String(error)}`);
    } finally {
      setSaving(false);
    }
  };

  const runDecode = async (requestId: string) => {
    if (!isTauri()) return;
    try {
      const result = await invoke<PxDecodeResult>("decode_px_payload", { requestId });
      setDecode(result);
      setSelectedPx(requestId);
    } catch (error) {
      onNotify(`PX 解码失败：${String(error)}`);
    }
  };

  const setTlsProfile = async (profile: string) => {
    if (!isTauri()) return;
    setSaving(true);
    try {
      const status = await invoke<OutboundTlsProfileStatus>("set_outbound_tls_profile", { profile });
      setOutboundTls(status);
      onNotify(
        `出站 TLS → ${status.presetId ?? status.profile}（${status.browserFamily ?? ""} ${status.browserMajorVersion ?? ""}）`,
      );
    } catch (error) {
      onNotify(String(error));
    } finally {
      setSaving(false);
    }
  };

  const setAutoInbound = async (enabled: boolean) => {
    if (!isTauri()) return;
    try {
      const status = await invoke<OutboundTlsProfileStatus>("set_outbound_tls_auto_from_inbound", {
        enabled,
      });
      setOutboundTls(status);
      onNotify(`入站自动选档：${enabled ? "开" : "关"}`);
    } catch (error) {
      onNotify(String(error));
    }
  };

  const goPhase = (phase: WorkflowPhaseId) => {
    const map: Record<WorkflowPhaseId, ConsoleTabId> = {
      capture: "capture",
      evidence: "fingerprint",
      analysis: "overview",
      export: "overview",
    };
    if (phase === "analysis" && onOpenAnalysis) {
      onOpenAnalysis();
      return;
    }
    if (phase === "export" && onOpenAnalysis) {
      onOpenAnalysis();
      return;
    }
    setTab(map[phase]);
  };

  return (
    <div className="advanced-console">
      <header className="advanced-console-hero">
        <div className="advanced-console-hero-main">
          <h2>
            <Activity size={18} aria-hidden /> MITM 高级控制台
          </h2>
          <p className="advanced-console-lead">
            抓包配置与证据中枢：和<strong>流量</strong>、<strong>浏览器</strong>、<strong>设置</strong>、
            <strong>AI 分析</strong>串联。按阶段使用，避免空会话上空调参数。
          </p>
          <p className="advanced-console-honesty" role="note">
            {honestyBanner()}
          </p>
        </div>
        <div className="advanced-console-stats" aria-label="会话状态">
          <span>
            代理端口 <strong>{proxyPort}</strong>
          </span>
          <span>
            请求 <strong>{packetCount}</strong>
          </span>
          <span>
            Hook <strong>{activeHookCount}</strong>
          </span>
          <span>
            指纹 <strong>{fingerprints.length}</strong>
          </span>
          <span>
            PX 证据 <strong>{pxEvidence.length}</strong>
          </span>
          <span>
            出站预置{" "}
            <strong>
              <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "—"}</code>
            </strong>
          </span>
          <span>
            JA3 对等 <strong className={outboundTls?.ja3Parity ? "is-ok" : "is-warn"}>{outboundTls?.ja3Parity ? "是" : "否"}</strong>
          </span>
        </div>
        <div className="advanced-console-toggles">
          <label className={pxSettings.decryptEnabled ? "is-on" : ""}>
            <span>PX 解密</span>
            <input
              type="checkbox"
              checked={pxSettings.decryptEnabled}
              disabled={saving}
              onChange={(e) => void updatePx({ decryptEnabled: e.target.checked })}
            />
            <em>{pxSettings.decryptEnabled ? "已启用" : "已禁用"}</em>
          </label>
          <label className={pxSettings.interceptEcData ? "is-on" : ""}>
            <span>拦截 ecData</span>
            <input
              type="checkbox"
              checked={pxSettings.interceptEcData}
              disabled={saving}
              onChange={(e) => void updatePx({ interceptEcData: e.target.checked })}
            />
            <em>{pxSettings.interceptEcData ? "已启用" : "已禁用"}</em>
          </label>
        </div>
      </header>

      <nav className="advanced-workflow" aria-label="推荐工作流：抓包 → 证据 → 分析 → 导出">
        {WORKFLOW_STAGES.map((stage, index) => (
          <button
            key={stage.id}
            type="button"
            className={`advanced-workflow-step${suggestedPhase === stage.id ? " is-suggested" : ""}`}
            onClick={() => goPhase(stage.id)}
          >
            <span className="advanced-workflow-num">{stage.step}</span>
            <span className="advanced-workflow-body">
              <strong>{stage.label}</strong>
              <small>{stage.summary}</small>
              <em>{stage.beginnerTip}</em>
            </span>
            {index < WORKFLOW_STAGES.length - 1 && (
              <ArrowRight className="advanced-workflow-arrow" size={14} aria-hidden />
            )}
          </button>
        ))}
      </nav>

      <nav className="advanced-console-tabs" aria-label="高级控制台分区">
        {TAB_ORDER.map((id) => {
          const meta = tabGuide(id);
          const Icon = TAB_ICONS[id];
          const badge =
            id === "capture"
              ? packetCount
              : id === "hooks"
                ? activeHookCount
                : id === "fingerprint"
                  ? fingerprints.length
                  : id === "px-replay" || id === "px-compare" || id === "px-tamper"
                    ? pxEvidence.length
                    : id === "recaptcha"
                      ? recaptchaHits.length
                      : null;
          return (
            <button
              key={id}
              type="button"
              className={tab === id ? "is-active" : ""}
              data-phase={meta.phase}
              onClick={() => setTab(id)}
            >
              <Icon size={14} aria-hidden />
              {meta.label}
              {badge !== null && badge > 0 ? <span className="advanced-tab-badge">{badge}</span> : null}
            </button>
          );
        })}
      </nav>

      <section className="advanced-console-panel">
        <div className="advanced-panel-guide" data-tab={tab}>
          <div>
            <span className="advanced-phase-pill" data-phase={guide.phase}>
              {WORKFLOW_STAGES.find((s) => s.id === guide.phase)?.shortLabel ?? guide.phase}
            </span>
            <h3>{guide.label}</h3>
          </div>
          <dl className="advanced-guide-grid">
            <div>
              <dt>何时用</dt>
              <dd>{guide.whenToUse}</dd>
            </div>
            <div>
              <dt>最佳实践</dt>
              <dd>{guide.bestPractice}</dd>
            </div>
            <div>
              <dt>下一步</dt>
              <dd>{guide.nextStep}</dd>
            </div>
          </dl>
        </div>

        {tab === "overview" && (
          <div className="advanced-panel-card">
            <h4>能力分工：抓包过程 vs AI 分析过程</h4>
            <p className="hint">
              下列能力与真实 IPC / MCP 工具一致；AI 默认只读取证，改出站预置与 PX 开关在控制台人工操作。
            </p>
            <div className="advanced-capability-columns">
              <div>
                <h5>
                  <Network size={14} aria-hidden /> 抓包过程
                </h5>
                <ul className="advanced-capability-list">
                  {CAPABILITY_CATALOG.filter((c) => c.phase === "capture" || c.phase === "both").map((c) => (
                    <li key={c.id}>
                      <strong>{c.name}</strong>
                      <span>{c.when}</span>
                      <code>{c.entryPoints.filter((p) => p.startsWith("shownet_") || !p.includes(":")).slice(0, 3).join(" · ")}</code>
                      {c.honesty ? <em>{c.honesty}</em> : null}
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h5>
                  <Sparkles size={14} aria-hidden /> AI 分析过程
                </h5>
                <ul className="advanced-capability-list">
                  {CAPABILITY_CATALOG.filter((c) => c.phase === "analysis" || c.phase === "both").map((c) => (
                    <li key={c.id}>
                      <strong>{c.name}</strong>
                      <span>{c.when}</span>
                      <code>{c.entryPoints.filter((p) => p.startsWith("shownet_")).join(" · ") || c.entryPoints.slice(0, 2).join(" · ")}</code>
                      {c.honesty ? <em>{c.honesty}</em> : null}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <div className="advanced-quick-actions">
              <button type="button" className="primary-button" onClick={onOpenBrowser}>
                内嵌浏览器抓包
              </button>
              <button type="button" className="secondary-button" onClick={onOpenTraffic}>
                打开流量
              </button>
              {onOpenAnalysis ? (
                <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  进入 AI 分析
                </button>
              ) : null}
              <button type="button" className="secondary-button" onClick={() => setTab("config")}>
                出站 TLS 配置
              </button>
            </div>
          </div>
        )}

        {tab === "capture" && (
          <div className="advanced-panel-card">
            <p>
              当前会话请求 <strong>{packetCount}</strong> 条。完整列表与报文检视在「流量」工作台。
            </p>
            <div className="advanced-quick-actions">
              <button type="button" className="primary-button" onClick={onOpenTraffic}>
                打开流量视图
              </button>
              <button type="button" className="secondary-button" onClick={onOpenBrowser}>
                内嵌浏览器
              </button>
            </div>
            {packetCount === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {requests.slice(0, 12).map((r) => (
                  <li key={r.id}>
                    <code>{r.method}</code> {r.host}
                    {r.path}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {tab === "hooks" && (
          <div className="advanced-panel-card">
            <p>
              会话内浏览器 Hook 事件 <strong>{hooks.length}</strong> 条（列表计数 {activeHookCount}）。
            </p>
            <div className="advanced-quick-actions">
              <button type="button" className="primary-button" onClick={onOpenBrowser}>
                打开浏览器 Hook 面板
              </button>
              {onOpenAnalysis ? (
                <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  用 AI 读 Hook / 加密
                </button>
              ) : null}
            </div>
            {hooks.length === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {hooks.slice(0, 20).map((h) => (
                  <li key={h.id}>
                    <strong>{h.kind}</strong> {h.name} · {h.timestamp}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {tab === "rules" && (
          <div className="advanced-panel-card">
            <p>通用重写 / 断点 / 镜像规则在请求实验室的规则工作台中编辑。</p>
            <button type="button" className="primary-button" onClick={onOpenRules}>
              打开替换规则工作台
            </button>
            {pxSettings.interceptEcData && (
              <p className="hint">已开启「拦截 ecData」：含 ecData 的请求会在分析中标记；可配合断点规则改包。</p>
            )}
          </div>
        )}

        {tab === "fingerprint" && (
          <div className="advanced-panel-card">
            <div className="advanced-tls-status">
              <div>
                <span>引擎</span>
                <strong>
                  <code>{outboundTls?.engine ?? "rustls"}</code>
                </strong>
              </div>
              <div>
                <span>预置</span>
                <strong>
                  <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "default"}</code>
                </strong>
              </div>
              <div>
                <span>浏览器标签</span>
                <strong>
                  {outboundTls?.browserFamily
                    ? `${outboundTls.browserFamily} ${outboundTls.browserMajorVersion ?? ""}`
                    : "—"}
                </strong>
              </div>
              <div>
                <span>ja3Parity</span>
                <strong className={outboundTls?.ja3Parity ? "is-ok" : "is-warn"}>
                  {String(outboundTls?.ja3Parity ?? false)}
                </strong>
              </div>
              <div>
                <span>supportsFullBrowserJa3</span>
                <strong className="is-warn">{String(outboundTls?.supportsFullBrowserJa3 ?? false)}</strong>
              </div>
            </div>
            <p className="hint">{outboundTls?.note ?? honestyBanner()}</p>
            <div className="advanced-quick-actions">
              <button type="button" className="secondary-button" onClick={() => setTab("config")}>
                修改出站预置
              </button>
              {onOpenAnalysis ? (
                <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  AI 读取指纹（shownet_get_tls_fingerprints）
                </button>
              ) : null}
            </div>
            {fingerprints.length === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {fingerprints.slice(0, 15).map((fp, index) => (
                  <li key={`${fp.inbound.ja3}-${index}`}>
                    入站 JA3 <code>{fp.inbound.ja3.slice(0, 16)}…</code> · 出站 {fp.outbound.profile} /{" "}
                    {fp.outbound.applicationProtocol ?? fp.outbound.negotiatedAlpn ?? "—"} ·{" "}
                    {fp.outbound.selectedFromInbound ? "入站映射" : fp.outbound.mode}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {(tab === "px-replay" || tab === "px-compare" || tab === "px-tamper") && (
          <div className="advanced-panel-card">
            <p>
              检测到 PX/HUMAN 相关请求 <strong>{pxEvidence.length}</strong> 条。
              <span className="hint"> 解码为结构解析，非无密钥硬破。</span>
            </p>
            {pxEvidence.length === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {pxEvidence.map((item) => (
                  <li key={item.requestId}>
                    <button type="button" className="linkish" onClick={() => void runDecode(item.requestId)}>
                      {item.method} {item.host}
                      {item.path}
                    </button>
                    <small>{item.markers.join(", ")}</small>
                    {tab === "px-compare" && (
                      <span className="row-actions">
                        <button type="button" onClick={() => setCompareA(item.requestId)}>
                          A
                        </button>
                        <button type="button" onClick={() => setCompareB(item.requestId)}>
                          B
                        </button>
                      </span>
                    )}
                    {tab === "px-tamper" && (
                      <button type="button" onClick={onOpenRules}>
                        生成改写规则
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {tab === "px-compare" && (
              <p>
                对比: A=<code>{compareA ?? "—"}</code> B=<code>{compareB ?? "—"}</code>
                （在流量/实验室中打开两条请求做字段 diff）
              </p>
            )}
            {decode && selectedPx === decode.requestId && (
              <details className="advanced-details" open>
                <summary>结构解码结果（可折叠）</summary>
                <pre className="advanced-json">{JSON.stringify(decode, null, 2)}</pre>
              </details>
            )}
          </div>
        )}

        {tab === "recaptcha" && (
          <div className="advanced-panel-card">
            <p>
              会话中疑似 reCAPTCHA 请求 <strong>{recaptchaHits.length}</strong> 条。完整解题走 Web 风控 Lab /
              视觉验证码工具。
            </p>
            {recaptchaHits.length === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {recaptchaHits.slice(0, 20).map((r) => (
                  <li key={r.id}>
                    {r.method} {r.host}
                    {r.path}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {tab === "config" && (
          <div className="advanced-panel-card">
            <div className="advanced-config-grid">
              <div>
                <h4>出站 ClientHello 预置</h4>
                <p className="hint" style={{ marginBottom: 8 }}>
                  当前: <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "—"}</code>
                  {outboundTls?.browserFamily
                    ? ` · ${outboundTls.browserFamily} ${outboundTls.browserMajorVersion ?? ""}`
                    : ""}
                </p>
                <label className="checkbox-row advanced-select-block">
                  <span>版本化预置（family + major）</span>
                  <select
                    disabled={saving}
                    value={outboundTls?.presetId ?? "chrome150"}
                    onChange={(e) => void setTlsProfile(e.target.value)}
                  >
                    {(outboundTls?.presets ?? []).length > 0
                      ? (outboundTls?.presets ?? []).map((preset) => (
                          <option key={preset.id} value={preset.id}>
                            {preset.label} ({preset.id})
                          </option>
                        ))
                      : (outboundTls?.profiles ?? []).map((id) => (
                          <option key={id} value={id}>
                            {id}
                          </option>
                        ))}
                  </select>
                </label>
                <div className="chip-row">
                  {(outboundTls?.presets ?? [])
                    .filter((p) =>
                      ["default", "chrome150", "chrome149", "firefox136", "safari-ios18", "edge150"].includes(
                        p.id,
                      ),
                    )
                    .map((preset) => (
                      <button
                        key={preset.id}
                        type="button"
                        className={outboundTls?.presetId === preset.id ? "is-active" : ""}
                        disabled={saving}
                        onClick={() => void setTlsProfile(preset.id)}
                      >
                        {preset.id}
                      </button>
                    ))}
                  {(outboundTls?.presets ?? []).length === 0 &&
                    ["default", "chrome150", "firefox136", "safari-ios18"].map((profile) => (
                      <button
                        key={profile}
                        type="button"
                        className={
                          outboundTls?.presetId === profile || outboundTls?.profile === profile
                            ? "is-active"
                            : ""
                        }
                        disabled={saving}
                        onClick={() => void setTlsProfile(profile)}
                      >
                        {profile}
                      </button>
                    ))}
                </div>
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={Boolean(outboundTls?.autoFromInbound)}
                    onChange={(e) => void setAutoInbound(e.target.checked)}
                  />
                  根据入站 JA3/JA4 自动选择出站预置（真实变更 rustls 套件顺序）
                </label>
                <p className="hint">
                  浏览器 JA3 全量对齐需要 BoringSSL/curl-impersonate 级栈（当前 engine=
                  {outboundTls?.engine ?? "rustls"}，supportsFullBrowserJa3=
                  {String(outboundTls?.supportsFullBrowserJa3 ?? false)}，ja3Parity=
                  {String(outboundTls?.ja3Parity ?? false)}）。版本预置仍会改变出站 ClientHello
                  的可测配方 / JA3。
                </p>
              </div>
              <div>
                <h4>系统设置</h4>
                <p className="hint">端口、Root CA 一键安装、HTTPS 拦截模式在设置页。</p>
                <button type="button" className="primary-button" onClick={onOpenSettings}>
                  打开设置（端口 / CA / 拦截模式）
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
