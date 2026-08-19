import { useCallback, useEffect, useMemo, useState } from "react";
import { t } from "../i18n.ts";
import {
  Activity,
  ArrowRight,
  Fingerprint,
  GitCompare,
  LayoutDashboard,
  Network,
  Settings2,
  Shield,
  Shuffle,
  Sparkles,
  Workflow,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import {
  CAPABILITY_CATALOG,
  WORKFLOW_STAGES,
  honestyBanner,
  suggestWorkflowStage,
  tabGuide,
  type ConsoleTabId,
  type WorkflowPhaseId,
} from "../advancedConsoleCapabilities";
import { displayedClientHelloPresetId } from "../clientHelloPreset.ts";
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
  px: GitCompare,
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
  "px",
  "recaptcha",
  "config",
];

/** What you can do with a PX evidence row. Was three separate console tabs. */
const PX_MODE_KEYS = [
  { id: "decode" as const, label: "advanced.px.decode" as const, hint: "advanced.px.decodeHint" as const },
  { id: "compare" as const, label: "advanced.px.compare" as const, hint: "advanced.px.compareHint" as const },
  { id: "tamper" as const, label: "advanced.px.tamper" as const, hint: "advanced.px.tamperHint" as const },
];
type PxMode = (typeof PX_MODE_KEYS)[number]["id"];

/** Short labels for the horizontal tab strip (full name stays in panel title). */
const TAB_SHORT_LABEL_KEYS: Record<ConsoleTabId, "advanced.tab.overview" | "advanced.tab.capture" | "advanced.tab.rules" | "advanced.tab.fingerprint" | "advanced.tab.px" | "advanced.tab.config" | null> = {
  overview: "advanced.tab.overview",
  capture: "advanced.tab.capture",
  hooks: null,
  rules: "advanced.tab.rules",
  fingerprint: "advanced.tab.fingerprint",
  px: "advanced.tab.px",
  recaptcha: null,
  config: "advanced.tab.config",
};

interface AdvancedConsoleViewProps {
  sessionId?: string | null;
  requests: RequestListItem[];
  hookCount: number;
  runtime?: RuntimeStatus | null;
  onOpenTraffic: () => void;
  onOpenBrowser: () => void;
  onOpenRules: () => void;
  onOpenSettings: () => void;
  onOpenAnalysis: () => void;
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
  const [pxMode, setPxMode] = useState<PxMode>("decode");
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
    // Analysis and export both live in the AI view; the console has no
    // export surface of its own.
    if (phase === "analysis" || phase === "export") {
      onOpenAnalysis();
      return;
    }
    setTab(map[phase]);
  };

  const suggestedStage = WORKFLOW_STAGES.find((stage) => stage.id === suggestedPhase) ?? WORKFLOW_STAGES[0];

  return (
    <div className="advanced-console">
      <header className="advanced-console-hero">
        <div className="advanced-console-hero-top">
          <div className="advanced-console-hero-main">
            <h2>
              <Activity size={18} aria-hidden /> {t("advanced.title")}
            </h2>
            <p className="advanced-console-lead">
              {t("advanced.lead")}
            </p>
          </div>
          <div className="advanced-console-toggles">
            <label className={pxSettings.decryptEnabled ? "is-on" : ""}>
              <span>{t("advanced.pxDecrypt")}</span>
              <input
                type="checkbox"
                checked={pxSettings.decryptEnabled}
                disabled={saving}
                onChange={(e) => void updatePx({ decryptEnabled: e.target.checked })}
              />
              <em>{pxSettings.decryptEnabled ? t("common.on") : t("common.off")}</em>
            </label>
            <label className={pxSettings.interceptEcData ? "is-on" : ""}>
              <span>{t("advanced.interceptEc")}</span>
              <input
                type="checkbox"
                checked={pxSettings.interceptEcData}
                disabled={saving}
                onChange={(e) => void updatePx({ interceptEcData: e.target.checked })}
              />
              <em>{pxSettings.interceptEcData ? t("common.on") : t("common.off")}</em>
            </label>
          </div>
        </div>
        <div className="advanced-console-stats" aria-label={t("advanced.sessionState")}>
          <span>
            {t("advanced.port")} <strong>{proxyPort}</strong>
          </span>
          <span>
            {t("advanced.requests")} <strong>{packetCount}</strong>
          </span>
          <span>
            Hook <strong>{activeHookCount}</strong>
          </span>
          <span>
            {t("advanced.fingerprints")} <strong>{fingerprints.length}</strong>
          </span>
          <span>
            PX <strong>{pxEvidence.length}</strong>
          </span>
          <span>
            {t("advanced.preset")}{" "}
            <strong>
              <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "—"}</code>
            </strong>
          </span>
          <span>
            {t("advanced.ja3Parity")}{" "}
            <strong className={outboundTls?.ja3Parity ? "is-ok" : "is-warn"}>
              {outboundTls?.ja3Parity ? t("common.yes") : t("common.no")}
            </strong>
          </span>
        </div>
        <p
          className="advanced-console-honesty"
          role="note"
          title={honestyBanner(outboundTls)}
        >
          {honestyBanner(outboundTls)}
        </p>
      </header>

      {/* Compact step strip — titles only; long tips live under the strip / in panel guide */}
      <div className="advanced-workflow-block">
        <nav className="advanced-workflow" aria-label={t("advanced.workflowAria")}>
          {WORKFLOW_STAGES.map((stage, index) => (
            <button
              key={stage.id}
              type="button"
              className={`advanced-workflow-step${suggestedPhase === stage.id ? " is-suggested" : ""}`}
              onClick={() => goPhase(stage.id)}
              title={`${stage.summary}\n${stage.beginnerTip}`}
            >
              <span className="advanced-workflow-num">{stage.step}</span>
              <strong className="advanced-workflow-label">{stage.label}</strong>
              {index < WORKFLOW_STAGES.length - 1 && (
                <ArrowRight className="advanced-workflow-arrow" size={14} aria-hidden />
              )}
            </button>
          ))}
        </nav>
        <p className="advanced-workflow-tip" role="status">
          <span className="advanced-workflow-tip-label">{t("advanced.suggest", { label: suggestedStage.label })}</span>
          {suggestedStage.beginnerTip}
        </p>
      </div>

      <nav className="advanced-console-tabs" aria-label={t("advanced.tabsAria")}>
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
                  : id === "px"
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
              title={meta.label}
              onClick={() => setTab(id)}
            >
              <Icon size={14} aria-hidden />
              <span>{TAB_SHORT_LABEL_KEYS[id] ? t(TAB_SHORT_LABEL_KEYS[id]!) : id === "hooks" ? "Hook" : "reCAPTCHA"}</span>
              {badge !== null && badge > 0 ? <span className="advanced-tab-badge">{badge}</span> : null}
            </button>
          );
        })}
      </nav>

      <section className="advanced-console-panel">
        <div className="advanced-panel-guide" data-tab={tab}>
          <div className="advanced-panel-guide-head">
            <span className="advanced-phase-pill" data-phase={guide.phase}>
              {WORKFLOW_STAGES.find((s) => s.id === guide.phase)?.shortLabel ?? guide.phase}
            </span>
            <h3>{guide.label}</h3>
          </div>
          <p className="advanced-panel-guide-next">
            <strong>{t("advanced.next")}</strong>
            <span>{guide.nextStep}</span>
          </p>
          <details className="advanced-panel-guide-more">
            <summary>{t("advanced.whenBest")}</summary>
            <dl className="advanced-guide-grid">
              <div>
                <dt>{t("advanced.when")}</dt>
                <dd>{guide.whenToUse}</dd>
              </div>
              <div>
                <dt>{t("advanced.best")}</dt>
                <dd>{guide.bestPractice}</dd>
              </div>
            </dl>
          </details>
        </div>

        {tab === "overview" && (
          <div className="advanced-panel-card">
            <h4>{t("advanced.splitTitle")}</h4>
            <p className="hint">
              {t("advanced.splitHint")}
            </p>
            <div className="advanced-capability-columns">
              <div>
                <h5>
                  <Network size={14} aria-hidden /> {t("advanced.capturePhase")}
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
                  <Sparkles size={14} aria-hidden /> {t("advanced.analysisPhase")}
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
                {t("advanced.openBrowserCapture")}
              </button>
              <button type="button" className="secondary-button" onClick={onOpenTraffic}>
                {t("advanced.openTraffic")}
              </button>
              <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  {t("advanced.openAnalysis")}
                </button>
              <button type="button" className="secondary-button" onClick={() => setTab("config")}>
                {t("advanced.outboundTlsConfig")}
              </button>
            </div>
          </div>
        )}

        {tab === "capture" && (
          <div className="advanced-panel-card">
            <p>
              {t("advanced.sessionRequests", { count: packetCount })}
            </p>
            <div className="advanced-quick-actions">
              <button type="button" className="primary-button" onClick={onOpenTraffic}>
                {t("advanced.openTrafficView")}
              </button>
              <button type="button" className="secondary-button" onClick={onOpenBrowser}>
                {t("advanced.embeddedBrowser")}
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
              {t("advanced.sessionHooks", { count: hooks.length, listed: activeHookCount })}
            </p>
            <div className="advanced-quick-actions">
              <button type="button" className="primary-button" onClick={onOpenBrowser}>
                {t("advanced.openHookPanel")}
              </button>
              <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  {t("advanced.readHooksAi")}
                </button>
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
            <p>{t("advanced.rulesHint")}</p>
            <p className="advanced-empty">{guide.emptyHint}</p>
            <button type="button" className="primary-button" onClick={onOpenRules}>
              {t("advanced.openRules")}
            </button>
            {pxSettings.interceptEcData && (
              <p className="hint">{t("advanced.ecDataOn")}</p>
            )}
          </div>
        )}

        {tab === "fingerprint" && (
          <div className="advanced-panel-card">
            <div className="advanced-tls-status">
              <div>
                <span>{t("advanced.engine")}</span>
                <strong>
                  <code>{outboundTls?.engine ?? "rustls"}</code>
                </strong>
              </div>
              <div>
                <span>{t("advanced.preset")}</span>
                <strong>
                  <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "default"}</code>
                </strong>
              </div>
              <div>
                <span>{t("advanced.browserTag")}</span>
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
                <span>{t("advanced.measuredAlign")}</span>
                <strong className="is-warn">
                  <code>{outboundTls?.alignmentLevel ?? "recipe"}</code>
                </strong>
              </div>
              <div>
                <span>{t("advanced.goldenCap")}</span>
                <strong title={outboundTls?.goldenAuthorisedClaim}>
                  <code>{outboundTls?.goldenAuthorisedCeiling ?? "recipe"}</code>
                </strong>
              </div>
              <div>
                <span>supportsFullBrowserJa3</span>
                <strong className={outboundTls?.supportsFullBrowserJa3 ? "is-ok" : "is-warn"}>
                  {String(outboundTls?.supportsFullBrowserJa3 ?? false)}
                </strong>
              </div>
            </div>
            <p className="hint">
              {outboundTls?.alignmentClaim ?? outboundTls?.note ?? honestyBanner(outboundTls)}
              {outboundTls?.goldenAuthorisedClaim
                ? ` · ${outboundTls.goldenAuthorisedClaim}`
                : ""}
            </p>
            <div className="advanced-quick-actions">
              <button type="button" className="secondary-button" onClick={() => setTab("config")}>
                {t("advanced.changePreset")}
              </button>
              <button type="button" className="secondary-button" onClick={onOpenAnalysis}>
                  {t("advanced.aiReadFp")}
                </button>
            </div>
            {fingerprints.length === 0 ? (
              <p className="advanced-empty">{guide.emptyHint}</p>
            ) : (
              <ul className="advanced-mini-list">
                {fingerprints.slice(0, 15).map((fp, index) => (
                  <li key={`${fp.inbound.ja3}-${index}`}>
                    {t("advanced.inboundJa3")} <code>{fp.inbound.ja3.slice(0, 16)}…</code> · {t("advanced.outbound")} {fp.outbound.profile} /{" "}
                    {fp.outbound.applicationProtocol ?? fp.outbound.negotiatedAlpn ?? "—"} ·{" "}
                    {fp.outbound.selectedFromInbound ? t("advanced.inboundMap") : fp.outbound.mode}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {tab === "px" && (
          <div className="advanced-panel-card">
            {/* One evidence list, three things you can do with it. These were
                three sibling tabs rendering the same body and the same badge,
                differing only by which per-row action they showed. */}
            <div className="px-mode-switch" role="tablist" aria-label={t("advanced.px.modes")}>
              {PX_MODE_KEYS.map((mode) => (
                <button
                  key={mode.id}
                  type="button"
                  role="tab"
                  aria-selected={pxMode === mode.id}
                  className={pxMode === mode.id ? "is-active" : ""}
                  onClick={() => setPxMode(mode.id)}
                  title={t(mode.hint)}
                >
                  {t(mode.label)}
                </button>
              ))}
            </div>
            <p>
              PX/HUMAN <strong>{pxEvidence.length}</strong>
              <span className="hint"> {t((PX_MODE_KEYS.find((mode) => mode.id === pxMode) ?? PX_MODE_KEYS[0]).hint)}</span>
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
                    {pxMode === "compare" && (
                      <span className="row-actions">
                        <button type="button" className={compareA === item.requestId ? "is-active" : ""} onClick={() => setCompareA(item.requestId)} title={t("advanced.markA")}>
                          A
                        </button>
                        <button type="button" className={compareB === item.requestId ? "is-active" : ""} onClick={() => setCompareB(item.requestId)} title={t("advanced.markB")}>
                          B
                        </button>
                      </span>
                    )}
                    {pxMode === "tamper" && (
                      <button type="button" onClick={onOpenRules}>
                        {t("advanced.makeRewrite")}
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            )}
            {pxMode === "compare" && pxEvidence.length > 0 && (
              <p>
                {t("advanced.compareAB", { a: compareA ?? "—", b: compareB ?? "—" })}
                {compareA && compareB
                  ? t("advanced.compareReady")
                  : t("advanced.compareNeed")}
              </p>
            )}
            {decode && selectedPx === decode.requestId && (
              <details className="advanced-details" open>
                <summary>{t("advanced.decodeResult")}</summary>
                <pre className="advanced-json">{JSON.stringify(decode, null, 2)}</pre>
              </details>
            )}
          </div>
        )}

        {tab === "recaptcha" && (
          <div className="advanced-panel-card">
            <p>
              {t("advanced.recaptchaHits", { count: recaptchaHits.length })}
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
                <h4>{t("advanced.cap.outboundTls")}</h4>
                <p className="hint" style={{ marginBottom: 8 }}>
                  {t("advanced.current")}: <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "—"}</code>
                  {outboundTls?.browserFamily
                    ? ` · ${outboundTls.browserFamily} ${outboundTls.browserMajorVersion ?? ""}`
                    : ""}
                </p>
                <label className="checkbox-row advanced-select-block">
                  <span>{t("advanced.versionedPreset")}</span>
                  <select
                    disabled={saving}
                    value={displayedClientHelloPresetId(outboundTls)}
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
                {/* The select above is the control. There used to be a chip row
                    here driving the same value, so the page showed one setting
                    twice and the two could visually disagree while loading. */}
                <label className="checkbox-row">
                  <input
                    type="checkbox"
                    checked={Boolean(outboundTls?.autoFromInbound)}
                    onChange={(e) => void setAutoInbound(e.target.checked)}
                  />
                  {t("advanced.autoPresetDev")}
                </label>
                <p className="hint">
                  {outboundTls?.realImpersonateStackAvailable ? (
                    <>
                      出站引擎<strong>固定</strong>为 wreq 逐字节 Chrome（不可关闭）：
                      <strong>engine={outboundTls?.engine ?? "impersonate"}</strong>，JA4{" "}
                      <code>t13d1516h2_8daaf6152771_806a8c22fdea</code>，HTTP/2 伪头{" "}
                      <code>m,a,s,p</code>。
                      supportsFullBrowserJa3=
                      {String(outboundTls?.supportsFullBrowserJa3 ?? false)}、ja3Parity=
                      {String(outboundTls?.ja3Parity ?? false)}。
                      <br />
                      入站 ClientHello 终止在 ShowNet；源站只看出站指纹。出站包含 Chrome 151 的
                      ML-DSA 0x0904/0905/0906，入站 JA4 与上式一致。产品路径<strong>不再提供 rustls 出站回退</strong>
                      （曾导致 JA4 分裂与 Cloudflare 循环）。WebSocket 升级仍需原始 TLS 流，为协议特例。
                    </>
                  ) : (
                    <>
                      当前构建未链接 impersonate 栈（engine={outboundTls?.engine ?? "rustls"}），
                      仅适合开发测试；正式包必须带 <code>impersonate-boring</code>，否则无法保证
                      入站/出站 JA4 一致。
                    </>
                  )}
                </p>
              </div>
              <div>
                <h4>{t("advanced.systemSettings")}</h4>
                <p className="hint">{t("advanced.systemSettingsHint")}</p>
                <button type="button" className="primary-button" onClick={onOpenSettings}>
                  {t("advanced.openSettings")}
                </button>
              </div>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
