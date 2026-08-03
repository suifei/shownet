import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Fingerprint,
  GitCompare,
  KeyRound,
  Network,
  RefreshCw,
  Settings2,
  Shield,
  Shuffle,
  Workflow,
} from "lucide-react";
import { invoke, isTauri } from "@tauri-apps/api/core";
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

type ConsoleTab =
  | "capture"
  | "hooks"
  | "rules"
  | "fingerprint"
  | "px-replay"
  | "px-compare"
  | "px-tamper"
  | "recaptcha"
  | "config";

const tabs: Array<{ id: ConsoleTab; label: string; icon: typeof Network }> = [
  { id: "capture", label: "数据包捕获", icon: Network },
  { id: "hooks", label: "Hook管理", icon: Workflow },
  { id: "rules", label: "替换规则", icon: Shuffle },
  { id: "fingerprint", label: "指纹数据", icon: Fingerprint },
  { id: "px-replay", label: "PX替换重放", icon: RefreshCw },
  { id: "px-compare", label: "PX对比", icon: GitCompare },
  { id: "px-tamper", label: "PX篡改", icon: KeyRound },
  { id: "recaptcha", label: "reCAPTCHA", icon: Shield },
  { id: "config", label: "配置", icon: Settings2 },
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
  onNotify,
}: AdvancedConsoleViewProps) {
  const [tab, setTab] = useState<ConsoleTab>("capture");
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

  return (
    <div className="advanced-console">
      <header className="advanced-console-hero">
        <div>
          <h2>
            <Activity size={18} /> MITM Proxy · 高级管理控制台
          </h2>
          <p>实时流量监控 · Hook 管理 · 动态替换规则 · 指纹 / PX / reCAPTCHA</p>
        </div>
        <div className="advanced-console-stats">
          <span>
            代理端口: <strong>{proxyPort}</strong>
          </span>
          <span>
            捕获数据包: <strong>{packetCount}</strong>
          </span>
          <span>
            活跃 Hook: <strong>{hookCount || hooks.length}</strong>
          </span>
        </div>
        <div className="advanced-console-toggles">
          <label className={pxSettings.decryptEnabled ? "is-on" : ""}>
            <span>PX解密</span>
            <input
              type="checkbox"
              checked={pxSettings.decryptEnabled}
              disabled={saving}
              onChange={(e) => void updatePx({ decryptEnabled: e.target.checked })}
            />
            <em>{pxSettings.decryptEnabled ? "已启用" : "已禁用"}</em>
          </label>
          <label className={pxSettings.interceptEcData ? "is-on" : ""}>
            <span>拦截ecData报文</span>
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

      <nav className="advanced-console-tabs" aria-label="高级控制台分区">
        {tabs.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.id}
              type="button"
              className={tab === item.id ? "is-active" : ""}
              onClick={() => setTab(item.id)}
            >
              <Icon size={14} />
              {item.label}
            </button>
          );
        })}
      </nav>

      <section className="advanced-console-panel">
        {tab === "capture" && (
          <div className="advanced-panel-card">
            <h3>数据包捕获</h3>
            <p>当前会话请求 {packetCount} 条。完整列表与报文检视在「流量」工作台。</p>
            <button type="button" className="primary-button" onClick={onOpenTraffic}>
              打开流量视图
            </button>
            <ul className="advanced-mini-list">
              {requests.slice(0, 12).map((r) => (
                <li key={r.id}>
                  <code>{r.method}</code> {r.host}
                  {r.path}
                </li>
              ))}
            </ul>
          </div>
        )}

        {tab === "hooks" && (
          <div className="advanced-panel-card">
            <h3>Hook 管理</h3>
            <p>会话内浏览器 Hook 事件 {hooks.length} 条。</p>
            <button type="button" className="primary-button" onClick={onOpenBrowser}>
              打开浏览器 Hook 面板
            </button>
            <ul className="advanced-mini-list">
              {hooks.slice(0, 20).map((h) => (
                <li key={h.id}>
                  <strong>{h.kind}</strong> {h.name} · {h.timestamp}
                </li>
              ))}
              {hooks.length === 0 && <li>暂无 Hook；在浏览器注入 JS Hook 后刷新。</li>}
            </ul>
          </div>
        )}

        {tab === "rules" && (
          <div className="advanced-panel-card">
            <h3>替换规则</h3>
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
            <h3>指纹数据</h3>
            <p>
              出站引擎: <code>{outboundTls?.engine ?? "rustls"}</code> · 预置:{" "}
              <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "default"}</code>
              {outboundTls?.browserFamily
                ? ` · ${outboundTls.browserFamily}${outboundTls.browserMajorVersion ? ` ${outboundTls.browserMajorVersion}` : ""}`
                : ""}{" "}
              · JA3 对等: <strong>{outboundTls?.ja3Parity ? "是" : "否"}</strong>
            </p>
            <p className="hint">{outboundTls?.note}</p>
            <ul className="advanced-mini-list">
              {fingerprints.slice(0, 15).map((fp, index) => (
                <li key={`${fp.inbound.ja3}-${index}`}>
                  入站 JA3 <code>{fp.inbound.ja3.slice(0, 16)}…</code> · 出站 {fp.outbound.profile} /{" "}
                  {fp.outbound.applicationProtocol ?? fp.outbound.negotiatedAlpn ?? "—"} ·{" "}
                  {fp.outbound.selectedFromInbound ? "入站映射" : fp.outbound.mode}
                </li>
              ))}
              {fingerprints.length === 0 && <li>暂无 TLS 指纹记录（需 MITM 抓包）。</li>}
            </ul>
          </div>
        )}

        {(tab === "px-replay" || tab === "px-compare" || tab === "px-tamper") && (
          <div className="advanced-panel-card">
            <h3>
              {tab === "px-replay" && "PX 替换重放"}
              {tab === "px-compare" && "PX 对比"}
              {tab === "px-tamper" && "PX 篡改"}
            </h3>
            <p>
              检测到 PX/HUMAN 相关请求 <strong>{pxEvidence.length}</strong> 条。解码为结构解析，非无密钥硬破。
            </p>
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
              {pxEvidence.length === 0 && <li>本会话未发现 PerimeterX / ecData 证据。</li>}
            </ul>
            {tab === "px-compare" && (
              <p>
                对比: A=<code>{compareA ?? "—"}</code> B=<code>{compareB ?? "—"}</code>（在流量/实验室中打开两条请求做字段 diff）
              </p>
            )}
            {decode && selectedPx === decode.requestId && (
              <pre className="advanced-json">{JSON.stringify(decode, null, 2)}</pre>
            )}
          </div>
        )}

        {tab === "recaptcha" && (
          <div className="advanced-panel-card">
            <h3>reCAPTCHA</h3>
            <p>会话中疑似 reCAPTCHA 请求 {recaptchaHits.length} 条。完整解题走 Web 风控 Lab / 视觉验证码工具。</p>
            <ul className="advanced-mini-list">
              {recaptchaHits.slice(0, 20).map((r) => (
                <li key={r.id}>
                  {r.method} {r.host}
                  {r.path}
                </li>
              ))}
              {recaptchaHits.length === 0 && <li>未捕获 reCAPTCHA 资源。</li>}
            </ul>
          </div>
        )}

        {tab === "config" && (
          <div className="advanced-panel-card">
            <h3>配置</h3>
            <div className="advanced-config-grid">
              <div>
                <h4>出站 ClientHello 预置</h4>
                <p className="hint" style={{ marginBottom: 8 }}>
                  当前: <code>{outboundTls?.presetId ?? outboundTls?.profile ?? "—"}</code>
                  {outboundTls?.browserFamily
                    ? ` · ${outboundTls.browserFamily} ${outboundTls.browserMajorVersion ?? ""}`
                    : ""}
                </p>
                <label className="checkbox-row" style={{ display: "block", marginBottom: 10 }}>
                  <span style={{ display: "block", marginBottom: 4, fontSize: 12, opacity: 0.85 }}>
                    版本化预置（family + major）
                  </span>
                  <select
                    disabled={saving}
                    value={outboundTls?.presetId ?? "chrome150"}
                    onChange={(e) => void setTlsProfile(e.target.value)}
                    style={{ width: "100%", maxWidth: 420 }}
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
