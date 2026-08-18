/**
 * Single source of truth for MITM Advanced Console workflow phases,
 * per-tab guidance, and capture-vs-analysis capability mapping.
 * UI, Agent skill previews, and structural tests import this module.
 *
 * User-facing strings resolve through t() at read time so language packs apply.
 */

import { t, type MessageKey } from "./i18n.ts";

function localized<T extends { id: string }>(
  base: T,
  fields: Record<string, MessageKey>,
): T {
  for (const [field, key] of Object.entries(fields)) {
    Object.defineProperty(base, field, {
      get: () => t(key),
      enumerable: true,
      configurable: true,
    });
  }
  return base;
}

export type WorkflowPhaseId = "capture" | "evidence" | "analysis" | "export";

export type ConsoleTabId =
  | "overview"
  | "capture"
  | "hooks"
  | "rules"
  | "fingerprint"
  | "px"
  | "recaptcha"
  | "config";

export type CapabilityPhase = "capture" | "analysis" | "both";

export interface WorkflowStage {
  id: WorkflowPhaseId;
  step: number;
  label: string;
  shortLabel: string;
  summary: string;
  beginnerTip: string;
  primaryNav: string;
}

export interface ConsoleTabGuide {
  id: ConsoleTabId;
  label: string;
  phase: WorkflowPhaseId;
  whenToUse: string;
  bestPractice: string;
  nextStep: string;
  emptyHint: string;
  /** Real UI / Tauri invoke names used by this tab (not agent tool names). */
  uiActions: string[];
  /** Agent/MCP tools that read evidence this tab surfaces (must exist in registry). */
  agentTools: string[];
}

export interface CapabilityEntry {
  id: string;
  name: string;
  phase: CapabilityPhase;
  /** When this capability is active in the product lifecycle. */
  when: string;
  /** How it connects to traffic / browser / settings / AI. */
  linksTo: string;
  /** Real entry points: UI, Tauri command, or MCP/agent tool name. */
  entryPoints: string[];
  honesty?: string;
}

/** Ordered beginner workflow shown at the top of Advanced Console. */
export const WORKFLOW_STAGES: WorkflowStage[] = [
  localized({ id: "capture", step: 1, label: "", shortLabel: "", summary: "", beginnerTip: "", primaryNav: "" }, {
    label: "advanced.wf.capture",
    shortLabel: "advanced.wf.captureShort",
    summary: "advanced.wf.captureSummary",
    beginnerTip: "advanced.wf.captureTip",
    primaryNav: "advanced.wf.captureNav",
  }),
  localized({ id: "evidence", step: 2, label: "", shortLabel: "", summary: "", beginnerTip: "", primaryNav: "" }, {
    label: "advanced.wf.evidence",
    shortLabel: "advanced.wf.evidenceShort",
    summary: "advanced.wf.evidenceSummary",
    beginnerTip: "advanced.wf.evidenceTip",
    primaryNav: "advanced.wf.evidenceNav",
  }),
  localized({ id: "analysis", step: 3, label: "", shortLabel: "", summary: "", beginnerTip: "", primaryNav: "" }, {
    label: "advanced.wf.analysis",
    shortLabel: "advanced.wf.analysisShort",
    summary: "advanced.wf.analysisSummary",
    beginnerTip: "advanced.wf.analysisTip",
    primaryNav: "advanced.wf.analysisNav",
  }),
  localized({ id: "export", step: 4, label: "", shortLabel: "", summary: "", beginnerTip: "", primaryNav: "" }, {
    label: "advanced.wf.export",
    shortLabel: "advanced.wf.exportShort",
    summary: "advanced.wf.exportSummary",
    beginnerTip: "advanced.wf.exportTip",
    primaryNav: "advanced.wf.exportNav",
  }),
];

/** Tab metadata: when / next / empty / real wiring. */
export const CONSOLE_TAB_GUIDES: ConsoleTabGuide[] = [
  localized({
    id: "overview", label: "", phase: "capture", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["nav:advanced", "nav:browser", "nav:traffic", "nav:analysis"],
    agentTools: ["shownet_list_requests", "shownet_get_tls_fingerprints", "shownet_get_outbound_tls_status", "shownet_list_px_evidence"],
  }, {
    label: "advanced.guide.overview.label",
    whenToUse: "advanced.guide.overview.when",
    bestPractice: "advanced.guide.overview.best",
    nextStep: "advanced.guide.overview.next",
    emptyHint: "advanced.guide.overview.empty",
  }),
  localized({
    id: "capture", label: "", phase: "capture", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["onOpenTraffic", "runtime.proxyPort"],
    agentTools: ["shownet_list_requests", "shownet_runtime_status"],
  }, {
    label: "advanced.guide.capture.label",
    whenToUse: "advanced.guide.capture.when",
    bestPractice: "advanced.guide.capture.best",
    nextStep: "advanced.guide.capture.next",
    emptyHint: "advanced.guide.capture.empty",
  }),
  localized({
    id: "hooks", label: "", phase: "evidence", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["list_browser_hooks", "onOpenBrowser"],
    agentTools: ["shownet_get_hooks", "shownet_get_crypto_snippets"],
  }, {
    label: "advanced.guide.hooks.label",
    whenToUse: "advanced.guide.hooks.when",
    bestPractice: "advanced.guide.hooks.best",
    nextStep: "advanced.guide.hooks.next",
    emptyHint: "advanced.guide.hooks.empty",
  }),
  localized({
    id: "rules", label: "", phase: "capture", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["onOpenRules", "set_px_settings.interceptEcData"],
    agentTools: [],
  }, {
    label: "advanced.guide.rules.label",
    whenToUse: "advanced.guide.rules.when",
    bestPractice: "advanced.guide.rules.best",
    nextStep: "advanced.guide.rules.next",
    emptyHint: "advanced.guide.rules.empty",
  }),
  localized({
    id: "fingerprint", label: "", phase: "evidence", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["get_tls_fingerprints", "get_outbound_tls_profile"],
    agentTools: ["shownet_get_tls_fingerprints", "shownet_get_outbound_tls_status"],
  }, {
    label: "advanced.guide.fingerprint.label",
    whenToUse: "advanced.guide.fingerprint.when",
    bestPractice: "advanced.guide.fingerprint.best",
    nextStep: "advanced.guide.fingerprint.next",
    emptyHint: "advanced.guide.fingerprint.empty",
  }),
  localized({
    id: "px", label: "", phase: "evidence", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["list_px_evidence", "decode_px_payload", "get_px_settings", "compareA/B", "onOpenRules"],
    agentTools: ["shownet_list_px_evidence", "shownet_decode_px_payload", "shownet_get_request"],
  }, {
    label: "advanced.guide.px.label",
    whenToUse: "advanced.guide.px.when",
    bestPractice: "advanced.guide.px.best",
    nextStep: "advanced.guide.px.next",
    emptyHint: "advanced.guide.px.empty",
  }),
  localized({
    id: "recaptcha", label: "reCAPTCHA", phase: "evidence", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["request filter recaptcha"],
    agentTools: ["shownet_analyze_dynamic_protection", "shownet_build_vision_captcha_package", "shownet_solve_vision_captcha"],
  }, {
    whenToUse: "advanced.guide.recaptcha.when",
    bestPractice: "advanced.guide.recaptcha.best",
    nextStep: "advanced.guide.recaptcha.next",
    emptyHint: "advanced.guide.recaptcha.empty",
  }),
  localized({
    id: "config", label: "", phase: "capture", whenToUse: "", bestPractice: "", nextStep: "", emptyHint: "",
    uiActions: ["set_outbound_tls_profile", "set_outbound_tls_auto_from_inbound", "get_outbound_tls_profile", "onOpenSettings"],
    agentTools: ["shownet_get_outbound_tls_status"],
  }, {
    label: "advanced.guide.config.label",
    whenToUse: "advanced.guide.config.when",
    bestPractice: "advanced.guide.config.best",
    nextStep: "advanced.guide.config.next",
    emptyHint: "advanced.guide.config.empty",
  }),
];

/**
 * Capture-time vs analysis-time capabilities (machine-readable).
 * entryPoints must match real UI invokes, Tauri commands, or MCP tool names.
 */
export const CAPABILITY_CATALOG: CapabilityEntry[] = [
  localized({
    id: "outbound-tls-preset", name: "", phase: "capture", when: "", linksTo: "",
    entryPoints: ["set_outbound_tls_profile", "get_outbound_tls_profile", "shownet_get_outbound_tls_status"],
    honesty: "",
  }, {
    name: "advanced.cap.outboundTls",
    when: "advanced.cap.outboundTlsWhen",
    linksTo: "advanced.cap.outboundTlsLinks",
    honesty: "advanced.cap.outboundTlsHonesty",
  }),
  localized({
    id: "inbound-auto-preset", name: "", phase: "capture", when: "", linksTo: "",
    entryPoints: ["set_outbound_tls_auto_from_inbound", "shownet_get_outbound_tls_status"],
  }, {
    name: "advanced.cap.autoPreset",
    when: "advanced.cap.autoPresetWhen",
    linksTo: "advanced.cap.autoPresetLinks",
  }),
  localized({
    id: "px-capture-toggles", name: "", phase: "capture", when: "", linksTo: "",
    entryPoints: ["get_px_settings", "set_px_settings"],
    honesty: "",
  }, {
    name: "advanced.cap.pxToggles",
    when: "advanced.cap.pxTogglesWhen",
    linksTo: "advanced.cap.pxTogglesLinks",
    honesty: "advanced.cap.pxTogglesHonesty",
  }),
  localized({
    id: "browser-hook-inject", name: "", phase: "capture", when: "", linksTo: "",
    entryPoints: ["list_browser_hooks", "shownet_get_hooks"],
  }, {
    name: "advanced.cap.hookInject",
    when: "advanced.cap.hookInjectWhen",
    linksTo: "advanced.cap.hookInjectLinks",
  }),
  localized({
    id: "proxy-capture", name: "", phase: "capture", when: "", linksTo: "",
    entryPoints: ["shownet_list_requests", "shownet_runtime_status", "onOpenTraffic"],
  }, {
    name: "advanced.cap.proxy",
    when: "advanced.cap.proxyWhen",
    linksTo: "advanced.cap.proxyLinks",
  }),
  localized({
    id: "tls-fingerprint-record", name: "", phase: "both", when: "", linksTo: "",
    entryPoints: ["get_tls_fingerprints", "shownet_get_tls_fingerprints"],
    honesty: "",
  }, {
    name: "advanced.cap.tlsRecord",
    when: "advanced.cap.tlsRecordWhen",
    linksTo: "advanced.cap.tlsRecordLinks",
    honesty: "advanced.cap.tlsRecordHonesty",
  }),
  localized({
    id: "px-evidence-collect", name: "", phase: "both", when: "", linksTo: "",
    entryPoints: ["list_px_evidence", "decode_px_payload", "shownet_list_px_evidence", "shownet_decode_px_payload"],
    honesty: "",
  }, {
    name: "advanced.cap.pxCollect",
    when: "advanced.cap.pxCollectWhen",
    linksTo: "advanced.cap.pxCollectLinks",
    honesty: "advanced.cap.pxCollectHonesty",
  }),
  localized({
    id: "agent-tls-read", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_get_tls_fingerprints"],
  }, {
    name: "advanced.cap.agentTls",
    when: "advanced.cap.agentTlsWhen",
    linksTo: "advanced.cap.agentTlsLinks",
  }),
  localized({
    id: "agent-outbound-status", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_get_outbound_tls_status"],
    honesty: "",
  }, {
    name: "advanced.cap.agentOutbound",
    when: "advanced.cap.agentOutboundWhen",
    linksTo: "advanced.cap.agentOutboundLinks",
    honesty: "advanced.cap.agentOutboundHonesty",
  }),
  localized({
    id: "agent-px-read", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_list_px_evidence", "shownet_decode_px_payload"],
  }, {
    name: "advanced.cap.agentPx",
    when: "advanced.cap.agentPxWhen",
    linksTo: "advanced.cap.agentPxLinks",
  }),
  localized({
    id: "agent-dynamic-protection", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_analyze_dynamic_protection", "shownet_decode_challenge_js", "shownet_eval_scorecard", "shownet_build_signature_harness"],
  }, {
    name: "advanced.cap.dynamic",
    when: "advanced.cap.dynamicWhen",
    linksTo: "advanced.cap.dynamicLinks",
  }),
  localized({
    id: "agent-hooks-crypto", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_get_hooks", "shownet_get_crypto_snippets", "shownet_get_request"],
  }, {
    name: "advanced.cap.hooksCrypto",
    when: "advanced.cap.hooksCryptoWhen",
    linksTo: "advanced.cap.hooksCryptoLinks",
  }),
  localized({
    id: "export-replay-code", name: "", phase: "analysis", when: "", linksTo: "",
    entryPoints: ["shownet_build_algorithm_replay", "shownet_generate_code", "shownet_build_auto_crawler", "shownet_export_analysis_artifacts"],
  }, {
    name: "advanced.cap.exportReplay",
    when: "advanced.cap.exportReplayWhen",
    linksTo: "advanced.cap.exportReplayLinks",
  }),
];

export function tabGuide(id: ConsoleTabId): ConsoleTabGuide {
  const found = CONSOLE_TAB_GUIDES.find((tab) => tab.id === id);
  if (!found) {
    throw new Error(`unknown console tab: ${id}`);
  }
  return found;
}

export function capabilitiesForPhase(phase: CapabilityPhase | "capture" | "analysis"): CapabilityEntry[] {
  if (phase === "capture") {
    return CAPABILITY_CATALOG.filter((entry) => entry.phase === "capture" || entry.phase === "both");
  }
  if (phase === "analysis") {
    return CAPABILITY_CATALOG.filter((entry) => entry.phase === "analysis" || entry.phase === "both");
  }
  return CAPABILITY_CATALOG.filter((entry) => entry.phase === phase);
}

/** All agent tool names referenced by the capability catalog or tab guides. */
export function catalogAgentToolNames(): string[] {
  const names = new Set<string>();
  for (const entry of CAPABILITY_CATALOG) {
    for (const point of entry.entryPoints) {
      if (point.startsWith("shownet_")) names.add(point);
    }
  }
  for (const tab of CONSOLE_TAB_GUIDES) {
    for (const tool of tab.agentTools) names.add(tool);
  }
  return [...names].sort();
}

/** Suggest next workflow stage from simple session stats. */
export function suggestWorkflowStage(stats: {
  requestCount: number;
  hookCount: number;
  fingerprintCount: number;
  pxCount: number;
  hasReport?: boolean;
}): WorkflowPhaseId {
  if (stats.hasReport) return "export";
  if (stats.requestCount === 0) return "capture";
  if (stats.fingerprintCount > 0 || stats.hookCount > 0 || stats.pxCount > 0) {
    return "analysis";
  }
  return "evidence";
}

/**
 * The one line that tells the user what their traffic actually leaves as.
 *
 * It used to be a constant reading "rustls 配方（ja3Parity=false）" whatever the
 * engine was, so a build with the impersonate engine active showed a header
 * claiming rustls directly above a panel reporting `engine=impersonate`. A
 * banner whose whole job is honesty cannot be the one element that ignores the
 * status it sits next to.
 *
 * Undefined status keeps the conservative wording: before the backend answers,
 * the weaker claim is the true one.
 */
export function honestyBanner(
  status?: { engine?: string; ja3Parity?: boolean } | null,
): string {
  const engine =
    status?.engine === "impersonate"
      ? t("advanced.honesty.wreq")
      : t("advanced.honesty.rustls");
  const parity = status?.ja3Parity === true ? "true" : "false";
  return t("advanced.honesty.banner", { engine, parity });
}
