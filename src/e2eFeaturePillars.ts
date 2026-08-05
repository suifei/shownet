/**
 * Product-pillar → automated coverage map for Windows e2e gating.
 * Source of truth for "every major feature has a shipped-code check".
 * Aligns with docs/feature-map.md workflow + modules (not full GUI Playwright).
 */
export type CoverageKind = "live" | "unit" | "structural";

export interface FeaturePillarCoverage {
  /** Stable id used in tests and logs */
  id: string;
  /** Human label (feature map pillar) */
  name: string;
  kind: CoverageKind;
  /** Repo-relative paths that must exist */
  artifacts: string[];
  /**
   * Pattern that must appear in at least one artifact — proves the check
   * targets shipped entry points, not a reimplementation of production logic.
   */
  shippedMarker: RegExp;
  /** Optional short note for operators */
  note?: string;
}

export const E2E_FEATURE_PILLARS: FeaturePillarCoverage[] = [
  {
    id: "capture-mitm-proxy",
    name: "Capture / MITM proxy",
    kind: "live",
    artifacts: [
      "src-tauri/src/proxy.rs",
      "tests/tls-interception-ui.test.ts",
      "scripts/windows-qa.mjs",
    ],
    shippedMarker: /live_shownet_mitm_smoke|ProxyHandle::start|handle_connect|error_response/,
    note: "Live: live_shownet_mitm_smoke via env PROXY; unit tunnel/bypass paths in proxy.rs",
  },
  {
    id: "egress",
    name: "Upstream egress proxy",
    kind: "live",
    artifacts: [
      "src-tauri/src/proxy.rs",
      "tests/upstream-egress-ui.test.ts",
      "src/components/SettingsView.tsx",
    ],
    shippedMarker: /probe_upstream_egress|connect_destination|live_upstream_proxy_from_env|effective_upstream_from_process_env/,
  },
  {
    id: "tls-interception-bypass",
    name: "TLS interception / static CDN bypass",
    kind: "unit",
    artifacts: [
      "src-tauri/src/tls_interception.rs",
      "src/tlsBypassPresets.ts",
      "tests/tls-interception-ui.test.ts",
      "tests/tls-bypass-presets.test.ts",
    ],
    shippedMarker: /STATIC_CDN_BYPASS_PRESET|apply_static_cdn_bypass_preset|TlsInterceptionSettings|bypass_selected/,
  },
  {
    id: "outbound-tls-clienthello",
    name: "Outbound TLS ClientHello catalog",
    kind: "unit",
    artifacts: [
      "src-tauri/src/tls_outbound.rs",
      "src-tauri/src/tls_clienthello_catalog.rs",
      "tests/tls-golden-gate.test.ts",
      "tests/advanced-console-capabilities.test.ts",
    ],
    shippedMarker: /ClientHello|chrome150|ja3Parity|browserParity|fidelityLabel/,
  },
  {
    id: "embedded-browser-lifecycle",
    name: "Embedded browser keep-alive + opener",
    kind: "structural",
    artifacts: [
      "src/components/BrowserView.tsx",
      "src/App.tsx",
      "tests/browser-keepalive.test.ts",
      "tests/browser-opener.test.ts",
    ],
    shippedMarker: /stop_proxy_browser|workspace-view-keep-alive|openUrl|plugin-opener/,
  },
  {
    id: "browser-bus-hook",
    name: "Browser bus / Hook correlation",
    kind: "unit",
    artifacts: [
      "src/browserBus.ts",
      "src-tauri/src/browser_bus.rs",
      "tests/browser-bus.test.ts",
    ],
    shippedMarker: /get_proxy_browser_status|tryBrowserNavigate|browser_install_lab|launch_proxy_browser/,
  },
  {
    id: "traffic-evidence",
    name: "Traffic / request evidence surfaces",
    kind: "structural",
    artifacts: [
      "src/components/TrafficView.tsx",
      "tests/traffic-workbench.test.ts",
      "tests/request-inspector.test.ts",
      "tests/sse-inspector.test.ts",
      "tests/live-capture-display.test.ts",
    ],
    shippedMarker: /list_requests|query_request|HttpBodyViewer|proxy-error-banner|capture:\/\/request/,
  },
  {
    id: "analysis-agent-mcp",
    name: "Analysis / Agent / MCP wiring",
    kind: "unit",
    artifacts: [
      "src/components/AnalysisView.tsx",
      "src/advancedConsoleCapabilities.ts",
      "src-tauri/src/grok_runtime.rs",
      "src-tauri/src/agent_tools.rs",
      "tests/advanced-console-capabilities.test.ts",
      "tests/mcp-client-guide.test.ts",
      "tests/analysis-scope.test.ts",
    ],
    shippedMarker: /real_sidecar|shownet_|mcp|SkillPlan|start_analysis|list_mcp_tools/,
    note: "Live agent: real_sidecar_* when sidecar binary present",
  },
  {
    id: "request-lab-replay-collections",
    name: "Request Lab / replay / collections",
    kind: "structural",
    artifacts: [
      "src/components/RequestWorkbench.tsx",
      "tests/request-workbench.test.ts",
      "tests/request-collections.test.ts",
      "tests/replay-export-ui.test.ts",
    ],
    shippedMarker: /save_capture_rule|start_replay_batch|request_collection|create_request_draft/,
  },
  {
    id: "settings-ca-client-access",
    name: "Settings CA / client access / reverse proxy",
    kind: "structural",
    artifacts: [
      "src/components/SettingsView.tsx",
      "tests/client-access-ui.test.ts",
      "tests/reverse-proxy-ui.test.ts",
      "tests/proxy-terminal-ui.test.ts",
    ],
    shippedMarker: /install_ca|get_tls_interception|client_access|reverse_proxy|launch_proxy_terminal/,
  },
  {
    id: "windows-qa-orchestrator",
    name: "Windows e2e orchestrator entry",
    kind: "structural",
    artifacts: [
      "scripts/windows-qa.mjs",
      "tests/windows-qa-runner.test.ts",
      "package.json",
    ],
    shippedMarker: /test:windows|loadDotEnv|LAYER_DEFAULT_OK|live_upstream_proxy_from_env/,
  },
];

export function pillarIds(): string[] {
  return E2E_FEATURE_PILLARS.map((p) => p.id);
}
