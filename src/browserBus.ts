/**
 * Unified Browser execution bus (frontend client).
 *
 * Agent / MCP / UI should prefer these wrappers for discrete commands.
 * Screencast + high-frequency pointer still use the UI CDP WebSocket for latency.
 */
import { invoke, isTauri } from "@tauri-apps/api/core";
import type { ProxyBrowserStatus } from "./types";

export interface BrowserEvaluateResult {
  expression: string;
  value: unknown;
  exception?: string | null;
}

export interface BrowserClickResult {
  mode: string;
  x: number;
  y: number;
  selector?: string | null;
}

export interface BrowserScreenshotResult {
  format: string;
  base64: string;
  bytes: number;
  truncatedInToolResponse?: boolean;
}

export interface BrowserInstallLabResult {
  ok: boolean;
  profileId?: string;
  sessionId?: string;
  steps?: unknown[];
  error?: string;
  next?: string[];
  interactionPlan?: unknown;
  visionCaptcha?: unknown;
  objectDump?: unknown;
  labState?: unknown;
}

export interface WebRiskFixtureProbeSummary {
  offlineOk?: boolean;
  objectDumpKeys?: string[];
  visionPointCount?: number;
  liveOk?: boolean | null;
  liveSkipped?: boolean;
}

export interface WebRiskFixtureProbeResult {
  ok: boolean;
  profileId?: string;
  fixtureSessionId?: string;
  seeded?: unknown;
  offlineProbe?: {
    ok?: boolean;
    objectDump?: unknown;
    visionCaptcha?: unknown;
    errors?: string[];
  };
  visionDryRun?: {
    indices?: number[];
    mapping?: { points?: unknown[] };
  };
  liveInstall?: {
    ok?: boolean;
    skipped?: boolean;
    error?: string;
    objectDump?: unknown;
    note?: string;
  } | null;
  summary?: WebRiskFixtureProbeSummary;
}

export function browserBusAvailable(): boolean {
  return isTauri();
}

export async function getProxyBrowserStatus(): Promise<ProxyBrowserStatus | null> {
  if (!isTauri()) return null;
  return invoke<ProxyBrowserStatus | null>("get_proxy_browser_status");
}

export async function browserEvaluate(
  expression: string,
  awaitPromise = false,
): Promise<BrowserEvaluateResult> {
  return invoke<BrowserEvaluateResult>("browser_evaluate", {
    expression,
    awaitPromise,
  });
}

export async function browserClick(options: {
  selector?: string;
  x?: number;
  y?: number;
}): Promise<BrowserClickResult> {
  return invoke<BrowserClickResult>("browser_click", options);
}

export async function browserScreenshot(format: "png" | "jpeg" = "png"): Promise<BrowserScreenshotResult> {
  return invoke<BrowserScreenshotResult>("browser_screenshot", { format });
}

export async function browserNavigate(url: string): Promise<unknown> {
  return invoke("browser_navigate", { url });
}

export async function browserInsertText(text: string): Promise<unknown> {
  return invoke("browser_insert_text", { text });
}

export async function browserDispatchKey(
  key: string,
  options?: { code?: string; pressed?: boolean },
): Promise<unknown> {
  return invoke("browser_dispatch_key", {
    key,
    code: options?.code,
    pressed: options?.pressed ?? true,
  });
}

export async function browserInstallLab(
  sessionId: string,
  profileId?: string,
): Promise<BrowserInstallLabResult> {
  return invoke<BrowserInstallLabResult>("browser_install_lab", {
    sessionId,
    profileId: profileId ?? null,
  });
}

/** Seed fixture session + offline objectDump + vision dry-run; optional live install_lab. */
export async function runWebRiskFixtureProbe(options?: {
  profileId?: string;
  installLive?: boolean;
}): Promise<WebRiskFixtureProbeResult> {
  return invoke<WebRiskFixtureProbeResult>("run_web_risk_fixture_probe", {
    profileId: options?.profileId ?? null,
    installLive: options?.installLive ?? true,
  });
}

export async function browserReload(): Promise<BrowserEvaluateResult> {
  return browserEvaluate("location.reload()", false);
}

/** Prefer bus navigate when available; returns false if bus unavailable. */
export async function tryBrowserNavigate(url: string): Promise<boolean> {
  if (!browserBusAvailable()) return false;
  try {
    await browserNavigate(url);
    return true;
  } catch {
    return false;
  }
}
