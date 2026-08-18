/**
 * Setup readiness — the four things that decide whether ShowNet can actually do
 * its job, computed in one place.
 *
 * These four states are otherwise scattered across the topbar (capture), the
 * connect dialog (sources), Settings → 抓包与 HTTPS (certificate) and
 * Settings → AI 模型 (analysis). Deriving them together is what lets a single
 * panel answer "what do I still need to do" instead of making the user check
 * four screens.
 */

import { t } from "./i18n.ts";

export type SetupStepId = "capture" | "source" | "certificate" | "ai";

export type SetupStepState = "done" | "pending" | "blocked";

export interface SetupStep {
  id: SetupStepId;
  title: string;
  /** What the user gets once this is done. */
  summary: string;
  /** Shown when the step is not yet done — the concrete next move. */
  hint: string;
  state: SetupStepState;
  /** Label of the button that resolves the step. */
  actionLabel: string;
  /**
   * Optional steps never block the "ready" verdict; they are the difference
   * between "works" and "works for App / HTTPS / AI traffic".
   */
  optional: boolean;
}

export interface SetupSignals {
  /** Proxy is running for the active session. */
  capturing: boolean;
  /** Requests already recorded in the active session. */
  requestCount: number;
  /** Root CA present in the OS trust store. */
  caInstalled: boolean;
  /** An AI provider has a usable key or is a local runtime. */
  aiConfigured: boolean;
  /** Distinct traffic sources seen in the active session. */
  sourceCount: number;
}

export function buildSetupSteps(signals: SetupSignals): SetupStep[] {
  const { capturing, requestCount, caInstalled, aiConfigured, sourceCount } = signals;
  const hasTraffic = requestCount > 0;

  return [
    {
      id: "capture",
      title: t("setup.capture.title"),
      summary: t("setup.capture.summary"),
      hint: t("setup.capture.hint"),
      state: capturing ? "done" : "pending",
      // Never offer "停止抓包" here. This panel is where a beginner clicks the
      // biggest button on screen; undoing the step they just completed is the
      // one outcome it must not produce.
      actionLabel: capturing ? t("setup.capture.actionReady") : t("shell.startCapture"),
      optional: false,
    },
    {
      id: "source",
      title: t("setup.source.title"),
      summary: hasTraffic
        ? sourceCount > 0
          ? t("setup.source.summarySources", { count: requestCount, sources: sourceCount })
          : t("setup.source.summary", { count: requestCount })
        : t("setup.source.empty"),
      hint: t("setup.source.hint"),
      // Traffic is proof the source works; without capture running there is
      // nothing to connect to yet, so the step reads as blocked rather than todo.
      state: hasTraffic ? "done" : capturing ? "pending" : "blocked",
      actionLabel: hasTraffic ? t("setup.source.view") : t("setup.source.open"),
      optional: false,
    },
    {
      id: "certificate",
      title: t("setup.cert.title"),
      summary: t("setup.cert.summary"),
      hint: t("setup.cert.hint"),
      state: caInstalled ? "done" : "pending",
      actionLabel: caInstalled ? t("setup.cert.ready") : t("setup.cert.action"),
      optional: true,
    },
    {
      id: "ai",
      title: t("setup.ai.title"),
      summary: t("setup.ai.summary"),
      hint: t("setup.ai.hint"),
      state: aiConfigured ? "done" : "pending",
      actionLabel: aiConfigured ? t("setup.ai.ready") : t("setup.ai.action"),
      optional: true,
    },
  ];
}

export interface SetupProgress {
  /** Required steps completed. */
  done: number;
  /** Required steps total. */
  total: number;
  /** All required steps are done — the app can capture and show traffic. */
  ready: boolean;
  /** Every step including the optional ones is done. */
  complete: boolean;
  /** The step the user should act on next, or undefined when nothing is left. */
  next?: SetupStep;
}

export function setupProgress(steps: SetupStep[]): SetupProgress {
  const required = steps.filter((step) => !step.optional);
  const done = required.filter((step) => step.state === "done").length;
  // A blocked step is never the suggested next move — its prerequisite is.
  const next = steps.find((step) => step.state === "pending" && !step.optional)
    ?? steps.find((step) => step.state === "pending");
  return {
    done,
    total: required.length,
    ready: done === required.length,
    complete: steps.every((step) => step.state === "done"),
    next,
  };
}

export const SETUP_DISMISSED_KEY = "shownet.setup-guide.dismissed.v1";

/** The guide auto-opens once per install, and never again after it is dismissed. */
export function shouldAutoOpenSetup(progress: SetupProgress, dismissed: boolean): boolean {
  return !dismissed && !progress.ready;
}
