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
      title: "开始抓包",
      summary: "代理已启动，流量会写入当前会话",
      hint: "点「开始抓包」启动本机代理，这一步不需要任何配置。",
      state: capturing ? "done" : "pending",
      // Never offer "停止抓包" here. This panel is where a beginner clicks the
      // biggest button on screen; undoing the step they just completed is the
      // one outcome it must not produce.
      actionLabel: capturing ? "代理设置" : "开始抓包",
      optional: false,
    },
    {
      id: "source",
      title: "接入流量来源",
      summary: hasTraffic
        ? `已收到 ${requestCount} 条请求${sourceCount > 0 ? ` · ${sourceCount} 个来源` : ""}`
        : "浏览器、终端、手机或桌面应用的流量进入 ShowNet",
      hint: "最快的方式是打开内嵌浏览器 —— 它已经指向本机代理，不用装证书。",
      // Traffic is proof the source works; without capture running there is
      // nothing to connect to yet, so the step reads as blocked rather than todo.
      state: hasTraffic ? "done" : capturing ? "pending" : "blocked",
      actionLabel: hasTraffic ? "查看流量" : "打开内嵌浏览器",
      optional: false,
    },
    {
      id: "certificate",
      title: "安装 HTTPS 证书",
      summary: "解密手机 App 与桌面程序的 HTTPS 正文",
      hint: "只看内嵌浏览器可以跳过。要抓 App / 系统流量时再装。",
      state: caInstalled ? "done" : "pending",
      actionLabel: caInstalled ? "证书设置" : "一键安装 CA",
      optional: true,
    },
    {
      id: "ai",
      title: "配置 AI 分析",
      summary: "自动逆向接口与加密链路，导出可运行代码",
      hint: "填入 API Key，或使用内置 Agent / 本地模型。",
      state: aiConfigured ? "done" : "pending",
      actionLabel: aiConfigured ? "AI 设置" : "配置 AI 服务",
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
