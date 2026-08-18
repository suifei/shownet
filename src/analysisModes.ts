/**
 * The five analysis modes, named once.
 *
 * AI 分析 and Skill 编排 are two views onto the same pipeline, and they used to
 * declare this list twice — so mode `auto` was 「自动识别」 in one and
 * 「自动场景分析」 in the other, and `api` was 「API 逆向」 vs 「API 协议逆向」.
 * Same id, same behaviour, two names the user had to reconcile.
 */
import { Code2, FileCode2, Gauge, ShieldCheck, WandSparkles, type LucideIcon } from "lucide-react";

import { t, type MessageKey } from "./i18n.ts";
import type { AnalysisMode } from "./types";

export interface AnalysisModeMeta {
  id: AnalysisMode;
  label: string;
  /** What this mode looks for — shown under the label. */
  focus: string;
  /**
   * The glyph, shared by both views. Labels were unified earlier but the icon
   * maps were left behind, so `auto` rendered as a wand in AI 分析 and as
   * sparkles in Skill 编排, and `crypto` as a file in one and a key in the other.
   */
  icon: LucideIcon;
}

const ANALYSIS_MODE_KEYS: Record<AnalysisMode, { label: MessageKey; focus: MessageKey; icon: LucideIcon }> = {
  auto: { label: "analysis.mode.auto", focus: "analysis.mode.autoFocus", icon: WandSparkles },
  api: { label: "analysis.mode.api", focus: "analysis.mode.apiFocus", icon: Code2 },
  security: { label: "analysis.mode.security", focus: "analysis.mode.securityFocus", icon: ShieldCheck },
  performance: { label: "analysis.mode.performance", focus: "analysis.mode.performanceFocus", icon: Gauge },
  crypto: { label: "analysis.mode.crypto", focus: "analysis.mode.cryptoFocus", icon: FileCode2 },
};

export const ANALYSIS_MODES: AnalysisModeMeta[] = (["auto", "api", "security", "performance", "crypto"] as const).map((id) => ({
  id,
  get label() {
    return t(ANALYSIS_MODE_KEYS[id].label);
  },
  get focus() {
    return t(ANALYSIS_MODE_KEYS[id].focus);
  },
  icon: ANALYSIS_MODE_KEYS[id].icon,
}));

export function analysisModeLabel(mode: AnalysisMode): string {
  return ANALYSIS_MODE_KEYS[mode] ? t(ANALYSIS_MODE_KEYS[mode].label) : mode;
}

export function analysisModeFocus(mode: AnalysisMode): string {
  return ANALYSIS_MODE_KEYS[mode] ? t(ANALYSIS_MODE_KEYS[mode].focus) : "";
}
