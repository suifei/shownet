/**
 * The five analysis modes, named once.
 *
 * AI 分析 and Skill 编排 are two views onto the same pipeline, and they used to
 * declare this list twice — so mode `auto` was 「自动识别」 in one and
 * 「自动场景分析」 in the other, and `api` was 「API 逆向」 vs 「API 协议逆向」.
 * Same id, same behaviour, two names the user had to reconcile.
 */
import { Code2, FileCode2, Gauge, ShieldCheck, WandSparkles, type LucideIcon } from "lucide-react";

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

export const ANALYSIS_MODES: AnalysisModeMeta[] = [
  { id: "auto", label: "自动识别", focus: "自动选择最合适的分析路径", icon: WandSparkles },
  { id: "api", label: "API 逆向", focus: "接口、参数、鉴权与调用链", icon: Code2 },
  { id: "security", label: "安全审计", focus: "敏感数据、越权与配置风险", icon: ShieldCheck },
  { id: "performance", label: "性能分析", focus: "瀑布、重复请求与慢接口", icon: Gauge },
  { id: "crypto", label: "JS 加密逆向", focus: "Hook、算法与动态签名", icon: FileCode2 },
];

export function analysisModeLabel(mode: AnalysisMode): string {
  return ANALYSIS_MODES.find((entry) => entry.id === mode)?.label ?? mode;
}

export function analysisModeFocus(mode: AnalysisMode): string {
  return ANALYSIS_MODES.find((entry) => entry.id === mode)?.focus ?? "";
}
