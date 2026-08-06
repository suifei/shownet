/**
 * How a capture rule resolved against one request.
 *
 * The label map was written twice: the workbench listed all six outcomes, while
 * the traffic detail pane only handled `applied`, `preview` and `error` and let
 * everything else fall through to 未命中. That reported `inherited` (the rule
 * matched, but the decision came from the connection) and `skipped` as "no
 * match" — the opposite of what happened, in the one panel people open to work
 * out why a rule did or did not fire.
 */
export const RULE_TRACE_RESULT_LABELS: Record<string, string> = {
  applied: "已执行",
  inherited: "沿用连接",
  skipped: "已跳过",
  preview: "预览",
  error: "错误",
  "not-matched": "未命中",
};

export function ruleTraceResultLabel(result: string): string {
  return RULE_TRACE_RESULT_LABELS[result] ?? result;
}
