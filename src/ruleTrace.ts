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
import { t } from "./i18n.ts";

export const RULE_TRACE_RESULT_LABELS: Record<string, string> = {
  get applied() { return t("traffic.rule.applied"); },
  get inherited() { return t("traffic.rule.inherited"); },
  get skipped() { return t("traffic.rule.skipped"); },
  get preview() { return t("traffic.rule.preview"); },
  get error() { return t("traffic.rule.error"); },
  get "not-matched"() { return t("traffic.rule.notMatched"); },
};

export function ruleTraceResultLabel(result: string): string {
  return RULE_TRACE_RESULT_LABELS[result] ?? result;
}
