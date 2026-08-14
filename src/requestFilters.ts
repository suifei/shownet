import { SLOW_REQUEST_MS } from "./format.ts";
import { OBSERVABLE_METHODS } from "./httpMethods.ts";
import type { FilterExpression, RequestField, RiskLevel, SourceType } from "./types";

export type QuickStatus = "pending" | "streaming" | "2xx" | "3xx" | "4xx" | "5xx" | "failed" | "tunnel";
export type QuickShownet = "hook" | "snippets" | "risk" | "slow";

export interface QuickFilterState {
  text: string;
  hosts: string[];
  methods: string[];
  protocols: string[];
  types: string[];
  statuses: QuickStatus[];
  exactStatuses: string[];
  sources: SourceType[];
  risks: RiskLevel[];
  shownet: QuickShownet[];
}

export const emptyQuickFilter: QuickFilterState = {
  text: "",
  hosts: [],
  methods: [],
  protocols: [],
  types: [],
  statuses: [],
  exactStatuses: [],
  sources: [],
  risks: [],
  shownet: [],
};

export function buildQuickFilter(state: QuickFilterState, advanced?: FilterExpression): FilterExpression | undefined {
  const groups: FilterExpression[] = [];
  addOrGroup(groups, state.hosts.map((value) => predicate("host", "equals", value)));
  addOrGroup(groups, state.methods.map((value) => predicate("method", "equals", value)));
  addOrGroup(groups, state.protocols.map((value) => predicate("protocol", "equals", value)));
  addOrGroup(groups, state.types.flatMap(typePredicates));
  addOrGroup(groups, state.statuses.map(statusPredicate));
  addOrGroup(groups, state.exactStatuses.map(exactStatusPredicate));
  addOrGroup(groups, state.sources.map((value) => predicate("source", "equals", value)));
  addOrGroup(groups, state.risks.map((value) => predicate("risk", "equals", value)));
  addOrGroup(groups, state.shownet.map(shownetPredicate));

  const text = state.text.trim();
  if (text) {
    // "全部" is intentionally a single backend predicate: the native query
    // can search request/response headers and bodies that are absent from list rows.
    addOrGroup(groups, [predicate("all", "contains", text)]);
  }
  if (advanced) groups.push(advanced);
  if (groups.length === 0) return undefined;
  return groups.length === 1 ? groups[0] : { kind: "group", operator: "and", children: groups };
}

/* ---- Shared option labels -------------------------------------------
   The filter panel and the facet sidebar both render these lists; they used to
   declare them separately, so a protocol could read "HTTP/2" in one place and
   "h2" in the other. */

export const METHOD_VALUES: readonly string[] = OBSERVABLE_METHODS;
export const PROTOCOL_VALUES = ["http/1.1", "h2", "ws"];
export const TYPE_VALUES = ["api", "document", "script", "image", "font", "websocket", "sse"];
export const STATUS_VALUES: QuickStatus[] = ["pending", "streaming", "2xx", "3xx", "4xx", "5xx", "failed", "tunnel"];
export const SHOWNET_VALUES: QuickShownet[] = ["hook", "snippets", "risk", "slow"];

export const PROTOCOL_LABELS: Record<string, string> = { "http/1.1": "HTTP/1.1", h2: "HTTP/2", ws: "WebSocket" };
export const TYPE_LABELS: Record<string, string> = { api: "Fetch/XHR", document: "文档", script: "脚本", image: "图片", font: "字体", websocket: "WebSocket", sse: "SSE" };
/**
 * How a request's lifecycle state is named, wherever it appears. The HTTP class
 * buckets below are filter-only groupings, not states.
 */
export const REQUEST_STATE_LABELS: Record<string, string> = {
  pending: "进行中",
  streaming: "流式",
  complete: "完成",
  tunnel: "未解密",
  failed: "失败",
};

export function requestStateLabel(state: string): string {
  return REQUEST_STATE_LABELS[state] ?? state;
}

export const STATUS_LABELS: Record<QuickStatus, string> = {
  pending: REQUEST_STATE_LABELS.pending,
  streaming: REQUEST_STATE_LABELS.streaming,
  "2xx": "2xx",
  "3xx": "3xx",
  "4xx": "4xx",
  "5xx": "5xx",
  failed: REQUEST_STATE_LABELS.failed,
  tunnel: REQUEST_STATE_LABELS.tunnel,
};
export const SHOWNET_LABELS: Record<QuickShownet, string> = { hook: "有 Hook", snippets: "有代码片段", risk: "有风险", slow: "慢请求" };
export const RISK_LABELS: Record<string, string> = { none: "无风险", info: "信息", warning: "注意", critical: "严重" };

/* ---- Active filter description ---------------------------------------
   Filters can be set from the search box, the method chips, the filter panel
   and the facet sidebar. Without a single read-out of the combined state, a
   list filtered from three surfaces looks identical to an empty session. */

/** Every part of the quick filter that holds a removable list of values. */
export type QuickFilterListKey = Exclude<keyof QuickFilterState, "text">;

export interface ActiveFilterChip {
  /** Stable React key. */
  id: string;
  /** Which slice of state this came from; `text` is the search box. */
  group: QuickFilterListKey | "text" | "advanced";
  /** Group name shown before the value, e.g. 方法. */
  groupLabel: string;
  /** Human-readable value, already label-mapped. */
  label: string;
  /** Raw value, used to remove exactly this entry. */
  value?: string;
}

const GROUP_LABELS: Record<QuickFilterListKey | "text" | "advanced", string> = {
  text: "搜索",
  hosts: "域名",
  methods: "方法",
  protocols: "协议",
  types: "类型",
  statuses: "状态",
  exactStatuses: "状态码",
  sources: "来源",
  risks: "风险",
  shownet: "标记",
  advanced: "自定义条件",
};

/** Order matches how the groups read in the panel, so the chip row is stable. */
const CHIP_GROUP_ORDER: QuickFilterListKey[] = [
  "methods", "hosts", "types", "protocols", "statuses", "exactStatuses", "sources", "risks", "shownet",
];

export function describeActiveFilters(
  state: QuickFilterState,
  advanced: FilterExpression | undefined,
  sourceLabels: Record<string, string> = {},
): ActiveFilterChip[] {
  const chips: ActiveFilterChip[] = [];
  const text = state.text.trim();
  if (text) chips.push({ id: "text", group: "text", groupLabel: GROUP_LABELS.text, label: text });

  const labelFor = (group: QuickFilterListKey, value: string) => {
    if (group === "protocols") return PROTOCOL_LABELS[value] ?? value;
    if (group === "types") return TYPE_LABELS[value] ?? value;
    if (group === "statuses") return STATUS_LABELS[value as QuickStatus] ?? value;
    if (group === "shownet") return SHOWNET_LABELS[value as QuickShownet] ?? value;
    if (group === "risks") return RISK_LABELS[value] ?? value;
    if (group === "sources") return sourceLabels[value] ?? value;
    return value;
  };

  for (const group of CHIP_GROUP_ORDER) {
    for (const value of state[group]) {
      chips.push({
        id: `${group}:${value}`,
        group,
        groupLabel: GROUP_LABELS[group],
        label: labelFor(group, value),
        value,
      });
    }
  }

  // The builder can express arbitrary nesting, so it collapses to one chip that
  // clears the whole expression rather than pretending to be per-predicate.
  if (advanced) {
    chips.push({
      id: "advanced",
      group: "advanced",
      groupLabel: GROUP_LABELS.advanced,
      label: `${countPredicates(advanced)} 个条件`,
    });
  }
  return chips;
}

function countPredicates(expression: FilterExpression): number {
  return expression.kind === "predicate" ? 1 : expression.children.reduce((total, child) => total + countPredicates(child), 0);
}

/** Remove exactly the criterion a chip represents. Advanced is handled by the caller. */
export function removeActiveFilter(state: QuickFilterState, chip: ActiveFilterChip): QuickFilterState {
  if (chip.group === "advanced") return state;
  if (chip.group === "text") return { ...state, text: "" };
  const current = state[chip.group] as readonly string[];
  return { ...state, [chip.group]: current.filter((entry) => entry !== chip.value) };
}

/** How many independent criteria are narrowing the list right now. */
export function countActiveFilters(state: QuickFilterState, advanced?: FilterExpression): number {
  return describeActiveFilters(state, advanced).length;
}

export function createPredicate(field: RequestField = "url"): FilterExpression {
  return { kind: "predicate", field, operator: "contains", value: "" };
}

export function normalizeFilterExpression(expression: FilterExpression | undefined): FilterExpression | undefined {
  if (!expression) return undefined;
  if (expression.kind === "predicate") {
    if (expression.operator !== "exists" && (expression.value === "" || expression.value == null)) return undefined;
    return expression;
  }
  const children = expression.children
    .map((child) => normalizeFilterExpression(child))
    .filter((child): child is FilterExpression => Boolean(child));
  if (children.length === 0) return undefined;
  return children.length === 1 ? children[0] : { ...expression, children };
}

export function serializeFilterExpression(expression: FilterExpression | undefined) {
  return JSON.stringify(expression ?? null);
}

export function parseFilterExpression(raw: string): FilterExpression | undefined {
  try {
    const value: unknown = JSON.parse(raw);
    return isFilterExpression(value) ? normalizeFilterExpression(value) : undefined;
  } catch {
    return undefined;
  }
}

export function isFilterExpression(value: unknown): value is FilterExpression {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Record<string, unknown>;
  if (candidate.kind === "group") {
    return (candidate.operator === "and" || candidate.operator === "or")
      && Array.isArray(candidate.children)
      && candidate.children.every(isFilterExpression);
  }
  return candidate.kind === "predicate"
    && typeof candidate.field === "string"
    && typeof candidate.operator === "string";
}

function predicate(field: RequestField, operator: "contains" | "equals" | "gte" | "lt" | "gt" | "not_equals", value: string | number | boolean): FilterExpression {
  return { kind: "predicate", field, operator, value };
}

function addOrGroup(groups: FilterExpression[], children: FilterExpression[]) {
  if (children.length === 1) groups.push(children[0]);
  else if (children.length > 1) groups.push({ kind: "group", operator: "or", children });
}

function typePredicates(value: string): FilterExpression[] {
  if (value === "api") return [predicate("type", "equals", "fetch"), predicate("type", "equals", "xhr")];
  return [predicate("type", "equals", value)];
}

function statusPredicate(value: QuickStatus): FilterExpression {
  if (value === "pending" || value === "streaming" || value === "failed" || value === "tunnel") return predicate("state", "equals", value);
  const floor = Number(value[0]) * 100;
  return { kind: "group", operator: "and", children: [predicate("status", "gte", floor), predicate("status", "lt", floor + 100)] };
}

function exactStatusPredicate(value: string): FilterExpression {
  const status = Number(value);
  return Number.isFinite(status)
    ? predicate("status", "equals", status)
    : predicate("state", "equals", value);
}

function shownetPredicate(value: QuickShownet): FilterExpression {
  if (value === "hook") return predicate("hasHook", "equals", true);
  if (value === "snippets") return predicate("cryptoSnippetCount", "gt", 0);
  if (value === "slow") return predicate("durationMs", "gte", SLOW_REQUEST_MS);
  return predicate("risk", "not_equals", "none");
}
