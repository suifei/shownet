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
    const numeric = Number(text);
    const textPredicates: FilterExpression[] = [
      predicate("url", "contains", text),
      predicate("host", "contains", text),
      predicate("path", "contains", text),
    ];
    if (Number.isFinite(numeric)) textPredicates.push(predicate("status", "equals", numeric));
    addOrGroup(groups, textPredicates);
  }
  if (advanced) groups.push(advanced);
  if (groups.length === 0) return undefined;
  return groups.length === 1 ? groups[0] : { kind: "group", operator: "and", children: groups };
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
  if (value === "slow") return predicate("durationMs", "gte", 1_000);
  return predicate("risk", "not_equals", "none");
}
