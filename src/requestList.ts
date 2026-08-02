import type { FacetCount, FilterExpression, RequestFacets, RequestField, RequestListItem, RequestListPage, RequestSort } from "./types";

export const REQUEST_LIST_WINDOW_SIZE = 500;
export const REQUEST_LIST_WINDOW_STRIDE = 250;
export const REQUEST_LIST_WINDOW_PREFETCH = 80;
export const REQUEST_QUERY_CANCELLED = "REQUEST_QUERY_CANCELLED";

export function createRequestQueryId(sequence: number, now = Date.now()) {
  return `request-${Math.max(0, Math.floor(now)).toString(36)}-${Math.max(0, Math.floor(sequence)).toString(36)}`;
}

export function isRequestQueryCancelled(error: unknown) {
  return String(error).includes(REQUEST_QUERY_CANCELLED);
}

export function shouldChangeRequestListWindow(
  desiredOffset: number,
  currentOffset: number,
  pendingOffset?: number,
) {
  const desired = Math.max(0, Math.floor(desiredOffset));
  const current = Math.max(0, Math.floor(currentOffset));
  const pending = pendingOffset == null ? undefined : Math.max(0, Math.floor(pendingOffset));
  if (desired === current) return pending !== undefined && pending !== desired;
  return pending !== desired;
}

export function requiresLiveQueryRefresh(filter: FilterExpression | undefined, sort: RequestSort[]) {
  return Boolean(filter)
    || sort.length !== 1
    || sort[0].field !== "order"
    || sort[0].direction !== "asc";
}

export function queryPreviewRequestList(
  items: RequestListItem[],
  filter: FilterExpression | undefined,
  sort: RequestSort[],
): RequestListPage {
  const filtered = filter ? items.filter((item) => matchesPreviewFilter(item, filter)) : [...items];
  filtered.sort((left, right) => comparePreviewRequests(left, right, sort));
  return {
    items: filtered,
    totalCount: items.length,
    filteredCount: filtered.length,
    hookCount: filtered.filter((item) => item.hasHook).length,
    bookmarkedCount: filtered.filter((item) => item.annotation?.bookmarked).length,
    facets: previewFacets(filtered),
  };
}

function matchesPreviewFilter(item: RequestListItem, expression: FilterExpression): boolean {
  if (expression.kind === "group") {
    return expression.operator === "and"
      ? expression.children.every((child) => matchesPreviewFilter(item, child))
      : expression.children.some((child) => matchesPreviewFilter(item, child));
  }
  const actual = previewRequestField(item, expression.field);
  const expected = expression.value;
  if (expression.operator === "exists") return actual !== undefined && actual !== null && String(actual) !== "";
  if (actual === undefined || actual === null || expected === undefined || expected === null) {
    return expression.operator === "not_equals" || expression.operator === "not_contains";
  }
  if (["gt", "gte", "lt", "lte"].includes(expression.operator)) {
    const left = Number(actual);
    const right = Number(expected);
    if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
    if (expression.operator === "gt") return left > right;
    if (expression.operator === "gte") return left >= right;
    if (expression.operator === "lt") return left < right;
    return left <= right;
  }
  if (typeof actual === "boolean" || typeof expected === "boolean") {
    const equal = actual === expected;
    return expression.operator === "not_equals" ? !equal : equal;
  }
  const left = String(actual).toLocaleLowerCase();
  const right = String(expected).toLocaleLowerCase();
  if (expression.operator === "contains") return left.includes(right);
  if (expression.operator === "not_contains") return !left.includes(right);
  if (expression.operator === "equals") return left === right;
  if (expression.operator === "not_equals") return left !== right;
  if (expression.operator === "starts_with") return left.startsWith(right);
  if (expression.operator === "ends_with") return left.endsWith(right);
  if (expression.operator === "wildcard") return wildcardPattern(right).test(left);
  if (expression.operator === "regex") {
    try {
      return new RegExp(String(expected), "i").test(String(actual));
    } catch {
      return false;
    }
  }
  return false;
}

function wildcardPattern(value: string) {
  const source = value.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${source}$`, "i");
}

function comparePreviewRequests(left: RequestListItem, right: RequestListItem, sort: RequestSort[]) {
  const effectiveSort = sort.length ? sort.slice(0, 3) : [{ field: "order", direction: "asc" } satisfies RequestSort];
  for (const entry of effectiveSort) {
    const compared = comparePreviewValues(previewSortField(left, entry.field), previewSortField(right, entry.field));
    if (compared !== 0) return entry.direction === "asc" ? compared : -compared;
  }
  return left.id.localeCompare(right.id);
}

function comparePreviewValues(left: string | number | boolean | undefined, right: string | number | boolean | undefined) {
  if (left === right) return 0;
  if (left === undefined) return 1;
  if (right === undefined) return -1;
  if (typeof left === "number" && typeof right === "number") return left - right;
  if (typeof left === "boolean" && typeof right === "boolean") return Number(left) - Number(right);
  return String(left).localeCompare(String(right), undefined, { numeric: true, sensitivity: "base" });
}

function previewRequestField(item: RequestListItem, field: RequestField): string | number | boolean | undefined {
  if (field === "url") return `${item.scheme}://${item.host}${item.path}${item.query ? `?${item.query}` : ""}`;
  if (field === "hook") return item.hasHook ? "hook" : undefined;
  if (field === "requestHeader" || field === "responseHeader" || field === "requestBody" || field === "responseBody") return undefined;
  return item[field];
}

function previewSortField(item: RequestListItem, field: RequestField): string | number | boolean | undefined {
  if (field === "risk") return ({ none: 0, info: 1, warning: 2, critical: 3 } as const)[item.risk];
  if (field === "state") return ({ pending: 0, streaming: 1, complete: 2, failed: 3, tunnel: 4 } as const)[item.state];
  return previewRequestField(item, field);
}

function previewFacets(items: RequestListItem[]): RequestFacets {
  return {
    hosts: countPreviewFacets(items.map((item) => item.host), 100),
    methods: countPreviewFacets(items.map((item) => item.method), 16),
    sources: countPreviewFacets(items.map((item) => item.source), 16),
    protocols: countPreviewFacets(items.map((item) => item.protocol), 16),
    statuses: countPreviewFacets(items.map((item) => item.status?.toString() ?? item.state), 64),
    types: countPreviewFacets(items.map((item) => item.type), 32),
    risks: countPreviewFacets(items.map((item) => item.risk), 16),
  };
}

function countPreviewFacets(values: string[], limit: number): FacetCount[] {
  const counts = new Map<string, number>();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value))
    .slice(0, limit);
}

export function upsertRequestListItem(items: RequestListItem[], item: RequestListItem) {
  const index = items.findIndex((candidate) => candidate.id === item.id);
  if (index >= 0) {
    if (items[index] === item) return items;
    const next = items.slice();
    next[index] = item;
    return next;
  }
  const next = [...items, item];
  next.sort((left, right) => left.order - right.order || left.id.localeCompare(right.id));
  return next;
}

export interface RequestListBatchEntry {
  item: RequestListItem;
  created: boolean;
}

export function mergeRequestListItems(items: RequestListItem[], entries: RequestListBatchEntry[]) {
  if (entries.length === 0) return items;
  const updates = new Map(entries.map((entry) => [entry.item.id, entry.item]));
  const merged = items.map((item) => updates.get(item.id) ?? item);
  for (const entry of entries) {
    if (!items.some((item) => item.id === entry.item.id)) merged.push(entry.item);
  }
  merged.sort((left, right) => left.order - right.order || left.id.localeCompare(right.id));
  return merged;
}

export function appendRequestListPage(items: RequestListItem[], page: RequestListItem[]) {
  if (page.length === 0) return items;
  const known = new Set(items.map((item) => item.id));
  const appended = page.filter((item) => !known.has(item.id));
  return appended.length === 0 ? items : [...items, ...appended];
}

export function nextRequestListWindowOffset(
  total: number,
  currentOffset: number,
  loadedLength: number,
  visibleStart: number,
  visibleEnd: number,
  windowSize = REQUEST_LIST_WINDOW_SIZE,
  stride = REQUEST_LIST_WINDOW_STRIDE,
  prefetch = REQUEST_LIST_WINDOW_PREFETCH,
) {
  const boundedTotal = Math.max(0, Math.floor(total));
  const maxOffset = Math.max(0, boundedTotal - windowSize);
  if (maxOffset === 0) return 0;

  const offset = Math.min(maxOffset, Math.max(0, Math.floor(currentOffset)));
  const loadedEnd = offset + Math.max(0, loadedLength);
  const start = Math.min(boundedTotal, Math.max(0, Math.floor(visibleStart)));
  const end = Math.min(boundedTotal, Math.max(start, Math.ceil(visibleEnd)));

  if (start >= offset && end <= loadedEnd) {
    if (end > loadedEnd - prefetch && offset < maxOffset) return Math.min(maxOffset, offset + stride);
    if (start < offset + prefetch && offset > 0) return Math.max(0, offset - stride);
    return offset;
  }

  const visibleRows = Math.max(1, end - start);
  const centered = Math.max(0, start - Math.floor((windowSize - visibleRows) / 2));
  return Math.min(maxOffset, Math.floor(centered / stride) * stride);
}

export function mergeRequestWindowItems(
  items: RequestListItem[],
  entries: RequestListBatchEntry[],
  offset: number,
  windowSize = REQUEST_LIST_WINDOW_SIZE,
) {
  if (entries.length === 0) return items;
  const updates = new Map(entries.map((entry) => [entry.item.id, entry.item]));
  const known = new Set(items.map((item) => item.id));
  const merged = items.map((item) => updates.get(item.id) ?? item);
  for (const entry of entries) {
    const absoluteIndex = entry.item.order - 1;
    if (!known.has(entry.item.id) && absoluteIndex >= offset && absoluteIndex < offset + windowSize) {
      merged.push(entry.item);
    }
  }
  merged.sort((left, right) => left.order - right.order || left.id.localeCompare(right.id));
  return merged.slice(0, windowSize);
}

export function addCreatedItemsToFacets(facets: RequestFacets, entries: RequestListBatchEntry[]) {
  const created = entries.filter((entry) => entry.created).map((entry) => entry.item);
  if (created.length === 0) return facets;
  return {
    hosts: addFacetValues(facets.hosts, created.map((item) => item.host), 100),
    methods: addFacetValues(facets.methods, created.map((item) => item.method), 16),
    sources: addFacetValues(facets.sources, created.map((item) => item.source), 16),
    protocols: addFacetValues(facets.protocols, created.map((item) => item.protocol), 16),
    statuses: addFacetValues(facets.statuses, created.map((item) => item.status?.toString() ?? item.state), 64),
    types: addFacetValues(facets.types, created.map((item) => item.type), 32),
    risks: addFacetValues(facets.risks, created.map((item) => item.risk), 16),
  };
}

function addFacetValues(facets: FacetCount[], values: string[], limit: number) {
  const counts = new Map(facets.map((facet) => [facet.value, facet.count]));
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return [...counts.entries()]
    .map(([value, count]) => ({ value, count }))
    .sort((left, right) => right.count - left.count || left.value.localeCompare(right.value))
    .slice(0, limit);
}

export function createRequestListBatcher(
  flush: (entries: RequestListBatchEntry[]) => void,
  delayMs = 100,
) {
  const pending = new Map<string, RequestListBatchEntry>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const run = () => {
    timer = undefined;
    if (pending.size === 0) return;
    const entries = [...pending.values()];
    pending.clear();
    flush(entries);
  };
  return {
    enqueue(item: RequestListItem, created: boolean) {
      const previous = pending.get(item.id);
      pending.set(item.id, { item, created: created || previous?.created === true });
      if (timer === undefined) timer = setTimeout(run, delayMs);
    },
    flushNow() {
      if (timer !== undefined) clearTimeout(timer);
      run();
    },
    dispose() {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
      pending.clear();
    },
    size() {
      return pending.size;
    },
  };
}

export function createRefreshCoalescer(refresh: () => void, delayMs = 250) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return {
    trigger() {
      if (timer !== undefined) return;
      timer = setTimeout(() => {
        timer = undefined;
        refresh();
      }, delayMs);
    },
    dispose() {
      if (timer !== undefined) clearTimeout(timer);
      timer = undefined;
    },
    pending() {
      return timer !== undefined;
    },
  };
}
