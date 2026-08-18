import { t, type MessageKey } from "./i18n.ts";
import type { RequestField, RequestListItem, RequestSort } from "./types";

export const REQUEST_GRID_ROW_HEIGHT = 38;
export const REQUEST_GRID_HEADER_HEIGHT = 32;
export const REQUEST_GRID_OVERSCAN = 8;
export const REQUEST_GRID_PREFERENCES_VERSION = 1;
export const REQUEST_GRID_PREFERENCES_KEY = "shownet.request-grid.preferences.v1";

export type RequestColumnId =
  | "order"
  | "state"
  | "method"
  | "url"
  | "host"
  | "path"
  | "status"
  | "type"
  | "source"
  | "sourceInstanceId"
  | "protocol"
  | "sizeBytes"
  | "durationMs"
  | "startedAt"
  | "risk"
  | "hasHook"
  | "cryptoSnippetCount"
  | "tlsIntercepted";

export interface RequestColumnDefinition {
  id: RequestColumnId;
  label: string;
  field: RequestField;
  width: number;
  minWidth: number;
  maxWidth: number;
  defaultVisible: boolean;
  locked?: boolean;
}

export interface RequestGridPreferences {
  version: number;
  order: RequestColumnId[];
  visible: RequestColumnId[];
  widths: Partial<Record<RequestColumnId, number>>;
}

export interface VirtualWindow {
  start: number;
  end: number;
  offsetTop: number;
  totalHeight: number;
}

export const requestColumnDefinitions: RequestColumnDefinition[] = [
  { id: "order", label: "序号", field: "order", width: 58, minWidth: 52, maxWidth: 100, defaultVisible: true, locked: true },
  { id: "state", label: "状态", field: "state", width: 68, minWidth: 60, maxWidth: 100, defaultVisible: true },
  { id: "method", label: "方法", field: "method", width: 66, minWidth: 58, maxWidth: 110, defaultVisible: true },
  { id: "url", label: "完整 URL", field: "url", width: 310, minWidth: 180, maxWidth: 720, defaultVisible: true },
  { id: "host", label: "域名", field: "host", width: 190, minWidth: 120, maxWidth: 480, defaultVisible: false },
  { id: "path", label: "路径", field: "path", width: 220, minWidth: 120, maxWidth: 520, defaultVisible: false },
  { id: "status", label: "状态码", field: "status", width: 68, minWidth: 58, maxWidth: 100, defaultVisible: true },
  { id: "type", label: "类型", field: "type", width: 82, minWidth: 66, maxWidth: 150, defaultVisible: true },
  { id: "source", label: "来源", field: "source", width: 94, minWidth: 78, maxWidth: 150, defaultVisible: true },
  { id: "sourceInstanceId", label: "来源实例", field: "sourceInstanceId", width: 150, minWidth: 100, maxWidth: 320, defaultVisible: false },
  { id: "protocol", label: "协议", field: "protocol", width: 92, minWidth: 72, maxWidth: 140, defaultVisible: true },
  { id: "sizeBytes", label: "大小", field: "sizeBytes", width: 80, minWidth: 66, maxWidth: 130, defaultVisible: true },
  { id: "durationMs", label: "耗时", field: "durationMs", width: 82, minWidth: 68, maxWidth: 130, defaultVisible: true },
  { id: "startedAt", label: "开始时间", field: "startedAt", width: 116, minWidth: 98, maxWidth: 180, defaultVisible: false },
  { id: "risk", label: "风险", field: "risk", width: 74, minWidth: 64, maxWidth: 120, defaultVisible: true },
  { id: "hasHook", label: "Hook", field: "hasHook", width: 64, minWidth: 58, maxWidth: 100, defaultVisible: false },
  { id: "cryptoSnippetCount", label: "代码片段", field: "cryptoSnippetCount", width: 82, minWidth: 72, maxWidth: 130, defaultVisible: false },
  { id: "tlsIntercepted", label: "TLS", field: "tlsIntercepted", width: 68, minWidth: 60, maxWidth: 110, defaultVisible: false },
];

const COLUMN_LABEL_KEYS = {
  order: "traffic.col.order",
  state: "traffic.col.state",
  method: "traffic.col.method",
  url: "traffic.col.url",
  host: "traffic.col.host",
  path: "traffic.col.path",
  status: "traffic.col.status",
  type: "traffic.col.type",
  source: "traffic.col.source",
  sourceInstanceId: "traffic.col.sourceInstanceId",
  protocol: "traffic.col.protocol",
  sizeBytes: "traffic.col.sizeBytes",
  durationMs: "traffic.col.durationMs",
  startedAt: "traffic.col.startedAt",
  risk: "traffic.col.risk",
  hasHook: "traffic.col.hasHook",
  cryptoSnippetCount: "traffic.col.cryptoSnippetCount",
  tlsIntercepted: "traffic.col.tlsIntercepted",
} as const satisfies Record<RequestColumnId, MessageKey>;

export function requestColumnLabel(id: RequestColumnId): string {
  return t(COLUMN_LABEL_KEYS[id]);
}

const definitionsById = new Map(requestColumnDefinitions.map((column) => [column.id, column]));

export function defaultRequestGridPreferences(): RequestGridPreferences {
  return {
    version: REQUEST_GRID_PREFERENCES_VERSION,
    order: requestColumnDefinitions.map((column) => column.id),
    visible: requestColumnDefinitions.filter((column) => column.defaultVisible).map((column) => column.id),
    widths: Object.fromEntries(requestColumnDefinitions.map((column) => [column.id, column.width])),
  };
}

export function parseRequestGridPreferences(raw: string | null | undefined): RequestGridPreferences {
  const fallback = defaultRequestGridPreferences();
  if (!raw) return fallback;
  try {
    const candidate = JSON.parse(raw) as Partial<RequestGridPreferences>;
    if (candidate.version !== REQUEST_GRID_PREFERENCES_VERSION) return fallback;
    const validIds = new Set(requestColumnDefinitions.map((column) => column.id));
    const order = Array.isArray(candidate.order)
      ? candidate.order.filter((id): id is RequestColumnId => validIds.has(id as RequestColumnId))
      : [];
    for (const id of fallback.order) if (!order.includes(id)) order.push(id);
    const visible = Array.isArray(candidate.visible)
      ? candidate.visible.filter((id): id is RequestColumnId => validIds.has(id as RequestColumnId))
      : fallback.visible;
    if (!visible.includes("order")) visible.unshift("order");
    const widths: Partial<Record<RequestColumnId, number>> = {};
    for (const column of requestColumnDefinitions) {
      const width = Number(candidate.widths?.[column.id]);
      widths[column.id] = clampWidth(column.id, Number.isFinite(width) ? width : column.width);
    }
    return { version: REQUEST_GRID_PREFERENCES_VERSION, order, visible, widths };
  } catch {
    return fallback;
  }
}

export function visibleRequestColumns(preferences: RequestGridPreferences) {
  const visible = new Set(preferences.visible);
  return preferences.order
    .map((id) => definitionsById.get(id))
    .filter((column): column is RequestColumnDefinition => Boolean(column && visible.has(column.id)));
}

export function requestGridTemplate(preferences: RequestGridPreferences) {
  return visibleRequestColumns(preferences)
    .map((column) => `${preferences.widths[column.id] ?? column.width}px`)
    .join(" ");
}

export function requestGridWidth(preferences: RequestGridPreferences) {
  return visibleRequestColumns(preferences)
    .reduce((total, column) => total + (preferences.widths[column.id] ?? column.width), 0);
}

export function toggleRequestColumn(preferences: RequestGridPreferences, id: RequestColumnId) {
  const definition = definitionsById.get(id);
  if (!definition || definition.locked) return preferences;
  const visible = preferences.visible.includes(id)
    ? preferences.visible.filter((candidate) => candidate !== id)
    : [...preferences.visible, id];
  return { ...preferences, visible };
}

export function resizeRequestColumn(preferences: RequestGridPreferences, id: RequestColumnId, width: number) {
  return { ...preferences, widths: { ...preferences.widths, [id]: clampWidth(id, width) } };
}

export function reorderRequestColumn(preferences: RequestGridPreferences, source: RequestColumnId, target: RequestColumnId) {
  if (source === target || !preferences.order.includes(source) || !preferences.order.includes(target)) return preferences;
  const order = preferences.order.filter((id) => id !== source);
  order.splice(order.indexOf(target), 0, source);
  return { ...preferences, order };
}

export function estimateRequestColumnWidth(id: RequestColumnId, rows: RequestListItem[]) {
  const definition = definitionsById.get(id);
  if (!definition) return 100;
  const sample = rows.slice(0, 200);
  const longest = sample.reduce((length, row) => Math.max(length, requestColumnText(row, id).length), definition.label.length);
  return clampWidth(id, 24 + longest * 7);
}

export function nextRequestSort(sort: RequestSort[], field: RequestField, additive: boolean) {
  const existing = sort.find((entry) => entry.field === field);
  const nextDirection = !existing ? "asc" : existing.direction === "asc" ? "desc" : undefined;
  const retained = additive ? sort.filter((entry) => entry.field !== field) : [];
  return nextDirection ? [...retained, { field, direction: nextDirection } satisfies RequestSort] : retained;
}

export function calculateVirtualWindow(
  total: number,
  scrollTop: number,
  viewportHeight: number,
  rowHeight = REQUEST_GRID_ROW_HEIGHT,
  overscan = REQUEST_GRID_OVERSCAN,
): VirtualWindow {
  if (total <= 0 || rowHeight <= 0) return { start: 0, end: 0, offsetTop: 0, totalHeight: 0 };
  const bodyScrollTop = Math.max(0, scrollTop - REQUEST_GRID_HEADER_HEIGHT);
  const start = Math.max(0, Math.floor(bodyScrollTop / rowHeight) - overscan);
  const visibleCount = Math.ceil(Math.max(0, viewportHeight) / rowHeight);
  const end = Math.min(total, start + visibleCount + overscan * 2);
  return { start, end, offsetTop: start * rowHeight, totalHeight: total * rowHeight };
}

export function requestColumnText(row: RequestListItem, id: RequestColumnId) {
  switch (id) {
    case "url": return `${row.scheme}://${row.host}${row.path}${row.query ? `?${row.query}` : ""}`;
    case "sizeBytes": return String(row.sizeBytes);
    case "durationMs": return row.durationMs == null ? "" : String(row.durationMs);
    case "startedAt": return new Date(row.startedAt).toISOString();
    case "hasHook": return row.hasHook ? "Hook" : "";
    case "tlsIntercepted": return row.tlsIntercepted ? row.tlsVersion ?? "TLS" : "未解密";
    default: return String(row[id] ?? "");
  }
}

function clampWidth(id: RequestColumnId, width: number) {
  const definition = definitionsById.get(id);
  if (!definition) return width;
  return Math.min(definition.maxWidth, Math.max(definition.minWidth, Math.round(width)));
}
