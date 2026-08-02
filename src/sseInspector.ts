import type { SseEvent } from "./types";

export type SseOrder = "ascending" | "descending";

export function filterAndOrderSseEvents(events: SseEvent[], query: string, order: SseOrder) {
  const needle = query.trim().toLocaleLowerCase();
  const filtered = needle
    ? events.filter((event) => sseEventSearchText(event).includes(needle))
    : [...events];
  return filtered.sort((left, right) => order === "ascending"
    ? left.sequence - right.sequence
    : right.sequence - left.sequence);
}

export function sseEventSearchText(event: SseEvent) {
  const payload = event.payload;
  return [
    payload.kind,
    payload.event,
    payload.id ?? "",
    payload.retry?.toString() ?? "",
    payload.data,
    payload.raw,
    ...payload.comments,
    ...payload.fields.flatMap((field) => [field.name, field.value]),
  ].join("\n").toLocaleLowerCase();
}

export function prettySseData(data: string) {
  const value = data.trim();
  if (!(value.startsWith("{") || value.startsWith("["))) return data;
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return data;
  }
}

export function sseEventLabel(event: SseEvent) {
  const payload = event.payload;
  if (payload.kind === "heartbeat") return "心跳";
  if (payload.kind === "stream_end") return payload.complete ? "流已结束" : "流已中断";
  if (payload.kind === "capture_limit") return "已达保存上限";
  if (payload.kind === "stream_notice") return "流提示";
  if (payload.kind === "partial") return "未完整事件";
  return payload.event || "message";
}

export function isSseTerminal(event: SseEvent) {
  return event.payload.kind === "stream_end" || event.payload.kind === "capture_limit";
}
