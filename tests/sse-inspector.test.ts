import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { filterAndOrderSseEvents, isSseTerminal, prettySseData, sseEventLabel } from "../src/sseInspector.ts";
import type { SseEvent } from "../src/types.ts";

function event(sequence: number, data: string, overrides: Partial<SseEvent["payload"]> = {}): SseEvent {
  return {
    sessionId: "session-sse",
    source: "desktop",
    sourceInstanceId: "proxy:127.0.0.1",
    requestId: "request-sse",
    sequence,
    timestamp: 1_785_393_200_000 + sequence,
    phase: "sse",
    payload: {
      kind: "event",
      event: "message",
      data,
      raw: `data: ${data}\n`,
      fields: [{ name: "data", value: data }],
      comments: [],
      sizeBytes: data.length,
      truncated: false,
      incomplete: false,
      index: sequence,
      ...overrides,
    },
  };
}

describe("SSE inspector", () => {
  it("searches case-insensitively across names, IDs, data and custom fields", () => {
    const events = [
      event(1, "Order PAID", { event: "order.updated", id: "EVT-42" }),
      event(2, "heartbeat", { fields: [{ name: "X-Trace", value: "EDGE-A" }] }),
    ];
    assert.deepEqual(filterAndOrderSseEvents(events, "paid", "ascending").map((item) => item.sequence), [1]);
    assert.deepEqual(filterAndOrderSseEvents(events, "evt-42", "ascending").map((item) => item.sequence), [1]);
    assert.deepEqual(filterAndOrderSseEvents(events, "edge-a", "ascending").map((item) => item.sequence), [2]);
  });

  it("keeps capture order stable and supports latest-first display", () => {
    const events = [event(3, "third"), event(1, "first"), event(2, "second")];
    assert.deepEqual(filterAndOrderSseEvents(events, "", "ascending").map((item) => item.sequence), [1, 2, 3]);
    assert.deepEqual(filterAndOrderSseEvents(events, "", "descending").map((item) => item.sequence), [3, 2, 1]);
  });

  it("pretty-prints JSON as inert text and identifies terminal evidence", () => {
    assert.equal(prettySseData('{"ok":true}'), '{\n  "ok": true\n}');
    assert.equal(prettySseData("<script>alert(1)</script>"), "<script>alert(1)</script>");
    const end = event(4, "事件流已结束", { kind: "stream_end", event: "stream_end", complete: true });
    assert.equal(sseEventLabel(end), "流已结束");
    assert.equal(isSseTerminal(end), true);
  });
});
