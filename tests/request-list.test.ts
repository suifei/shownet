import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createRefreshCoalescer, createRequestListBatcher, createRequestQueryId, isRequestQueryCancelled, mergeRequestWindowItems, nextRequestListWindowOffset, queryPreviewRequestList, requiresLiveQueryRefresh, shouldChangeRequestListWindow, upsertRequestListItem } from "../src/requestList.ts";
import type { RequestListItem } from "../src/types.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("request query cancellation identity", () => {
  it("creates bounded query IDs and recognizes the backend cancellation sentinel", () => {
    assert.match(createRequestQueryId(8, 1_725_000_000_000), /^request-[0-9a-z]+-8$/);
    assert.equal(isRequestQueryCancelled(new Error("REQUEST_QUERY_CANCELLED")), true);
    assert.equal(isRequestQueryCancelled("database interrupted"), false);
  });
});

function item(id: string, order: number, status = 200): RequestListItem {
  return {
    id,
    order,
    startedAt: order,
    completedAt: order + 1,
    state: "complete",
    method: "GET",
    scheme: "https",
    host: "api.example.test",
    path: `/${id}`,
    status,
    type: "fetch",
    source: "browser",
    sourceInstanceId: "browser-test",
    protocol: "h2",
    sizeBytes: 128,
    durationMs: 10,
    risk: "none",
    hasHook: false,
    cryptoSnippetCount: 0,
    tlsIntercepted: true,
    tlsVersion: "TLS 1.3",
  };
}

describe("request list incremental updates", () => {
  it("inserts in stable order and replaces an existing row without duplication", () => {
    const first = upsertRequestListItem([item("b", 2)], item("a", 1));
    assert.deepEqual(first.map((entry) => entry.id), ["a", "b"]);

    const updated = upsertRequestListItem(first, item("a", 1, 503));
    assert.equal(updated.length, 2);
    assert.equal(updated[0].status, 503);
    assert.deepEqual(updated.map((entry) => entry.id), ["a", "b"]);
  });

  it("coalesces a capture burst into one refresh window", async () => {
    let refreshes = 0;
    const coalescer = createRefreshCoalescer(() => { refreshes += 1; }, 10);
    for (let index = 0; index < 100; index += 1) coalescer.trigger();
    assert.equal(coalescer.pending(), true);
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(refreshes, 1);
    assert.equal(coalescer.pending(), false);

    coalescer.trigger();
    coalescer.dispose();
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(refreshes, 1);
  });

  it("batches row events by id and preserves the created flag", async () => {
    const batches: Array<Array<{ id: string; created: boolean; status?: number }>> = [];
    const batcher = createRequestListBatcher((entries) => {
      batches.push(entries.map((entry) => ({ id: entry.item.id, created: entry.created, status: entry.item.status })));
    }, 10);
    batcher.enqueue(item("a", 1), true);
    batcher.enqueue(item("a", 1, 503), false);
    for (let index = 0; index < 99; index += 1) batcher.enqueue(item(`row-${index}`, index + 2), true);
    assert.equal(batcher.size(), 100);
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.equal(batches.length, 1);
    assert.equal(batches[0].length, 100);
    assert.deepEqual(batches[0].find((entry) => entry.id === "a"), { id: "a", created: true, status: 503 });
  });

  it("wires capture row events without a full request-list refresh", () => {
    const source = readFileSync(join(root, "src/App.tsx"), "utf8");
    const start = source.indexOf('listen<RequestListEvent>("capture://request-created"');
    const end = source.indexOf('listen<RuntimeStatus>("capture://status"', start);
    assert.ok(start >= 0 && end > start);
    const eventHandlers = source.slice(start, end);
    assert.match(eventHandlers, /requestListBatcher\.enqueue/);
    assert.match(eventHandlers, /liveDisplayPausedRef\.current/);
    assert.match(eventHandlers, /bufferLiveDisplaySyncEntry/);
    assert.doesNotMatch(eventHandlers, /refreshRequests/);
    assert.match(source, /createRefreshCoalescer\(\(\) => void refreshSessions\(\), 250\)/);
    assert.match(source, /createRequestListBatcher[\s\S]{0,1200}requiresLiveQueryRefresh/);
    assert.match(source, /createRequestListBatcher[\s\S]{0,1400}, 100\)/);
    assert.match(source, /synchronizeLiveDisplay[\s\S]{0,1800}refreshRequests\(activeSessionId\)/);
  });

  it("keeps native request summaries in a bounded remote window", () => {
    const app = readFileSync(join(root, "src/App.tsx"), "utf8");
    const traffic = readFileSync(join(root, "src/components/TrafficView.tsx"), "utf8");
    const styles = readFileSync(join(root, "src/styles.css"), "utf8");
    assert.match(app, /invoke<RequestListWindow>\("query_request_window"/);
    assert.match(app, /limit: REQUEST_LIST_WINDOW_SIZE/);
    assert.doesNotMatch(app, /while \(cursor\)/);
    assert.match(traffic, /calculateVirtualWindow\(filteredCount/);
    assert.match(traffic, /request-grid-row is-loading/);
    assert.match(traffic, /shouldChangeRequestListWindow\(desiredWindowOffset/);
    assert.match(app, /requestWindowTargetOffset/);
    assert.match(traffic, /当前窗口/);
    assert.match(styles, /\.request-grid-statusbar\.has-selection/);
    assert.match(styles, /\.selection-window-compact/);
  });

  it("refreshes live results when filtering or custom sorting can change membership or order", () => {
    assert.equal(requiresLiveQueryRefresh(undefined, [{ field: "order", direction: "asc" }]), false);
    assert.equal(requiresLiveQueryRefresh(undefined, [{ field: "durationMs", direction: "desc" }]), true);
    assert.equal(requiresLiveQueryRefresh({ kind: "predicate", field: "status", operator: "gte", value: 400 }, [{ field: "order", direction: "asc" }]), true);
  });

  it("applies visible filtering, sorting and facets in the browser preview", () => {
    const ok = item("ok", 1, 200);
    const server = { ...item("server", 2, 503), risk: "critical" as const };
    const missing = { ...item("missing", 3, 404), state: "failed" as const };
    const page = queryPreviewRequestList(
      [ok, server, missing],
      { kind: "predicate", field: "status", operator: "gte", value: 400 },
      [{ field: "status", direction: "desc" }],
    );
    assert.deepEqual(page.items.map((entry) => entry.id), ["server", "missing"]);
    assert.equal(page.totalCount, 3);
    assert.equal(page.filteredCount, 2);
    assert.deepEqual(page.facets.statuses, [{ value: "404", count: 1 }, { value: "503", count: 1 }]);
    assert.deepEqual(
      queryPreviewRequestList([ok, server, missing], { kind: "predicate", field: "risk", operator: "equals", value: "critical" }, []).items.map((entry) => entry.id),
      ["server"],
    );
    assert.deepEqual(
      queryPreviewRequestList([ok, server, missing], { kind: "predicate", field: "state", operator: "equals", value: "failed" }, []).items.map((entry) => entry.id),
      ["missing"],
    );
    assert.deepEqual(
      queryPreviewRequestList([ok, server, missing], { kind: "predicate", field: "all", operator: "contains", value: "api.example.test" }, []).items.map((entry) => entry.id),
      ["ok", "server", "missing"],
    );
  });

  it("targets overlapping windows and jumps directly across a 100k result set", () => {
    assert.equal(nextRequestListWindowOffset(100_000, 0, 500, 0, 40), 0);
    assert.equal(nextRequestListWindowOffset(100_000, 0, 500, 430, 470), 250);
    assert.equal(nextRequestListWindowOffset(100_000, 250, 500, 260, 300), 0);
    assert.equal(nextRequestListWindowOffset(100_000, 0, 500, 89_990, 90_030), 89_750);
    assert.equal(nextRequestListWindowOffset(100_000, 89_750, 500, 99_970, 100_000), 99_500);
  });

  it("cancels an obsolete window load when scrolling returns to the retained window", () => {
    assert.equal(shouldChangeRequestListWindow(250, 0), true);
    assert.equal(shouldChangeRequestListWindow(250, 0, 250), false);
    assert.equal(shouldChangeRequestListWindow(0, 0, 250), true);
    assert.equal(shouldChangeRequestListWindow(0, 0), false);
    assert.equal(shouldChangeRequestListWindow(500, 250, 500), false);
  });

  it("merges live updates without retaining rows outside the active window", () => {
    const merged = mergeRequestWindowItems(
      [item("a", 1), item("b", 2)],
      [
        { item: item("b", 2, 503), created: false },
        { item: item("c", 3), created: true },
        { item: item("outside", 501), created: true },
      ],
      0,
      500,
    );
    assert.deepEqual(merged.map((entry) => entry.id), ["a", "b", "c"]);
    assert.equal(merged[1].status, 503);
  });
});
