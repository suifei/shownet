/**
 * The throttle dropped a second, different failure purely because of timing.
 * These tests pin the property that matters: nothing is lost.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  createProxyErrorQueue,
  PROXY_ERROR_WINDOW_MS,
  truncateProxyError,
} from "../src/proxyErrorQueue.ts";

function harness(startAt = 1_000) {
  const shown: string[] = [];
  let clock = startAt;
  const timers = new Map<number, { at: number; run: () => void }>();
  let nextHandle = 1;

  const queue = createProxyErrorQueue({
    show: (message) => shown.push(message),
    now: () => clock,
    schedule: (callback, delayMs) => {
      const handle = nextHandle++;
      timers.set(handle, { at: clock + delayMs, run: callback });
      return handle;
    },
    cancel: (handle) => void timers.delete(handle),
  });

  const advance = (ms: number) => {
    clock += ms;
    for (const [handle, timer] of [...timers]) {
      if (timer.at <= clock) {
        timers.delete(handle);
        timer.run();
      }
    }
  };

  return { queue, shown, advance, pendingTimers: () => timers.size };
}

describe("proxy error toasts are rate limited without being lost", () => {
  it("shows the first failure immediately", () => {
    const { queue, shown } = harness();
    queue.push("连接 example.test:443 超时");
    assert.deepEqual(shown, ["连接 example.test:443 超时"]);
  });

  it("does not discard a different failure that arrives inside the window", () => {
    // The original bug: this second message was dropped outright, so a real
    // failure could be swallowed by an unrelated one 300ms earlier.
    const { queue, shown, advance } = harness();
    queue.push("HTTPS 绕行隧道传输失败");
    queue.push("连接 example.test:443 超时");
    assert.deepEqual(shown, ["HTTPS 绕行隧道传输失败"], "still rate limited");

    advance(PROXY_ERROR_WINDOW_MS);
    assert.deepEqual(
      shown,
      ["HTTPS 绕行隧道传输失败", "连接 example.test:443 超时"],
      "the held failure must arrive once the window opens",
    );
  });

  it("keeps the newest and counts the rest rather than queueing a backlog", () => {
    const { queue, shown, advance } = harness();
    queue.push("第一条");
    queue.push("第二条");
    queue.push("第三条");
    queue.push("第四条");
    advance(PROXY_ERROR_WINDOW_MS);
    assert.deepEqual(shown, ["第一条", "第四条（另有 2 条）"]);
  });

  it("shows a later failure directly once the window has passed", () => {
    const { queue, shown, advance } = harness();
    queue.push("第一条");
    advance(PROXY_ERROR_WINDOW_MS + 1);
    queue.push("第二条");
    assert.deepEqual(shown, ["第一条", "第二条"]);
  });

  it("ignores blank payloads", () => {
    const { queue, shown } = harness();
    queue.push("   ");
    queue.push("");
    assert.deepEqual(shown, []);
  });

  it("drops a pending flush when disposed, so an unmounted view stays quiet", () => {
    const { queue, shown, advance, pendingTimers } = harness();
    queue.push("第一条");
    queue.push("第二条");
    queue.dispose();
    assert.equal(pendingTimers(), 0);
    advance(PROXY_ERROR_WINDOW_MS * 2);
    assert.deepEqual(shown, ["第一条"]);
  });

  it("truncates without losing the marker that it was cut", () => {
    const long = "错".repeat(400);
    assert.equal(truncateProxyError(long).length, 221);
    assert.ok(truncateProxyError(long).endsWith("…"));
    assert.equal(truncateProxyError("短"), "短");
  });

  it("is what the shell actually uses", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.match(app, /createProxyErrorQueue/);
    assert.doesNotMatch(
      app,
      /if \(now - lastProxyErrorToastAt\.current < 2500\) return;/,
      "the plain drop must be gone",
    );
  });
});
