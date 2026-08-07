import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Own file, and it has to be: the runtime installs once per realm behind a
 * non-configurable flag, and its library probe runs on an interval created at
 * install time. Sharing a realm with another install means the second
 * `new Function(...)` returns immediately, no interval exists, and
 * `advanceTimersByTime` drives nothing — the test then passes without ever
 * reaching the code it names.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("a prototype chain that points at itself", () => {
  it("does not hang the probe", () => {
    let traversals = 0;
    const cyclic: Record<string, unknown> = {};
    const proxy: unknown = new Proxy(cyclic, {
      getPrototypeOf: () => {
        traversals += 1;
        return proxy as object;
      },
    });
    Object.defineProperty(globalThis, "sm2", { configurable: true, writable: true, value: proxy });

    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();

    // Unbounded, this never returns: the probe runs on the page's main thread.
    expect(() => vi.advanceTimersByTime(600)).not.toThrow();

    // Proves the walk actually happened — without this the test would pass just
    // as happily against an install that never ran.
    expect(traversals).toBeGreaterThan(0);
  });

});
