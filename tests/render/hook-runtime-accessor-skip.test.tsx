import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Own file. The runtime installs once per realm behind a non-configurable flag,
 * so a second install in a shared realm is a no-op: no interval is registered,
 * the probe never runs, and assertions about what it did or did not wrap hold
 * vacuously. This test only means anything in a realm of its own.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("an inherited accessor", () => {
  it("is left alone rather than flattened into a data property", () => {
    const seen: string[] = [];
    Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", {
      configurable: true,
      value: (payload: string) => seen.push(payload),
    });

    let reads = 0;
    class Lazy {
      get encrypt() {
        reads += 1;
        return (value: string) => `enc:${value}`;
      }
    }
    const sm2 = new Lazy();
    Object.defineProperty(globalThis, "sm2", { configurable: true, writable: true, value: sm2 });

    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();
    vi.advanceTimersByTime(600);

    // Proof the probe actually ran and reached this property. Without it the
    // test would pass just as happily against an install that never happened —
    // which is exactly how the shared-realm version of this test was vacuous.
    const skipped = seen
      .map((entry) => JSON.parse(entry))
      .filter((event) => event.name === "hook.skipped")
      .map((event) => event.input.property);
    expect(skipped).toContain("encrypt");

    // Detection reads the descriptor, never the value, so deciding not to hook
    // must not have triggered the getter's own work.
    expect(reads).toBe(0);

    // Installing a wrapper as an own data property would shadow the getter for
    // good — its per-access work would stop, and the matching setter would be
    // silently disabled.
    expect(Object.getOwnPropertyDescriptor(sm2, "encrypt")).toBeUndefined();

    void sm2.encrypt;
    void sm2.encrypt;
    expect(reads).toBe(2);
  });
});
