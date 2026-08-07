import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Lives in its own file because the hook runtime installs once per realm and
 * wraps whatever `fetch` it finds at that moment. To prove the wrapper does not
 * substitute its own failure for the page's, `fetch` has to be a function we
 * control *before* the runtime is installed — which needs a fresh realm.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

/** Refuses enumeration, the way an anti-hooking page does. */
function unwalkable() {
  return new Proxy(
    {},
    {
      ownKeys() {
        throw new Error("enumeration refused");
      },
    },
  );
}

class SentinelFailure extends Error {}

describe("fetch wrapper", () => {
  it("rethrows the failure the page's fetch produced, not the one describing it produced", async () => {
    const nativeCalls: unknown[] = [];
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      writable: true,
      value: (...args: unknown[]) => {
        nativeCalls.push(args);
        throw new SentinelFailure("the real reason");
      },
    });

    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();

    let raised: unknown;
    try {
      // Headers that cannot be enumerated: the reporter trips on them while
      // describing the very call that already failed for its own reason.
      (globalThis.fetch as (input: string, init?: unknown) => unknown)("https://example.com/", {
        headers: unwalkable(),
      });
    } catch (error) {
      raised = error;
    }

    expect(nativeCalls).toHaveLength(1);
    expect(raised).toBeInstanceOf(SentinelFailure);
    expect((raised as Error).message).toBe("the real reason");
  });
});
