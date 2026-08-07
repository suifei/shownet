import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Own realm: the runtime installs once per realm behind a non-configurable flag,
 * so a second evaluation anywhere in this file would be a silent no-op and every
 * assertion below would hold vacuously.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

describe("wrapped functions do not announce themselves", () => {
  it("answers the standard toString probe with the original source", () => {
    function sentinelFetch(_input?: unknown, _init?: unknown) {
      return undefined;
    }
    // Whatever the engine says about the function we are replacing is what the
    // wrapper has to keep saying. For a real `fetch` that is
    // "function fetch() { [native code] }"; here it is this function's source.
    const originalSource = Function.prototype.toString.call(sentinelFetch);
    Object.defineProperty(globalThis, "fetch", {
      configurable: true,
      writable: true,
      value: sentinelFetch,
    });

    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();

    expect(globalThis.fetch).not.toBe(sentinelFetch);

    // `Function.prototype.toString.call(fn)` is the form a bot manager actually
    // uses. An own toString on the wrapper — the previous approach — does not
    // answer it at all, and carrying one is itself an anomaly: no native
    // function has an own toString.
    expect(Function.prototype.toString.call(globalThis.fetch)).toBe(originalSource);
    expect(String(globalThis.fetch)).toBe(originalSource);
    expect(Object.getOwnPropertyNames(globalThis.fetch)).not.toContain("toString");
  });

  it("leaves unwrapped functions reporting themselves", () => {
    // The proxy must answer for wrappers only; rewriting every function's source
    // would be a louder tell than the one it replaces.
    function ordinary(a: number) {
      return a;
    }
    expect(Function.prototype.toString.call(ordinary)).toContain("ordinary");
  });
});
