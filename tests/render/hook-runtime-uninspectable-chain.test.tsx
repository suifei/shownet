import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * One install per file. The runtime's once-per-realm flag is non-configurable,
 * so a second `new Function(RUNTIME_SOURCE)()` anywhere in the same file is a
 * no-op: no probe interval is registered and every assertion about what the
 * probe decided holds vacuously. Any test that needs a fresh install needs a
 * fresh file.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("a prototype chain the walk could not finish inspecting", () => {
  it("is declined rather than wrapped", () => {
    const seen: string[] = [];
    Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", {
      configurable: true,
      value: (payload: string) => seen.push(payload),
    });

    // Cyclic prototype AND a real function behind the property. The walk hits
    // its depth bound without ever finding a descriptor, so it has to decide
    // what to do about a chain it could not inspect. Without the function the
    // property reads `undefined`, `replace` bails at its typeof check, and the
    // decision would be invisible — which is why the plain cyclic test cannot
    // pin this.
    const target: unknown = new Proxy(
      {},
      {
        getPrototypeOf: () => target as object,
        getOwnPropertyDescriptor: () => undefined,
        get: () => () => "encrypted",
      },
    );
    Object.defineProperty(globalThis, "sm4", { configurable: true, writable: true, value: target });

    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();
    vi.advanceTimersByTime(600);

    // Installing a data property onto a chain we failed to inspect is the unsafe
    // reading; declining is the conservative one. Flipping the exhausted-bound
    // result to `false` makes this fail.
    const skipped = seen
      .map((entry) => JSON.parse(entry))
      .filter((event) => event.name === "hook.skipped")
      .map((event) => event.input.property);
    expect(skipped).toContain("encrypt");
  });
});
