import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Own file because the runtime installs once per realm, and its library probe
 * runs on an interval created at install time. Driving that interval means
 * installing after the objects under test exist, with fake timers already in
 * place — neither of which is possible in a realm where it is already loaded.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("a hook the runtime declined to install", () => {
  it("is reported once, not once per probe tick", () => {
    const seen: string[] = [];
    Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", {
      configurable: true,
      value: (payload: string) => seen.push(payload),
    });

    // Lazy getters on the prototype: the runtime skips these rather than
    // flattening them into data properties.
    class Lazy {
      get encrypt() {
        return (value: string) => `enc:${value}`;
      }
      get decrypt() {
        return (value: string) => value;
      }
    }
    Object.defineProperty(globalThis, "sm4", { configurable: true, writable: true, value: new Lazy() });

    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();
    // The probe retries every 500ms up to 120 times; run forty of those ticks.
    vi.advanceTimersByTime(20_000);

    const properties = seen
      .map((entry) => JSON.parse(entry))
      .filter((event) => event.name === "hook.skipped")
      .map((event) => event.input.property)
      .sort();

    // A silent capture gap is worse than a noisy one, but forty ticks of
    // duplicates would bury the log the operator actually reads.
    expect(properties).toEqual(["decrypt", "encrypt"]);
  });
});
