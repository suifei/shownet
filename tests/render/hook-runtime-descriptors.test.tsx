import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * Own realm: the runtime installs once per realm and wraps whatever it finds at
 * that moment, so the object it should wrap has to exist before it is evaluated.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

afterEach(() => {
  vi.useRealTimers();
});

describe("wrapping an inherited method leaves it as writable as it was", () => {
  it("does not freeze a crypto library's method against the page", () => {
    class Cipher {
      encrypt(value: string) {
        return `enc:${value}`;
      }
    }
    const sm4 = new Cipher();
    Object.defineProperty(globalThis, "sm4", { configurable: true, writable: true, value: sm4 });

    // The library probe runs on a 500ms interval, so the clock has to be fake
    // before the runtime installs it.
    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();
    vi.advanceTimersByTime(600);

    const descriptor = Object.getOwnPropertyDescriptor(sm4, "encrypt");
    expect(descriptor, "the probe should have wrapped the prototype method").toBeTruthy();

    // `encrypt` is inherited, so there was no own descriptor to copy. Defaulting
    // to defineProperty's own defaults would have made it non-writable,
    // non-enumerable and non-configurable — the page could then never take its
    // own method back, and it would vanish from for...in and object spread.
    expect(descriptor?.writable).toBe(true);
    expect(descriptor?.configurable).toBe(true);
    expect(descriptor?.enumerable).toBe(true);

    (sm4 as unknown as Record<string, unknown>).encrypt = () => "replaced";
    expect((sm4 as unknown as { encrypt: () => string }).encrypt()).toBe("replaced");
  });
});
