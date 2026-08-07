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
    // to defineProperty's own defaults would have made it non-writable and
    // non-configurable, so the page could never take its own method back.
    expect(descriptor?.writable).toBe(true);
    expect(descriptor?.configurable).toBe(true);

    // But it must not become enumerable either. A prototype method is never an
    // own enumerable key, and inventing one changes Object.keys, for...in,
    // object spread and structuredClone for every instance.
    expect(descriptor?.enumerable).toBe(false);
    expect(Object.keys(sm4)).not.toContain("encrypt");
    expect({ ...sm4 }).not.toHaveProperty("encrypt");

    (sm4 as unknown as Record<string, unknown>).encrypt = () => "replaced";
    expect((sm4 as unknown as { encrypt: () => string }).encrypt()).toBe("replaced");
  });

  it("survives a prototype chain that points at itself", () => {
    // A Proxy can return itself from getPrototypeOf. Walking that chain with an
    // ordinary loop never terminates, and this runs on a 500ms interval on the
    // page's main thread — the tab would hang outright.
    const cyclic: Record<string, unknown> = {};
    const proxy: unknown = new Proxy(cyclic, { getPrototypeOf: () => proxy as object });
    Object.defineProperty(globalThis, "sm2", { configurable: true, writable: true, value: proxy });

    vi.useFakeTimers();
    // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
    new Function(RUNTIME_SOURCE)();

    // If the walk were unbounded this call would never return.
    expect(() => vi.advanceTimersByTime(600)).not.toThrow();
  });

  it("leaves an inherited accessor alone rather than flattening it", () => {
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

    // Replacing the getter with a data property would shadow it permanently:
    // the per-access work would stop running and the property would freeze at
    // whatever the first read returned.
    expect(Object.getOwnPropertyDescriptor(sm2, "encrypt")).toBeUndefined();
    const before = reads;
    void sm2.encrypt;
    void sm2.encrypt;
    expect(reads).toBe(before + 2);
  });
});
