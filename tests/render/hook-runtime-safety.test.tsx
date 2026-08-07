import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";

/**
 * The hook runtime is injected into every document the embedded browser loads,
 * so it sits inside the page's own control flow. An observer that throws kills
 * the very call it was watching, and a page whose writes keep failing reloads
 * forever — which is what issue #4 reported.
 */
const RUNTIME_SOURCE = readFileSync(
  resolve(process.cwd(), "public/lab/shownet-hook-runtime.js"),
  "utf8",
);

/**
 * The runtime guards itself against double installation per realm, so it goes
 * in once and every test shares the installed hooks — which is also how a real
 * page sees it. The bridge is what varies per test; the hooks read it at emit
 * time, not at install time.
 */
function installRuntime() {
  // eslint-disable-next-line no-new-func -- evaluating the shipped file is the point
  new Function(RUNTIME_SOURCE)();
}

/**
 * A value that cannot be walked. Refusing enumeration is a real anti-hooking
 * move, and it is the shape that used to escape the reporter and surface as an
 * exception inside the page's own call.
 */
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

/** Makes the transport itself fail, the other half of the worst case. */
function installHostileBridge() {
  Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", {
    configurable: true,
    value: () => {
      throw new Error("bridge exploded");
    },
  });
}

beforeEach(() => {
  delete (globalThis as Record<string, unknown>).__SHOWNET_HOOK_BRIDGE__;
  delete (globalThis as Record<string, unknown>).__SHOWNET_HOOK_QUEUE__;
  localStorage.clear();
});

describe("reporting never escapes into the page", () => {
  it("keeps a storage write working when the value cannot be described", () => {
    installRuntime();

    // The regression: describing the value threw, and the throw travelled out
    // of the hook into the site's own setItem call.
    expect(() => localStorage.setItem("token", unwalkable() as unknown as string)).not.toThrow();
  });

  it("keeps a storage write working when the transport fails", () => {
    installRuntime();
    installHostileBridge();

    expect(() => localStorage.setItem("token", "kept")).not.toThrow();
    expect(localStorage.getItem("token")).toBe("kept");
  });

  it("swallows both failures at once rather than surfacing either", () => {
    installRuntime();
    installHostileBridge();

    const lab = (globalThis as Record<string, unknown>).__SHOWNET_LAB__ as {
      emit: (event: unknown) => void;
    };
    expect(lab).toBeTruthy();
    expect(() => lab.emit({ kind: "runtime", name: "probe", input: unwalkable() })).not.toThrow();
  });
});

describe("describing a value is always possible", () => {
  it("falls back to a placeholder rather than throwing", () => {
    installRuntime();
    const lab = (globalThis as Record<string, unknown>).__SHOWNET_LAB__ as {
      scrub: (value: unknown) => unknown;
    };

    expect(() => lab.scrub(unwalkable())).not.toThrow();
    // Nested is guarded too, and was even before this pass.
    expect(() => lab.scrub({ nested: unwalkable() })).not.toThrow();
  });
});

describe("document.cookie hook", () => {
  it("stores the cookie and reports it", () => {
    installRuntime();
    const seen: string[] = [];
    Object.defineProperty(globalThis, "__SHOWNET_HOOK_BRIDGE__", {
      configurable: true,
      value: (payload: string) => seen.push(payload),
    });

    document.cookie = "cf_clearance=abc123; path=/";

    expect(document.cookie).toContain("cf_clearance=abc123");
    const event = seen.map((entry) => JSON.parse(entry)).find((item) => item.name === "document.cookie.set");
    expect(event?.input.name).toBe("cf_clearance");
  });

  it("performs the write before describing it", () => {
    // Every value a cookie hook sees is a string, so no input can make the
    // reporter fail from inside a test. The ordering is the invariant that
    // matters — a clearance cookie that is described first and written second
    // is a clearance cookie that any reporting failure loses — so it is pinned
    // against the source.
    const setter = RUNTIME_SOURCE.slice(
      RUNTIME_SOURCE.indexOf("set(value) {"),
      RUNTIME_SOURCE.indexOf("Storage?.prototype"),
    );
    const write = setter.indexOf("Reflect.apply(cookieDescriptor.set");
    const report = setter.indexOf("emit({ kind: \"storage\", name: \"document.cookie.set\"");

    expect(write).toBeGreaterThan(-1);
    expect(report).toBeGreaterThan(-1);
    expect(write).toBeLessThan(report);
  });
});
