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

  it("does not name the product in the functions it replaces", () => {
    // `window.fetch.name === "shownetFetch"` was a one-property check that said
    // outright what was doing the hooking, and the arity disagreed too. The
    // wrapper has to carry whatever the function it replaced carried — here the
    // sentinel's own name and arity, in a real browser `"fetch"` and 1.
    expect(globalThis.fetch.name).toBe("sentinelFetch");
    expect(globalThis.fetch.name).not.toContain("shownet");
    expect(globalThis.fetch.length).toBe(2);
  });

  it("leaves no own symbol on wrappers or on the function it proxies", () => {
    // The marker used to be an own Symbol.for() on every wrapper: one entry
    // where a native function has none, and readable back through the global
    // registry by name. A later version planted the same marker on the real
    // Function.prototype.toString, the most-probed function in the language.
    expect(Object.getOwnPropertySymbols(globalThis.fetch)).toHaveLength(0);
    expect(Object.getOwnPropertySymbols(Function.prototype.toString)).toHaveLength(0);
  });

  it("does not render toString itself as an anonymous native function", () => {
    // A callable Proxy reports "function () { [native code] }" instead of
    // naming itself, which is a one-line tell that something replaced it.
    expect(Function.prototype.toString.toString()).toBe(
      "function toString() { [native code] }",
    );
  });

  it("keeps the cookie setter looking native", () => {
    // The loudest leak in the file: this descriptor's setter is page-authored,
    // so its source used to dump the wrapper body, comments and all.
    const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    expect(descriptor?.set).toBeTypeOf("function");
    expect(String(descriptor?.set)).not.toContain("emit");
    expect(String(descriptor?.set)).not.toContain("shownet");
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
