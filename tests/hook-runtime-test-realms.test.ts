/**
 * Guards a failure mode that presents as a *passing* test.
 *
 * The hook runtime installs once per realm behind a non-configurable symbol
 * (`public/lab/shownet-hook-runtime.js`), and its crypto-library probe runs on
 * an interval registered at install time. Vitest isolates per file, not per
 * test — so a second `new Function(RUNTIME_SOURCE)()` in the same file returns
 * immediately, no interval exists, `advanceTimersByTime` drives nothing, and any
 * assertion about what the probe decided holds vacuously.
 *
 * That mistake was made three separate times while this suite was being written,
 * and every time the symptom was green. A count is the cheapest thing that turns
 * it back into a failure.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { describe, it } from "node:test";

const RENDER_DIR = new URL("./render/", import.meta.url);

async function hookRuntimeTestFiles() {
  const entries = await readdir(RENDER_DIR);
  return entries.filter((name) => name.startsWith("hook-runtime-") && name.endsWith(".test.tsx"));
}

/** Strips block comments and line comments so doc text is not counted as code. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

describe("hook runtime tests keep one realm per install", () => {
  it("covers at least the files that exist", async () => {
    const files = await hookRuntimeTestFiles();
    assert.ok(files.length >= 6, `expected the hook-runtime suite, found ${files.length} files`);
  });

  it("never drives the probe interval more than once per file", async () => {
    // The interval belongs to the first install. A file that advances timers
    // twice is asserting against a probe that only ran for the first of them.
    for (const name of await hookRuntimeTestFiles()) {
      const source = stripComments(await readFile(new URL(name, RENDER_DIR), "utf8"));
      const advances = source.match(/advanceTimersByTime/g) ?? [];
      assert.ok(
        advances.length <= 1,
        `${name} drives the probe ${advances.length} times; only the first install registers an interval, so split the extra tests into their own files`,
      );
    }
  });

  it("evaluates the runtime source at most once per file", async () => {
    for (const name of await hookRuntimeTestFiles()) {
      const source = stripComments(await readFile(new URL(name, RENDER_DIR), "utf8"));
      const installs = source.match(/new Function\(RUNTIME_SOURCE\)/g) ?? [];
      assert.ok(
        installs.length <= 1,
        `${name} evaluates the runtime ${installs.length} times; every call after the first is a silent no-op`,
      );
    }
  });

  it("says why in each file, so the constraint survives the next edit", async () => {
    for (const name of await hookRuntimeTestFiles()) {
      const source = await readFile(new URL(name, RENDER_DIR), "utf8");
      assert.match(
        source,
        /realm/i,
        `${name} must explain the one-install-per-realm constraint it depends on`,
      );
    }
  });
});
