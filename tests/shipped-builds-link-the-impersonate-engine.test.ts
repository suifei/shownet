/**
 * `impersonate-boring` is off by default, which is right for a `cargo build` —
 * it pulls a vendored BoringSSL C build. It is not right for anything a user
 * installs, because the app exposes an impersonate setting and stores it: a
 * release without the feature reads `impersonate: true` from the user's own
 * config, finds no linked stack, and silently egresses through rustls instead.
 *
 * That is not hypothetical. It shipped: a real session recorded an inbound JA4
 * of t13d1516h2_8daaf6152771_d8a2da3f94cd against an outbound handshake that
 * never matched it, because no build the user had ever run could honour the
 * setting they had switched on.
 *
 * So every command that produces something a user runs has to carry the
 * feature, and every runner that compiles it has to be able to — BoringSSL's
 * x86_64 assembly is NASM syntax, so a Windows job without NASM fails in
 * cmake with "No CMAKE_ASM_NASM_COMPILER could be found".
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));
const FEATURE = "--features impersonate-boring";

/** npm scripts that produce a binary someone installs or runs. */
const SHIPPING_SCRIPTS = ["tauri:bundle", "build:windows:cross"];

describe("shipped builds link the impersonate engine", () => {
  it("passes the feature from every packaging script", async () => {
    const scripts: Record<string, string> = JSON.parse(
      await readFile(join(root, "package.json"), "utf8"),
    ).scripts;

    const missing = SHIPPING_SCRIPTS.filter((name) => !scripts[name]?.includes(FEATURE));
    assert.deepEqual(
      missing,
      [],
      `these produce a binary a user runs, so they must pass ${FEATURE}: ${missing.join(", ")}`,
    );

    // Named scripts that no longer exist would make the check above vacuous.
    const gone = SHIPPING_SCRIPTS.filter((name) => !(name in scripts));
    assert.deepEqual(gone, [], `SHIPPING_SCRIPTS names scripts that are gone: ${gone.join(", ")}`);
  });

  it("passes the feature from every release-workflow build", async () => {
    const workflow = await readFile(join(root, ".github/workflows/release.yml"), "utf8");

    // Joined on the backslash continuation first: the ad-hoc DMG build spans
    // three physical lines, so a per-line read saw only its head and reported
    // it as missing the feature when the feature was two lines below. Reading
    // it as one command is also what a shell does.
    const joined = workflow.replace(/\\\n\s*/g, " ");

    // Every `tauri ... build`, including the gate's --debug one. That build is
    // not shipped, but it writes the same target/debug/shownet a developer runs,
    // so a featureless build there silently replaces a feature build — and the
    // two binaries look identical. Requiring the feature everywhere removes the
    // trap rather than documenting it.
    const builds = joined
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => /tauri\s+--\s+build/.test(line));

    assert.ok(builds.length >= 2, `expected the macOS and Windows release builds, saw ${builds.length}`);
    const bare = builds.filter((line) => !line.includes(FEATURE));
    assert.deepEqual(bare, [], `release builds without ${FEATURE}: ${bare.join(" | ")}`);
  });

  it("gives the Windows runners the assembler BoringSSL needs", async () => {
    const workflow = await readFile(join(root, ".github/workflows/release.yml"), "utf8");

    // Every job that compiles with the feature on Windows needs the install
    // step; counting them is what catches a third job added later without one.
    const jobs = workflow.split(/\n  (?=[a-z][\w-]*:\n)/);
    const windowsBuilders = jobs.filter(
      (job) =>
        job.includes(FEATURE) &&
        (job.includes("windows-latest") || job.includes("x86_64-pc-windows-msvc")),
    );
    assert.ok(windowsBuilders.length > 0, "no Windows job compiles the feature — did the matrix change?");

    const withoutNasm = windowsBuilders.filter((job) => !/choco install nasm/.test(job));
    assert.equal(
      withoutNasm.length,
      0,
      `a Windows job compiles ${FEATURE} without installing NASM; BoringSSL's x86_64 ` +
        "assembly cannot build and cmake fails with No CMAKE_ASM_NASM_COMPILER could be found",
    );
  });

  it("keeps the feature off by default so a plain cargo build stays portable", async () => {
    const manifest = await readFile(join(root, "src-tauri/Cargo.toml"), "utf8");
    const features = /\[features\]([\s\S]*?)(\n\[|$)/.exec(manifest)?.[1] ?? "";

    assert.match(
      features,
      /^default\s*=\s*\[\s*\]/m,
      "the default feature set must stay empty: the vendored BoringSSL build is what " +
        "the packaging commands opt into, not something every contributor's cargo build pays for",
    );
    assert.match(features, /^impersonate-boring\s*=/m, "the feature the packaging commands name must exist");
  });
});
