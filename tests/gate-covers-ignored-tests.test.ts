/**
 * `cargo test --manifest-path X` does not run that crate's `#[ignore]`d tests,
 * so gate-covers-every-crate cannot see them. They are the tests most likely to
 * rot, because rot is invisible when nothing runs them.
 *
 * Every ignored test must be either driven by a gate step that passes
 * `--ignored` with a matching filter, or listed below with why it cannot be.
 * Adding a new one fails this until that decision is made explicitly.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));

/** Ignored tests the gate deliberately does not run, and the reason. */
const EXCLUDED: Record<string, string> = {
  live_upstream_proxy_from_env_reaches_https:
    "needs PROXY/HTTP(S)_PROXY pointing at a working egress; run via npm run test:egress",
  live_shownet_mitm_smoke_via_env_upstream:
    "needs an egress proxy and the ability to bind a listener; run via npm run test:mitm-smoke",
  real_sidecar_streams_openai_report_and_cleans_runtime_directory:
    "needs the built Agent sidecar; run via npm run test:agent-sidecar",
  real_sidecar_discovers_calls_and_consumes_shownet_mcp_tool:
    "needs the built Agent sidecar; run via npm run test:agent-sidecar",
  request_list_performance_benchmark:
    "a benchmark, not a pass/fail check; run via npm run benchmark:request-list",
  dump_real_session_analysis:
    "a manual instrument needing SHOWNET_SESSION and a real captured session",
  wreq_egress_is_byte_exact_chrome:
    "hits a live JA4 reflector to prove Chrome parity; run explicitly under --features impersonate-boring",
  mitm_impersonate_presents_chrome_to_the_origin:
    "drives the full MITM path to a live reflector; run via npm run test:impersonate-mitm",
};

describe("the release gate runs every ignored test it can", () => {
  it("leaves none unrun without a stated reason", async () => {
    const [workflow, pkg] = await Promise.all([
      readFile(join(root, ".github/workflows/release.yml"), "utf8"),
      readFile(join(root, "package.json"), "utf8"),
    ]);
    const scripts: Record<string, string> = JSON.parse(pkg).scripts;

    // Filters the gate actually drives, e.g. `cargo test ... local_socket_ -- --ignored`.
    const gateFilters: string[] = [];
    for (const line of workflow.split("\n")) {
      const run = /- run:\s*(.+)$/.exec(line.trim())?.[1];
      if (!run?.startsWith("npm run ")) continue;
      const command = scripts[run.replace("npm run ", "").split(" ")[0]] ?? "";
      if (!command.includes("--ignored")) continue;
      const filter = /Cargo\.toml\s+(\S+)\s+--/.exec(command)?.[1];
      if (filter) gateFilters.push(filter);
    }
    assert.ok(gateFilters.length > 0, "no gate step runs ignored tests at all");

    const names: string[] = [];
    const directory = join(root, "src-tauri/src");
    for (const entry of await readdir(directory)) {
      if (!entry.endsWith(".rs")) continue;
      const source = await readFile(join(directory, entry), "utf8");
      for (const match of source.matchAll(/#\[ignore[^\]]*\]\s*(?:async\s+)?fn\s+(\w+)/g)) {
        names.push(match[1]);
      }
    }
    assert.ok(names.length > 20, `expected the ignored suite, saw ${names.length}`);

    const unaccounted = names.filter(
      (name) => !gateFilters.some((f) => name.startsWith(f)) && !(name in EXCLUDED),
    );
    assert.deepEqual(
      unaccounted,
      [],
      `ignored tests that nothing runs and nothing explains: ${unaccounted.join(", ")}`,
    );

    // An excluded name that no longer exists is a stale exemption.
    const stale = Object.keys(EXCLUDED).filter((name) => !names.includes(name));
    assert.deepEqual(stale, [], `EXCLUDED lists tests that are gone: ${stale.join(", ")}`);

    // A reason that points at an npm script has to point at one that exists.
    // Otherwise deleting the script leaves the exemption reading as if the test
    // is still runnable by hand, which is how a suite quietly becomes dead.
    const broken: string[] = [];
    for (const [name, reason] of Object.entries(EXCLUDED)) {
      for (const [, script] of reason.matchAll(/npm run ([\w:-]+)/g)) {
        if (!(script in scripts)) broken.push(`${name} -> npm run ${script}`);
      }
    }
    assert.deepEqual(
      broken,
      [],
      `EXCLUDED points at npm scripts that do not exist: ${broken.join(", ")}`,
    );
  });
});
