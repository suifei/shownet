import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));

describe("Windows QA runner (entry point)", () => {
  it("is wired as npm script and documents layers without embedding secrets", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.equal(pkg.scripts["test:windows"], "node scripts/windows-qa.mjs --layer all");
    assert.equal(pkg.scripts["test:windows:default"], "node scripts/windows-qa.mjs --layer default");
    assert.match(pkg.scripts["test:egress"], /live_upstream_proxy_from_env/);
    assert.match(pkg.scripts["test:mitm-smoke"], /live_shownet_mitm_smoke/);

    const runner = readFileSync(join(root, "scripts/windows-qa.mjs"), "utf8");
    assert.match(runner, /loadDotEnv/);
    assert.match(runner, /LAYER_DEFAULT_OK|runDefaultLayer/);
    assert.match(runner, /live_upstream_proxy_from_env/);
    assert.match(runner, /live_shownet_mitm_smoke/);
    assert.match(runner, /real_system_grok_streams_openai_report/);
    assert.match(runner, /PROXY/);
    assert.match(runner, /Never prints secret|values redacted|redacted/);
    assert.match(runner, /--help/);
    assert.doesNotMatch(runner, /sk-[a-zA-Z0-9]{10,}/);
    assert.doesNotMatch(runner, /OPENAI_KEY=sk/);

    const gitignore = readFileSync(join(root, ".gitignore"), "utf8");
    assert.match(gitignore, /^\.env$/m);

    // Live Rust tests must not hardcode dead 7890/7891 as the only path.
    const proxy = readFileSync(join(root, "src-tauri/src/proxy.rs"), "utf8");
    assert.match(proxy, /live_upstream_proxy_from_env_reaches_https/);
    assert.match(proxy, /effective_upstream_from_process_env/);
    assert.match(proxy, /live_shownet_mitm_smoke_via_env_upstream/);
    assert.doesNotMatch(
      proxy,
      /async fn live_upstream_proxies_reach_overseas_https[\s\S]*?\(\("http", 7890\)/,
    );
  });

  it("ships help text for layers", () => {
    const runner = readFileSync(join(root, "scripts/windows-qa.mjs"), "utf8");
    assert.match(runner, /Always-on \(default layer\)/);
    assert.match(runner, /egress/);
    assert.match(runner, /mitm/);
    assert.match(runner, /agent/);
    assert.ok(existsSync(join(root, "scripts/windows-qa.mjs")));
  });
});
