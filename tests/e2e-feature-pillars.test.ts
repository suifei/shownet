import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { E2E_FEATURE_PILLARS, pillarIds } from "../src/e2eFeaturePillars.ts";

const root = fileURLToPath(new URL("..", import.meta.url));

function read(rel: string): string {
  return readFileSync(join(root, rel), "utf8");
}

describe("e2e feature pillar coverage map", () => {
  it("covers every major product pillar with real artifacts and shipped markers", () => {
    const ids = pillarIds();
    assert.ok(ids.length >= 8, `expected >=8 pillars, got ${ids.length}`);
    assert.equal(new Set(ids).size, ids.length, "pillar ids must be unique");

    const required = [
      "capture-mitm-proxy",
      "egress",
      "tls-interception-bypass",
      "embedded-browser-lifecycle",
      "traffic-evidence",
      "analysis-agent-mcp",
      "request-lab-replay-collections",
      "windows-qa-orchestrator",
    ];
    for (const id of required) {
      assert.ok(ids.includes(id), `missing required pillar ${id}`);
    }

    for (const pillar of E2E_FEATURE_PILLARS) {
      assert.ok(pillar.artifacts.length > 0, `${pillar.id}: need artifacts`);
      let matched = false;
      for (const rel of pillar.artifacts) {
        const abs = join(root, rel);
        assert.ok(existsSync(abs), `${pillar.id}: missing artifact ${rel}`);
        const body = read(rel);
        if (pillar.shippedMarker.test(body)) matched = true;
      }
      assert.ok(
        matched,
        `${pillar.id} (${pillar.name}): shippedMarker ${pillar.shippedMarker} not found in artifacts`,
      );
    }
  });

  it("maps live network pillars to env-driven tests not hardcoded 7890/7891-only loops", () => {
    const proxy = read("src-tauri/src/proxy.rs");
    assert.match(proxy, /effective_upstream_from_process_env/);
    assert.match(proxy, /live_upstream_proxy_from_env_reaches_https/);
    assert.match(proxy, /live_shownet_mitm_smoke_via_env_upstream/);
    assert.doesNotMatch(
      proxy,
      /async fn live_upstream_proxies_reach_overseas_https[\s\S]{0,200}\(\("http", 7890\)/,
    );
  });

  it("feature-map workflow stages are still named in repo docs/capabilities", () => {
    // feature-map.md may be gitignored in some checkouts; capabilities + pillars stay committed.
    const caps = read("src/advancedConsoleCapabilities.ts");
    assert.match(caps, /capture|proxy-capture|fingerprint|分析/i);
    const pillars = read("src/e2eFeaturePillars.ts");
    assert.match(pillars, /capture-mitm-proxy/);
    assert.match(pillars, /analysis-agent-mcp/);
  });
});
