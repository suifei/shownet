import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("upstream egress probe and env import (P1)", () => {
  it("exposes probe + env import commands and settings UI", async () => {
    const [settings, types, lib, styles, app, traffic] = await Promise.all([
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
    ]);

    assert.match(types, /export interface UpstreamProbeResult/);
    assert.match(types, /export interface DetectedEnvProxy/);
    assert.match(lib, /detect_env_upstream_proxy,/);
    assert.match(lib, /probe_upstream_proxy,/);
    assert.match(lib, /async fn probe_upstream_proxy/);
    assert.match(lib, /fn detect_env_upstream_proxy/);

    assert.match(settings, /HTTP_PROXY/);
    assert.match(settings, /不会.*自动继承|不会<\/strong>自动继承/);
    assert.match(settings, /detect_env_upstream_proxy/);
    assert.match(settings, /probe_upstream_proxy/);
    assert.match(settings, /一键导入/);
    assert.match(settings, /aria-label="探测出口连通性"/);
    assert.match(settings, /runUpstreamProbe/);
    assert.match(settings, /importEnvUpstream/);

    assert.match(styles, /\.upstream-proxy-help/);
    assert.match(styles, /\.upstream-env-import/);

    // 502 full error surface
    assert.match(traffic, /proxy-error-banner/);
    // Dynamic status: 502/504 both use the same proxy-error banner wording.
    assert.match(traffic, /代理错误（\{request\.status\}）|代理错误（502）/);
    assert.match(traffic, /overview-proxy-error/);
    assert.match(app, /capture:\/\/proxy-error/);
  });
});

describe("egress ignores the ambient environment", () => {
  it("clears env proxies on every outbound client", async () => {
    // BUGFIXES.md records the invariant: ShowNet does not inherit env/system
    // proxies — an env proxy is *offered for import* precisely because it is
    // not picked up silently. reqwest reads http_proxy/https_proxy by default,
    // so each builder has to say otherwise. It bit hardest here: ShowNet points
    // the system proxy at itself, so an inherited env proxy can route the app's
    // own requests back through its capture proxy.
    // Checking only that *a* builder in each file says `.no_proxy()` would let a
    // second, unguarded client sit beside a guarded one — browser.rs has two. So
    // every builder outside `mod tests` is checked, across every .rs in the
    // crate rather than a hand-listed few: an egress client added in a new
    // module is exactly what a fixed list would miss.
    const dir = new URL("../src-tauri/src/", import.meta.url);
    const files = (await readdir(dir)).filter((name) => name.endsWith(".rs")).sort();
    assert.ok(files.length > 5, "expected to find the crate's sources");

    let checked = 0;
    for (const file of files) {
      const source = await readFile(new URL(file, dir), "utf8");
      const testModuleAt = source.indexOf("\n#[cfg(test)]\nmod tests {");
      // If a file has tests but the marker no longer matches, the slice below
      // would silently become the whole file and a builder inside `mod tests`
      // could stand in for a production one. Fail loudly instead.
      assert.ok(
        testModuleAt > 0 || !source.includes("#[cfg(test)]"),
        `${file}: has tests but the module marker did not match; the slice would be a no-op`,
      );
      // Blank out line comments but keep their newlines, so reported line
      // numbers stay true. Each `.no_proxy()` carries a long rationale comment
      // above it, which any fixed lookahead window would have to guess at.
      const production = (testModuleAt > 0 ? source.slice(0, testModuleAt) : source).replace(
        /^([ \t]*)\/\/[^\n]*$/gm,
        "$1",
      );

      const builder = /(?:reqwest::)?Client::builder\(\)/g;
      for (let hit = builder.exec(production); hit; hit = builder.exec(production)) {
        const line = production.slice(0, hit.index).split("\n").length;
        assert.match(
          production.slice(hit.index + hit[0].length),
          /^\s*\.no_proxy\(\)/,
          `${file}:${line} must clear env proxies before configuring egress`,
        );
        checked += 1;
      }
    }
    // The wreq path owns separate proxied and direct clients so bypass rules
    // retain ShowNet's exact-match semantics. Both are feature-gated, but this
    // scans source text and the invariant holds regardless of build config.
    assert.equal(checked, 8, "expected 8 production egress clients; a new one must be guarded too");
  });
});

describe("connect_tcp Happy Eyeballs / IPv4 preference (P4)", () => {
  it("implements IPv4-first connect with host:port errors in proxy.rs", async () => {
    const whole = await readFile(new URL("../src-tauri/src/proxy.rs", import.meta.url), "utf8");
    // Searching the whole file lets a mention inside `mod tests` stand in for
    // the production symbol it names, so deleting the real function would leave
    // this green. Production assertions run against the file with its own tests
    // cut off; the one that genuinely names a test keeps the full text.
    const testModuleAt = whole.indexOf("\n#[cfg(test)]\nmod tests {");
    assert.ok(testModuleAt > 0, "test module marker not found; the slice below would be a no-op");
    const production = whole.slice(0, testModuleAt);

    assert.match(production, /fn order_connect_addrs_ipv4_first/);
    assert.match(production, /async fn connect_tcp_addrs/);
    assert.match(production, /CONNECT_IPV6_WHEN_IPV4_EXISTS/);
    assert.match(production, /lookup_host/);
    assert.match(production, /连接 \{host\}:\{port\}/);
    assert.match(production, /pub async fn probe_upstream_egress/);
    assert.match(production, /pub fn parse_proxy_env_value/);

    // This one is a test name, so it lives in the module the slice removes.
    assert.match(whole, /connect_tcp_falls_back_to_ipv4_when_ipv6_is_unreachable/);
  });
});
