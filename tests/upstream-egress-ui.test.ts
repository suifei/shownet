import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
