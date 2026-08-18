import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("HTTPS interception settings", () => {
  it("exposes three novice-facing modes and persists them through Tauri", async () => {
    const [settings, types, lib] = await Promise.all([
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
    ]);

    assert.match(types, /TlsInterceptionMode = "intercept_all" \| "bypass_selected" \| "bypass_all"/);
    assert.match(types, /showBypassedConnections: boolean/);
    assert.match(settings, /invoke<TlsInterceptionSettings>\("get_tls_interception_settings"\)/);
    assert.match(settings, /invoke<TlsInterceptionSettings>\("save_tls_interception_settings"/);
    assert.match(settings, /settings\.tls\.decryptAll/);
    assert.match(settings, /settings\.tls\.bypassSelected/);
    assert.match(settings, /settings\.tls\.bypassAll/);
    assert.match(settings, /aria-label=\{t\("settings\.tls\.bypassHostsAria"\)\}/);
    assert.match(settings, /settings\.tls\.keepRawHint/);
    assert.match(settings, /全部 HTTPS 将不再解密，成功连接也不会出现在流量列表中；失败仍保留/);
    assert.match(settings, /settings\.tls\.showBypass/);
    assert.match(settings, /settings\.tls\.showBypassOff/);
    assert.match(settings, /settings\.tls\.policyHint/);
    assert.match(lib, /get_tls_interception_settings,/);
    assert.match(lib, /save_tls_interception_settings,/);
  });

  it("offers a one-click static CDN bypass preset for Baidu-style MITM 400s", async () => {
    const [settings, presets, rust, styles, storage] = await Promise.all([
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/tlsBypassPresets.ts", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/tls_interception.rs", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/storage.rs", import.meta.url), "utf8"),
    ]);

    assert.match(presets, /\*\.bdstatic\.com/);
    assert.match(presets, /\*\.bcebos\.com/);
    assert.match(presets, /mergeStaticCdnBypassRules/);
    assert.match(rust, /STATIC_CDN_BYPASS_PRESET/);
    assert.match(rust, /"\*\.bdstatic\.com"/);
    assert.match(rust, /"\*\.bcebos\.com"/);
    assert.match(rust, /fn apply_static_cdn_bypass_preset/);
    assert.match(rust, /static_cdn_preset_bypasses_baidu_cdn_hosts_without_mitm/);
    assert.match(settings, /applyStaticCdnBypassPreset/);
    assert.match(settings, /aria-label=\{t\("settings\.tls\.cdnPreset"\)\}/);
    assert.match(settings, /settings\.tls\.cdnWriteTitle/);
    assert.match(settings, /bypass_selected/);
    assert.match(settings, /STATIC_CDN_BYPASS_PRESET/);
    assert.match(styles, /\.tls-static-cdn-preset/);
    // First-run seeds CDN bypass into SQLite when no prior tls_interception key.
    assert.match(storage, /first_run_tls_interception_seeds_static_cdn_bypass_preset|apply_static_cdn_bypass_preset/);
    assert.match(storage, /First-run product default/);
  });

  it("uses Codex blue for normal policy state and stacks controls on narrow screens", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

    assert.match(styles, /\.tls-interception-modes button\.is-active[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.tls-interception-policy > footer \.save-settings-button[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.tls-interception-modes button\.is-danger\.is-active/);
    assert.match(styles, /\.tls-bypass-visibility input:checked \+ i[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.settings-section > summary:focus-visible[^}]*var\(--codex-accent\)/s);
    assert.match(styles, /\.tls-interception-modes \{ grid-template-columns: 1fr; \}/);
    assert.match(styles, /\.tls-interception-policy > footer \{ align-items: stretch; flex-direction: column; \}/);
  });

  it("labels bypassed CONNECT rows as locked and not decrypted", async () => {
    const [traffic, storage, proxy] = await Promise.all([
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/storage.rs", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/proxy.rs", import.meta.url), "utf8"),
    ]);

    assert.match(traffic, /request\.state === "tunnel" && <LockKeyhole/);
    // The state label moved into REQUEST_STATE_LABELS so the grid and the
    // filter cannot name the same state differently.
    assert.match(traffic, /requestStateLabel\(request\.state\)/);
    assert.match(
      await readFile(new URL("../src/requestFilters.ts", import.meta.url), "utf8"),
      /traffic\.state\.tunnel/,
    );
    assert.match(storage, /json_extract\(r\.tls_fingerprint_json, '\$\.captureMode'\) = 'mitm'/);
    assert.match(storage, /UPPER\(r\.method\) != 'CONNECT'/);
    assert.match(proxy, /tunnel_fingerprint\(inbound\)/);
    assert.match(proxy, /let record_tunnel = tls_interception\.record_successful_tunnel \|\| mirror_route\.is_some\(\);/);
    assert.match(proxy, /if record_tunnel[^}]*capture_connect_record/s);
    assert.match(proxy, /if !record_tunnel[^}]*capture_connect_record/s);
    assert.match(proxy, /原样隧道失败/);
    assert.match(proxy, /write_all\(&hello\.bytes\)/);
    assert.match(proxy, /正文不可见/);
  });
});
