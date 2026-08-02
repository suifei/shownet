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
    assert.match(settings, /解密全部/);
    assert.match(settings, /绕行指定/);
    assert.match(settings, /全部绕行/);
    assert.match(settings, /aria-label="HTTPS 绕行域名"/);
    assert.match(settings, /支持 \* 和 \?/);
    assert.match(settings, /ClientHello 中的 SNI/);
    assert.match(settings, /全部 HTTPS 将不再解密，成功连接也不会出现在流量列表中；失败仍保留/);
    assert.match(settings, /在流量列表显示绕行连接/);
    assert.match(settings, /只隐藏成功连接；连接失败仍会保留用于排查/);
    assert.match(settings, /新连接立即生效/);
    assert.match(lib, /get_tls_interception_settings,/);
    assert.match(lib, /save_tls_interception_settings,/);
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
    assert.match(traffic, /request\.state === "tunnel" \? "未解密"/);
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
