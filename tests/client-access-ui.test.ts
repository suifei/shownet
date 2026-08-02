import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  MAX_CLIENT_ACCESS_RULES,
  clientAccessModeLabel,
  clientAccessModeSummary,
  parseClientAccessRules,
  validateClientAccessSettings,
} from "../src/clientAccess.ts";

describe("trusted LAN client access", () => {
  it("parses one trimmed IP or CIDR per non-empty line", () => {
    assert.deepEqual(
      parseClientAccessRules(" 192.168.1.23\r\n\n10.20.0.0/16 \n fd12:3456::9 "),
      ["192.168.1.23", "10.20.0.0/16", "fd12:3456::9"],
    );
  });

  it("requires a non-empty allowlist and keeps the editor bounded", () => {
    assert.equal(validateClientAccessSettings({ lanEnabled: true, accessMode: "allow", accessRules: [] }), "仅受信设备模式至少需要一个私网 IP 或 CIDR");
    assert.equal(validateClientAccessSettings({ lanEnabled: true, accessMode: "allow", accessRules: ["192.168.1.23"] }), undefined);
    assert.match(
      validateClientAccessSettings({
        lanEnabled: true,
        accessMode: "deny",
        accessRules: Array.from({ length: MAX_CLIENT_ACCESS_RULES + 1 }, (_, index) => `192.168.1.${index}`),
      }) ?? "",
      /最多支持 128 条/,
    );
  });

  it("uses novice-facing mode labels consistently", () => {
    assert.equal(clientAccessModeLabel("private"), "所有私网设备");
    assert.equal(clientAccessModeLabel("allow"), "仅受信设备");
    assert.equal(clientAccessModeLabel("deny"), "除已阻止设备外");
    assert.equal(clientAccessModeSummary("allow", 3), "仅允许 3 条受信范围");
  });

  it("exposes the complete runtime contract and restores active entries around policy changes", async () => {
    const [types, settings, app, backend] = await Promise.all([
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
    ]);

    assert.match(types, /accessMode: ClientAccessMode/);
    assert.match(types, /accessRules: string\[\]/);
    assert.match(settings, /get_reverse_proxy_status/);
    assert.match(settings, /restartReverseProxy\(reverseBefore, activeSessionId\)/);
    assert.match(settings, /save_capture_listener_settings[\s\S]*settings: previous/);
    assert.match(settings, /accessMode: status\.accessMode \?\? "private"/);
    assert.match(settings, /Array\.isArray\(status\.accessRules\)/);
    assert.match(app, /遵循设置：\{clientAccessModeSummary/);
    assert.match(backend, /ProxyHandle::start\([\s\S]*client_access/);
    assert.match(backend, /ReverseProxyHandle::start\([\s\S]*client_access/);
  });

  it("keeps the three-mode control bounded on narrow layouts", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

    assert.match(styles, /\.client-access-modes \{[^}]*grid-template-columns: repeat\(3, minmax\(0, 1fr\)\)/);
    assert.match(styles, /\.client-access-modes button \{[^}]*min-width: 0/);
    assert.match(styles, /\.client-access-policy > footer \{[^}]*min-width: 0/);
  });
});
