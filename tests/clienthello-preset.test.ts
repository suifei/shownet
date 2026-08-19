import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { displayedClientHelloPresetId } from "../src/clientHelloPreset.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("ClientHello preset display", () => {
  it("keeps chrome151 instead of inventing chrome150 when presetId is present", () => {
    assert.equal(displayedClientHelloPresetId({ presetId: "chrome151", profile: "chrome-like" }), "chrome151");
  });

  it("does not display a missing presetId as chrome150", () => {
    assert.notEqual(displayedClientHelloPresetId({ profile: "chrome-like" }), "chrome150");
    assert.equal(displayedClientHelloPresetId({ profile: "chrome-like" }), "chrome-like");
    assert.equal(displayedClientHelloPresetId(undefined), "");
  });

  it("settings and advanced console use the shipped display helper", () => {
    const settings = readFileSync(join(root, "src/components/SettingsView.tsx"), "utf8");
    const advanced = readFileSync(join(root, "src/components/AdvancedConsoleView.tsx"), "utf8");
    const outbound = readFileSync(join(root, "src-tauri/src/tls_outbound.rs"), "utf8");
    assert.match(settings, /displayedClientHelloPresetId\(outboundTls\)/);
    assert.match(advanced, /displayedClientHelloPresetId\(outboundTls\)/);
    assert.doesNotMatch(settings, /presetId \?\? "chrome150"/);
    assert.doesNotMatch(advanced, /presetId \?\? "chrome150"/);
    assert.match(outbound, /inbound_auto_pick_does_not_overwrite_user_chrome151_selection/);
    assert.match(outbound, /if let Ok\(p\) = tls_clienthello_catalog::get_preset\(id\) \{/);
    const resolveStart = outbound.indexOf("pub fn resolve_preset_for_connection");
    const resolveEnd = outbound.indexOf("fn parse_root_certificates", resolveStart);
    assert.ok(resolveStart >= 0 && resolveEnd > resolveStart);
    assert.doesNotMatch(
      outbound.slice(resolveStart, resolveEnd),
      /set_active_preset\(/,
    );
  });
});
