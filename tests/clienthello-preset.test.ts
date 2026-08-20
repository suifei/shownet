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

  it("maps catalog ids onto linked wreq-util profiles without inventing missing majors", () => {
    const source = readFileSync(join(root, "src-tauri/src/tls_clienthello_catalog.rs"), "utf8");
    const egress = readFileSync(join(root, "src-tauri/src/impersonate_egress.rs"), "utf8");
    assert.match(source, /"chrome131" => "Chrome131"/);
    assert.match(source, /"firefox133" => "Firefox133"/);
    assert.match(source, /uses_chrome151_sigalgs_overlay/);
    assert.match(source, /id: "firefox115"/);
    assert.match(source, /id: "edge150"/);
    assert.match(source, /id: "chrome-android150"/);
    assert.match(source, /wreq_profile_name\("firefox115"\)/);
    assert.match(egress, /fn emulation_for_preset/);
    assert.match(egress, /mapped_presets_match_detector_ja4/);
    assert.match(egress, /is_profile_identity_header/);
    assert.match(egress, /Profile::Firefox133/);
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
