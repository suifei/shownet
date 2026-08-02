import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { availableBodyModes, bodyHex, bodyPreviewPolicy, defaultInspectorPreferences, detectBodyKind, parseCookies, parseInspectorPreferences, parseQueryEntries, prettyBody, timingEvidence } from "../src/requestInspector.ts";

describe("request inspector", () => {
  it("keeps the inspector visible at 1280px and sanitizes persisted sizes", () => {
    assert.equal(defaultInspectorPreferences(1280).layout, "bottom");
    assert.equal(defaultInspectorPreferences(1360).layout, "right");
    assert.equal(defaultInspectorPreferences(1440).layout, "right");
    const parsed = parseInspectorPreferences(JSON.stringify({ version: 1, layout: "right", rightWidth: 9999, bottomHeight: 1 }), 1440);
    assert.equal(parsed.rightWidth, 760);
    assert.equal(parsed.bottomHeight, 240);
    assert.equal(parseInspectorPreferences(JSON.stringify({ version: 1, layout: "right", rightWidth: 390, bottomHeight: 360 }), 1280).layout, "bottom");
    assert.deepEqual(parseInspectorPreferences("bad", 1000), defaultInspectorPreferences(1000));
  });

  it("preserves repeated query keys and decodes values", () => {
    const entries = parseQueryEntries("tag=a&tag=%E4%B8%AD%E6%96%87&q=hello%20world");
    assert.equal(entries.length, 3);
    assert.equal(entries[0].duplicate, true);
    assert.equal(entries[1].value, "中文");
    assert.equal(entries[2].value, "hello world");
  });

  it("parses request cookies and Set-Cookie security attributes", () => {
    const cookies = parseCookies([
      { name: "Cookie", value: "sid=abc; theme=dark" },
      { name: "Set-Cookie", value: "token=xyz; HttpOnly; Secure; SameSite=Lax" },
    ]);
    assert.equal(cookies.length, 3);
    assert.equal(cookies[2].attributes.httponly, true);
    assert.equal(cookies[2].attributes.samesite, "Lax");
  });

  it("detects body formats without executing HTML or JavaScript previews", () => {
    assert.equal(detectBodyKind('{"ok":true}', [{ name: "content-type", value: "application/json" }]), "json");
    assert.equal(prettyBody('{"ok":true}', "json"), '{\n  "ok": true\n}');
    assert.equal(detectBodyKind("<html><script>alert(1)</script></html>", [{ name: "content-type", value: "text/html" }]), "html");
    assert.equal(bodyPreviewPolicy("html"), "text-only");
    assert.equal(bodyPreviewPolicy("javascript"), "text-only");
    assert.ok(availableBodyModes("html").includes("preview"));
    assert.match(bodyHex("ABC"), /41 42 43/);
  });

  it("does not invent timing phases when only total duration was captured", () => {
    const evidence = timingEvidence(147.6);
    assert.equal(evidence.totalMs, 148);
    assert.equal(evidence.complete, false);
    assert.deepEqual(evidence.phases, []);
    assert.match(evidence.note, /尚未采集/);
  });
});
