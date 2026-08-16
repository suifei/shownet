import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { DEFAULT_PAGE_HOOKS_ENABLED } from "../src/browserCompatibility.ts";

describe("sensitive browser page compatibility", () => {
  it("keeps deep page hooks opt-in", () => {
    assert.equal(DEFAULT_PAGE_HOOKS_ENABLED, false);
  });

  it("keeps Chrome on the ShowNet transport proxy", async () => {
    const browser = await readFile(new URL("../src-tauri/src/browser.rs", import.meta.url), "utf8");
    assert.match(browser, /--proxy-server=http:\/\/127\.0\.0\.1:\{proxy_port\}/);
  });

  it("stores an unweighted Chrome language preference", async () => {
    const browser = await readFile(new URL("../src-tauri/src/browser.rs", import.meta.url), "utf8");
    assert.match(browser, /"accept_languages": profile_accept_languages_for\(language\)/);
    assert.match(browser, /format!\("\{language\},\{base\}"\)/);
    assert.doesNotMatch(browser, /"accept_languages": accept_language_for\(language\)/);
  });

  it("does not report a profile JA4 as a per-connection measurement", async () => {
    const proxy = await readFile(new URL("../src-tauri/src/proxy.rs", import.meta.url), "utf8");
    assert.match(proxy, /fingerprint\.outbound\.ja4 = None/);
    assert.match(proxy, /this connection was not measured/);
    assert.doesNotMatch(proxy, /fingerprint\.outbound\.ja4 = Some\(egress_ja4\.to_string\(\)\)/);
  });
});
