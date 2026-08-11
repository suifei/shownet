import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import {
  browserAcceptLanguage,
  cloudflareChallengeHost,
  initialBrowserLanguage,
  normalizeBrowserLanguage,
} from "../src/browserLanguage.ts";

describe("embedded browser language", () => {
  it("canonicalizes a freely entered BCP 47 language and builds a real Chrome header", () => {
    assert.equal(normalizeBrowserLanguage(" th-th "), "th-TH");
    assert.equal(normalizeBrowserLanguage("zh-hans-cn"), "zh-Hans-CN");
    assert.equal(normalizeBrowserLanguage("zh_CN"), null);
    assert.equal(browserAcceptLanguage("th-TH"), "th-TH,th;q=0.9");
  });

  it("prefers a saved language and falls back safely", () => {
    assert.equal(initialBrowserLanguage({ getItem: () => "ja-jp" }), "ja-JP");
    assert.match(initialBrowserLanguage({ getItem: () => "invalid_language" }), /^[A-Za-z]{2,8}(?:-|$)/);
  });
});

describe("Cloudflare challenge detection", () => {
  it("returns only the exact HTTPS verification host", () => {
    assert.equal(cloudflareChallengeHost({
      url: "https://shield.lionairthai.com/shield/verify?d=1",
      title: "请稍候...",
      text: "正在进行安全验证 请验证您是真人 Cloudflare",
      cloudflareMarker: true,
    }), "shield.lionairthai.com");
    assert.equal(cloudflareChallengeHost({
      url: "https://example.com/",
      title: "Cloudflare product page",
      text: "No challenge here",
      cloudflareMarker: false,
    }), "");
  });

  it("keeps MITM and arms Chrome egress instead of temporary TLS bypass", async () => {
    const [view, lib, proxy] = await Promise.all([
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/proxy.rs", import.meta.url), "utf8"),
    ]);
    assert.match(view, /cloudflareChallengeHost/);
    assert.match(view, /hooksEnabledRef\.current = false/);
    assert.match(view, /get_outbound_tls_profile/);
    assert.ok(
      view.indexOf('invoke<OutboundTlsProfileStatus>("get_outbound_tls_profile")') <
        view.indexOf("hooksEnabledRef.current = false"),
      "the app must verify impersonate capability before disabling page Hooks",
    );
    assert.match(view, /hooksEnabledRef\.current = previousHooksEnabled/);
    assert.match(view, /setHooksEnabled\(previousHooksEnabled\)/);
    assert.doesNotMatch(view, /确认「用逐字节 Chrome 出站」已开启/);
    assert.match(view, /关闭 Hook 并重试/);
    assert.doesNotMatch(view, /tlsBypassHost/);
    assert.doesNotMatch(view, /set_outbound_impersonate/);
    assert.doesNotMatch(lib, /temporary_browser_tls_interception_decision/);
    assert.match(lib, /Challenge compatibility must never temporarily bypass MITM/);
    assert.match(proxy, /state\.tls_interception_decision\(host, sni\)/);
    // Product MITM with the stack linked must not gate on a user request flag.
    assert.match(proxy, /Product MITM origin egress is impersonate-only/);
    // Viewport must not overwrite the desktop screen fingerprint with the pane size.
    assert.match(view, /BROWSER_SCREEN_WIDTH/);
    assert.match(view, /screenWidth:\s*BROWSER_SCREEN_WIDTH/);
    assert.match(view, /screenHeight:\s*BROWSER_SCREEN_HEIGHT/);
  });
});
