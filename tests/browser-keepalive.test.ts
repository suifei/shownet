import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("embedded browser keep-alive (P2)", () => {
  it("keeps BrowserView mounted across nav switches and does not stop Chrome on hide", async () => {
    const [app, browser, styles] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    ]);

    // Must not conditionally unmount on activeView === "browser".
    assert.doesNotMatch(app, /activeView === "browser"\s*&&\s*<BrowserView/);
    assert.match(app, /workspace-view-keep-alive/);
    assert.match(app, /hidden=\{activeView !== "browser"\}/);
    assert.match(app, /active=\{activeView === "browser"\}/);
    assert.match(app, /Keep BrowserView mounted/);

    // Props contract: active flag for visibility restore.
    assert.match(browser, /active: boolean/);
    assert.match(browser, /export function BrowserView\(\{ active, capturing, sessionId, onAnalyzeCryptoLab \}/);

    // Stop only on true unmount or capture stop — not when switching tabs.
    assert.match(browser, /True unmount only \(app exit\): stop Chrome/);
    assert.match(browser, /Stop capture tears down the isolated proxy Chrome/);
    assert.match(browser, /if \(capturing \|\| !proxyBrowser\?\.running\) return;/);
    // Returning to tab restarts screencast without re-launch.
    assert.match(browser, /Page\.startScreencast/);
    assert.match(browser, /\[active, proxyBrowser\?\.running\]/);

    // CSS hide without destroying layout contract for height:100% child.
    assert.match(styles, /\.workspace-view-keep-alive\.is-hidden/);
    assert.match(styles, /display:\s*none\s*!important/);
  });

  it("user stop still calls stop_proxy_browser while keep-alive remains mounted", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");

    // These two live in different functions: the toggle guard calls
    // stopProxyChrome(), which is where the invoke happens. A single
    // `if (proxyBrowser?.running) {[\s\S]*?await invoke(...)` span appears to
    // tie them together but does not — it starts at the *first* of ~24
    // `proxyBrowser?.running` occurrences and runs ~385 lines to the only
    // `await invoke`, crossing several functions. Deleting the toggle guard
    // entirely left that assertion green. Pin each function separately.
    const body = (name: string) => {
      const at = browser.indexOf(`async function ${name}(`);
      assert.notEqual(at, -1, `${name} is gone`);
      const end = browser.indexOf("\n  }", at);
      assert.notEqual(end, -1, `${name} has no closing brace at function indent`);
      return browser.slice(at, end);
    };

    // Toggle CDP button path when already running: stop, and do not fall
    // through to a relaunch.
    assert.match(body("launchProxyChrome"), /if \(proxyBrowser\?\.running\) \{\s*await stopProxyChrome\(\);\s*return;\s*\}/);
    assert.match(body("stopProxyChrome"), /await invoke\("stop_proxy_browser"\)/);
    // Capture-stop path.
    assert.match(browser, /void invoke\("stop_proxy_browser"\)\.catch\(\(error\) => setBrowserError/);
  });

  it("restores remote focus on click for keyboard/IME (P5)", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /ensureRemotePageFocus/);
    assert.match(browser, /Emulation\.setFocusEmulationEnabled/);
    assert.match(browser, /imeInputRef\.current\?\.focus/);
    assert.match(browser, /browser-statusbar__hint/);
  });

  it("persists last URL and can reattach CDP after keep-alive disconnect", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /LAST_URL_STORAGE_KEY|shownet\.browser\.lastUrl/);
    assert.match(browser, /writeStoredBrowserUrl/);
    assert.match(browser, /readStoredBrowserUrl/);
    assert.match(browser, /attachCdpSession/);
    assert.match(browser, /正在重连 CDP/);
    assert.match(browser, /CDP 已断开/);
  });

  it("isolates the restored URL by session", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /browserUrlStorageKey\(sessionId\)/);
    assert.match(browser, /encodeURIComponent\(sessionId\)/);
    assert.match(browser, /readStoredBrowserUrl\(sessionId\)/);
    assert.match(browser, /writeStoredBrowserUrl\(sessionId, frame\.url\)/);
    assert.match(browser, /setExternalPage\(null\)/);
    assert.match(browser, /previousSessionId !== sessionId/);
    assert.match(browser, /stop_proxy_browser/);
  });

  it("keeps 12306 page APIs native while retaining the CDP bridge", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /pageHookGuardSource/);
    assert.match(browser, /guardedHookRuntime/);
    assert.match(browser, /__SHOWNET_HOOK_BRIDGE__/);
  });
});
