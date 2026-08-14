import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("embedded browser keep-alive (P2)", () => {
  it("keeps TrafficView mounted so filters survive Request Lab navigation", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.doesNotMatch(app, /activeView === "traffic"\s*&&\s*\(\s*<TrafficView/);
    assert.match(app, /Keep TrafficView mounted/);
    assert.match(app, /hidden=\{activeView !== "traffic"\}/);
    assert.match(app, /className=\{`workspace-view-keep-alive \$\{activeView === "traffic"/);
  });

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
    assert.match(browser, /export function BrowserView\(\{ active, capturing, sessionId, sessionName, onAnalyzeCryptoLab \}/);

    // Stop only on true unmount or the backend-owned capture stop — not when switching views.
    assert.match(browser, /True unmount only \(app exit\): stop Chrome/);
    assert.match(browser, /The backend owns capture-stop teardown/);
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
    assert.match(body("launchProxyChrome"), /if \(proxyBrowser\?\.running\) \{\s*if \(!await confirmBrowserStop\(\)\) return;\s*await stopProxyChrome\(\);\s*return;\s*\}/);
    assert.match(body("stopProxyChrome"), /await invoke\("stop_proxy_browser", \{ expectedInstanceId: proxyBrowser\?\.sourceInstanceId \?\? null \}\)/);
    assert.match(browser, /title: "停止内嵌浏览器？"[\s\S]*?Chrome 将关闭；当前登录状态、表单内容、页面历史和长连接会被清除。[\s\S]*?confirmLabel: "停止并清除"/);
    assert.match(browser, /Chrome 将以新的临时环境重启；当前登录状态、表单内容、页面历史和长连接会被清除。[\s\S]*?confirmLabel: "重启并清除"/);
    // Capture-stop path.
    // Capture stop is already serialized by the backend. A second fire-and-forget
    // stop from this component could arrive after a fast restart and kill it.
    const captureStopEffect = browser.match(/The backend owns capture-stop teardown[\s\S]*?\}, \[capturing, proxyBrowser\?\.running\]\);/)?.[0] ?? "";
    assert.ok(captureStopEffect);
    assert.doesNotMatch(captureStopEffect, /stop_proxy_browser/);
  });

  it("restores remote focus on click for keyboard/IME (P5)", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /ensureRemotePageFocus/);
    assert.match(browser, /Emulation\.setFocusEmulationEnabled/);
    assert.match(browser, /imeInputRef\.current\?\.focus/);
    assert.match(browser, /browser-statusbar__hint/);
  });

  it("persists last URL and can reattach CDP after keep-alive disconnect", async () => {
    const [browser, storage] = await Promise.all([
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/browserSessionUrl.ts", import.meta.url), "utf8"),
    ]);
    assert.match(storage, /LAST_URL_STORAGE_KEY|shownet\.browser\.lastUrl/);
    assert.match(browser, /writeStoredBrowserUrl/);
    assert.match(browser, /readStoredBrowserUrl/);
    assert.match(browser, /attachCdpSession/);
    assert.match(browser, /正在重连 CDP/);
    assert.match(browser, /CDP 已断开/);
  });

  it("isolates URLs while session history selection stays side-effect free", async () => {
    const [app, browser] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
    ]);
    assert.match(browser, /readStoredBrowserUrl\(sessionId\)/);
    assert.match(browser, /writeStoredBrowserUrl\(sessionId, frame\.url\)/);
    assert.doesNotMatch(browser, /previousSessionId !== sessionId/);
    assert.match(app, /const captureSessionId = capturing/);
    assert.match(app, /runtime\.activeSessionId \?\? sessions\.find\(\(session\) => session\.active\)\?\.id \?\? ""/);
    assert.doesNotMatch(app, /sessions\.find\(\(session\) => session\.active\)\?\.id \?\? activeSession\.id/);
    assert.match(app, /const browserSession = capturing/);
    assert.match(app, /sessionId=\{browserSession\.id\}/);
    assert.match(app, /正在查看/);
    assert.match(app, /抓包写入/);
    assert.match(browser, /requireMatchingBrowserOwner/);
    assert.match(browser, /status\.ownerSessionId !== sessionId/);
    assert.match(app, /临时登录状态、表单内容、页面历史和长连接将被清除/);
    assert.match(app, /captureTransitioningRef\.current = true;[\s\S]*?if \(!next && hasNativeRuntime\)[\s\S]*?confirm\(/);
    assert.match(app, /confirmLabel: "停止并清除"[\s\S]*?captureTransitioningRef\.current = false;[\s\S]*?setCaptureTransitioning\(false\)/);
  });

  it("ignores stale CDP callbacks from an older socket", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /addEventListener\("message", \(message\) => \{\s*if \(cdpSocketRef\.current !== socket\) return;/);
    assert.match(browser, /addEventListener\("error", \(\) => \{\s*if \(cdpSocketRef\.current !== socket\) return;/);
    assert.match(browser, /addEventListener\("close", \(\) => \{\s*if \(cdpSocketRef\.current !== socket\) return;/);
  });

  it("cannot install a Chrome launch invalidated by a newer launch or stop", async () => {
    const backend = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
    assert.match(backend, /browser_generation: AtomicU64/);
    assert.match(backend, /let launch_generation = state\.browser_generation\.fetch_add\(1, Ordering::SeqCst\) \+ 1/);
    assert.match(backend, /state\.browser_generation\.load\(Ordering::SeqCst\) == launch_generation[\s\S]*?browser\.replace/);
    assert.match(backend, /async fn stop_proxy_browser[\s\S]*?browser_generation\.fetch_add\(1, Ordering::SeqCst\)/);
    assert.match(backend, /async fn set_capture_running[\s\S]*?browser_generation\.fetch_add\(1, Ordering::SeqCst\)/);
  });

  it("keeps 12306 page APIs native while retaining the CDP bridge", async () => {
    const browser = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(browser, /pageHookGuardSource/);
    assert.match(browser, /guardedHookRuntime/);
    assert.match(browser, /__SHOWNET_HOOK_BRIDGE__/);
  });
});
