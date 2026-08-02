import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("proxy terminal onboarding", () => {
  it("starts capture before opening the default embedded browser", async () => {
    const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.match(source, /const openBrowserCapture = async \(\) => \{\s*if \(!capturing && !await onStartCapture\(\)\) return;\s*onNavigate\("browser"\);\s*\}/s);
    assert.match(source, /onStartCapture=\{onStartCapture\}/);
    assert.match(source, /onClick=\{\(\) => void openBrowserCapture\(\)\}/);
    assert.match(source, /\{capturing \? "打开浏览器" : "开始并打开"\}/);
  });

  it("offers one-click native launch with an explicit terminal choice and manual fallback", async () => {
    const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.match(source, /invoke<ProxyTerminalLaunchResult>\("launch_proxy_terminal"/);
    assert.match(source, /sessionId,\s*terminal: terminalPreference/);
    assert.match(source, /aria-label="终端应用"/);
    assert.match(source, /PROXY_TERMINAL_PREFERENCE_KEY/);
    assert.match(source, /localStorage\?\.setItem\(PROXY_TERMINAL_PREFERENCE_KEY, preference\)/);
    assert.match(source, /打开代理终端/);
    assert.match(source, /启动并打开/);
    assert.match(source, /复制代理变量/);
    assert.match(source, /自动注入 CA · 保持 TLS 校验/);
  });

  it("registers a current-session-only native command without disabling TLS verification", async () => {
    const [module, entry] = await Promise.all([
      readFile(new URL("../src-tauri/src/proxy_terminal.rs", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
    ]);

    assert.match(entry, /fn launch_proxy_terminal\(/);
    assert.match(entry, /capture\.session_id\.as_deref\(\) != Some\(session_id\)/);
    assert.match(entry, /launch_proxy_terminal,\s*launch_proxy_browser/);
    assert.match(module, /NODE_EXTRA_CA_CERTS/);
    assert.match(module, /REQUESTS_CA_BUNDLE/);
    assert.match(module, /NODE_USE_ENV_PROXY/);
    assert.doesNotMatch(module, /NODE_TLS_REJECT_UNAUTHORIZED\s*"?\s*,\s*"?0/);
  });
});
