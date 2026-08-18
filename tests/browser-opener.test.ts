import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("system browser opener (P3)", () => {
  it("uses tauri plugin-opener on desktop instead of window.open as the primary path", async () => {
    const [browser, cargo, capabilities, lib, pkg] = await Promise.all([
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/Cargo.toml", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/capabilities/default.json", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
    ]);

    assert.match(pkg, /"@tauri-apps\/plugin-opener"/);
    assert.match(cargo, /tauri-plugin-opener/);
    assert.match(lib, /tauri_plugin_opener::init\(\)/);
    assert.match(capabilities, /"opener:default"/);

    assert.match(browser, /import \{ openUrl \} from "@tauri-apps\/plugin-opener"/);
    assert.match(browser, /openInSystemBrowser/);
    assert.match(browser, /await openUrl\(target\)/);
    assert.match(browser, /disabled=\{!currentUrl\.trim\(\)\}/);
    assert.match(browser, /aria-label=\{t\("browser\.openSystem"\)\}/);
    // Desktop path must not rely on window.open as the only opener.
    assert.doesNotMatch(
      browser,
      /onClick=\{\(\) => window\.open\(currentUrl/,
    );
    // Preview-only fallback is fine inside the non-desktop branch.
    assert.match(browser, /if \(desktop\) \{[\s\S]*?await openUrl\(target\)[\s\S]*?\} else \{[\s\S]*?window\.open/);
  });
});
