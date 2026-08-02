import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  browserBusAvailable,
  browserClick,
  browserDispatchKey,
  browserEvaluate,
  browserInsertText,
  browserInstallLab,
  browserNavigate,
  browserReload,
  browserScreenshot,
  getProxyBrowserStatus,
  runWebRiskFixtureProbe,
  tryBrowserNavigate,
} from "../src/browserBus.ts";

describe("browserBus client", () => {
  it("reports unavailable outside Tauri", () => {
    // Node test harness is not the Tauri webview.
    assert.equal(browserBusAvailable(), false);
  });

  it("exports discrete command wrappers used by UI and Agent surfaces", () => {
    const wrappers = [
      getProxyBrowserStatus,
      browserEvaluate,
      browserClick,
      browserScreenshot,
      browserNavigate,
      browserInsertText,
      browserDispatchKey,
      browserInstallLab,
      browserReload,
      tryBrowserNavigate,
      runWebRiskFixtureProbe,
    ];
    for (const fn of wrappers) {
      assert.equal(typeof fn, "function");
    }
  });

  it("tryBrowserNavigate is a no-op outside Tauri", async () => {
    assert.equal(await tryBrowserNavigate("https://example.com"), false);
  });
});