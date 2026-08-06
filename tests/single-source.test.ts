/**
 * Facts that must be declared exactly once.
 *
 * Each of these had two or more copies that had already drifted apart. The
 * tests assert both the corrected behaviour and the absence of the duplicate,
 * because a duplicate that agrees today is just a bug waiting for the next edit.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { formatBytes, formatClock, formatListBytes, isSlowRequest, SLOW_REQUEST_MS } from "../src/format.ts";
import { RULE_TRACE_RESULT_LABELS, ruleTraceResultLabel } from "../src/ruleTrace.ts";
import { shellQuote } from "../src/shellQuote.ts";

const read = (name: string) => readFile(new URL(`../src/${name}`, import.meta.url), "utf8");

describe("shell quoting", () => {
  it("escapes an apostrophe into a runnable sequence", () => {
    // The request-code copy produced `"'"'`, dropping the leading quote, so any
    // value containing an apostrophe generated an unrunnable command.
    assert.equal(shellQuote("it's"), `'it'"'"'s'`);
  });

  it("leaves values without quotes alone", () => {
    assert.equal(shellQuote("https://example.com/a?b=1"), `'https://example.com/a?b=1'`);
  });

  it("handles several apostrophes", () => {
    assert.equal(shellQuote("a'b'c"), `'a'"'"'b'"'"'c'`);
  });

  it("is declared once", async () => {
    for (const file of ["requestCode.ts", "requestWorkbench.ts"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /function shellQuote/, `${file} must not redeclare it`);
      assert.match(source, /from "\.\/shellQuote\.ts"/, `${file} must import it`);
    }
  });
});

describe("rule trace labels", () => {
  it("names every outcome, including the two that used to read 未命中", () => {
    assert.equal(ruleTraceResultLabel("inherited"), "沿用连接");
    assert.equal(ruleTraceResultLabel("skipped"), "已跳过");
    assert.equal(ruleTraceResultLabel("not-matched"), "未命中");
    assert.equal(Object.keys(RULE_TRACE_RESULT_LABELS).length, 6);
  });

  it("falls back to the raw value rather than mislabelling", () => {
    assert.equal(ruleTraceResultLabel("something-new"), "something-new");
  });

  it("is the only label map for these outcomes", async () => {
    const [traffic, workbench] = await Promise.all([
      read("components/TrafficView.tsx"),
      read("components/RequestWorkbench.tsx"),
    ]);
    // The traffic pane used an inline ternary that fell through to 未命中.
    assert.doesNotMatch(traffic, /trace\.result === "applied" \? "已执行"/);
    assert.doesNotMatch(workbench, /function ruleTraceResultLabel/);
    for (const source of [traffic, workbench]) {
      assert.match(source, /from "\.\.\/ruleTrace"/);
    }
  });
});

describe("slow request threshold", () => {
  it("treats the boundary the same everywhere", () => {
    // The grid highlight used `> 1000` and the filter `>= 1000`, so a request
    // timed at exactly 1000 ms matched the filter but rendered unmarked.
    assert.equal(isSlowRequest(SLOW_REQUEST_MS), true);
    assert.equal(isSlowRequest(SLOW_REQUEST_MS - 1), false);
    assert.equal(isSlowRequest(null), false);
    assert.equal(isSlowRequest(undefined), false);
  });

  it("has no remaining inline comparison", async () => {
    for (const file of ["components/TrafficView.tsx", "requestFilters.ts", "capabilities.ts"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /durationMs[^\n]*[><]=?\s*1_000/, `${file} must use isSlowRequest`);
    }
  });
});

describe("byte formatting", () => {
  it("uses one convention", () => {
    assert.equal(formatBytes(0), "0 B");
    assert.equal(formatBytes(512), "512 B");
    assert.equal(formatBytes(5_000), "4.9 KB");
    assert.equal(formatBytes(5_000_000), "4.8 MB");
    assert.equal(formatBytes(5_000_000_000), "4.66 GB");
  });

  it("survives non-finite input, which the grid copy did not", () => {
    assert.equal(formatBytes(Number.NaN), "0 B");
    assert.equal(formatBytes(Number.POSITIVE_INFINITY), "0 B");
    assert.equal(formatBytes(null), "0 B");
  });

  it("keeps the denser grid variant whole above 10 KB", () => {
    assert.equal(formatListBytes(5_000), "4.9 KB");
    assert.equal(formatListBytes(50_000), "49 KB");
  });

  it("is declared once", async () => {
    for (const file of ["App.tsx", "components/TrafficView.tsx", "components/HttpBodyViewer.tsx", "components/SettingsView.tsx"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /function format(FileSize|Bytes|FrameSize|StorageBytes|ListBytes)\b/, `${file} redeclares a byte formatter`);
    }
  });
});

describe("clock formatting", () => {
  it("shows a placeholder instead of Invalid Date", () => {
    // The websocket frame formatter had no guard and rendered "Invalid Date.NaN".
    assert.equal(formatClock(Number.NaN), "--:--:--");
    assert.equal(formatClock(Number.NaN, true), "--:--:--.---");
    assert.equal(formatClock(null), "--:--:--");
  });

  it("pads milliseconds when asked", () => {
    const value = formatClock(new Date(2026, 0, 1, 9, 8, 7, 5).getTime(), true);
    assert.match(value, /\.005$/);
  });

  it("is declared once", async () => {
    for (const file of ["components/TrafficView.tsx", "components/BrowserView.tsx"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /function format(FrameTime|HookTime)\b/, `${file} redeclares a clock formatter`);
    }
  });
});

describe("session lifecycle is a closed loop", () => {
  it("offers delete alongside create and rename", async () => {
    // `delete_session` was registered in Rust and emitted session://deleted,
    // but nothing in the UI could call it — sessions only accumulated.
    const app = await read("App.tsx");
    assert.match(app, /invoke\("delete_session", \{ sessionId: session\.id \}\)/);
    assert.match(app, /id: "session-delete"/);
    assert.match(app, /className="is-danger" onClick=\{\(\) => void deleteSession\(activeSession\)\}/);
  });

  it("refuses to delete the session that is being captured into", async () => {
    const app = await read("App.tsx");
    assert.match(app, /if \(capturing && session\.id === activeSessionId\)/);
    assert.match(app, /请先停止抓包，再删除当前会话/);
  });

  it("confirms before deleting and says what is lost", async () => {
    const app = await read("App.tsx");
    assert.match(app, /tone: "danger"/);
    assert.match(app, /条请求、以及这个会话的标注与规则轨迹都会一并删除，无法撤销。/);
  });
});

describe("live capture does not restart the request query", () => {
  it("keeps the session list out of the desktop refresh effect", async () => {
    // refreshSessions() runs on every capture://request-created and returns a
    // fresh array, so sharing one effect reset the scroll window ~4x/s.
    const app = await read("App.tsx");
    assert.match(app, /refreshRequests\(activeSessionId\)\.catch[\s\S]{0,120}\}, \[activeSessionId, refreshRequests\]\);/);
    assert.doesNotMatch(app, /\[activeSessionId, refreshRequests, requestFilter, requestSort, sessions\]/);
  });
});

describe("http methods", () => {
  it("separates what can be observed from what can be built", async () => {
    const { BUILDABLE_METHODS, OBSERVABLE_METHODS } = await import("../src/httpMethods.ts");
    // CONNECT is a tunnel verb the proxy sees; it is not composable by hand.
    assert.ok(OBSERVABLE_METHODS.includes("CONNECT"));
    assert.ok(!(BUILDABLE_METHODS as readonly string[]).includes("CONNECT"));
    // HEAD was missing from the observable union, so a captured HEAD request
    // had no valid type.
    assert.ok(OBSERVABLE_METHODS.includes("HEAD"));
    assert.ok(BUILDABLE_METHODS.includes("HEAD"));
  });

  it("is declared once", async () => {
    for (const file of ["components/RequestWorkbench.tsx", "components/TrafficView.tsx", "requestFilters.ts", "types.ts"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /\["GET",\s*"POST"/, `${file} inlines a method list`);
      assert.doesNotMatch(source, /"GET" \| "POST"/, `${file} inlines a method union`);
    }
  });
});

describe("request state naming", () => {
  it("gives each state exactly one name", async () => {
    const { REQUEST_STATE_LABELS, STATUS_LABELS, requestStateLabel } = await import("../src/requestFilters.ts");
    // The grid said 流式 and the filter said 流式传输 for the same state.
    assert.equal(STATUS_LABELS.streaming, REQUEST_STATE_LABELS.streaming);
    assert.equal(STATUS_LABELS.tunnel, REQUEST_STATE_LABELS.tunnel);
    assert.equal(requestStateLabel("complete"), "完成");
    assert.equal(requestStateLabel("unknown-state"), "unknown-state");
  });

  it("leaves no inline state ternary in the grid", async () => {
    const traffic = await read("components/TrafficView.tsx");
    assert.doesNotMatch(traffic, /request\.state === "pending" \? "进行中"/);
  });
});

describe("shared maps that used to be copied", () => {
  it("declares the source icon map once", async () => {
    for (const file of ["App.tsx", "components/TrafficView.tsx"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /const sourceIcons: Record/, `${file} redeclares sourceIcons`);
      assert.match(source, /from "\.{1,2}\/(\.\.\/)?sourceIcons"/, `${file} must import it`);
    }
  });

  it("gives each analysis mode one icon", async () => {
    const { ANALYSIS_MODES } = await import("../src/analysisModes.ts");
    assert.equal(new Set(ANALYSIS_MODES.map((mode) => mode.icon)).size, ANALYSIS_MODES.length);
    for (const file of ["components/AnalysisView.tsx", "components/SkillsView.tsx"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /Icons: Record<AnalysisMode, typeof Sparkles>/, `${file} redeclares the icon map`);
    }
  });

  it("uses one MCP placeholder status", async () => {
    const { defaultMcpServerStatus } = await import("../src/mcpDefaults.ts");
    const { mcpToolPreview } = await import("../src/capabilities.ts");
    // Settings claimed 28 tools while Skills derived its own number, so the two
    // panels reported different facts about the same server.
    assert.equal(defaultMcpServerStatus().toolCount, mcpToolPreview.length);
    assert.equal(defaultMcpServerStatus({ enabled: true }).enabled, true);

    for (const file of ["components/SettingsView.tsx", "components/SkillsView.tsx"]) {
      const source = await read(file);
      assert.doesNotMatch(source, /toolCount: \d+/, `${file} hardcodes a tool count`);
      assert.match(source, /defaultMcpServerStatus\(/, `${file} must use the shared placeholder`);
    }
  });
});

describe("embedded browser keeps its page", () => {
  it("does not key the frame on the URL", async () => {
    // `key={currentUrl}` made React destroy and recreate the element on every
    // navigation, discarding login state, form input, scroll and the JS runtime.
    const source = await read("components/BrowserView.tsx");
    assert.doesNotMatch(source, /<iframe[^>]*key=\{currentUrl\}/);
    assert.match(source, /<iframe ref=\{iframeRef\} src=\{externalPage\}/);
  });

  it("stops Chrome only on a real unmount", async () => {
    const source = await read("components/BrowserView.tsx");
    // A dependency here would let the teardown fire while the user is working.
    assert.match(source, /if \(desktopRef\.current\) void invoke\("stop_proxy_browser"\)[\s\S]{0,40}\}, \[\]\);/);
  });

  it("never pushes a hidden surface's size to the real page", async () => {
    const source = await read("components/BrowserView.tsx");
    assert.match(source, /if \(!surface\.clientWidth \|\| !surface\.clientHeight\) return;/);
  });
});

describe("closed loops", () => {
  it("browser://status carries one payload shape on both edges", async () => {
  // A channel that emits a struct on start and a bare boolean on stop cannot be
  // consumed: any listener written against one shape breaks on the other. This
  // was latent because nothing listens yet, which is exactly when it is cheap
  // to fix and expensive to discover later.
  const lib = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  const emissions = [...lib.matchAll(/emit\(\s*&app,\s*"browser:\/\/status",\s*([^)]*?)\)/gs)].map(
    (match) => match[1].trim(),
  );
  assert.ok(emissions.length >= 2, `expected both edges to emit, saw ${emissions.length}`);
  for (const payload of emissions) {
    assert.ok(
      !/^&(true|false)\b/.test(payload),
      `browser://status must not emit a bare boolean: ${payload}`,
    );
  }
});

  it("no Tauri command duplicates logic the agent tools already own", async () => {
  // `generate_code` is shared, but a second registered entry point into it with
  // no caller is dead IPC surface — and code generation for the UI deliberately
  // lives in TypeScript, so this command had no future consumer either.
  const lib = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
  assert.ok(
    !lib.includes("fn generate_request_code("),
    "generate_request_code was removed from the Tauri surface; agent tools own it",
  );
});

  it("LAN access copy uses the app's own source vocabulary", async () => {
  // The app models `mobile` and `iot` as separate sources. Prose that invents
  // its own wording drifts from the labels shown everywhere else.
  const settings = await readFile(
    new URL("../src/components/SettingsView.tsx", import.meta.url),
    "utf8",
  );
  assert.ok(
    !settings.includes("手机、平板和 IoT 设备"),
    "device copy must derive from sourceLabels rather than restating it",
  );
  assert.ok(
    settings.includes("sourceLabels.mobile") && settings.includes("sourceLabels.iot"),
    "device copy must read both source labels",
  );
});

  it("checks for updates against GitHub, not a self-hosted manifest", async () => {
    // The release workflow used to build a latest.json and PUT it to a private
    // host. That was a second statement of "what the latest version is", able to
    // drift from the release it described or go missing if the upload failed
    // after the release was already public.
    const updates = await readFile(
      new URL("../src-tauri/src/updates.rs", import.meta.url),
      "utf8",
    );
    assert.match(
      updates,
      /https:\/\/api\.github\.com\/repos\/[\w.-]+\/[\w.-]+\/releases\/latest/,
      "the default update endpoint must be the GitHub Releases API",
    );

    const workflow = await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    );
    for (const leftover of ["SHOWNET_UPDATE_PUBLISH", "SHOWNET_UPDATE_MANIFEST_URL"]) {
      assert.ok(
        !workflow.includes(leftover),
        `release workflow must not carry ${leftover}`,
      );
    }
    assert.ok(
      !/--data-binary @release-assets\/latest\.json/.test(workflow),
      "release workflow must not publish a manifest to a self-hosted endpoint",
    );
  });

});
