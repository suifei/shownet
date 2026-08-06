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

import { formatBytes, formatReleaseNotes, formatClock, formatListBytes, isSlowRequest, SLOW_REQUEST_MS } from "../src/format.ts";
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


  it("documents the update source the code actually uses", async () => {
    // Release docs that describe a mechanism the code abandoned are worse than
    // no docs: whoever cuts the next release follows them and looks for a file
    // nothing produces any more.
    const doc = await readFile(new URL("../docs/release.md", import.meta.url), "utf8");
    assert.ok(
      doc.includes("api.github.com/repos/suifei/shownet/releases/latest"),
      "release docs must name the endpoint the client reads",
    );
    assert.ok(
      !doc.includes("SHOWNET_UPDATE_PUBLISH"),
      "release docs must not instruct anyone to configure a manifest publish endpoint",
    );

    // The asset names are load-bearing: update checking resolves the download
    // from them, so the docs and the workflow have to agree.
    const workflow = await readFile(
      new URL("../.github/workflows/release.yml", import.meta.url),
      "utf8",
    );
    for (const token of ["aarch64", "windows_x86_64"]) {
      assert.ok(
        doc.includes(token) && workflow.includes(token),
        `${token} must appear in both the release docs and the workflow`,
      );
    }
  });

});

describe("release notes", () => {
  it("flattens the Markdown a GitHub release body actually contains", () => {
    // Shaped after `generate_release_notes: true`, which is what the workflow
    // asks for: a heading over a bulleted list, ending in a bold label.
    const body = [
      "## What's Changed",
      "* Fix **PROBE_ADDR** parse race by @flynn in https://github.com/suifei/shownet/pull/1",
      "* Add `--check` gate",
      "",
      "",
      "",
      "**Full Changelog**: https://github.com/suifei/shownet/commits/v0.1.0",
    ].join("\n");

    const rendered = formatReleaseNotes(body);
    for (const syntax of ["##", "**", "`"]) {
      assert.ok(
        !rendered.includes(syntax),
        `${syntax} would show through to the user: ${rendered}`,
      );
    }
    assert.ok(rendered.startsWith("What's Changed"), rendered);
    assert.ok(rendered.includes("• Fix PROBE_ADDR parse race"), rendered);
    // URLs are the useful part of these notes and must survive untouched.
    assert.ok(
      rendered.includes("https://github.com/suifei/shownet/pull/1"),
      rendered,
    );
    assert.ok(!/\n{3,}/.test(rendered), "collapses Markdown spacing");
  });

  it("keeps a link's text and its target", () => {
    assert.equal(
      formatReleaseNotes("See [the notes](https://example.com/x)"),
      "See the notes (https://example.com/x)",
    );
  });

  it("survives an empty or missing body", () => {
    assert.equal(formatReleaseNotes(null), "");
    assert.equal(formatReleaseNotes(""), "");
    assert.equal(formatReleaseNotes("   \n\n  "), "");
  });

  it("drops the rules a text dialog cannot draw, keeps the rows", () => {
    // The published v0.2.0 notes open with an install table; the separator row
    // is pure noise as text, while the rows still read as columns.
    const body = [
      "| 平台 | 文件 |",
      "|------|------|",
      "| macOS | ShowNet.dmg |",
      "",
      "---",
      "",
      "## What's Changed",
    ].join("\n");
    const rendered = formatReleaseNotes(body);
    assert.ok(!rendered.includes("|------|"), rendered);
    assert.ok(!/^---$/m.test(rendered), rendered);
    assert.ok(rendered.includes("| macOS | ShowNet.dmg |"), rendered);
    assert.ok(rendered.includes("What's Changed"), rendered);
  });

  it("does not eat prose that merely contains dashes", () => {
    // The guard must key on a line being *only* rule characters, or a real
    // sentence with an em dash or a hyphenated term would vanish.
    for (const line of [
      "未经过商业代码签名 —— 请先核对校验和",
      "- 支持 HTTP/2 与 gRPC-Web",
      "见 SHA256SUMS.txt",
    ]) {
      assert.ok(
        formatReleaseNotes(line).length > 0,
        `dropped a real line: ${line}`,
      );
    }
  });

  it("leaves prose that is not Markdown alone", () => {
    const plain = "ShowNet 0.1.0 desktop builds (macOS aarch64 + Windows x86_64).";
    assert.equal(formatReleaseNotes(plain), plain);
  });
});

describe("IPC surface", () => {
  /** Commands registered with no frontend caller, each deliberate and explained. */
  const INTENTIONALLY_UNCALLED = new Set<string>([]);

  it("registers no command the app cannot reach and has not justified", async () => {
    // A registered command with no caller is reachable over IPC and maintained
    // by nobody. Ten were removed because an agent tool or another return value
    // already covered them; this keeps that from silently growing back.
    const lib = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
    const handler = /generate_handler!\[([\s\S]*?)\]/.exec(lib);
    assert.ok(handler, "could not find the command registration");
    const registered = handler[1]
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    assert.ok(registered.length > 100, `only found ${registered.length} commands`);

    const frontend = await readSourceTree(new URL("../src/", import.meta.url));
    const unreachable = registered.filter(
      (command) => !frontend.includes(`"${command}"`) && !INTENTIONALLY_UNCALLED.has(command),
    );
    assert.deepEqual(
      unreachable,
      [],
      "these commands have no caller: either wire them up, delete them, or add them to INTENTIONALLY_UNCALLED with the reason why",
    );
  });

  it("keeps the exemption list honest", async () => {
    // An exemption for a command that no longer exists is stale bookkeeping that
    // makes the list stop meaning anything.
    const lib = await readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8");
    for (const command of INTENTIONALLY_UNCALLED) {
      assert.ok(
        lib.includes(`fn ${command}(`),
        `${command} is exempted but no longer exists`,
      );
    }
  });
});

async function readSourceTree(root: URL): Promise<string> {
  const { readdir } = await import("node:fs/promises");
  const entries = await readdir(root, { withFileTypes: true });
  const parts = await Promise.all(
    entries.map(async (entry) => {
      const child = new URL(`${entry.name}${entry.isDirectory() ? "/" : ""}`, root);
      if (entry.isDirectory()) return readSourceTree(child);
      return /\.tsx?$/.test(entry.name) ? readFile(child, "utf8") : "";
    }),
  );
  return parts.join("\n");
}

describe("replay batch history", () => {
  it("reads back the batches storage already keeps", async () => {
    // Batches were persisted and never read: replay fifty requests, switch away,
    // and the results were gone while still sitting in the database.
    const workbench = await readFile(
      new URL("../src/components/RequestWorkbench.tsx", import.meta.url),
      "utf8",
    );
    assert.ok(
      workbench.includes('invoke<ReplayBatch[]>("list_replay_batches"'),
      "the workbench must read the persisted batch list",
    );
    // Loading history once on mount would leave it stale the moment a batch
    // finishes, which is exactly when the user wants to see it.
    assert.ok(
      /\["queued", "running"\]\.includes\(event\.payload\.status\)[\s\S]{0,80}loadHistory/.test(
        workbench,
      ),
      "history must refresh when a batch reaches a terminal state",
    );
    assert.ok(
      workbench.includes("setBatch(entry)"),
      "picking a past batch must show its results",
    );
  });
});

describe("release publishing", () => {
  it("keeps one source for the install guidance both workflows ship", async () => {
    // Two workflows publish releases now. If each carried its own copy of this
    // text they would drift, and users would get different instructions
    // depending on which path produced their download.
    const body = await readFile(
      new URL("../.github/release/body.md", import.meta.url),
      "utf8",
    );
    assert.match(body, /\{\{VERSION\}\}/, "the shared body must be a template");
    assert.ok(body.includes("SHA256SUMS.txt"), "it must point at the checksums");

    for (const workflow of ["release.yml", "publish-from-run.yml"]) {
      const text = await readFile(
        new URL(`../.github/workflows/${workflow}`, import.meta.url),
        "utf8",
      );
      assert.ok(
        text.includes(".github/release/body.md"),
        `${workflow} must render the shared body rather than inlining its own`,
      );
      assert.ok(
        !text.includes("Gatekeeper"),
        `${workflow} still inlines install prose; it belongs in the shared file`,
      );
    }
  });

  it("refuses to publish artifacts from a different version", async () => {
    // Republishing exists to skip a two-hour rebuild, which also makes it easy
    // to point at the wrong run and hand users a download that does not match
    // the tag they clicked.
    const workflow = await readFile(
      new URL("../.github/workflows/publish-from-run.yml", import.meta.url),
      "utf8",
    );
    assert.ok(
      workflow.includes("does not match package.json version"),
      "the tag must be checked against the version at that tag",
    );
    assert.ok(
      /is not version \$\{version\}/.test(workflow),
      "asset filenames must be checked against that version",
    );
  });
});

describe("repository hygiene", () => {
  it("commits the files the build and tests read", async () => {
    // `.github/release/body.md` existed locally and was ignored by an unanchored
    // `release/` rule, so `git add -A` skipped it in silence and CI checked out
    // a tree without it. Everything passed here and failed there.
    const { execFile } = await import("node:child_process");
    const { promisify } = await import("node:util");
    const { fileURLToPath } = await import("node:url");
    const run = promisify(execFile);
    // `.pathname` yields "/C:/..." on Windows, which is not a path any process
    // can be spawned in — the failure surfaces as a confusing `git ENOENT`.
    const root = fileURLToPath(new URL("../", import.meta.url));

    const required = [
      ".github/release/body.md",
      ".github/workflows/release.yml",
      ".github/workflows/publish-from-run.yml",
    ];
    for (const path of required) {
      const { stdout } = await run("git", ["ls-files", "--", path], { cwd: root });
      assert.equal(
        stdout.trim(),
        path,
        `${path} is read at build or test time but is not tracked by git`,
      );
    }
  });

  it("never turns a file URL into a path with .pathname", async () => {
    // On Windows that yields "/C:/..." — not a path any API accepts. It works on
    // macOS and Linux, so the mistake only ever surfaces on the one runner, and
    // it surfaces as something unrelated-looking like `spawn git ENOENT`.
    const { readdir } = await import("node:fs/promises");
    const root = new URL("../tests/", import.meta.url);
    const files = (await readdir(root, { withFileTypes: true }))
      .filter((entry) => entry.isFile() && /\.tsx?$/.test(entry.name));

    for (const file of files) {
      const text = await readFile(new URL(file.name, root), "utf8");
      assert.ok(
        !/new URL\([^)]*import\.meta\.url[^)]*\)\.pathname/.test(text),
        `${file.name} converts a file URL with .pathname; use fileURLToPath instead`,
      );
    }
  });

  it("anchors root-only ignore rules so they cannot match nested paths", async () => {
    // `release/` matches at any depth; `/release/` matches only the root build
    // output it was written for.
    const ignore = await readFile(new URL("../.gitignore", import.meta.url), "utf8");
    for (const line of ignore.split("\n").map((entry) => entry.trim())) {
      assert.ok(
        !["release/", "output/", "tmp/", "build/", "dist/"].includes(line),
        `${line} matches at any depth; anchor it as /${line}`,
      );
    }
  });
});
