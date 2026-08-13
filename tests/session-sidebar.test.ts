import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { defaultCaptureSessionName } from "../src/sessionPresentation.ts";

describe("session sidebar", () => {
  it("uses a recognizable timestamp for new capture sessions", () => {
    assert.equal(defaultCaptureSessionName(new Date(2026, 7, 1, 9, 5)), "抓包 08-01 09:05");
  });

  it("keeps traffic and AI report navigation as separate actions", async () => {
    const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.doesNotMatch(source, /setActiveView\(session\.analysisReportCount/);
    assert.match(source, /title=\{isCaptureTarget \? `\${session\.name} 正在接收抓包；点击查看记录` : `打开 \${session\.name} 的抓包记录`\}/);
    assert.match(source, /aria-label={`打开 \${session\.name} 的最近 AI 报告`}/);
    assert.match(source, /invoke<Session>\("rename_session"/);
  });

  it("puts a session-scoped delete action on each row without selecting the row", async () => {
    const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.match(source, /className="session-delete-button"/);
    assert.match(source, /aria-label={`删除 \${session\.name}`}/);
    assert.match(source, /event\.stopPropagation\(\);\s*void deleteSession\(session\);/);
    assert.match(source, /invoke\("delete_session", \{ sessionId: session\.id \}\)/);
    assert.match(
      await readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
      /\.session-rename-button\s*\{[^}]*right:\s*37px/s,
    );
  });

  it("stacks the session tools dropdown above the session list without glass bleed", async () => {
    const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

    assert.match(css, /\.sessions-label\s*\{[^}]*z-index:\s*20/s);
    assert.match(css, /\.session-tools-menu\s*\{[^}]*z-index:\s*50/s);
    assert.match(css, /\.session-list\s*\{[^}]*z-index:\s*1/s);
    assert.match(css, /\.session-list\s*\{[^}]*isolation:\s*isolate/s);
    // Glass material must target the menu panel, not the relative wrapper.
    assert.match(css, /\.session-tools-menu/);
    assert.doesNotMatch(
      css,
      /\.dialog,\s*\n\.command-palette,\s*\n\.filter-builder-popover,\s*\n\.session-tools,\s*\n\.toast/,
    );
    assert.match(
      css,
      /\.session-tools-menu\s*\{[^}]*backdrop-filter:\s*none/s,
    );
    assert.match(
      css,
      /\.session-tools-menu\s*\{[^}]*background-color:\s*var\(--dark-elevated\)/s,
    );
  });
});
