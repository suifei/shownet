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
    assert.match(source, /title={`打开 \${session\.name} 的抓包记录`}/);
    assert.match(source, /aria-label={`打开 \${session\.name} 的最近 AI 报告`}/);
    assert.match(source, /invoke<Session>\("rename_session"/);
  });
});
