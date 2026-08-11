import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("native AI report streaming", () => {
  it("forwards GrokBuild deltas and persists visible progress", async () => {
    const [analysis, analysisView, types] = await Promise.all([
      readFile(new URL("../src-tauri/src/analysis.rs", import.meta.url), "utf8"),
      readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
    ]);

    assert.doesNotMatch(analysis, /\|_delta\| Ok\(\(\)\)/);
    assert.match(analysis, /let visible_delta = native_stream\.push\(delta\)/);
    assert.match(
      analysis,
      /save_analysis_progress\(&report\.id, native_stream\.visible\(\)\)/,
    );
    assert.match(analysis, /"content-reset"/);
    assert.match(types, /\| "content-reset"/);
    assert.match(
      analysisView,
      /update\.phase === "content-reset"[\s\S]*?setContent\(""\)/,
    );
  });
});
