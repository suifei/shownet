import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { pickReplayExportDirectory } from "../src/replayExport.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("replay export UI path", () => {
  it("pickReplayExportDirectory requires an explicit path and treats null as cancel", async () => {
    const cancelled = await pickReplayExportDirectory(async () => null);
    assert.equal(cancelled.status, "cancel");

    const empty = await pickReplayExportDirectory(async () => "   ");
    assert.equal(empty.status, "cancel");

    const ok = await pickReplayExportDirectory(async () => "/Users/demo/exports");
    assert.deepEqual(ok, { status: "ok", path: "/Users/demo/exports" });

    const fromArray = await pickReplayExportDirectory(async () => ["/Users/demo/parent"]);
    assert.deepEqual(fromArray, { status: "ok", path: "/Users/demo/parent" });

    const failed = await pickReplayExportDirectory(async () => {
      throw new Error("dialog unavailable");
    });
    assert.equal(failed.status, "error");
    if (failed.status === "error") {
      assert.match(failed.message, /dialog unavailable/);
    }
  });

  it("AnalysisView export path always calls directory picker before invoke", () => {
    const source = readFileSync(join(root, "src/components/AnalysisView.tsx"), "utf8");
    assert.match(source, /pickReplayExportDirectory/);
    assert.match(source, /outputDir/);
    // Must not hard-code a silent Application Support write for UI export.
    assert.doesNotMatch(
      source,
      /export_algorithm_replay_package[\s\S]{0,400}outputDir:\s*null/,
    );
    assert.match(source, /选择目录并导出|选择目录后导出|先选目录/);
  });

  it("BrowserView fixture probe uses a structured side panel with collapsed details", () => {
    const source = readFileSync(join(root, "src/components/BrowserView.tsx"), "utf8");
    assert.match(source, /fixture-probe-panel/);
    assert.match(source, /fixture-probe-chip|fixture-probe-chips/);
    assert.match(source, /fixture-probe-badge/);
    assert.match(source, /has-probe/);
    assert.match(source, /样本探针结果/);
    assert.match(source, /对象导出路径/);
    assert.match(source, /setProbeResult\(null\)[\s\S]{0,120}setProbePanelOpen\(true\)/);
    // JSON is secondary under details, not the only body content.
    assert.match(source, /fixture-probe-panel__details/);
    const css = readFileSync(join(root, "src/styles.css"), "utf8");
    assert.match(css, /\.browser-view\.has-probe\s*\{/);
    assert.match(css, /\.fixture-probe-panel\s*\{/);
    assert.match(css, /\.fixture-probe-chip/);
    assert.doesNotMatch(css, /\.fixture-probe-panel\s*\{[^}]*max-height:\s*280px/s);
    assert.match(css, /\.replay-export-toolbar/);
    assert.match(css, /\.replay-export-pill/);
  });
});
