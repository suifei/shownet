/**
 * Settings has seven independent save buttons and no shared notion of pending
 * edits. Most sections are collapsed, so an unsaved change inside one was
 * invisible, and leaving the view dropped it without a word.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  computeDirtySections,
  seedMissingBaselines,
  serializeSectionValue,
  summarizeUnsaved,
} from "../src/settingsDirty.ts";
import { SEND_SETTINGS } from "../src/sendSettings.ts";

const settings = await readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8");
const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");
const analysis = await readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8");
const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

describe("section value serialization", () => {
  it("ignores key order, so an object literal cannot fake an edit", () => {
    assert.equal(
      serializeSectionValue({ a: 1, b: 2 }),
      serializeSectionValue({ b: 2, a: 1 }),
    );
  });

  it("still distinguishes real changes", () => {
    assert.notEqual(serializeSectionValue({ port: 8888 }), serializeSectionValue({ port: 8080 }));
  });

  it("preserves array order, which is meaningful", () => {
    assert.notEqual(serializeSectionValue(["a", "b"]), serializeSectionValue(["b", "a"]));
  });

  it("sorts keys inside nested objects too", () => {
    assert.equal(
      serializeSectionValue({ outer: { y: 1, x: 2 } }),
      serializeSectionValue({ outer: { x: 2, y: 1 } }),
    );
  });
});

describe("dirty section computation", () => {
  it("reports only sections that differ from their baseline", () => {
    const dirty = computeDirtySections(
      { a: "1", b: "2", c: "3" },
      { a: "1", b: "changed", c: "3" },
    );
    assert.deepEqual(dirty, ["b"]);
  });

  it("never reports a section that has no baseline yet", () => {
    // A cold load would otherwise light up every indicator on the page.
    assert.deepEqual(computeDirtySections({ a: "1", b: "2" }, {}), []);
    assert.deepEqual(computeDirtySections({ a: "1", b: "2" }, { a: "1" }), []);
  });

  it("seeds baselines only for sections that lack one", () => {
    const seeded = seedMissingBaselines({ a: "new", b: "new" }, { a: "old" });
    assert.equal(seeded.a, "old", "an existing baseline must not adopt an in-progress edit");
    assert.equal(seeded.b, "new");
  });

  it("returns the same object when nothing needs seeding", () => {
    const baselines = { a: "1" };
    assert.equal(seedMissingBaselines({ a: "2" }, baselines), baselines, "no needless re-render");
  });

  it("summarizes what is outstanding", () => {
    assert.deepEqual(summarizeUnsaved(["capture.routing", "ai.provider"]), {
      count: 2,
      ids: ["capture.routing", "ai.provider"],
    });
  });
});

describe("settings surfaces its unsaved state", () => {
  it("badges a section header, which is visible while collapsed", () => {
    assert.match(settings, /className="settings-section__dirty" title="有未保存的更改"/);
    assert.match(styles, /\.settings-section__dirty \{/);
  });

  it("keeps a page-level summary that names the sections", () => {
    assert.match(settings, /className="settings-unsaved" role="status"/);
    assert.match(settings, /\{dirtySections\.length\} 处未保存的更改/);
    assert.match(settings, /dirtySections\.map\(sectionTitle\)\.join\("、"\)/);
    assert.match(settings, /onClick=\{\(\) => revealSection\(dirtySections\[0\]\)\}/);
    assert.match(styles, /\.settings-unsaved \{[^}]*position: sticky/s);
  });

  it("adopts the backend value as the baseline on load and after saving", () => {
    // Otherwise a freshly loaded page reads as entirely unsaved.
    for (const id of ["capture.routing", "capture.upstream", "capture.https", "ai.provider", "ai.strategy", "data.database", "mcp.server"]) {
      assert.match(settings, new RegExp(`commitBaseline\\("${id}"`), `${id} needs a baseline commit`);
    }
    assert.ok((settings.match(/commitBaseline\(/g) ?? []).length >= 14, "loads and saves both commit");
  });

  it("treats a backend push as saved state, not a local edit", () => {
    assert.match(settings, /mirroring it\s+\/\/ is not an edit\./);
  });

  it("does not let an MCP activity push overwrite in-progress edits", () => {
    // settings://mcp-server also fires on every MCP tool call, carrying the
    // saved port/enabled/allowWrites. Adopting those unconditionally discarded
    // whatever the user was typing and re-baselined so the badge never showed.
    assert.match(settings, /const settingsChanged =/);
    assert.match(settings, /savedMcpSettings\.current\.port/);
    assert.match(
      settings,
      /setMcpStatus\(\(current\) => \(settingsChanged \? pushed : \{ \.\.\.pushed, port: current\.port, enabled: current\.enabled, allowWrites: current\.allowWrites \}\)\)/,
    );
  });

  it("does not let a status refresh revert a pending takeover toggle", () => {
    // `active` and `recoveryPending` are runtime readings and may be adopted on
    // any refresh; `enabled` is a saved preference the user may be editing, so
    // its effect must depend on that preference alone.
    assert.match(
      settings,
      /setSystemProxy\(\(current\) => \(\{ \.\.\.current, enabled: runtime\.systemProxyEnabled \}\)\);[\s\S]*?\}, \[commitBaseline, runtime\.systemProxyEnabled\]\);/,
      "the enabled mirror must not re-run on unrelated runtime changes",
    );
  });
});

describe("send settings read the same in both panels", () => {
  it("carries the TLS warning wherever the switch appears", () => {
    // The lab said only "默认开启"; turning verification off there is exactly
    // as risky as in the replay panel.
    assert.equal(SEND_SETTINGS.verifyTls.detail, "关闭仅用于授权测试");
  });

  it("is the only source of that copy", () => {
    assert.match(workbench, /from "\.\.\/sendSettings"/);
    assert.equal((workbench.match(/SEND_SETTINGS\.verifyTls\.label/g) ?? []).length, 2, "replay and lab both read it");
    assert.doesNotMatch(workbench, /label="验证 TLS"/);
    assert.doesNotMatch(workbench, /detail="沿用全局出口设置"/);
    assert.doesNotMatch(workbench, /detail="沿用设置中的出口"/);
  });
});

describe("analysis scope is written once", () => {
  it("shares one block between the desktop rail and the mobile drawer", () => {
    // The two were verbatim copies, so every label change had to be made twice.
    assert.match(analysis, /const scopeControls = \(/);
    assert.match(analysis, /className="analysis-config__section analysis-scope">\{scopeControls\}<\/div>/);
    assert.match(analysis, /aria-label="移动端分析范围">\{scopeControls\}<\/section>/);
    assert.equal((analysis.match(/仅分析已标记关键请求/g) ?? []).length, 1);
    assert.equal((analysis.match(/总提示受 \{formatContextSize\(/g) ?? []).length, 1);
    // The budget follows the configured context window; a literal here would go
    // stale the moment the user changes 上下文上限.
    assert.doesNotMatch(analysis, /总提示受 \d+ KiB/);
  });
});
