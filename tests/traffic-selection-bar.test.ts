/**
 * Selecting requests is the gateway into replay, diff, the request lab and AI
 * analysis. Those actions used to be eight unlabelled icons in the status bar,
 * which meant a first-time user had to hover each one to learn what it did.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { activateUiLocale } from "../src/i18n.ts";
import { ANALYSIS_MODES, analysisModeFocus, analysisModeLabel } from "../src/analysisModes.ts";

activateUiLocale("zh-CN");

const traffic = await readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8");
const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

describe("traffic selection bar", () => {
  it("labels every primary action with text, not just an icon tooltip", () => {
    assert.match(traffic, /className="selection-bar"/);
    for (const key of ["traffic.analyzeSelected", "traffic.replay", "traffic.rewrite", "traffic.diff", "traffic.more"]) {
      assert.match(traffic, new RegExp(`t\\("${key.replace(".", "\\.")}"\\)`), `selection bar must spell out "${key}"`);
    }
  });

  it("moves the low-frequency actions into an overflow menu", () => {
    assert.match(traffic, /className="selection-more-menu" role="menu"/);
    for (const key of ["traffic.copyUrl", "traffic.archive", "traffic.exportEvidence"]) {
      assert.match(traffic, new RegExp(`role="menuitem"[^\\n]*t\\("${key.replace(".", "\\.")}"\\)`), `${key} belongs in the overflow menu`);
    }
  });

  it("exposes bookmarking outside the right-click menu", () => {
    // Bookmarking used to be reachable only by right-clicking a row.
    const menu = traffic.slice(traffic.indexOf("selection-more-menu"), traffic.indexOf("selection-bar__clear"));
    assert.match(menu, /toggleSelectedBookmark/);
  });

  it("distinguishes session-wide analysis from selection-scoped analysis", () => {
    // Both entry points used to read "AI 分析" with no hint of their scope.
    assert.match(traffic, /t\("traffic\.analyzeSession"\)/);
    assert.match(traffic, /t\("traffic\.analyzeSelected"\)/);
    assert.match(traffic, /t\("traffic\.analyzeSelectedHint"/);
    assert.match(traffic, /t\("traffic\.analyzeSelectedN"/);
  });

  it("says what a disabled action needs instead of going silent", () => {
    assert.match(traffic, /selection\.selectedIds\.length === 1 \? t\("traffic\.rewriteHint"\) : t\("traffic\.rewriteNeedOne"\)/);
    assert.match(traffic, /selection\.selectedIds\.length === 2 \? t\("traffic\.diffHint"\) : t\("traffic\.diffNeedTwo"\)/);
  });

  it("dismisses the overflow menu the same way every other floating layer does", () => {
    assert.match(traffic, /useDismissibleLayer\(selectionMoreOpen, selectionMoreRef/);
  });

  it("no longer crowds the status bar with icon buttons", () => {
    assert.doesNotMatch(traffic, /className="selection-actions"/);
    assert.doesNotMatch(styles, /\.selection-actions \{/);
    assert.match(traffic, /className=\{`request-grid-statusbar/, "the numeric read-outs stay");
  });

  it("floats over the grid without clipping on a narrow window", () => {
    assert.match(styles, /\.selection-bar \{[^}]*position: absolute/s);
    assert.match(styles, /\.selection-bar \{ max-width: calc\(100% - 12px\); overflow-x: auto;/);
    assert.match(styles, /@media \(prefers-reduced-motion: reduce\) \{\n {2}\.selection-bar \{ animation: none; \}/);
  });
});

describe("collection pane actions", () => {
  it("labels the two everyday actions and folds the rest into a menu", async () => {
    const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");

    assert.match(workbench, /<FolderPlus size=\{14\} \/>新建文件夹/);
    assert.match(workbench, /<Archive size=\{14\} \/>归档抓包/);
    assert.match(workbench, /className="collection-pane-menu" role="menu"/);
    for (const label of ["集合公共配置", "同步 OpenAPI 规范", "重命名", "导出 ShowNet JSON", "导出 Postman"]) {
      assert.match(workbench, new RegExp(`\\/>${label}`), `${label} needs a visible label`);
    }
  });

  it("says what the destructive item actually does", async () => {
    // It used to be a bare trash can whose tooltip was the only thing telling
    // the user the requests survive.
    const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");
    assert.match(workbench, /"删除文件夹（保留请求）" : "删除集合（保留请求）"/);
    assert.match(workbench, /role="menuitem" className="is-danger"/);
  });

  it("dismisses the menu the way every other floating layer does", async () => {
    const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");
    assert.match(workbench, /useDismissibleLayer\(paneMenuOpen, paneMenuRef/);
  });

  it("keeps the square icon rule off the labelled buttons", async () => {
    // `.collection-pane-actions button` forced 28x28 on every descendant, which
    // crushed the labelled buttons and every row of their menu into one column.
    assert.match(styles, /\.collection-pane-actions > button:not\(\.collection-pane-action\) \{ display: grid; width: 28px;/);
    assert.doesNotMatch(styles, /\.collection-pane-actions button \{ display: grid; width: 28px;/);
    assert.match(styles, /\.collection-pane-action \{[^}]*flex: none;/s);
  });
});

describe("analysis mode naming", () => {
  it("names all five modes once", () => {
    assert.deepEqual(ANALYSIS_MODES.map((mode) => mode.id), ["auto", "api", "security", "performance", "crypto"]);
    for (const mode of ANALYSIS_MODES) {
      assert.ok(mode.label.length > 0, `${mode.id} needs a label`);
      assert.ok(mode.focus.length > 0, `${mode.id} needs a focus line`);
    }
  });

  it("resolves labels and focus text by id, falling back to the id", () => {
    assert.equal(analysisModeLabel("crypto"), "JS 加密逆向");
    assert.equal(analysisModeFocus("api"), "接口、参数、鉴权与调用链");
    // @ts-expect-error deliberately probing an unknown mode
    assert.equal(analysisModeLabel("nope"), "nope");
  });

  it("is the only place the analysis and skills views get mode names from", async () => {
    const [analysis, skills] = await Promise.all([
      readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/SkillsView.tsx", import.meta.url), "utf8"),
    ]);

    for (const [name, source] of [["AnalysisView", analysis], ["SkillsView", skills]] as const) {
      assert.match(source, /from "\.\.\/analysisModes"/, `${name} must import the shared list`);
    }

    // The duplicated literals that drifted apart must not come back.
    assert.doesNotMatch(skills, /自动场景分析/);
    assert.doesNotMatch(skills, /API 协议逆向/);
    for (const source of [analysis, skills]) {
      assert.doesNotMatch(source, /\{ id: "security", label: "安全审计"/);
    }
  });
});
