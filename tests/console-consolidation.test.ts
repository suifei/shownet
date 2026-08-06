/**
 * Covers the second pass of grouping work: three PX tabs that rendered one
 * body merged into one, controls that existed twice for one value removed,
 * dead affordances made real, and time-critical state surfaced where it can
 * actually be seen.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { CONSOLE_TAB_GUIDES, tabGuide, type ConsoleTabId } from "../src/advancedConsoleCapabilities.ts";

const console_ = await readFile(new URL("../src/components/AdvancedConsoleView.tsx", import.meta.url), "utf8");
const skills = await readFile(new URL("../src/components/SkillsView.tsx", import.meta.url), "utf8");
const workbench = await readFile(new URL("../src/components/RequestWorkbench.tsx", import.meta.url), "utf8");
const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

describe("advanced console PX consolidation", () => {
  it("has one PX tab instead of three", () => {
    const ids = CONSOLE_TAB_GUIDES.map((entry) => entry.id);
    assert.ok(ids.includes("px" as ConsoleTabId));
    for (const gone of ["px-replay", "px-compare", "px-tamper"]) {
      assert.ok(!ids.includes(gone as ConsoleTabId), `${gone} must be merged away`);
    }
    assert.equal(CONSOLE_TAB_GUIDES.length, 8, "the console is down to eight tabs");
  });

  it("keeps full guidance on the merged tab", () => {
    const guide = tabGuide("px");
    assert.ok(guide.whenToUse.length > 10);
    assert.ok(guide.bestPractice.length > 10);
    assert.ok(guide.nextStep.length > 8);
    // The three old empty hints said different things; the merged one has to
    // still explain the compare-needs-two case.
    assert.match(guide.emptyHint, /两条/);
    assert.match(guide.bestPractice, /不是无密钥硬破|非无密钥硬破/);
  });

  it("turns the three tabs into modes over one evidence list", () => {
    assert.match(console_, /const PX_MODES = \[/);
    assert.match(console_, /className="px-mode-switch" role="tablist"/);
    assert.match(console_, /pxMode === "compare"/);
    assert.match(console_, /pxMode === "tamper"/);
    assert.doesNotMatch(console_, /tab === "px-replay"/);
    assert.match(styles, /\.px-mode-switch \{/);
  });

  it("gives every PX mode a hint explaining what it does", () => {
    const block = console_.slice(console_.indexOf("const PX_MODES"), console_.indexOf("type PxMode"));
    for (const label of ["解码", "对比", "改写"]) {
      assert.ok(block.includes(label), `PX mode ${label} is missing`);
    }
    assert.equal((block.match(/hint:/g) ?? []).length, 3);
  });

  it("tells the user when an A/B comparison is still incomplete", () => {
    assert.match(console_, /标记 A 和 B 两条请求后再做字段 diff/);
  });

  it("shows one control for the outbound TLS preset, not two", () => {
    // A select and a chip row both drove setTlsProfile, so the page rendered
    // one setting twice and the two could disagree while loading.
    assert.doesNotMatch(console_, /className="chip-row"/);
    assert.match(console_, /onChange=\{\(e\) => void setTlsProfile\(e\.target\.value\)\}/);
  });

  it("renders the rules tab empty hint like every other tab", () => {
    const rules = console_.slice(console_.indexOf('{tab === "rules" &&'), console_.indexOf('{tab === "fingerprint" &&'));
    assert.match(rules, /className="advanced-empty">\{guide\.emptyHint\}/);
  });

  it("requires the analysis callback so workflow steps 3 and 4 always land", () => {
    assert.match(console_, /onOpenAnalysis: \(\) => void;/);
    assert.doesNotMatch(console_, /onOpenAnalysis\?: \(\) => void;/);
    assert.doesNotMatch(console_, /\{onOpenAnalysis \? \(/);
    assert.match(console_, /if \(phase === "analysis" \|\| phase === "export"\)/);
  });
});

describe("skills view honesty and reachability", () => {
  it("shows errors on every tab, not only the MCP one", () => {
    // Skills-tab adapter failures and workflow-plan failures both set `error`.
    const tabsStart = skills.indexOf('className="capabilities-tabs"');
    const firstTab = skills.indexOf('{tab === "skills" &&');
    const betweenTabsAndBody = skills.slice(tabsStart, firstTab);
    assert.match(betweenTabsAndBody, /\{error && <div className="capability-error">\{error\}<\/div>\}/);
    assert.equal((skills.match(/className="capability-error"/g) ?? []).length, 1, "one banner, outside the tabs");
  });

  it("stops reporting a resource count the backend never sends", () => {
    assert.doesNotMatch(skills, /<strong>3<\/strong><span>Resources<\/span>/);
    assert.match(skills, /allowWrites \? "读写" : "只读"\}<\/strong><span>Access<\/span>/);
  });

  it("makes the external MCP row lead somewhere", () => {
    // It used to render a permanent 未配置 chip with no action attached.
    assert.match(skills, /onClick=\{onOpenMcpSettings\}/);
    assert.match(skills, /onOpenMcpSettings: \(\) => void;/);
    assert.match(app, /onOpenMcpSettings=\{\(\) => openSettingsTab\("mcp"\)\}/);
    assert.match(styles, /\.connection-item\.is-actionable/);
  });
});

describe("request workbench reachability", () => {
  it("surfaces the pending breakpoint count outside the rules tab", () => {
    // Breakpoint tasks expire on a timer, so the count cannot be visible only
    // to someone already standing on 规则.
    assert.match(workbench, /breakpointCount: number;/);
    assert.match(workbench, /tab\.id === "rules" && breakpointCount > 0/);
    assert.match(workbench, /className="request-workbench__nav-badge"/);
    assert.match(app, /breakpointCount=\{breakpointQueue\.tasks\.length\}/);
    assert.match(styles, /\.request-workbench__nav-badge \{/);
  });

  it("keeps cURL import reachable once a draft is open", () => {
    // The import textarea only existed on the empty lab screen.
    assert.match(workbench, /className="lab-curl-menu"/);
    assert.match(workbench, /title="cURL 导入与导出"/);
    const menu = workbench.slice(workbench.indexOf('className="lab-curl-menu"'), workbench.indexOf('title="保存草稿"'));
    assert.match(menu, /copyCurl\(\)/, "export sits next to import");
    assert.match(menu, /importCurl\(\)/);
    assert.match(menu, /导入会覆盖当前草稿/, "the overwrite has to be stated");
    assert.match(workbench, /useDismissibleLayer\(curlMenuOpen, curlMenuRef/);
  });
});
