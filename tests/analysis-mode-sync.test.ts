/**
 * AI 分析 and Skill 编排 are two views onto the same pipeline. They used to
 * hold independent mode state, so picking 安全审计 in one left the other on
 * 自动识别 — and because AnalysisView unmounts on navigation, its selection
 * was lost every time the user left the view.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { ANALYSIS_MODES } from "../src/analysisModes.ts";

const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
const analysis = await readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8");
const skills = await readFile(new URL("../src/components/SkillsView.tsx", import.meta.url), "utf8");

describe("shared analysis mode", () => {
  it("lives in App, above both views", () => {
    assert.match(app, /const \[analysisMode, setAnalysisMode\] = useState<AnalysisMode>\("auto"\)/);
    // Inline JSX carries arrow functions, so slice each element rather than
    // trying to match across it.
    const analysisTag = app.slice(app.indexOf("<AnalysisView"), app.indexOf("<AnalysisView") + 1400);
    const skillsTag = app.slice(app.indexOf("<SkillsView"), app.indexOf("<SkillsView") + 400);
    for (const [name, tag] of [["AnalysisView", analysisTag], ["SkillsView", skillsTag]] as const) {
      assert.match(tag, /mode=\{analysisMode\}/, `${name} must read the shared mode`);
      assert.match(tag, /onModeChange=\{chooseAnalysisMode\}/, `${name} must write it back`);
    }
  });

  it("leaves neither view holding its own copy", () => {
    assert.doesNotMatch(analysis, /useState<AnalysisMode>\("auto"\)/);
    assert.doesNotMatch(skills, /useState<AnalysisMode>\("auto"\)/);
    assert.match(analysis, /mode: AnalysisMode;\n {2}onModeChange: \(mode: AnalysisMode\) => void;/);
    assert.match(skills, /mode: AnalysisMode;\n {2}onModeChange: \(mode: AnalysisMode\) => void;/);
  });

  it("seeds the skills preview plan from the shared mode, not a literal", () => {
    // It used to build the preview plan for "auto" regardless of the selection.
    assert.match(skills, /buildPreviewSkillPlan\(workflowMode, requests\)/);
    assert.doesNotMatch(skills, /buildPreviewSkillPlan\("auto", requests\)/);
  });

  it("still offers all five modes in both views", () => {
    assert.equal(ANALYSIS_MODES.length, 5);
    // Icons moved into the shared list as well, so neither view maps over it
    // to graft its own glyphs on any more.
    assert.match(analysis, /const modes = ANALYSIS_MODES;/);
    assert.match(skills, /ANALYSIS_MODES\.map\(\(entry\) => \(\{ mode: entry\.id, name: entry\.label, icon: entry\.icon \}\)\)/);
    for (const mode of ANALYSIS_MODES) assert.ok(mode.icon, `${mode.id} needs one shared icon`);
  });
});

describe("restoring a report defers to a chosen mode", () => {
  // The behaviour is covered by tests/render/analysis-mode.test.tsx. These only
  // pin the rule that tells a default apart from a deliberate choice.
  it("tracks whether the user has actually picked a mode", () => {
    assert.match(app, /const \[analysisModePinned, setAnalysisModePinned\] = useState\(false\)/);
    assert.match(app, /setAnalysisModePinned\(true\)/);
    assert.match(app, /modePinned=\{analysisModePinned\}/);
  });

  it("lets a restored report set the mode only while none is pinned", () => {
    assert.match(analysis, /modePinned: boolean;/);
    assert.match(analysis, /await restoreReport\(latest, \(\) => disposed, !modePinned\)/);
    assert.match(analysis, /if \(!modePinned\) setMode\(latest\.mode\)/);
  });
});

describe("report header describes the report, not the picker", () => {
  it("titles the report with the mode that produced it", () => {
    // The title tracked the mode picker. That was invisible while mount forced
    // the two into agreement, and became a lie once it no longer did.
    assert.match(analysis, /<h2>\{modeLabel\(report\?\.mode \?\? mode\)\}报告<\/h2>/);
    assert.doesNotMatch(analysis, /<h2>\{selectedMode\.label\}报告<\/h2>/);
  });

  it("hides the skill count when the plan is for a different mode", () => {
    // The plan is fetched for the picker mode; showing its skill count next to
    // another mode's report would attribute the wrong number to that report.
    assert.match(analysis, /const planDescribesReport = !report \|\| report\.mode === mode;/);
    assert.match(analysis, /\{planDescribesReport && skillPlan \?/);
  });
});
