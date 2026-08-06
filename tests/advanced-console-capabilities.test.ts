/**
 * Drives the shipped advancedConsoleCapabilities module + Advanced Console UI
 * structure, and asserts agent tool names match capabilities.ts / agent_tools.rs.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  CAPABILITY_CATALOG,
  CONSOLE_TAB_GUIDES,
  WORKFLOW_STAGES,
  catalogAgentToolNames,
  capabilitiesForPhase,
  honestyBanner,
  suggestWorkflowStage,
  tabGuide,
} from "../src/advancedConsoleCapabilities.ts";

describe("advanced console capability map (shipped pure data)", () => {
  it("defines ordered capture → evidence → analysis → export workflow", () => {
    assert.deepEqual(
      WORKFLOW_STAGES.map((stage) => stage.id),
      ["capture", "evidence", "analysis", "export"],
    );
    for (const stage of WORKFLOW_STAGES) {
      assert.ok(stage.beginnerTip.length > 8);
      assert.ok(stage.summary.length > 8);
    }
  });

  it("gives every main tab whenToUse / bestPractice / nextStep guidance", () => {
    const required = [
      "overview",
      "capture",
      "hooks",
      "rules",
      "fingerprint",
      "px",
      "recaptcha",
      "config",
    ];
    for (const id of required) {
      const guide = tabGuide(id as Parameters<typeof tabGuide>[0]);
      assert.ok(guide.whenToUse.includes("时") || guide.whenToUse.length > 10, id);
      assert.ok(guide.bestPractice.length > 10, id);
      assert.ok(guide.nextStep.length > 8, id);
      assert.ok(guide.emptyHint.length > 6, id);
    }
    assert.equal(CONSOLE_TAB_GUIDES.length, required.length);
  });

  it("splits capture vs analysis capabilities with real entry points", () => {
    const capture = capabilitiesForPhase("capture");
    const analysis = capabilitiesForPhase("analysis");
    assert.ok(capture.some((c) => c.id === "outbound-tls-preset"));
    assert.ok(capture.some((c) => c.id === "px-capture-toggles"));
    assert.ok(analysis.some((c) => c.id === "agent-tls-read"));
    assert.ok(analysis.some((c) => c.id === "agent-px-read"));
    assert.ok(analysis.some((c) => c.id === "agent-outbound-status"));

    for (const entry of CAPABILITY_CATALOG) {
      assert.ok(entry.entryPoints.length > 0, entry.id);
      assert.ok(entry.when.length > 4, entry.id);
    }
  });

  it("suggests workflow stage from session stats", () => {
    assert.equal(suggestWorkflowStage({ requestCount: 0, hookCount: 0, fingerprintCount: 0, pxCount: 0 }), "capture");
    assert.equal(
      suggestWorkflowStage({ requestCount: 3, hookCount: 0, fingerprintCount: 0, pxCount: 0 }),
      "evidence",
    );
    assert.equal(
      suggestWorkflowStage({ requestCount: 3, hookCount: 1, fingerprintCount: 0, pxCount: 0 }),
      "analysis",
    );
    assert.equal(
      suggestWorkflowStage({
        requestCount: 3,
        hookCount: 1,
        fingerprintCount: 1,
        pxCount: 0,
        hasReport: true,
      }),
      "export",
    );
  });

  it("honesty banner rejects full JA3 and hard-break PX claims", () => {
    const banner = honestyBanner();
    assert.match(banner, /rustls|ja3Parity/i);
    assert.match(banner, /非无密钥硬破|结构解析/);
  });
});

describe("advanced console UI consumes capability map and codex tokens", () => {
  it("AdvancedConsoleView imports workflow stages and per-tab guides", async () => {
    const src = await readFile(
      new URL("../src/components/AdvancedConsoleView.tsx", import.meta.url),
      "utf8",
    );
    assert.match(src, /from ["']\.\.\/advancedConsoleCapabilities["']/);
    assert.match(src, /WORKFLOW_STAGES/);
    assert.match(src, /何时用/);
    assert.match(src, /最佳实践/);
    assert.match(src, /下一步/);
    assert.match(src, /抓包过程/);
    assert.match(src, /AI 分析过程/);
    assert.match(src, /onOpenAnalysis/);
    assert.match(src, /honestyBanner|ja3Parity/);
    assert.match(src, /get_tls_fingerprints/);
    assert.match(src, /list_px_evidence/);
    assert.match(src, /set_outbound_tls_profile/);
    // Compact layout: step strip titles only + tip line; long tips not inside step cards
    assert.match(src, /advanced-workflow-tip/);
    assert.match(src, /TAB_SHORT_LABEL/);
    assert.match(src, /advanced-panel-guide-more/);
    assert.doesNotMatch(src, /advanced-workflow-body/);
  });

  it("styles use codex accent tokens without isolated #5b6cff primary", async () => {
    const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    const consoleCssStart = css.indexOf("/* —— MITM Advanced Console");
    assert.ok(consoleCssStart >= 0);
    const slice = css.slice(consoleCssStart, consoleCssStart + 14_000);
    assert.match(slice, /--codex-accent/);
    assert.doesNotMatch(slice, /#5b6cff/);
    assert.doesNotMatch(slice, /#8ea2ff/);
    assert.match(slice, /\.advanced-mini-list \.linkish[^}]*var\(--codex-accent-ink\)/s);
    assert.match(slice, /\.advanced-workflow/);
    assert.match(slice, /\.advanced-empty/);
    assert.match(slice, /\.advanced-capability-columns/);
    // Layout contract: step strip single-row; tabs no-wrap scroll
    assert.match(slice, /\.advanced-workflow\s*\{[^}]*flex-wrap:\s*nowrap/s);
    assert.match(slice, /\.advanced-workflow-step\s*\{[^}]*max-height:\s*44px/s);
    assert.match(slice, /\.advanced-console-tabs\s*\{[^}]*flex-wrap:\s*nowrap/s);
    assert.match(slice, /\.advanced-console-tabs\s*\{[^}]*overflow-x:\s*auto/s);
    assert.doesNotMatch(slice, /grid-template-columns:\s*repeat\(4/);
    // brace balance of full stylesheet must not be left open/closed by Advanced Console edits
    const full = css;
    assert.equal(full.split("{").length, full.split("}").length, "styles.css brace imbalance");
  });

  it("App wires Advanced Console to analysis navigation", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.match(app, /onOpenAnalysis=\{\(\) => setActiveView\("analysis"\)\}/);
  });
});

describe("agent wiring: catalog tools exist in MCP preview and agent_tools", () => {
  it("catalog agent tools are registered in capabilities mcpToolPreview and agent_tools.rs", async () => {
    const [caps, agentTools, analysisView] = await Promise.all([
      readFile(new URL("../src/capabilities.ts", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/agent_tools.rs", import.meta.url), "utf8"),
      readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8"),
    ]);

    const required = [
      "shownet_get_tls_fingerprints",
      "shownet_get_outbound_tls_status",
      "shownet_list_px_evidence",
      "shownet_decode_px_payload",
    ];
    for (const name of required) {
      assert.ok(catalogAgentToolNames().includes(name), `catalog missing ${name}`);
      assert.ok(caps.includes(`"${name}"`) || caps.includes(`'${name}'`), `mcpToolPreview missing ${name}`);
      assert.ok(
        agentTools.includes(`"${name}"`),
        `agent_tools.rs must define ${name}`,
      );
      assert.match(
        agentTools,
        new RegExp(`"${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\s*=>`),
        `execute_read_tool must dispatch ${name}`,
      );
      assert.ok(analysisView.includes(name), `AnalysisView tool labels missing ${name}`);
    }

    // Honesty in tool descriptions
    assert.match(agentTools, /位级浏览器 JA3|不宣称|ja3Parity/);
    assert.match(agentTools, /非无密钥硬破|结构解码/);
  });

  it("crypto-reverse and dynamic-signature skills list TLS/PX analysis tools", async () => {
    const [caps, skills] = await Promise.all([
      readFile(new URL("../src/capabilities.ts", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/skills.rs", import.meta.url), "utf8"),
    ]);
    for (const name of [
      "shownet_get_outbound_tls_status",
      "shownet_list_px_evidence",
      "shownet_decode_px_payload",
    ]) {
      assert.ok(caps.includes(name));
      assert.ok(skills.includes(name));
    }
  });
});
