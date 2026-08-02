import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { estimateAnalysisScope, formatContextSize } from "../src/analysisScope.ts";
import { buildPreviewSkillPlan, builtInSkillPreview, mcpToolPreview } from "../src/capabilities.ts";
import type { RequestListItem } from "../src/types.ts";

function request(index: number, overrides: Partial<RequestListItem> = {}): RequestListItem {
  return {
    id: `request-${index}`, order: index, startedAt: index, state: "complete", method: "GET",
    scheme: "https", host: "api.example.test", path: `/v1/${index}`, status: 200, type: "image",
    source: "browser", sourceInstanceId: "browser-1", protocol: "h2", sizeBytes: 1024,
    risk: "none", hasHook: false, cryptoSnippetCount: 0, tlsIntercepted: true, ...overrides,
  };
}

describe("analysis scope estimate", () => {
  it("matches the initial backend scope rules and caps selected requests", () => {
    const requests = Array.from({ length: 150 }, (_, index) => request(index, index % 10 === 0
      ? { type: "xhr", method: "POST", hasHook: true, cryptoSnippetCount: 1 }
      : {}));
    const automatic = estimateAnalysisScope(requests, {
      mode: "api", includeStatic: false, manualScope: false, manualRequestIds: [], includeAnnotations: false,
    });
    assert.equal(automatic.requestCount, 15);
    assert.equal(automatic.hookCount, 15);
    assert.equal(automatic.codeCount, 15);
    const all = estimateAnalysisScope(requests, {
      mode: "performance", includeStatic: false, manualScope: false, manualRequestIds: [], includeAnnotations: false,
    });
    assert.equal(all.requestCount, 120);
  });

  it("uses explicit manual ids and only counts annotations when enabled", () => {
    const requests = [request(1, { annotation: { bookmarked: true, struckThrough: false, tags: ["reviewed"] } }), request(2)];
    const estimate = estimateAnalysisScope(requests, {
      mode: "auto", includeStatic: false, manualScope: true, manualRequestIds: ["request-1"], includeAnnotations: true,
    });
    assert.equal(estimate.requestCount, 1);
    assert.equal(estimate.annotationCount, 1);
    assert.match(formatContextSize(estimate.estimatedBytes), /KiB/);
  });
});

describe("real-time protocol capability", () => {
  it("enables the same evidence skill for SSE and exposes its complete read tool", () => {
    const plan = buildPreviewSkillPlan("auto", [request(1, { type: "sse", path: "/events" })]);
    const skill = builtInSkillPreview.find((entry) => entry.id === "realtime-protocol");

    assert.ok(skill);
    assert.equal(skill.version, "1.1.0");
    assert.ok(plan.selectedSkillIds.includes("realtime-protocol"));
    assert.ok(plan.toolNames.includes("shownet_get_sse_events"));
    assert.ok(plan.reasons.some((reason) => reason.includes("SSE")));
    assert.ok(mcpToolPreview.some((tool) => tool.name === "shownet_get_sse_events" && tool.access === "read"));
  });
});

describe("advisory analysis graph preview", () => {
  it("describes tools as suggestions and carries no approval gate", () => {
    const plan = buildPreviewSkillPlan("api", [request(1, { type: "xhr", method: "POST" })]);
    const apiStage = plan.stages.find((stage) => stage.skillId === "api-reverse");

    assert.ok(apiStage);
    assert.ok(apiStage.suggestedToolCount > 0);
    assert.equal("approvalPolicy" in apiStage, false);
    assert.equal("allowedToolCount" in apiStage, false);
    assert.deepEqual(plan.stages.slice(-2).map((stage) => stage.id), ["quality-gate", "report"]);
  });
});
