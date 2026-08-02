import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  calculateWorkflowLayout,
  partitionWorkflowStages,
  WORKFLOW_EDGE_WIDTH,
  WORKFLOW_NODE_WIDTH,
} from "../src/workflowLayout.ts";

describe("workflow layout", () => {
  it("wraps a long plan into a compact layered graph", () => {
    const layout = calculateWorkflowLayout(9, 1120, 640);

    assert.ok(layout.columns < 9);
    assert.equal(layout.rows, Math.ceil(9 / layout.columns));
    assert.ok(layout.graphWidth <= 1120 - 40);
    assert.equal(
      layout.graphWidth,
      layout.columns * WORKFLOW_NODE_WIDTH + (layout.columns - 1) * WORKFLOW_EDGE_WIDTH,
    );
  });

  it("keeps short plans on one row when they fit", () => {
    const layout = calculateWorkflowLayout(4, 900, 500);

    assert.equal(layout.columns, 4);
    assert.equal(layout.rows, 1);
  });

  it("never returns a graph wider than a narrow flow viewport", () => {
    const layout = calculateWorkflowLayout(8, 340, 620);

    assert.ok(layout.columns <= 2);
    assert.ok(layout.graphWidth <= 340 - 40);
  });

  it("partitions stages without changing execution order", () => {
    const stages = ["filter", "api", "security", "performance", "crypto", "report"];

    assert.deepEqual(partitionWorkflowStages(stages, 3), [
      ["filter", "api", "security"],
      ["performance", "crypto", "report"],
    ]);
  });

  it("centers vertical turn arrows between workflow rows", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    const turnRule = styles.match(/\.workflow-turn > svg \{([^}]+)\}/)?.[1] ?? "";

    assert.match(turnRule, /top:\s*50%/);
    assert.match(turnRule, /transform:\s*translateY\(-50%\)/);
    assert.doesNotMatch(turnRule, /bottom:/);
  });
});
