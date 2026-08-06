/**
 * Filters used to be settable from five independent surfaces that all wrote
 * into one query, with no combined read-out — a list narrowed from three of
 * them looked exactly like an empty session.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  countActiveFilters,
  describeActiveFilters,
  emptyQuickFilter,
  METHOD_VALUES,
  PROTOCOL_LABELS,
  removeActiveFilter,
  RISK_LABELS,
  SHOWNET_LABELS,
  STATUS_LABELS,
  TYPE_LABELS,
  type QuickFilterState,
} from "../src/requestFilters.ts";
import type { FilterExpression } from "../src/types.ts";

const traffic = await readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8");
const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

const sourceLabels = { browser: "浏览器", mobile: "移动设备" };

function state(patch: Partial<QuickFilterState> = {}): QuickFilterState {
  return { ...emptyQuickFilter, ...patch };
}

describe("active filter description", () => {
  it("says nothing when nothing is filtering", () => {
    assert.deepEqual(describeActiveFilters(state(), undefined), []);
    assert.equal(countActiveFilters(state(), undefined), 0);
  });

  it("reports criteria set from different surfaces as one list", () => {
    // Search box + method chips + facet sidebar, the three real entry points.
    const chips = describeActiveFilters(
      state({ text: "auth", methods: ["POST"], sources: ["browser"] }),
      undefined,
      sourceLabels,
    );
    assert.deepEqual(chips.map((chip) => chip.group), ["text", "methods", "sources"]);
    assert.deepEqual(chips.map((chip) => chip.label), ["auth", "POST", "浏览器"]);
    assert.deepEqual(chips.map((chip) => chip.groupLabel), ["搜索", "方法", "来源"]);
  });

  it("ignores whitespace-only search text", () => {
    assert.deepEqual(describeActiveFilters(state({ text: "   " }), undefined), []);
  });

  it("maps raw values to the labels the UI shows", () => {
    const chips = describeActiveFilters(
      state({ protocols: ["h2"], types: ["api"], statuses: ["tunnel"], shownet: ["hook"], risks: ["critical"] }),
      undefined,
    );
    const labels = chips.map((chip) => chip.label);
    assert.ok(labels.includes(PROTOCOL_LABELS.h2), "protocol must read HTTP/2, not h2");
    assert.ok(labels.includes(TYPE_LABELS.api));
    assert.ok(labels.includes(STATUS_LABELS.tunnel));
    assert.ok(labels.includes(SHOWNET_LABELS.hook));
    assert.ok(labels.includes(RISK_LABELS.critical));
  });

  it("falls back to the raw value for an unknown source", () => {
    const chip = describeActiveFilters(state({ sources: ["iot"] }), undefined, sourceLabels)[0];
    assert.equal(chip.label, "iot");
  });

  it("collapses the condition builder into one chip counting its predicates", () => {
    const advanced: FilterExpression = {
      kind: "group",
      operator: "and",
      children: [
        { kind: "predicate", field: "url", operator: "contains", value: "a" },
        { kind: "group", operator: "or", children: [
          { kind: "predicate", field: "host", operator: "equals", value: "b" },
          { kind: "predicate", field: "path", operator: "contains", value: "c" },
        ] },
      ],
    };
    const chips = describeActiveFilters(state(), advanced);
    assert.equal(chips.length, 1);
    assert.equal(chips[0].group, "advanced");
    assert.equal(chips[0].label, "3 个条件");
  });

  it("gives every chip a unique key", () => {
    const chips = describeActiveFilters(
      state({ text: "x", methods: ["GET", "POST"], hosts: ["a.com", "b.com"] }),
      undefined,
    );
    assert.equal(new Set(chips.map((chip) => chip.id)).size, chips.length);
  });

  it("removes exactly the criterion a chip stands for", () => {
    const current = state({ methods: ["GET", "POST"], sources: ["browser"] });
    const chip = describeActiveFilters(current, undefined, sourceLabels).find((entry) => entry.label === "GET");
    assert.ok(chip);
    const next = removeActiveFilter(current, chip);
    assert.deepEqual(next.methods, ["POST"], "the sibling method must survive");
    assert.deepEqual(next.sources, ["browser"], "other groups must be untouched");
  });

  it("clears the search text through its own chip", () => {
    const next = removeActiveFilter(state({ text: "auth", methods: ["GET"] }), {
      id: "text", group: "text", groupLabel: "搜索", label: "auth",
    });
    assert.equal(next.text, "");
    assert.deepEqual(next.methods, ["GET"]);
  });

  it("leaves quick state alone for the advanced chip, which the caller owns", () => {
    const current = state({ methods: ["GET"] });
    const next = removeActiveFilter(current, { id: "advanced", group: "advanced", groupLabel: "自定义条件", label: "1 个条件" });
    assert.deepEqual(next, current);
  });

  it("counts the advanced expression alongside the quick criteria", () => {
    const advanced: FilterExpression = { kind: "predicate", field: "url", operator: "contains", value: "x" };
    assert.equal(countActiveFilters(state({ text: "a", methods: ["GET"] }), advanced), 3);
  });
});

describe("traffic filter surface", () => {
  it("has one filter button instead of three", () => {
    assert.match(traffic, /className="traffic-popover filter-panel"/);
    assert.match(traffic, /role="tablist" aria-label="筛选方式"/);
    // The three former sibling popovers are gone as separate toolbar entries.
    assert.doesNotMatch(traffic, /menu === "quick" \? undefined : "quick"/);
    assert.doesNotMatch(traffic, /menu === "advanced" \? undefined : "advanced"/);
    assert.doesNotMatch(traffic, /menu === "views" \? undefined : "views"/);
    assert.match(traffic, /menu === "filter" \? undefined : "filter"/);
  });

  it("narrows the popover slot to the menus that are still separate", () => {
    assert.match(traffic, /type TrafficMenu = "filter" \| "columns" \| "live";/);
  });

  it("shows the combined filter state as removable chips", () => {
    assert.match(traffic, /className="active-filters" role="region" aria-label="生效中的筛选"/);
    assert.match(traffic, /className="active-filter-chip"/);
    assert.match(traffic, /onClick=\{\(\) => removeFilterChip\(chip\)\}/);
    assert.match(traffic, /className="active-filters__clear"/);
    assert.match(styles, /\.active-filter-chip \{/);
  });

  it("keeps reset always reachable rather than appearing with state", () => {
    // The toolbar reset button only existed while a filter was set, so the
    // control vanished exactly when a user went looking for it again.
    assert.match(traffic, /className="filter-panel__footer"/);
    assert.match(traffic, /onClick=\{clearFilters\} disabled=\{!activeFilterChips\.length\}/);
    assert.doesNotMatch(traffic, /\{\(query \|\| hasQuickFilters\(quickFilter\) \|\| advancedFilter\) && \(\s*\n\s*<button className="toolbar-icon-button" onClick=\{clearFilters\}/);
  });

  it("badges the filter button with how many criteria are active", () => {
    assert.match(traffic, /className="toolbar-filter-count"/);
    assert.match(styles, /\.toolbar-filter-count \{/);
  });

  it("shares one set of option labels between the panel and the facet sidebar", () => {
    assert.match(traffic, /labels=\{PROTOCOL_LABELS\}/);
    assert.match(traffic, /labels=\{TYPE_LABELS\}/);
    assert.match(traffic, /labels=\{RISK_LABELS\}/);
    assert.match(traffic, /values=\{METHOD_VALUES\}/);
    // The inline duplicates that could drift apart must not come back.
    assert.doesNotMatch(traffic, /labels=\{\{ "http\/1\.1": "HTTP\/1\.1", h2: "HTTP\/2", ws: "WebSocket" \}\}/);
    // HEAD joined the observable set; a captured HEAD request had no valid type.
    assert.equal(METHOD_VALUES.length, 8, "the panel offers every observable method");
    assert.ok(METHOD_VALUES.includes("HEAD"));
    assert.ok(METHOD_VALUES.includes("CONNECT"));
  });

  it("drops the styles of the popovers it replaced", () => {
    assert.doesNotMatch(styles, /\.filter-builder-popover/);
    assert.doesNotMatch(styles, /\.saved-views-popover/);
  });
});
