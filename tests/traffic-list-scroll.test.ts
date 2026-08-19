import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { emptyQuickFilter } from "../src/requestFilters.ts";
import {
  nextScrollTopToRevealRow,
  shouldKeepFocusedRowInView,
  shouldResetTrafficListScroll,
  trafficListFilterKey,
  trafficListSortKey,
} from "../src/trafficListScroll.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const sameQuery = {
  sessionId: "session-live",
  filterKey: trafficListFilterKey(emptyQuickFilter, undefined),
  sortKey: trafficListSortKey([{ field: "order", direction: "asc" }]),
};

describe("traffic list scroll reset policy", () => {
  it("keeps a scrolled-away list still when only new rows arrive", () => {
    assert.equal(shouldResetTrafficListScroll(sameQuery, { ...sameQuery }), false);
    assert.equal(shouldKeepFocusedRowInView("row-1", "row-1"), false);
    // The pin math the pre-fix effect applied on every requests[] identity
    // change: auto-selected first row (rowTop === header) + any scrollTop > 0
    // writes the scroller back to 0. The policy above must refuse to apply it.
    assert.equal(nextScrollTopToRevealRow({
      scrollTop: 400,
      clientHeight: 500,
      rowTop: 32,
      rowHeight: 38,
      headerHeight: 32,
    }), 0);
  });

  it("still resets when the session, filter or sort identity changes", () => {
    assert.equal(shouldResetTrafficListScroll(undefined, sameQuery), false);
    assert.equal(
      shouldResetTrafficListScroll(sameQuery, { ...sameQuery, sessionId: "session-other" }),
      true,
    );
    assert.equal(
      shouldResetTrafficListScroll(sameQuery, {
        ...sameQuery,
        filterKey: trafficListFilterKey({ ...emptyQuickFilter, methods: ["POST"] }, undefined),
      }),
      true,
    );
    assert.equal(
      shouldResetTrafficListScroll(sameQuery, {
        ...sameQuery,
        sortKey: trafficListSortKey([{ field: "startedAt", direction: "desc" }]),
      }),
      true,
    );
  });

  it("follows a row only when the focused id itself changes", () => {
    assert.equal(shouldKeepFocusedRowInView(undefined, "row-1"), true);
    assert.equal(shouldKeepFocusedRowInView("row-1", "row-20"), true);
    assert.equal(shouldKeepFocusedRowInView("row-20", undefined), false);
    assert.equal(
      nextScrollTopToRevealRow({
        scrollTop: 400,
        clientHeight: 500,
        rowTop: 32 + 25 * 38,
        rowHeight: 38,
        headerHeight: 32,
      }),
      32 + 26 * 38 - 500,
    );
  });
});

describe("traffic list scroll is wired through the shipped view", () => {
  it("gates DOM scrollTop writes on the policy, not on every requests identity", () => {
    const traffic = readFileSync(join(root, "src/components/TrafficView.tsx"), "utf8");
    const app = readFileSync(join(root, "src/App.tsx"), "utf8");
    assert.match(traffic, /shouldResetTrafficListScroll\(previous, queryIdentity\)/);
    assert.match(traffic, /shouldKeepFocusedRowInView\(revealedFocusedIdRef\.current, nextFocusedId\)/);
    assert.match(traffic, /nextScrollTopToRevealRow\(/);
    assert.doesNotMatch(
      traffic,
      /if \(rowTop < element\.scrollTop \+ 32\) element\.scrollTop = Math\.max\(0, rowTop - 32\)/,
    );
    assert.match(app, /key=\{activeSession\.id\}/);
    assert.match(app, /refreshRequests\(activeSessionId, \{ resetWindow: false \}\)/);
    assert.match(
      app,
      /refreshRequests\(activeSessionId\)\.catch[\s\S]{0,120}\}, \[activeSessionId, refreshRequests\]\);/,
    );
  });
});
