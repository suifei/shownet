import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { TrafficView } from "../../src/components/TrafficView";
import { initialRequestListItems } from "../../src/data";
import type { LiveCaptureDisplaySnapshot, RequestFacets, RequestListItem } from "../../src/types";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

const emptyFacets: RequestFacets = {
  hosts: [],
  methods: [],
  sources: [],
  protocols: [],
  statuses: [],
  types: [],
  risks: [],
};

const idleLiveDisplay: LiveCaptureDisplaySnapshot = {
  paused: false,
  syncing: false,
  pendingCreated: 0,
  pendingUpdated: 0,
  pendingChanges: 0,
  ratePerSecond: 0,
  peakRatePerSecond: 0,
  autoProtection: true,
  rateThreshold: 120,
};

function manyItems(count: number): RequestListItem[] {
  return Array.from({ length: count }, (_, index) => {
    const seed = initialRequestListItems[index % initialRequestListItems.length];
    return { ...seed, id: `row-${index + 1}`, order: index + 1 };
  });
}

function scroller() {
  const element = document.querySelector(".request-grid-scroll");
  if (!(element instanceof HTMLElement)) throw new Error("missing request-grid-scroll");
  Object.defineProperty(element, "clientHeight", { configurable: true, value: 500 });
  return element;
}

function scrollAway(top: number) {
  const element = scroller();
  act(() => {
    element.scrollTop = top;
    element.dispatchEvent(new Event("scroll", { bubbles: true }));
  });
  return element;
}

function renderTraffic(items: RequestListItem[], sessionId = "session-live") {
  return render(
    <TrafficView
      requests={items}
      totalCount={items.length}
      filteredCount={items.length}
      hookCount={0}
      bookmarkedCount={0}
      requestWindowOffset={0}
      facets={emptyFacets}
      loading={false}
      cancelling={false}
      capturing={true}
      captureElsewhere={false}
      liveDisplay={idleLiveDisplay}
      sessionId={sessionId}
      onQueryChange={vi.fn()}
      onRequestWindowChange={vi.fn()}
      onCancelRequestQuery={vi.fn()}
      onOpenAnalysis={vi.fn()}
      onAnalyzeSelection={vi.fn()}
      onOpenWorkbench={vi.fn()}
      onToggleLiveDisplay={vi.fn()}
      onLiveDisplayAutoProtectionChange={vi.fn()}
      onConnect={vi.fn()}
    />,
  );
}

describe("live traffic list scroll", () => {
  beforeEach(() => {
    Object.defineProperty(HTMLElement.prototype, "clientHeight", {
      configurable: true,
      get() {
        return this.classList?.contains("request-grid-scroll") ? 500 : 0;
      },
    });
  });

  afterEach(() => {
    delete (HTMLElement.prototype as { clientHeight?: number }).clientHeight;
  });

  it("does not jump to the top when new rows arrive after the user has scrolled away", () => {
    const first = manyItems(80);
    const view = renderTraffic(first);
    expect(document.querySelector(".request-grid-row.is-focused")).toHaveAttribute("data-request-id", "row-1");

    const element = scrollAway(400);
    expect(element.scrollTop).toBe(400);

    view.rerender(
      <TrafficView
        requests={[...first, { ...first[0], id: "row-81", order: 81 }]}
        totalCount={81}
        filteredCount={81}
        hookCount={0}
        bookmarkedCount={0}
        requestWindowOffset={0}
        facets={emptyFacets}
        loading={false}
        cancelling={false}
        capturing={true}
        captureElsewhere={false}
        liveDisplay={idleLiveDisplay}
        sessionId="session-live"
        onQueryChange={vi.fn()}
        onRequestWindowChange={vi.fn()}
        onCancelRequestQuery={vi.fn()}
        onOpenAnalysis={vi.fn()}
        onAnalyzeSelection={vi.fn()}
        onOpenWorkbench={vi.fn()}
        onToggleLiveDisplay={vi.fn()}
        onLiveDisplayAutoProtectionChange={vi.fn()}
        onConnect={vi.fn()}
      />,
    );

    expect(scroller().scrollTop).toBe(400);
    const firstBodyRow = document.querySelector(".request-grid-row:not(.is-loading)");
    expect(firstBodyRow).not.toHaveAttribute("data-request-id", "row-1");
  });

  it("still resets scroll when the session or sort changes", async () => {
    const items = manyItems(80);
    const view = renderTraffic(items);
    scrollAway(400);
    expect(scroller().scrollTop).toBe(400);

    view.rerender(
      <TrafficView
        requests={items}
        totalCount={items.length}
        filteredCount={items.length}
        hookCount={0}
        bookmarkedCount={0}
        requestWindowOffset={0}
        facets={emptyFacets}
        loading={false}
        cancelling={false}
        capturing={true}
        captureElsewhere={false}
        liveDisplay={idleLiveDisplay}
        sessionId="session-other"
        onQueryChange={vi.fn()}
        onRequestWindowChange={vi.fn()}
        onCancelRequestQuery={vi.fn()}
        onOpenAnalysis={vi.fn()}
        onAnalyzeSelection={vi.fn()}
        onOpenWorkbench={vi.fn()}
        onToggleLiveDisplay={vi.fn()}
        onLiveDisplayAutoProtectionChange={vi.fn()}
        onConnect={vi.fn()}
      />,
    );
    expect(scroller().scrollTop).toBe(0);

    scrollAway(400);
    await userEvent.click(screen.getByRole("button", { name: /状态码/ }));
    expect(scroller().scrollTop).toBe(0);
  });

  it("still brings a newly focused row into view", async () => {
    renderTraffic(manyItems(80));
    scrollAway(400);
    const rows = [...document.querySelectorAll(".request-grid-row")].filter((node) => !node.classList.contains("is-loading"));
    const far = rows[rows.length - 1] as HTMLElement;
    await userEvent.click(far);
    expect(scroller().scrollTop).toBeGreaterThan(400);
    expect(scroller().scrollTop).not.toBe(0);
  });
});
