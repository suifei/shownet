import { serializeFilterExpression, type QuickFilterState } from "./requestFilters.ts";
import type { FilterExpression, RequestSort } from "./types.ts";

export interface TrafficListQueryIdentity {
  sessionId: string;
  filterKey: string;
  sortKey: string;
}

export function trafficListFilterKey(
  quickFilter: QuickFilterState,
  advancedFilter: FilterExpression | undefined,
) {
  return JSON.stringify({
    quick: quickFilter,
    advanced: serializeFilterExpression(advancedFilter),
  });
}

export function trafficListSortKey(sort: RequestSort[]) {
  return JSON.stringify(sort);
}

/** Session / filter / sort changes reset the list; new rows must not. */
export function shouldResetTrafficListScroll(
  previous: TrafficListQueryIdentity | undefined,
  next: TrafficListQueryIdentity,
) {
  if (!previous) return false;
  return previous.sessionId !== next.sessionId
    || previous.filterKey !== next.filterKey
    || previous.sortKey !== next.sortKey;
}

/** Follow a row only when the focused id itself changes (click / keyboard / locate). */
export function shouldKeepFocusedRowInView(
  previousFocusedId: string | undefined,
  nextFocusedId: string | undefined,
) {
  return Boolean(nextFocusedId) && previousFocusedId !== nextFocusedId;
}

/**
 * Scroll adjustment that keeps one row in the viewport. The old pin applied
 * this on every `requests` identity change, which yanked a scrolled-away list
 * back to the auto-selected first row (`rowTop === headerHeight` → 0).
 */
export function nextScrollTopToRevealRow(input: {
  scrollTop: number;
  clientHeight: number;
  rowTop: number;
  rowHeight: number;
  headerHeight: number;
}) {
  const { scrollTop, clientHeight, rowTop, rowHeight, headerHeight } = input;
  const rowBottom = rowTop + rowHeight;
  if (rowTop < scrollTop + headerHeight) return Math.max(0, rowTop - headerHeight);
  if (rowBottom > scrollTop + clientHeight) return Math.max(0, rowBottom - clientHeight);
  return undefined;
}
