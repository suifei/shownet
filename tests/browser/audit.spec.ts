import { expect, test } from "@playwright/test";

import { findCrushedText, findHorizontalOverflow, findOffscreenLayers, gotoApp } from "./helpers";
import { STATES } from "./states";

/**
 * A sweep over every reachable UI state.
 *
 * Individual specs check one thing well; this checks that no state anywhere
 * violates the layout invariants — including the ones that only exist behind a
 * right-click, a second click inside a popover, or a scroll.
 *
 * Not serial: a failure in one state must not hide the others.
 */

for (const state of STATES) {
  test(`[${state.area}] ${state.id}`, async ({ page }, testInfo) => {
    const width = page.viewportSize()?.width ?? 0;
    test.skip(Boolean(state.minWidth) && width < state.minWidth!, "该状态在此宽度下不存在");
    await gotoApp(page);
    const reached = await state.enter(page);
    test.skip(reached === false, "该状态在当前布局下不可达");

    await page.screenshot({ path: `test-results/audit/${testInfo.project.name}/${state.id}.png` });

    const crushed = await findCrushedText(page);
    const overflow = await findHorizontalOverflow(page);
    const offscreen = await findOffscreenLayers(page);

    expect(crushed, `${state.id}: 文字被挤压`).toEqual([]);
    expect(overflow.offenders, `${state.id}: 元素越出窗口`).toEqual([]);
    expect(overflow.pageScrollWidth, `${state.id}: 页面出现水平滚动`).toBeLessThanOrEqual(overflow.pageClientWidth + 1);
    expect(offscreen, `${state.id}: 浮层越界`).toEqual([]);
  });
}
