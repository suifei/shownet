import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axe from "axe-core";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

const goTo = (label: string) => userEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}$`) }));

/**
 * Colour contrast is the one rule jsdom cannot judge, because it has no layout
 * and no computed colours. Everything else axe checks statically applies.
 */
async function audit(container: HTMLElement) {
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } });
  return results.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    count: violation.nodes.length,
    example: violation.nodes[0]?.html.slice(0, 120),
  }));
}

/// axe over a rendered view is inherently slow; these get their own budget so
/// the default timeout keeps guarding every other test.
const AXE_SWEEP_TIMEOUT_MS = 30_000;

describe("accessibility", () => {
  it("keeps every primary view clean", async () => {
    const { container } = render(<App />);
    // Wait for the async request detail, which brings its own headings.
    await waitFor(() => expect(screen.getByText("正文捕获证据")).toBeInTheDocument());

    for (const view of ["流量", "实验室", "高级", "AI 分析", "能力", "设置"]) {
      await goTo(view);
      expect(await audit(container), `${view} has accessibility violations`).toEqual([]);
    }
    // axe sweeps six full views; the default 5s budget is a CI-runner coin flip
    // (this took 5.7s on a Windows runner while passing locally). Kept far above
    // the real cost so it still catches a hang, not a slow machine.
  }, AXE_SWEEP_TIMEOUT_MS);

  it("keeps the dialogs clean", async () => {
    const { container } = render(<App />);

    await userEvent.click(screen.getByTitle("快捷命令"));
    expect(await audit(container), "命令面板").toEqual([]);
    await userEvent.keyboard("{Escape}");

    await userEvent.keyboard("?");
    expect(await audit(container), "快捷操作").toEqual([]);
    await userEvent.keyboard("{Escape}");

    await userEvent.click(screen.getByRole("button", { name: /个来源/ }));
    expect(await audit(container), "流量来源").toEqual([]);
  }, AXE_SWEEP_TIMEOUT_MS);
});

describe("request grid semantics", () => {
  it("exposes itself as a grid, not a pile of orphaned rows", async () => {
    render(<App />);
    // Without role="grid" the rows, column headers and rowgroup had no owner.
    const grid = screen.getByRole("grid", { name: "请求数据网格" });
    expect(within(grid).getAllByRole("columnheader").length).toBeGreaterThan(0);
    expect(within(grid).getAllByRole("row").length).toBeGreaterThan(1);
  });

  it("reports the real row count, not the virtualized slice", async () => {
    render(<App />);
    const grid = screen.getByRole("grid", { name: "请求数据网格" });
    const rendered = within(grid).getAllByRole("row").length;
    const declared = Number(grid.getAttribute("aria-rowcount"));

    // 15 preview requests plus the header row.
    expect(declared).toBe(16);
    expect(declared).toBeGreaterThanOrEqual(rendered);
  });

  it("numbers rows by their place in the full result, not the DOM", async () => {
    render(<App />);
    const grid = screen.getByRole("grid", { name: "请求数据网格" });
    const rows = within(grid).getAllByRole("row");

    expect(rows[0]).toHaveAttribute("aria-rowindex", "1");
    // Data rows start at 2, because the header occupies index 1.
    expect(rows[1]).toHaveAttribute("aria-rowindex", "2");
  });

  it("marks which column each header is", async () => {
    render(<App />);
    const headers = within(screen.getByRole("grid", { name: "请求数据网格" })).getAllByRole("columnheader");
    expect(headers[0]).toHaveAttribute("aria-colindex", "1");
    expect(headers[headers.length - 1]).toHaveAttribute("aria-colindex", String(headers.length));
  });
});

describe("landmarks and headings", () => {
  it("has exactly one main region", async () => {
    render(<App />);
    await goTo("实验室");
    // The workbench used to nest its own <main> inside the app shell's.
    expect(screen.getAllByRole("main")).toHaveLength(1);
  });

  it("never skips a heading level", async () => {
    render(<App />);
    await waitFor(() => expect(screen.getByText("正文捕获证据")).toBeInTheDocument());

    const levels = screen.getAllByRole("heading").map((node) => Number(node.tagName.slice(1)));
    for (const [index, level] of levels.entries()) {
      if (index === 0) continue;
      expect(level - levels[index - 1], `heading ${index} jumps a level`).toBeLessThanOrEqual(1);
    }
  });
});

describe("keyboard reachability", () => {
  it("opens and closes the palette without a pointer", async () => {
    render(<App />);
    await userEvent.keyboard("{Meta>}k{/Meta}");
    expect(screen.getByRole("dialog", { name: "快捷命令" })).toBeInTheDocument();

    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "快捷命令" })).toBeNull();
  });

  it("gives the request grid a tab stop and arrow navigation", async () => {
    render(<App />);
    const grid = screen.getByRole("grid", { name: "请求数据网格" });
    expect(grid).toHaveAttribute("tabindex", "0");

    grid.focus();
    await userEvent.keyboard("{ArrowDown}");
    // Arrow navigation is a documented shortcut; it has to actually move.
    const rows = within(grid).getAllByRole("row");
    expect(rows.some((row) => row.className.includes("is-focused"))).toBe(true);
  });
});
