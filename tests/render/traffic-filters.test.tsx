import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

/**
 * Filters can be set from the search box, the method chips, the filter panel
 * and the facet sidebar. What matters is that they compose into one visible,
 * reversible state — which is behaviour, not source text.
 */
function chipRow() {
  return screen.queryByRole("region", { name: "生效中的筛选" });
}

function chipLabels() {
  const row = chipRow();
  if (!row) return [];
  return within(row)
    .getAllByRole("button")
    .filter((button) => button.className.includes("active-filter-chip"))
    .map((button) => button.textContent ?? "");
}

/** The search box debounces into the filter state, so chips arrive a tick late. */
async function chipLabelsAfterDebounce(expected: number) {
  await waitFor(() => expect(chipLabels()).toHaveLength(expected));
  return chipLabels();
}

async function openFilterPanel() {
  await userEvent.click(screen.getByRole("button", { name: /筛选/ }));
  return screen.getByRole("tablist", { name: "筛选方式" });
}

describe("traffic filter surface", () => {
  it("shows no chip row until something filters", () => {
    render(<App />);
    expect(chipRow()).toBeNull();
  });

  it("reports a search, a method chip and a facet as one combined state", async () => {
    render(<App />);
    await userEvent.type(screen.getByPlaceholderText(/搜索 URL/), "auth");
    await userEvent.click(screen.getByRole("button", { name: "POST" }));

    // The facet sidebar is a third, independent entry point.
    await userEvent.click(screen.getByTitle("展开统计侧栏"));
    const sidebar = screen.getByRole("complementary", { name: "筛选统计" });
    await userEvent.click(within(sidebar).getByRole("button", { name: /浏览器/ }));

    const labels = await chipLabelsAfterDebounce(3);
    expect(labels.some((label) => label.includes("auth"))).toBe(true);
    expect(labels.some((label) => label.includes("POST"))).toBe(true);
    expect(labels.some((label) => label.includes("浏览器"))).toBe(true);
  });

  it("counts the active criteria on the filter button", async () => {
    render(<App />);
    await userEvent.type(screen.getByPlaceholderText(/搜索 URL/), "auth");
    await userEvent.click(screen.getByRole("button", { name: "POST" }));

    await waitFor(() => expect(screen.getByRole("button", { name: /筛选/ })).toHaveTextContent("2"));
  });

  it("removes exactly the criterion whose chip was clicked", async () => {
    render(<App />);
    await userEvent.type(screen.getByPlaceholderText(/搜索 URL/), "auth");
    await userEvent.click(screen.getByRole("button", { name: "POST" }));
    await chipLabelsAfterDebounce(2);

    const methodChip = within(chipRow() as HTMLElement).getByTitle(/移除筛选：方法 POST/);
    await userEvent.click(methodChip);

    const labels = chipLabels();
    expect(labels).toHaveLength(1);
    expect(labels[0]).toContain("auth");
  });

  it("puts the search box back in sync when its chip is removed", async () => {
    // The chip clears `query`, and the debounced copy in the filter state has
    // to follow — otherwise the text reappears a moment later.
    render(<App />);
    const search = screen.getByPlaceholderText(/搜索 URL/);
    await userEvent.type(search, "auth");
    await chipLabelsAfterDebounce(1);

    await userEvent.click(within(chipRow() as HTMLElement).getByTitle(/移除筛选：搜索 auth/));

    expect(search).toHaveValue("");
    await waitFor(() => expect(chipRow()).toBeNull());
  });

  it("clears everything from one control", async () => {
    render(<App />);
    await userEvent.type(screen.getByPlaceholderText(/搜索 URL/), "auth");
    await userEvent.click(screen.getByRole("button", { name: "POST" }));

    await chipLabelsAfterDebounce(2);
    await userEvent.click(within(chipRow() as HTMLElement).getByRole("button", { name: "清除全部" }));
    await waitFor(() => expect(chipRow()).toBeNull());
    expect(screen.getByPlaceholderText(/搜索 URL/)).toHaveValue("");
  });

  it("offers quick facets, the condition builder and saved views as one panel", async () => {
    render(<App />);
    const tabs = await openFilterPanel();
    expect(within(tabs).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["快捷", "条件", "视图"]);
  });

  it("switches the panel body between its tabs", async () => {
    render(<App />);
    const tabs = await openFilterPanel();

    expect(screen.getByText("ShowNet")).toBeInTheDocument();
    await userEvent.click(within(tabs).getByRole("tab", { name: "条件" }));
    expect(screen.getByText("条件构建器")).toBeInTheDocument();

    await userEvent.click(within(tabs).getByRole("tab", { name: "视图" }));
    expect(screen.getByText("还没有保存视图")).toBeInTheDocument();
  });

  it("keeps reset reachable whether or not anything is filtering", async () => {
    // The old toolbar reset button only existed while a filter was set.
    render(<App />);
    await openFilterPanel();
    const reset = screen.getByRole("button", { name: /重置全部/ });
    expect(reset).toBeDisabled();
    expect(screen.getByText("当前没有筛选")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "POST" }));
    expect(screen.getByRole("button", { name: /重置全部/ })).toBeEnabled();
    expect(screen.getByText("1 项筛选生效")).toBeInTheDocument();
  });

  it("offers every method in the panel, not just the four toolbar chips", async () => {
    render(<App />);
    const tabs = await openFilterPanel();
    const panel = tabs.parentElement as HTMLElement;
    for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"]) {
      expect(within(panel).getByRole("button", { name: new RegExp(`^${method}`) })).toBeInTheDocument();
    }
  });

  it("names a protocol the same way in the panel and the sidebar", async () => {
    // They used to declare their own label maps, so one could read h2 and the
    // other HTTP/2.
    render(<App />);
    const tabs = await openFilterPanel();
    const panel = tabs.parentElement as HTMLElement;
    expect(within(panel).getByRole("button", { name: /HTTP\/2/ })).toBeInTheDocument();

    await userEvent.keyboard("{Escape}");
    await userEvent.click(screen.getByTitle("展开统计侧栏"));
    const sidebar = screen.getByRole("complementary", { name: "筛选统计" });
    expect(within(sidebar).getByRole("button", { name: /HTTP\/2/ })).toBeInTheDocument();
  });
});
