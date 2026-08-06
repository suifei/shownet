import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

/**
 * The palette's value is in behaviour the source cannot show: what a query
 * matches, where the keyboard cursor lands, and whether a disabled row can be
 * triggered anyway.
 */
async function openPalette() {
  render(<App />);
  await userEvent.click(screen.getByTitle("快捷命令"));
  return screen.getByRole("dialog", { name: "快捷命令" });
}

function rowLabels(palette: HTMLElement) {
  return within(palette)
    .getAllByRole("option")
    .map((row) => row.querySelector("strong")?.textContent ?? "");
}

describe("CommandPalette", () => {
  it("opens grouped, with the groups in a fixed order", async () => {
    const palette = await openPalette();
    const groups = within(palette).getAllByRole("group").map((node) => node.getAttribute("aria-label"));
    expect(groups).toEqual(["开始使用", "抓包与连接", "会话与导出", "前往", "设置与证书"]);
  });

  it("matches a Chinese label", async () => {
    const palette = await openPalette();
    await userEvent.type(within(palette).getByRole("textbox"), "证书");
    expect(rowLabels(palette)).toContain("安装 HTTPS 证书");
  });

  it("matches an English alias an API developer would type", async () => {
    const palette = await openPalette();
    await userEvent.type(within(palette).getByRole("textbox"), "har");
    expect(rowLabels(palette)).toContain("导出为 HAR / Postman / OpenAPI");
  });

  it("drops groups that have no matches", async () => {
    const palette = await openPalette();
    await userEvent.type(within(palette).getByRole("textbox"), "mcp");
    const groups = within(palette).getAllByRole("group").map((node) => node.getAttribute("aria-label"));
    expect(groups).not.toContain("会话与导出");
  });

  it("says so when nothing matches", async () => {
    const palette = await openPalette();
    await userEvent.type(within(palette).getByRole("textbox"), "zzzznope");
    expect(within(palette).getByText("没有匹配的操作")).toBeInTheDocument();
    expect(within(palette).queryAllByRole("option")).toHaveLength(0);
  });

  it("starts the cursor on the first row and moves it with the arrows", async () => {
    const palette = await openPalette();
    const rows = within(palette).getAllByRole("option");
    expect(rows[0]).toHaveAttribute("aria-selected", "true");

    await userEvent.keyboard("{ArrowDown}");
    expect(within(palette).getAllByRole("option")[1]).toHaveAttribute("aria-selected", "true");

    await userEvent.keyboard("{ArrowUp}");
    expect(within(palette).getAllByRole("option")[0]).toHaveAttribute("aria-selected", "true");
  });

  it("wraps the cursor at the ends", async () => {
    const palette = await openPalette();
    await userEvent.keyboard("{ArrowUp}");
    const rows = within(palette).getAllByRole("option");
    expect(rows[rows.length - 1]).toHaveAttribute("aria-selected", "true");
  });

  it("runs the highlighted action on Enter", async () => {
    const palette = await openPalette();
    // The first row opens the setup guide, which replaces the palette.
    await userEvent.keyboard("{Enter}");
    expect(screen.queryByRole("dialog", { name: "快捷命令" })).toBeNull();
    expect(screen.getByRole("dialog", { name: /三分钟跑通|已经可以开始了/ })).toBeInTheDocument();
  });

  it("explains a disabled action instead of leaving it dead", async () => {
    const palette = await openPalette();
    // Capture is running in the preview build, which is what blocks this one.
    await userEvent.type(within(palette).getByRole("textbox"), "打开会话文件");
    const row = within(palette).getByRole("option");

    expect(row).toBeDisabled();
    expect(row).toHaveTextContent("请先停止抓包");

    // Clicking must not close the palette or run anything.
    await userEvent.click(row);
    expect(screen.getByRole("dialog", { name: "快捷命令" })).toBeInTheDocument();
  });

  it("keeps the keyboard cursor off disabled rows", async () => {
    const palette = await openPalette();
    await userEvent.type(within(palette).getByRole("textbox"), "会话");
    const rows = within(palette).getAllByRole("option");
    const selected = rows.find((row) => row.getAttribute("aria-selected") === "true");
    expect(selected).toBeDefined();
    expect(selected).toBeEnabled();
  });

  it("closes on Escape", async () => {
    await openPalette();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "快捷命令" })).toBeNull();
  });
});

describe("ShortcutsSheet", () => {
  it("opens with ? and documents the invisible grid interactions", async () => {
    render(<App />);
    await userEvent.keyboard("?");

    const sheet = screen.getByRole("dialog", { name: "快捷操作" });
    for (const phrase of ["追加为次级排序条件", "全选当前窗口的请求", "按内容自适应列宽"]) {
      // The rendered lines are longer than the phrase, so match loosely.
      expect(within(sheet).getByText(new RegExp(phrase))).toBeInTheDocument();
    }
  });

  it("ignores ? typed into a field", async () => {
    render(<App />);
    const search = screen.getByPlaceholderText(/搜索 URL/);
    await userEvent.click(search);
    await userEvent.keyboard("?");

    expect(screen.queryByRole("dialog", { name: "快捷操作" })).toBeNull();
    expect(search).toHaveValue("?");
  });
});

vi.mock("../../src/components/BrowserView", () => ({
  // The embedded browser drives a real webview and is irrelevant here.
  BrowserView: () => null,
}));
