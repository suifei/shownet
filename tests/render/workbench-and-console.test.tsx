import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

const goTo = (label: string) => userEvent.click(screen.getByRole("button", { name: new RegExp(`^${label}$`) }));

describe("request lab", () => {
  it("names request parts the way the traffic detail pane does", async () => {
    render(<App />);
    await goTo("实验室");
    await userEvent.click(screen.getByRole("button", { name: /空白请求/ }));

    const tabs = ["参数", "请求头", "请求体", "认证", "发送设置"];
    for (const tab of tabs) {
      expect(screen.getByRole("button", { name: new RegExp(tab) })).toBeInTheDocument();
    }
    // The English labels the lab used to carry are gone.
    expect(screen.queryByRole("button", { name: /^Query/ })).toBeNull();
  });

  it("carries the same TLS warning as the replay panel", async () => {
    render(<App />);
    await goTo("实验室");
    await userEvent.click(screen.getByRole("button", { name: /空白请求/ }));
    await userEvent.click(screen.getByRole("button", { name: /发送设置/ }));

    expect(screen.getByText("关闭仅用于授权测试")).toBeInTheDocument();
  });

  it("offers cURL import while a draft is open", async () => {
    // Import used to exist only on the empty lab screen.
    render(<App />);
    await goTo("实验室");
    await userEvent.click(screen.getByRole("button", { name: /空白请求/ }));

    await userEvent.click(screen.getByTitle("cURL 导入与导出"));
    expect(screen.getByLabelText("粘贴 cURL 命令")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /复制当前请求/ })).toBeInTheDocument();
    expect(screen.getByText(/导入会覆盖当前草稿/)).toBeInTheDocument();
  });
});

describe("request diff", () => {
  it("blocks entry and says what the selection must be", async () => {
    render(<App />);
    await goTo("实验室");

    const diffTab = screen.getByRole("button", { name: /请求对比/ });
    expect(diffTab).toBeDisabled();
    expect(diffTab).toHaveAttribute("title", "请从流量页带入两条请求");
  });

  it("never renders a zero-difference result as if the requests matched", async () => {
    render(<App />);
    await goTo("实验室");
    // The old panel rendered "0 项差异" for an unusable selection.
    expect(screen.queryByText("项差异")).toBeNull();
  });
});

describe("request collections", () => {
  async function openCollections() {
    render(<App />);
    await goTo("实验室");
    await userEvent.click(screen.getByRole("button", { name: /请求集合/ }));
    await userEvent.click(screen.getAllByRole("button", { name: /商城核心 API/ })[0]);
  }

  it("labels its two everyday actions", async () => {
    await openCollections();
    expect(screen.getByRole("button", { name: /新建文件夹/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /更多/ })).toBeInTheDocument();
  });

  it("keeps the rest behind an overflow menu with real labels", async () => {
    await openCollections();
    expect(screen.queryByRole("menu", { name: "集合操作" })).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: /更多/ }));
    const menu = screen.getByRole("menu", { name: "集合操作" });
    // The two exports used to differ by icon alone.
    expect(within(menu).getByRole("menuitem", { name: /导出 ShowNet JSON/ })).toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: /导出 Postman/ })).toBeInTheDocument();
    expect(within(menu).getByRole("menuitem", { name: /删除集合（保留请求）/ })).toBeInTheDocument();
  });
});

describe("MITM advanced console", () => {
  async function openConsole() {
    render(<App />);
    await goTo("高级");
  }

  it("is down to eight tabs, with one PX entry", async () => {
    await openConsole();
    const tabs = screen.getByRole("navigation", { name: "高级控制台分区" });
    const labels = within(tabs).getAllByRole("button").map((button) => button.textContent ?? "");

    expect(labels).toHaveLength(8);
    expect(labels.filter((label) => label.includes("PX"))).toHaveLength(1);
  });

  it("turns the three former PX tabs into modes over one list", async () => {
    await openConsole();
    await userEvent.click(screen.getByRole("button", { name: /PX 证据/ }));

    const modes = screen.getByRole("tablist", { name: "PX 操作模式" });
    expect(within(modes).getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["解码", "对比", "改写"]);
  });

  it("changes the guidance with the mode", async () => {
    await openConsole();
    await userEvent.click(screen.getByRole("button", { name: /PX 证据/ }));
    const panel = screen.getByRole("tablist", { name: "PX 操作模式" }).parentElement as HTMLElement;
    expect(within(panel).getByText(/非无密钥硬破/)).toBeInTheDocument();

    const modes = within(panel).getByRole("tablist", { name: "PX 操作模式" });
    await userEvent.click(within(modes).getByRole("tab", { name: "对比" }));
    expect(within(panel).getByText(/标记 A \/ B 两条请求/)).toBeInTheDocument();
  });

  it("shows one control for the outbound TLS preset", async () => {
    await openConsole();
    const tabs = screen.getByRole("navigation", { name: "高级控制台分区" });
    await userEvent.click(within(tabs).getByRole("button", { name: /配置/ }));

    // A select and a chip row used to drive the same value.
    expect(screen.getAllByRole("combobox")).toHaveLength(1);
  });
});
