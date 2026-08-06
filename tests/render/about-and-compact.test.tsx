import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";
import { filterCommands, groupCommands, type CommandAction } from "../../src/commandRegistry";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

describe("About", () => {
  async function openAbout() {
    render(<App />);
    await userEvent.click(screen.getByTitle(/关于 ShowNet/));
    return screen.getByRole("dialog", { name: "ShowNet" });
  }

  it("opens from the brand mark", async () => {
    const dialog = await openAbout();
    expect(within(dialog).getByRole("heading", { name: "ShowNet" })).toBeInTheDocument();
  });

  it("states the version, platform and where the proxy listens", async () => {
    const dialog = await openAbout();
    expect(dialog).toHaveTextContent("版本 0.1.0");
    expect(within(dialog).getByText("127.0.0.1:8888")).toBeInTheDocument();
    expect(within(dialog).getByText("GPL-3.0-only")).toBeInTheDocument();
  });

  it("says whether the certificate is trusted, rather than implying it is", async () => {
    const dialog = await openAbout();
    expect(within(dialog).getByText("尚未安装")).toBeInTheDocument();
  });

  it("marks a browser preview as such, so a bug report is not mistaken for the desktop app", async () => {
    const dialog = await openAbout();
    expect(within(dialog).getByText("浏览器预览")).toBeInTheDocument();
  });

  it("offers one line of diagnostics to paste into a report", async () => {
    const dialog = await openAbout();
    await userEvent.click(within(dialog).getByRole("button", { name: /复制版本信息/ }));
    expect(within(dialog).getByRole("button", { name: /已复制/ })).toBeInTheDocument();
  });

  it("is reachable from the command palette too", async () => {
    render(<App />);
    await userEvent.click(screen.getByTitle("快捷命令"));
    const palette = screen.getByRole("dialog", { name: "快捷命令" });
    await userEvent.type(within(palette).getByRole("textbox"), "关于");
    await userEvent.click(within(palette).getByRole("option", { name: /关于 ShowNet/ }));
    expect(screen.getByRole("dialog", { name: "ShowNet" })).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    await openAbout();
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("dialog", { name: "ShowNet" })).toBeNull();
  });
});

describe("collapsed session rail", () => {
  async function collapse() {
    render(<App />);
    await userEvent.click(screen.getByTitle("收起会话"));
  }

  it("keeps each session identifiable once the names are hidden", async () => {
    // Collapsed, the rail is 72px and the body is hidden; without an initial
    // every session is the same anonymous dot.
    await collapse();
    const initials = document.querySelectorAll(".session-item__initial");
    expect(initials.length).toBeGreaterThan(0);
    for (const initial of initials) {
      expect(initial.textContent?.trim().length).toBeGreaterThan(0);
    }
  });

  it("keeps the full name reachable as a tooltip", async () => {
    await collapse();
    const tooltips = screen.getAllByTitle(/打开 .+ 的抓包记录/);
    expect(tooltips.length).toBeGreaterThan(0);
    expect(tooltips[0].getAttribute("title")).toMatch(/打开 .+ 的抓包记录/);
  });

  it("switches the panel into its compact form", async () => {
    // Whether the compact rules actually hide the product name is a cascade
    // question; jsdom loads no stylesheet, so that lives in tests/browser.
    await collapse();
    expect(document.querySelector(".sessions-panel.is-compact")).not.toBeNull();
  });
});

describe("command palette ranking", () => {
  const mk = (id: string, title: string, group: CommandAction["group"], keywords: string[]): CommandAction =>
    ({ id, title, group, keywords, run: () => undefined });

  it("puts the best match first, whatever group it belongs to", () => {
    // The curated group order used to win over the score, so "ca" surfaced
    // 停止抓包 (capture group) above 安装 HTTPS 证书 (config group).
    const actions = [
      mk("capture", "停止抓包", "capture", ["capture", "start"]),
      mk("session", "新建会话", "session", ["create", "new"]),
      mk("ca", "安装 HTTPS 证书", "config", ["ca", "cert"]),
    ];
    const groups = groupCommands(filterCommands(actions, "ca"), true);
    expect(groups[0].actions[0].title).toBe("安装 HTTPS 证书");
  });

  it("keeps the curated order when there is no query", () => {
    const actions = [
      mk("ca", "安装 HTTPS 证书", "config", ["ca"]),
      mk("capture", "开始抓包", "capture", ["capture"]),
    ];
    const groups = groupCommands(filterCommands(actions, ""), false);
    expect(groups.map((group) => group.id)).toEqual(["capture", "config"]);
  });

  it("resolves the aliases an API developer would reach for", async () => {
    render(<App />);
    await userEvent.click(screen.getByTitle("快捷命令"));
    const palette = screen.getByRole("dialog", { name: "快捷命令" });
    const input = within(palette).getByRole("textbox");

    for (const [query, expected] of [["ca", "安装 HTTPS 证书"], ["cert", "安装 HTTPS 证书"], ["har", "导出为 HAR / Postman / OpenAPI"], ["ja3", "MITM 高级控制台"]] as const) {
      await userEvent.clear(input);
      await userEvent.type(input, query);
      const first = within(palette).getAllByRole("option")[0];
      expect(first.querySelector("strong")?.textContent, `"${query}" should surface ${expected}`).toBe(expected);
    }
  });
});
