import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SettingsView } from "../../src/components/SettingsView";
import type { RuntimeStatus } from "../../src/types";

const runtime: RuntimeStatus = {
  appVersion: "0.1.0",
  platform: "macos",
  proxyPort: 8888,
  listenHost: "127.0.0.1",
  lanEnabled: false,
  accessMode: "private",
  accessRules: [],
  lanAddresses: [],
  proxyRunning: false,
  caInstalled: false,
  transparentModeAvailable: false,
  systemProxyEnabled: false,
  systemProxyActive: false,
  systemProxyRecoveryPending: false,
};

function renderSettings() {
  return render(
    <SettingsView
      runtime={runtime}
      onRuntimeChange={vi.fn()}
      onNotify={vi.fn()}
      initialTab="capture"
    />,
  );
}

/** The 未保存 badge lives inside the section's own summary row. */
function sectionBadge(title: string) {
  const heading = screen.getByRole("heading", { name: new RegExp(title) });
  return within(heading).queryByText("未保存");
}

beforeEach(() => {
  globalThis.localStorage?.clear();
});

describe("SettingsView unsaved state", () => {
  it("shows nothing unsaved on a cold render", () => {
    // A baseline is seeded on first sight, so an untouched page must be clean.
    renderSettings();
    expect(screen.queryByRole("status")).toBeNull();
    expect(sectionBadge("流量路由")).toBeNull();
  });

  it("marks the section and the page once a field is edited", async () => {
    renderSettings();
    const bypass = screen.getByRole("textbox", { name: /绕过域名/ });

    await userEvent.clear(bypass);
    await userEvent.type(bypass, "example.com");

    // This is the assertion a source-text test cannot make: it depends on the
    // value actually reaching the comparison, which is where reading state at
    // commit time instead of passing it in silently broke.
    expect(sectionBadge("流量路由")).toBeInTheDocument();
    const summary = screen.getByRole("status");
    expect(summary).toHaveTextContent("1 处未保存的更改");
    expect(summary).toHaveTextContent("流量路由");
  });

  it("does not implicate sections the user did not touch", async () => {
    renderSettings();
    const bypass = screen.getByRole("textbox", { name: /绕过域名/ });
    await userEvent.type(bypass, "x");

    expect(sectionBadge("HTTPS 解密")).toBeNull();
    expect(screen.getByRole("status")).not.toHaveTextContent("HTTPS 解密");
  });

  it("clears the mark when the value is typed back to what it was", async () => {
    renderSettings();
    const bypass = screen.getByRole("textbox", { name: /绕过域名/ });
    const original = (bypass as HTMLInputElement).value;

    await userEvent.type(bypass, "abc");
    expect(screen.getByRole("status")).toBeInTheDocument();

    await userEvent.clear(bypass);
    await userEvent.type(bypass, original);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("counts each edited section once, and names them all", async () => {
    renderSettings();
    await userEvent.type(screen.getByRole("textbox", { name: /绕过域名/ }), "a");
    // The switches are checkboxes styled as switches; their accessible name is
    // the whole label row, description included.
    await userEvent.click(screen.getByRole("checkbox", { name: /接管系统代理/ }));

    // Both edits belong to 流量路由; the page must not double-count them.
    expect(screen.getByRole("status")).toHaveTextContent("1 处未保存的更改");
  });
});

describe("SettingsView presents unchangeable values honestly", () => {
  it("renders the listener address and port as read-only facts", () => {
    renderSettings();
    // No command changes either value, so neither may appear as a form field.
    expect(screen.queryByRole("spinbutton", { name: /代理端口/ })).toBeNull();
    expect(screen.getByText("127.0.0.1")).toBeInTheDocument();
    expect(screen.getByText("8888")).toBeInTheDocument();
    expect(screen.getByText(/端口固定为 8888/)).toBeInTheDocument();
  });
});

describe("SettingsView section ordering", () => {
  it("puts the certificate section first and open", () => {
    renderSettings();
    const headings = screen.getAllByRole("heading", { level: 3 }).map((node) => node.textContent ?? "");
    expect(headings[0]).toContain("HTTPS 解密");

    // Installing the CA is the most common reason to open Settings at all.
    expect(screen.getByRole("button", { name: /一键安装/ })).toBeInTheDocument();
  });
});
