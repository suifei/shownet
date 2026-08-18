import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

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

function assertSwitch(label: string) {
  const title = screen.getByText(label);
  const row = title.closest("label");
  expect(row, label).toHaveClass("settings-switch-row");
  expect(row?.querySelector("input[type='checkbox']"), `${label} checkbox`).not.toBeNull();
  expect(row?.querySelector("i"), `${label} track`).not.toBeNull();
}

describe("Settings named switches stay on the contrast-fixed control", () => {
  it("capture tab: 接管系统代理 and 允许局域网设备接入", () => {
    render(<SettingsView runtime={runtime} onRuntimeChange={vi.fn()} onNotify={vi.fn()} initialTab="capture" />);
    assertSwitch("接管系统代理");
    assertSwitch("允许局域网设备接入");
  });

  it("AI tab: 两阶段分析, 允许 MCP 工具调用, 流式输出", () => {
    render(<SettingsView runtime={runtime} onRuntimeChange={vi.fn()} onNotify={vi.fn()} initialTab="ai" />);
    assertSwitch("两阶段分析");
    assertSwitch("允许 MCP 工具调用");
    assertSwitch("流式输出");
  });

  it("data tab: 自动清理 and 保存二进制响应", () => {
    render(<SettingsView runtime={runtime} onRuntimeChange={vi.fn()} onNotify={vi.fn()} initialTab="data" />);
    assertSwitch("自动清理");
    assertSwitch("保存二进制响应");
  });
});
