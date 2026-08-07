import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true, invoke: vi.fn() }));

// Captured so a test can push a backend event the way the runtime would.
const listeners = new Map<string, (event: { payload: unknown }) => void>();
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async (name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return () => listeners.delete(name);
  }),
}));

import { invoke } from "@tauri-apps/api/core";

import { SettingsView } from "../../src/components/SettingsView";
import type { McpServerStatus, RuntimeStatus } from "../../src/types";

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

const SAVED_MCP: McpServerStatus = {
  enabled: false,
  running: true,
  starting: false,
  host: "127.0.0.1",
  port: 8899,
  endpoint: "http://127.0.0.1:8899/mcp",
  protocolVersion: "2025-06-18",
  toolCount: 32,
  allowWrites: false,
  hasAccessToken: true,
  recentClients: [],
};

beforeEach(() => {
  listeners.clear();
  globalThis.localStorage?.clear();
  vi.mocked(invoke).mockImplementation(async (command: string) => {
    if (command === "get_mcp_server_status") return SAVED_MCP;
    throw new Error(`unstubbed: ${command}`);
  });
});

function renderMcpSettings() {
  return render(
    <SettingsView runtime={runtime} onRuntimeChange={vi.fn()} onNotify={vi.fn()} initialTab="mcp" />,
  );
}

const portField = () => screen.getByRole("spinbutton", { name: /端口/ }) as HTMLInputElement;
const writesSwitch = () => screen.getByRole("checkbox", { name: /允许写入型工具/ });

/** Mimics the activity push the backend sends on every MCP tool call. */
function pushActivity(overrides: Partial<McpServerStatus> = {}) {
  act(() => {
    listeners.get("settings://mcp-server")?.({
      payload: { ...SAVED_MCP, lastRequestAt: 1_700_000_000_000, ...overrides },
    });
  });
}

describe("an MCP activity push does not eat the user's edits", () => {
  it("keeps a typed port when a tool call arrives", async () => {
    renderMcpSettings();
    await waitFor(() => expect(portField().value).toBe("8899"));

    await userEvent.clear(portField());
    await userEvent.type(portField(), "9100");
    pushActivity();

    // The push carries the *saved* port 8899; adopting it would silently undo
    // the edit and, because it also re-baselined, hide that anything was lost.
    await waitFor(() => expect(portField().value).toBe("9100"));
  });

  it("keeps a flipped switch, and keeps saying it is unsaved", async () => {
    renderMcpSettings();
    await waitFor(() => expect(portField().value).toBe("8899"));

    await userEvent.click(writesSwitch());
    expect(writesSwitch()).toBeChecked();
    pushActivity();

    await waitFor(() => expect(writesSwitch()).toBeChecked());
    expect(screen.getByRole("status")).toHaveTextContent("1 处未保存的更改");
  });

  it("still adopts a genuine settings change from the backend", async () => {
    renderMcpSettings();
    await waitFor(() => expect(portField().value).toBe("8899"));

    // Saved elsewhere — a real change to the stored config, not activity noise.
    pushActivity({ port: 9500, enabled: true });

    await waitFor(() => expect(portField().value).toBe("9500"));
    expect(screen.queryByRole("status")).toBeNull();
  });
});

describe("MCP panel states only what it can honour", () => {
  it("presents the listen address as a fact, not a dead input", async () => {
    renderMcpSettings();
    await waitFor(() => expect(portField().value).toBe("8899"));

    // No command carries a host, so it must not look editable.
    expect(screen.queryByRole("textbox", { name: /监听地址/ })).toBeNull();
    expect(screen.getByText("127.0.0.1")).toBeInTheDocument();
  });

  it("does not invent a tool count the server has not reported", async () => {
    renderMcpSettings();
    await waitFor(() => expect(screen.getByText(/32 Tools/)).toBeInTheDocument());

    await userEvent.click(writesSwitch());

    // The old code guessed 36; the real number only arrives from the backend.
    expect(screen.queryByText(/36 Tools/)).toBeNull();
    expect(screen.getByText(/32 Tools/)).toBeInTheDocument();
  });
});
