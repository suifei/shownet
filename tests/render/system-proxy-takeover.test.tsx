import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SettingsView } from "../../src/components/SettingsView";
import type { RuntimeStatus } from "../../src/types";

function runtimeWith(overrides: Partial<RuntimeStatus> = {}): RuntimeStatus {
  return {
    appVersion: "0.1.0",
    platform: "windows",
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
    ...overrides,
  };
}

function renderRouting(runtime: RuntimeStatus) {
  return render(
    <SettingsView
      runtime={runtime}
      onRuntimeChange={vi.fn()}
      onNotify={vi.fn()}
      initialTab="capture"
    />,
  );
}

const takeoverSwitch = () => screen.getByRole("checkbox", { name: /接管系统代理/ });

beforeEach(() => {
  globalThis.localStorage?.clear();
});

describe("system proxy takeover status", () => {
  it("does not warn about a recovery while the takeover is healthy", () => {
    // The backend holds a restore snapshot for the whole takeover, so it used
    // to report one as "pending" — every successful capture raised an alarm
    // saying the proxy had not been set, which is what issue #5 reported.
    renderRouting(runtimeWith({
      proxyRunning: true,
      systemProxyEnabled: true,
      systemProxyActive: true,
      systemProxyRecoveryPending: false,
    }));

    expect(screen.queryByText(/尚未完成的系统代理恢复记录/)).toBeNull();
    expect(screen.queryByRole("button", { name: "重试恢复" })).toBeNull();
    expect(screen.getByText(/已接管 · 停止抓包或退出时自动恢复/)).toBeInTheDocument();
  });

  it("still offers recovery when a snapshot outlived its takeover", () => {
    renderRouting(runtimeWith({ systemProxyRecoveryPending: true }));

    expect(screen.getByText(/尚未完成的系统代理恢复记录/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "重试恢复" })).toBeInTheDocument();
  });
});

describe("system proxy takeover switch", () => {
  it("says so when the toggle has not been saved yet", async () => {
    renderRouting(runtimeWith());

    expect(screen.queryByText(/接管开关改动尚未保存/)).toBeNull();
    await userEvent.click(takeoverSwitch());

    // Starting a capture reads the persisted preference, not this checkbox, so
    // an unsaved toggle takes nothing over — the user has to be told.
    expect(screen.getByText(/接管开关改动尚未保存/)).toBeInTheDocument();
    expect(screen.getByText(/尚未保存 · 保存路由设置后/)).toBeInTheDocument();
  });

  it("keeps a pending toggle when unrelated runtime status changes", async () => {
    const { rerender } = renderRouting(runtimeWith());
    await userEvent.click(takeoverSwitch());
    expect(takeoverSwitch()).toBeChecked();

    // A status refresh used to mirror `enabled` back from the runtime and
    // re-baseline the section, discarding the edit without a word.
    rerender(
      <SettingsView
        runtime={runtimeWith({ systemProxyActive: false, systemProxyRecoveryPending: true })}
        onRuntimeChange={vi.fn()}
        onNotify={vi.fn()}
        initialTab="capture"
      />,
    );

    await waitFor(() => expect(takeoverSwitch()).toBeChecked());
    expect(screen.getByText(/接管开关改动尚未保存/)).toBeInTheDocument();
  });

  it("adopts the value once the backend confirms it", async () => {
    const { rerender } = renderRouting(runtimeWith());
    await userEvent.click(takeoverSwitch());

    rerender(
      <SettingsView
        runtime={runtimeWith({ systemProxyEnabled: true })}
        onRuntimeChange={vi.fn()}
        onNotify={vi.fn()}
        initialTab="capture"
      />,
    );

    await waitFor(() => expect(screen.queryByText(/接管开关改动尚未保存/)).toBeNull());
    expect(takeoverSwitch()).toBeChecked();
  });
});
