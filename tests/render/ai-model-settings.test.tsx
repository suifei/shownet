import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

// This file needs the Tauri branch: model discovery and the save round-trip are
// both skipped outright when `isTauri()` is false, so the shared setup mock —
// which reports false — would leave every assertion below vacuous.
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => true,
  invoke: vi.fn(),
}));

import { invoke } from "@tauri-apps/api/core";

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

const DISCOVERED = ["gpt-4o-mini", "gpt-4o"];
const SAVED_MODEL = "internal-llm-v3";
const SAVED_CONTEXT = 128_000;

/** Answers only the commands this screen needs; the rest resolve to undefined. */
function stubBackend() {
  vi.mocked(invoke).mockImplementation(async (command: string, args?: unknown) => {
    switch (command) {
      case "get_ai_provider_settings":
        return {
          provider: "compatible",
          baseUrl: "https://api.example.com/v1",
          model: SAVED_MODEL,
          contextTokens: SAVED_CONTEXT,
          hasApiKey: true,
        };
      case "list_ai_models":
        return DISCOVERED;
      case "save_ai_provider_settings": {
        const settings = (args as { settings: Record<string, unknown> }).settings;
        return { ...settings, hasApiKey: true };
      }
      default:
        // Rejecting keeps every other panel on its declared defaults; resolving
        // undefined would overwrite them with nothing and crash on first read.
        throw new Error(`unstubbed command: ${command}`);
    }
  });
}

function renderAiSettings() {
  return render(
    <SettingsView runtime={runtime} onRuntimeChange={vi.fn()} onNotify={vi.fn()} initialTab="ai" />,
  );
}

/**
 * The model field's accessible name is the whole label, status chip included.
 * Its role is combobox either way — an `<input list>` and a `<select>` both
 * report that — so the tests below check the tag name, which is the thing that
 * decides whether a name can be typed.
 */
const modelField = () => screen.getByRole("combobox", { name: /^模型/ }) as HTMLInputElement;
const contextField = () => screen.getByRole("spinbutton", { name: /上下文上限/ }) as HTMLInputElement;

beforeEach(() => {
  globalThis.localStorage?.clear();
  stubBackend();
});

describe("model selection stays typable after discovery", () => {
  it("keeps a text field once /models has been read", async () => {
    renderAiSettings();
    await waitFor(() => expect(screen.getByText(/已同步 2 个模型/)).toBeInTheDocument());

    // The regression: a successful discovery used to swap the input for a
    // <select>, which is what made a model outside the catalogue untypable.
    expect(modelField().tagName).toBe("INPUT");
    expect(modelField()).not.toHaveAttribute("readonly");
  });

  it("does not overwrite a saved model the endpoint never listed", async () => {
    renderAiSettings();
    await waitFor(() => expect(screen.getByText(/已同步 2 个模型/)).toBeInTheDocument());

    expect(modelField().value).toBe(SAVED_MODEL);
    expect(DISCOVERED).not.toContain(SAVED_MODEL);
  });

  it("offers the discovered models as suggestions rather than as the only choices", async () => {
    const { container } = renderAiSettings();
    await waitFor(() => expect(screen.getByText(/已同步 2 个模型/)).toBeInTheDocument());

    const list = modelField().getAttribute("list");
    expect(list).toBeTruthy();
    const options = Array.from(container.querySelectorAll(`datalist#${list} option`));
    expect(options.map((option) => option.getAttribute("value"))).toEqual(DISCOVERED);
  });

  it("accepts a model name typed by hand", async () => {
    renderAiSettings();
    await waitFor(() => expect(screen.getByText(/已同步 2 个模型/)).toBeInTheDocument());

    await userEvent.clear(modelField());
    await userEvent.type(modelField(), "qwen3-max");

    expect(modelField().value).toBe("qwen3-max");
  });
});

describe("context window is a real setting", () => {
  it("loads the persisted value instead of a hardcoded label", async () => {
    renderAiSettings();
    await waitFor(() => expect(contextField().value).toBe(String(SAVED_CONTEXT)));
    expect(contextField()).not.toHaveAttribute("readonly");
  });

  it("sends the edited model and context window to the backend", async () => {
    renderAiSettings();
    await waitFor(() => expect(contextField().value).toBe(String(SAVED_CONTEXT)));

    await userEvent.clear(modelField());
    await userEvent.type(modelField(), "qwen3-max");
    await userEvent.clear(contextField());
    await userEvent.type(contextField(), "262144");
    await userEvent.click(screen.getByRole("button", { name: /保存设置/ }));

    await waitFor(() => {
      const call = vi
        .mocked(invoke)
        .mock.calls.find(([command]) => command === "save_ai_provider_settings");
      expect(call).toBeTruthy();
      expect((call![1] as { settings: Record<string, unknown> }).settings).toMatchObject({
        model: "qwen3-max",
        contextTokens: 262_144,
      });
    });
  });

  it("clamps a value below the backend minimum before saving", async () => {
    renderAiSettings();
    await waitFor(() => expect(contextField().value).toBe(String(SAVED_CONTEXT)));

    await userEvent.clear(contextField());
    await userEvent.type(contextField(), "12");
    await userEvent.click(screen.getByRole("button", { name: /保存设置/ }));

    await waitFor(() => {
      const call = vi
        .mocked(invoke)
        .mock.calls.find(([command]) => command === "save_ai_provider_settings");
      // 1024 is MIN_AI_CONTEXT_TOKENS; sending 12 would be rejected by validation.
      expect((call![1] as { settings: Record<string, unknown> }).settings.contextTokens).toBe(1024);
    });
  });
});
