import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach, vi } from "vitest";

afterEach(cleanup);

// Same pin as playwright.config.ts `locale: "zh-CN"`. jsdom defaults to
// en-US, and App now resolves the UI pack from navigator.language; existing
// render specs click 流量 / 实验室 / 设置.
Object.defineProperty(globalThis.navigator, "language", {
  configurable: true,
  get: () => "zh-CN",
});
Object.defineProperty(globalThis.navigator, "languages", {
  configurable: true,
  get: () => ["zh-CN", "zh"],
});

// The app renders inside Tauri. Under jsdom there is no native runtime, so the
// IPC surface has to be stubbed before any component module is imported —
// several of them call `isTauri()` at module scope.
vi.mock("@tauri-apps/api/core", () => ({
  isTauri: () => false,
  invoke: vi.fn(async () => undefined),
}));

vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn(async () => () => undefined),
}));

vi.mock("@tauri-apps/plugin-clipboard-manager", () => ({
  writeText: vi.fn(async () => undefined),
  readText: vi.fn(async () => ""),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(async () => null),
  save: vi.fn(async () => null),
}));

// jsdom implements neither, and components use both for layout bookkeeping.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver;

Element.prototype.scrollIntoView ??= function scrollIntoView() {};
