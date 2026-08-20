import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import App from "../../src/App";
import { UI_THEME_STORAGE_KEY } from "../../src/theme";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

describe("top-bar appearance switcher", () => {
  beforeEach(() => {
    globalThis.localStorage?.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.style.colorScheme = "";
  });

  it("is always on the top bar and is not buried in capture settings", () => {
    render(<App />);
    expect(document.querySelector("[data-theme-switcher]")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "外观" })).toBeInTheDocument();
    expect(screen.queryByRole("listbox", { name: "选择外观" })).toBeNull();
  });

  it("applies light immediately and persists the preference", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "外观" }));
    const menu = screen.getByRole("listbox", { name: "选择外观" });
    expect(within(menu).getByRole("option", { name: "深色" })).toHaveAttribute("aria-selected", "true");
    await userEvent.click(within(menu).getByRole("option", { name: "浅色" }));
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(globalThis.localStorage.getItem(UI_THEME_STORAGE_KEY)).toBe("light");
  });

  it("restores the stored preference on the next mount", () => {
    globalThis.localStorage.setItem(UI_THEME_STORAGE_KEY, "light");
    render(<App />);
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(screen.getByRole("button", { name: "外观" })).toBeInTheDocument();
  });
});
