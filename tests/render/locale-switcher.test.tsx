import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import App from "../../src/App";
import { UI_LOCALE_STORAGE_KEY } from "../../src/i18n";

vi.mock("../../src/components/BrowserView", () => ({ BrowserView: () => null }));

describe("top-bar language switcher", () => {
  it("is always on the top bar and is not a settings control", () => {
    render(<App />);
    expect(document.querySelector("[data-locale-switcher]")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "界面语言" })).toBeInTheDocument();
    expect(screen.queryByRole("listbox", { name: "选择界面语言" })).toBeNull();
  });

  it("expands registered languages and switches chrome immediately", async () => {
    render(<App />);
    await userEvent.click(screen.getByRole("button", { name: "界面语言" }));
    const menu = screen.getByRole("listbox", { name: "选择界面语言" });
    expect(within(menu).getByRole("option", { name: "简体中文" })).toHaveAttribute("aria-selected", "true");
    await userEvent.click(within(menu).getByRole("option", { name: "English" }));
    expect(screen.getByRole("button", { name: "Language" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Traffic$/ })).toBeInTheDocument();
    expect(globalThis.localStorage.getItem(UI_LOCALE_STORAGE_KEY)).toBe("en");
  });

  it("restores the stored pack on the next mount", () => {
    globalThis.localStorage.setItem(UI_LOCALE_STORAGE_KEY, "en");
    render(<App />);
    expect(screen.getByRole("button", { name: "Language" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Traffic$/ })).toBeInTheDocument();
  });
});
