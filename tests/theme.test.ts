/**
 * Appearance preference: dark (default), light, or follow the OS.
 *
 * CSS only consumes the resolved `data-theme`. The preference itself is what
 * we persist, so "system" can still react after launch.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  applyResolvedTheme,
  DEFAULT_THEME_PREFERENCE,
  parseThemePreference,
  readStoredThemePreference,
  resolveTheme,
  THEME_COLOR,
  THEME_PREFERENCES,
  UI_THEME_STORAGE_KEY,
  writeStoredThemePreference,
} from "../src/theme.ts";
import { SETTINGS_INDEX } from "../src/settingsIndex.ts";

class MemoryStorage implements Storage {
  #data = new Map<string, string>();
  get length() { return this.#data.size; }
  clear() { this.#data.clear(); }
  getItem(key: string) { return this.#data.get(key) ?? null; }
  key(index: number) { return [...this.#data.keys()][index] ?? null; }
  removeItem(key: string) { this.#data.delete(key); }
  setItem(key: string, value: string) { this.#data.set(key, value); }
}

describe("theme preference", () => {
  it("defaults to dark so existing sessions keep the shipped look", () => {
    assert.equal(DEFAULT_THEME_PREFERENCE, "dark");
    assert.equal(parseThemePreference(undefined), "dark");
    assert.equal(parseThemePreference(""), "dark");
    assert.equal(parseThemePreference("sepia"), "dark");
    assert.deepEqual([...THEME_PREFERENCES], ["system", "light", "dark"]);
  });

  it("resolves system from the OS without inverting the other two", () => {
    assert.equal(resolveTheme("light", true), "light");
    assert.equal(resolveTheme("light", false), "light");
    assert.equal(resolveTheme("dark", false), "dark");
    assert.equal(resolveTheme("system", true), "dark");
    assert.equal(resolveTheme("system", false), "light");
  });

  it("round-trips the stored preference", () => {
    const storage = new MemoryStorage();
    assert.equal(readStoredThemePreference(storage), "dark");
    writeStoredThemePreference("light", storage);
    assert.equal(storage.getItem(UI_THEME_STORAGE_KEY), "light");
    assert.equal(readStoredThemePreference(storage), "light");
    writeStoredThemePreference("system", storage);
    assert.equal(readStoredThemePreference(storage), "system");
  });

  it("writes the resolved theme onto the root, not the preference", () => {
    const root = { dataset: {} as DOMStringMap, style: { colorScheme: "" }, ownerDocument: { querySelector: () => null } };
    applyResolvedTheme("light", root as unknown as HTMLElement);
    assert.equal(root.dataset.theme, "light");
    assert.equal(root.style.colorScheme, "light");
    applyResolvedTheme("dark", root as unknown as HTMLElement);
    assert.equal(root.dataset.theme, "dark");
    assert.equal(root.style.colorScheme, "dark");
  });
});

describe("theme wiring", () => {
  it("boots from localStorage before paint and keeps three preferences", async () => {
    const html = await readFile(new URL("../index.html", import.meta.url), "utf8");
    assert.match(html, /shownet\.ui\.theme/);
    assert.match(html, /stored === "light" \|\| stored === "dark" \|\| stored === "system"/);
    assert.match(html, /setAttribute\("data-theme"/);
    assert.match(html, /THEME_COLOR|e9edf3|#101315/);
  });

  it("defines a light token set that is not a dark invert", async () => {
    const css = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    assert.match(css, /html\[data-theme="light"\]/);
    assert.match(css, /html\[data-theme="light"\][^{]*\{[^}]*--surface-page:\s*#e9edf3/s);
    assert.match(css, /html\[data-theme="light"\][^{]*\{[^}]*--text-primary:\s*#1d1d1f/s);
    assert.match(css, /html\[data-theme="light"\][^{]*\{[^}]*color-scheme:\s*light/s);
    assert.match(css, /:root\s*\{[^}]*--codex-accent:\s*#339cff;/s);
    assert.match(css, /html\[data-theme="light"\][^{]*\{[^}]*--codex-accent:\s*#0071e3/s);
    assert.match(css, /background:\s*var\(--canvas-wash\)/);
    assert.equal(THEME_COLOR.light, "#e9edf3");
  });

  it("indexes appearance under data so Settings search can find it", () => {
    const entry = SETTINGS_INDEX.find((item) => item.id === "data.appearance");
    assert.ok(entry);
    assert.equal(entry.tab, "data");
    assert.ok(entry.keywords.includes("主题"));
    assert.ok(entry.keywords.includes("light"));
  });

  it("exposes the switcher, settings radios, and command palette actions", async () => {
    const [app, settings, switcher] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/SettingsView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/ThemeSwitcher.tsx", import.meta.url), "utf8"),
    ]);
    assert.match(app, /id: "theme-system"/);
    assert.match(app, /id: "theme-light"/);
    assert.match(app, /id: "theme-dark"/);
    assert.match(app, /<ThemeSwitcher preference=\{themePreference\} onChange=\{chooseTheme\} \/>/);
    assert.match(settings, /id="data.appearance"/);
    assert.match(settings, /className="theme-preference"/);
    assert.match(settings, /role="radiogroup"/);
    assert.match(switcher, /role="listbox"/);
    assert.match(switcher, /"shell\.theme\.system"/);
  });
});
