/**
 * UI appearance: dark (the shipped look), light, or follow the OS.
 *
 * Preference is stored; the resolved value is written to `html[data-theme]`
 * so CSS only consumes semantic tokens. Default stays dark so existing
 * sessions do not flip to light on first launch.
 */

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export const UI_THEME_STORAGE_KEY = "shownet.ui.theme";
export const THEME_PREFERENCES = ["system", "light", "dark"] as const satisfies readonly ThemePreference[];
export const DEFAULT_THEME_PREFERENCE: ThemePreference = "dark";

export const THEME_COLOR = {
  light: "#e9edf3",
  dark: "#101315",
} as const;

function readStorage(storage?: Storage | null): Storage | null {
  if (storage) return storage;
  try {
    return globalThis.localStorage ?? null;
  } catch {
    return null;
  }
}

export function parseThemePreference(raw: string | null | undefined): ThemePreference {
  if (raw === "system" || raw === "light" || raw === "dark") return raw;
  return DEFAULT_THEME_PREFERENCE;
}

export function detectSystemDark(media?: { matches: boolean } | null): boolean {
  if (media) return media.matches;
  try {
    return Boolean(globalThis.matchMedia?.("(prefers-color-scheme: dark)")?.matches);
  } catch {
    return true;
  }
}

export function resolveTheme(
  preference: ThemePreference,
  systemDark = detectSystemDark(),
): ResolvedTheme {
  if (preference === "light") return "light";
  if (preference === "dark") return "dark";
  return systemDark ? "dark" : "light";
}

export function readStoredThemePreference(storage?: Storage | null): ThemePreference {
  try {
    return parseThemePreference(readStorage(storage)?.getItem(UI_THEME_STORAGE_KEY));
  } catch {
    return DEFAULT_THEME_PREFERENCE;
  }
}

export function writeStoredThemePreference(preference: ThemePreference, storage?: Storage | null): void {
  try {
    readStorage(storage)?.setItem(UI_THEME_STORAGE_KEY, preference);
  } catch {
    // Private mode / missing storage must not block a live switch.
  }
}

export function applyResolvedTheme(
  theme: ResolvedTheme,
  root: HTMLElement | null | undefined = globalThis.document?.documentElement,
): void {
  if (!root) return;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  const meta = root.ownerDocument?.querySelector?.('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", THEME_COLOR[theme]);
}

export async function syncNativeWindowTheme(
  preference: ThemePreference,
  theme: ResolvedTheme,
): Promise<void> {
  try {
    const { isTauri } = await import("@tauri-apps/api/core");
    if (!isTauri()) return;
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().setTheme(preference === "system" ? null : theme);
  } catch {
    // Title-bar matching is best-effort; the WebView theme still applies.
  }
}

export function applyThemePreference(
  preference: ThemePreference,
  options?: { systemDark?: boolean; root?: HTMLElement | null },
): ResolvedTheme {
  const theme = resolveTheme(preference, options?.systemDark ?? detectSystemDark());
  applyResolvedTheme(theme, options?.root);
  void syncNativeWindowTheme(preference, theme);
  return theme;
}

export function subscribeSystemTheme(onChange: (dark: boolean) => void): () => void {
  const media = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  if (!media) return () => undefined;
  const handler = (event: MediaQueryListEvent) => onChange(event.matches);
  media.addEventListener("change", handler);
  return () => media.removeEventListener("change", handler);
}
