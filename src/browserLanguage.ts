export const BROWSER_LANGUAGE_STORAGE_KEY = "shownet.browser.language";

export const BROWSER_LANGUAGE_SUGGESTIONS = [
  "zh-CN",
  "zh-TW",
  "en-US",
  "en-GB",
  "th-TH",
  "ja-JP",
  "ko-KR",
] as const;

export function normalizeBrowserLanguage(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    return Intl.getCanonicalLocales(trimmed)[0] ?? null;
  } catch {
    return null;
  }
}

export function initialBrowserLanguage(storage: Pick<Storage, "getItem"> | undefined): string {
  const saved = storage?.getItem(BROWSER_LANGUAGE_STORAGE_KEY) ?? "";
  return normalizeBrowserLanguage(saved)
    ?? normalizeBrowserLanguage(globalThis.navigator?.language ?? "")
    ?? "en-US";
}

export interface BrowserChallengeSnapshot {
  url: string;
  title: string;
  text: string;
  cloudflareMarker: boolean;
}

export function cloudflareChallengeHost(snapshot: BrowserChallengeSnapshot): string {
  if (!snapshot.cloudflareMarker) return "";
  const words = `${snapshot.title} ${snapshot.text}`.toLowerCase();
  const challengeCopy = [
    "cloudflare",
    "verify you are human",
    "checking your browser",
    "security verification",
    "请验证您是真人",
    "正在进行安全验证",
    "验证您不是自动程序",
  ];
  if (!challengeCopy.some((word) => words.includes(word))) return "";
  try {
    const url = new URL(snapshot.url);
    return url.protocol === "https:" ? url.hostname.toLowerCase() : "";
  } catch {
    return "";
  }
}
