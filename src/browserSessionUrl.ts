export const DEFAULT_BROWSER_URL = "about:blank";

const LAST_URL_STORAGE_KEY = "shownet.browser.lastUrl";

type SessionStorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem"> & Partial<Pick<Storage, "key" | "length">>;

function availableSessionStorage(storage?: SessionStorageLike): SessionStorageLike | undefined {
  if (storage) return storage;
  try {
    return globalThis.sessionStorage;
  } catch {
    return undefined;
  }
}

export function browserUrlStorageKey(sessionId: string): string {
  return `${LAST_URL_STORAGE_KEY}:${encodeURIComponent(sessionId)}`;
}

export function readStoredBrowserUrl(
  sessionId: string,
  storage?: SessionStorageLike,
): string | null {
  try {
    const value = availableSessionStorage(storage)?.getItem(browserUrlStorageKey(sessionId))?.trim() ?? "";
    return /^https?:\/\//i.test(value) ? value : null;
  } catch {
    return null;
  }
}

export function writeStoredBrowserUrl(
  sessionId: string,
  url: string,
  storage?: SessionStorageLike,
) {
  try {
    if (/^https?:\/\//i.test(url)) {
      availableSessionStorage(storage)?.setItem(browserUrlStorageKey(sessionId), url);
    }
  } catch {
    // Storage may be unavailable in private/preview contexts.
  }
}

export function forgetStoredBrowserUrl(sessionId: string, storage?: SessionStorageLike) {
  try {
    availableSessionStorage(storage)?.removeItem(browserUrlStorageKey(sessionId));
  } catch {
    // Best-effort cleanup only.
  }
}

export function forgetAllStoredBrowserUrls(storage?: SessionStorageLike) {
  try {
    const target = availableSessionStorage(storage);
    if (!target || typeof target.key !== "function" || typeof target.length !== "number") return;
    const keys = Array.from({ length: target.length }, (_, index) => target.key?.(index) ?? "")
      .filter((key) => key.startsWith(`${LAST_URL_STORAGE_KEY}:`));
    keys.forEach((key) => target.removeItem(key));
  } catch {
    // Best-effort cleanup only.
  }
}
