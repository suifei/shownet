/**
 * Detects a page that keeps re-navigating to itself.
 *
 * A bot-management challenge that never validates — or an origin whose TLS the
 * MITM cannot satisfy — presents as the same URL loading over and over with
 * nothing to show for it. Chrome's own auto-reload has no interstitial here, so
 * without this the user just watches a home page flicker forever.
 */

/** How far back a navigation still counts toward a loop. */
export const RELOAD_LOOP_WINDOW_MS = 15_000;
/** Repeats of one URL inside that window before we call it a loop. */
export const RELOAD_LOOP_THRESHOLD = 4;

export interface NavigationMark {
  url: string;
  at: number;
}

/**
 * Ignores the fragment and the query, because a challenge typically bounces
 * through the same path carrying a fresh nonce each time.
 */
export function navigationKey(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return url;
  }
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

/**
 * Appends `url` to `log`, drops marks outside the window, and returns both the
 * pruned log and the host to warn about (empty when there is no loop).
 */
export function trackNavigation(
  log: NavigationMark[],
  url: string,
  at: number,
): { log: NavigationMark[]; loopHost: string } {
  // `about:blank` and the like are startup noise, not a site looping.
  if (!/^https?:/i.test(url)) return { log: [], loopHost: "" };

  const pruned = [...log, { url, at }].filter((mark) => at - mark.at < RELOAD_LOOP_WINDOW_MS);
  const key = navigationKey(url);
  const repeats = pruned.filter((mark) => navigationKey(mark.url) === key).length;
  return { log: pruned, loopHost: repeats >= RELOAD_LOOP_THRESHOLD ? hostOf(url) : "" };
}
