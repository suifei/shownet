import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  RELOAD_LOOP_THRESHOLD,
  RELOAD_LOOP_WINDOW_MS,
  navigationKey,
  trackNavigation,
  type NavigationMark,
} from "../src/reloadLoop.ts";

/** Feeds `count` navigations to the same URL, one second apart. */
function repeat(url: string, count: number, startAt = 1_000) {
  let log: NavigationMark[] = [];
  let loopHost = "";
  for (let index = 0; index < count; index += 1) {
    ({ log, loopHost } = trackNavigation(log, url, startAt + index * 1_000));
  }
  return { log, loopHost };
}

describe("reload loop detection", () => {
  it("stays quiet while a page navigates normally", () => {
    let log: NavigationMark[] = [];
    let loopHost = "";
    for (const url of ["https://example.com/", "https://example.com/a", "https://example.com/b"]) {
      ({ log, loopHost } = trackNavigation(log, url, 1_000));
    }
    assert.equal(loopHost, "");
  });

  it("reports the host once one URL repeats past the threshold", () => {
    const below = repeat("https://www.lionairthai.com/", RELOAD_LOOP_THRESHOLD - 1);
    assert.equal(below.loopHost, "", "must not fire before the threshold");

    const at = repeat("https://www.lionairthai.com/", RELOAD_LOOP_THRESHOLD);
    assert.equal(at.loopHost, "www.lionairthai.com");
  });

  it("counts a challenge that returns with a fresh nonce each time", () => {
    // The query is where the changing token lives, so it cannot be part of the key.
    let log: NavigationMark[] = [];
    let loopHost = "";
    for (let index = 0; index < RELOAD_LOOP_THRESHOLD; index += 1) {
      ({ log, loopHost } = trackNavigation(log, `https://site.example/?__cf_chl_tk=${index}`, 1_000 + index * 500));
    }
    assert.equal(loopHost, "site.example");
  });

  it("forgets navigations that fall outside the window", () => {
    let log: NavigationMark[] = [];
    let loopHost = "";
    for (let index = 0; index < RELOAD_LOOP_THRESHOLD * 2; index += 1) {
      // Spaced so the window never holds more than two at once.
      ({ log, loopHost } = trackNavigation(log, "https://slow.example/", index * (RELOAD_LOOP_WINDOW_MS - 1_000)));
    }
    assert.equal(loopHost, "", "a slow poll is not a loop");
  });

  it("ignores non-http navigations", () => {
    const { log, loopHost } = repeat("about:blank", RELOAD_LOOP_THRESHOLD + 2);
    assert.equal(loopHost, "");
    assert.deepEqual(log, [], "startup noise must not accumulate");
  });

  it("keys on origin and path, so a different page is a different key", () => {
    assert.equal(navigationKey("https://a.example/x?y=1#z"), "https://a.example/x");
    assert.notEqual(navigationKey("https://a.example/x"), navigationKey("https://a.example/y"));
    assert.notEqual(navigationKey("https://a.example/x"), navigationKey("https://b.example/x"));
  });

  it("survives a URL it cannot parse", () => {
    assert.equal(navigationKey("not a url"), "not a url");
  });
});

describe("the browser surface explains the loop", () => {
  it("warns in place instead of leaving the page flickering", async () => {
    const view = await readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8");
    assert.match(view, /className="browser-reload-loop" role="alert"/);
    assert.match(view, /正在反复刷新/);
    // The warning is only useful if it names the way out.
    assert.match(view, /HTTPS 解密/);

    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");
    assert.match(styles, /\.browser-reload-loop \{/);
  });
});
