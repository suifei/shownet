import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// Enabling a CDP domain is not free: Chrome starts pushing that domain's events
// down the same WebSocket the live view rides on. Network.enable shipped in the
// first release with no handler behind it, and one bing.com load measured 246
// events / 464KB of JSON that were parsed and thrown away — against 5 events /
// 568B for Page. Pinning the string would only stop that one line coming back,
// so this asserts the rule instead: every domain we turn on has to be read.
describe("CDP domains enabled by the embedded browser", () => {
  it("are each consumed by a packet handler", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../src/components/BrowserView.tsx", import.meta.url)),
      "utf8",
    );

    const enabled = new Set(
      [...source.matchAll(/send\("([A-Z][A-Za-z]*)\.enable"\)/g)].map((match) => match[1]),
    );
    assert.ok(enabled.size > 0, "no CDP domain enable found — did the send() call shape change?");

    // Both comparison directions: the bindingCalled handler is written as an
    // early-return `!==` guard, so an `===`-only scan would miss Runtime.
    const consumed = new Set(
      [...source.matchAll(/packet\.method\s*[!=]==\s*"([A-Z][A-Za-z]*)\./g)].map((match) => match[1]),
    );

    for (const domain of enabled) {
      assert.ok(
        consumed.has(domain),
        `${domain}.enable is sent but no packet.method branch reads ${domain}.* — ` +
          "either handle its events or stop enabling the domain",
      );
    }
  });
});
