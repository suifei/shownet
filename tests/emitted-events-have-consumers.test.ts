import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// A Tauri emit serializes its payload and pushes it to the webview whether or
// not anything is listening. capture://request did that once per captured
// request, carrying the same RequestListItem that capture://request-created
// already ships, with no listener anywhere — so this asserts the rule.
//
// The events below are emitted with nothing listening on purpose: each fires
// once on a user action with a small payload, from the very command the
// frontend invoked, so the frontend already knows the outcome. They are cheap
// enough that removing them would only risk tearing out intended surface.
// Anything NOT on this list has to be consumed.
const KNOWN_UNCONSUMED = new Set([
  "browser://status",
  "certificate://status",
  "replay://item",
  "settings://ai-analysis",
  "settings://ai-provider",
  "settings://data-storage",
  "settings://mcp-clients",
  "settings://system-proxy",
  "settings://tls-interception",
  "settings://upstream-proxy",
]);

const readTree = async (root: URL): Promise<string> => {
  const entries = await readdir(fileURLToPath(root), { withFileTypes: true, recursive: true });
  const files = entries
    .filter((entry) => entry.isFile() && /\.(rs|ts|tsx)$/.test(entry.name))
    .map((entry) => readFile(`${entry.parentPath}/${entry.name}`, "utf8"));
  return (await Promise.all(files)).join("\n");
};

describe("events the backend emits", () => {
  it("are each consumed by the frontend, or listed as deliberately unconsumed", async () => {
    const [rust, frontend] = await Promise.all([
      readTree(new URL("../src-tauri/src/", import.meta.url)),
      readTree(new URL("../src/", import.meta.url)),
    ]);

    // Only names sitting in an emit call — plenty of scheme-shaped strings in
    // this tree are routes or URLs, not events.
    const emitted = new Set(
      [...rust.matchAll(/\bemit(?:_to)?\(\s*(?:&?\w+\s*,\s*)?"([a-z]+:\/\/[a-z0-9-]+)"/g)].map(
        (match) => match[1],
      ),
    );
    assert.ok(
      emitted.size >= 20,
      `only ${emitted.size} emitted events found — the emit call shape probably changed and this test stopped looking`,
    );

    for (const event of emitted) {
      if (KNOWN_UNCONSUMED.has(event)) continue;
      assert.ok(
        frontend.includes(`"${event}"`),
        `${event} is emitted but never referenced under src/ — add a listener, stop emitting it, ` +
          "or list it in KNOWN_UNCONSUMED with the reason",
      );
    }

    // The other direction, so the list cannot rot: an entry that is no longer
    // emitted, or that someone quietly gave a listener, has to be removed.
    for (const event of KNOWN_UNCONSUMED) {
      assert.ok(emitted.has(event), `${event} is in KNOWN_UNCONSUMED but nothing emits it any more`);
      assert.ok(
        !frontend.includes(`"${event}"`),
        `${event} now has a frontend reference — take it out of KNOWN_UNCONSUMED`,
      );
    }
  });
});
