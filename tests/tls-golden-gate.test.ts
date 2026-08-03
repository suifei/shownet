import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const goldenDir = join(root, "src-tauri/testdata/tls-golden");
const entriesDir = join(goldenDir, "entries");

type Golden = {
  presetId: string;
  platform: string;
  family: string;
  major: number;
  stack: string;
  stackVersion: string | null;
  status: "pending-capture" | "captured" | "superseded";
  alignment: "recipe" | "tool-matched" | "browser-matched";
  source: { kind: string; tool: string | null; environment: string | null; capturedAt: string | null };
  golden: {
    ja3: string | null;
    ja3Raw: string | null;
    ja4: string | null;
    ja4Raw: string | null;
    clientHelloHex: string | null;
  };
  notes: string | null;
};

async function loadEntries(): Promise<Array<{ file: string; entry: Golden }>> {
  const files = (await readdir(entriesDir)).filter((f) => f.endsWith(".json")).sort();
  return Promise.all(
    files.map(async (file) => ({
      file,
      entry: JSON.parse(await readFile(join(entriesDir, file), "utf8")) as Golden,
    })),
  );
}

describe("tls golden: honesty gate", () => {
  it("has a schema and at least the P0 matrix present", async () => {
    const schema = JSON.parse(await readFile(join(goldenDir, "schema.json"), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    const entries = await loadEntries();
    assert.ok(entries.length >= 5, `expected the P0 matrix, got ${entries.length} entries`);
  });

  it("file name matches the presetId and platform inside", async () => {
    for (const { file, entry } of await loadEntries()) {
      assert.equal(
        file,
        `${entry.presetId}--${entry.platform}.json`,
        `${file}: name must be <presetId>--<platform>.json`,
      );
    }
  });

  // The core contract: an uncaptured golden may never authorise an alignment claim.
  it("pending-capture entries carry no fingerprint data and stay at recipe", async () => {
    for (const { file, entry } of await loadEntries()) {
      if (entry.status !== "pending-capture") continue;
      assert.equal(entry.alignment, "recipe", `${file}: pending capture must stay at recipe`);
      assert.equal(entry.source.kind, "pending", `${file}: source.kind must be pending`);
      for (const [key, value] of Object.entries(entry.golden)) {
        assert.equal(value, null, `${file}: golden.${key} must be null while pending-capture`);
      }
    }
  });

  it("captured entries are complete and their alignment follows the capture source", async () => {
    for (const { file, entry } of await loadEntries()) {
      if (entry.status !== "captured") continue;
      assert.ok(entry.golden.clientHelloHex, `${file}: captured entry needs the raw ClientHello`);
      assert.match(entry.golden.ja3 ?? "", /^[0-9a-f]{32}$/, `${file}: ja3 must be an md5 hex digest`);
      assert.ok(entry.source.capturedAt, `${file}: captured entry needs capturedAt`);
      assert.ok(entry.source.environment, `${file}: captured entry needs a capture environment`);
      const expected = entry.source.kind === "browser-capture" ? "browser-matched" : "tool-matched";
      assert.equal(
        entry.alignment,
        expected,
        `${file}: source ${entry.source.kind} may only authorise ${expected}`,
      );
      if (entry.source.kind === "tool-capture") {
        assert.ok(entry.source.tool, `${file}: tool-capture must name the tool`);
      }
    }
  });

  // Anti-fabrication: the catalog's documentedJa3 values are reference material, not
  // measurements. Copying one into a golden would silently manufacture a passing gate.
  it("no golden reuses a documentedJa3 value from the catalog", async () => {
    const catalog = await readFile(join(root, "src-tauri/src/tls_clienthello_catalog.rs"), "utf8");
    const documented = new Set(
      [...catalog.matchAll(/Some\("([0-9a-f]{32})"\)/g)].map((m) => m[1]),
    );
    assert.ok(documented.size > 0, "expected documentedJa3 values in the catalog");
    for (const { file, entry } of await loadEntries()) {
      if (!entry.golden.ja3) continue;
      assert.ok(
        !documented.has(entry.golden.ja3),
        `${file}: golden.ja3 equals a catalog documentedJa3 value — goldens must come from a real capture`,
      );
    }
  });

  // Plan section 4.4/4.5: a desktop capture may never gate a mobile preset.
  it("mobile presets do not share a fingerprint with any desktop capture", async () => {
    const entries = await loadEntries();
    const desktopJa3 = new Set(
      entries
        .filter((e) => e.entry.platform.startsWith("desktop-") && e.entry.golden.ja3)
        .map((e) => e.entry.golden.ja3 as string),
    );
    for (const { file, entry } of entries) {
      if (entry.platform === "desktop-macos" || entry.platform === "desktop-windows") continue;
      if (entry.platform === "desktop-linux" || !entry.golden.ja3) continue;
      assert.ok(
        !desktopJa3.has(entry.golden.ja3),
        `${file}: mobile golden must not reuse a desktop fingerprint`,
      );
    }
  });

  it("apple clients are not labelled as BoringSSL", async () => {
    for (const { file, entry } of await loadEntries()) {
      if (entry.family !== "safari-ios" && entry.family !== "safari" && entry.family !== "chrome-ios") continue;
      assert.notEqual(
        entry.stack,
        "chromium-boringssl",
        `${file}: Apple clients use the system network stack, not BoringSSL`,
      );
    }
  });

  it("every entry references a preset id that exists in the catalog", async () => {
    const catalog = await readFile(join(root, "src-tauri/src/tls_clienthello_catalog.rs"), "utf8");
    const known = new Set([...catalog.matchAll(/id: *"([a-z0-9-]+)"/g)].map((m) => m[1]));
    for (const { file, entry } of await loadEntries()) {
      assert.ok(known.has(entry.presetId), `${file}: unknown presetId ${entry.presetId}`);
    }
  });
});
