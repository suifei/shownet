import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const goldenDir = join(root, "src-tauri/testdata/tls-golden");
const entriesDir = join(goldenDir, "entries");
const refDir = join(goldenDir, "fingerprint-reference");
const inventoryPath = join(refDir, "sources-inventory.json");
const inventorySchemaPath = join(refDir, "sources-inventory.schema.json");
const matrixPath = join(refDir, "version-matrix.json");

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

type InventorySource = {
  id: string;
  name: string;
  kind: string;
  url: string;
  claimedFamilies: string[];
  claimedVersionsNote: string;
  captureCost: string;
  mayAuthoriseAlignment: string;
  lastReviewed: string;
  binaryHints?: string[];
  notes?: string | null;
};

type Inventory = {
  schemaVersion: number;
  lastReviewed: string;
  honesty: {
    toolMatchedIsNotBrowserMatched: boolean;
    noInventedJa3: boolean;
    noDocumentedJa3AsGolden: boolean;
  };
  sources: InventorySource[];
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

  it("includes multi-version industry-floor stubs (chrome majors)", async () => {
    const entries = await loadEntries();
    const windowsChrome = entries
      .filter((e) => e.entry.platform === "desktop-windows" && e.entry.family === "chrome")
      .map((e) => e.entry.major)
      .sort((a, b) => a - b);
    for (const major of [120, 124, 131, 133, 144, 146, 149, 150]) {
      assert.ok(
        windowsChrome.includes(major),
        `expected chrome${major}--desktop-windows pending/captured stub`,
      );
    }
    assert.ok(entries.length >= 12, `expected multi-version matrix, got ${entries.length}`);
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

describe("tls golden: fingerprint-reference inventory", () => {
  it("inventory file and schema exist", async () => {
    assert.ok(existsSync(inventoryPath), "sources-inventory.json missing");
    assert.ok(existsSync(inventorySchemaPath), "sources-inventory.schema.json missing");
    assert.ok(existsSync(matrixPath), "version-matrix.json missing");
    assert.ok(existsSync(join(refDir, "README.md")), "fingerprint-reference README missing");
  });

  it("lists at least 3 external sources with required non-empty fields and https URLs", async () => {
    const inv = JSON.parse(await readFile(inventoryPath, "utf8")) as Inventory;
    assert.ok(inv.schemaVersion >= 1);
    assert.ok(inv.lastReviewed, "lastReviewed required");
    assert.equal(inv.honesty.toolMatchedIsNotBrowserMatched, true);
    assert.equal(inv.honesty.noInventedJa3, true);
    assert.equal(inv.honesty.noDocumentedJa3AsGolden, true);
    assert.ok(Array.isArray(inv.sources) && inv.sources.length >= 3, "need ≥3 sources");

    const ids = new Set<string>();
    for (const s of inv.sources) {
      assert.ok(s.id && s.id.trim(), "source.id empty");
      assert.ok(s.name && s.name.trim(), "source.name empty");
      assert.ok(s.url && /^https:\/\//.test(s.url), `${s.id}: url must be https`);
      assert.ok(
        s.claimedVersionsNote && s.claimedVersionsNote.length >= 8,
        `${s.id}: claimedVersionsNote required`,
      );
      assert.ok(Array.isArray(s.claimedFamilies) && s.claimedFamilies.length >= 1, `${s.id}: families`);
      assert.ok(s.lastReviewed, `${s.id}: lastReviewed required`);
      assert.ok(
        s.mayAuthoriseAlignment === "tool-matched" || s.mayAuthoriseAlignment === "none",
        `${s.id}: mayAuthoriseAlignment invalid`,
      );
      // Inventory must never claim browser-matched from a tool source field.
      assert.notEqual(
        (s as { mayAuthoriseAlignment: string }).mayAuthoriseAlignment,
        "browser-matched",
      );
      assert.ok(!ids.has(s.id), `duplicate source id ${s.id}`);
      ids.add(s.id);
    }
  });

  it("empty inventory or empty required source fields would fail the gate", async () => {
    // Structural negative checks against the loaded file (guards the contract).
    const inv = JSON.parse(await readFile(inventoryPath, "utf8")) as Inventory;
    assert.notEqual(inv.sources.length, 0, "empty inventory must fail");
    for (const s of inv.sources) {
      assert.notEqual(s.url, "", "empty url must fail");
      assert.notEqual(s.claimedVersionsNote, "", "empty claimedVersionsNote must fail");
    }
  });

  it("version-matrix covers multi-version chrome majors and matches entry files", async () => {
    const matrix = JSON.parse(await readFile(matrixPath, "utf8")) as {
      matrix: Array<{ presetId: string; platform: string; status: string; alignment: string }>;
    };
    assert.ok(matrix.matrix.length >= 12, "matrix too small");
    const entryFiles = new Set(
      (await readdir(entriesDir)).filter((f) => f.endsWith(".json")),
    );
    for (const row of matrix.matrix) {
      const name = `${row.presetId}--${row.platform}.json`;
      assert.ok(entryFiles.has(name), `matrix row missing entry file ${name}`);
      // Pending matrix rows must not claim matched alignment in the index.
      if (row.status === "pending-capture") {
        assert.equal(row.alignment, "recipe", `${name}: matrix pending must stay recipe`);
      }
    }
  });

  it("low-cost capture script exists", async () => {
    const script = join(root, "scripts/tls-golden-capture.mjs");
    assert.ok(existsSync(script), "scripts/tls-golden-capture.mjs missing");
    const body = await readFile(script, "utf8");
    assert.match(body, /tool not installed \/ capture skipped/);
    assert.match(body, /curl_cffi|curl-impersonate/);
  });

  it("version-matrix and entries/ stay bijective (no orphan files)", async () => {
    const matrix = JSON.parse(await readFile(matrixPath, "utf8")) as {
      matrix: Array<{ presetId: string; platform: string }>;
    };
    const matrixKeys = new Set(matrix.matrix.map((r) => `${r.presetId}--${r.platform}.json`));
    const entryFiles = (await readdir(entriesDir)).filter((f) => f.endsWith(".json"));
    for (const file of entryFiles) {
      assert.ok(matrixKeys.has(file), `entry ${file} missing from version-matrix.json`);
    }
    assert.equal(matrixKeys.size, entryFiles.length, "matrix size must equal entry file count");
  });

  it("validateGoldenTree from capture script validates the real tree", async () => {
    const scriptUrl = pathToFileURL(join(root, "scripts/tls-golden-capture.mjs")).href;
    const mod = await import(scriptUrl);
    assert.equal(typeof mod.validateGoldenTree, "function");
    const summary = mod.validateGoldenTree() as {
      sources: number;
      entries: number;
      lowCostSources: string[];
    };
    assert.ok(summary.sources >= 3, "inventory must list at least 3 sources");
    assert.ok(summary.entries >= 12, "multi-version matrix expected");
    assert.ok(summary.lowCostSources.length >= 1, "need at least one low-cost tool source");
  });

  it("capture CLI --validate-only exits 0 on the shipped tree", () => {
    const script = join(root, "scripts/tls-golden-capture.mjs");
    const r = spawnSync(process.execPath, [script, "--validate-only"], {
      encoding: "utf8",
      cwd: root,
    });
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.match(r.stdout, /validate-only ok:/);
    assert.match(r.stdout, /low-cost sources:/);
  });

  it("capture CLI without tools prints honest skip (or dry-run ok)", () => {
    const script = join(root, "scripts/tls-golden-capture.mjs");
    const dry = spawnSync(process.execPath, [script, "--dry-run", "--preset", "chrome150"], {
      encoding: "utf8",
      cwd: root,
    });
    assert.equal(dry.status, 0, dry.stderr || dry.stdout);
    assert.match(dry.stdout, /dry-run ok:|inventory sources=/);

    const capture = spawnSync(
      process.execPath,
      [script, "--preset", "chrome150", "--platform", "desktop-windows"],
      { encoding: "utf8", cwd: root, env: { ...process.env, PATH: process.env.PATH } },
    );
    // Either tool missing (honest skip) or tool present (capture-result / observed).
    assert.ok(
      capture.status === 0 || capture.status === 1,
      `unexpected exit ${capture.status}: ${capture.stderr}`,
    );
    const out = `${capture.stdout}\n${capture.stderr}`;
    assert.ok(
      /tool not installed \/ capture skipped|capture-result:|capture observed|capture failed honestly/.test(
        out,
      ),
      `expected honest skip or real capture output, got: ${out.slice(0, 400)}`,
    );
  });

  it("package.json wires tls-golden scripts to the real capture entry", async () => {
    const pkg = JSON.parse(await readFile(join(root, "package.json"), "utf8")) as {
      scripts: Record<string, string>;
    };
    assert.match(pkg.scripts["test:tls-golden"], /tls-golden-gate\.test\.ts/);
    assert.match(pkg.scripts["tls-golden:capture"], /tls-golden-capture\.mjs/);
    assert.match(pkg.scripts["tls-golden:capture:dry"], /--dry-run/);
  });
});
