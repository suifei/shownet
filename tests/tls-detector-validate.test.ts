import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const refDir = join(root, "src-tauri/testdata/tls-golden/fingerprint-reference");
const inventoryPath = join(refDir, "detector-sites.json");
const schemaPath = join(refDir, "detector-sites.schema.json");
const scriptPath = join(root, "scripts/tls-detector-validate.mjs");

describe("tls detector sites inventory", () => {
  it("ships ≥3 primary-capable public detector URLs with field maps", () => {
    assert.ok(existsSync(inventoryPath));
    assert.ok(existsSync(schemaPath));
    const inv = JSON.parse(readFileSync(inventoryPath, "utf8"));
    assert.equal(inv.honesty.detectorPassIsNotBrowserParity, true);
    assert.equal(inv.honesty.noSilentHundredPercentWithoutStack, true);
    assert.ok(inv.detectors.length >= 3);
    const ids = new Set<string>();
    for (const d of inv.detectors) {
      assert.ok(d.id && d.url.startsWith("https://"));
      assert.ok(d.uiUrl.startsWith("https://"));
      assert.ok(Array.isArray(d.fields.ja3));
      assert.ok(Array.isArray(d.fields.ja4));
      assert.ok(d.signals.length >= 1);
      assert.ok(!ids.has(d.id));
      ids.add(d.id);
    }
    // Industry-standard set required by the plan.
    assert.ok(ids.has("browserleaks-tls-json"));
    assert.ok(ids.has("peet-tls-api-all"));
    assert.ok(ids.has("scrapfly-fp-ja3"));
  });

  it("extractFingerprints parses real fixture shapes via shipped helpers", async () => {
    const mod = await import(pathToFileURL(scriptPath).href);
    const inv = mod.loadDetectorInventory();
    const bl = inv.detectors.find((d: { id: string }) => d.id === "browserleaks-tls-json");
    const body = JSON.parse(
      readFileSync(join(refDir, "fixtures/browserleaks-tls.json"), "utf8"),
    );
    const fp = mod.extractFingerprints(body, bl);
    assert.equal(fp.ja3, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert.ok(fp.ja4?.startsWith("t13d"));

    const peet = inv.detectors.find((d: { id: string }) => d.id === "peet-tls-api-all");
    const peetBody = JSON.parse(readFileSync(join(refDir, "fixtures/peet-api-all.json"), "utf8"));
    const pfp = mod.extractFingerprints(peetBody, peet);
    assert.equal(pfp.ja3, "dddddddddddddddddddddddddddddddd");
    assert.ok(pfp.ja4);

    const zone = inv.detectors.find((d: { id: string }) => d.id === "ja3-zone-check");
    const zBody = JSON.parse(readFileSync(join(refDir, "fixtures/ja3-zone.json"), "utf8"));
    const zfp = mod.extractFingerprints(zBody, zone);
    assert.equal(zfp.ja3, "11111111111111111111111111111111");
  });

  it("evaluateDetectorRow never claims browser match; empty FP fails", async () => {
    const mod = await import(pathToFileURL(scriptPath).href);
    const pass = mod.evaluateDetectorRow({
      extract: { ja3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ja4: "t13d1516h2_abc" },
      httpStatus: 200,
      alignmentCeiling: "recipe",
    });
    assert.equal(pass.status, "pass");
    assert.equal(pass.browserMatchClaim, false);

    const fail = mod.evaluateDetectorRow({
      extract: { ja3: null, ja4: null },
      httpStatus: 200,
      alignmentCeiling: "recipe",
    });
    assert.equal(fail.status, "fail");

    const skip = mod.evaluateDetectorRow({
      extract: null,
      error: "network down",
      alignmentCeiling: "recipe",
    });
    assert.equal(skip.status, "skip");
  });

  it("offline fixture run writes matrix without claiming browser 100%", () => {
    assert.ok(existsSync(scriptPath));
    const r = spawnSync(
      process.execPath,
      [scriptPath, "--offline-fixtures", "--out-dir", join(root, "tmp", "ja3-detector-test")],
      { encoding: "utf8", cwd: root },
    );
    assert.equal(r.status, 0, r.stderr || r.stdout);
    assert.match(r.stdout, /claimBrowserHundredPercent=false/);
    assert.match(r.stdout, /fullBrowserPassClaim=false/);
    assert.match(r.stdout, /matrix written:/);
    const matrixPath = join(root, "tmp/ja3-detector-test/ja3-detector-matrix.json");
    assert.ok(existsSync(matrixPath));
    const report = JSON.parse(readFileSync(matrixPath, "utf8"));
    assert.equal(report.honesty.fullBrowserPassClaim, false);
    assert.equal(report.summary.claimBrowserHundredPercent, false);
    assert.ok(report.rows.length >= 3);
    // Mapped fixtures must pass
    for (const id of ["browserleaks-tls-json", "peet-tls-api-all", "ja3-zone-check"]) {
      const row = report.rows.find((x: { id: string }) => x.id === id);
      assert.ok(row, id);
      assert.equal(row.status, "pass", id);
      assert.equal(row.browserMatchClaim, false);
    }
  });

  it("package.json wires detector validate scripts", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.match(pkg.scripts["tls-detector:validate"], /tls-detector-validate\.mjs/);
    assert.match(pkg.scripts["tls-detector:offline"], /offline-fixtures/);
    assert.match(pkg.scripts["test:tls-detector"], /tls-detector-validate\.test\.ts/);
  });
});
