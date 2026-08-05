import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const measureScript = join(root, "scripts/tls-impersonate-measure.mjs");
const goldenPath = join(
  root,
  "src-tauri/testdata/tls-golden/entries/chrome150--desktop-windows.json",
);

describe("Phase 1 tool impersonate measure", () => {
  it("ships measure entry and utls dial sources", () => {
    assert.ok(existsSync(measureScript));
    assert.ok(existsSync(join(root, "tools/utls-chrome-dial/main.go")));
    assert.ok(existsSync(join(root, "tools/utls-chrome-dial/go.mod")));
    const body = readFileSync(measureScript, "utf8");
    assert.match(body, /tool not installed \/ capture skipped/);
    assert.match(body, /tool-matched/);
    assert.match(body, /utls-chrome-dial/);
  });

  it("chrome150 desktop-windows golden is tool-capture when filled", () => {
    assert.ok(existsSync(goldenPath));
    const entry = JSON.parse(readFileSync(goldenPath, "utf8"));
    if (entry.status === "pending-capture") {
      // Environment without tool: still valid Phase1 honest state.
      assert.equal(entry.alignment, "recipe");
      return;
    }
    assert.equal(entry.status, "captured");
    assert.equal(entry.alignment, "tool-matched");
    assert.equal(entry.source.kind, "tool-capture");
    assert.ok(entry.source.tool);
    assert.ok(entry.source.capturedAt);
    assert.match(entry.golden.ja3 ?? "", /^[0-9a-f]{32}$/);
    assert.ok(entry.golden.clientHelloHex && entry.golden.clientHelloHex.length > 40);
    // Must never claim browser-matched from tool data.
    assert.notEqual(entry.alignment, "browser-matched");
    assert.notEqual(entry.source.kind, "browser-capture");
  });

  it("detectImpersonateTool and check-only use the real script entry", async () => {
    const mod = await import(pathToFileURL(measureScript).href);
    assert.equal(typeof mod.detectImpersonateTool, "function");
    const tool = mod.detectImpersonateTool();
    // Either utls binary / curl_cffi present, or honest null.
    if (!tool.kind) {
      assert.match(tool.detail || "", /tool not installed/);
    } else {
      assert.ok(tool.detail);
    }

    const r = spawnSync(process.execPath, [measureScript, "--check-only"], {
      encoding: "utf8",
      cwd: root,
    });
    // 0 = tool present, 2 = honest skip
    assert.ok(r.status === 0 || r.status === 2, r.stderr || r.stdout);
    if (r.status === 2) {
      assert.match(`${r.stdout}\n${r.stderr}`, /tool not installed \/ capture skipped/);
    } else {
      assert.match(r.stdout, /tool available:/);
    }
  });

  it("package.json wires phase1 measure and tool detector scripts", () => {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert.match(pkg.scripts["tls-impersonate:measure"], /tls-impersonate-measure/);
    assert.match(pkg.scripts["tls-detector:tool"], /--client tool/);
  });

  it("mapUtlsHello pins goldenable chrome majors to chrome102", async () => {
    const mod = await import(pathToFileURL(measureScript).href);
    assert.equal(mod.mapUtlsHello("chrome150"), "chrome102");
    assert.equal(mod.mapUtlsHello("chrome131"), "chrome102");
    assert.equal(mod.mapUtlsHello("chrome120"), "chrome102");
    assert.equal(mod.mapUtlsHello("chrome149"), "chrome102");
  });

  it("writeToolGoldenEntry persists the actual tool identity from the measure result", async () => {
    const mod = await import(pathToFileURL(measureScript).href);
    const cffiId = mod.toolIdentityFromResult({
      ok: true,
      presetId: "chrome150",
      toolKind: "curl_cffi",
      toolDetail: "curl_cffi 0.7.0 via python",
      toolVersion: "0.7.0",
      impersonateProfile: "chrome150",
      golden: {
        ja3: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ja3Raw: "raw",
        ja4: "t13d1516h2_test",
        ja4Raw: null,
        clientHelloHex: "1603",
      },
    });
    assert.match(cffiId.tool, /curl_cffi/);
    assert.doesNotMatch(cffiId.tool, /utls-chrome-dial/);
    assert.match(cffiId.stackVersion, /curl_cffi/);

    const utlsId = mod.toolIdentityFromResult({
      ok: true,
      presetId: "chrome150",
      toolKind: "utls-chrome-dial",
      toolDetail: "utls-chrome-dial @ /path/utls-chrome-dial.exe",
      utlsHello: "chrome102",
      impersonateProfile: "chrome150",
      golden: {
        ja3: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ja3Raw: null,
        ja4: "t13d1516h2_x",
        ja4Raw: null,
        clientHelloHex: "1603",
      },
    });
    assert.match(utlsId.tool, /utls/);
    assert.match(utlsId.stackVersion, /chrome102|pre-shuffle/i);
  });

  it("re-measure without --write-golden equals stored tool golden digests", async () => {
    const mod = await import(pathToFileURL(measureScript).href);
    const tool = mod.detectImpersonateTool();
    if (!tool.kind) {
      // Honest skip when no tool binary — not a silent green equality claim.
      console.log("re-measure skipped: tool not installed");
      return;
    }
    const entry = JSON.parse(readFileSync(goldenPath, "utf8"));
    if (entry.status !== "captured" || entry.source.kind !== "tool-capture") {
      console.log("re-measure skipped: no tool-capture golden committed");
      return;
    }
    assert.ok(entry.golden.ja3 && entry.golden.ja4 && entry.golden.clientHelloHex);

    // Real path: drive measure twice without writing; digests must match the golden.
    const first = await mod.measureToolClientHello({ preset: "chrome150", waitSeconds: 20 });
    const second = await mod.measureToolClientHello({ preset: "chrome150", waitSeconds: 20 });
    assert.equal(first.ok, true, first.reason || "first measure failed");
    assert.equal(second.ok, true, second.reason || "second measure failed");

    assert.equal(
      first.golden.ja4,
      entry.golden.ja4,
      "first re-measure JA4 must equal committed golden JA4",
    );
    assert.equal(
      second.golden.ja4,
      entry.golden.ja4,
      "second re-measure JA4 must equal committed golden JA4",
    );
    assert.equal(
      first.golden.ja3,
      entry.golden.ja3,
      "first re-measure JA3 must equal committed golden JA3 (pinned non-shuffle Hello)",
    );
    assert.equal(
      second.golden.ja3,
      first.golden.ja3,
      "JA3 must be stable across two re-measures with the pinned HelloID",
    );
  });
});
