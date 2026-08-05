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
});
