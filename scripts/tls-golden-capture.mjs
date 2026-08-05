#!/usr/bin/env node
/**
 * Low-cost TLS golden capture / refresh entrypoint.
 *
 * Prefers tool self-connect (curl-impersonate / curl_cffi) so adding a Chrome
 * major does not require downloading a full browser. Browser capture remains a
 * separate path for browser-matched only.
 *
 * Honesty:
 * - Never invent JA3 strings.
 * - Never promote pending entries to tool-matched without a real capture.
 * - If the tool binary is missing, print a single honest skip line and exit 0
 *   (or exit 2 when --require-tool is set). Do not silently pretend success.
 *
 * Usage:
 *   node scripts/tls-golden-capture.mjs --dry-run
 *   node scripts/tls-golden-capture.mjs --preset chrome150 --platform desktop-windows
 *   node scripts/tls-golden-capture.mjs --list-tools
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const goldenDir = join(root, "src-tauri/testdata/tls-golden");
const entriesDir = join(goldenDir, "entries");
const inventoryPath = join(
  goldenDir,
  "fingerprint-reference/sources-inventory.json",
);
const matrixPath = join(
  goldenDir,
  "fingerprint-reference/version-matrix.json",
);

function parseArgs(argv) {
  const out = {
    dryRun: false,
    listTools: false,
    requireTool: false,
    write: false,
    validateOnly: false,
    /** auto | tool | measure-rustls */
    mode: "auto",
    preset: "chrome150",
    platform: "desktop-windows",
    probeUrl: process.env.TLS_GOLDEN_PROBE_URL || "https://tls.browserleaks.com/json",
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") out.dryRun = true;
    else if (a === "--list-tools") out.listTools = true;
    else if (a === "--require-tool") out.requireTool = true;
    else if (a === "--write") out.write = true;
    else if (a === "--validate-only") out.validateOnly = true;
    else if (a === "--mode") out.mode = argv[++i] || "auto";
    else if (a === "--preset") out.preset = argv[++i];
    else if (a === "--platform") out.platform = argv[++i];
    else if (a === "--probe-url") out.probeUrl = argv[++i];
    else if (a === "--help" || a === "-h") out.help = true;
    // npm on Windows sometimes strips leading -- flags; accept bare tokens.
    else if (!a.startsWith("-") && /^chrome[a-z0-9-]*\d+$/i.test(a) && out.preset === "chrome150") {
      out.preset = a;
    } else if (
      !a.startsWith("-") &&
      /^(desktop-|android|ios)/.test(a) &&
      out.platform === "desktop-windows"
    ) {
      out.platform = a;
    }
  }
  return out;
}

/**
 * Pure structural validation used by tests and --validate-only.
 * Throws on contract violations; returns a summary object on success.
 */
export function validateGoldenTree() {
  const inventory = loadInventory();
  const matrix = loadMatrix();
  const entries = listEntries();
  const entryKeys = new Set(entries.map((e) => `${e.entry.presetId}--${e.entry.platform}`));
  for (const row of matrix.matrix) {
    const key = `${row.presetId}--${row.platform}`;
    if (!entryKeys.has(key)) {
      throw new Error(`version-matrix references missing entry ${key}`);
    }
    if (row.status === "pending-capture" && row.alignment !== "recipe") {
      throw new Error(`${key}: pending matrix row must stay recipe`);
    }
  }
  for (const { file, entry } of entries) {
    if (entry.status === "pending-capture") {
      if (entry.alignment !== "recipe") {
        throw new Error(`${file}: pending-capture must be recipe`);
      }
      for (const [k, v] of Object.entries(entry.golden)) {
        if (v != null) throw new Error(`${file}: golden.${k} must be null while pending`);
      }
    }
  }
  return {
    sources: inventory.sources.length,
    entries: entries.length,
    matrix: matrix.matrix.length,
    lowCostSources: inventory.sources.filter((s) => s.captureCost === "low-tool").map((s) => s.id),
  };
}

function which(cmd) {
  const isWin = process.platform === "win32";
  const checker = isWin ? "where" : "which";
  const r = spawnSync(checker, [cmd], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const line = (r.stdout || "").split(/\r?\n/).map((s) => s.trim()).find(Boolean);
  return line || null;
}

function toolCandidates(preset) {
  const major = (preset.match(/(\d+)$/) || [])[1];
  const names = [];
  if (major) {
    names.push(`curl_chrome${major}`);
    names.push(`curl-impersonate-chrome${major}`);
  }
  names.push("curl-impersonate", "curl_chrome", "curl-cffi");
  return names;
}

function detectTools(preset) {
  const found = [];
  for (const name of toolCandidates(preset)) {
    const path = which(name);
    if (path) found.push({ name, path });
  }
  // python -m curl_cffi / curl_cffi CLI via python
  const py = which("python") || which("python3") || which("py");
  if (py) {
    const r = spawnSync(py, ["-c", "import curl_cffi; print(curl_cffi.__version__)"], {
      encoding: "utf8",
    });
    if (r.status === 0) {
      found.push({
        name: "python-curl_cffi",
        path: py,
        version: (r.stdout || "").trim(),
      });
    }
  }
  return found;
}

function loadInventory() {
  const inv = JSON.parse(readFileSync(inventoryPath, "utf8"));
  if (!Array.isArray(inv.sources) || inv.sources.length < 3) {
    throw new Error("inventory must list ≥3 sources");
  }
  for (const s of inv.sources) {
    if (!s.id || !s.url || !s.claimedVersionsNote) {
      throw new Error(`inventory source missing required fields: ${s.id || "?"}`);
    }
    if (!/^https:\/\//.test(s.url)) {
      throw new Error(`inventory source ${s.id} url must be https`);
    }
  }
  return inv;
}

function loadMatrix() {
  return JSON.parse(readFileSync(matrixPath, "utf8"));
}

function listEntries() {
  return readdirSync(entriesDir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((file) => {
      const entry = JSON.parse(readFileSync(join(entriesDir, file), "utf8"));
      return { file, entry };
    });
}

function printHelp() {
  console.log(`tls-golden-capture — low-cost tool-based golden path

Options:
  --dry-run              Validate inventory + matrix; list tools; do not capture
  --validate-only        Structural validation only (no tool detection / network)
  --list-tools           Print detected capture tools for --preset
  --mode <auto|tool|measure-rustls>
                         auto (default): external tool, else local rustls probe measure
                         tool: curl-impersonate / curl_cffi only
                         measure-rustls: local tls-golden-probe (recipe only)
  --preset <id>          Catalog preset (default chrome150)
  --platform <plat>      Platform key (default desktop-windows)
  --probe-url <url>      Optional live probe (default tls.browserleaks.com/json)
  --write                Annotate entry notes if a tool returns parseable JA3
  --require-tool         Exit 2 when no external tool is installed
  -h, --help             This help

Honesty: never invents JA3; never claims browser-matched from tools.
measure-rustls uses the real loopback ClientHello probe but alignment ceiling is recipe only.
Full status=captured + tool-matched still needs an external tool capture + clientHelloHex.
`);
}

function findTlsGoldenProbeBinary() {
  const candidates = [
    join(root, "src-tauri/target/debug/tls-golden-probe.exe"),
    join(root, "src-tauri/target/debug/tls-golden-probe"),
    join(root, "src-tauri/target/release/tls-golden-probe.exe"),
    join(root, "src-tauri/target/release/tls-golden-probe"),
  ];
  return candidates.find((p) => existsSync(p)) || null;
}

/**
 * Drive the shipped Rust `tls-golden-probe` against the real ClientHello probe.
 * Prefers an already-built binary; falls back to `cargo run`.
 * Returns parsed JSON or { ok:false }.
 */
export function measureRustlsViaProbe(preset) {
  const built = findTlsGoldenProbeBinary();
  let r;
  if (built) {
    r = spawnSync(built, ["measure-rustls", "--preset", preset], {
      encoding: "utf8",
      cwd: root,
      timeout: 60000,
    });
  } else {
    const rustStable = join(root, "scripts/rust-stable.mjs");
    r = spawnSync(
      process.execPath,
      [
        rustStable,
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        join(root, "src-tauri/Cargo.toml"),
        "--bin",
        "tls-golden-probe",
        "--",
        "measure-rustls",
        "--preset",
        preset,
      ],
      { encoding: "utf8", cwd: root, timeout: 300000 },
    );
  }
  if (r.status !== 0) {
    return {
      ok: false,
      error: `tls-golden-probe failed (status=${r.status}): ${(r.stderr || r.stdout || "").slice(0, 400)}`,
    };
  }
  const text = (r.stdout || "").trim();
  // cargo may print warnings; find the JSON object
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < start) {
    return { ok: false, error: `no JSON from tls-golden-probe: ${text.slice(0, 200)}` };
  }
  try {
    return JSON.parse(text.slice(start, end + 1));
  } catch (e) {
    return { ok: false, error: `parse tls-golden-probe JSON: ${e.message}` };
  }
}

function tryCaptureWithCurlCffi(tools, preset, probeUrl) {
  const py = tools.find((t) => t.name === "python-curl_cffi");
  if (!py) return null;

  // Map shownet preset -> curl_cffi impersonate string when possible.
  const impersonate = preset.startsWith("chrome-android")
    ? preset.replace("chrome-android", "chrome") + "_android"
    : preset.startsWith("safari-ios")
      ? "safari_ios"
      : preset;

  const code = `
import json, sys
try:
    from curl_cffi import requests as r
except Exception as e:
    print(json.dumps({"ok": False, "error": f"import: {e}"}))
    sys.exit(0)
try:
    resp = r.get(${JSON.stringify(probeUrl)}, impersonate=${JSON.stringify(impersonate)}, timeout=30)
    data = resp.json() if resp.headers.get("content-type","").startswith("application/json") else {}
    ja3 = data.get("ja3_hash") or data.get("ja3n_hash") or data.get("ja3")
    print(json.dumps({"ok": True, "impersonate": ${JSON.stringify(impersonate)}, "status": resp.status_code, "ja3": ja3, "bodyKeys": list(data)[:20]}))
except Exception as e:
    print(json.dumps({"ok": False, "error": str(e), "impersonate": ${JSON.stringify(impersonate)}}))
`;
  const r = spawnSync(py.path, ["-c", code], { encoding: "utf8", timeout: 60000 });
  const line = (r.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop();
  if (!line) {
    return { ok: false, error: `curl_cffi produced no stdout (stderr=${(r.stderr || "").slice(0, 200)})` };
  }
  try {
    return JSON.parse(line);
  } catch {
    return { ok: false, error: `unparseable curl_cffi output: ${line.slice(0, 200)}` };
  }
}

function tryCaptureWithCurlBinary(tools, preset, probeUrl) {
  const major = (preset.match(/(\d+)$/) || [])[1];
  const preferred = tools.find(
    (t) => major && (t.name === `curl_chrome${major}` || t.name.includes(major)),
  ) || tools.find((t) => t.name.startsWith("curl_chrome") || t.name.includes("impersonate"));
  if (!preferred || preferred.name === "python-curl_cffi") return null;

  const r = spawnSync(preferred.path, ["-sS", probeUrl], {
    encoding: "utf8",
    timeout: 60000,
  });
  if (r.status !== 0) {
    return { ok: false, error: `binary ${preferred.name} failed: ${(r.stderr || r.stdout || "").slice(0, 200)}` };
  }
  try {
    const data = JSON.parse(r.stdout);
    const ja3 = data.ja3_hash || data.ja3n_hash || data.ja3 || null;
    return { ok: true, tool: preferred.name, ja3, bodyKeys: Object.keys(data).slice(0, 20) };
  } catch {
    return {
      ok: false,
      error: `binary ${preferred.name} returned non-JSON (need a JA3 probe endpoint)`,
    };
  }
}

function writeCapturedEntry(preset, platform, result, toolLabel) {
  const file = `${preset}--${platform}.json`;
  const path = join(entriesDir, file);
  if (!existsSync(path)) {
    throw new Error(`missing entry stub: ${file}`);
  }
  const entry = JSON.parse(readFileSync(path, "utf8"));
  if (!result.ja3 || !/^[0-9a-f]{32}$/i.test(result.ja3)) {
    throw new Error("refusing to write: capture did not yield a 32-hex JA3");
  }
  // We only accept tool path here; clientHelloHex remains required for full gate use.
  // Without raw ClientHello we keep pending-capture (honesty: incomplete capture).
  console.log(
    `capture produced ja3=${result.ja3.toLowerCase()} via ${toolLabel}; ` +
      "raw ClientHello not available from this probe — entry stays pending-capture " +
      "(fill clientHelloHex via local probe for full captured status).",
  );
  entry.notes =
    (entry.notes || "") +
    ` | tool-observed-ja3=${result.ja3.toLowerCase()} tool=${toolLabel} at ${new Date().toISOString().slice(0, 10)} (not promoted: missing clientHelloHex)`;
  writeFileSync(path, JSON.stringify(entry, null, 2) + "\n", "utf8");
  return entry;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  if (args.validateOnly) {
    const summary = validateGoldenTree();
    console.log(
      `validate-only ok: sources=${summary.sources} entries=${summary.entries} matrix=${summary.matrix}`,
    );
    console.log(`low-cost sources: ${summary.lowCostSources.join(", ")}`);
    process.exit(0);
  }

  const inventory = loadInventory();
  const matrix = loadMatrix();
  const entries = listEntries();

  console.log(
    `tls-golden-capture: inventory sources=${inventory.sources.length} entries=${entries.length} matrix=${matrix.matrix.length}`,
  );

  if (args.listTools || args.dryRun) {
    const tools = detectTools(args.preset);
    console.log(`tools for preset=${args.preset}:`);
    if (tools.length === 0) {
      console.log("  (none detected)");
    } else {
      for (const t of tools) {
        console.log(`  - ${t.name}${t.version ? ` v${t.version}` : ""} @ ${t.path}`);
      }
    }
    console.log("inventory:");
    for (const s of inventory.sources) {
      console.log(`  - ${s.id}: ${s.url}`);
      console.log(`    families=${s.claimedFamilies.join(",")} cost=${s.captureCost} align<=${s.mayAuthoriseAlignment}`);
    }
    const pending = entries.filter((e) => e.entry.status === "pending-capture");
    console.log(`pending-capture entries: ${pending.length}`);
    for (const e of pending.slice(0, 20)) {
      console.log(`  - ${e.file}`);
    }
    if (args.dryRun) {
      console.log("dry-run ok: inventory + matrix validated; no tool capture attempted.");
      process.exit(0);
    }
    if (args.listTools) process.exit(0);
  }

  const tools = detectTools(args.preset);
  const wantTool = args.mode === "auto" || args.mode === "tool";
  const wantRustls = args.mode === "auto" || args.mode === "measure-rustls";

  if (wantTool && tools.length > 0) {
    console.log(
      `attempting tool capture preset=${args.preset} platform=${args.platform} tools=${tools.map((t) => t.name).join(",")}`,
    );
    let result =
      tryCaptureWithCurlCffi(tools, args.preset, args.probeUrl) ||
      tryCaptureWithCurlBinary(tools, args.preset, args.probeUrl);

    if (result?.ok) {
      console.log("capture-result:", JSON.stringify(result));
      if (args.write) {
        writeCapturedEntry(args.preset, args.platform, result, result.tool || "curl_cffi");
      } else {
        console.log(
          "capture observed (not written; pass --write to annotate entry notes). " +
            "Full status=captured still requires clientHelloHex from local tls-golden-probe wait mode.",
        );
      }
      process.exit(0);
    }
    if (result && !result.ok) {
      console.log(`tool capture failed honestly: ${result.error || "unknown"}`);
      if (args.mode === "tool") process.exit(1);
    }
  }

  if (wantTool && tools.length === 0 && args.mode === "tool") {
    console.log("tool not installed / capture skipped");
    console.log(
      `hint: install curl-impersonate or pip install curl_cffi, then re-run for ${args.preset} (${args.platform})`,
    );
    process.exit(args.requireTool ? 2 : 0);
  }

  if (wantRustls) {
    console.log(
      `attempting local probe measure-rustls preset=${args.preset} (alignment ceiling: recipe only)`,
    );
    const measured = measureRustlsViaProbe(args.preset);
    console.log("measure-rustls-result:", JSON.stringify(measured));
    if (!measured.ok) {
      if (args.mode === "measure-rustls") {
        console.log(`measure-rustls failed honestly: ${measured.error || "unknown"}`);
        process.exit(1);
      }
      console.log("tool not installed / capture skipped");
      console.log(`hint: rustls measure also failed: ${measured.error || "unknown"}`);
      process.exit(args.requireTool ? 2 : 0);
    }
    const ja3 = measured.golden?.ja3;
    console.log(
      `recipe measure ok ja3=${ja3} clientHelloHexLen=${(measured.golden?.clientHelloHex || "").length} ` +
        "(NOT tool-matched; NOT written as golden unless you manually review)",
    );
    if (args.write) {
      console.log(
        "refusing --write for measure-rustls: would invent a false tool/browser golden from rustls recipe",
      );
      process.exit(3);
    }
    process.exit(0);
  }

  console.log("tool not installed / capture skipped");
  process.exit(args.requireTool ? 2 : 0);
}

function isMainModule() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return /tls-golden-capture\.mjs$/i.test(entry.replace(/\\/g, "/"));
  }
}

// Only run CLI when executed directly (tests may import validateGoldenTree).
if (isMainModule()) {
  try {
    main();
  } catch (err) {
    console.error("tls-golden-capture error:", err?.message || err);
    process.exit(1);
  }
}
