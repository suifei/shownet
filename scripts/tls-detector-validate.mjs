#!/usr/bin/env node
/**
 * Validate outbound TLS fingerprints against public JA3/JA4 detector sites.
 *
 * Inventory: src-tauri/testdata/tls-golden/fingerprint-reference/detector-sites.json
 *
 * Honesty:
 * - A detector returning a fingerprint ≠ browser parity / 100% Chrome pass.
 * - recipe/node client path never sets fullBrowserPassClaim=true.
 * - tool client (curl_cffi) may report tool-matched ceiling but still not browser-matched.
 * - Never invent fingerprints; unreachable sites → skip with reason.
 *
 * Usage:
 *   node scripts/tls-detector-validate.mjs
 *   node scripts/tls-detector-validate.mjs --client node --out-dir ./tmp
 *   node scripts/tls-detector-validate.mjs --offline-fixtures
 *   node scripts/tls-detector-validate.mjs --preset chrome150
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const refDir = join(root, "src-tauri/testdata/tls-golden/fingerprint-reference");
const inventoryPath = join(refDir, "detector-sites.json");
const fixturesDir = join(refDir, "fixtures");

function parseArgs(argv) {
  const out = {
    client: "auto", // auto | node | tool | offline
    preset: "chrome150",
    outDir: null,
    offlineFixtures: false,
    timeoutMs: 20000,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--client") out.client = argv[++i] || "auto";
    else if (a === "--preset") out.preset = argv[++i] || "chrome150";
    else if (a === "--out-dir") out.outDir = argv[++i];
    else if (a === "--offline-fixtures") out.offlineFixtures = true;
    else if (a === "--timeout-ms") out.timeoutMs = Number(argv[++i]) || 20000;
    else if (a === "-h" || a === "--help") out.help = true;
  }
  return out;
}

export function loadDetectorInventory() {
  const inv = JSON.parse(readFileSync(inventoryPath, "utf8"));
  if (!Array.isArray(inv.detectors) || inv.detectors.length < 3) {
    throw new Error("detector inventory must list ≥3 endpoints");
  }
  for (const d of inv.detectors) {
    if (!d.id || !d.url || !/^https:\/\//.test(d.url)) {
      throw new Error(`invalid detector entry: ${d.id || "?"}`);
    }
    if (!d.fields || !Array.isArray(d.fields.ja3) || !Array.isArray(d.fields.ja4)) {
      throw new Error(`${d.id}: fields.ja3 and fields.ja4 required arrays`);
    }
  }
  if (!inv.honesty?.detectorPassIsNotBrowserParity) {
    throw new Error("honesty.detectorPassIsNotBrowserParity must be true");
  }
  return inv;
}

/** Resolve dotted path; supports simple a.b.c */
export function getPath(obj, path) {
  if (!path) return undefined;
  const parts = path.split(".");
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") return undefined;
    cur = cur[p];
  }
  return cur;
}

export function firstPath(obj, paths) {
  for (const p of paths || []) {
    const v = getPath(obj, p);
    if (v != null && v !== "") return String(v);
  }
  return null;
}

/**
 * Extract fingerprint fields from a detector JSON body using inventory field map.
 * For JA3 prefer a 32-hex digest when multiple paths exist (e.g. scrapfly returns both).
 */
export function extractFingerprints(body, detector) {
  let ja3 = null;
  let ja3Raw = firstPath(body, detector.fields.ja3Raw || []);
  for (const p of detector.fields.ja3 || []) {
    const v = getPath(body, p);
    if (v == null || v === "") continue;
    const s = String(v);
    if (/^[0-9a-f]{32}$/i.test(s)) {
      ja3 = s.toLowerCase();
      break;
    }
    // keep first non-hash as raw fallback, continue seeking a digest
    if (!ja3Raw && s.includes(",")) ja3Raw = s;
    if (!ja3 && !/^[0-9a-f]{32}$/i.test(s)) {
      // do not treat long cipher lists as ja3 hash
    }
  }
  if (!ja3) {
    // last resort: any path value that looks like md5
    for (const p of detector.fields.ja3 || []) {
      const s = String(getPath(body, p) ?? "");
      if (/^[0-9a-f]{32}$/i.test(s)) {
        ja3 = s.toLowerCase();
        break;
      }
    }
  }
  const ja4 = firstPath(body, detector.fields.ja4);
  const ja4Raw = firstPath(body, detector.fields.ja4Raw || []);
  const extra = {};
  for (const p of detector.fields.extra || []) {
    const v = getPath(body, p);
    if (v != null && typeof v !== "object") extra[p] = String(v);
  }
  return { ja3, ja3Raw, ja4, ja4Raw, extra };
}

/**
 * Status for one detector hit under a given alignment ceiling.
 * "pass" = non-empty parseable JA3 and/or JA4 (site responded with usable FP).
 * Does NOT mean Chrome browser match.
 */
export function evaluateDetectorRow({ extract, httpStatus, error, alignmentCeiling }) {
  if (error) {
    return {
      status: "skip",
      reason: error,
      browserMatchClaim: false,
    };
  }
  if (httpStatus && (httpStatus < 200 || httpStatus >= 300)) {
    return {
      status: "fail",
      reason: `HTTP ${httpStatus}`,
      browserMatchClaim: false,
    };
  }
  const hasJa3 = Boolean(extract?.ja3 && /^[0-9a-f]{32}$/i.test(extract.ja3));
  const hasJa4 = Boolean(extract?.ja4 && String(extract.ja4).length >= 8);
  if (!hasJa3 && !hasJa4) {
    return {
      status: "fail",
      reason: "response missing parseable ja3 hash and ja4",
      browserMatchClaim: false,
    };
  }
  // Sites that only advertise JA4 (empty ja3 field list) may pass on JA4 alone.
  return {
    status: "pass",
    reason: hasJa3 && hasJa4 ? "ja3+ja4 observed" : hasJa3 ? "ja3 observed" : "ja4 observed",
    browserMatchClaim: false,
    alignmentCeiling,
  };
}

function detectCurlCffi() {
  for (const py of ["python", "python3", "py"]) {
    const r = spawnSync(py, ["-c", "import curl_cffi; print(curl_cffi.__version__)"], {
      encoding: "utf8",
    });
    if (r.status === 0) {
      return { python: py, version: (r.stdout || "").trim() };
    }
  }
  return null;
}

async function fetchWithNode(url, timeoutMs) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: { Accept: "application/json", "User-Agent": "ShowNet-tls-detector-validate/1.0" },
    });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    return { httpStatus: res.status, body: json, rawText: text.slice(0, 500), client: "node" };
  } finally {
    clearTimeout(t);
  }
}

function fetchWithCurlCffi(url, preset, timeoutMs) {
  const tool = detectCurlCffi();
  if (!tool) return { error: "curl_cffi not installed", client: "tool" };
  const impersonate = preset.startsWith("chrome") ? preset : "chrome";
  const code = `
import json, sys
from curl_cffi import requests
try:
    r = requests.get(${JSON.stringify(url)}, impersonate=${JSON.stringify(impersonate)}, timeout=${Math.max(5, Math.floor(timeoutMs / 1000))})
    try:
        body = r.json()
    except Exception:
        body = None
    print(json.dumps({"httpStatus": r.status_code, "body": body, "rawText": (r.text or "")[:500]}))
except Exception as e:
    print(json.dumps({"error": str(e)}))
`;
  const r = spawnSync(tool.python, ["-c", code], { encoding: "utf8", timeout: timeoutMs + 5000 });
  const line = (r.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop();
  if (!line) {
    return { error: `curl_cffi empty stdout: ${(r.stderr || "").slice(0, 200)}`, client: "tool" };
  }
  try {
    const parsed = JSON.parse(line);
    return { ...parsed, client: "tool", toolVersion: tool.version };
  } catch {
    return { error: `curl_cffi unparseable: ${line.slice(0, 200)}`, client: "tool" };
  }
}

function measureLocalRustls(preset) {
  try {
    // Dynamic import of capture helper (same process / sibling script).
    // Use spawn of probe binary for isolation.
    const candidates = [
      join(root, "src-tauri/target/debug/tls-golden-probe.exe"),
      join(root, "src-tauri/target/debug/tls-golden-probe"),
      join(root, "src-tauri/target/release/tls-golden-probe.exe"),
      join(root, "src-tauri/target/release/tls-golden-probe"),
    ];
    const bin = candidates.find((p) => existsSync(p));
    if (!bin) {
      return { ok: false, error: "tls-golden-probe binary not built" };
    }
    const r = spawnSync(bin, ["measure-rustls", "--preset", preset], {
      encoding: "utf8",
      timeout: 60000,
    });
    if (r.status !== 0) {
      return { ok: false, error: (r.stderr || r.stdout || "").slice(0, 300) };
    }
    const text = (r.stdout || "").trim();
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start < 0) return { ok: false, error: "no JSON from probe" };
    return JSON.parse(text.slice(start, end + 1));
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
}

export function buildReport({ inventory, rows, client, preset, localRustls }) {
  const nonSkip = rows.filter((r) => r.status !== "skip");
  const passes = nonSkip.filter((r) => r.status === "pass");
  const fails = nonSkip.filter((r) => r.status === "fail");
  const skips = rows.filter((r) => r.status === "skip");
  const reachabilityPct =
    nonSkip.length === 0 ? 0 : Math.round((passes.length / nonSkip.length) * 1000) / 10;

  const alignmentCeiling =
    client === "tool" ? "tool-matched" : client === "offline" ? "recipe" : "recipe";

  // Never claim full browser 100% from detector reachability alone.
  const fullBrowserPassClaim = false;
  const chromeMatch100Claim = false;
  const allNonSkipPass = nonSkip.length > 0 && fails.length === 0;

  return {
    ok: true,
    presetId: preset,
    client,
    alignmentCeiling,
    generatedAt: new Date().toISOString(),
    honesty: {
      ...inventory.honesty,
      fullBrowserPassClaim,
      chromeMatch100Claim,
      note:
        "pass = detector returned parseable JA3/JA4 for this client stack; NOT Chrome browser parity. ja3Parity remains product-false under rustls-only.",
    },
    summary: {
      total: rows.length,
      pass: passes.length,
      fail: fails.length,
      skip: skips.length,
      detectorReachabilityPct: reachabilityPct,
      allNonSkipPass,
      // Explicit: do not rename reachability into browser 100%.
      claimBrowserHundredPercent: false,
    },
    localRustlsBaseline: localRustls?.ok
      ? {
          ja3: localRustls.golden?.ja3 ?? null,
          ja4: localRustls.golden?.ja4 ?? null,
          alignmentCeiling: "recipe",
          honesty: localRustls.honesty || "rustls recipe only",
        }
      : { error: localRustls?.error || "not measured" },
    rows,
  };
}

async function runLive(args, inventory) {
  let client = args.client;
  if (client === "auto") {
    client = detectCurlCffi() ? "tool" : "node";
  }
  if (client === "tool" && !detectCurlCffi()) {
    console.log("tool not installed / falling back to node client");
    client = "node";
  }

  const alignmentCeiling = client === "tool" ? "tool-matched" : "recipe";
  const rows = [];

  for (const detector of inventory.detectors) {
    process.stderr.write(`hitting ${detector.id} via ${client}…\n`);
    let hit;
    try {
      if (client === "tool") {
        hit = fetchWithCurlCffi(detector.url, args.preset, args.timeoutMs);
      } else {
        hit = await fetchWithNode(detector.url, args.timeoutMs);
      }
    } catch (e) {
      hit = { error: String(e.message || e), client };
    }

    if (hit.error) {
      const evalRow = evaluateDetectorRow({
        extract: null,
        error: hit.error,
        alignmentCeiling,
      });
      rows.push({
        id: detector.id,
        url: detector.url,
        client: hit.client || client,
        status: evalRow.status,
        reason: evalRow.reason,
        ja3: null,
        ja4: null,
        browserMatchClaim: false,
        alignmentCeiling,
      });
      continue;
    }

    if (!hit.body || typeof hit.body !== "object") {
      const evalRow = evaluateDetectorRow({
        extract: null,
        httpStatus: hit.httpStatus,
        error: hit.httpStatus ? null : "non-JSON body",
        alignmentCeiling,
      });
      rows.push({
        id: detector.id,
        url: detector.url,
        client: hit.client || client,
        httpStatus: hit.httpStatus,
        status: hit.httpStatus && hit.httpStatus >= 200 && hit.httpStatus < 300 ? "fail" : evalRow.status,
        reason:
          hit.httpStatus && hit.httpStatus >= 200 && hit.httpStatus < 300
            ? "non-JSON body"
            : evalRow.reason,
        ja3: null,
        ja4: null,
        browserMatchClaim: false,
        alignmentCeiling,
        rawPreview: hit.rawText?.slice?.(0, 120) || null,
      });
      continue;
    }

    const extract = extractFingerprints(hit.body, detector);
    const evalRow = evaluateDetectorRow({
      extract,
      httpStatus: hit.httpStatus,
      alignmentCeiling,
    });
    rows.push({
      id: detector.id,
      url: detector.url,
      client: hit.client || client,
      httpStatus: hit.httpStatus,
      status: evalRow.status,
      reason: evalRow.reason,
      ja3: extract.ja3,
      ja3Raw: extract.ja3Raw,
      ja4: extract.ja4,
      ja4Raw: extract.ja4Raw,
      extra: extract.extra,
      browserMatchClaim: false,
      alignmentCeiling,
    });
  }

  const localRustls = measureLocalRustls(args.preset);
  return buildReport({ inventory, rows, client, preset: args.preset, localRustls });
}

export function runOfflineFixtures(inventory) {
  const fixtureMap = {
    "browserleaks-tls-json": "browserleaks-tls.json",
    "peet-tls-api-all": "peet-api-all.json",
    "ja3-zone-check": "ja3-zone.json",
  };
  const rows = [];
  for (const detector of inventory.detectors) {
    const fname = fixtureMap[detector.id];
    if (!fname) {
      rows.push({
        id: detector.id,
        url: detector.url,
        client: "offline",
        status: "skip",
        reason: "no offline fixture for this detector",
        ja3: null,
        ja4: null,
        browserMatchClaim: false,
        alignmentCeiling: "recipe",
      });
      continue;
    }
    const body = JSON.parse(readFileSync(join(fixturesDir, fname), "utf8"));
    const extract = extractFingerprints(body, detector);
    const evalRow = evaluateDetectorRow({ extract, httpStatus: 200, alignmentCeiling: "recipe" });
    rows.push({
      id: detector.id,
      url: detector.url,
      client: "offline",
      httpStatus: 200,
      status: evalRow.status,
      reason: evalRow.reason,
      ja3: extract.ja3,
      ja4: extract.ja4,
      browserMatchClaim: false,
      alignmentCeiling: "recipe",
    });
  }
  return buildReport({
    inventory,
    rows,
    client: "offline",
    preset: "fixture",
    localRustls: { ok: false, error: "offline mode" },
  });
}

function printHelp() {
  console.log(`tls-detector-validate — hit public JA3/JA4 detector sites

Options:
  --client auto|node|tool|offline   TLS client used to hit detectors (default auto)
  --preset <id>                     Impersonate preset for tool client (default chrome150)
  --out-dir <dir>                   Write matrix JSON + summary
  --offline-fixtures                Parse canned fixtures only (no network)
  --timeout-ms <n>                  Per-request timeout (default 20000)
  -h, --help

Honesty: never claims fullBrowserPass / Chrome 100% from detector reachability alone.
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const inventory = loadDetectorInventory();
  console.log(
    `tls-detector-validate: detectors=${inventory.detectors.length} primary=${inventory.detectors.filter((d) => d.priority === "primary").length}`,
  );

  let report;
  if (args.offlineFixtures || args.client === "offline") {
    report = runOfflineFixtures(inventory);
  } else {
    report = await runLive(args, inventory);
  }

  // Console summary
  for (const row of report.rows) {
    console.log(
      `[${row.status}] ${row.id} ja3=${row.ja3 || "-"} ja4=${row.ja4 || "-"} :: ${row.reason}`,
    );
  }
  console.log(
    `summary: pass=${report.summary.pass} fail=${report.summary.fail} skip=${report.summary.skip} reachability=${report.summary.detectorReachabilityPct}% claimBrowserHundredPercent=${report.summary.claimBrowserHundredPercent}`,
  );
  console.log(
    `honesty: fullBrowserPassClaim=${report.honesty.fullBrowserPassClaim} alignmentCeiling=${report.alignmentCeiling}`,
  );

  const outDir =
    args.outDir ||
    process.env.SCRATCH ||
    process.env.SHOWNET_QA_SCRATCH ||
    join(root, "tmp", "ja3-detector");
  mkdirSync(outDir, { recursive: true });
  const matrixPath = join(outDir, "ja3-detector-matrix.json");
  writeFileSync(matrixPath, JSON.stringify(report, null, 2) + "\n", "utf8");
  console.log(`matrix written: ${matrixPath}`);

  // Exit: 0 if no hard fails (skips OK); 1 if any fail. Offline fixtures must all pass for mapped ids.
  if (report.summary.fail > 0) process.exit(1);
  process.exit(0);
}

function isMainModule() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return /tls-detector-validate\.mjs$/i.test(entry.replace(/\\/g, "/"));
  }
}

if (isMainModule()) {
  main().catch((err) => {
    console.error("tls-detector-validate error:", err?.message || err);
    process.exit(1);
  });
}
