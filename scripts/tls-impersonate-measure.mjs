#!/usr/bin/env node
/**
 * Phase 1: measure a curl-impersonate / curl_cffi ClientHello against the local
 * ShowNet ClientHello probe, optionally write a tool-matched golden.
 *
 * Flow:
 *   1. Detect curl_cffi (or curl_chrome* binary)
 *   2. Spawn tls-golden-probe wait (captures raw ClientHello)
 *   3. Connect the tool with impersonate=<preset> to the probe
 *   4. Emit measured golden JSON; optionally write entries/<preset>--<platform>.json
 *
 * Honesty:
 *   - Never invents JA3 / clientHelloHex
 *   - alignment ceiling is tool-matched only (never browser-matched)
 *   - product ja3Parity still requires the measure match + stack availability wiring
 *
 * Usage:
 *   node scripts/tls-impersonate-measure.mjs --preset chrome150 --platform desktop-windows
 *   node scripts/tls-impersonate-measure.mjs --preset chrome150 --write-golden
 *   node scripts/tls-impersonate-measure.mjs --check-only
 */

import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const entriesDir = join(root, "src-tauri/testdata/tls-golden/entries");

function parseArgs(argv) {
  const out = {
    preset: "chrome150",
    platform: process.platform === "win32" ? "desktop-windows" : process.platform === "darwin" ? "desktop-macos" : "desktop-linux",
    writeGolden: false,
    checkOnly: false,
    waitSeconds: 25,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--preset") out.preset = argv[++i] || out.preset;
    else if (a === "--platform") out.platform = argv[++i] || out.platform;
    else if (a === "--write-golden") out.writeGolden = true;
    else if (a === "--check-only") out.checkOnly = true;
    else if (a === "--wait-seconds") out.waitSeconds = Number(argv[++i]) || 25;
    else if (a === "-h" || a === "--help") out.help = true;
  }
  return out;
}

export function detectImpersonateTool() {
  const found = { kind: null, python: null, version: null, binary: null, detail: null };
  for (const py of ["python", "python3", "py"]) {
    const r = spawnSync(py, ["-c", "import curl_cffi; print(curl_cffi.__version__)"], {
      encoding: "utf8",
    });
    if (r.status === 0) {
      found.kind = "curl_cffi";
      found.python = py;
      found.version = (r.stdout || "").trim();
      found.detail = `curl_cffi ${found.version} via ${py}`;
      return found;
    }
  }
  // In-repo uTLS Chrome dialer (Phase 1 real stack when pip/curl-impersonate unavailable).
  const utlsCandidates = [
    join(root, "tools/utls-chrome-dial/utls-chrome-dial.exe"),
    join(root, "tools/utls-chrome-dial/utls-chrome-dial"),
    join(root, "tools/utls-chrome-dial/utls-chrome-dial.bin"),
  ];
  const utlsBin = utlsCandidates.find((p) => existsSync(p));
  if (utlsBin) {
    found.kind = "utls-chrome-dial";
    found.binary = utlsBin;
    found.detail = `utls-chrome-dial @ ${utlsBin}`;
    return found;
  }
  // curl-impersonate chrome wrappers on PATH
  const isWin = process.platform === "win32";
  const checker = isWin ? "where" : "which";
  for (const name of ["curl_chrome150", "curl_chrome131", "curl-impersonate", "curl_chrome"]) {
    const r = spawnSync(checker, [name], { encoding: "utf8" });
    if (r.status === 0) {
      const path = (r.stdout || "").split(/\r?\n/).map((s) => s.trim()).find(Boolean);
      if (path) {
        found.kind = "curl-impersonate-bin";
        found.binary = path;
        found.detail = path;
        return found;
      }
    }
  }
  found.kind = null;
  found.detail = "tool not installed / capture skipped";
  return found;
}

function findProbeBinary() {
  const candidates = [
    join(root, "src-tauri/target/debug/tls-golden-probe.exe"),
    join(root, "src-tauri/target/debug/tls-golden-probe"),
    join(root, "src-tauri/target/release/tls-golden-probe.exe"),
    join(root, "src-tauri/target/release/tls-golden-probe"),
  ];
  return candidates.find((p) => existsSync(p)) || null;
}

function mapImpersonateName(preset) {
  // curl_cffi uses chrome120, chrome124, ... chrome131, chrome133, etc.
  // chrome150 may map to latest chrome if unsupported — try exact then chrome.
  if (/^chrome\d+$/.test(preset)) return preset;
  if (preset.startsWith("chrome-android")) {
    return preset.replace("chrome-android", "chrome") + "_android";
  }
  return "chrome";
}

function mapUtlsHello(preset) {
  if (preset === "chrome120") return "chrome120";
  if (preset === "chrome131") return "chrome131";
  if (/^chrome\d+$/.test(preset)) return preset; // chrome150 → handled as Auto in dialer
  return "chrome";
}

/**
 * Drive tool → local probe and return capture result.
 * Exported for unit tests (structural path); live run needs tool + probe binary.
 */
export async function measureToolClientHello({ preset, waitSeconds = 25 } = {}) {
  const tool = detectImpersonateTool();
  if (!tool.kind) {
    return {
      ok: false,
      skipped: true,
      reason: "tool not installed / capture skipped",
      hint: "pip install curl_cffi  OR install curl-impersonate chrome wrappers on PATH",
    };
  }

  let probeBin = findProbeBinary();
  if (!probeBin) {
    // try cargo build
    const rustStable = join(root, "scripts/rust-stable.mjs");
    const build = spawnSync(
      process.execPath,
      [
        rustStable,
        "cargo",
        "build",
        "--manifest-path",
        join(root, "src-tauri/Cargo.toml"),
        "--bin",
        "tls-golden-probe",
      ],
      { encoding: "utf8", cwd: root, timeout: 600000 },
    );
    if (build.status !== 0) {
      return {
        ok: false,
        skipped: true,
        reason: `tls-golden-probe missing and build failed: ${(build.stderr || build.stdout || "").slice(0, 300)}`,
      };
    }
    probeBin = findProbeBinary();
  }
  if (!probeBin) {
    return { ok: false, skipped: true, reason: "tls-golden-probe binary not found after build" };
  }

  const probe = spawn(probeBin, ["wait", "--seconds", String(waitSeconds)], {
    cwd: root,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let stderr = "";
  let stdout = "";
  probe.stderr.on("data", (c) => {
    stderr += c.toString();
  });
  probe.stdout.on("data", (c) => {
    stdout += c.toString();
  });

  // Wait for PROBE_ADDR line
  const addr = await new Promise((resolve, reject) => {
    const deadline = setTimeout(() => {
      reject(new Error("probe did not print PROBE_ADDR in time"));
    }, 15000);
    const check = () => {
      const m = stderr.match(/PROBE_ADDR\s+(\S+)/);
      if (m) {
        clearTimeout(deadline);
        resolve(m[1]);
        return true;
      }
      return false;
    };
    if (check()) return;
    probe.stderr.on("data", () => {
      check();
    });
    probe.on("error", (e) => {
      clearTimeout(deadline);
      reject(e);
    });
    probe.on("exit", (code) => {
      if (!stderr.includes("PROBE_ADDR")) {
        clearTimeout(deadline);
        reject(new Error(`probe exited early code=${code} stderr=${stderr.slice(0, 200)}`));
      }
    });
  }).catch((e) => {
    try {
      probe.kill();
    } catch {
      /* ignore */
    }
    return { error: e.message };
  });

  if (addr?.error) {
    return { ok: false, skipped: false, reason: addr.error, tool };
  }

  const hostPort = String(addr);
  const url = `https://${hostPort}/`;
  const impersonate = mapImpersonateName(preset);

  let connectResult;
  if (tool.kind === "curl_cffi") {
    const code = `
import json, sys
from curl_cffi import requests
try:
    # verify=False: probe aborts after ClientHello; cert is irrelevant
    r = requests.get(${JSON.stringify(url)}, impersonate=${JSON.stringify(impersonate)}, timeout=10, verify=False)
    print(json.dumps({"ok": True, "status": getattr(r, "status_code", None)}))
except Exception as e:
    # Connection reset after ClientHello is expected success for capture
    msg = str(e).lower()
    if "reset" in msg or "ssl" in msg or "eof" in msg or "handshake" in msg or "connect" in msg:
        print(json.dumps({"ok": True, "expected_abort": True, "error": str(e)}))
    else:
        print(json.dumps({"ok": False, "error": str(e)}))
`;
    const r = spawnSync(tool.python, ["-c", code], {
      encoding: "utf8",
      timeout: (waitSeconds + 10) * 1000,
    });
    try {
      const line = (r.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop();
      connectResult = line ? JSON.parse(line) : { ok: false, error: "empty curl_cffi stdout" };
    } catch {
      connectResult = { ok: false, error: (r.stderr || r.stdout || "").slice(0, 300) };
    }
  } else if (tool.kind === "utls-chrome-dial") {
    const r = spawnSync(
      tool.binary,
      ["-addr", hostPort, "-sni", "probe.local", "-hello", mapUtlsHello(preset), "-timeout", "8s"],
      { encoding: "utf8", timeout: 15000 },
    );
    const line = (r.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop();
    try {
      connectResult = line ? JSON.parse(line) : { ok: r.status === 0, raw: (r.stderr || "").slice(0, 120) };
    } catch {
      // Dial abort is fine if probe captured; treat non-crash as ok.
      connectResult = { ok: true, status: r.status, stderr: (r.stderr || "").slice(0, 120) };
    }
  } else {
    const r = spawnSync(tool.binary, ["-k", "-sS", "--max-time", "10", url], {
      encoding: "utf8",
      timeout: 15000,
    });
    // exit non-zero expected when probe drops
    connectResult = { ok: true, status: r.status, stderr: (r.stderr || "").slice(0, 100) };
  }

  const probeExit = await new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        probe.kill();
      } catch {
        /* ignore */
      }
      resolve({ timedOut: true });
    }, (waitSeconds + 5) * 1000);
    probe.on("exit", (code) => {
      clearTimeout(t);
      resolve({ code });
    });
  });

  const text = stdout.trim();
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end < start) {
    return {
      ok: false,
      skipped: false,
      reason: `probe produced no golden JSON (connect=${JSON.stringify(connectResult)} stderr=${stderr.slice(0, 200)})`,
      tool,
      probeExit,
    };
  }

  let body;
  try {
    body = JSON.parse(text.slice(start, end + 1));
  } catch (e) {
    return { ok: false, reason: `parse probe JSON: ${e.message}`, tool };
  }

  const golden = body.golden || {};
  if (!golden.ja3 || !/^[0-9a-f]{32}$/i.test(golden.ja3) || !golden.clientHelloHex) {
    return {
      ok: false,
      reason: "probe capture incomplete (need ja3 + clientHelloHex)",
      body,
      tool,
    };
  }

  return {
    ok: true,
    mode: "tool-capture",
    alignmentCeiling: "tool-matched",
    honesty: "tool ClientHello via curl-impersonate-class stack; not browser-matched",
    presetId: preset,
    tool: tool.detail,
    impersonateProfile: impersonate,
    probeAddr: hostPort,
    connectResult,
    golden: {
      ja3: String(golden.ja3).toLowerCase(),
      ja3Raw: golden.ja3Raw || null,
      ja4: golden.ja4 || null,
      ja4Raw: golden.ja4Raw || null,
      clientHelloHex: String(golden.clientHelloHex).toLowerCase(),
    },
  };
}

export function writeToolGoldenEntry(result, platform) {
  if (!result?.ok || !result.golden) {
    throw new Error("refusing to write golden: measure not ok");
  }
  const file = `${result.presetId}--${platform}.json`;
  const path = join(entriesDir, file);
  if (!existsSync(path)) {
    throw new Error(`missing entry stub: ${file}`);
  }
  const entry = JSON.parse(readFileSync(path, "utf8"));
  // Refuse browser-matched
  entry.status = "captured";
  entry.alignment = "tool-matched";
  entry.source = {
    kind: "tool-capture",
    tool: result.tool || "curl_cffi",
    environment: `impersonate=${result.impersonateProfile}; probe=${result.probeAddr}; host=${process.platform}`,
    capturedAt: new Date().toISOString().slice(0, 10),
  };
  entry.golden = {
    ja3: result.golden.ja3,
    ja3Raw: result.golden.ja3Raw,
    ja4: result.golden.ja4,
    ja4Raw: result.golden.ja4Raw,
    clientHelloHex: result.golden.clientHelloHex,
  };
  entry.stackVersion = result.tool || null;
  entry.notes =
    (entry.notes || "") +
    " | Phase1 tool-capture via tls-impersonate-measure.mjs; not browser-matched.";
  writeFileSync(path, JSON.stringify(entry, null, 2) + "\n", "utf8");
  return { path, entry };
}

function printHelp() {
  console.log(`tls-impersonate-measure — Phase 1 tool ClientHello capture

Options:
  --preset <id>           default chrome150
  --platform <plat>       default host desktop-*
  --write-golden          write entries/<preset>--<platform>.json as tool-matched
  --check-only            only detect tool availability
  --wait-seconds <n>      probe wait budget (default 25)
`);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const tool = detectImpersonateTool();
  console.log(`tls-impersonate-measure: tool=${tool.detail || "none"}`);

  if (args.checkOnly) {
    if (!tool.kind) {
      console.log("tool not installed / capture skipped");
      process.exit(2);
    }
    console.log(`tool available: ${tool.detail}`);
    process.exit(0);
  }

  if (!tool.kind) {
    console.log("tool not installed / capture skipped");
    console.log("hint: pip install curl_cffi");
    process.exit(2);
  }

  console.log(`measuring preset=${args.preset} platform=${args.platform}…`);
  const result = await measureToolClientHello({
    preset: args.preset,
    waitSeconds: args.waitSeconds,
  });
  console.log(JSON.stringify(result, null, 2));

  if (!result.ok) {
    if (result.skipped) {
      console.log(result.reason || "tool not installed / capture skipped");
      process.exit(2);
    }
    console.error("measure failed:", result.reason);
    process.exit(1);
  }

  if (args.writeGolden) {
    const written = writeToolGoldenEntry(result, args.platform);
    console.log(`wrote tool-matched golden: ${written.path}`);
    console.log(`ja3=${written.entry.golden.ja3} alignment=${written.entry.alignment}`);
  } else {
    console.log("measure ok (pass --write-golden to update entries/*.json; then rebuild to embed)");
  }
  process.exit(0);
}

function isMainModule() {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return /tls-impersonate-measure\.mjs$/i.test(entry.replace(/\\/g, "/"));
  }
}

if (isMainModule()) {
  main().catch((err) => {
    console.error("tls-impersonate-measure error:", err?.message || err);
    process.exit(1);
  });
}
