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

/**
 * Map catalog preset → utls -hello id.
 * Goldenable Chrome majors use HelloChrome_102 (pre-shuffle) so JA3 re-measures
 * equal the committed golden. Post-106 parrots shuffle extension order every
 * handshake and cannot satisfy exact JA3 equality.
 */
export function mapUtlsHello(preset) {
  const id = String(preset || "").toLowerCase();
  // Explicit aliases if we ever capture fixed non-102 goldens.
  if (id === "chrome102") return "chrome102";
  // All product chrome* majors that may be written as tool goldens.
  if (/^chrome\d+$/.test(id) || id.startsWith("chrome-android")) {
    return "chrome102";
  }
  return "chrome102";
}

/** Build source.tool / stackVersion from the real measure tool result. */
export function toolIdentityFromResult(result) {
  const kind = result?.toolKind || result?.tool?.kind || null;
  const detail = result?.toolDetail || result?.tool || "unknown-tool";
  const hello = result?.utlsHello || mapUtlsHello(result?.presetId || "chrome150");
  if (kind === "curl_cffi" || (typeof detail === "string" && detail.includes("curl_cffi"))) {
    return {
      tool: typeof detail === "string" ? detail : `curl_cffi ${result?.toolVersion || ""}`.trim(),
      stackVersion: `curl_cffi impersonate=${result?.impersonateProfile || result?.presetId || "chrome"}`,
      environment: `tool=curl_cffi; impersonate=${result?.impersonateProfile || ""}; probe=loopback; host=${process.platform}`,
    };
  }
  if (kind === "curl-impersonate-bin" || (typeof detail === "string" && detail.includes("curl_chrome"))) {
    return {
      tool: typeof detail === "string" ? detail : "curl-impersonate",
      stackVersion: `curl-impersonate binary (${result?.impersonateProfile || "chrome"})`,
      environment: `tool=curl-impersonate-bin; profile=${result?.impersonateProfile || ""}; host=${process.platform}`,
    };
  }
  // Default / utls-chrome-dial
  const toolLabel =
    typeof detail === "string" && detail.includes("utls")
      ? detail
      : `utls-chrome-dial (refraction-networking/utls ${hello})`;
  return {
    tool: toolLabel,
    stackVersion: `utls ${hello} (pinned pre-shuffle for re-measure) via tools/utls-chrome-dial`,
    environment: `tool=utls-chrome-dial; hello=${hello}; preset=${result?.presetId || ""}; probe=loopback; host=${process.platform}`,
  };
}

/**
 * Extract PROBE_ADDR only from a **complete** stderr line (terminated by newline).
 * Rejects truncated stream chunks such as "PROBE_ADDR 127.0.0" before ":port" arrives
 * (otherwise utls dials without a port and re-measure fails intermittently).
 *
 * @param {string} stderrBuf cumulative stderr text from tls-golden-probe wait
 * @returns {string|null} host:port or null if no complete line yet
 */
export function parseProbeAddrLine(stderrBuf) {
  if (!stderrBuf || typeof stderrBuf !== "string") return null;
  // Lines that are not yet terminated are incomplete — ignore the last fragment
  // unless the buffer itself ends with a newline.
  const endsWithNl = /\r?\n$/.test(stderrBuf);
  const parts = stderrBuf.split(/\r?\n/);
  const completeLines = endsWithNl ? parts.filter((l) => l.length > 0) : parts.slice(0, -1);
  for (const line of completeLines) {
    // Require host:port with numeric port on a full line (no trailing partial tokens).
    const m = line.match(/^PROBE_ADDR\s+(\S+:\d{1,5})\s*$/);
    if (!m) continue;
    const addr = m[1];
    // Guard truncated IPv4 like "127.0.0" (no colon) — already rejected by :\d
    // Guard "127.0.0:" incomplete port — :\d{1,5} requires digits.
    if (/^.+:\d{1,5}$/.test(addr)) {
      return addr;
    }
  }
  return null;
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

  // Wait for a *complete* PROBE_ADDR host:port line (newline-terminated).
  const addr = await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      fn(value);
    };
    const deadline = setTimeout(() => {
      finish(reject, new Error("probe did not print complete PROBE_ADDR host:port line in time"));
    }, 15000);
    const check = () => {
      const parsed = parseProbeAddrLine(stderr);
      if (parsed) {
        finish(resolve, parsed);
        return true;
      }
      return false;
    };
    if (check()) return;
    probe.stderr.on("data", () => {
      check();
    });
    probe.on("error", (e) => {
      finish(reject, e);
    });
    probe.on("exit", (code) => {
      if (settled) return;
      // Final chance: if process flushed a complete line on exit.
      const parsed = parseProbeAddrLine(stderr.endsWith("\n") ? stderr : `${stderr}\n`);
      if (parsed) {
        finish(resolve, parsed);
        return;
      }
      finish(
        reject,
        new Error(
          `probe exited early code=${code} without complete PROBE_ADDR host:port (stderr=${stderr.slice(0, 200)})`,
        ),
      );
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
  if (!/:\d{1,5}$/.test(hostPort)) {
    try {
      probe.kill();
    } catch {
      /* ignore */
    }
    return {
      ok: false,
      skipped: false,
      reason: `invalid probe address (missing port): ${hostPort}`,
      tool,
    };
  }
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
    toolKind: tool.kind,
    toolDetail: tool.detail,
    tool: tool.detail,
    toolVersion: tool.version || null,
    utlsHello: tool.kind === "utls-chrome-dial" ? mapUtlsHello(preset) : null,
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
  const identity = toolIdentityFromResult(result);
  // Refuse browser-matched
  entry.status = "captured";
  entry.alignment = "tool-matched";
  entry.source = {
    kind: "tool-capture",
    tool: identity.tool,
    environment: identity.environment,
    capturedAt: new Date().toISOString().slice(0, 10),
  };
  entry.stackVersion = identity.stackVersion;
  entry.golden = {
    ja3: result.golden.ja3,
    ja3Raw: result.golden.ja3Raw,
    ja4: result.golden.ja4,
    ja4Raw: result.golden.ja4Raw,
    clientHelloHex: result.golden.clientHelloHex,
  };
  entry.notes =
    (entry.notes || "") +
    ` | Phase1 tool-capture via tls-impersonate-measure.mjs (${result.toolKind || "tool"}); not browser-matched.`;
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
