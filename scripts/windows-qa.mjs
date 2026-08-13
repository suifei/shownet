#!/usr/bin/env node
/**
 * Windows automated regression entry point for ShowNet.
 *
 * Layers (default always-on; live opt-in via project .env):
 *   1. default   — npm test, tsc --noEmit, cargo test --lib
 *   2. egress    — when PROXY / HTTP(S)_PROXY present: live_upstream_proxy_from_env*
 *   3. mitm      — when egress env present: live_shownet_mitm_smoke*
 *   4. agent     — when OPENAI_KEY (or SHOWNET_GROK_BINARY + key) and sidecar binary:
 *                  real_sidecar_streams_openai_report*
 *
 * Usage:
 *   npm run test:windows
 *   node scripts/windows-qa.mjs --help
 *   node scripts/windows-qa.mjs --scratch <dir>
 *   node scripts/windows-qa.mjs --layer default
 *   node scripts/windows-qa.mjs --layer egress|mitm|agent|all
 *
 * Never prints secret values from .env.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const rustStable = join(root, "scripts", "rust-stable.mjs");

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  printHelp();
  process.exit(0);
}

const scratch = resolve(
  args.scratch
    || process.env.SHOWNET_QA_SCRATCH
    || join(root, "tmp", "windows-qa"),
);
mkdirSync(scratch, { recursive: true });

const runStamp = new Date().toISOString().replace(/[:.]/g, "-");
const masterLog = join(scratch, `windows-qa-${runStamp}.log`);
const envPath = join(root, ".env");

logLine(`Windows QA start root=${root}`);
logLine(`scratch=${scratch}`);
logLine(`masterLog=${masterLog}`);

const loaded = loadDotEnv(envPath);
logLine(loaded.loaded
  ? `loaded .env keys=[${loaded.keys.join(", ")}] (values redacted)`
  : `no .env at ${envPath}`);

const hasEgress = Boolean(firstEnv(["PROXY", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"]));
const hasAiKey = Boolean(firstEnv(["OPENAI_KEY", "OPENAI_API_KEY", "SHOWNET_AGENT_API_KEY"]));
const sidecarBinary = discoverSidecarBinary();
logLine(`layer flags: egress=${hasEgress} aiKey=${hasAiKey} sidecar=${sidecarBinary ? "yes" : "no"}`);

const layers = selectLayers(args.layer);
let failed = 0;

for (const layer of layers) {
  if (layer === "default") {
    failed += await runDefaultLayer();
  } else if (layer === "egress") {
    failed += await runEgressLayer();
  } else if (layer === "mitm") {
    failed += await runMitmLayer();
  } else if (layer === "agent") {
    failed += await runAgentLayer();
  }
}

logLine(failed === 0 ? "WINDOWS_QA_OK" : `WINDOWS_QA_FAILED failures=${failed}`);
process.exit(failed === 0 ? 0 : 1);

function printHelp() {
  console.log(`ShowNet Windows QA / e2e entry

Always-on (default layer):
  npm test  (includes e2e feature pillar map + UI/unit structural checks)
  tsc --noEmit
  cargo test --lib  (via scripts/rust-stable.mjs)

Live layers (require project .env; never committed):
  egress  PROXY or HTTP(S)_PROXY → cargo test live_upstream_proxy_from_env -- --ignored
  mitm    same + bind local ShowNet listener → live_shownet_mitm_smoke
  agent   OPENAI_KEY + built sidecar under src-tauri/binaries/ → real_sidecar_streams*

Feature pillars (machine-checked by tests/e2e-feature-pillars.test.ts):
  capture-mitm-proxy, egress, tls-interception-bypass, outbound-tls-clienthello,
  embedded-browser-lifecycle, browser-bus-hook, traffic-evidence,
  analysis-agent-mcp, request-lab-replay-collections, settings-ca-client-access,
  windows-qa-orchestrator

Options:
  --scratch <dir>   Write logs here (default: tmp/windows-qa or SHOWNET_QA_SCRATCH)
  --layer <name>    default | egress | mitm | agent | all  (default: all)
  --help            This message
`);
}

function parseArgs(argv) {
  const out = { help: false, layer: "all", scratch: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") out.help = true;
    else if (a === "--scratch") out.scratch = argv[++i];
    else if (a === "--layer") out.layer = argv[++i] || "all";
    else if (a.startsWith("--scratch=")) out.scratch = a.slice("--scratch=".length);
    else if (a.startsWith("--layer=")) out.layer = a.slice("--layer=".length);
  }
  return out;
}

function selectLayers(layer) {
  if (layer === "all") return ["default", "egress", "mitm", "agent"];
  if (["default", "egress", "mitm", "agent"].includes(layer)) return [layer];
  throw new Error(`unknown --layer ${layer}`);
}

function loadDotEnv(path) {
  if (!existsSync(path)) return { loaded: false, keys: [] };
  const text = readFileSync(path, "utf8");
  const keys = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith("\"") && value.endsWith("\""))
      || (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (!(key in process.env) || process.env[key] === "") {
      process.env[key] = value;
    }
    keys.push(key);
  }
  return { loaded: true, keys };
}

function firstEnv(names) {
  for (const name of names) {
    const value = process.env[name];
    if (value && value.trim()) return value.trim();
  }
  return null;
}

function discoverSidecarBinary() {
  if (process.env.SHOWNET_GROK_BINARY && existsSync(process.env.SHOWNET_GROK_BINARY)) {
    return process.env.SHOWNET_GROK_BINARY;
  }
  const triple = "x86_64-pc-windows-msvc";
  const candidates = [
    join(root, "src-tauri", "binaries", `grok-build-${triple}.exe`),
    join(root, "src-tauri", "binaries", "grok-build.exe"),
  ];
  return candidates.find((path) => existsSync(path)) || null;
}

function logLine(message) {
  const line = `[${new Date().toISOString()}] ${message}`;
  console.log(line);
  appendFileSync(masterLog, `${line}\n`, "utf8");
}

function run(command, args, { logFile, env = process.env, cwd = root, shell = false } = {}) {
  logLine(`$ ${command} ${args.join(" ")}`);
  // Default shell:false so cargo filter args are not re-parsed by cmd.exe.
  // Windows .cmd shims require shell:true (otherwise Node returns EINVAL).
  const result = spawnSync(command, args, {
    cwd,
    env: { ...env },
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
    shell,
    windowsHide: true,
  });
  const out = `${result.stdout || ""}${result.stderr || ""}${result.error ? String(result.error) : ""}`;
  if (logFile) {
    writeFileSync(logFile, out, "utf8");
    logLine(`wrote ${logFile} exit=${result.status ?? "spawn-error"}`);
  }
  if (result.error || result.status !== 0) {
    logLine(`FAILED exit=${result.status} error=${result.error || ""} cmd=${command}`);
  }
  return { status: result.error ? 1 : (result.status ?? 1), out };
}

/** Prefer invoking node entrypoints directly to avoid npm.cmd spawn issues on Windows. */
function runNodeScript(scriptArgs, options) {
  return run(process.execPath, scriptArgs, options);
}

async function runDefaultLayer() {
  let fails = 0;
  const npmLog = join(scratch, "npm-test.log");
  const tscLog = join(scratch, "tsc.log");
  const cargoLog = join(scratch, "cargo-lib.log");

  // Use npm package script (shell) so the same glob as CI/`npm test` is used on Windows.
  let r = run("npm", ["test"], { logFile: npmLog, shell: true });
  if (r.status !== 0) fails += 1;
  if (r.status === 0 && !/# fail 0/.test(r.out)) {
    logLine("WARN: npm test exit 0 but could not confirm fail 0 line");
  }

  const tscJs = join(root, "node_modules", "typescript", "bin", "tsc");
  r = existsSync(tscJs)
    ? runNodeScript([tscJs, "--noEmit"], { logFile: tscLog })
    : run("npx", ["tsc", "--noEmit"], { logFile: tscLog, shell: true });
  if (r.status !== 0) fails += 1;

  r = runNodeScript(
    [rustStable, "cargo", "test", "--manifest-path", "src-tauri/Cargo.toml", "--lib"],
    { logFile: cargoLog },
  );
  if (r.status !== 0) fails += 1;
  if (r.status === 0 && !/test result: ok\./.test(r.out)) {
    logLine("WARN: cargo test --lib exit 0 without test result ok line");
  }

  logLine(fails === 0 ? "LAYER_DEFAULT_OK" : "LAYER_DEFAULT_FAILED");
  return fails;
}

async function runEgressLayer() {
  const logFile = join(scratch, "live-egress.log");
  if (!hasEgress) {
    const msg = "SKIP live egress: no PROXY/HTTP(S)_PROXY/ALL_PROXY in environment\n";
    writeFileSync(logFile, msg, "utf8");
    logLine(msg.trim());
    return 0;
  }
  const r = runNodeScript([
    rustStable,
    "cargo",
    "test",
    "--manifest-path",
    "src-tauri/Cargo.toml",
    "--lib",
    "live_upstream_proxy_from_env",
    "--",
    "--ignored",
    "--nocapture",
  ], { logFile });
  if (r.status === 0 && /LIVE_EGRESS_OK/.test(r.out)) {
    logLine("LAYER_EGRESS_OK");
    return 0;
  }
  logLine("LAYER_EGRESS_FAILED");
  return 1;
}

async function runMitmLayer() {
  const logFile = join(scratch, "mitm-smoke.log");
  if (!hasEgress) {
    const msg = "SKIP live MITM: no PROXY/HTTP(S)_PROXY (egress required for outbound MITM smoke)\n";
    writeFileSync(logFile, msg, "utf8");
    logLine(msg.trim());
    return 0;
  }
  const r = runNodeScript([
    rustStable,
    "cargo",
    "test",
    "--manifest-path",
    "src-tauri/Cargo.toml",
    "--lib",
    "live_shownet_mitm_smoke",
    "--",
    "--ignored",
    "--nocapture",
  ], { logFile });
  if (r.status === 0 && /LIVE_MITM_OK/.test(r.out)) {
    logLine("LAYER_MITM_OK");
    return 0;
  }
  // Bind failure must be visible, not silent green.
  logLine("LAYER_MITM_FAILED");
  return 1;
}

async function runAgentLayer() {
  const logFile = join(scratch, "agent-live.log");
  if (!hasAiKey) {
    writeFileSync(logFile, "SKIP agent live: no OPENAI_KEY / OPENAI_API_KEY in environment\n", "utf8");
    logLine("SKIP agent live: no AI key");
    return 0;
  }

  if (!sidecarBinary) {
    const msg = [
      "AGENT_SIDECAR_MISSING",
      "Download the official stable binary with npm run download:agent-sidecar before the live Agent layer.",
      "Default-layer agent unit tests still apply via cargo test --lib / npm test.",
    ].join("\n");
    writeFileSync(logFile, `${msg}\n`, "utf8");
    logLine(msg.split("\n")[0]);
    return 0;
  } else {
    process.env.SHOWNET_GROK_BINARY = sidecarBinary;
  }

  // Map project OPENAI_* into the names the sidecar path expects when present.
  if (process.env.OPENAI_KEY && !process.env.OPENAI_API_KEY) {
    process.env.OPENAI_API_KEY = process.env.OPENAI_KEY;
  }

  const r = runNodeScript([
    rustStable,
    "cargo",
    "test",
    "--manifest-path",
    "src-tauri/Cargo.toml",
    "--lib",
    "real_sidecar_streams_openai_report",
    "--",
    "--ignored",
    "--nocapture",
  ], {
    logFile,
    env: {
      ...process.env,
      SHOWNET_GROK_BINARY: process.env.SHOWNET_GROK_BINARY,
    },
  });
  if (r.status === 0 && /SIDECAR_E2E_OK|test result: ok/.test(r.out)) {
    logLine("LAYER_AGENT_OK");
    return 0;
  }
  logLine("LAYER_AGENT_FAILED");
  return 1;
}
