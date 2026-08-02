import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { basename, delimiter, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const sourceMetadata = JSON.parse(await readFile(resolve(root, "third-party/grok-build/SOURCE.json"), "utf8"));
validateSourceMetadata(sourceMetadata);
const GROK_REPOSITORY = sourceMetadata.repository;
const GROK_COMMIT = sourceMetadata.commit;
const GROK_VERSION = sourceMetadata.version;
const GROK_RUST_TOOLCHAIN = sourceMetadata.rustToolchain;

const options = parseArguments(process.argv.slice(2));
if (options.fresh && options.source) {
  throw new Error("--fresh cannot be used with an explicit --source directory");
}
if (options.stampOnly && (options.fresh || options.source)) {
  throw new Error("--stamp-only cannot be combined with --fresh or --source");
}
const target = options.target ?? hostTarget();
const executableSuffix = target.includes("windows") ? ".exe" : "";
if (options.xwin && !target.includes("windows")) {
  throw new Error("--xwin requires a Windows target");
}
const sourceDir = resolve(options.source ?? resolve(root, "src-tauri/.sidecar-src/grok-build"));
const output = resolve(
  root,
  `src-tauri/binaries/grok-build-${target}${executableSuffix}`,
);

if (!options.stampOnly) {
  await ensurePinnedSource(sourceDir);
  validatePinnedSource(sourceDir);
  const buildArgs = ["build", "-p", "xai-grok-pager-bin", "--release", "--features", "release-dist", "--target", target];
  if (options.xwin) {
    const pinnedCargo = capture("rustup", ["which", "--toolchain", GROK_RUST_TOOLCHAIN, "cargo"], root);
    run("cargo-xwin", buildArgs, sourceDir, {
      ...process.env,
      PATH: `${dirname(pinnedCargo)}${delimiter}${process.env.PATH ?? ""}`,
      RUSTUP_TOOLCHAIN: GROK_RUST_TOOLCHAIN,
    });
  } else {
    run("rustup", ["run", GROK_RUST_TOOLCHAIN, "cargo", ...buildArgs], sourceDir);
  }

  const built = resolve(sourceDir, `target/${target}/release/xai-grok-pager${executableSuffix}`);
  await assertFile(built, "官方 grok-build 编译产物");
  await mkdir(resolve(root, "src-tauri/binaries"), { recursive: true });
  await copyFile(built, output);
  if (process.platform !== "win32") await chmod(output, 0o755);
}
await assertFile(output, "Agent sidecar");
const bytes = await readFile(output);
const checksum = createHash("sha256").update(bytes).digest("hex");
await writeFile(`${output}.sha256`, `${checksum}  ${basename(output)}\n`, { mode: 0o600 });
await writeFile(
  `${output}.metadata.json`,
  `${JSON.stringify({
    name: "xai-org/grok-build",
    version: GROK_VERSION,
    repository: GROK_REPOSITORY,
    commit: GROK_COMMIT,
    rustToolchain: GROK_RUST_TOOLCHAIN,
    target,
    sha256: checksum,
  }, null, 2)}\n`,
  { mode: 0o600 },
);
console.log(`Built verified Agent sidecar: ${output}`);
console.log(`SHA-256: ${checksum}`);

function validateSourceMetadata(metadata) {
  if (metadata.name !== "xai-org/grok-build") throw new Error("Unexpected Agent source name");
  if (!/^https:\/\/github\.com\/xai-org\/grok-build(?:\.git)?$/.test(metadata.repository ?? "")) {
    throw new Error("Agent source repository must be the official xai-org/grok-build repository");
  }
  if (!/^[0-9a-f]{40}$/.test(metadata.commit ?? "")) throw new Error("Agent source commit must be a full Git SHA");
  if (!/^\d+\.\d+\.\d+$/.test(metadata.version ?? "")) throw new Error("Agent source version is invalid");
  if (!/^\d+\.\d+\.\d+$/.test(metadata.rustToolchain ?? "")) throw new Error("Agent Rust toolchain is invalid");
  if (metadata.license !== "Apache-2.0") throw new Error("Agent source license must be Apache-2.0");
}

function parseArguments(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--target" || argument === "--source") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      parsed[argument.slice(2)] = value;
      index += 1;
    } else if (argument === "--fresh") {
      parsed.fresh = true;
    } else if (argument === "--stamp-only") {
      parsed.stampOnly = true;
    } else if (argument === "--xwin") {
      parsed.xwin = true;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return parsed;
}

function hostTarget() {
  const key = `${process.platform}-${process.arch}`;
  const targets = {
    "darwin-arm64": "aarch64-apple-darwin",
    "darwin-x64": "x86_64-apple-darwin",
    "win32-x64": "x86_64-pc-windows-msvc",
    "win32-arm64": "aarch64-pc-windows-msvc",
    "linux-x64": "x86_64-unknown-linux-gnu",
    "linux-arm64": "aarch64-unknown-linux-gnu",
  };
  const target = targets[key];
  if (!target) throw new Error(`Unsupported sidecar host: ${key}`);
  return target;
}

async function ensurePinnedSource(directory) {
  if (options.fresh) await rm(directory, { recursive: true, force: true });
  let cloned = false;
  try {
    await stat(resolve(directory, ".git"));
  } catch {
    await mkdir(resolve(directory, ".."), { recursive: true });
    run("git", ["clone", "--filter=blob:none", "--no-checkout", GROK_REPOSITORY, directory], root);
    cloned = true;
  }
  if (!cloned) {
    const changes = capture("git", ["status", "--porcelain"], directory);
    if (changes) throw new Error(`Agent source checkout has local changes: ${directory}`);
    const currentCommit = capture("git", ["rev-parse", "HEAD"], directory);
    if (currentCommit === GROK_COMMIT) return;
  }
  run("git", ["fetch", "--depth", "1", "origin", GROK_COMMIT], directory);
  run("git", ["checkout", "--detach", GROK_COMMIT], directory);
}

function validatePinnedSource(directory) {
  const commit = capture("git", ["rev-parse", "HEAD"], directory);
  if (commit !== GROK_COMMIT) throw new Error(`grok-build checkout mismatch: ${commit}`);
  const cargoToml = capture("git", ["show", "HEAD:crates/codegen/xai-grok-pager-bin/Cargo.toml"], directory);
  const version = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (version !== GROK_VERSION) {
    throw new Error(`grok-build version mismatch: expected ${GROK_VERSION}, found ${version ?? "<missing>"}`);
  }
}

function run(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with status ${result.status}`);
}

function capture(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, env: process.env, encoding: "utf8" });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr?.trim() || `${command} failed`);
  return result.stdout.trim();
}

async function assertFile(path, label) {
  const info = await stat(path).catch(() => null);
  if (!info?.isFile() || info.size === 0) throw new Error(`${label}不存在或为空: ${path}`);
}
