import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { constants as fsConstants } from "node:fs";
import {
  grokBuildArtifact,
  resolveGrokTargetDirectory,
} from "./grok-sidecar-layout.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

/** Paths we rewrite during the sidecar build (must not trip the dirty-tree guard).
 * Declared before top-level await so ensurePinnedSource can see them. */
const EPHEMERAL_SOURCE_PATHS = [
  "bin/protoc",
  "bin/protoc.exe",
  "crates/build/xai-proto-build/src/lib.rs",
  ".cargo/config.toml",
];

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
if (options.prepareOnly && (options.stampOnly || options.xwin)) {
  throw new Error("--prepare-only cannot be combined with --stamp-only or --xwin");
}
const target = options.target ?? hostTarget();
const executableSuffix = target.includes("windows") ? ".exe" : "";
if (options.xwin && !target.includes("windows")) {
  throw new Error("--xwin requires a Windows target");
}
const sourceDir = resolve(options.source ?? resolve(root, "src-tauri/.sidecar-src/grok-build"));
const targetDir = resolveGrokTargetDirectory(root);
const output = resolve(
  root,
  `src-tauri/binaries/grok-build-${target}${executableSuffix}`,
);

if (options.prepareOnly) {
  await ensurePinnedSource(sourceDir);
  validatePinnedSource(sourceDir);
  console.log(`Prepared pinned Agent source for cache metadata: ${sourceDir}`);
  console.log(`Agent Cargo target cache: ${targetDir}`);
} else if (!options.stampOnly) {
  await ensurePinnedSource(sourceDir);
  validatePinnedSource(sourceDir);
  // Vendored bin/protoc is a macOS dotslash stub; CI must inject a real protoc.
  const protocEnv = await ensureRealProtoc(sourceDir);
  // xai-proto-build hardcodes /dev/stdout and /dev/null — broken on Windows.
  await patchWindowsProtocDeps(sourceDir);
  const buildArgs = ["build", "-p", "xai-grok-pager-bin", "--release", "--features", "release-dist", "--target", target];
  // Windows MSVC LNK4319: PDB public-symbol limit on this large binary.
  // Force no PDB via profile + rustflags (link-arg=/DEBUG:NONE is required —
  // rustc still passes /DEBUG for some crates even with debuginfo=0 alone).
  const windowsTarget = target.includes("windows");
  if (windowsTarget) {
    await writeWindowsReleaseCargoConfig(sourceDir);
  }
  // Prefer cargo config rustflags (merged into upstream target arrays). Do not
  // set RUSTFLAGS env — it can replace config rustflags and drop crt-static.
  const windowsLinkEnv = windowsTarget
    ? {
        CARGO_PROFILE_RELEASE_DEBUG: "0",
        CARGO_PROFILE_RELEASE_STRIP: "symbols",
        CARGO_PROFILE_RELEASE_INCREMENTAL: "false",
      }
    : {};
  const buildEnv = {
    ...process.env,
    ...protocEnv,
    ...windowsLinkEnv,
    CARGO_TARGET_DIR: targetDir,
  };
  if (windowsTarget) {
    console.log("Windows release: CARGO_PROFILE_RELEASE_DEBUG=0 + cargo config /DEBUG:NONE");
  }
  if (options.xwin) {
    const pinnedCargo = capture("rustup", ["which", "--toolchain", GROK_RUST_TOOLCHAIN, "cargo"], root);
    run("cargo-xwin", buildArgs, sourceDir, {
      ...buildEnv,
      PATH: `${dirname(pinnedCargo)}${delimiter}${process.env.PATH ?? ""}`,
      RUSTUP_TOOLCHAIN: GROK_RUST_TOOLCHAIN,
    });
  } else {
    run("rustup", ["run", GROK_RUST_TOOLCHAIN, "cargo", ...buildArgs], sourceDir, {
      ...buildEnv,
    });
  }

  const built = grokBuildArtifact(targetDir, target, executableSuffix);
  await assertFile(built, "官方 grok-build 编译产物");
  await mkdir(resolve(root, "src-tauri/binaries"), { recursive: true });
  await copyFile(built, output);
  if (process.platform !== "win32") await chmod(output, 0o755);
}
if (!options.prepareOnly) {
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
}

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
    } else if (argument === "--prepare-only") {
      parsed.prepareOnly = true;
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

/**
 * Force Windows release links without PDBs so MSVC does not hit LNK4319.
 * Upstream grok-build already has .cargo/config.toml and notes that rustflags
 * are NOT additive — we must extend the existing msvc target arrays rather
 * than replace the whole file (which would drop force-unwind-tables / crt-static).
 */
async function writeWindowsReleaseCargoConfig(sourceDir) {
  const configPath = join(sourceDir, ".cargo", "config.toml");
  let body = await readFile(configPath, "utf8").catch(() => "");
  if (body.includes("SHOWNET_WIN_LNK4319_PATCH")) {
    console.log("Windows LNK4319 cargo config patch already applied");
    return;
  }
  // Append profile.release overrides (additive with existing file sections).
  body += `

# SHOWNET_WIN_LNK4319_PATCH — avoid MSVC PDB public-symbol limit (LNK4319)
[profile.release]
debug = 0
strip = "symbols"
incremental = false
`;
  // Patch each MSVC target's rustflags array to disable PDB generation.
  // rustflags are not additive across config layers for the same target.
  const msvcExtra = `"-C", "debuginfo=0", "-C", "link-arg=/DEBUG:NONE", "-C", "link-arg=/INCREMENTAL:NO"`;
  for (const triple of ["x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]) {
    const section = `[target.${triple}]`;
    const re = new RegExp(
      `(\\[target\\.${triple.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\]\\s*\\nrustflags\\s*=\\s*\\[[^\\]]*)(\\])`,
      "m",
    );
    if (re.test(body)) {
      body = body.replace(re, `$1, ${msvcExtra}$2`);
    } else if (body.includes(section)) {
      // section exists without rustflags — leave as-is and rely on RUSTFLAGS env
      console.log(`Note: ${section} present without rustflags array; using RUSTFLAGS env`);
    } else {
      body += `\n${section}\nrustflags = [${msvcExtra}]\n`;
    }
  }
  await writeFile(configPath, body, "utf8");
  console.log(`Patched Windows release cargo config: ${configPath}`);
}

function resetEphemeralPatches(directory) {
  // Restore tracked files we may have overwritten on a previous run.
  // Checkout one path at a time — some (e.g. bin/protoc.exe) are not in the tree.
  for (const relative of EPHEMERAL_SOURCE_PATHS) {
    try {
      capture("git", ["ls-files", "--error-unmatch", relative], directory);
      run("git", ["checkout", "HEAD", "--", relative], directory);
    } catch {
      // Path not in HEAD — ignore it without printing a misleading pathspec error.
    }
  }
}

async function ensurePinnedSource(directory) {
  if (options.fresh) await rm(directory, { recursive: true, force: true });
  let cloned = false;
  try {
    await stat(resolve(directory, ".git"));
  } catch {
    // CI rust-cache / prior partial runs can leave a non-empty directory without
    // .git; git clone refuses to write into it. Wipe and clone cleanly.
    await rm(directory, { recursive: true, force: true });
    await mkdir(resolve(directory, ".."), { recursive: true });
    run("git", ["clone", "--filter=blob:none", "--no-checkout", GROK_REPOSITORY, directory], root);
    cloned = true;
  }
  if (!cloned) {
    resetEphemeralPatches(directory);
    // Ignore leftover untracked protoc.exe from prior Windows builds.
    await rm(join(directory, "bin/protoc.exe"), { force: true }).catch(() => {});
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

/**
 * grok-build ships a `bin/protoc` that is a macOS "dotslash" stub (not a real
 * protoc binary). CI must provide a real protoc via PATH / PROTOC and we replace
 * the vendored stub so build.rs does not pick a non-Win32 / non-executable file.
 */
async function ensureRealProtoc(sourceDir) {
  const fromEnv = process.env.PROTOC?.trim();
  let protocPath = fromEnv || "";
  if (!protocPath) {
    const which = process.platform === "win32" ? "where" : "which";
    const found = spawnSync(which, ["protoc"], { encoding: "utf8" });
    if (found.status === 0) {
      protocPath = found.stdout.trim().split(/\r?\n/).find(Boolean) ?? "";
    }
  }
  if (!protocPath) {
    throw new Error(
      "protoc not found. Install protobuf compiler and set PROTOC, or put protoc on PATH (CI: arduino/setup-protoc).",
    );
  }
  await access(protocPath, fsConstants.X_OK).catch(async () => {
    await access(protocPath, fsConstants.F_OK);
  });
  const version = spawnSync(protocPath, ["--version"], { encoding: "utf8" });
  if (version.status !== 0) {
    throw new Error(`protoc at ${protocPath} is not runnable: ${version.stderr || version.stdout}`);
  }
  console.log(`Using protoc: ${protocPath} (${version.stdout.trim()})`);

  const binDir = join(sourceDir, "bin");
  await mkdir(binDir, { recursive: true });
  // Remove non-portable stubs (no extension and wrong-arch copies).
  for (const name of ["protoc", "protoc.exe"]) {
    await rm(join(binDir, name), { force: true }).catch(() => {});
  }
  const destName = process.platform === "win32" ? "protoc.exe" : "protoc";
  const dest = join(binDir, destName);
  await copyFile(protocPath, dest);
  if (process.platform !== "win32") await chmod(dest, 0o755);
  // Also place plain "protoc" on Windows for build scripts that look for that name.
  if (process.platform === "win32") {
    await copyFile(protocPath, join(binDir, "protoc"));
  }
  return { PROTOC: dest };
}

/**
 * Upstream xai-proto-build runs:
 *   protoc --dependency_out=/dev/stdout --descriptor_set_out=/dev/null ...
 * Those device paths do not exist on Windows, so Windows CI fails with:
 *   /dev/stdout: No such file or directory
 * Rewrite the build helper to use temp files when building on win32.
 */
async function patchWindowsProtocDeps(sourceDir) {
  if (process.platform !== "win32") return;
  const libPath = join(sourceDir, "crates/build/xai-proto-build/src/lib.rs");
  let source = await readFile(libPath, "utf8");
  // Git on Windows may materialize CRLF; normalize before matching LF snippets.
  const hadCrlf = source.includes("\r\n");
  source = source.replace(/\r\n/g, "\n");
  if (source.includes("SHOWNET_WIN_PROTOC_PATCH")) {
    console.log("Windows protoc dependency patch already applied");
    return;
  }
  const needle = `            command
                .arg("--dependency_out=/dev/stdout")
                .arg("--descriptor_set_out=/dev/null");

            // Add protoc's well-known types include directory first (if found).
            // This is needed for Bazel sandboxed builds where protoc and its
            // include files are in different locations.
            if let Some(include_dir) = protoc_include_dir {
                command.arg(format!(
                    "-I{}",
                    include_dir.to_str().context("include path not UTF-8")?
                ));
            }

            for include in &includes {
                command.arg(format!("-I{}", include.to_str().context("path not UTF-8")?));
            }

            command.arg(proto);

            command.stdin(Stdio::null());
            command.stderr(Stdio::inherit());

            let output = command.output().context("protoc command failed")?;
            if !output.status.success() {
                return Err(anyhow::anyhow!("protoc command failed"));
            }

            let output =
                String::from_utf8(output.stdout).context("protoc command output not UTF-8")?;

            let mut lines = output.lines();
            let first_line = lines.next().context("protoc command output is empty")?;
            let prefix = "/dev/null:";
            let rem = first_line.strip_prefix(prefix).with_context(|| {
                format!("protoc command output must start with /dev/null: {output:?}")
            })?;`;

  const replacement = `            // SHOWNET_WIN_PROTOC_PATCH: Windows has no /dev/stdout or /dev/null.
            let dep_path = std::env::temp_dir().join(format!(
                "shownet-protoc-deps-{}-{}.d",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let null_path = dep_path.with_extension("pb");
            let null_prefix = format!("{}:", null_path.display());
            command
                .arg(format!("--dependency_out={}", dep_path.display()))
                .arg(format!("--descriptor_set_out={}", null_path.display()));

            // Add protoc's well-known types include directory first (if found).
            // This is needed for Bazel sandboxed builds where protoc and its
            // include files are in different locations.
            if let Some(include_dir) = protoc_include_dir {
                command.arg(format!(
                    "-I{}",
                    include_dir.to_str().context("include path not UTF-8")?
                ));
            }

            for include in &includes {
                command.arg(format!("-I{}", include.to_str().context("path not UTF-8")?));
            }

            command.arg(proto);

            command.stdin(Stdio::null());
            command.stderr(Stdio::inherit());

            let output = command.output().context("protoc command failed")?;
            if !output.status.success() {
                let _ = fs::remove_file(&dep_path);
                let _ = fs::remove_file(&null_path);
                return Err(anyhow::anyhow!("protoc command failed"));
            }

            let output = fs::read_to_string(&dep_path).context("failed to read protoc dependency file")?;
            let _ = fs::remove_file(&dep_path);
            let _ = fs::remove_file(&null_path);

            let mut lines = output.lines();
            let first_line = lines.next().context("protoc command output is empty")?;
            // Match protoc's "out.pb: deps" line without split_once(':') — Windows drive letters contain ':'.
            let null_fwd = null_path.display().to_string().replace('\\\\', "/");
            let rem = first_line
                .strip_prefix(null_prefix.as_str())
                .or_else(|| first_line.strip_prefix(format!("{}:", null_fwd).as_str()))
                .with_context(|| {
                    format!("protoc dependency output missing descriptor prefix: {output:?}")
                })?;`;

  if (!source.includes(needle)) {
    // Diagnostics for upstream drift / line-ending surprises.
    const idx = source.indexOf("dependency_out");
    const snippet = idx >= 0 ? source.slice(Math.max(0, idx - 40), idx + 200) : "<no dependency_out>";
    throw new Error(
      `Unable to apply Windows protoc patch: expected snippet missing in xai-proto-build/src/lib.rs (upstream changed?). Near match: ${JSON.stringify(snippet)}`,
    );
  }
  source = source.replace(needle, replacement);
  if (hadCrlf) source = source.replace(/\n/g, "\r\n");
  await writeFile(libPath, source, "utf8");
  console.log("Applied Windows protoc dependency patch to xai-proto-build");
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
