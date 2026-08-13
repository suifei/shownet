import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const PRIMARY_BASE_URL = "https://x.ai/cli";
const FALLBACK_BASE_URL = "https://storage.googleapis.com/grok-build-public-artifacts/cli";
const SOURCE_REPOSITORY = "https://github.com/xai-org/grok-build";

export function validateGrokVersion(value) {
  const version = value.trim();
  if (!/^\d+\.\d+\.\d+(?:-[A-Za-z0-9._]+)?$/.test(version)) {
    throw new Error(`Invalid Grok stable version: ${JSON.stringify(value)}`);
  }
  return version;
}

export function officialPlatformForTarget(target) {
  const platforms = {
    "aarch64-apple-darwin": { platform: "macos-aarch64", suffix: "" },
    "x86_64-pc-windows-msvc": { platform: "windows-x86_64", suffix: ".exe" },
  };
  const platform = platforms[target];
  if (!platform) throw new Error(`No official Grok binary is configured for target ${target}`);
  return platform;
}

export function officialArtifactUrls(version, target) {
  const { platform, suffix } = officialPlatformForTarget(target);
  const name = `grok-${validateGrokVersion(version)}-${platform}${suffix}`;
  return [PRIMARY_BASE_URL, FALLBACK_BASE_URL].map((baseUrl) => `${baseUrl}/${name}`);
}

export function parseGrokVersionOutput(output, expectedVersion) {
  const normalized = output.trim();
  const version = validateGrokVersion(expectedVersion);
  if (!new RegExp(`\\b${version.replaceAll(".", "\\.")}(?:\\s|\\(|$)`).test(normalized)) {
    throw new Error(`Downloaded Grok reports ${JSON.stringify(normalized)}, expected ${version}`);
  }
  return normalized;
}

async function fetchText(url) {
  const response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  return response.text();
}

async function download(url, output) {
  const response = await fetch(url, { redirect: "follow", signal: AbortSignal.timeout(10 * 60_000) });
  if (!response.ok || !response.body) throw new Error(`${url} returned HTTP ${response.status}`);
  const temporary = `${output}.download-${process.pid}`;
  await rm(temporary, { force: true });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 1_000_000) throw new Error(`${url} returned an unexpectedly small binary (${bytes.length} bytes)`);
  await writeFile(temporary, bytes, { mode: 0o700 });
  await rename(temporary, output);
  return response.url || url;
}

function assertBinaryFormat(bytes, target) {
  if (target === "aarch64-apple-darwin") {
    if (bytes.length < 8 || bytes.readUInt32LE(0) !== 0xfeedfacf || bytes.readUInt32LE(4) !== 0x0100000c) {
      throw new Error("Official Grok download is not a Mach-O arm64 executable");
    }
    return;
  }
  const peOffset = bytes.length >= 0x40 ? bytes.readUInt32LE(0x3c) : -1;
  if (bytes.subarray(0, 2).toString("ascii") !== "MZ"
    || peOffset < 0
    || peOffset + 6 > bytes.length
    || bytes.subarray(peOffset, peOffset + 4).toString("binary") !== "PE\0\0"
    || bytes.readUInt16LE(peOffset + 4) !== 0x8664) {
    throw new Error("Official Grok download is not a Windows AMD64 PE executable");
  }
}

function runVersion(binary) {
  const result = spawnSync(binary, ["--version"], { encoding: "utf8", timeout: 30_000 });
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  if (result.error) throw new Error(`Downloaded Grok could not start: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`Downloaded Grok --version failed (${result.status}): ${output}`);
  return output;
}

async function stampSidecar({ output, target, version, artifactUrl, versionOutput }) {
  const bytes = await readFile(output);
  assertBinaryFormat(bytes, target);
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  const metadata = {
    schemaVersion: 1,
    name: "xai-org/grok-build",
    repository: SOURCE_REPOSITORY,
    distribution: PRIMARY_BASE_URL,
    channel: "stable",
    version,
    target,
    artifactUrl,
    downloadSha256: sha256,
    versionOutput,
  };
  await writeFile(`${output}.sha256`, `${sha256}  ${basename(output)}\n`, "utf8");
  await writeFile(`${output}.metadata.json`, `${JSON.stringify(metadata, null, 2)}\n`, "utf8");
  await writeFile(
    resolve(root, "src-tauri/binaries/grok-build-source.json"),
    `${JSON.stringify(metadata, null, 2)}\n`,
    "utf8",
  );
  return metadata;
}

export async function resolveStableVersion() {
  const failures = [];
  for (const baseUrl of [PRIMARY_BASE_URL, FALLBACK_BASE_URL]) {
    try {
      return validateGrokVersion(await fetchText(`${baseUrl}/stable`));
    } catch (error) {
      failures.push(error.message);
    }
  }
  throw new Error(`Unable to resolve official Grok stable version: ${failures.join("; ")}`);
}

async function downloadSidecar(options) {
  const version = validateGrokVersion(options.version);
  const target = options.target;
  const { suffix } = officialPlatformForTarget(target);
  const output = resolve(root, `src-tauri/binaries/grok-build-${target}${suffix}`);
  await mkdir(resolve(root, "src-tauri/binaries"), { recursive: true });

  let artifactUrl = options.artifactUrl;
  if (!options.stampOnly) {
    const failures = [];
    for (const url of officialArtifactUrls(version, target)) {
      try {
        artifactUrl = await download(url, output);
        break;
      } catch (error) {
        failures.push(error.message);
      }
    }
    if (!artifactUrl) throw new Error(`Unable to download official Grok ${version}: ${failures.join("; ")}`);
    if (process.platform !== "win32") await chmod(output, 0o755);
  }

  const info = await stat(output).catch(() => null);
  if (!info?.isFile() || info.size === 0) throw new Error(`Agent sidecar is missing: ${output}`);
  const existing = JSON.parse(await readFile(`${output}.metadata.json`, "utf8").catch(() => "{}"));
  artifactUrl ??= existing.artifactUrl;
  if (!artifactUrl || !officialArtifactUrls(version, target).includes(artifactUrl)) {
    throw new Error(`Agent artifact URL is not an official x.ai distribution URL: ${artifactUrl ?? "<missing>"}`);
  }
  const versionOutput = options.stampOnly ? existing.versionOutput : runVersion(output);
  parseGrokVersionOutput(versionOutput, version);
  const metadata = await stampSidecar({ output, target, version, artifactUrl, versionOutput });
  console.log(`Prepared official Grok ${version} for ${target}`);
  console.log(`Source: ${artifactUrl}`);
  console.log(`Downloaded SHA-256: ${metadata.downloadSha256}`);
}

function parseArguments(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (["--target", "--version", "--artifact-url"].includes(argument)) {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      parsed[argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
      index += 1;
    } else if (argument === "--resolve-version") parsed.resolveVersion = true;
    else if (argument === "--stamp-only") parsed.stampOnly = true;
    else throw new Error(`Unknown argument: ${argument}`);
  }
  return parsed;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  if (options.resolveVersion) {
    const version = await resolveStableVersion();
    console.log(version);
    if (process.env.GITHUB_OUTPUT) await writeFile(process.env.GITHUB_OUTPUT, `version=${version}\n`, { flag: "a" });
    return;
  }
  if (!options.target || !options.version) throw new Error("--target and --version are required");
  await downloadSidecar(options);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
