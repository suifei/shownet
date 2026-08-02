import { lstat, readFile, readdir, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyArchive } from "./archive-local-release.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

export async function cleanLocalBuildCache(options = {}) {
  const projectRoot = options.projectRoot ?? root;
  const packageMetadata = options.packageMetadata
    ?? JSON.parse(await readFile(resolve(projectRoot, "package.json"), "utf8"));
  const releaseDirectory = options.releaseDirectory
    ?? resolve(projectRoot, "release", `ShowNet-${packageMetadata.version}-local-qa`);
  const manifest = JSON.parse(await readFile(resolve(releaseDirectory, "release-manifest.json"), "utf8"));
  if (manifest.product !== "ShowNet"
    || manifest.version !== packageMetadata.version
    || manifest.channel !== "local-unsigned-qa") {
    throw new Error("Refusing to clean without a matching verified ShowNet local QA archive");
  }
  await verifyArchive(releaseDirectory, manifest);

  const projectPaths = options.projectPaths ?? [
    resolve(projectRoot, "src-tauri", "target"),
    resolve(projectRoot, "src-tauri", ".sidecar-src"),
    resolve(projectRoot, "packaging", "windows", "launcher", "target"),
    resolve(projectRoot, "dist"),
    resolve(projectRoot, "output"),
  ];
  const generatedSidecars = options.generatedSidecars ?? await listGeneratedSidecars(projectRoot);
  const xwinCache = options.xwinCache ?? resolve(homedir(), "Library", "Caches", "cargo-xwin");
  const paths = [...projectPaths, ...generatedSidecars];
  if (options.includeXwinCache) paths.push(xwinCache);
  for (const path of paths) assertAllowedCleanupPath(path, projectRoot, xwinCache);

  const existing = [];
  let bytes = 0;
  for (const path of paths) {
    const info = await lstat(path).catch(() => null);
    if (!info) continue;
    existing.push(path);
    bytes += await recursiveSize(path);
  }

  if (!options.confirm) {
    return { cleaned: false, bytes, paths: existing, releaseDirectory };
  }
  for (const path of existing) {
    await rm(path, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  }
  await removeFinderMetadata(projectRoot);
  return { cleaned: true, bytes, paths: existing, releaseDirectory };
}

function assertAllowedCleanupPath(path, projectRoot, xwinCache) {
  const normalized = resolve(path);
  const insideProject = normalized.startsWith(`${projectRoot}${sep}`) && normalized !== projectRoot;
  if (!insideProject && normalized !== resolve(xwinCache)) {
    throw new Error(`Refusing to clean path outside the approved build roots: ${path}`);
  }
}

async function listGeneratedSidecars(projectRoot) {
  const directory = resolve(projectRoot, "src-tauri", "binaries");
  return (await readdir(directory).catch(() => []))
    .filter((name) => name.startsWith("grok-build-"))
    .map((name) => resolve(directory, name));
}

async function recursiveSize(path) {
  const info = await lstat(path);
  if (!info.isDirectory()) return info.size;
  let bytes = 0;
  for (const entry of await readdir(path)) bytes += await recursiveSize(resolve(path, entry));
  return bytes;
}

async function removeFinderMetadata(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true }).catch(() => [])) {
    const path = resolve(directory, entry.name);
    if (entry.name === ".DS_Store") await rm(path, { force: true });
    else if (entry.isDirectory()) await removeFinderMetadata(path);
  }
}

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function parseArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--confirm") options.confirm = true;
    else if (argument === "--include-xwin-cache") options.includeXwinCache = true;
    else if (argument === "--release") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error("--release requires a value");
      options.releaseDirectory = resolve(value);
      index += 1;
    } else throw new Error(`Unknown argument: ${argument}`);
  }
  return options;
}

async function main() {
  const result = await cleanLocalBuildCache(parseArguments(process.argv.slice(2)));
  if (result.cleaned) {
    console.log(`Cleaned ${formatBytes(result.bytes)} of verified local build cache.`);
    return;
  }
  console.log(`Verified release archive: ${result.releaseDirectory}`);
  console.log(`Would clean ${formatBytes(result.bytes)} from:`);
  for (const path of result.paths) {
    const label = path.startsWith(`${root}${sep}`) ? relative(root, path) : path;
    console.log(`- ${label || basename(path)}`);
  }
  console.log("Run again with --confirm after reviewing this list.");
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
