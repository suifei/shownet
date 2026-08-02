import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  open,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyPortablePackage } from "./package-windows-portable.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

export async function archiveLocalRelease(options = {}) {
  const packageMetadata = options.packageMetadata
    ?? JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  const version = options.version ?? packageMetadata.version;
  const dmg = options.dmg ?? await findSingleDmg(
    resolve(root, "src-tauri", "target", "release", "bundle", "dmg"),
  );
  const portable = options.portable ?? resolve(
    root,
    "src-tauri",
    "target",
    "x86_64-pc-windows-msvc",
    "release",
    "bundle",
    "portable",
    "ShowNetPortable",
  );
  const output = options.output ?? resolve(root, "release", `ShowNet-${version}-local-qa`);
  const dmgName = `ShowNet_${version}_macOS_arm64.dmg`;
  const zipName = `ShowNetPortable_${version}_windows_x86_64.zip`;

  await assertDmg(dmg);
  await verifyPortablePackage(portable, { version });
  if (options.replace) await rm(output, { recursive: true, force: true });
  if (await stat(output).catch(() => null)) {
    throw new Error(`Release output already exists; pass --replace to refresh it: ${output}`);
  }

  await mkdir(output, { recursive: true });
  try {
    const archivedDmg = resolve(output, dmgName);
    const archivedZip = resolve(output, zipName);
    await copyFile(dmg, archivedDmg);
    createZip(portable, archivedZip);
    verifyZip(archivedZip);

    const artifacts = {};
    for (const [platform, path] of [["macOS-arm64", archivedDmg], ["windows-x86_64", archivedZip]]) {
      const info = await stat(path);
      artifacts[platform] = {
        file: basename(path),
        bytes: info.size,
        sha256: await sha256(path),
      };
    }
    const manifest = {
      schemaVersion: 1,
      product: "ShowNet",
      version,
      channel: "local-unsigned-qa",
      generatedAt: new Date().toISOString(),
      signing: {
        macOS: "ad-hoc",
        windows: "unsigned",
      },
      artifacts,
    };
    const manifestName = "release-manifest.json";
    const manifestPath = resolve(output, manifestName);
    await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

    const checksums = [
      `${artifacts["macOS-arm64"].sha256}  ${dmgName}`,
      `${artifacts["windows-x86_64"].sha256}  ${zipName}`,
      `${await sha256(manifestPath)}  ${manifestName}`,
    ];
    await writeFile(resolve(output, "SHA256SUMS.txt"), `${checksums.join("\n")}\n`, "ascii");
    await verifyArchive(output, manifest);
    return { output, manifest };
  } catch (error) {
    await rm(output, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyArchive(output, manifest) {
  for (const artifact of Object.values(manifest.artifacts)) {
    const path = resolve(output, artifact.file);
    const info = await stat(path).catch(() => null);
    if (!info?.isFile() || info.size !== artifact.bytes || await sha256(path) !== artifact.sha256) {
      throw new Error(`Archived artifact does not match release manifest: ${artifact.file}`);
    }
  }
  const checksumLines = (await readFile(resolve(output, "SHA256SUMS.txt"), "ascii"))
    .trim()
    .split(/\r?\n/);
  if (checksumLines.length !== 3) throw new Error("Local release must contain three checksum entries");
  for (const line of checksumLines) {
    const match = /^([a-f0-9]{64})  ([^/\\]+)$/.exec(line);
    if (!match || await sha256(resolve(output, match[2])) !== match[1]) {
      throw new Error(`Invalid local release checksum entry: ${line}`);
    }
  }
}

async function assertDmg(path) {
  const info = await stat(path).catch(() => null);
  if (!info?.isFile() || info.size < 512) throw new Error(`macOS DMG is missing or empty: ${path}`);
  const trailer = Buffer.alloc(4);
  const handle = await open(path, "r");
  try {
    await handle.read(trailer, 0, trailer.length, info.size - 512);
  } finally {
    await handle.close();
  }
  if (trailer.toString("ascii") !== "koly") {
    throw new Error(`macOS artifact is not a UDIF DMG: ${path}`);
  }
  if (process.platform === "darwin") run("hdiutil", ["verify", path], dirname(path));
}

async function findSingleDmg(directory) {
  const files = (await readdir(directory)).filter((file) => file.endsWith(".dmg"));
  if (files.length !== 1) throw new Error(`Expected exactly one DMG in ${directory}, received ${files.length}`);
  return resolve(directory, files[0]);
}

function createZip(portable, archive) {
  if (process.platform === "win32") {
    const escapedPortable = portable.replaceAll("'", "''");
    const escapedArchive = archive.replaceAll("'", "''");
    run("powershell.exe", [
      "-NoProfile",
      "-Command",
      `Compress-Archive -Path '${escapedPortable}' -DestinationPath '${escapedArchive}' -CompressionLevel Optimal -Force`,
    ], dirname(portable));
    return;
  }
  run("zip", ["-X", "-q", "-r", archive, basename(portable)], dirname(portable));
}

function verifyZip(archive) {
  if (process.platform === "win32") return;
  run("unzip", ["-tq", archive], dirname(archive));
  const listing = run("unzip", ["-Z1", archive], dirname(archive), true);
  const forbidden = listing.split(/\r?\n/).filter((entry) =>
    /(?:^|\/)(?:__MACOSX|\.DS_Store)(?:\/|$)/.test(entry)
      || /\.(?:pdb|ilk|exp|lib|sqlite3?|db)$/i.test(entry),
  );
  if (forbidden.length > 0) throw new Error(`Release ZIP contains forbidden files: ${forbidden.join(", ")}`);
}

function run(command, args, cwd, capture = false) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit",
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} failed with exit code ${result.status}: ${result.stderr ?? ""}`.trim());
  }
  return result.stdout ?? "";
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function parseArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--replace") {
      options.replace = true;
      continue;
    }
    if (!["--dmg", "--portable", "--output"].includes(argument)) {
      throw new Error(`Unknown argument: ${argument}`);
    }
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
    if (argument === "--dmg") options.dmg = resolve(value);
    else if (argument === "--portable") options.portable = resolve(value);
    else options.output = resolve(value);
    index += 1;
  }
  return options;
}

async function main() {
  const result = await archiveLocalRelease(parseArguments(process.argv.slice(2)));
  console.log(`Archived verified local QA release at ${result.output}`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
