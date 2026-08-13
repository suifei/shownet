import { createHash } from "node:crypto";
import {
  copyFile,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const defaultTarget = "x86_64-pc-windows-msvc";

export async function buildPortablePackage(options = {}) {
  const packageJson = options.packageJson ?? JSON.parse(
    await readFile(resolve(projectRoot, "package.json"), "utf8"),
  );
  const target = options.target ?? defaultTarget;
  const version = options.version ?? packageJson.version;
  const frontendAssetReferences = options.frontendAssetReferences
    ?? await readFrontendAssetReferences();
  const releaseDirectory = options.releaseDirectory
    ?? resolve(projectRoot, "src-tauri", "target", target, "release");
  const outputDirectory = options.outputDirectory
    ?? resolve(releaseDirectory, "bundle", "portable", "ShowNetPortable");
  const sources = {
    application: options.application
      ?? resolve(releaseDirectory, "shownet.exe"),
    launcher: options.launcher
      ?? resolve(releaseDirectory, "shownet-portable-launcher.exe"),
    sidecar: options.sidecar
      ?? resolve(projectRoot, "src-tauri", "binaries", `grok-build-${target}.exe`),
    icon: options.icon ?? resolve(projectRoot, "src-tauri", "icons", "icon.ico"),
    projectLicense: options.projectLicense ?? resolve(projectRoot, "LICENSE"),
    notices: options.notices ?? resolve(projectRoot, "THIRD_PARTY_NOTICES.md"),
    agentLicense: options.agentLicense
      ?? resolve(projectRoot, "third-party", "grok-build", "LICENSE"),
    agentNotices: options.agentNotices
      ?? resolve(projectRoot, "third-party", "grok-build", "THIRD-PARTY-NOTICES"),
    agentSource: options.agentSource
      ?? resolve(projectRoot, "src-tauri", "binaries", "grok-build-source.json"),
  };

  validateTarget(target);
  const packageVersion = portablePackageVersion(version);
  await Promise.all([
    assertPeFile(sources.application, "ShowNet application", { subsystem: 2 }),
    assertPeFile(sources.launcher, "portable launcher", { subsystem: 2 }),
    assertPeFile(sources.sidecar, "built-in Agent"),
    assertIcoFile(sources.icon),
    ...Object.entries(sources)
      .filter(([name]) => !["application", "launcher", "sidecar", "icon"].includes(name))
      .map(([name, path]) => assertRegularFile(path, name)),
  ]);
  await assertProductionFrontend(
    sources.application,
    "ShowNet application",
    frontendAssetReferences,
  );

  await rm(outputDirectory, { recursive: true, force: true });
  const applicationDirectory = resolve(outputDirectory, "App", "ShowNet");
  const appInfoDirectory = resolve(outputDirectory, "App", "AppInfo");
  const agentLicenseDirectory = resolve(applicationDirectory, "licenses", "grok-build");
  const dataDirectory = resolve(outputDirectory, "Data", "ShowNet");
  await Promise.all([
    mkdir(applicationDirectory, { recursive: true }),
    mkdir(appInfoDirectory, { recursive: true }),
    mkdir(agentLicenseDirectory, { recursive: true }),
    mkdir(dataDirectory, { recursive: true }),
  ]);

  await Promise.all([
    copyFile(sources.launcher, resolve(outputDirectory, "ShowNetPortable.exe")),
    copyFile(sources.application, resolve(applicationDirectory, "ShowNet.exe")),
    copyFile(sources.sidecar, resolve(applicationDirectory, "grok-build.exe")),
    copyFile(sources.icon, resolve(appInfoDirectory, "appicon.ico")),
    copyFile(sources.projectLicense, resolve(applicationDirectory, "LICENSE")),
    copyFile(sources.notices, resolve(applicationDirectory, "THIRD_PARTY_NOTICES.md")),
    copyFile(sources.agentLicense, resolve(agentLicenseDirectory, "LICENSE")),
    copyFile(sources.agentNotices, resolve(agentLicenseDirectory, "THIRD-PARTY-NOTICES")),
    copyFile(sources.agentSource, resolve(agentLicenseDirectory, "SOURCE.json")),
  ]);

  const manifest = {
    schemaVersion: 1,
    product: "ShowNet",
    version,
    architecture: "x86_64",
    launcher: "ShowNetPortable.exe",
    application: "App/ShowNet/ShowNet.exe",
    sidecar: "App/ShowNet/grok-build.exe",
    dataDirectory: "Data/ShowNet",
    dataPolicy: "portable",
    frontendAssets: frontendAssetReferences,
  };
  await Promise.all([
    writeFile(
      resolve(appInfoDirectory, "appinfo.ini"),
      portableAppInfo(version, packageVersion),
      "utf8",
    ),
    writeFile(
      resolve(outputDirectory, "portable-manifest.json"),
      `${JSON.stringify(manifest, null, 2)}\n`,
      "utf8",
    ),
    writeFile(
      resolve(dataDirectory, ".portable"),
      "ShowNet stores its database, certificates, browser profile, and settings in this directory.\n",
      "utf8",
    ),
  ]);

  const files = await listFiles(outputDirectory);
  const checksumLines = [];
  for (const file of files) {
    const path = resolve(outputDirectory, file);
    const digest = createHash("sha256").update(await readFile(path)).digest("hex");
    checksumLines.push(`${digest}  ${file}`);
  }
  await writeFile(
    resolve(outputDirectory, "portable-checksums.sha256"),
    `${checksumLines.join("\n")}\n`,
    "utf8",
  );

  await verifyPortablePackage(outputDirectory, { version, frontendAssetReferences });
  return { outputDirectory, version, target };
}

export async function verifyPortablePackage(
  outputDirectory,
  { version, frontendAssetReferences } = {},
) {
  const required = [
    "ShowNetPortable.exe",
    "App/ShowNet/ShowNet.exe",
    "App/ShowNet/grok-build.exe",
    "App/ShowNet/LICENSE",
    "App/AppInfo/appicon.ico",
    "App/AppInfo/appinfo.ini",
    "App/ShowNet/licenses/grok-build/LICENSE",
    "App/ShowNet/licenses/grok-build/THIRD-PARTY-NOTICES",
    "App/ShowNet/licenses/grok-build/SOURCE.json",
    "Data/ShowNet/.portable",
    "portable-manifest.json",
    "portable-checksums.sha256",
  ];
  await Promise.all(required.map((file) => assertRegularFile(resolve(outputDirectory, file), file)));
  const manifest = JSON.parse(await readFile(resolve(outputDirectory, "portable-manifest.json"), "utf8"));
  const packagedFrontendAssets = validateFrontendAssetReferences(manifest.frontendAssets);
  const expectedFrontendAssets = frontendAssetReferences ?? packagedFrontendAssets;
  await Promise.all([
    assertPeFile(resolve(outputDirectory, "ShowNetPortable.exe"), "portable launcher", { subsystem: 2 }),
    assertPeFile(resolve(outputDirectory, "App/ShowNet/ShowNet.exe"), "ShowNet application", { subsystem: 2 }),
    assertPeFile(resolve(outputDirectory, "App/ShowNet/grok-build.exe"), "built-in Agent"),
    assertIcoFile(resolve(outputDirectory, "App/AppInfo/appicon.ico")),
  ]);
  await assertProductionFrontend(
    resolve(outputDirectory, "App/ShowNet/ShowNet.exe"),
    "ShowNet application",
    expectedFrontendAssets,
  );

  if (manifest.dataDirectory !== "Data/ShowNet" || manifest.dataPolicy !== "portable") {
    throw new Error("Portable manifest must keep all mutable data in Data/ShowNet");
  }
  if (version && manifest.version !== version) {
    throw new Error(`Portable manifest version ${manifest.version} does not match ${version}`);
  }
  const appInfo = await readFile(resolve(outputDirectory, "App/AppInfo/appinfo.ini"), "utf8");
  for (const expected of ["Type=PortableApps.comFormat", "AppID=ShowNetPortable", "Start=ShowNetPortable.exe"]) {
    if (!appInfo.includes(expected)) throw new Error(`appinfo.ini is missing ${expected}`);
  }

  const forbidden = (await listFiles(outputDirectory)).filter((file) =>
    /(?:^|\/)(?:target|debug)(?:\/|$)/i.test(file)
      || /\.(?:pdb|ilk|exp|lib|sqlite3?|db)$/i.test(file),
  );
  if (forbidden.length > 0) {
    throw new Error(`Portable package contains build or mutable data: ${forbidden.join(", ")}`);
  }
  await verifyPortableChecksums(outputDirectory);
}

function portableAppInfo(displayVersion, packageVersion) {
  return [
    "[Format]",
    "Type=PortableApps.comFormat",
    "Version=3.7",
    "",
    "[Details]",
    "Name=ShowNet Portable",
    "AppID=ShowNetPortable",
    "Publisher=ShowNet Team",
    "Homepage=https://claudegpt.org/shownet",
    "Category=Development",
    "Description=AI-native traffic capture and protocol analysis",
    "Language=Multilingual",
    "",
    "[License]",
    "Shareable=true",
    "OpenSource=true",
    "CommercialUse=true",
    "",
    "[Version]",
    `PackageVersion=${packageVersion}`,
    `DisplayVersion=${displayVersion}`,
    "",
    "[Control]",
    "Icons=1",
    "Start=ShowNetPortable.exe",
    "BaseAppID=com.shownet.desktop",
    "",
  ].join("\r\n");
}

function portablePackageVersion(version) {
  const match = /^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(version ?? "");
  if (!match) throw new Error(`Invalid package version: ${version ?? "<missing>"}`);
  return `${match[1]}.${match[2]}.${match[3]}.0`;
}

function validateTarget(target) {
  if (target !== defaultTarget) {
    throw new Error(`Windows portable packages require ${defaultTarget}, received ${target}`);
  }
}

async function assertRegularFile(path, label) {
  const info = await stat(path).catch(() => null);
  if (!info?.isFile() || info.size === 0) throw new Error(`${label} is missing or empty: ${path}`);
}

async function assertPeFile(path, label, { subsystem } = {}) {
  await assertRegularFile(path, label);
  const bytes = await readFile(path);
  const peOffset = bytes.length >= 0x40 ? bytes.readUInt32LE(0x3c) : -1;
  const hasPeSignature = peOffset >= 0
    && peOffset + 6 <= bytes.length
    && bytes.subarray(peOffset, peOffset + 4).equals(Buffer.from([0x50, 0x45, 0x00, 0x00]));
  const machine = hasPeSignature ? bytes.readUInt16LE(peOffset + 4) : -1;
  if (bytes[0] !== 0x4d || bytes[1] !== 0x5a || !hasPeSignature || machine !== 0x8664) {
    throw new Error(`${label} is not a Windows AMD64 PE executable: ${path}`);
  }
  if (subsystem !== undefined) {
    const optionalHeader = peOffset + 24;
    const optionalMagic = optionalHeader + 2 <= bytes.length
      ? bytes.readUInt16LE(optionalHeader)
      : -1;
    const subsystemOffset = optionalHeader + 68;
    const actualSubsystem = optionalMagic === 0x20b && subsystemOffset + 2 <= bytes.length
      ? bytes.readUInt16LE(subsystemOffset)
      : -1;
    if (actualSubsystem !== subsystem) {
      throw new Error(`${label} is not a Windows GUI executable: ${path}`);
    }
  }
}

async function assertIcoFile(path) {
  await assertRegularFile(path, "Windows icon");
  const bytes = await readFile(path);
  if (bytes.length < 4 || !bytes.subarray(0, 4).equals(Buffer.from([0, 0, 1, 0]))) {
    throw new Error(`Windows icon is not an ICO file: ${path}`);
  }
}

async function readFrontendAssetReferences() {
  const index = await readFile(resolve(projectRoot, "dist", "index.html"), "utf8");
  const references = [...index.matchAll(/(?:src|href)=["']\/?([^"']+\.(?:js|css))(?:[?#][^"']*)?["']/g)]
    .map((match) => match[1]);
  if (references.length === 0) {
    throw new Error("dist/index.html does not reference production JavaScript or CSS assets");
  }
  return validateFrontendAssetReferences(references);
}

function validateFrontendAssetReferences(references) {
  if (!Array.isArray(references) || references.length === 0) {
    throw new Error("Portable manifest must list embedded production frontend assets");
  }
  const normalized = [...new Set(references)];
  if (normalized.some((reference) =>
    typeof reference !== "string"
      || !/^assets\/[A-Za-z0-9_.-]+\.(?:js|css)$/.test(reference)
  )) {
    throw new Error("Portable manifest contains an invalid frontend asset reference");
  }
  return normalized.sort();
}

async function assertProductionFrontend(path, label, frontendAssetReferences) {
  const bytes = await readFile(path);
  const missing = frontendAssetReferences.filter((reference) =>
    !bytes.includes(Buffer.from(reference, "utf8"))
  );
  if (missing.length > 0) {
    throw new Error(`${label} does not embed production frontend assets: ${missing.join(", ")}`);
  }
}

async function listFiles(root) {
  const files = [];
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(relative(root, path).split("\\").join("/"));
    }
  }
  await visit(root);
  return files.sort();
}

async function verifyPortableChecksums(outputDirectory) {
  const checksumFile = "portable-checksums.sha256";
  const actualFiles = (await listFiles(outputDirectory)).filter((file) => file !== checksumFile);
  const lines = (await readFile(resolve(outputDirectory, checksumFile), "utf8"))
    .split(/\r?\n/)
    .filter(Boolean);
  const expected = new Map();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  ([^\\]+)$/.exec(line);
    if (!match || match[2].startsWith("/") || match[2].split("/").includes("..")) {
      throw new Error(`Invalid portable checksum entry: ${line}`);
    }
    if (expected.has(match[2])) throw new Error(`Duplicate portable checksum entry: ${match[2]}`);
    expected.set(match[2], match[1]);
  }

  const listedFiles = [...expected.keys()].sort();
  if (JSON.stringify(listedFiles) !== JSON.stringify(actualFiles)) {
    throw new Error("Portable checksum manifest does not list the exact package contents");
  }
  for (const file of actualFiles) {
    const digest = createHash("sha256")
      .update(await readFile(resolve(outputDirectory, file)))
      .digest("hex");
    if (digest !== expected.get(file)) throw new Error(`Portable checksum mismatch: ${file}`);
  }
}

function parseArguments(args) {
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!["--target", "--output"].includes(argument)) throw new Error(`Unknown argument: ${argument}`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
    if (argument === "--target") options.target = value;
    else options.outputDirectory = resolve(value);
    index += 1;
  }
  return options;
}

async function main() {
  const result = await buildPortablePackage(parseArguments(process.argv.slice(2)));
  console.log(`Built verified ShowNet ${result.version} portable package at ${result.outputDirectory}`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  await main();
}
