import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { validateAppIconSet } from "./app-icon-tools.mjs";
import { validateMacBundleSigningConfig } from "./verify-macos-release.mjs";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const options = parseArguments(process.argv.slice(2));
const requiredAgentTarget = options.requireAgentTarget ?? process.env.SHOWNET_AGENT_TARGET;
const packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
const tauriConfig = JSON.parse(await readFile(resolve(root, "src-tauri/tauri.conf.json"), "utf8"));
const agentBundleConfig = JSON.parse(await readFile(resolve(root, "src-tauri/tauri.grok.conf.json"), "utf8"));
const agentSource = JSON.parse(await readFile(resolve(root, "third-party/grok-build/SOURCE.json"), "utf8"));
const releaseWorkflow = await readFile(resolve(root, ".github/workflows/release.yml"), "utf8");
const portableLauncher = await readFile(resolve(root, "packaging/windows/launcher/src/main.rs"), "utf8");
const portablePackager = await readFile(resolve(root, "scripts/package-windows-portable.mjs"), "utf8");
const desktopMain = await readFile(resolve(root, "src-tauri/src/main.rs"), "utf8");
const cargoToml = await readFile(resolve(root, "src-tauri/Cargo.toml"), "utf8");
const projectLicense = await readFile(resolve(root, "LICENSE"), "utf8");
const cargoVersion = cargoToml.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const versions = new Map([
  ["package.json", packageJson.version],
  ["src-tauri/tauri.conf.json", tauriConfig.version],
  ["src-tauri/Cargo.toml", cargoVersion],
]);

for (const [file, version] of versions) {
  if (!version || version !== packageJson.version) {
    throw new Error(`${file} version ${version ?? "<missing>"} does not match ${packageJson.version}`);
  }
}

validateProjectLicense(packageJson, cargoToml, projectLicense, portablePackager);

const tag = process.env.GITHUB_REF_NAME;
if (tag?.startsWith("v") && tag.slice(1) !== packageJson.version) {
  throw new Error(`release tag ${tag} does not match version ${packageJson.version}`);
}

if (tauriConfig.productName !== "ShowNet") throw new Error("Tauri productName must be ShowNet");
if (!/^[a-z][a-z0-9-]*(\.[a-z0-9-]+){2,}$/.test(tauriConfig.identifier)
  || ["com.tauri.dev", "com.example.app"].includes(tauriConfig.identifier)) {
  throw new Error(`Tauri identifier is not release-ready: ${tauriConfig.identifier}`);
}

const requiredBundleIcons = [
  "src-tauri/icons/32x32.png",
  "src-tauri/icons/128x128.png",
  "src-tauri/icons/128x128@2x.png",
  "src-tauri/icons/icon.icns",
  "src-tauri/icons/icon.ico",
];
const configuredIcons = new Set(tauriConfig.bundle?.icon ?? []);
for (const file of requiredBundleIcons) {
  const relative = file.replace("src-tauri/", "");
  if (!configuredIcons.has(relative)) throw new Error(`${relative} is not configured for bundling`);
}
await validateAppIconSet(root);

validateAgentSource(agentSource);
await validateAgentLicenses(agentSource);
validateAgentBundleConfig(agentBundleConfig);
validateMacBundleSigningConfig(agentBundleConfig);
validateWindowsPortableRelease(packageJson, releaseWorkflow, desktopMain, portableLauncher, portablePackager);
if (requiredAgentTarget) await validateAgentSidecar(requiredAgentTarget, agentSource);

console.log(`ShowNet ${packageJson.version} release metadata is consistent${requiredAgentTarget ? ` for ${requiredAgentTarget}` : ""}.`);

function parseArguments(args) {
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--require-agent-target") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      parsed.requireAgentTarget = value;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return parsed;
}

function validateAgentSource(source) {
  if (source.name !== "xai-org/grok-build") throw new Error("Unexpected Agent source name");
  if (!/^https:\/\/github\.com\/xai-org\/grok-build(?:\.git)?$/.test(source.repository ?? "")) {
    throw new Error("Agent source repository must be the official xai-org/grok-build repository");
  }
  if (!/^\d+\.\d+\.\d+$/.test(source.version ?? "")) throw new Error("Agent source version is invalid");
  if (!/^[0-9a-f]{40}$/.test(source.commit ?? "")) throw new Error("Agent source commit must be a full Git SHA");
  if (source.license !== "Apache-2.0") throw new Error("Agent source license must be Apache-2.0");
  if (!/^\d+\.\d+\.\d+$/.test(source.rustToolchain ?? "")) throw new Error("Agent Rust toolchain is invalid");
}

function validateProjectLicense(packageMetadata, cargoMetadata, license, packager) {
  if (packageMetadata.license !== "GPL-3.0-only") {
    throw new Error("package.json must declare GPL-3.0-only");
  }
  if (!/^license\s*=\s*"GPL-3\.0-only"$/m.test(cargoMetadata)) {
    throw new Error("src-tauri/Cargo.toml must declare GPL-3.0-only");
  }
  if (Buffer.byteLength(license) < 30_000
    || !license.includes("GNU GENERAL PUBLIC LICENSE")
    || !license.includes("Version 3, 29 June 2007")) {
    throw new Error("LICENSE must contain the complete GNU GPL version 3 text");
  }
  for (const required of ["App/ShowNet/LICENSE", "OpenSource=true"]) {
    if (!packager.includes(required)) throw new Error(`Portable packager is missing ${required}`);
  }
}

async function validateAgentLicenses(source) {
  const license = await readFile(resolve(root, "third-party/grok-build/LICENSE"), "utf8");
  const notices = await readFile(resolve(root, "third-party/grok-build/THIRD-PARTY-NOTICES"), "utf8");
  const projectNotices = await readFile(resolve(root, "THIRD_PARTY_NOTICES.md"), "utf8");
  if (!license.includes("Apache License") || !license.includes("Version 2.0, January 2004")) {
    throw new Error("grok-build LICENSE is not the complete Apache-2.0 license");
  }
  if (Buffer.byteLength(notices) < 100_000 || !notices.includes("THIRD-PARTY")) {
    throw new Error("grok-build THIRD-PARTY-NOTICES is missing or incomplete");
  }
  for (const value of [source.version, source.commit, source.repository]) {
    if (!projectNotices.includes(value)) throw new Error(`THIRD_PARTY_NOTICES.md does not reference ${value}`);
  }
}

function validateAgentBundleConfig(config) {
  const externalBins = config.bundle?.externalBin ?? [];
  if (!externalBins.includes("binaries/grok-build")) {
    throw new Error("tauri.grok.conf.json must bundle binaries/grok-build");
  }
  const requiredResources = new Map([
    ["../LICENSE", "licenses/ShowNet/LICENSE"],
    ["../THIRD_PARTY_NOTICES.md", "licenses/ShowNet/THIRD_PARTY_NOTICES.md"],
    ["../third-party/grok-build/LICENSE", "licenses/grok-build/LICENSE"],
    ["../third-party/grok-build/THIRD-PARTY-NOTICES", "licenses/grok-build/THIRD-PARTY-NOTICES"],
    ["../third-party/grok-build/SOURCE.json", "licenses/grok-build/SOURCE.json"],
  ]);
  for (const [source, destination] of requiredResources) {
    if (config.bundle?.resources?.[source] !== destination) {
      throw new Error(`tauri.grok.conf.json must bundle ${source} as ${destination}`);
    }
  }
}

function validateWindowsPortableRelease(packageMetadata, workflow, desktop, launcher, packager) {
  if (packageMetadata.scripts?.["package:windows:portable"] !== "node scripts/package-windows-portable.mjs") {
    throw new Error("package.json must expose the Windows portable packager");
  }
  for (const required of [
    "--no-bundle --config src-tauri/tauri.grok.conf.json",
    "packaging/windows/launcher/Cargo.toml",
    "npm run package:windows:portable",
    "Compress-Archive",
    "ShowNetPortable_${version}_windows_x86_64.zip",
  ]) {
    if (!workflow.includes(required)) throw new Error(`Windows release workflow is missing ${required}`);
  }
  if (/--bundles\s+(?:nsis|msi)/.test(workflow)) {
    throw new Error("Windows release must publish the PortableApps package, not an installed-data bundle");
  }
  if (!desktop.includes('windows_subsystem = "windows"')) {
    throw new Error("Windows release executable must use the GUI subsystem");
  }
  for (const required of ["App", "ShowNet", "Data", "SHOWNET_DATA_DIR"]) {
    if (!launcher.includes(required)) throw new Error(`Portable launcher is missing ${required}`);
  }
  for (const required of [
    "PortableApps.comFormat",
    "Data/ShowNet",
    "grok-build.exe",
    "portable-checksums.sha256",
    "machine !== 0x8664",
    "subsystem: 2",
    "verifyPortableChecksums",
  ]) {
    if (!packager.includes(required)) throw new Error(`Portable packager is missing ${required}`);
  }
}

async function validateAgentSidecar(target, source) {
  if (!/^[a-zA-Z0-9_.-]+$/.test(target)) throw new Error(`Invalid Agent target: ${target}`);
  const suffix = target.includes("windows") ? ".exe" : "";
  const binary = resolve(root, `src-tauri/binaries/grok-build-${target}${suffix}`);
  const binaryInfo = await stat(binary).catch(() => null);
  if (!binaryInfo?.isFile() || binaryInfo.size === 0) throw new Error(`Agent sidecar is missing: ${binary}`);
  if (process.platform !== "win32" && !suffix && (binaryInfo.mode & 0o111) === 0) {
    throw new Error(`Agent sidecar is not executable: ${binary}`);
  }
  const bytes = await readFile(binary);
  const checksum = createHash("sha256").update(bytes).digest("hex");
  const checksumFile = (await readFile(`${binary}.sha256`, "utf8")).trim();
  if (checksumFile !== `${checksum}  ${basename(binary)}`) {
    throw new Error(`Agent sidecar checksum file does not match ${basename(binary)}`);
  }
  const metadata = JSON.parse(await readFile(`${binary}.metadata.json`, "utf8"));
  const expected = {
    name: source.name,
    version: source.version,
    repository: source.repository,
    commit: source.commit,
    rustToolchain: source.rustToolchain,
    target,
    sha256: checksum,
  };
  for (const [key, value] of Object.entries(expected)) {
    if (metadata[key] !== value) throw new Error(`Agent sidecar metadata ${key} does not match ${value}`);
  }
}
