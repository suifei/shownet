import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = resolve(dirname(scriptPath), "..");

export function validateMacBundleSigningConfig(config) {
  const macOS = config.bundle?.macOS ?? {};
  if (macOS.signingIdentity === "-") {
    throw new Error("macOS release config must not force the ad-hoc '-' signing identity");
  }
  if (macOS.hardenedRuntime === false) {
    throw new Error("macOS release config must keep hardenedRuntime enabled");
  }
}

export function parseCodesignMetadata(output) {
  const metadata = { authorities: [] };
  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith("CodeDirectory ")) {
      metadata.codeDirectory = line.slice("CodeDirectory ".length).trim();
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (key === "Authority") metadata.authorities.push(value);
    else if (key === "TeamIdentifier") metadata.teamIdentifier = value;
    else if (key === "Identifier") metadata.identifier = value;
    else if (key === "Signature") metadata.signature = value;
    else if (key === "Format") metadata.format = value;
  }
  return metadata;
}

export function assertDeveloperIdSignature(label, output, expectedTeamId, { requireRuntime = true } = {}) {
  const metadata = parseCodesignMetadata(output);
  const primaryAuthority = metadata.authorities[0] ?? "";
  if (!primaryAuthority.startsWith("Developer ID Application:")) {
    throw new Error(`${label} is not signed with Developer ID Application`);
  }
  if (metadata.teamIdentifier !== expectedTeamId) {
    throw new Error(`${label} TeamIdentifier ${metadata.teamIdentifier ?? "<missing>"} does not match ${expectedTeamId}`);
  }
  if (metadata.signature === "adhoc" || /\badhoc\b/.test(metadata.codeDirectory ?? "")) {
    throw new Error(`${label} still has an ad-hoc signature`);
  }
  if (requireRuntime && !/\([^)]*\bruntime\b[^)]*\)/.test(metadata.codeDirectory ?? "")) {
    throw new Error(`${label} is missing the hardened runtime signature flag`);
  }
  return metadata;
}

export function assertNotarizedGatekeeperAssessment(label, output) {
  if (!/(^|\n).*:\s*accepted(?:\n|$)/m.test(output)) {
    throw new Error(`${label} was not accepted by Gatekeeper`);
  }
  if (!/(^|\n)source=Notarized Developer ID(?:\n|$)/m.test(output)) {
    throw new Error(`${label} Gatekeeper source is not Notarized Developer ID`);
  }
}

export function parseArguments(args) {
  const parsed = {};
  const valueOptions = new Map([
    ["--app", "app"],
    ["--dmg", "dmg"],
    ["--team-id", "teamId"],
    ["--architecture", "architecture"],
    ["--report", "report"],
  ]);
  for (let index = 0; index < args.length; index += 1) {
    const key = valueOptions.get(args[index]);
    if (!key) throw new Error(`Unknown argument: ${args[index]}`);
    const value = args[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`${args[index]} requires a value`);
    parsed[key] = value;
    index += 1;
  }
  for (const key of ["app", "dmg", "teamId", "architecture"]) {
    if (!parsed[key]) throw new Error(`--${key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} is required`);
  }
  if (!/^[A-Z0-9]{10}$/.test(parsed.teamId)) throw new Error("--team-id must be a 10-character Apple Team ID");
  if (!["arm64", "x86_64"].includes(parsed.architecture)) throw new Error("--architecture must be arm64 or x86_64");
  return parsed;
}

async function assertFile(path, label) {
  const info = await stat(path).catch(() => null);
  if (!info?.isFile() || info.size === 0) throw new Error(`${label} is missing or empty: ${path}`);
}

async function assertDirectory(path, label) {
  const info = await stat(path).catch(() => null);
  if (!info?.isDirectory()) throw new Error(`${label} is missing: ${path}`);
}

function runTool(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  const output = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  if (result.error) throw new Error(`${command} could not start: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed (${result.status ?? result.signal ?? "unknown"})${output ? `:\n${output}` : ""}`);
  }
  return output;
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

async function assertSameFile(expectedPath, actualPath, label) {
  const [expected, actual] = await Promise.all([readFile(expectedPath), readFile(actualPath)]);
  if (!expected.equals(actual)) throw new Error(`${label} does not match the pinned release source`);
}

function assertArchitecture(label, output, expectedArchitecture) {
  const architectures = output.trim().split(/\s+/).filter(Boolean);
  if (!architectures.includes(expectedArchitecture)) {
    throw new Error(`${label} does not contain ${expectedArchitecture}: ${architectures.join(", ") || "<none>"}`);
  }
  return architectures;
}

export async function verifyMacosRelease(options) {
  if (process.platform !== "darwin") throw new Error("macOS release verification must run on macOS");
  const appPath = resolve(options.app);
  const dmgPath = resolve(options.dmg);
  await assertDirectory(appPath, "application bundle");
  await assertFile(dmgPath, "DMG");

  const infoPlist = resolve(appPath, "Contents/Info.plist");
  await assertFile(infoPlist, "Info.plist");
  const plist = (key) => runTool("/usr/libexec/PlistBuddy", ["-c", `Print :${key}`, infoPlist]).trim();
  const identifier = plist("CFBundleIdentifier");
  const version = plist("CFBundleShortVersionString");
  const executableName = plist("CFBundleExecutable");
  if (identifier !== "com.shownet.desktop") throw new Error(`unexpected bundle identifier: ${identifier}`);

  const packageJson = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
  if (version !== packageJson.version) throw new Error(`bundle version ${version} does not match ${packageJson.version}`);

  const mainExecutable = resolve(appPath, "Contents/MacOS", executableName);
  const sidecar = resolve(appPath, "Contents/MacOS/grok-build");
  await assertFile(mainExecutable, "main executable");
  await assertFile(sidecar, "Agent sidecar");

  const resources = resolve(appPath, "Contents/Resources/licenses/grok-build");
  for (const file of ["LICENSE", "THIRD-PARTY-NOTICES", "SOURCE.json"]) {
    await assertSameFile(resolve(root, "third-party/grok-build", file), resolve(resources, file), `bundled ${file}`);
  }
  const projectResources = resolve(appPath, "Contents/Resources/licenses/ShowNet");
  await assertSameFile(resolve(root, "LICENSE"), resolve(projectResources, "LICENSE"), "bundled ShowNet LICENSE");
  await assertSameFile(
    resolve(root, "THIRD_PARTY_NOTICES.md"),
    resolve(projectResources, "THIRD_PARTY_NOTICES.md"),
    "bundled ShowNet THIRD_PARTY_NOTICES.md",
  );
  const agentSource = JSON.parse(await readFile(resolve(root, "third-party/grok-build/SOURCE.json"), "utf8"));
  const expectedAgentVersion = `grok ${agentSource.version} (${agentSource.commit.slice(0, 7)})`;
  const actualAgentVersion = runTool(sidecar, ["--version"]).trim();
  if (actualAgentVersion !== expectedAgentVersion) {
    throw new Error(`Agent version ${actualAgentVersion} does not match ${expectedAgentVersion}`);
  }

  runTool("codesign", ["--verify", "--deep", "--strict", "--verbose=4", appPath]);
  runTool("codesign", ["--verify", "--strict", "--verbose=4", mainExecutable]);
  runTool("codesign", ["--verify", "--strict", "--verbose=4", sidecar]);
  runTool("codesign", ["--verify", "--strict", "--verbose=4", dmgPath]);

  const appSignatureOutput = runTool("codesign", ["-d", "--verbose=4", appPath]);
  const mainSignatureOutput = runTool("codesign", ["-d", "--verbose=4", mainExecutable]);
  const sidecarSignatureOutput = runTool("codesign", ["-d", "--verbose=4", sidecar]);
  const dmgSignatureOutput = runTool("codesign", ["-d", "--verbose=4", dmgPath]);
  const appSignature = assertDeveloperIdSignature("application bundle", appSignatureOutput, options.teamId);
  const mainSignature = assertDeveloperIdSignature("main executable", mainSignatureOutput, options.teamId);
  const sidecarSignature = assertDeveloperIdSignature("Agent sidecar", sidecarSignatureOutput, options.teamId);
  const dmgSignature = assertDeveloperIdSignature("DMG", dmgSignatureOutput, options.teamId, { requireRuntime: false });
  if (appSignature.identifier !== identifier) {
    throw new Error(`signed bundle identifier ${appSignature.identifier ?? "<missing>"} does not match ${identifier}`);
  }

  const mainArchitectures = assertArchitecture(
    "main executable",
    runTool("lipo", ["-archs", mainExecutable]),
    options.architecture,
  );
  const sidecarArchitectures = assertArchitecture(
    "Agent sidecar",
    runTool("lipo", ["-archs", sidecar]),
    options.architecture,
  );

  runTool("hdiutil", ["verify", dmgPath]);
  runTool("xcrun", ["stapler", "validate", appPath]);
  runTool("xcrun", ["stapler", "validate", dmgPath]);
  const appGatekeeper = runTool("spctl", ["--assess", "--type", "execute", "--verbose=4", appPath]);
  const dmgGatekeeper = runTool("spctl", [
    "--assess",
    "--type",
    "open",
    "--context",
    "context:primary-signature",
    "--verbose=4",
    dmgPath,
  ]);
  assertNotarizedGatekeeperAssessment("application bundle", appGatekeeper);
  assertNotarizedGatekeeperAssessment("DMG", dmgGatekeeper);

  const report = {
    schemaVersion: 1,
    verifiedAt: new Date().toISOString(),
    teamId: options.teamId,
    version,
    application: {
      name: basename(appPath),
      identifier,
      executable: executableName,
      executableSha256: await sha256(mainExecutable),
      architectures: mainArchitectures,
      authority: appSignature.authorities[0],
      gatekeeper: appGatekeeper,
    },
    agent: {
      version: actualAgentVersion,
      executableSha256: await sha256(sidecar),
      architectures: sidecarArchitectures,
      authority: sidecarSignature.authorities[0],
    },
    diskImage: {
      name: basename(dmgPath),
      sha256: await sha256(dmgPath),
      authority: dmgSignature.authorities[0],
      gatekeeper: dmgGatekeeper,
    },
    checks: {
      strictDeepCodeSignature: true,
      hardenedRuntime: true,
      applicationTicketStapled: true,
      diskImageTicketStapled: true,
      gatekeeperAccepted: true,
      pinnedAgentNotices: true,
    },
  };
  if (options.report) {
    const reportPath = resolve(options.report);
    await mkdir(dirname(reportPath), { recursive: true });
    await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }
  return report;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const report = await verifyMacosRelease(options);
  console.log(
    `Verified notarized ShowNet ${report.version} for ${report.application.architectures.join(",")} `
      + `(team ${report.teamId}, DMG SHA-256 ${report.diskImage.sha256}).`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
