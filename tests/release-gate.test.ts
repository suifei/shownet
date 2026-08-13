import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  assertDeveloperIdSignature,
  assertNotarizedGatekeeperAssessment,
  parseArguments,
  parseCodesignMetadata,
  validateMacBundleSigningConfig,
} from "../scripts/verify-macos-release.mjs";

const validCodesignOutput = `
Identifier=com.shownet.desktop
CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=4+7 location=embedded
Authority=Developer ID Application: ShowNet Limited (A1B2C3D4E5)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=A1B2C3D4E5
`;

describe("signed macOS release gate", () => {
  it("rejects a release config that forces ad-hoc signing or disables hardened runtime", () => {
    assert.throws(
      () => validateMacBundleSigningConfig({ bundle: { macOS: { signingIdentity: "-" } } }),
      /ad-hoc/,
    );
    assert.throws(
      () => validateMacBundleSigningConfig({ bundle: { macOS: { hardenedRuntime: false } } }),
      /hardenedRuntime/,
    );
    assert.doesNotThrow(() => validateMacBundleSigningConfig({ bundle: { macOS: { hardenedRuntime: true } } }));
  });

  it("requires Developer ID, one team and hardened runtime for nested executables", () => {
    const metadata = parseCodesignMetadata(validCodesignOutput);
    assert.equal(metadata.identifier, "com.shownet.desktop");
    assert.deepEqual(metadata.authorities, [
      "Developer ID Application: ShowNet Limited (A1B2C3D4E5)",
      "Developer ID Certification Authority",
      "Apple Root CA",
    ]);
    assert.deepEqual(assertDeveloperIdSignature("app", validCodesignOutput, "A1B2C3D4E5"), metadata);
    assert.throws(() => assertDeveloperIdSignature("app", validCodesignOutput, "Z9Y8X7W6V5"), /does not match/);
    assert.throws(
      () => assertDeveloperIdSignature("app", validCodesignOutput.replace("Developer ID Application", "Apple Development"), "A1B2C3D4E5"),
      /not signed with Developer ID/,
    );
    assert.throws(
      () => assertDeveloperIdSignature("app", validCodesignOutput.replace("(runtime)", "(adhoc)"), "A1B2C3D4E5"),
      /ad-hoc/,
    );
  });

  it("accepts only a notarized Gatekeeper assessment", () => {
    assert.doesNotThrow(() => assertNotarizedGatekeeperAssessment(
      "app",
      "/tmp/ShowNet.app: accepted\nsource=Notarized Developer ID",
    ));
    assert.throws(
      () => assertNotarizedGatekeeperAssessment("app", "/tmp/ShowNet.app: rejected\nsource=no usable signature"),
      /not accepted/,
    );
    assert.throws(
      () => assertNotarizedGatekeeperAssessment("app", "/tmp/ShowNet.app: accepted\nsource=Developer ID"),
      /not Notarized Developer ID/,
    );
  });

  it("requires explicit artifact, team and architecture arguments", () => {
    assert.deepEqual(parseArguments([
      "--app", "/tmp/ShowNet.app",
      "--dmg", "/tmp/ShowNet.dmg",
      "--team-id", "A1B2C3D4E5",
      "--architecture", "arm64",
      "--report", "/tmp/report.json",
    ]), {
      app: "/tmp/ShowNet.app",
      dmg: "/tmp/ShowNet.dmg",
      teamId: "A1B2C3D4E5",
      architecture: "arm64",
      report: "/tmp/report.json",
    });
    assert.throws(() => parseArguments(["--app", "/tmp/ShowNet.app"]), /--dmg is required/);
    assert.throws(() => parseArguments([
      "--app", "a", "--dmg", "b", "--team-id", "short", "--architecture", "arm64",
    ]), /10-character Apple Team ID/);
  });

  it("keeps CI wired to the reusable Gatekeeper verifier without a fixed identity", async () => {
    const [workflow, config, localConfig, packageJson, verifier] = await Promise.all([
      readFile(new URL("../.github/workflows/release.yml", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/tauri.grok.conf.json", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/tauri.local.macos.conf.json", import.meta.url), "utf8"),
      readFile(new URL("../package.json", import.meta.url), "utf8"),
      readFile(new URL("../scripts/verify-macos-release.mjs", import.meta.url), "utf8"),
    ]);
    assert.doesNotMatch(workflow, /APPLE_SIGNING_IDENTITY/);
    assert.doesNotMatch(config, /"signingIdentity"\s*:\s*"-"/);
    assert.match(localConfig, /"signingIdentity"\s*:\s*"-"/);
    assert.match(packageJson, /tauri\.grok\.conf\.json --config src-tauri\/tauri\.local\.macos\.conf\.json/);
    // Signed path still uses the Gatekeeper verifier; ad-hoc fallback may use local.macos.conf.
    assert.match(workflow, /npm run verify:release:macos/);
    assert.match(workflow, /release-verification-macos\.json/);
    assert.match(workflow, /tauri\.local\.macos\.conf\.json/);
    assert.match(workflow, /shownet-macos-aarch64/);
    assert.match(workflow, /shownet-windows-x86_64/);
    assert.match(workflow, /softprops\/action-gh-release/);
    assert.match(workflow, /Resolve latest official stable Grok version/);
    assert.match(workflow, /npm run download:agent-sidecar/);
    assert.match(workflow, /npm run test:agent-sidecar/);
    assert.doesNotMatch(workflow, /arduino\/setup-protoc@v3/);
    assert.doesNotMatch(workflow, /build:agent-sidecar/);
    assert.match(verifier, /codesign[\s\S]*--deep[\s\S]*--strict/);
    assert.match(verifier, /stapler[\s\S]*validate/);
    assert.match(verifier, /runTool\("spctl"/);
    assert.match(verifier, /source=Notarized Developer ID/);
    assert.match(verifier, /Contents\/MacOS\/grok-build/);
  });
});
