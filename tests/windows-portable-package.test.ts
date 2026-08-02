import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  buildPortablePackage,
  verifyPortablePackage,
} from "../scripts/package-windows-portable.mjs";

const frontendAssetReferences = ["assets/index-test.js", "assets/index-test.css"];

describe("Windows PortableApps package", () => {
  it("uses the Tauri release driver so frontend assets are embedded", async () => {
    const packageMetadata = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    );
    const command = packageMetadata.scripts["build:windows:cross"];
    assert.match(command, /tauri build --runner cargo-xwin/);
    assert.match(command, /--target x86_64-pc-windows-msvc/);
    assert.match(command, /--no-bundle/);
    assert.doesNotMatch(command, /rust-stable\.mjs xwin build/);
  });

  it("keeps executables immutable and all user data under Data/ShowNet", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-portable-package-"));
    try {
      const application = join(fixture, "shownet.exe");
      const launcher = join(fixture, "launcher.exe");
      const sidecar = join(fixture, "grok-build.exe");
      const icon = join(fixture, "icon.ico");
      const projectLicense = join(fixture, "PROJECT-LICENSE");
      const notices = join(fixture, "THIRD_PARTY_NOTICES.md");
      const agentLicense = join(fixture, "LICENSE");
      const agentNotices = join(fixture, "AGENT-NOTICES");
      const agentSource = join(fixture, "SOURCE.json");
      const outputDirectory = join(fixture, "ShowNetPortable");
      await Promise.all([
        writeFile(application, productionAmd64PeFixture(1)),
        writeFile(launcher, amd64PeFixture(2)),
        writeFile(sidecar, amd64PeFixture(3)),
        writeFile(icon, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])),
        writeFile(projectLicense, "project license\n"),
        writeFile(notices, "project notices\n"),
        writeFile(agentLicense, "agent license\n"),
        writeFile(agentNotices, "agent notices\n"),
        writeFile(agentSource, '{"name":"xai-org/grok-build"}\n'),
      ]);

      await buildPortablePackage({
        version: "1.2.3",
        target: "x86_64-pc-windows-msvc",
        outputDirectory,
        application,
        launcher,
        sidecar,
        icon,
        projectLicense,
        notices,
        agentLicense,
        agentNotices,
        agentSource,
        packageJson: { version: "1.2.3" },
        frontendAssetReferences,
      });
      await assert.doesNotReject(() => verifyPortablePackage(outputDirectory, {
        version: "1.2.3",
        frontendAssetReferences,
      }));

      const manifest = JSON.parse(await readFile(join(outputDirectory, "portable-manifest.json"), "utf8"));
      assert.equal(manifest.application, "App/ShowNet/ShowNet.exe");
      assert.equal(manifest.dataDirectory, "Data/ShowNet");
      assert.equal(manifest.dataPolicy, "portable");
      assert.deepEqual(manifest.frontendAssets, frontendAssetReferences);
      const appInfo = await readFile(join(outputDirectory, "App/AppInfo/appinfo.ini"), "utf8");
      assert.match(appInfo, /PackageVersion=1\.2\.3\.0/);
      assert.match(appInfo, /Type=PortableApps\.comFormat/);
      assert.match(appInfo, /OpenSource=true/);
      assert.equal(await readFile(join(outputDirectory, "App/ShowNet/LICENSE"), "utf8"), "project license\n");
      const dataMarker = await readFile(join(outputDirectory, "Data/ShowNet/.portable"), "utf8");
      assert.match(dataMarker, /database, certificates, browser profile, and settings/);

      await writeFile(join(outputDirectory, "App/ShowNet/ShowNet.exe"), productionAmd64PeFixture(9));
      await assert.rejects(
        verifyPortablePackage(outputDirectory, { version: "1.2.3", frontendAssetReferences }),
        /Portable checksum mismatch: App\/ShowNet\/ShowNet\.exe/,
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });

  it("rejects non-Windows binaries before producing an artifact", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-portable-invalid-"));
    try {
      const invalid = join(fixture, "invalid.exe");
      await writeFile(invalid, "not a PE file");
      await assert.rejects(
        buildPortablePackage({
          version: "1.0.0",
          target: "x86_64-pc-windows-msvc",
          outputDirectory: join(fixture, "output"),
          application: invalid,
          launcher: invalid,
          sidecar: invalid,
          icon: invalid,
          notices: invalid,
          agentLicense: invalid,
          agentNotices: invalid,
          agentSource: invalid,
          packageJson: { version: "1.0.0" },
          frontendAssetReferences,
        }),
        /not (?:a Windows AMD64 PE executable|an ICO file)/,
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });

  it("rejects a console-subsystem desktop executable", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-portable-console-"));
    try {
      const consoleApplication = join(fixture, "shownet.exe");
      const guiLauncher = join(fixture, "launcher.exe");
      const sidecar = join(fixture, "grok-build.exe");
      const icon = join(fixture, "icon.ico");
      const metadata = join(fixture, "metadata.txt");
      await Promise.all([
        writeFile(consoleApplication, amd64PeFixture(1, 3)),
        writeFile(guiLauncher, amd64PeFixture(2)),
        writeFile(sidecar, amd64PeFixture(3, 3)),
        writeFile(icon, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])),
        writeFile(metadata, "metadata\n"),
      ]);
      await assert.rejects(
        buildPortablePackage({
          version: "1.0.0",
          target: "x86_64-pc-windows-msvc",
          outputDirectory: join(fixture, "output"),
          application: consoleApplication,
          launcher: guiLauncher,
          sidecar,
          icon,
          notices: metadata,
          agentLicense: metadata,
          agentNotices: metadata,
          agentSource: metadata,
          packageJson: { version: "1.0.0" },
          frontendAssetReferences,
        }),
        /ShowNet application is not a Windows GUI executable/,
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });

  it("rejects a release executable that does not embed the production frontend", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-portable-dev-url-"));
    try {
      const application = join(fixture, "shownet.exe");
      const launcher = join(fixture, "launcher.exe");
      const sidecar = join(fixture, "grok-build.exe");
      const icon = join(fixture, "icon.ico");
      const metadata = join(fixture, "metadata.txt");
      await Promise.all([
        writeFile(application, amd64PeFixture(1)),
        writeFile(launcher, amd64PeFixture(2)),
        writeFile(sidecar, amd64PeFixture(3, 3)),
        writeFile(icon, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])),
        writeFile(metadata, "metadata\n"),
      ]);
      await assert.rejects(
        buildPortablePackage({
          version: "1.0.0",
          target: "x86_64-pc-windows-msvc",
          outputDirectory: join(fixture, "output"),
          application,
          launcher,
          sidecar,
          icon,
          projectLicense: metadata,
          notices: metadata,
          agentLicense: metadata,
          agentNotices: metadata,
          agentSource: metadata,
          packageJson: { version: "1.0.0" },
          frontendAssetReferences,
        }),
        /does not embed production frontend assets: assets\/index-test\.js, assets\/index-test\.css/,
      );
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });

  it("embeds the shared Windows icon in the portable launcher", async () => {
    const manifest = await readFile(new URL("../packaging/windows/launcher/Cargo.toml", import.meta.url), "utf8");
    const buildScript = await readFile(new URL("../packaging/windows/launcher/build.rs", import.meta.url), "utf8");

    assert.match(manifest, /build = "build\.rs"/);
    assert.match(manifest, /embed-resource = "3\.0\.11"/);
    assert.match(buildScript, /src-tauri\/icons\/icon\.ico/);
    assert.match(buildScript, /embed_resource::compile/);
  });
});

function amd64PeFixture(marker: number, subsystem = 2) {
  const bytes = Buffer.alloc(192);
  bytes.write("MZ", 0, "ascii");
  bytes.writeUInt32LE(0x40, 0x3c);
  bytes.write("PE\0\0", 0x40, "binary");
  bytes.writeUInt16LE(0x8664, 0x44);
  bytes.writeUInt16LE(0xf0, 0x54);
  bytes.writeUInt16LE(0x20b, 0x58);
  bytes.writeUInt16LE(subsystem, 0x9c);
  bytes[0xb0] = marker;
  return bytes;
}

function productionAmd64PeFixture(marker: number, subsystem = 2) {
  return Buffer.concat([
    amd64PeFixture(marker, subsystem),
    Buffer.from(frontendAssetReferences.join("\0"), "utf8"),
  ]);
}
