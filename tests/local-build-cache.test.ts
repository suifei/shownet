import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { cleanLocalBuildCache } from "../scripts/clean-local-build-cache.mjs";

describe("verified local build cleanup", () => {
  it("previews known build paths and deletes them only after explicit confirmation", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-clean-cache-"));
    try {
      const releaseDirectory = await createVerifiedRelease(fixture);
      const target = join(fixture, "src-tauri", "target");
      const output = join(fixture, "output");
      const xwin = join(fixture, "cargo-xwin");
      await Promise.all([
        mkdir(target, { recursive: true }),
        mkdir(output, { recursive: true }),
        mkdir(xwin, { recursive: true }),
      ]);
      await Promise.all([
        writeFile(join(target, "artifact.bin"), "target bytes"),
        writeFile(join(output, "trace.log"), "trace bytes"),
        writeFile(join(xwin, "sdk.lib"), "sdk bytes"),
      ]);
      const options = {
        projectRoot: fixture,
        packageMetadata: { version: "1.2.3" },
        releaseDirectory,
        projectPaths: [target, output],
        generatedSidecars: [],
        includeXwinCache: true,
        xwinCache: xwin,
      };

      const preview = await cleanLocalBuildCache(options);
      assert.equal(preview.cleaned, false);
      assert.equal(preview.paths.length, 3);
      assert.ok(preview.bytes > 0);
      assert.ok((await stat(target)).isDirectory());

      const cleaned = await cleanLocalBuildCache({ ...options, confirm: true });
      assert.equal(cleaned.cleaned, true);
      await assert.rejects(stat(target));
      await assert.rejects(stat(output));
      await assert.rejects(stat(xwin));
      assert.ok((await stat(releaseDirectory)).isDirectory());
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });

  it("preserves build outputs when the release archive was modified", async () => {
    const fixture = await mkdtemp(join(tmpdir(), "shownet-clean-tamper-"));
    try {
      const releaseDirectory = await createVerifiedRelease(fixture);
      const target = join(fixture, "target");
      await mkdir(target);
      await writeFile(join(target, "artifact.bin"), "keep me");
      await writeFile(join(releaseDirectory, "ShowNet_1.2.3_macOS_arm64.dmg"), "tampered");

      await assert.rejects(
        cleanLocalBuildCache({
          projectRoot: fixture,
          packageMetadata: { version: "1.2.3" },
          releaseDirectory,
          projectPaths: [target],
          generatedSidecars: [],
          confirm: true,
        }),
        /Archived artifact does not match release manifest/,
      );
      assert.equal(await readFile(join(target, "artifact.bin"), "utf8"), "keep me");
    } finally {
      await rm(fixture, { recursive: true, force: true });
    }
  });
});

async function createVerifiedRelease(root: string) {
  const releaseDirectory = join(root, "release", "ShowNet-1.2.3-local-qa");
  await mkdir(releaseDirectory, { recursive: true });
  const dmgName = "ShowNet_1.2.3_macOS_arm64.dmg";
  const zipName = "ShowNetPortable_1.2.3_windows_x86_64.zip";
  await Promise.all([
    writeFile(join(releaseDirectory, dmgName), "dmg bytes"),
    writeFile(join(releaseDirectory, zipName), "zip bytes"),
  ]);
  const manifest = {
    schemaVersion: 1,
    product: "ShowNet",
    version: "1.2.3",
    channel: "local-unsigned-qa",
    artifacts: {
      "macOS-arm64": await artifact(releaseDirectory, dmgName),
      "windows-x86_64": await artifact(releaseDirectory, zipName),
    },
  };
  const manifestName = "release-manifest.json";
  const manifestPath = join(releaseDirectory, manifestName);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(join(releaseDirectory, "SHA256SUMS.txt"), [
    `${manifest.artifacts["macOS-arm64"].sha256}  ${dmgName}`,
    `${manifest.artifacts["windows-x86_64"].sha256}  ${zipName}`,
    `${await digest(manifestPath)}  ${manifestName}`,
    "",
  ].join("\n"));
  return releaseDirectory;
}

async function artifact(root: string, file: string) {
  const path = join(root, file);
  return {
    file,
    bytes: (await stat(path)).size,
    sha256: await digest(path),
  };
}

async function digest(path: string) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}
