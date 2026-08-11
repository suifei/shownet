import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import {
  grokBuildArtifact,
  resolveGrokTargetDirectory,
} from "../scripts/grok-sidecar-layout.mjs";

describe("Agent sidecar build cache", () => {
  it("keeps Cargo output outside the source checkout", () => {
    const root = "/workspace/shownet";
    const targetDirectory = resolveGrokTargetDirectory(root, {});

    assert.equal(targetDirectory, resolve(root, "src-tauri/.sidecar-target"));
    assert.equal(
      grokBuildArtifact(targetDirectory, "x86_64-pc-windows-msvc", ".exe"),
      resolve(targetDirectory, "x86_64-pc-windows-msvc/release/xai-grok-pager.exe"),
    );
    assert.equal(
      resolveGrokTargetDirectory(root, { SHOWNET_GROK_TARGET_DIR: "tmp/grok-target" }),
      resolve(root, "tmp/grok-target"),
    );
  });

  it("prepares pinned source before restoring the mapped target cache", async () => {
    const [workflow, builder, cleanup, ignore] = await Promise.all([
      readFile(new URL("../.github/workflows/release.yml", import.meta.url), "utf8"),
      readFile(new URL("../scripts/build-grok-sidecar.mjs", import.meta.url), "utf8"),
      readFile(new URL("../scripts/clean-local-build-cache.mjs", import.meta.url), "utf8"),
      readFile(new URL("../.gitignore", import.meta.url), "utf8"),
    ]);

    for (const target of ["aarch64-apple-darwin", "x86_64-pc-windows-msvc"]) {
      const prepare = workflow.indexOf(`--prepare-only --target ${target}`);
      const cache = workflow.indexOf("uses: Swatinem/rust-cache@v2", prepare);
      assert.ok(prepare >= 0, `missing prepare step for ${target}`);
      assert.ok(cache > prepare, `Rust cache runs before source preparation for ${target}`);
    }
    assert.equal(
      workflow.match(/grok-build -> \.\.\/\.\.\/\.sidecar-target/g)?.length,
      2,
    );
    assert.match(builder, /CARGO_TARGET_DIR: targetDir/);
    assert.doesNotMatch(builder, /resolve\(sourceDir, `target\//);
    assert.match(cleanup, /\.sidecar-target/);
    assert.match(ignore, /src-tauri\/\.sidecar-target\//);
  });
});
