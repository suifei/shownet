import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  officialArtifactUrls,
  officialPlatformForTarget,
  parseGrokVersionOutput,
  validateGrokVersion,
} from "../scripts/download-grok-sidecar.mjs";

describe("official Grok sidecar download", () => {
  it("maps ShowNet release targets to the names documented by x.ai/cli", () => {
    assert.deepEqual(officialPlatformForTarget("aarch64-apple-darwin"), {
      platform: "macos-aarch64",
      suffix: "",
    });
    assert.deepEqual(officialPlatformForTarget("x86_64-pc-windows-msvc"), {
      platform: "windows-x86_64",
      suffix: ".exe",
    });
  });

  it("uses only the official primary and fallback distribution endpoints", () => {
    assert.deepEqual(officialArtifactUrls("1.0.3", "aarch64-apple-darwin"), [
      "https://x.ai/cli/grok-1.0.3-macos-aarch64",
      "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-1.0.3-macos-aarch64",
    ]);
    assert.deepEqual(officialArtifactUrls("1.0.3", "x86_64-pc-windows-msvc"), [
      "https://x.ai/cli/grok-1.0.3-windows-x86_64.exe",
      "https://storage.googleapis.com/grok-build-public-artifacts/cli/grok-1.0.3-windows-x86_64.exe",
    ]);
  });

  it("rejects unsafe version pointers and mismatched binaries", () => {
    assert.equal(validateGrokVersion("1.0.3\n"), "1.0.3");
    assert.throws(() => validateGrokVersion("../../latest"), /Invalid Grok stable version/);
    assert.equal(parseGrokVersionOutput("grok 1.0.3 (abcdef0)", "1.0.3"), "grok 1.0.3 (abcdef0)");
    assert.throws(() => parseGrokVersionOutput("grok 1.0.2", "1.0.3"), /expected 1.0.3/);
  });

  it("does not silently support a platform x.ai does not publish for ShowNet", () => {
    assert.throws(() => officialPlatformForTarget("x86_64-unknown-linux-gnu"), /No official Grok binary/);
  });

  it("runs its command-line entry point instead of silently exiting", () => {
    const script = fileURLToPath(new URL("../scripts/download-grok-sidecar.mjs", import.meta.url));
    const result = spawnSync(process.execPath, [script, "--unknown"], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unknown argument: --unknown/);
  });
});
