import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// third-party/grok-build/SOURCE.json is what the sidecar build reads, but the
// workflow installs the toolchain with a hard-coded version on two lines. They
// are the same fact in three places, and nothing kept them together: updating
// the pinned Agent from 0.2.114 to 1.0.0 meant the upstream toolchain moved
// from 1.92.0 to 1.94.0, and the two workflow lines had to be found by hand.
// Missing one of them would install a toolchain the source cannot build with,
// in a job that only runs on a release tag.
describe("the Agent's pinned Rust toolchain", () => {
  it("is the same version in SOURCE.json and every workflow that installs it", async () => {
    const read = (path: string) =>
      readFile(fileURLToPath(new URL(`../${path}`, import.meta.url)), "utf8");

    const source = JSON.parse(await read("third-party/grok-build/SOURCE.json"));
    const declared = source.rustToolchain;
    assert.match(
      declared,
      /^\d+\.\d+\.\d+$/,
      `SOURCE.json rustToolchain is not a version: ${declared}`,
    );

    const workflow = await read(".github/workflows/release.yml");
    const installs = [...workflow.matchAll(/rustup toolchain install (\S+)/g)].map(
      (match) => match[1],
    );
    assert.ok(
      installs.length > 0,
      "no toolchain install found — did the step change shape?",
    );
    for (const version of installs) {
      assert.equal(
        version,
        declared,
        `the workflow installs ${version} while SOURCE.json pins ${declared}`,
      );
    }
  });

  it("matches the version the pinned source itself requires", async () => {
    // Recorded rather than fetched: the test must not need the network, and an
    // upstream that moves on is not this repo's problem until someone bumps the
    // commit. What matters is that whoever bumps it reads rust-toolchain.toml
    // at that commit and puts the answer here.
    const source = JSON.parse(
      await readFile(
        fileURLToPath(new URL("../third-party/grok-build/SOURCE.json", import.meta.url)),
        "utf8",
      ),
    );
    assert.equal(
      source.rustToolchain,
      "1.94.0",
      "grok-build afbc0fb7 declares channel = 1.94.0 in rust-toolchain.toml; " +
        "update this expectation in the same commit that moves the pin",
    );
    assert.equal(source.version, "1.0.0");
    assert.equal(source.commit, "afbc0fb710320c7add294c2106d447ecc3e3af2e");
  });
});
