import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

// SHA256SUMS.txt is only useful if the names in it are the names GitHub serves.
// Both workflows built it with `find . | xargs sha256sum` from a directory where
// the DMG sits under dmg/, while the upload flattens everything — so every
// release through v0.4.11 recorded ./dmg/ShowNet_x.y.z.dmg and
// `shasum -a 256 -c SHA256SUMS.txt` answered "FAILED open or read" for the DMG.
// The hashes were correct; only the paths were wrong, which is the version of
// this bug that survives a hash-by-hash check.
const WORKFLOWS = ["release.yml", "publish-from-run.yml"];

describe("the published checksum file", () => {
  it("is written with publish names in every workflow that writes one", async () => {
    for (const workflow of WORKFLOWS) {
      const source = await readFile(
        fileURLToPath(new URL(`../.github/workflows/${workflow}`, import.meta.url)),
        "utf8",
      );

      assert.match(
        source,
        /sha256sum/,
        `${workflow} no longer writes checksums — drop it from WORKFLOWS if that is deliberate`,
      );

      // The directory prefix has to be stripped between hashing and writing.
      assert.match(
        source,
        /sed -E 's#\^\(\[0-9a-f\]\{64\}\s{2}\)\\\.\/\(\.\*\/\)\?#\\1#'/,
        `${workflow} writes sha256sum output unnormalised, so a nested asset ` +
          "would be recorded under a path that does not exist once uploaded",
      );

      // Flattening only stays safe while basenames are unique.
      assert.match(
        source,
        /uniq -d/,
        `${workflow} does not check for assets that share a basename, which the ` +
          "flattened upload would silently collapse into one file",
      );
    }
  });
});
