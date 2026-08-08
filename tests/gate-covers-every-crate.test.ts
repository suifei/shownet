/**
 * The gate can only catch what it runs, and nothing checked what it runs.
 *
 * The portable launcher is its own crate. The Quality job ran `cargo test`
 * twice and both pointed at src-tauri, so the launcher's test — the one
 * covering the layout that keeps user data inside the portable root — had
 * never executed anywhere. It was added by hand once that was noticed; this
 * makes the next crate impossible to forget.
 *
 * Deliberately not a list of expected commands. That would pass by matching
 * strings someone remembered to update. It asks the question that matters
 * instead: for every crate in the repo that has tests, does some gate step run
 * them?
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { describe, it } from "node:test";

const root = new URL("..", import.meta.url).pathname;

async function walk(directory: string, out: string[] = []): Promise<string[]> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === "target" || entry.name === "node_modules" || entry.name === ".git") continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await walk(path, out);
    else if (entry.name === "Cargo.toml") out.push(path);
  }
  return out;
}

async function hasRustTests(manifest: string): Promise<boolean> {
  const sources = await walk(join(manifest, "..", "src")).catch(() => []);
  void sources;
  const files: string[] = [];
  const collect = async (directory: string) => {
    for (const entry of await readdir(directory, { withFileTypes: true }).catch(() => [])) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await collect(path);
      else if (entry.name.endsWith(".rs")) files.push(path);
    }
  };
  await collect(join(manifest, "..", "src"));
  for (const file of files) {
    const source = await readFile(file, "utf8");
    if (/#\[(tokio::)?test\]/.test(source)) return true;
  }
  return false;
}

describe("the release gate runs every crate's tests", () => {
  it("leaves no crate with tests unexecuted", async () => {
    const workflow = await readFile(join(root, ".github/workflows/release.yml"), "utf8");
    const manifests = await walk(root);
    assert.ok(manifests.length >= 2, `expected to find the crates, saw ${manifests.length}`);

    const uncovered: string[] = [];
    for (const manifest of manifests) {
      if (!(await hasRustTests(manifest))) continue;
      const relativePath = relative(root, manifest).split("\\").join("/");
      // A gate step must run cargo test against this exact manifest.
      const pattern = new RegExp(
        `cargo test[^\\n]*--manifest-path ${relativePath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`,
      );
      if (!pattern.test(workflow)) uncovered.push(relativePath);
    }

    assert.deepEqual(
      uncovered,
      [],
      `these crates have tests that no gate step runs: ${uncovered.join(", ")}`,
    );
  });
});
