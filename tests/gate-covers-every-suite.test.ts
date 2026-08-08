/**
 * The Rust half of this question is in gate-covers-every-crate; this is the
 * JavaScript half.
 *
 * `test:unit` globs `tests/*.test.ts` — one level, no recursion. vitest takes
 * `tests/render/**\/*.test.tsx`. Playwright takes `tests/browser`. A file that
 * falls between them runs nowhere and looks exactly like a file that passes:
 * `tests/render/foo.test.ts` would be missed by both of the first two.
 *
 * The patterns are read from the configs rather than restated here, so
 * narrowing a glob fails this instead of silently shrinking coverage.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));

async function testFiles(directory: string, out: string[] = []): Promise<string[]> {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) await testFiles(path, out);
    else if (/\.(test|spec)\.(ts|tsx)$/.test(entry.name)) out.push(path);
  }
  return out;
}

describe("the release gate runs every test suite", () => {
  it("leaves no test file that nothing executes", async () => {
    const [pkg, vitest, playwright] = await Promise.all([
      readFile(join(root, "package.json"), "utf8"),
      readFile(join(root, "vitest.config.ts"), "utf8"),
      readFile(join(root, "playwright.config.ts"), "utf8"),
    ]);

    const unitGlob = /--test "([^"]+)"/.exec(JSON.parse(pkg).scripts["test:unit"])?.[1];
    assert.ok(unitGlob, "test:unit must pass a glob to node --test");
    const renderGlob = /include:\s*\["([^"]+)"\]/.exec(vitest)?.[1];
    assert.ok(renderGlob, "vitest config must declare include");
    const browserDir = /testDir:\s*"([^"]+)"/.exec(playwright)?.[1];
    assert.ok(browserDir, "playwright config must declare testDir");

    // tests/*.test.ts is one level deep; tests/render/**/*.test.tsx recurses.
    const unitDepth = unitGlob.includes("**") ? Infinity : 1;
    const unitPrefix = unitGlob.split("*")[0];
    const renderPrefix = renderGlob.split("*")[0];
    const renderSuffix = renderGlob.slice(renderGlob.lastIndexOf("."));

    const uncovered: string[] = [];
    for (const file of await testFiles(join(root, "tests"))) {
      const rel = relative(root, file).split("\\").join("/");
      const depth = rel.slice(unitPrefix.length).split("/").length;
      const byUnit = rel.startsWith(unitPrefix) && rel.endsWith(".test.ts") && depth <= unitDepth;
      const byRender = rel.startsWith(renderPrefix) && rel.endsWith(renderSuffix);
      const byBrowser = rel.startsWith(`${browserDir}/`);
      if (!byUnit && !byRender && !byBrowser) uncovered.push(rel);
    }

    assert.deepEqual(uncovered, [], `no runner executes these: ${uncovered.join(", ")}`);
  });
});
