/**
 * The SDK's fixed scaffolding lives in `src-tauri/templates/python/` as real
 * Python files, not as Rust string literals.
 *
 * It used to be literals with `\x20` standing in for indentation. That is
 * unreadable, and worse it fails silently: the `_origin` helper came out
 * flush-left — a syntax error — and every assertion about the export still
 * passed, because nothing compiled what was produced. A template is a file
 * Python tooling can open, and this checks it stays that way.
 *
 * Placeholders are written so the template still parses: they sit in expression
 * position, where `__SHOWNET_CONTRACT__` is just a name.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const run = promisify(execFile);
const root = fileURLToPath(new URL("..", import.meta.url));
const templates = join(root, "src-tauri/templates/python");

/** Fragments that are class-body only, so they cannot stand alone. */
const CLASS_BODY_ONLY = new Set(["client_helpers.py"]);

describe("the SDK's Python templates are Python", () => {
  it("every whole-file template compiles as written", async () => {
    const files = (await readdir(templates)).filter((name) => name.endsWith(".py"));
    assert.ok(files.length >= 3, `expected the template set, saw ${files.length}`);

    for (const file of files) {
      if (CLASS_BODY_ONLY.has(file)) continue;
      await run("python3", ["-m", "py_compile", join(templates, file)]);
    }
  });

  it("a class-body fragment compiles once given a class to sit in", async () => {
    for (const file of CLASS_BODY_ONLY) {
      const body = await readFile(join(templates, file), "utf8");
      const wrapped = `class _Probe:\n    def __init__(self) -> None:\n        pass\n\n${body}`;
      const path = join(templates, `.probe_${file}`);
      const { writeFile, rm } = await import("node:fs/promises");
      await writeFile(path, wrapped, "utf8");
      try {
        await run("python3", ["-m", "py_compile", path]);
      } finally {
        await rm(path, { force: true });
      }
    }
  });

  it("the Rust generator includes them rather than restating them", async () => {
    const source = await readFile(join(root, "src-tauri/src/sdk_build.rs"), "utf8");
    for (const name of ["fingerprint.py", "crypto.py", "client_prelude.py", "client_helpers.py"]) {
      assert.ok(
        source.includes(`templates/python/${name}`),
        `${name} exists but nothing includes it, so it is not the thing being shipped`,
      );
    }
    // The escape that made indentation invisible. Its absence is the point.
    assert.doesNotMatch(
      source,
      /\\x20 {3}"""/,
      "Python is being emitted from Rust literals again; put it in a template",
    );
  });
});
