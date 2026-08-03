/**
 * Structural release gate: Advanced Console IPC targets must be registered
 * Tauri commands (generate_handler), not only agent tools.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("advanced console UI wiring", () => {
  it("registers every AdvancedConsoleView invoke command in lib.rs generate_handler", async () => {
    const [consoleSrc, libSrc] = await Promise.all([
      readFile(new URL("../src/components/AdvancedConsoleView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src-tauri/src/lib.rs", import.meta.url), "utf8"),
    ]);

    // Extract string literals passed to invoke("…") / invoke<…>("…")
    // Generics may span lines: invoke<{ ... }>("get_tls_fingerprints", ...)
    const invokeNames = new Set<string>();
    const re =
      /invoke(?:<(?:[^<>]|<[^>]*>)*>)?\s*\(\s*["']([a-zA-Z0-9_]+)["']/gs;
    let match: RegExpExecArray | null;
    while ((match = re.exec(consoleSrc)) !== null) {
      invokeNames.add(match[1]);
    }

    assert.ok(invokeNames.size >= 6, `expected multiple invokes, got ${[...invokeNames]}`);
    assert.ok(
      invokeNames.has("get_tls_fingerprints"),
      "fingerprint tab must call get_tls_fingerprints",
    );
    assert.ok(invokeNames.has("get_px_settings"));
    assert.ok(invokeNames.has("list_px_evidence"));
    assert.ok(invokeNames.has("get_outbound_tls_profile"));

    // Handler list is the generate_handler!(...) block — each command appears as bare id.
    const handlerStart = libSrc.indexOf("generate_handler![");
    assert.ok(handlerStart >= 0, "lib.rs must define generate_handler!");
    const handlerSlice = libSrc.slice(handlerStart, handlerStart + 12_000);

    for (const name of invokeNames) {
      // Registered as `get_tls_fingerprints,` (or last item before ])
      const registered =
        new RegExp(`\\b${name}\\s*,`).test(handlerSlice) ||
        new RegExp(`\\b${name}\\s*\\]`).test(handlerSlice);
      assert.ok(
        registered,
        `AdvancedConsole invoke("${name}") must be registered in generate_handler (not only agent_tools)`,
      );
      // Also require a #[tauri::command] fn with that name exists in lib.rs
      assert.match(
        libSrc,
        new RegExp(`fn ${name}\\s*\\(`),
        `lib.rs must define #[tauri::command] fn ${name}`,
      );
    }

    // Fingerprint load must not silently swallow IPC errors with empty fallback.
    assert.doesNotMatch(
      consoleSrc,
      /get_tls_fingerprints[^;]{0,200}\.catch\(\s*\(\)\s*=>\s*\(\s*\{\s*inboundFingerprints/,
      "get_tls_fingerprints must not silently catch to empty fingerprints",
    );
  });

  it("exposes ClientHello preset picker and honesty copy in Advanced Console", async () => {
    const src = await readFile(
      new URL("../src/components/AdvancedConsoleView.tsx", import.meta.url),
      "utf8",
    );
    assert.match(src, /出站 ClientHello 预置|ClientHello/);
    assert.match(src, /presetId/);
    assert.match(src, /supportsFullBrowserJa3/);
    assert.match(src, /ja3Parity/);
    assert.match(src, /set_outbound_tls_profile/);
  });
});
