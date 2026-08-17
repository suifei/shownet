/**
 * #42 ships as a Rust fixture under impersonate-boring. Local npm test cannot
 * compile that feature, so this file asserts the fixture is wired to the
 * shipped entry points rather than a parallel reimplementation.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";

const root = fileURLToPath(new URL("..", import.meta.url));

describe("capture integrity fixture drives the shipped path", () => {
  it("is registered and calls ProxyHandle, wreq, SQLite, and Chrome launch", async () => {
    const [lib, fixture] = await Promise.all([
      readFile(join(root, "src-tauri/src/lib.rs"), "utf8"),
      readFile(join(root, "src-tauri/src/capture_integrity.rs"), "utf8"),
    ]);
    assert.match(lib, /mod capture_integrity;/);
    assert.match(fixture, /ProxyHandle::start_with_sinks/);
    assert.match(fixture, /impersonate_egress::install_test_root_certificate_der/);
    assert.match(fixture, /Storage::open/);
    assert.match(fixture, /get_request_detail/);
    assert.match(fixture, /Content-Length: 0/);
    assert.match(fixture, /POST \/empty/);
    assert.match(fixture, /__SHOWNET_HOOK_BRIDGE__/);
    assert.match(fixture, /ProxyBrowserHandle::launch_with_extra_args/);
    assert.doesNotMatch(fixture, /bypass_selected|whitelist|intercept_none/);
  });
});
