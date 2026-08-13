import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { userAgentMetadataFor } from "../src/browserIdentity.ts";

function status(overrides: Partial<Parameters<typeof userAgentMetadataFor>[0]> = {}) {
  return {
    browserPresetFamily: "chrome",
    browserPresetMajorVersion: 149,
    browserUserAgentMajorVersion: 149,
    honestUserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/149.0.0.0 Safari/537.36",
    ...overrides,
  };
}

describe("embedded browser identity", () => {
  it("keeps Chrome UA-CH brands and full versions on the selected major", () => {
    const metadata = userAgentMetadataFor(status());
    assert.ok(metadata);
    assert.deepEqual(metadata.brands, [
      { brand: "Not/A Brand", version: "99" },
      { brand: "Chromium", version: "149" },
      { brand: "Google Chrome", version: "149" },
    ]);
    assert.deepEqual(metadata.fullVersionList, [
      { brand: "Not/A Brand", version: "99.0.0.0" },
      { brand: "Chromium", version: "149.0.0.0" },
      { brand: "Google Chrome", version: "149.0.0.0" },
    ]);
    assert.equal(metadata.platform, "macOS");
    assert.equal(metadata.mobile, false);
  });

  it("does not invent Chrome client hints for another family or generic preset", () => {
    assert.equal(userAgentMetadataFor(status({ browserPresetFamily: "firefox" })), undefined);
    assert.equal(userAgentMetadataFor(status({ browserPresetFamily: "chrome", browserPresetMajorVersion: 0 })), undefined);
  });
});
