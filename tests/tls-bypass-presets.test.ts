import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  mergeStaticCdnBypassRules,
  STATIC_CDN_BYPASS_PRESET,
  staticCdnBypassRulesPresent,
} from "../src/tlsBypassPresets.ts";

describe("static CDN bypass presets (P0-A)", () => {
  it("merges preset hosts without duplicates and detects presence", () => {
    assert.deepEqual([...STATIC_CDN_BYPASS_PRESET], ["*.bdstatic.com", "*.bcebos.com"]);

    const merged = mergeStaticCdnBypassRules(["*.BDSTATIC.com", "api.secure.example"]);
    assert.deepEqual(merged, ["*.BDSTATIC.com", "api.secure.example", "*.bcebos.com"]);
    assert.equal(staticCdnBypassRulesPresent(merged), true);
    assert.equal(staticCdnBypassRulesPresent(["*.bdstatic.com"]), false);
    assert.equal(staticCdnBypassRulesPresent([]), false);
  });

  it("starts from empty list with both recommended CDN wildcards", () => {
    assert.deepEqual(mergeStaticCdnBypassRules([]), ["*.bdstatic.com", "*.bcebos.com"]);
  });
});
