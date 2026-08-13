import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { pageHookGuardSource, pageHooksAllowedForUrl } from "../src/browserCompatibility.ts";

describe("sensitive browser page compatibility", () => {
  it("keeps 12306 authentication pages on native page APIs", () => {
    assert.equal(pageHooksAllowedForUrl("https://www.12306.cn/index/"), false);
    assert.equal(pageHooksAllowedForUrl("https://kyfw.12306.cn/otn/login/init"), false);
    assert.equal(pageHooksAllowedForUrl("https://12306.cn/"), false);
  });

  it("still enables hooks for ordinary pages and malformed URLs", () => {
    assert.equal(pageHooksAllowedForUrl("https://example.com/login"), true);
    assert.equal(pageHooksAllowedForUrl("not a URL"), true);
  });

  it("emits a document-time guard that covers subdomains", () => {
    const source = pageHookGuardSource();
    assert.match(source, /location\.hostname/);
    assert.match(source, /12306/);
  });
});
