import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  browserUrlStorageKey,
  forgetAllStoredBrowserUrls,
  forgetStoredBrowserUrl,
  readStoredBrowserUrl,
  writeStoredBrowserUrl,
} from "../src/browserSessionUrl.ts";

class MemoryStorage {
  private values = new Map<string, string>();

  getItem(key: string) {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string) {
    this.values.set(key, value);
  }

  removeItem(key: string) {
    this.values.delete(key);
  }

  key(index: number) {
    return [...this.values.keys()][index] ?? null;
  }

  get length() {
    return this.values.size;
  }
}

describe("embedded browser session URLs", () => {
  it("does not let a new session inherit another session's URL", () => {
    const storage = new MemoryStorage();
    writeStoredBrowserUrl("session-a", "https://example.com/login?step=2", storage);

    assert.equal(readStoredBrowserUrl("session-a", storage), "https://example.com/login?step=2");
    assert.equal(readStoredBrowserUrl("session-b", storage), null);
    assert.notEqual(browserUrlStorageKey("session-a"), browserUrlStorageKey("session-b"));
  });

  it("accepts only navigable HTTP(S) addresses", () => {
    const storage = new MemoryStorage();

    writeStoredBrowserUrl("session-a", "chrome://settings", storage);
    writeStoredBrowserUrl("session-a", "javascript:alert(1)", storage);
    assert.equal(readStoredBrowserUrl("session-a", storage), null);

    storage.setItem(browserUrlStorageKey("session-a"), "not-a-url");
    assert.equal(readStoredBrowserUrl("session-a", storage), null);
  });

  it("removes a deleted session's saved address", () => {
    const storage = new MemoryStorage();
    writeStoredBrowserUrl("session-a", "https://example.com/private?token=redacted", storage);

    forgetStoredBrowserUrl("session-a", storage);

    assert.equal(readStoredBrowserUrl("session-a", storage), null);
  });

  it("removes every saved address when all session data is cleared", () => {
    const storage = new MemoryStorage();
    writeStoredBrowserUrl("session-a", "https://example.com/a", storage);
    writeStoredBrowserUrl("session-b", "https://example.com/b", storage);
    storage.setItem("shownet.unrelated", "keep");

    forgetAllStoredBrowserUrls(storage);

    assert.equal(readStoredBrowserUrl("session-a", storage), null);
    assert.equal(readStoredBrowserUrl("session-b", storage), null);
    assert.equal(storage.getItem("shownet.unrelated"), "keep");
  });
});
