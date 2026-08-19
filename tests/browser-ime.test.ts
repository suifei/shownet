import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { cdpInsertTextPayload, shouldForwardRawKeyToCdp } from "../src/browserIme.ts";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("embedded browser IME", () => {
  it("does not inject latin event.key while composing or typing on the IME surface", () => {
    const composingPinyin = shouldForwardRawKeyToCdp({
      composing: true,
      key: "n",
      metaKey: false,
      ctrlKey: false,
      imeSurfaceFocused: true,
    });
    const printableOnIme = shouldForwardRawKeyToCdp({
      composing: false,
      key: "n",
      metaKey: false,
      ctrlKey: false,
      imeSurfaceFocused: true,
    });
    assert.equal(composingPinyin, false);
    assert.equal(printableOnIme, false);
    assert.deepEqual(cdpInsertTextPayload("你好"), {
      method: "Input.insertText",
      params: { text: "你好" },
    });
    assert.equal(cdpInsertTextPayload(""), null);
  });

  it("still forwards Enter and arrows to CDP", () => {
    assert.equal(
      shouldForwardRawKeyToCdp({
        composing: false,
        key: "Enter",
        metaKey: false,
        ctrlKey: false,
        imeSurfaceFocused: true,
      }),
      true,
    );
    assert.equal(
      shouldForwardRawKeyToCdp({
        composing: false,
        key: "a",
        metaKey: false,
        ctrlKey: false,
        imeSurfaceFocused: false,
      }),
      true,
    );
  });

  it("keeps IME focus on the textarea and commits via insertText", () => {
    const browser = readFileSync(join(root, "src/components/BrowserView.tsx"), "utf8");
    const css = readFileSync(join(root, "src/styles.css"), "utf8");
    assert.match(browser, /imeInputRef\.current\?\.focus\(\{ preventScroll: true \}\)/);
    assert.doesNotMatch(
      browser,
      /imeInputRef\.current\?\.focus\(\{ preventScroll: true \}\);\s*event\.currentTarget\.focus/,
    );
    assert.match(browser, /shouldForwardRawKeyToCdp\(/);
    assert.match(browser, /cdpInsertTextPayload\(/);
    assert.match(css, /\.browser-ime-input \{[\s\S]*?font-size: 16px;/);
    assert.doesNotMatch(css, /\.browser-ime-input \{[\s\S]*?z-index: -1;/);
  });
});
