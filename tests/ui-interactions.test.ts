import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("dismissible UI interactions", () => {
  it("dismisses floating layers from outside clicks, Escape and window blur", async () => {
    const hook = await readFile(new URL("../src/useDismissibleLayer.ts", import.meta.url), "utf8");

    assert.match(hook, /document\.addEventListener\("pointerdown", onPointerDown, true\)/);
    assert.match(hook, /event\.key !== "Escape"/);
    assert.match(hook, /window\.addEventListener\("blur", onBlur\)/);
    assert.match(hook, /document\.removeEventListener\("pointerdown", onPointerDown, true\)/);
  });

  it("uses the shared dismissal behavior for every toolbar and context menu", async () => {
    const [app, traffic, browser] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/BrowserView.tsx", import.meta.url), "utf8"),
    ]);

    assert.match(app, /useDismissibleLayer\(sessionToolsOpen, sessionToolsRef/);
    assert.match(traffic, /useDismissibleLayer\(Boolean\(menu\), toolbarRef/);
    assert.match(traffic, /useDismissibleLayer\(Boolean\(contextMenu\), contextMenuRef/);
    assert.match(traffic, /role="menu" aria-label=\{t\("traffic\.requestActions"\)\}/);
    assert.match(browser, /useDismissibleLayer\(browserMenuOpen, browserMenuRef/);
  });

  it("keeps sortable headers and the command palette keyboard-operable", async () => {
    const [app, traffic] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
    ]);

    assert.match(traffic, /aria-sort=\{ariaSort\}/);
    assert.match(traffic, /nextRequestSort\(current, column\.field, event\.shiftKey\)/);
    assert.match(app, /event\.key\.toLowerCase\(\) === "k"/);
    assert.match(app, /setCommandOpen\(\(open\) => !open\)/);
    assert.match(app, /className="modal-backdrop command-backdrop" onMouseDown=\{onClose\}/);
  });
});
