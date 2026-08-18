import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

describe("no-proxy capture entry", () => {
  it("exposes one-step lifecycle controls in the connection workspace", async () => {
    const source = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.match(source, /免代理接入/);
    assert.match(source, /invoke<ReverseProxyStatus>\("get_reverse_proxy_status"/);
    assert.match(source, /invoke<ReverseProxyStatus>\("start_reverse_proxy"/);
    assert.match(source, /invoke<ReverseProxyStatus>\("stop_reverse_proxy"/);
    assert.match(source, /启动抓包与入口/);
    assert.match(source, /connect\.caByReverse/);
  });

  it("treats reverse traffic as a first-class filterable source", async () => {
    const [types, data, traffic] = await Promise.all([
      readFile(new URL("../src/types.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/data.ts", import.meta.url), "utf8"),
      readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8"),
    ]);

    assert.match(types, /\| "reverse"/);
    assert.match(data, /reverse: "source\.reverse"/);
    assert.match(traffic, /"mobile", "iot", "reverse"/);
  });

  it("keeps the endpoint editor usable on narrow screens", async () => {
    const styles = await readFile(new URL("../src/styles.css", import.meta.url), "utf8");

    assert.match(styles, /\.reverse-proxy-fields \{[\s\S]*grid-template-columns: minmax\(0, 1fr\) 112px/);
    assert.match(styles, /\.reverse-proxy-endpoints \{[\s\S]*grid-template-columns: repeat\(2, minmax\(0, 1fr\)\)/);
    assert.match(styles, /\.reverse-proxy-endpoints \{ grid-template-columns: 1fr; \}/);
    assert.match(styles, /\.connect-dialog > \.source-grid,[\s\S]*flex-shrink: 0/);
    assert.match(styles, /\.reverse-proxy-setup \.source-setup__actions \{[\s\S]*min-height: 50px/);
  });
});
