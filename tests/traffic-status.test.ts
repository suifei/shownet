import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  classifyTrafficStatus,
  looksLikeProxyErrorBody,
} from "../src/trafficStatus.ts";

describe("traffic status classification (P0-C)", () => {
  it("labels ShowNet proxy failures separately from origin 4xx", () => {
    assert.equal(looksLikeProxyErrorBody("连接 www.baidu.com:443 超时"), true);
    assert.equal(looksLikeProxyErrorBody("出口 127.0.0.1:8080 连不上：连接超时"), true);
    assert.equal(looksLikeProxyErrorBody("400 Bad Request\nJSP3/2.0.14"), false);

    const proxy = classifyTrafficStatus(502, {
      responseBody: "连接 www.baidu.com:443 超时",
    });
    assert.equal(proxy.kind, "proxy");
    assert.match(proxy.label, /502/);
    assert.match(proxy.label, /代理/);
    assert.match(proxy.title, /代理错误|连接/);

    // List row without body still treats bare 502 as proxy-facing.
    const bare = classifyTrafficStatus(502, { responseBody: null });
    assert.equal(bare.kind, "proxy");

    const origin = classifyTrafficStatus(400, { server: "JSP3/2.0.14" });
    assert.equal(origin.kind, "origin4xx");
    assert.equal(origin.label, "400");
    assert.match(origin.title, /源站 4xx/);
    assert.match(origin.title, /JSP3/);

    const ok = classifyTrafficStatus(200);
    assert.equal(ok.kind, "success");
    assert.equal(ok.label, "200");
  });

  it("wires classification into TrafficView status column and banners", async () => {
    const traffic = await readFile(new URL("../src/components/TrafficView.tsx", import.meta.url), "utf8");
    assert.match(traffic, /classifyTrafficStatus/);
    assert.match(traffic, /origin-4xx-banner/);
    assert.match(traffic, /proxy-error-banner/);
    assert.match(traffic, /源站/);
  });
});
