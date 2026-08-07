/**
 * The toast rendered a green tick unconditionally, so every failure the app
 * reported — "转发目标请求失败: http2 error", "无法连接 AI 服务" — arrived wearing
 * a success mark, and the only way to tell was to read the sentence.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import { toastTone } from "../src/toastTone.ts";

describe("toast tone follows what the message says", () => {
  it("marks the failures the proxy actually reports as failures", () => {
    // Every one of these was observed in the running app wearing a tick.
    for (const message of [
      "转发目标请求失败: http2 error",
      "转发目标请求失败: operation was canceled",
      "HTTPS MITM 连接结束: connection error",
      "客户端 TLS 握手失败 fonts.gstatic.com:443: tls handshake eof",
      "抓包状态切换失败：系统代理恢复失败",
      "读取流量窗口失败：database is locked",
      "查询取消超时，界面已停止等待",
      "系统代理运行状态已损坏",
    ]) {
      assert.equal(toastTone(message), "error", `${message} is a failure`);
    }
  });

  it("still recognises a completed action", () => {
    for (const message of [
      "AI 配置、凭据与分析策略已保存",
      "ShowNet Root CA 已导出",
      "AI API Key 已清除",
    ]) {
      assert.equal(toastTone(message), "success", `${message} completed`);
    }
  });

  it("stays neutral rather than claiming success it cannot verify", () => {
    // The conservative direction: an unrecognised message must not be dressed
    // up as a win, which is exactly what the unconditional tick did.
    assert.equal(toastTone("查询已取消，仍显示上一次结果"), "neutral");
    assert.equal(toastTone("系统代理将在抓包启动时接管"), "neutral");
  });

  it("is what the shell actually renders from", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.match(app, /const tone = toastTone\(toast\)/);
    // An error toast must also be announced as one to assistive tech.
    assert.match(app, /role=\{tone === "error" \? "alert" : "status"\}/);
    assert.doesNotMatch(
      app,
      /<div className="toast" role="status">\s*<Check size=\{16\} \/>/,
      "the unconditional tick must be gone",
    );
  });
});
