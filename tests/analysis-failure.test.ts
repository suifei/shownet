import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { parseAnalysisFailure } from "../src/analysisFailure.ts";
import { clampContextTokens, DEFAULT_AI_CONTEXT_TOKENS, LEGACY_DEFAULT_AI_CONTEXT_TOKENS, promptBudgetBytes } from "../src/aiContextBudget.ts";

const RESPONSES_FAILED = `{
  "response": {
    "background": false,
    "completed_at": null,
    "created_at": 1786985537,
    "error": {
      "code": "context_length_exceeded",
      "message": "Your input exceeds the context window of this model. Please adjust your input and try again.",
      "type": "invalid_request_error"
    },
    "id": "resp_0152a6261316287f016a833c41309481908926745fc3b4034a",
    "model": "gpt-5.5",
    "object": "response",
    "status": "failed",
    "store": false
  },
  "sequence_number": 3,
  "type": "response.failed"
}`;

describe("parseAnalysisFailure", () => {
  it("reads code/type/message from a Responses API response.failed event", () => {
    const parsed = parseAnalysisFailure(RESPONSES_FAILED);
    assert.equal(parsed.code, "context_length_exceeded");
    assert.equal(parsed.type, "invalid_request_error");
    assert.equal(parsed.model, "gpt-5.5");
    assert.equal(parsed.event, "response.failed");
    assert.match(parsed.detail, /context window/);
    assert.match(parsed.headline, /上下文超出模型窗口/);
  });

  it("does not label a different provider code as a context overflow", () => {
    const parsed = parseAnalysisFailure(JSON.stringify({
      response: {
        error: {
          code: "server_error",
          message: "The server had an error while processing your request.",
          type: "api_error",
        },
        model: "gpt-5.5",
        status: "failed",
      },
      type: "response.failed",
    }));
    assert.equal(parsed.code, "server_error");
    assert.equal(parsed.headline, "分析未完成：server_error");
    assert.doesNotMatch(parsed.headline, /上下文/);
  });

  it("unwraps a gateway body that embeds the raw event", () => {
    const parsed = parseAnalysisFailure(JSON.stringify({
      error: {
        message: "upstream failed",
        type: "upstream_error",
        metadata: { raw: RESPONSES_FAILED },
      },
    }));
    assert.equal(parsed.code, "context_length_exceeded");
    assert.equal(parsed.type, "invalid_request_error");
  });

  it("reads the formatted Rust failure lines", () => {
    const parsed = parseAnalysisFailure([
      "AI 请求失败",
      "事件：response.failed",
      "模型：gpt-5.5",
      "错误码：content_filter",
      "类型：invalid_request_error",
      "说明：The response was filtered.",
      "HTTP：502（传输层状态，根因见上方错误码）",
    ].join("\n"));
    assert.equal(parsed.code, "content_filter");
    assert.equal(parsed.headline, "分析未完成：content_filter");
    assert.equal(parsed.detail, "The response was filtered.");
    assert.equal(parsed.model, "gpt-5.5");
  });
});

describe("legacy 200k context default", () => {
  it("remaps the old product default onto the 100 KiB budget", () => {
    assert.equal(clampContextTokens(LEGACY_DEFAULT_AI_CONTEXT_TOKENS), DEFAULT_AI_CONTEXT_TOKENS);
    assert.equal(promptBudgetBytes(DEFAULT_AI_CONTEXT_TOKENS), 102_400);
    assert.equal(clampContextTokens(262_144), 262_144);
  });
});

describe("failed analysis surfaces the provider code", () => {
  it("wires the failed report UI to parseAnalysisFailure", async () => {
    const view = await readFile(new URL("../src/components/AnalysisView.tsx", import.meta.url), "utf8");
    assert.match(view, /parseAnalysisFailure/);
    assert.match(view, /analysisFailure\.headline/);
    const rust = await readFile(new URL("../src-tauri/src/ai_error.rs", import.meta.url), "utf8");
    assert.match(rust, /response\/error/);
    assert.match(rust, /context_length_exceeded/);
    assert.match(rust, /is_retryable_ai_failure/);
  });
});
