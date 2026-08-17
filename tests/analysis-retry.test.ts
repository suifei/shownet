import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import {
  LOCAL_AI_BASE_URL,
  analysisRetryInvokeInput,
  continueOnLocalModel,
  initialAnalysisRetryDraft,
} from "../src/analysisRetry.ts";

const read = (name: string) => readFile(new URL(`../src/${name}`, import.meta.url), "utf8");

describe("analysis retry draft", () => {
  it("keeps the last prompt and can continue on a local model without saving settings", () => {
    const draft = initialAnalysisRetryDraft({
      provider: "claudegpt",
      model: "gpt-5.5",
      baseUrl: "https://claudegpt.org/v1",
    }, "# ShowNet 内置 Agent 分析任务\n\n缩短证据");
    const local = continueOnLocalModel(draft, "llama3.1");
    assert.equal(local.provider, "local");
    assert.equal(local.model, "llama3.1");
    assert.equal(local.baseUrl, LOCAL_AI_BASE_URL);
    assert.match(local.prompt, /缩短证据/);
    const input = analysisRetryInvokeInput({
      sessionId: "session-1",
      mode: "security",
      includeStatic: false,
      manualRequestIds: ["req-1"],
      includeAnnotations: true,
    }, local);
    assert.equal(input.promptOverride, "# ShowNet 内置 Agent 分析任务\n\n缩短证据");
    assert.equal(input.provider, "local");
    assert.equal(input.model, "llama3.1");
    assert.equal(input.baseUrl, LOCAL_AI_BASE_URL);
  });
});

describe("failed analysis exposes retry with the last prompt", () => {
  it("wires the failed report UI to the stored prompt and start_ai_analysis overrides", async () => {
    const view = await read("components/AnalysisView.tsx");
    assert.match(view, /get_analysis_prompt/);
    assert.match(view, /调整并重试/);
    assert.match(view, /用本地模型继续/);
    assert.match(view, /analysisRetryInvokeInput/);
    const rust = await readFile(new URL("../src-tauri/src/analysis.rs", import.meta.url), "utf8");
    assert.match(rust, /fn resolve_prompt_override/);
    assert.match(rust, /fn apply_analysis_runtime_overrides/);
    assert.match(rust, /save_analysis_prompt/);
    const storage = await readFile(new URL("../src-tauri/src/storage.rs", import.meta.url), "utf8");
    assert.match(storage, /prompt_text/);
    assert.match(storage, /fn get_analysis_prompt/);
  });
});
