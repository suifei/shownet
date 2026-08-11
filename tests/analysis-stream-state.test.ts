import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  analysisStreamReducer,
  createAnalysisStreamState,
} from "../src/analysisStreamState.ts";
import type {
  AnalysisReport,
  AnalysisStreamEvent,
} from "../src/types.ts";

const report: AnalysisReport = {
  id: "analysis-1",
  sessionId: "session-1",
  mode: "api",
  status: "complete",
  requestCount: 30,
  keyRequestCount: 4,
  selectedRequestIds: ["request-1"],
  content: "# 完整报告",
  provider: "compatible",
  model: "test-model",
  createdAt: 1,
  updatedAt: 2,
};

function streamEvent(
  phase: AnalysisStreamEvent["phase"],
  overrides: Partial<AnalysisStreamEvent> = {},
): AnalysisStreamEvent {
  return {
    analysisId: "analysis-1",
    sessionId: "session-1",
    phase,
    delta: "",
    requestCount: 30,
    keyRequestCount: 4,
    ...overrides,
  };
}

describe("AI analysis stream state machine", () => {
  it("moves from filtering through visible report output to completion", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "start",
      filtering: true,
      message: "正在识别关键请求",
      occurredAt: 100,
    });
    assert.equal(state.status, "filtering");

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("runtime", { message: "启动运行时" }),
      occurredAt: 200,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("reasoning", { message: "关联证据" }),
      occurredAt: 300,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("first-visible", {
        message: "首段报告内容已显示 · 420 ms",
        elapsedMs: 420,
      }),
      occurredAt: 420,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("delta", { delta: "# 部分" }),
      occurredAt: 421,
    });

    assert.equal(state.status, "analyzing");
    assert.equal(state.content, "# 部分");
    assert.equal(state.firstVisibleLatencyMs, 420);
    assert.equal(state.agentActivities.at(-1)?.phase, "first-visible");

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("complete", { report }),
      occurredAt: 500,
    });
    assert.equal(state.status, "complete");
    assert.equal(state.content, report.content);
    assert.equal(state.error, "");
    assert.equal(state.agentActivities.at(-1)?.phase, "complete");
  });

  it("clears failed native output before accepting fallback deltas", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "start",
      filtering: false,
      message: "准备直接进入深度分析",
      occurredAt: 10,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("delta", { delta: "native partial" }),
      occurredAt: 20,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("content-reset"),
      occurredAt: 30,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("delta", { delta: "fallback report" }),
      occurredAt: 40,
    });

    assert.equal(state.status, "analyzing");
    assert.equal(state.content, "fallback report");
  });

  it("settles cancellation instead of leaving the stop control pending", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "start",
      filtering: false,
      message: "准备分析",
      occurredAt: 10,
    });
    state = analysisStreamReducer(state, { type: "cancel-requested" });
    assert.equal(state.cancelling, true);

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("error", {
        message: "AI 分析已取消",
        report: { ...report, status: "failed", error: "AI 分析已取消" },
      }),
      occurredAt: 20,
    });
    assert.equal(state.status, "failed");
    assert.equal(state.failureKind, "cancelled");
    assert.equal(state.cancelling, false);
    assert.equal(state.agentActivities.at(-1)?.title, "分析已停止");
  });

  it("recovers a live analysis after remount and fails a stale one explicitly", () => {
    const runningReport: AnalysisReport = { ...report, status: "analyzing", content: "# 已持久化片段" };
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "restore",
      report: runningReport,
    });
    state = analysisStreamReducer(state, {
      type: "recover",
      report: runningReport,
      running: true,
    });
    assert.equal(state.status, "analyzing");
    assert.equal(state.content, "# 已持久化片段");

    state = analysisStreamReducer(state, {
      type: "recover",
      report: runningReport,
      running: false,
    });
    assert.equal(state.status, "failed");
    assert.match(state.error, /未正常结束/);
  });

  it("ignores recovery and cancellation results that arrive after completion", () => {
    const runningReport: AnalysisReport = { ...report, status: "analyzing", content: "# 已持久化片段" };
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "restore",
      report: runningReport,
    });
    state = analysisStreamReducer(state, { type: "cancel-requested" });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("complete", { report }),
      occurredAt: 20,
    });

    state = analysisStreamReducer(state, {
      type: "recover",
      report: runningReport,
      running: false,
    });
    state = analysisStreamReducer(state, {
      type: "recovery-error",
      message: "late recovery failure",
    });
    state = analysisStreamReducer(state, {
      type: "cancel-failed",
      message: "late cancellation failure",
    });

    assert.equal(state.status, "complete");
    assert.equal(state.report?.id, report.id);
    assert.equal(state.error, "");
    assert.equal(state.phaseMessage, "");
  });

  it("does not let a late command rejection replace a completed report", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "start",
      filtering: false,
      message: "准备分析",
      occurredAt: 10,
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("complete", { report }),
      occurredAt: 20,
    });
    const completed = state;

    state = analysisStreamReducer(state, {
      type: "command-failed",
      message: "late IPC rejection",
      occurredAt: 30,
    });

    assert.deepEqual(state, completed);
    assert.equal(state.status, "complete");
    assert.equal(state.error, "");
  });

  it("restores the persisted first-visible latency from activity history", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "restore",
      report,
    });
    state = analysisStreamReducer(state, {
      type: "restore-activities",
      activities: [{
        id: 1,
        analysisId: report.id,
        phase: "first-visible",
        message: "首段报告内容已显示 · 875 ms",
        elapsedMs: 875,
        createdAt: 100,
      }],
    });
    assert.equal(state.firstVisibleLatencyMs, 875);
    assert.equal(state.agentActivities[0]?.title, "首段报告已显示");
  });

  it("settles streamed and command-based follow-up answers", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "restore",
      report,
    });
    state = analysisStreamReducer(state, {
      type: "followup-requested",
    });
    assert.equal(state.sending, true);

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("tool", { message: "内置 Agent 正在调用 shownet_get_request" }),
    });
    assert.equal(state.status, "complete", "follow-up tools must not restart report generation");
    assert.equal(state.sending, true);
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("tool-complete", { message: "shownet_get_request 已返回取证结果" }),
    });

    for (const event of [
      streamEvent("delta", { delta: "迟到的报告正文" }),
      streamEvent("content-reset"),
      streamEvent("error", { message: "迟到的报告错误" }),
    ]) {
      state = analysisStreamReducer(state, { type: "event", event });
    }
    assert.equal(state.status, "complete");
    assert.equal(state.content, report.content);
    assert.equal(state.sending, true, "report events must not settle an active follow-up");

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("followup-delta", { delta: "第一段" }),
    });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("followup-delta", { delta: "第二段" }),
    });
    assert.equal(state.pendingAnswer, "第一段第二段");

    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("followup-complete"),
    });
    assert.equal(state.sending, false);
    assert.equal(state.status, "complete");
    assert.equal(state.phaseMessage, "");

    state = analysisStreamReducer(state, { type: "followup-finished" });
    assert.equal(state.pendingAnswer, "");
    assert.equal(state.sending, false);

    state = analysisStreamReducer(state, { type: "followup-requested" });
    state = analysisStreamReducer(state, {
      type: "followup-failed",
      message: "network timeout",
    });
    assert.equal(state.sending, false);
    assert.equal(state.phaseMessage, "追问失败：network timeout");
  });

  it("ignores follow-up and analysis events that arrive after the command settles", () => {
    let state = analysisStreamReducer(createAnalysisStreamState(), {
      type: "restore",
      report,
    });
    state = analysisStreamReducer(state, { type: "followup-requested" });
    state = analysisStreamReducer(state, {
      type: "event",
      event: streamEvent("followup-delta", { delta: "已接收" }),
    });
    state = analysisStreamReducer(state, { type: "followup-finished" });
    const settled = state;

    for (const event of [
      streamEvent("followup-delta", { delta: "迟到正文" }),
      streamEvent("followup-start"),
      streamEvent("tool", { message: "迟到工具调用" }),
      streamEvent("tool-complete", { message: "迟到工具返回" }),
      streamEvent("delta", { delta: "迟到报告正文" }),
    ]) {
      state = analysisStreamReducer(state, { type: "event", event });
    }

    assert.deepEqual(state, settled);
    assert.equal(state.status, "complete");
    assert.equal(state.sending, false);
    assert.equal(state.pendingAnswer, "");
  });
});
