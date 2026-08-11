import { act, render, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AnalysisReport, AnalysisStreamEvent, RequestListItem } from "../../src/types";

const eventHarness = vi.hoisted(() => ({
  resolve: undefined as undefined | ((unlisten: () => void) => void),
  handler: undefined as undefined | ((event: { payload: AnalysisStreamEvent }) => void),
}));

vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true, invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({
  listen: vi.fn((_name: string, handler: (event: { payload: AnalysisStreamEvent }) => void) => new Promise<() => void>((resolve) => {
    eventHarness.handler = handler;
    eventHarness.resolve = resolve;
  })),
}));

import { invoke } from "@tauri-apps/api/core";

import { AnalysisView } from "../../src/components/AnalysisView";

const request: RequestListItem = {
  id: "request-1",
  order: 1,
  startedAt: 1,
  state: "complete",
  method: "POST",
  scheme: "https",
  host: "api.example.com",
  path: "/v1/order",
  type: "xhr",
  source: "script",
  sourceInstanceId: "proxy-1",
  protocol: "h2",
  sizeBytes: 100,
  risk: "none",
  hasHook: false,
  cryptoSnippetCount: 0,
  tlsIntercepted: true,
};

const completedReport: AnalysisReport = {
  id: "analysis-1",
  sessionId: "session-1",
  mode: "api",
  status: "complete",
  requestCount: 1,
  keyRequestCount: 1,
  selectedRequestIds: [request.id],
  content: "# FINAL_STREAM_REPORT",
  provider: "local",
  model: "test-model",
  createdAt: 1,
  updatedAt: 2,
};

beforeEach(() => {
  eventHarness.resolve = undefined;
  eventHarness.handler = undefined;
  vi.mocked(invoke).mockImplementation(async (command: string) => {
    if (command === "get_ai_provider_settings") {
      return {
        provider: "local",
        baseUrl: "http://localhost:11434/v1",
        model: "test-model",
        contextTokens: 32_000,
        hasApiKey: false,
      };
    }
    if (command === "get_ai_analysis_settings") {
      return {
        twoStageAnalysis: false,
        allowMcpTools: true,
        streamingOutput: true,
        maxAgentTurns: 8,
      };
    }
    if (command === "list_analysis_reports") return [];
    if (command === "get_analysis_skill_plan") {
      return { selectedSkillIds: [], toolNames: [], stages: [] };
    }
    if (command === "start_ai_analysis") return completedReport;
    if (command === "get_analysis_graph_run") return null;
    if (command === "list_analysis_skill_runs") return [];
    throw new Error(`unstubbed command: ${command}`);
  });
});

describe("analysis stream listener readiness", () => {
  it("does not start analysis until the current session listener is registered", async () => {
    const view = render(
      <AnalysisView
        sessionId="session-1"
        requests={[request]}
        onConfigureAi={vi.fn()}
        onNotify={vi.fn()}
        onAutoRunConsumed={vi.fn()}
        onScopeConsumed={vi.fn()}
        onOpenEvidenceRequest={vi.fn()}
        mode="api"
        onModeChange={vi.fn()}
        modePinned
      />,
    );
    const start = view.container.querySelector(".analysis-start-button") as HTMLButtonElement;

    expect(start).toBeDisabled();
    expect(invoke).not.toHaveBeenCalledWith("list_analysis_reports", { sessionId: "session-1" });
    await userEvent.click(start);
    expect(invoke).not.toHaveBeenCalledWith("start_ai_analysis", expect.anything());

    await waitFor(() => expect(eventHarness.resolve).toBeTypeOf("function"));
    act(() => eventHarness.resolve?.(() => undefined));
    await waitFor(() => expect(start).toBeEnabled());
    expect(invoke).toHaveBeenCalledWith("list_analysis_reports", { sessionId: "session-1" });

    await userEvent.click(start);
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("start_ai_analysis", expect.anything());
    });
  });

  it("does not let an older history snapshot overwrite a completed stream event", async () => {
    let resolveHistory: (reports: AnalysisReport[]) => void = () => undefined;
    const historyPromise = new Promise<AnalysisReport[]>((resolve) => {
      resolveHistory = resolve;
    });
    const defaultImplementation = vi.mocked(invoke).getMockImplementation()!;
    vi.mocked(invoke).mockImplementation((command: string, args?: unknown) => {
      if (command === "list_analysis_reports") return historyPromise;
      return defaultImplementation(command, args);
    });
    const staleReport: AnalysisReport = {
      ...completedReport,
      status: "analyzing",
      content: "# STALE_HISTORY_SNAPSHOT",
      updatedAt: 1,
    };

    const view = render(
      <AnalysisView
        sessionId="session-1"
        requests={[request]}
        onConfigureAi={vi.fn()}
        onNotify={vi.fn()}
        onAutoRunConsumed={vi.fn()}
        onScopeConsumed={vi.fn()}
        onOpenEvidenceRequest={vi.fn()}
        mode="api"
        onModeChange={vi.fn()}
        modePinned
      />,
    );

    await waitFor(() => expect(eventHarness.resolve).toBeTypeOf("function"));
    act(() => eventHarness.resolve?.(() => undefined));
    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith("list_analysis_reports", { sessionId: "session-1" });
    });

    act(() => eventHarness.handler?.({
      payload: {
        analysisId: completedReport.id,
        sessionId: completedReport.sessionId,
        phase: "complete",
        delta: "",
        requestCount: completedReport.requestCount,
        keyRequestCount: completedReport.keyRequestCount,
        report: completedReport,
      },
    }));
    await waitFor(() => expect(view.container).toHaveTextContent("FINAL_STREAM_REPORT"));

    await act(async () => {
      resolveHistory([staleReport]);
      await historyPromise;
      await Promise.resolve();
    });

    expect(view.container).toHaveTextContent("FINAL_STREAM_REPORT");
    expect(view.container).not.toHaveTextContent("STALE_HISTORY_SNAPSHOT");
    expect(invoke).not.toHaveBeenCalledWith("list_analysis_activities", expect.anything());
  });
});
