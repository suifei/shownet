import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  parseArgs,
  percentile,
  protocolGateChecks,
  protocolForIndex,
  renderMarkdown,
  loadUtilizationGate,
  summarizeLoadRate,
  summarizeCancellationIpc,
} from "../scripts/soak-long-session.mjs";

describe("release long-session soak harness", () => {
  it("uses a short smoke default and validates bounded load settings", () => {
    const defaults = parseArgs([]);
    assert.equal(defaults.mode, "smoke");
    assert.equal(defaults.durationSeconds, 30);
    assert.equal(defaults.rate, 20);
    assert.equal(defaults.concurrency, 8);
    assert.equal(defaults.warmupSeconds, 10);
    assert.equal(defaults.cooldownSeconds, 0);
    assert.equal(defaults.minimumRateUtilization, 0.8);
    assert.deepEqual(defaults.protocols, ["http"]);

    const long = parseArgs(["--mode", "long", "--rate=40", "--concurrency", "12", "--protocols", "all"]);
    assert.equal(long.durationSeconds, 1800);
    assert.equal(long.rate, 40);
    assert.equal(long.concurrency, 12);
    assert.equal(long.cooldownSeconds, 60);
    assert.deepEqual(long.protocols, ["http", "https", "websocket", "sse"]);
    assert.throws(() => parseArgs(["--duration-seconds", "2"]), /between 5 and 3600/);
    assert.throws(() => parseArgs(["--mode", "benchmark"]), /smoke or long/);
    assert.throws(() => parseArgs(["--protocols", "http,ftp"]), /supports only/);
    assert.throws(() => parseArgs(["--cooldown-seconds", "301"]), /between 0 and 300/);
    assert.throws(() => parseArgs(["--minimum-rate-utilization", "0.05"]), /between 0.1 and 1/);
  });

  it("makes realized formal load an explicit release gate", () => {
    const load = summarizeLoadRate(29_967, 1800.03, 20);
    assert.equal(load.realizedRatePerSecond, 16.65);
    assert.equal(load.rateUtilization, 0.8324);
    assert.equal(loadUtilizationGate(load, 0.8).pass, true);
    assert.equal(loadUtilizationGate(load, 0.9).pass, false);
  });

  it("rotates the selected protocol matrix without changing request order", () => {
    const protocols = ["http", "https", "websocket", "sse"];
    assert.deepEqual(
      Array.from({ length: 10 }, (_, index) => protocolForIndex(protocols, index + 1)),
      ["http", "https", "websocket", "sse", "http", "https", "websocket", "sse", "http", "https"],
    );
  });

  it("uses a nearest-rank percentile without mutating samples", () => {
    const values = [8, 1, 5, 3];
    assert.equal(percentile(values, 50), 3);
    assert.equal(percentile(values, 95), 8);
    assert.deepEqual(values, [8, 1, 5, 3]);
    assert.equal(percentile([], 95), null);
  });

  it("summarizes only acknowledged and fully settled WebView cancellation samples", () => {
    const samples = Array.from({ length: 12 }, (_, index) => ({
      queryId: `request-${index}`,
      accepted: index !== 0,
      settled: index !== 1,
      clickToIdleMs: 20 + index,
      backendWaitMs: 2 + index / 10,
    }));
    const summary = summarizeCancellationIpc({ targetSamples: 12, samples });
    assert.equal(summary.status, "measured");
    assert.equal(summary.attempts, 12);
    assert.equal(summary.validSamples, 10);
    assert.equal(summary.clickToIdle.p50Ms, 26);
    assert.equal(summary.clickToIdle.p95Ms, 31);
    assert.match(summary.measurement, /React cancellation handler/);
  });

  it("requires transport-specific evidence for every selected protocol", () => {
    const traffic = {
      http: { completed: 2 },
      https: { completed: 2 },
      websocket: { completed: 2 },
      sse: { completed: 2 },
    };
    const complete = protocolGateChecks(
      ["http", "https", "websocket", "sse"],
      traffic,
      {
        http: { requests: 2 },
        https: { requests: 2, mitmRequests: 2 },
        websocket: { requests: 2, eventRequests: 2, events: 4 },
        sse: { requests: 2, completedRequests: 2, eventRequests: 2, events: 6 },
      },
    );
    assert.ok(complete.every((gate) => gate.pass), complete);

    const incomplete = protocolGateChecks(["https", "websocket", "sse"], traffic, {
      https: { requests: 2, mitmRequests: 1 },
      websocket: { requests: 2, eventRequests: 1, events: 4 },
      sse: { requests: 2, completedRequests: 1, eventRequests: 2, events: 5 },
    });
    assert.ok(incomplete.every((gate) => !gate.pass), incomplete);
  });

  it("renders eligibility, gates, metrics and limitations into the report", () => {
    const report = {
      runId: "shownet-smoke-soak-test",
      formalEligibility: { eligible: false },
      config: { mode: "smoke", protocols: ["http", "https", "websocket", "sse"] },
      artifact: { path: "/Applications/ShowNet.app/Contents/MacOS/ShowNet" },
      traffic: {
        actualDurationSeconds: 30,
        attempted: 600,
        completed: 600,
        failed: 0,
        byProtocol: {
          http: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 8 } },
          https: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 12 } },
          websocket: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 14 } },
          sse: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 16 } },
        },
        latency: { p50Ms: 4, p95Ms: 9, maxMs: 12 },
        loadRate: { realizedRatePerSecond: 20, dispatchCeilingPerSecond: 20, rateUtilization: 1 },
      },
      capture: { requestCount: 600, connectCount: 150, totalRows: 750, ratio: 1 },
      protocolMatrix: {
        selected: ["http", "https", "websocket", "sse"],
        traffic: {
          http: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 8 } },
          https: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 12 } },
          websocket: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 14 } },
          sse: { attempted: 150, completed: 150, failed: 0, latency: { p95Ms: 16 } },
        },
        capture: {
          http: { requests: 150 },
          https: { requests: 150, mitmRequests: 150 },
          websocket: { requests: 150, events: 300 },
          sse: { requests: 150, completedRequests: 150, events: 450 },
        },
      },
      resources: {
        main: { startBytes: 10 * 1024 * 1024, peakBytes: 20 * 1024 * 1024, endBytes: 1.52 * 1024 * 1024, growthBytes: -8.48 * 1024 * 1024 },
        webview: { startBytes: 20, peakBytes: 30, endBytes: 25, growthBytes: 5 },
        helper: { startBytes: 5, peakBytes: 8, endBytes: 6, growthBytes: 1 },
        tree: { startBytes: 30, peakBytes: 50, endBytes: 40, growthBytes: 10 },
      },
      cooldown: {
        requestedSeconds: 60,
        actualSeconds: 60.2,
        webview: { trafficEndBytes: 30 * 1024 * 1024, endBytes: 20 * 1024 * 1024, deltaBytes: -10 * 1024 * 1024 },
        tree: { trafficEndBytes: 50 * 1024 * 1024, endBytes: 40 * 1024 * 1024, deltaBytes: -10 * 1024 * 1024 },
      },
      storage: { startPhysicalBytes: 100, endPhysicalBytes: 300, growthBytes: 200 },
      queryWindow: { samples: 3, p50Ms: 5, p95Ms: 8, maxMs: 9 },
      gates: {
        passed: true,
        checks: [{ name: "Capture completeness", pass: true, observed: "100%", gate: ">= 98%" }],
      },
      cancellationIpc: {
        status: "measured",
        attempts: 12,
        validSamples: 12,
        clickToIdle: { samples: 12, p50Ms: 32, p95Ms: 38, maxMs: 42 },
        backendWait: { samples: 12, p50Ms: 3, p95Ms: 4, maxMs: 5 },
        measurement: "Packaged WebView cancellation path.",
      },
      limitations: ["Smoke duration cannot prove long-session stability."],
    };

    const markdown = renderMarkdown(report);
    assert.match(markdown, /Non-formal smoke run/);
    assert.match(markdown, /Capture completeness \| PASS/);
    assert.match(markdown, /WebView Cancellation IPC/);
    assert.match(markdown, /Protocol Matrix/);
    assert.match(markdown, /https \| 150 \| 150 \| 0 \| 12\.00 ms \| 150 HTTPS \/ 150 MITM/);
    assert.match(markdown, /websocket \| 150 \| 150 \| 0 \| 14\.00 ms \| 150 handshakes \/ 300 events/);
    assert.match(markdown, /12 \/ 12/);
    assert.match(markdown, /20\.00 \/ 20\.00 op\/s \(100\.00%\)/);
    assert.match(markdown, /Post-traffic cooldown: 60\.20 seconds/);
    assert.match(markdown, /-8\.48 MiB/);
    assert.match(markdown, /Smoke duration cannot prove/);
  });
});
