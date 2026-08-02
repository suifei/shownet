import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  createLiveCaptureDisplayController,
  parseLiveCaptureDisplayPreferences,
} from "../src/liveCaptureDisplay.ts";

describe("live capture display controller", () => {
  it("freezes only visible updates and clears pending counts after a successful sync", () => {
    const controller = createLiveCaptureDisplayController({ autoProtection: false });
    controller.recordCreated(0);
    controller.pause("manual", 100);
    controller.recordCreated(150);
    controller.recordUpdated();
    controller.recordUpdated();

    const paused = controller.snapshot(200);
    assert.equal(paused.paused, true);
    assert.equal(paused.pauseReason, "manual");
    assert.equal(paused.pendingCreated, 1);
    assert.equal(paused.pendingUpdated, 2);
    assert.equal(paused.pendingChanges, 3);

    assert.equal(controller.startSync(250).syncing, true);
    const resumed = controller.finishSync(300);
    assert.equal(resumed.paused, false);
    assert.equal(resumed.syncing, false);
    assert.equal(resumed.pendingChanges, 0);
  });

  it("automatically protects the UI only after a sustained high request rate", () => {
    const controller = createLiveCaptureDisplayController({
      autoProtection: true,
      rateThreshold: 2,
      sustainMs: 1_000,
      rateWindowMs: 2_000,
    });
    [0, 100, 200].forEach((time) => controller.recordCreated(time));
    assert.equal(controller.tick(200).paused, false);
    [700, 800, 900].forEach((time) => controller.recordCreated(time));
    assert.equal(controller.tick(1_199).paused, false);

    const protectedSnapshot = controller.tick(1_200);
    assert.equal(protectedSnapshot.paused, true);
    assert.equal(protectedSnapshot.pauseReason, "automatic");
    assert.ok(protectedSnapshot.ratePerSecond >= 2);
  });

  it("lets users disable automatic protection without disabling rate measurement", () => {
    const controller = createLiveCaptureDisplayController({
      autoProtection: false,
      rateThreshold: 1,
      sustainMs: 0,
    });
    controller.recordCreated(100);
    const disabled = controller.tick(100);
    assert.equal(disabled.paused, false);
    assert.equal(disabled.ratePerSecond, 1);

    controller.setAutoProtection(true, 100);
    const enabled = controller.tick(100);
    assert.equal(enabled.paused, true);
    assert.equal(enabled.pauseReason, "automatic");
  });

  it("restores only valid versioned preferences", () => {
    assert.deepEqual(parseLiveCaptureDisplayPreferences(null), { version: 1, autoProtection: true });
    assert.deepEqual(parseLiveCaptureDisplayPreferences("broken"), { version: 1, autoProtection: true });
    assert.deepEqual(parseLiveCaptureDisplayPreferences('{"version":0,"autoProtection":false}'), { version: 1, autoProtection: true });
    assert.deepEqual(parseLiveCaptureDisplayPreferences('{"version":1,"autoProtection":false}'), { version: 1, autoProtection: false });
  });
});
