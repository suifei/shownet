/**
 * Setup readiness drives the first-run guide and the topbar nudge, so its
 * verdict has to stay honest: optional work must never block "ready", and a
 * step whose prerequisite is missing must read as blocked rather than todo.
 */
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";

import {
  buildSetupSteps,
  SETUP_DISMISSED_KEY,
  setupProgress,
  shouldAutoOpenSetup,
  type SetupSignals,
} from "../src/setupChecklist.ts";

const cold: SetupSignals = {
  capturing: false,
  requestCount: 0,
  caInstalled: false,
  aiConfigured: false,
  sourceCount: 0,
};

describe("setup checklist", () => {
  it("covers the four things that decide whether the app can work", () => {
    assert.deepEqual(buildSetupSteps(cold).map((step) => step.id), ["capture", "source", "certificate", "ai"]);
  });

  it("treats certificate and AI as optional so a browser-only user is ready", () => {
    const steps = buildSetupSteps({ ...cold, capturing: true, requestCount: 12, sourceCount: 1 });
    const progress = setupProgress(steps);

    assert.equal(progress.ready, true, "capture + traffic is enough to be usable");
    assert.equal(progress.complete, false, "optional steps are still outstanding");
    assert.equal(progress.done, 2);
    assert.equal(progress.total, 2);
  });

  it("blocks the source step until capture is running", () => {
    const blocked = buildSetupSteps(cold).find((step) => step.id === "source");
    assert.equal(blocked?.state, "blocked");

    const pending = buildSetupSteps({ ...cold, capturing: true }).find((step) => step.id === "source");
    assert.equal(pending?.state, "pending");
  });

  it("marks the source step done once traffic actually arrived", () => {
    const step = buildSetupSteps({ ...cold, capturing: true, requestCount: 3, sourceCount: 2 })
      .find((entry) => entry.id === "source");
    assert.equal(step?.state, "done");
    assert.match(step?.summary ?? "", /3 条请求/);
    assert.match(step?.summary ?? "", /2 个来源/);
  });

  it("never suggests a blocked step as the next move", () => {
    const progress = setupProgress(buildSetupSteps(cold));
    assert.equal(progress.next?.id, "capture", "the unblocking step is what to do next");
  });

  it("falls through to an optional step once the required ones are done", () => {
    const progress = setupProgress(buildSetupSteps({ ...cold, capturing: true, requestCount: 1 }));
    assert.equal(progress.ready, true);
    assert.equal(progress.next?.id, "certificate");
  });

  it("reports complete only when the optional steps are done too", () => {
    const progress = setupProgress(buildSetupSteps({
      capturing: true,
      requestCount: 5,
      caInstalled: true,
      aiConfigured: true,
      sourceCount: 1,
    }));
    assert.equal(progress.complete, true);
    assert.equal(progress.next, undefined);
  });

  it("counts a local model as configured AI, with no API key", () => {
    const step = buildSetupSteps({ ...cold, aiConfigured: true }).find((entry) => entry.id === "ai");
    assert.equal(step?.state, "done");
  });

  it("auto-opens only for a fresh install that is not yet ready", () => {
    const notReady = setupProgress(buildSetupSteps(cold));
    const ready = setupProgress(buildSetupSteps({ ...cold, capturing: true, requestCount: 1 }));

    assert.equal(shouldAutoOpenSetup(notReady, false), true);
    assert.equal(shouldAutoOpenSetup(notReady, true), false, "a dismissal is permanent");
    assert.equal(shouldAutoOpenSetup(ready, false), false, "no nagging once capture works");
  });

  it("never offers to undo a completed step", () => {
    // This panel puts the biggest button on screen next to each step; a running
    // capture must not be one click from being stopped here.
    const step = buildSetupSteps({ ...cold, capturing: true }).find((entry) => entry.id === "capture");
    assert.equal(step?.state, "done");
    assert.doesNotMatch(step?.actionLabel ?? "", /停止/);
  });

  it("gives every unfinished step a concrete next move", () => {
    for (const step of buildSetupSteps(cold)) {
      assert.ok(step.hint.length > 0, `${step.id} needs a hint`);
      assert.ok(step.actionLabel.length > 0, `${step.id} needs an action label`);
    }
  });
});

describe("setup guide wiring", () => {
  it("is reachable from the topbar, the palette and the keyboard", async () => {
    const [app, guide, styles] = await Promise.all([
      readFile(new URL("../src/App.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/components/SetupGuide.tsx", import.meta.url), "utf8"),
      readFile(new URL("../src/styles.css", import.meta.url), "utf8"),
    ]);

    assert.match(app, /className="setup-pill"/);
    assert.match(app, /id: "setup-guide"/);
    assert.match(app, /<SetupGuide/);
    assert.match(app, /setSetupOpen\(false\)/);
    assert.match(guide, /role="dialog"/);
    assert.match(guide, /onDismissForever/);
    assert.match(styles, /\.setup-guide__steps/);
    assert.match(styles, /\.setup-pill/);
  });

  it("routes each step to the place that resolves it", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.match(app, /const runSetupStep = \(id: SetupStepId\)/);
    assert.match(app, /if \(capturing\) openSettingsTab\("capture"\);/);
    assert.match(app, /openSettingsTab\(id === "certificate" \? "capture" : "ai"\)/);
  });

  it("persists the dismissal under a versioned key", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
    assert.equal(SETUP_DISMISSED_KEY, "shownet.setup-guide.dismissed.v1");
    assert.match(app, /localStorage\?\.setItem\(SETUP_DISMISSED_KEY, "1"\)/);
  });
});
