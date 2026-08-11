import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { readFile } from "node:fs/promises";
import { ensureCaptureSession } from "../src/captureSession.ts";

describe("capture session startup", () => {
  it("reuses the active session without creating another one", async () => {
    let createCalls = 0;
    const result = await ensureCaptureSession("session-existing", async () => {
      createCalls += 1;
      return { id: "session-new" };
    });

    assert.deepEqual(result, { sessionId: "session-existing", created: false });
    assert.equal(createCalls, 0);
  });

  it("creates a session when capture starts from an empty session list", async () => {
    const result = await ensureCaptureSession("", async () => ({ id: "session-new" }));

    assert.deepEqual(result, { sessionId: "session-new", created: true });
  });

  it("does not attempt capture when automatic session creation fails", async () => {
    const result = await ensureCaptureSession("", async () => null);

    assert.equal(result, null);
  });

  it("uses the resolved session id in the application capture transition", async () => {
    const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");

    assert.match(app, /await ensureCaptureSession\(activeSession\.id/);
    assert.match(app, /sessionId:\s*next \? sessionId : null/);
    assert.match(app, /已自动创建会话并开始抓包/);
    assert.doesNotMatch(app, /id: "capture-toggle"[\s\S]{0,500}disabled: !activeSession\.id/);
    assert.match(app, /id: "session-new"[\s\S]{0,500}disabled: captureTransitioning/);
  });
});
