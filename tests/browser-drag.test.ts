import assert from "node:assert/strict";
import test from "node:test";
import {
  MAX_BROWSER_DROP_FILES,
  buildCdpFileDragData,
  isShownetSessionPath,
  mapScreencastPoint,
} from "../src/browserDrag.ts";

test("maps client coordinates through screencast letterboxing", () => {
  const frame = { width: 800, height: 600 };
  const bounds = { left: 10, top: 20, width: 1000, height: 600 };

  assert.deepEqual(mapScreencastPoint(510, 320, bounds, frame), { x: 400, y: 300 });
  assert.equal(mapScreencastPoint(20, 320, bounds, frame), null);
  assert.deepEqual(mapScreencastPoint(20, 320, bounds, frame, true), { x: 0, y: 300 });
});

test("constructs bounded copy-only CDP file drag data", () => {
  const paths = Array.from({ length: MAX_BROWSER_DROP_FILES + 5 }, (_, index) => `/tmp/file-${index}.txt`);
  paths.push("/tmp/file-0.txt", "/tmp/archive.shownet", "");
  const data = buildCdpFileDragData(paths);

  assert.equal(data.files.length, MAX_BROWSER_DROP_FILES);
  assert.equal(new Set(data.files).size, data.files.length);
  assert.equal(data.dragOperationsMask, 1);
  assert.deepEqual(data.items, []);
  assert.equal(data.files.some(isShownetSessionPath), false);
  assert.equal(isShownetSessionPath("/tmp/ARCHIVE.SHOWNET"), true);
});
