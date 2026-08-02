import assert from "node:assert/strict";
import path from "node:path";

const debugPort = Number(process.argv[2]);
if (!Number.isInteger(debugPort) || debugPort < 1 || debugPort > 65535) {
  throw new Error("Usage: node scripts/probe-browser-drag.mjs <debug-port>");
}

const targets = await fetch(`http://127.0.0.1:${debugPort}/json/list`).then((response) => response.json());
const target = targets.find((item) => item.type === "page" && item.webSocketDebuggerUrl);
if (!target) throw new Error("No debuggable page target found");

const socket = new WebSocket(target.webSocketDebuggerUrl);
const pending = new Map();
let nextId = 0;

await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", () => reject(new Error("CDP WebSocket connection failed")), { once: true });
});

socket.addEventListener("message", (event) => {
  const packet = JSON.parse(String(event.data));
  if (!packet.id || !pending.has(packet.id)) return;
  const { resolve, reject } = pending.get(packet.id);
  pending.delete(packet.id);
  if (packet.error) reject(new Error(`${packet.error.code}: ${packet.error.message}`));
  else resolve(packet.result ?? {});
});

const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++nextId;
  pending.set(id, { resolve, reject });
  socket.send(JSON.stringify({ id, method, params }));
});

const evaluate = async (expression) => {
  const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(result.exceptionDetails.text || "Runtime evaluation failed");
  return result.result?.value;
};

await send("Input.dispatchKeyEvent", { type: "rawKeyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });
await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27 });

const geometry = await evaluate(`(() => {
  const source = document.querySelector("#drag-source").getBoundingClientRect();
  const target = document.querySelector("#drop-target").getBoundingClientRect();
  document.querySelector("#drop-status").textContent = "等待事件";
  document.querySelector("#drag-source").classList.remove("is-dragging");
  document.querySelector("#drop-target").classList.remove("is-over");
  return {
    source: { x: source.x + source.width / 2, y: source.y + source.height / 2 },
    target: { x: target.x + target.width / 2, y: target.y + target.height / 2 },
  };
})()`);

await send("Input.dispatchMouseEvent", { type: "mousePressed", ...geometry.source, button: "left", buttons: 1, clickCount: 1 });
for (let step = 1; step <= 12; step += 1) {
  const progress = step / 12;
  await send("Input.dispatchMouseEvent", {
    type: "mouseMoved",
    x: geometry.source.x + (geometry.target.x - geometry.source.x) * progress,
    y: geometry.source.y + (geometry.target.y - geometry.source.y) * progress,
    button: "left",
    buttons: 1,
  });
  await new Promise((resolve) => setTimeout(resolve, 12));
}
await send("Input.dispatchMouseEvent", { type: "mouseReleased", ...geometry.target, button: "left", buttons: 0, clickCount: 1 });

const pageDrag = await evaluate(`(() => ({
  status: document.querySelector("#drop-status").textContent,
  dragging: document.querySelector("#drag-source").classList.contains("is-dragging"),
}))()`);
assert.equal(pageDrag.status, "页面元素拖放完成");
assert.equal(pageDrag.dragging, false);

const filePath = path.resolve("package.json");
const data = { items: [], files: [filePath], dragOperationsMask: 1 };
await send("Input.dispatchDragEvent", { type: "dragEnter", ...geometry.target, data });
await send("Input.dispatchDragEvent", { type: "dragOver", ...geometry.target, data });
await send("Input.dispatchDragEvent", { type: "drop", ...geometry.target, data });

const fileDropStatus = await evaluate('document.querySelector("#drop-status").textContent');
assert.match(fileDropStatus, /^1 个文件 · package\.json$/);
socket.close();

console.log(JSON.stringify({ pageDrag, fileDropStatus }, null, 2));
