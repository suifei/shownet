const encoder = new TextEncoder();
const state = document.querySelector("#state");
const runButton = document.querySelector("#run");
const logList = document.querySelector("#log");
const dragSource = document.querySelector("#drag-source");
const dropTarget = document.querySelector("#drop-target");
const dropStatus = document.querySelector("#drop-status");

const emitLabStatus = (payload) => {
  let delivered = false;
  if (typeof globalThis.__SHOWNET_LAB_BRIDGE__ === "function") {
    try {
      globalThis.__SHOWNET_LAB_BRIDGE__(JSON.stringify(payload));
      delivered = true;
    } catch {}
  }
  if (!delivered && parent === window && typeof globalThis.__SHOWNET_HOOK_BRIDGE__ === "function") {
    try {
      globalThis.__SHOWNET_HOOK_BRIDGE__(JSON.stringify({ type: "shownet-lab-status", payload }));
    } catch {}
  }
  if (parent !== window) parent.postMessage({ type: "shownet-lab-status", ...payload }, location.origin);
};

const base64 = (bytes) => {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary);
};

const hex = (bytes) => [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const log = (message) => {
  const item = document.createElement("li");
  item.textContent = `${new Date().toISOString().slice(11, 23)}  ${message}`;
  logList.append(item);
  logList.scrollTop = logList.scrollHeight;
};

const mark = (step) => document.querySelector(`[data-step="${step}"]`)?.classList.add("is-done");

const updateState = (label, tone) => {
  state.textContent = label;
  state.className = `state state--${tone}`;
};

async function runScenario() {
  runButton.disabled = true;
  document.querySelectorAll("[data-step]").forEach((step) => step.classList.remove("is-done"));
  updateState("运行中", "running");
  emitLabStatus({ phase: "running" });
  try {
    const account = document.querySelector("#account").value.trim();
    const messageText = document.querySelector("#message").value;
    const business = JSON.parse(messageText);
    const plaintext = encoder.encode(JSON.stringify({ account, business, timestamp: Date.now() }));
    log(`构造业务明文 ${plaintext.byteLength} bytes`);

    const digest = await crypto.subtle.digest("SHA-256", plaintext);
    document.querySelector("#digest").textContent = hex(digest);
    mark("digest");
    log("SHA-256 摘要完成");

    const aesKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plaintext);
    document.querySelector("#iv").textContent = hex(iv);
    mark("encrypt");
    log(`AES-GCM 加密完成 ${ciphertext.byteLength} bytes`);

    const signingKey = await crypto.subtle.importKey("raw", digest, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", signingKey, ciphertext);
    const signatureHex = hex(signature);
    document.querySelector("#signature").textContent = signatureHex;
    mark("sign");
    log("HMAC-SHA256 签名完成");

    const nonce = crypto.getRandomValues(new Uint32Array(2)).join("");
    const payload = {
      algorithm: "AES-256-GCM+HMAC-SHA256",
      account,
      digest: hex(digest),
      iv: base64(iv),
      ciphertext: base64(ciphertext),
      signature: signatureHex,
      nonce,
      clientTime: Date.now(),
    };
    const endpoint = document.querySelector("#endpoint").value.trim();
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-shownet-lab": "crypto-v1",
        "x-signature": signatureHex,
        "x-client-nonce": nonce,
      },
      body: JSON.stringify(payload),
      credentials: "omit",
    });
    const responseText = await response.text();
    document.querySelector("#response").textContent = `${response.status} ${response.statusText} · ${responseText.slice(0, 160)}`;
    mark("send");
    log(`HTTPS 请求完成，状态 ${response.status}`);
    updateState("验证完成", "success");
    emitLabStatus({ phase: "complete", status: response.status, endpoint });
  } catch (error) {
    document.querySelector("#response").textContent = String(error);
    log(`失败：${String(error)}`);
    updateState("验证失败", "error");
    emitLabStatus({ phase: "error", message: String(error) });
  } finally {
    runButton.disabled = false;
  }
}

runButton.addEventListener("click", runScenario);
document.querySelector("#clear").addEventListener("click", () => { logList.textContent = ""; });

dragSource.addEventListener("dragstart", (event) => {
  event.dataTransfer.effectAllowed = "copyMove";
  event.dataTransfer.setData("text/plain", "shownet-page-drag");
  dragSource.classList.add("is-dragging");
  dropStatus.textContent = "页面元素拖动中";
});
dragSource.addEventListener("dragend", () => dragSource.classList.remove("is-dragging"));
dropTarget.addEventListener("dragenter", (event) => {
  event.preventDefault();
  dropTarget.classList.add("is-over");
});
dropTarget.addEventListener("dragover", (event) => {
  event.preventDefault();
  event.dataTransfer.dropEffect = "copy";
});
dropTarget.addEventListener("dragleave", (event) => {
  if (!dropTarget.contains(event.relatedTarget)) dropTarget.classList.remove("is-over");
});
dropTarget.addEventListener("drop", (event) => {
  event.preventDefault();
  dropTarget.classList.remove("is-over");
  const files = [...event.dataTransfer.files];
  if (files.length > 0) {
    const names = files.slice(0, 3).map((file) => file.name).join(", ");
    dropStatus.textContent = `${files.length} 个文件 · ${names}`;
    log(`本地文件投放完成：${files.length} 个文件`);
    return;
  }
  const token = event.dataTransfer.getData("text/plain");
  dropStatus.textContent = token === "shownet-page-drag" ? "页面元素拖放完成" : "拖放数据已接收";
  log("页面元素拖放完成");
});

if (new URLSearchParams(location.search).get("autorun") === "1") window.setTimeout(runScenario, 500);
