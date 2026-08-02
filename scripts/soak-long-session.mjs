import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { Agent, createServer as createHttpServer, request as httpRequest } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as netConnect } from "node:net";
import { cpus, freemem, platform, release, totalmem } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import process from "node:process";
import { performance } from "node:perf_hooks";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultAppBinary = resolve(
  root,
  "src-tauri/target/release/bundle/macos/ShowNet.app/Contents/MacOS/shownet",
);
const supportedProtocols = ["http", "https", "websocket", "sse"];

export function parseProtocols(value) {
  const requested = String(value).trim().toLowerCase();
  const protocols = requested === "all"
    ? [...supportedProtocols]
    : requested.split(",").map((item) => item.trim()).filter(Boolean);
  if (!protocols.length) throw new Error("--protocols must include at least one protocol");
  const invalid = protocols.filter((protocol) => !supportedProtocols.includes(protocol));
  if (invalid.length) {
    throw new Error(`--protocols supports only ${supportedProtocols.join(", ")}; received ${invalid.join(", ")}`);
  }
  return [...new Set(protocols)];
}

export function protocolForIndex(protocols, index) {
  if (!protocols.length || !Number.isInteger(index) || index < 1) {
    throw new Error("protocol selection requires a non-empty matrix and a positive index");
  }
  return protocols[(index - 1) % protocols.length];
}

export function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help" || token === "-h") return { help: true };
    if (!token.startsWith("--")) throw new Error(`Unknown argument: ${token}`);
    const [name, inlineValue] = token.slice(2).split("=", 2);
    const value = inlineValue ?? argv[++index];
    if (value == null || value.startsWith("--")) throw new Error(`Missing value for --${name}`);
    values.set(name, value);
  }
  const mode = values.get("mode") ?? "smoke";
  if (!new Set(["smoke", "long"]).has(mode)) throw new Error("--mode must be smoke or long");
  const durationSeconds = positiveNumber(
    values.get("duration-seconds") ?? (mode === "long" ? "1800" : "30"),
    "duration-seconds",
    5,
    3600,
  );
  return {
    help: false,
    mode,
    durationSeconds,
    rate: positiveNumber(values.get("rate") ?? "20", "rate", 1, 500),
    concurrency: positiveInteger(values.get("concurrency") ?? "8", "concurrency", 1, 100),
    protocols: parseProtocols(values.get("protocols") ?? "http"),
    warmupSeconds: positiveNumber(values.get("warmup-seconds") ?? "10", "warmup-seconds", 0, 120),
    cooldownSeconds: positiveNumber(
      values.get("cooldown-seconds") ?? (mode === "long" ? "60" : "0"),
      "cooldown-seconds",
      0,
      300,
    ),
    minimumRateUtilization: positiveNumber(
      values.get("minimum-rate-utilization") ?? "0.8",
      "minimum-rate-utilization",
      0.1,
      1,
    ),
    sampleSeconds: positiveNumber(values.get("sample-seconds") ?? "5", "sample-seconds", 1, 60),
    readyTimeoutSeconds: positiveNumber(
      values.get("ready-timeout-seconds") ?? "45",
      "ready-timeout-seconds",
      5,
      180,
    ),
    appBinary: resolve(values.get("app") ?? defaultAppBinary),
    outputDirectory: resolve(values.get("output") ?? resolve(root, "output")),
  };
}

function positiveNumber(value, name, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`--${name} must be between ${minimum} and ${maximum}`);
  }
  return parsed;
}

function positiveInteger(value, name, minimum, maximum) {
  const parsed = positiveNumber(value, name, minimum, maximum);
  if (!Number.isInteger(parsed)) throw new Error(`--${name} must be an integer`);
  return parsed;
}

export function percentile(values, percentileValue) {
  if (!values.length) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const index = Math.min(
    ordered.length - 1,
    Math.max(0, Math.ceil((percentileValue / 100) * ordered.length) - 1),
  );
  return ordered[index];
}

export function summarizeLoadRate(attempted, durationSeconds, dispatchCeilingPerSecond) {
  const realizedRatePerSecond = durationSeconds > 0 ? attempted / durationSeconds : 0;
  const rateUtilization = dispatchCeilingPerSecond > 0
    ? realizedRatePerSecond / dispatchCeilingPerSecond
    : 0;
  return {
    realizedRatePerSecond: round(realizedRatePerSecond),
    dispatchCeilingPerSecond,
    rateUtilization: round(rateUtilization, 4),
  };
}

export function loadUtilizationGate(loadRate, minimumRateUtilization) {
  return {
    name: "Dispatch ceiling utilization",
    pass: loadRate.rateUtilization >= minimumRateUtilization,
    observed: `${(loadRate.rateUtilization * 100).toFixed(2)}% (${loadRate.realizedRatePerSecond.toFixed(2)} / ${loadRate.dispatchCeilingPerSecond.toFixed(2)} op/s)`,
    gate: `>= ${(minimumRateUtilization * 100).toFixed(0)}%`,
  };
}

function summarizeDurations(values) {
  return {
    samples: values.length,
    p50Ms: round(percentile(values, 50)),
    p95Ms: round(percentile(values, 95)),
    maxMs: round(values.length ? Math.max(...values) : null),
  };
}

function round(value, digits = 2) {
  if (value == null || !Number.isFinite(value)) return null;
  return Number(value.toFixed(digits));
}

function formatBytes(bytes) {
  if (bytes == null) return "n/a";
  const units = ["B", "KiB", "MiB", "GiB"];
  const sign = bytes < 0 ? "-" : "";
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${sign}${value.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}

function formatMs(value) {
  return value == null ? "n/a" : `${value.toFixed(2)} ms`;
}

function markdownStatus(value) {
  return value ? "PASS" : "FAIL";
}

export function renderMarkdown(report) {
  const formalLabel = report.formalEligibility.eligible
    ? "Formal 30-60 minute release soak"
    : `Non-formal ${report.config.mode} run`;
  const checks = report.gates.checks
    .map((check) => `| ${check.name} | ${markdownStatus(check.pass)} | ${check.observed} | ${check.gate} |`)
    .join("\n");
  const cancellation = report.cancellationIpc ?? { status: "not-measured", attempts: 0, validSamples: 0 };
  const selectedProtocols = report.protocolMatrix?.selected ?? report.config.protocols ?? [];
  const protocolRows = selectedProtocols.map((protocol) => {
    const traffic = report.protocolMatrix?.traffic?.[protocol] ?? {};
    const capture = report.protocolMatrix?.capture?.[protocol] ?? {};
    const evidence = protocol === "https"
      ? `${capture.requests ?? 0} HTTPS / ${capture.mitmRequests ?? 0} MITM`
      : protocol === "websocket"
        ? `${capture.requests ?? 0} handshakes / ${capture.events ?? 0} events`
        : protocol === "sse"
          ? `${capture.completedRequests ?? 0} complete / ${capture.events ?? 0} events`
          : `${capture.requests ?? 0} HTTP rows`;
    return `| ${protocol} | ${traffic.attempted ?? 0} | ${traffic.completed ?? 0} | ${traffic.failed ?? 0} | ${formatMs(traffic.latency?.p95Ms)} | ${evidence} |`;
  }).join("\n");
  const protocolSection = selectedProtocols.length
    ? `## Protocol Matrix\n\n| Protocol | Attempted | Completed | Failed | Latency P95 | Captured evidence |\n| --- | ---: | ---: | ---: | ---: | --- |\n${protocolRows}\n\n`
    : "";
  const loadRate = report.traffic.loadRate;
  const loadRateRow = loadRate
    ? `| Realized / ceiling operation rate | ${loadRate.realizedRatePerSecond.toFixed(2)} / ${loadRate.dispatchCeilingPerSecond.toFixed(2)} op/s (${(loadRate.rateUtilization * 100).toFixed(2)}%) |\n`
    : "";
  const cooldown = report.cooldown;
  const cooldownLine = cooldown?.requestedSeconds > 0
    ? `Post-traffic cooldown: ${cooldown.actualSeconds.toFixed(2)} seconds. `
      + `WebView ${formatBytes(cooldown.webview.trafficEndBytes)} -> ${formatBytes(cooldown.webview.endBytes)} `
      + `(${formatBytes(cooldown.webview.deltaBytes)}); process tree `
      + `${formatBytes(cooldown.tree.trafficEndBytes)} -> ${formatBytes(cooldown.tree.endBytes)} `
      + `(${formatBytes(cooldown.tree.deltaBytes)}).\n\n`
    : "";
  return `# ShowNet Release Long-Session Soak\n\n` +
    `- Run: \`${report.runId}\`\n` +
    `- Classification: **${formalLabel}**\n` +
    `- Artifact: \`${report.artifact.path}\`\n` +
    `- Duration: ${report.traffic.actualDurationSeconds.toFixed(2)} seconds\n` +
    `- Overall gate: **${markdownStatus(report.gates.passed)}**\n\n` +
    `## Capture\n\n` +
    `| Metric | Result |\n| --- | ---: |\n` +
    `| Attempted requests | ${report.traffic.attempted} |\n` +
    `| Completed responses | ${report.traffic.completed} |\n` +
    `| Transport failures | ${report.traffic.failed} |\n` +
    `| Captured application requests | ${report.capture.requestCount} |\n` +
    `| Captured CONNECT tunnel rows | ${report.capture.connectCount ?? 0} |\n` +
    `| Total database request rows | ${report.capture.totalRows ?? report.capture.requestCount} |\n` +
    `| Capture ratio | ${(report.capture.ratio * 100).toFixed(2)}% |\n` +
    loadRateRow +
    `| Traffic latency P50 / P95 / max | ${formatMs(report.traffic.latency.p50Ms)} / ${formatMs(report.traffic.latency.p95Ms)} / ${formatMs(report.traffic.latency.maxMs)} |\n\n` +
    protocolSection +
    `## Resource And Storage\n\n` +
    `| Metric | Start | Peak / End | Growth |\n| --- | ---: | ---: | ---: |\n` +
    `| Main process RSS | ${formatBytes(report.resources.main.startBytes)} | ${formatBytes(report.resources.main.peakBytes)} / ${formatBytes(report.resources.main.endBytes)} | ${formatBytes(report.resources.main.growthBytes)} |\n` +
    `| WebView RSS | ${formatBytes(report.resources.webview.startBytes)} | ${formatBytes(report.resources.webview.peakBytes)} / ${formatBytes(report.resources.webview.endBytes)} | ${formatBytes(report.resources.webview.growthBytes)} |\n` +
    `| GPU/network helper RSS | ${formatBytes(report.resources.helper.startBytes)} | ${formatBytes(report.resources.helper.peakBytes)} / ${formatBytes(report.resources.helper.endBytes)} | ${formatBytes(report.resources.helper.growthBytes)} |\n` +
    `| Process-tree RSS | ${formatBytes(report.resources.tree.startBytes)} | ${formatBytes(report.resources.tree.peakBytes)} / ${formatBytes(report.resources.tree.endBytes)} | ${formatBytes(report.resources.tree.growthBytes)} |\n` +
    `| SQLite + WAL + SHM | ${formatBytes(report.storage.startPhysicalBytes)} | ${formatBytes(report.storage.endPhysicalBytes)} | ${formatBytes(report.storage.growthBytes)} |\n\n` +
    cooldownLine +
    `Window query probe: P50 ${formatMs(report.queryWindow.p50Ms)}, P95 ${formatMs(report.queryWindow.p95Ms)}, max ${formatMs(report.queryWindow.maxMs)} across ${report.queryWindow.samples} samples.\n\n` +
    `## WebView Cancellation IPC\n\n` +
    `| Metric | Result |\n| --- | ---: |\n` +
    `| Status | ${cancellation.status} |\n` +
    `| Valid samples / attempts | ${cancellation.validSamples ?? 0} / ${cancellation.attempts ?? 0} |\n` +
    `| Click-to-idle P50 / P95 / max | ${formatMs(cancellation.clickToIdle?.p50Ms)} / ${formatMs(cancellation.clickToIdle?.p95Ms)} / ${formatMs(cancellation.clickToIdle?.maxMs)} |\n` +
    `| Backend wait P50 / P95 / max | ${formatMs(cancellation.backendWait?.p50Ms)} / ${formatMs(cancellation.backendWait?.p95Ms)} / ${formatMs(cancellation.backendWait?.maxMs)} |\n\n` +
    `${cancellation.measurement ?? cancellation.reason ?? "No cancellation measurement metadata was recorded."}\n\n` +
    `## Gates\n\n| Gate | Result | Observed | Required |\n| --- | --- | --- | --- |\n${checks}\n\n` +
    `## Limitations\n\n${report.limitations.map((item) => `- ${item}`).join("\n")}\n`;
}

function usage() {
  return `Usage: npm run soak:long-session -- [options]\n\n` +
    `  --mode smoke|long             smoke defaults to 30s; long defaults to 1800s\n` +
    `  --duration-seconds <5-3600>  explicit run duration\n` +
    `  --rate <1-500>               requests per second (default 20)\n` +
    `  --concurrency <1-100>        maximum in-flight requests (default 8)\n` +
    `  --protocols <list|all>       http, https, websocket and/or sse (default http)\n` +
    `  --warmup-seconds <0-120>     settle WebView before the RSS baseline (default 10)\n` +
    `  --cooldown-seconds <0-300>   sample recovery after traffic (long default 60)\n` +
    `  --minimum-rate-utilization <0.1-1> formal dispatch gate (default 0.8)\n` +
    `  --sample-seconds <1-60>      resource/database sample interval (default 5)\n` +
    `  --app <path>                 release ShowNet executable\n` +
    `  --output <directory>         report root (default output/)\n`;
}

function delay(milliseconds) {
  return new Promise((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function reserveLoopbackPort() {
  const server = createHttpServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  if (!port) throw new Error("Could not reserve a loopback port");
  return port;
}

async function generateProtocolCertificates(runDirectory) {
  const fixtureDirectory = resolve(runDirectory, "protocol-fixture");
  await mkdir(fixtureDirectory, { recursive: true });
  const rootConfig = resolve(fixtureDirectory, "root.cnf");
  const leafConfig = resolve(fixtureDirectory, "leaf.cnf");
  const rootKey = resolve(fixtureDirectory, "root.key");
  const rootCertificate = resolve(fixtureDirectory, "root.pem");
  const leafKey = resolve(fixtureDirectory, "localhost.key");
  const leafRequest = resolve(fixtureDirectory, "localhost.csr");
  const leafCertificate = resolve(fixtureDirectory, "localhost.pem");
  await Promise.all([
    writeFile(rootConfig, `[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = v3_ca\n[dn]\nCN = ShowNet Release Soak Root\n[v3_ca]\nbasicConstraints = critical,CA:true\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\n`),
    writeFile(leafConfig, `[req]\nprompt = no\ndistinguished_name = dn\nreq_extensions = v3_req\n[dn]\nCN = localhost\n[v3_req]\nsubjectAltName = @alt_names\n[server_cert]\nbasicConstraints = critical,CA:false\nkeyUsage = critical,digitalSignature,keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n[alt_names]\nDNS.1 = localhost\nIP.1 = 127.0.0.1\n`),
  ]);
  await runCommand("/usr/bin/openssl", [
    "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-config", rootConfig, "-days", "2", "-sha256", "-keyout", rootKey, "-out", rootCertificate,
  ]);
  await runCommand("/usr/bin/openssl", [
    "req", "-new", "-newkey", "rsa:2048", "-nodes",
    "-config", leafConfig, "-keyout", leafKey, "-out", leafRequest,
  ]);
  await runCommand("/usr/bin/openssl", [
    "x509", "-req", "-in", leafRequest, "-CA", rootCertificate, "-CAkey", rootKey,
    "-CAcreateserial", "-out", leafCertificate, "-days", "2", "-sha256",
    "-extfile", leafConfig, "-extensions", "server_cert",
  ]);
  return { rootCertificate, leafCertificate, leafKey };
}

function targetMetrics() {
  return {
    requestCount: 0,
    byProtocol: Object.fromEntries(supportedProtocols.map((protocol) => [protocol, 0])),
    websocketFrames: 0,
    sseEvents: 0,
  };
}

function recordTargetRequest(metrics, protocol) {
  metrics.requestCount += 1;
  metrics.byProtocol[protocol] += 1;
  return metrics.requestCount;
}

function encodeWebSocketFrame(payload, { masked = false, opcode = 0x1 } = {}) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(String(payload));
  if (body.length > 125) throw new Error("Release soak WebSocket payload exceeds 125 bytes");
  const mask = masked ? randomBytes(4) : null;
  const header = Buffer.from([0x80 | opcode, (masked ? 0x80 : 0) | body.length]);
  if (!mask) return Buffer.concat([header, body]);
  const encoded = Buffer.alloc(body.length);
  for (let index = 0; index < body.length; index += 1) encoded[index] = body[index] ^ mask[index % 4];
  return Buffer.concat([header, mask, encoded]);
}

function decodeWebSocketFrames(input) {
  const frames = [];
  let offset = 0;
  while (input.length - offset >= 2) {
    const first = input[offset];
    const second = input[offset + 1];
    let length = second & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (input.length - offset < 4) break;
      length = input.readUInt16BE(offset + 2);
      headerLength = 4;
    } else if (length === 127) {
      throw new Error("Release soak WebSocket frame is unexpectedly large");
    }
    const masked = (second & 0x80) !== 0;
    const maskLength = masked ? 4 : 0;
    const frameLength = headerLength + maskLength + length;
    if (input.length - offset < frameLength) break;
    const maskOffset = offset + headerLength;
    const payloadOffset = maskOffset + maskLength;
    const payload = Buffer.from(input.subarray(payloadOffset, payloadOffset + length));
    if (masked) {
      const mask = input.subarray(maskOffset, maskOffset + 4);
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    frames.push({ opcode: first & 0x0f, payload });
    offset += frameLength;
  }
  return { frames, remaining: input.subarray(offset) };
}

function attachWebSocketTarget(server, metrics) {
  server.on("upgrade", (request, socket, head) => {
    const path = new URL(request.url ?? "/", "http://localhost").pathname;
    const key = request.headers["sec-websocket-key"];
    if (!path.startsWith("/soak/websocket/") || typeof key !== "string") {
      socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n");
      return;
    }
    recordTargetRequest(metrics, "websocket");
    const accept = createHash("sha1")
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest("base64");
    socket.write(
      `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    let pending = head;
    let replied = false;
    const consume = (chunk) => {
      pending = Buffer.concat([pending, chunk]);
      const decoded = decodeWebSocketFrames(pending);
      pending = decoded.remaining;
      for (const frame of decoded.frames) {
        if (frame.opcode === 0x1 && !replied) {
          replied = true;
          metrics.websocketFrames += 1;
          const reply = encodeWebSocketFrame(`echo:${frame.payload.toString("utf8")}`);
          metrics.websocketFrames += 1;
          socket.write(Buffer.concat([reply, encodeWebSocketFrame(Buffer.alloc(0), { opcode: 0x8 })]));
          setTimeout(() => socket.end(), 10);
        } else if (frame.opcode === 0x8) {
          socket.end();
        }
      }
    };
    socket.on("data", consume);
    socket.setTimeout(15_000, () => socket.destroy(new Error("target websocket timed out")));
    if (head.length) consume(Buffer.alloc(0));
  });
}

function targetRequestHandler(metrics, transport) {
  return (request, response) => {
    const path = new URL(request.url ?? "/", `${transport}://localhost`).pathname;
    if (path.startsWith("/soak/sse/")) {
      const sequence = recordTargetRequest(metrics, "sse");
      response.writeHead(200, {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-cache",
        connection: "close",
        "x-shownet-soak-target": "local-sse",
      });
      let event = 0;
      const timer = setInterval(() => {
        event += 1;
        metrics.sseEvents += 1;
        response.write(`id: ${sequence}-${event}\nevent: tick\ndata: {"sequence":${sequence},"event":${event}}\n\n`);
        if (event === 3) {
          clearInterval(timer);
          response.end();
        }
      }, 8);
      response.once("close", () => clearInterval(timer));
      return;
    }
    let requestBytes = 0;
    request.on("data", (chunk) => { requestBytes += chunk.length; });
    request.on("end", () => {
      const sequence = recordTargetRequest(metrics, transport);
      const status = sequence % 50 === 0 ? 503 : request.method === "POST" ? 201 : 200;
      const evidence = JSON.stringify({
        request: sequence,
        protocol: transport,
        method: request.method,
        path: request.url,
        requestBytes,
      });
      const body = `${evidence}\n${"shownet-soak-response".repeat(96)}`;
      response.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "content-length": Buffer.byteLength(body),
        "x-shownet-soak-target": `local-${transport}`,
      });
      response.end(body);
    });
  };
}

async function listenTarget(server) {
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  if (typeof address !== "object" || !address) throw new Error("Local protocol target did not bind");
  return address.port;
}

async function closeTarget(server) {
  if (!server) return;
  await new Promise((resolveClose) => server.close(() => resolveClose()));
}

async function startProtocolTargets(runDirectory, protocols) {
  const metrics = targetMetrics();
  let httpServer;
  let httpsServer;
  let certificates;
  if (protocols.some((protocol) => protocol !== "https")) {
    httpServer = createHttpServer(targetRequestHandler(metrics, "http"));
    attachWebSocketTarget(httpServer, metrics);
  }
  if (protocols.includes("https")) {
    certificates = await generateProtocolCertificates(runDirectory);
    httpsServer = createHttpsServer({
      key: await readFile(certificates.leafKey),
      cert: await readFile(certificates.leafCertificate),
    }, targetRequestHandler(metrics, "https"));
  }
  const httpPort = httpServer ? await listenTarget(httpServer) : null;
  const httpsPort = httpsServer ? await listenTarget(httpsServer) : null;
  return {
    httpPort,
    httpsPort,
    upstreamRootCertificate: certificates?.rootCertificate,
    metrics: () => structuredClone(metrics),
    close: async () => {
      await Promise.all([closeTarget(httpServer), closeTarget(httpsServer)]);
    },
  };
}

function sendHttpThroughProxy({ agent, index, proxyPort, targetPort, protocol }) {
  return new Promise((resolveRequest, reject) => {
    const started = performance.now();
    const isSse = protocol === "sse";
    const method = isSse ? "GET" : index % 5 === 0 ? "POST" : "GET";
    const targetPath = isSse
      ? `/soak/sse/${index}?bucket=${index % 17}`
      : `/soak/http/${index}?bucket=${index % 17}`;
    const absoluteUrl = `http://127.0.0.1:${targetPort}${targetPath}`;
    const body = method === "POST" ? JSON.stringify({ index, source: "release-soak", value: "x".repeat(256) }) : "";
    const request = httpRequest({
      agent,
      hostname: "127.0.0.1",
      port: proxyPort,
      method,
      path: absoluteUrl,
      headers: {
        host: `127.0.0.1:${targetPort}`,
        accept: isSse ? "text/event-stream" : "application/json",
        "user-agent": "ShowNet-Release-Soak/1.0",
        "x-shownet-soak-sequence": String(index),
        ...(body ? {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        } : {}),
      },
    }, (response) => {
      let responseBytes = 0;
      let eventBuffer = "";
      let eventCount = 0;
      response.on("data", (chunk) => {
        responseBytes += chunk.length;
        if (isSse) {
          eventBuffer += chunk.toString("utf8");
          let boundary;
          while ((boundary = eventBuffer.indexOf("\n\n")) >= 0) {
            const event = eventBuffer.slice(0, boundary);
            eventBuffer = eventBuffer.slice(boundary + 2);
            if (event.includes("data:")) eventCount += 1;
          }
        }
      });
      response.on("end", () => resolveRequest({
        status: response.statusCode ?? 0,
        responseBytes,
        eventCount,
        latencyMs: performance.now() - started,
      }));
    });
    request.setTimeout(15_000, () => request.destroy(new Error("proxy request timed out")));
    request.once("error", reject);
    if (body) request.write(body);
    request.end();
  });
}

function connectToProxy(proxyPort) {
  return new Promise((resolveSocket, reject) => {
    const socket = netConnect({ host: "127.0.0.1", port: proxyPort });
    const timer = setTimeout(() => socket.destroy(new Error("proxy connection timed out")), 15_000);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      resolveSocket(socket);
    });
    socket.once("error", reject);
  });
}

function readHttpHead(socket) {
  return new Promise((resolveHead, reject) => {
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => fail(new Error("HTTP handshake timed out")), 15_000);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", fail);
      socket.off("end", onEnd);
    };
    const fail = (error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () => fail(new Error("Connection ended before HTTP headers completed"));
    const onData = (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 64 * 1024) return fail(new Error("HTTP handshake headers exceeded 64 KiB"));
      const boundary = buffer.indexOf("\r\n\r\n");
      if (boundary < 0) return;
      socket.pause();
      cleanup();
      resolveHead({
        head: buffer.subarray(0, boundary + 4).toString("latin1"),
        remainder: buffer.subarray(boundary + 4),
      });
    };
    socket.on("data", onData);
    socket.once("error", fail);
    socket.once("end", onEnd);
    socket.resume();
  });
}

async function sendHttpsThroughProxy({ index, proxyPort, targetPort, proxyCa }) {
  const started = performance.now();
  const socket = await connectToProxy(proxyPort);
  socket.write(
    `CONNECT localhost:${targetPort} HTTP/1.1\r\nHost: localhost:${targetPort}\r\nUser-Agent: ShowNet-Release-Soak/1.0\r\nProxy-Connection: keep-alive\r\n\r\n`,
  );
  const connectResponse = await readHttpHead(socket);
  if (!/^HTTP\/1\.[01] 200\b/.test(connectResponse.head)) {
    socket.destroy();
    throw new Error(`HTTPS proxy CONNECT failed: ${connectResponse.head.split("\r\n", 1)[0]}`);
  }
  if (connectResponse.remainder.length) {
    socket.destroy();
    throw new Error("HTTPS proxy CONNECT returned unexpected tunneled bytes");
  }
  const secureSocket = tlsConnect({
    socket,
    servername: "localhost",
    ca: proxyCa,
    rejectUnauthorized: true,
    ALPNProtocols: ["http/1.1"],
  });
  await new Promise((resolveSecure, reject) => {
    const timer = setTimeout(() => secureSocket.destroy(new Error("proxy TLS handshake timed out")), 15_000);
    secureSocket.once("secureConnect", () => {
      clearTimeout(timer);
      resolveSecure();
    });
    secureSocket.once("error", reject);
  });
  return await new Promise((resolveRequest, reject) => {
    let response = Buffer.alloc(0);
    const timer = setTimeout(() => secureSocket.destroy(new Error("HTTPS request timed out")), 15_000);
    secureSocket.on("data", (chunk) => { response = Buffer.concat([response, chunk]); });
    secureSocket.once("error", reject);
    secureSocket.once("end", () => {
      clearTimeout(timer);
      const status = Number(response.toString("latin1", 0, Math.min(response.length, 64)).match(/^HTTP\/1\.[01] (\d{3})/)?.[1] ?? 0);
      resolveRequest({ status, responseBytes: response.length, latencyMs: performance.now() - started });
    });
    secureSocket.write(
      `GET /soak/https/${index}?bucket=${index % 17} HTTP/1.1\r\nHost: localhost:${targetPort}\r\nAccept: application/json\r\nUser-Agent: ShowNet-Release-Soak/1.0\r\nX-ShowNet-Soak-Sequence: ${index}\r\nConnection: close\r\n\r\n`,
    );
  });
}

async function sendWebSocketThroughProxy({ index, proxyPort, targetPort }) {
  const started = performance.now();
  const socket = await connectToProxy(proxyPort);
  const key = randomBytes(16).toString("base64");
  const path = `/soak/websocket/${index}`;
  socket.write(
    `GET http://127.0.0.1:${targetPort}${path} HTTP/1.1\r\nHost: 127.0.0.1:${targetPort}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: ShowNet-Release-Soak/1.0\r\nX-ShowNet-Soak-Sequence: ${index}\r\n\r\n`,
  );
  const response = await readHttpHead(socket);
  if (!/^HTTP\/1\.[01] 101\b/.test(response.head)) {
    socket.destroy();
    throw new Error(`WebSocket proxy upgrade failed: ${response.head.split("\r\n", 1)[0]}`);
  }
  const expected = `echo:soak-${index}`;
  return await new Promise((resolveRequest, reject) => {
    let pending = response.remainder;
    let responseBytes = response.remainder.length;
    let receivedEcho = false;
    let settled = false;
    const timer = setTimeout(() => socket.destroy(new Error("WebSocket exchange timed out")), 15_000);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", fail);
      socket.off("end", onEnd);
    };
    const finish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      socket.end();
      resolveRequest({ status: 101, responseBytes, frameCount: 2, latencyMs: performance.now() - started });
    };
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onEnd = () => receivedEcho ? finish() : fail(new Error("WebSocket ended before the echo frame"));
    const consume = () => {
      const decoded = decodeWebSocketFrames(pending);
      pending = decoded.remaining;
      for (const frame of decoded.frames) {
        if (frame.opcode === 0x1) {
          if (frame.payload.toString("utf8") !== expected) return fail(new Error("WebSocket echo payload mismatch"));
          receivedEcho = true;
        }
        if (frame.opcode === 0x8 && receivedEcho) return finish();
      }
    };
    const onData = (chunk) => {
      responseBytes += chunk.length;
      pending = Buffer.concat([pending, chunk]);
      consume();
    };
    socket.on("data", onData);
    socket.once("error", fail);
    socket.once("end", onEnd);
    consume();
    socket.write(encodeWebSocketFrame(`soak-${index}`, { masked: true }));
    socket.resume();
  });
}

function sendProtocolRequest({ agent, index, protocol, proxyPort, targets, proxyCa }) {
  switch (protocol) {
    case "http":
    case "sse":
      return sendHttpThroughProxy({ agent, index, protocol, proxyPort, targetPort: targets.httpPort });
    case "https":
      return sendHttpsThroughProxy({ index, proxyPort, proxyCa, targetPort: targets.httpsPort });
    case "websocket":
      return sendWebSocketThroughProxy({ index, proxyPort, targetPort: targets.httpPort });
    default:
      throw new Error(`Unsupported release soak protocol: ${protocol}`);
  }
}

async function runTraffic(config, targets, proxyCa, appState) {
  const agent = new Agent({ keepAlive: true, maxSockets: config.concurrency });
  const started = performance.now();
  const deadline = started + config.durationSeconds * 1000;
  const interval = 1000 / config.rate;
  const inFlight = new Set();
  const latency = [];
  const statuses = {};
  const errors = [];
  const byProtocol = Object.fromEntries(config.protocols.map((protocol) => [protocol, {
    attempted: 0,
    completed: 0,
    failed: 0,
    statuses: {},
    errors: [],
    eventCount: 0,
    frameCount: 0,
    latencyValues: [],
  }]));
  let attempted = 0;
  let completed = 0;
  let failed = 0;
  let nextDispatch = started;

  try {
    while (performance.now() < deadline) {
      if (appState.exited) throw new Error(`ShowNet exited during traffic generation (${appState.exitCode})`);
      if (inFlight.size >= config.concurrency) {
        await Promise.race(inFlight);
        continue;
      }
      const wait = nextDispatch - performance.now();
      if (wait > 1) await delay(wait);
      if (performance.now() >= deadline) break;
      attempted += 1;
      const protocol = protocolForIndex(config.protocols, attempted);
      const protocolStats = byProtocol[protocol];
      protocolStats.attempted += 1;
      const requestPromise = sendProtocolRequest({
        agent,
        index: attempted,
        protocol,
        proxyPort: config.proxyPort,
        targets,
        proxyCa,
      }).then((result) => {
        completed += 1;
        latency.push(result.latencyMs);
        statuses[result.status] = (statuses[result.status] ?? 0) + 1;
        protocolStats.completed += 1;
        protocolStats.latencyValues.push(result.latencyMs);
        protocolStats.statuses[result.status] = (protocolStats.statuses[result.status] ?? 0) + 1;
        protocolStats.eventCount += result.eventCount ?? 0;
        protocolStats.frameCount += result.frameCount ?? 0;
      }).catch((error) => {
        failed += 1;
        if (errors.length < 20) errors.push(String(error));
        protocolStats.failed += 1;
        if (protocolStats.errors.length < 10) protocolStats.errors.push(String(error));
      }).finally(() => inFlight.delete(requestPromise));
      inFlight.add(requestPromise);
      nextDispatch += interval;
      if (nextDispatch < performance.now() - 1000) nextDispatch = performance.now();
    }
    await Promise.allSettled(inFlight);
  } finally {
    agent.destroy();
  }
  return {
    attempted,
    completed,
    failed,
    statuses,
    errors,
    byProtocol: Object.fromEntries(Object.entries(byProtocol).map(([protocol, stats]) => [protocol, {
      attempted: stats.attempted,
      completed: stats.completed,
      failed: stats.failed,
      statuses: stats.statuses,
      errors: stats.errors,
      eventCount: stats.eventCount,
      frameCount: stats.frameCount,
      latency: summarizeDurations(stats.latencyValues),
    }])),
    latency: summarizeDurations(latency),
    actualDurationSeconds: (performance.now() - started) / 1000,
  };
}

function runCommand(command, args, options = {}) {
  return new Promise((resolveCommand, reject) => {
    const child = spawn(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => {
      if (code === 0) resolveCommand(stdout);
      else reject(new Error(`${basename(command)} exited ${code}: ${stderr.trim()}`));
    });
  });
}

async function sqliteJson(databasePath, sql) {
  const stdout = await runCommand("/usr/bin/sqlite3", [
    "-cmd", ".timeout 5000",
    "-json",
    databasePath,
    sql,
  ]);
  return stdout.trim() ? JSON.parse(stdout) : [];
}

function sqlString(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

async function databaseSample(databasePath, sessionId) {
  const files = await Promise.all(["", "-wal", "-shm"].map(async (suffix) => {
    const info = await stat(`${databasePath}${suffix}`).catch(() => null);
    return { suffix: suffix || "database", bytes: info?.size ?? 0 };
  }));
  const rows = await sqliteJson(
    databasePath,
    `SELECT COUNT(*) AS requestCount, COALESCE(SUM(LENGTH(CAST(response_body AS BLOB))), 0) AS responseBodyBytes FROM requests WHERE session_id = ${sqlString(sessionId)};`,
  );
  const protocolRows = await sqliteJson(
    databasePath,
    `SELECT
       SUM(CASE WHEN method <> 'CONNECT' THEN 1 ELSE 0 END) AS applicationRequestCount,
       SUM(CASE WHEN method = 'CONNECT' THEN 1 ELSE 0 END) AS connectCount,
       SUM(CASE WHEN method <> 'CONNECT' AND scheme = 'http' AND resource_type NOT IN ('websocket', 'sse') THEN 1 ELSE 0 END) AS httpCount,
       SUM(CASE WHEN method <> 'CONNECT' AND scheme = 'https' THEN 1 ELSE 0 END) AS httpsCount,
       SUM(CASE WHEN method <> 'CONNECT' AND scheme = 'https' AND tls_version IS NOT NULL AND json_extract(tls_fingerprint_json, '$.captureMode') = 'mitm' THEN 1 ELSE 0 END) AS httpsMitmCount,
       SUM(CASE WHEN resource_type = 'websocket' THEN 1 ELSE 0 END) AS websocketCount,
       SUM(CASE WHEN resource_type = 'sse' THEN 1 ELSE 0 END) AS sseCount,
       SUM(CASE WHEN resource_type = 'sse' AND COALESCE(json_extract(response_body_meta_json, '$.complete'), 0) = 1 THEN 1 ELSE 0 END) AS completedSseCount
     FROM requests WHERE session_id = ${sqlString(sessionId)};`,
  );
  const eventRows = await sqliteJson(
    databasePath,
    `SELECT phase, COUNT(*) AS eventCount, COUNT(DISTINCT request_id) AS requestCount
     FROM capture_events
     WHERE session_id = ${sqlString(sessionId)} AND phase IN ('websocket', 'sse')
     GROUP BY phase;`,
  );
  const requestCount = Number(rows[0]?.requestCount ?? 0);
  const protocolRow = protocolRows[0] ?? {};
  const events = Object.fromEntries(eventRows.map((row) => [row.phase, row]));
  const offset = Math.max(0, requestCount - 500);
  const queryStarted = performance.now();
  const windowRows = await sqliteJson(
    databasePath,
    `SELECT id, sequence, method, host, path, status, size_bytes, duration_ms, protocol, risk_level FROM requests WHERE session_id = ${sqlString(sessionId)} ORDER BY sequence ASC LIMIT 500 OFFSET ${offset};`,
  );
  return {
    timestampMs: Date.now(),
    requestCount,
    applicationRequestCount: Number(protocolRow.applicationRequestCount ?? 0),
    connectCount: Number(protocolRow.connectCount ?? 0),
    protocolCapture: {
      http: { requests: Number(protocolRow.httpCount ?? 0) },
      https: {
        requests: Number(protocolRow.httpsCount ?? 0),
        mitmRequests: Number(protocolRow.httpsMitmCount ?? 0),
      },
      websocket: {
        requests: Number(protocolRow.websocketCount ?? 0),
        eventRequests: Number(events.websocket?.requestCount ?? 0),
        events: Number(events.websocket?.eventCount ?? 0),
      },
      sse: {
        requests: Number(protocolRow.sseCount ?? 0),
        completedRequests: Number(protocolRow.completedSseCount ?? 0),
        eventRequests: Number(events.sse?.requestCount ?? 0),
        events: Number(events.sse?.eventCount ?? 0),
      },
    },
    responseBodyBytes: Number(rows[0]?.responseBodyBytes ?? 0),
    physicalBytes: files.reduce((sum, file) => sum + file.bytes, 0),
    files,
    windowRows: windowRows.length,
    windowOffset: offset,
    windowQueryMs: performance.now() - queryStarted,
  };
}

async function listProcesses() {
  const output = await runCommand("/bin/ps", ["-axo", "pid=,ppid=,rss=,command="]);
  return output.split("\n").map((line) => {
    const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/);
    return match ? {
      pid: Number(match[1]),
      ppid: Number(match[2]),
      rssBytes: Number(match[3]) * 1024,
      command: match[4],
    } : null;
  }).filter(Boolean);
}

function isWebKitProcess(row) {
  return /com\.apple\.WebKit\.(WebContent|Networking|GPU)|WebKit\.WebContent/i.test(row.command);
}

async function processSample(mainPid, baselineWebKitPids) {
  const rows = await listProcesses();
  const byParent = new Map();
  for (const row of rows) {
    const children = byParent.get(row.ppid) ?? [];
    children.push(row);
    byParent.set(row.ppid, children);
  }
  const selected = [];
  const pending = [mainPid];
  const visited = new Set();
  while (pending.length) {
    const pid = pending.pop();
    if (visited.has(pid)) continue;
    visited.add(pid);
    const row = rows.find((item) => item.pid === pid);
    if (row) selected.push(row);
    for (const child of byParent.get(pid) ?? []) pending.push(child.pid);
  }
  for (const row of rows) {
    if (isWebKitProcess(row) && !baselineWebKitPids.has(row.pid) && !visited.has(row.pid)) {
      selected.push(row);
      visited.add(row.pid);
    }
  }
  const main = selected.find((row) => row.pid === mainPid);
  const webview = selected.filter((row) => /WebContent|Renderer/i.test(row.command));
  const helper = selected.filter((row) => row.pid !== mainPid && !webview.includes(row));
  return {
    timestampMs: Date.now(),
    mainRssBytes: main?.rssBytes ?? 0,
    webviewRssBytes: webview.reduce((sum, row) => sum + row.rssBytes, 0),
    helperRssBytes: helper.reduce((sum, row) => sum + row.rssBytes, 0),
    treeRssBytes: selected.reduce((sum, row) => sum + row.rssBytes, 0),
    processCount: selected.length,
    processes: selected.map((row) => ({ pid: row.pid, ppid: row.ppid, rssBytes: row.rssBytes, command: basename(row.command.split(" ")[0]) })),
  };
}

async function waitForReady(readyFile, timeoutSeconds, appState) {
  const deadline = Date.now() + timeoutSeconds * 1000;
  while (Date.now() < deadline) {
    if (appState.exited) throw new Error(`ShowNet exited before ready (${appState.exitCode})`);
    const content = await readFile(readyFile, "utf8").catch(() => null);
    if (content) {
      const payload = JSON.parse(content);
      if (payload.status !== "ready") throw new Error(payload.error ?? "ShowNet soak startup failed");
      return payload;
    }
    await delay(100);
  }
  throw new Error(`ShowNet did not become ready within ${timeoutSeconds} seconds`);
}

async function sha256(path) {
  const hash = createHash("sha256");
  await new Promise((resolveHash, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", reject);
    stream.once("end", resolveHash);
  });
  return hash.digest("hex");
}

function resourceSummary(samples, key) {
  const values = samples.map((sample) => sample[key]).filter(Number.isFinite);
  const startBytes = values[0] ?? 0;
  const endBytes = values.at(-1) ?? 0;
  return {
    startBytes,
    endBytes,
    peakBytes: values.length ? Math.max(...values) : 0,
    growthBytes: endBytes - startBytes,
  };
}

function cooldownResourceSummary(trafficEndProcess, finalProcess, key) {
  const trafficEndBytes = trafficEndProcess?.[key] ?? 0;
  const endBytes = finalProcess?.[key] ?? 0;
  return { trafficEndBytes, endBytes, deltaBytes: endBytes - trafficEndBytes };
}

export function summarizeCancellationIpc(probe) {
  const attempts = Array.isArray(probe?.samples) ? probe.samples : [];
  const valid = attempts.filter((sample) => sample?.accepted === true
    && sample?.settled === true
    && Number.isFinite(sample?.clickToIdleMs)
    && sample.clickToIdleMs >= 0
    && Number.isFinite(sample?.backendWaitMs)
    && sample.backendWaitMs >= 0);
  const clickToIdle = summarizeDurations(valid.map((sample) => sample.clickToIdleMs));
  const backendWait = summarizeDurations(valid.map((sample) => sample.backendWaitMs));
  const targetSamples = Number.isInteger(probe?.targetSamples) ? probe.targetSamples : 12;
  const status = valid.length >= 5 ? "measured" : valid.length > 0 ? "partial" : "not-measured";
  return {
    status,
    attempts: attempts.length,
    validSamples: valid.length,
    targetSamples,
    clickToIdle,
    backendWait,
    measurement: status === "not-measured"
      ? undefined
      : "Packaged WebView HTMLElement.click -> React cancellation handler -> Tauri invoke -> matching SQLite worker exit -> two animation frames.",
    reason: status === "not-measured"
      ? "No valid packaged-WebView cancellation sample was recorded; short runs may not reach the minimum request-count threshold."
      : undefined,
    samples: attempts,
  };
}

export function protocolGateChecks(selectedProtocols, trafficByProtocol = {}, protocolCapture = {}) {
  return selectedProtocols.map((protocol) => {
    const protocolTraffic = trafficByProtocol[protocol] ?? { attempted: 0, completed: 0, failed: 0 };
    const captured = protocolCapture[protocol] ?? {};
    const completed = protocolTraffic.completed ?? 0;
    if (protocol === "https") {
      return {
        name: "HTTPS MITM capture",
        pass: completed > 0 && captured.requests >= completed && captured.mitmRequests >= completed,
        observed: `${captured.mitmRequests ?? 0} MITM / ${completed} completed`,
        gate: "all completed HTTPS requests captured with MITM evidence",
      };
    }
    if (protocol === "websocket") {
      return {
        name: "WebSocket frame capture",
        pass: completed > 0 && captured.requests >= completed && captured.eventRequests >= completed && captured.events >= completed * 2,
        observed: `${captured.requests ?? 0} handshakes / ${captured.events ?? 0} events`,
        gate: `>= ${completed} handshakes and >= ${completed * 2} events`,
      };
    }
    if (protocol === "sse") {
      return {
        name: "SSE event capture",
        pass: completed > 0 && captured.requests >= completed && captured.completedRequests >= completed && captured.eventRequests >= completed && captured.events >= completed * 3,
        observed: `${captured.completedRequests ?? 0} complete streams / ${captured.events ?? 0} events`,
        gate: `>= ${completed} complete streams and >= ${completed * 3} events`,
      };
    }
    return {
      name: "HTTP application capture",
      pass: completed > 0 && captured.requests >= completed,
      observed: `${captured.requests ?? 0} captured / ${completed} completed`,
      gate: "all completed HTTP requests captured",
    };
  });
}

function buildReport({ runId, config, artifact, ready, traffic, target, samples, cancellationProbe, startedAt, endedAt }) {
  const selectedProtocols = config.protocols ?? ["http"];
  const processSamples = samples.map((sample) => sample.process);
  const databaseSamples = samples.map((sample) => sample.database);
  const firstDatabase = databaseSamples[0] ?? {};
  const finalDatabase = databaseSamples.at(-1) ?? {};
  const applicationRequestCount = finalDatabase.applicationRequestCount ?? finalDatabase.requestCount ?? 0;
  const captureRatio = traffic.attempted ? applicationRequestCount / traffic.attempted : 0;
  const queryWindow = summarizeDurations(databaseSamples.map((sample) => sample.windowQueryMs));
  const resources = {
    main: resourceSummary(processSamples, "mainRssBytes"),
    webview: resourceSummary(processSamples, "webviewRssBytes"),
    helper: resourceSummary(processSamples, "helperRssBytes"),
    tree: resourceSummary(processSamples, "treeRssBytes"),
    samples: processSamples.length,
  };
  const formalEligible = config.mode === "long" && traffic.actualDurationSeconds >= 1800;
  const loadRate = summarizeLoadRate(traffic.attempted, traffic.actualDurationSeconds, config.rate);
  const cancellationIpc = summarizeCancellationIpc(cancellationProbe);
  const protocolCapture = finalDatabase.protocolCapture ?? {};
  const checks = [
    { name: "Release app became ready", pass: ready.status === "ready", observed: ready.status, gate: "ready" },
    { name: "Transport failure rate", pass: traffic.failed / Math.max(1, traffic.attempted) <= 0.01, observed: `${((traffic.failed / Math.max(1, traffic.attempted)) * 100).toFixed(2)}%`, gate: "<= 1%" },
    { name: "Capture completeness", pass: captureRatio >= 0.98, observed: `${(captureRatio * 100).toFixed(2)}%`, gate: ">= 98%" },
    { name: "External window query P95", pass: (queryWindow.p95Ms ?? Infinity) <= 750, observed: formatMs(queryWindow.p95Ms), gate: "<= 750 ms" },
  ];
  checks.push(...protocolGateChecks(selectedProtocols, traffic.byProtocol, protocolCapture));
  if (formalEligible) {
    checks.push(
      loadUtilizationGate(loadRate, config.minimumRateUtilization),
      { name: "Main RSS growth", pass: resources.main.growthBytes <= 256 * 1024 * 1024, observed: formatBytes(resources.main.growthBytes), gate: "<= 256 MiB" },
      { name: "Process-tree RSS growth", pass: resources.tree.growthBytes <= 512 * 1024 * 1024, observed: formatBytes(resources.tree.growthBytes), gate: "<= 512 MiB" },
      {
        name: "WebView click-to-idle cancellation P95",
        pass: cancellationIpc.validSamples >= 10 && (cancellationIpc.clickToIdle.p95Ms ?? Infinity) <= 500,
        observed: `${cancellationIpc.validSamples} samples / ${formatMs(cancellationIpc.clickToIdle.p95Ms)}`,
        gate: ">= 10 samples and <= 500 ms",
      },
    );
  }
  const trafficEndSample = [...samples].reverse().find((sample) => sample.phase === "traffic-end") ?? samples.at(-1);
  const finalSample = samples.at(-1);
  const actualCooldownSeconds = Math.max(
    0,
    ((finalSample?.timestampMs ?? 0) - (trafficEndSample?.timestampMs ?? 0)) / 1000,
  );
  return {
    schemaVersion: 2,
    runId,
    startedAt,
    endedAt,
    formalEligibility: {
      eligible: formalEligible,
      requiredDurationSeconds: 1800,
      reason: formalEligible ? "Duration satisfies the release soak gate" : "Smoke/custom duration cannot prove 30-60 minute stability",
    },
    config: {
      mode: config.mode,
      requestedDurationSeconds: config.durationSeconds,
      requestRatePerSecond: config.rate,
      concurrency: config.concurrency,
      warmupSeconds: config.warmupSeconds,
      cooldownSeconds: config.cooldownSeconds,
      minimumRateUtilization: config.minimumRateUtilization,
      sampleSeconds: config.sampleSeconds,
      proxyPort: config.proxyPort,
      protocols: selectedProtocols,
    },
    environment: {
      platform: platform(),
      osRelease: release(),
      cpuCount: cpus().length,
      totalMemoryBytes: totalmem(),
      freeMemoryBytesAtEnd: freemem(),
      nodeVersion: process.version,
    },
    artifact,
    ready,
    traffic: { ...traffic, loadRate, targetReceived: target.requestCount, target },
    capture: {
      requestCount: applicationRequestCount,
      totalRows: finalDatabase.requestCount ?? 0,
      connectCount: finalDatabase.connectCount ?? 0,
      protocols: protocolCapture,
      responseBodyBytes: finalDatabase.responseBodyBytes ?? 0,
      ratio: captureRatio,
    },
    protocolMatrix: {
      selected: selectedProtocols,
      traffic: traffic.byProtocol,
      capture: protocolCapture,
    },
    resources,
    cooldown: {
      requestedSeconds: config.cooldownSeconds,
      actualSeconds: round(actualCooldownSeconds),
      main: cooldownResourceSummary(trafficEndSample?.process, finalSample?.process, "mainRssBytes"),
      webview: cooldownResourceSummary(trafficEndSample?.process, finalSample?.process, "webviewRssBytes"),
      helper: cooldownResourceSummary(trafficEndSample?.process, finalSample?.process, "helperRssBytes"),
      tree: cooldownResourceSummary(trafficEndSample?.process, finalSample?.process, "treeRssBytes"),
    },
    storage: {
      databasePath: ready.databasePath,
      startPhysicalBytes: firstDatabase.physicalBytes ?? 0,
      endPhysicalBytes: finalDatabase.physicalBytes ?? 0,
      growthBytes: (finalDatabase.physicalBytes ?? 0) - (firstDatabase.physicalBytes ?? 0),
      endFiles: finalDatabase.files ?? [],
      samples: databaseSamples.length,
    },
    queryWindow,
    gates: { passed: checks.every((check) => check.pass), checks },
    cancellationIpc,
    limitations: [
      "A run shorter than 1800 seconds is functional smoke evidence only and must not be cited as a long-session stability result.",
      `The local workload selected ${selectedProtocols.join(", ")}; WAN loss, mobile-device behavior, certificate pinning, mutual TLS, and multi-hour reconnect/backpressure behavior remain outside this run.`,
      "The HTTPS target uses an ephemeral run-local root trusted only by the isolated soak process; this validates verified MITM transport but not platform certificate installation or public PKI behavior.",
      "WebSocket and SSE fixtures exchange bounded messages and close deterministically; long-lived idle connections and reconnect storms require a separate profile.",
      "Window-query timing includes sqlite3 process startup and does not measure Tauri invoke or WebView rendering latency.",
      "WebKit services are attributed by app descendants plus the PID delta from a pre-launch WebKit baseline; another WebKit app launched during the run can add noise.",
      "The WebView cancellation probe invokes the real rendered button with HTMLElement.click(); OS hardware-pointer dispatch latency is outside the measurement.",
      ...(cancellationIpc.status === "not-measured" ? [cancellationIpc.reason] : []),
    ],
    samples,
  };
}

async function terminateChild(child) {
  if (!child || child.exitCode != null || child.signalCode != null) return;
  child.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => child.once("exit", resolveExit)),
    delay(5000),
  ]);
  if (child.exitCode == null && child.signalCode == null) child.kill("SIGKILL");
}

async function main() {
  const config = parseArgs(process.argv.slice(2));
  if (config.help) {
    process.stdout.write(usage());
    return;
  }
  if (platform() !== "darwin") throw new Error("The current release soak harness targets the macOS .app bundle");
  const artifactInfo = await stat(config.appBinary).catch(() => null);
  if (!artifactInfo?.isFile()) throw new Error(`Release app binary is missing: ${config.appBinary}`);

  const timestamp = new Date().toISOString().replaceAll(":", "-").replace(".", "-");
  const runId = `shownet-${config.mode}-soak-${timestamp}-${process.pid}`;
  const runDirectory = resolve(config.outputDirectory, runId);
  const dataDirectory = resolve(runDirectory, "app-data");
  const readyFile = resolve(runDirectory, "ready.json");
  const reportJson = resolve(runDirectory, "report.json");
  const reportMarkdown = resolve(runDirectory, "report.md");
  await mkdir(dataDirectory, { recursive: true });
  const proxyPort = await reserveLoopbackPort();
  config.proxyPort = proxyPort;
  const targets = await startProtocolTargets(runDirectory, config.protocols);
  const baselineWebKitPids = new Set((await listProcesses()).filter(isWebKitProcess).map((row) => row.pid));
  const stdoutLog = createWriteStream(resolve(runDirectory, "app.stdout.log"));
  const stderrLog = createWriteStream(resolve(runDirectory, "app.stderr.log"));
  const appState = { exited: false, exitCode: null };
  const child = spawn(config.appBinary, [], {
    cwd: dirname(config.appBinary),
    env: {
      ...process.env,
      SHOWNET_DATA_DIR: dataDirectory,
      SHOWNET_SOAK_READY_FILE: readyFile,
      SHOWNET_SOAK_PROXY_PORT: String(proxyPort),
      SHOWNET_SOAK_SESSION_NAME: `Release ${config.mode} ${timestamp}`,
      ...(targets.upstreamRootCertificate ? {
        SHOWNET_SOAK_UPSTREAM_CA_FILE: targets.upstreamRootCertificate,
      } : {}),
      NO_PROXY: "127.0.0.1,localhost,::1",
      no_proxy: "127.0.0.1,localhost,::1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.pipe(stdoutLog);
  child.stderr.pipe(stderrLog);
  child.once("exit", (code, signal) => {
    appState.exited = true;
    appState.exitCode = code ?? signal ?? "unknown";
  });

  let samplerRunning = true;
  let samplerPromise;
  try {
    const ready = await waitForReady(readyFile, config.readyTimeoutSeconds, appState);
    if (config.protocols.includes("https") && Number(ready.soakUpstreamRootCount ?? 0) < 1) {
      throw new Error("ShowNet did not load the isolated HTTPS target root certificate");
    }
    const proxyCa = await readFile(resolve(ready.dataDirectory, "shownet-root-ca.pem"));
    const artifact = {
      path: config.appBinary,
      bytes: artifactInfo.size,
      modifiedAt: artifactInfo.mtime.toISOString(),
      sha256: await sha256(config.appBinary),
    };
    const samples = [];
    const monitoringStartedAt = Date.now();
    let lastProgressAt = 0;
    let samplePhase = "baseline";
    const sampleOnce = async (phase = samplePhase) => {
      const [processMetrics, databaseMetrics] = await Promise.all([
        processSample(child.pid, baselineWebKitPids),
        databaseSample(ready.databasePath, ready.sessionId),
      ]);
      samples.push({ timestampMs: Date.now(), phase, process: processMetrics, database: databaseMetrics });
      if (config.mode === "long" && Date.now() - lastProgressAt >= 60_000) {
        lastProgressAt = Date.now();
        process.stdout.write(
          `PROGRESS elapsed=${Math.round((Date.now() - monitoringStartedAt) / 1000)}s ` +
          `captured=${databaseMetrics.requestCount} ` +
          `main=${formatBytes(processMetrics.mainRssBytes)} ` +
          `webview=${formatBytes(processMetrics.webviewRssBytes)} ` +
          `tree=${formatBytes(processMetrics.treeRssBytes)} ` +
          `database=${formatBytes(databaseMetrics.physicalBytes)} ` +
          `window=${formatMs(databaseMetrics.windowQueryMs)}\n`,
        );
      }
    };
    if (config.warmupSeconds > 0) await delay(config.warmupSeconds * 1000);
    if (appState.exited) throw new Error(`ShowNet exited during warmup (${appState.exitCode})`);
    await sampleOnce("baseline");
    samplePhase = "traffic";
    samplerPromise = (async () => {
      while (samplerRunning) {
        await delay(config.sampleSeconds * 1000);
        if (!samplerRunning || appState.exited) break;
        await sampleOnce().catch((error) => {
          stderrLog.write(`\nsoak sampler error: ${error}\n`);
        });
      }
    })();

    const startedAt = new Date().toISOString();
    const traffic = await runTraffic(config, targets, proxyCa, appState);
    const settleDeadline = Date.now() + 15_000;
    while (Date.now() < settleDeadline) {
      const latest = await databaseSample(ready.databasePath, ready.sessionId);
      const websocketCompleted = traffic.byProtocol.websocket?.completed ?? 0;
      const sseCompleted = traffic.byProtocol.sse?.completed ?? 0;
      if (latest.applicationRequestCount >= traffic.completed
        && (latest.protocolCapture.websocket?.events ?? 0) >= websocketCompleted * 2
        && (latest.protocolCapture.sse?.events ?? 0) >= sseCompleted * 3) break;
      await delay(250);
    }
    await sampleOnce("traffic-end");
    samplePhase = "cooldown";
    if (config.cooldownSeconds > 0) {
      await delay(config.cooldownSeconds * 1000);
      if (appState.exited) throw new Error(`ShowNet exited during cooldown (${appState.exitCode})`);
    }
    samplerRunning = false;
    await samplerPromise;
    await sampleOnce("cooldown-end");
    const endedAt = new Date().toISOString();
    const cancellationProbe = ready.cancellationIpcPath
      ? await readFile(ready.cancellationIpcPath, "utf8").then(JSON.parse).catch(() => null)
      : null;
    const report = buildReport({
      runId,
      config,
      artifact,
      ready,
      traffic,
      target: targets.metrics(),
      samples,
      cancellationProbe,
      startedAt,
      endedAt,
    });
    await Promise.all([
      writeFile(reportJson, `${JSON.stringify(report, null, 2)}\n`),
      writeFile(reportMarkdown, renderMarkdown(report)),
    ]);
    process.stdout.write(`${report.gates.passed ? "PASS" : "FAIL"} ${reportMarkdown}\n`);
    if (!report.gates.passed) process.exitCode = 1;
  } catch (error) {
    samplerRunning = false;
    if (samplerPromise) await samplerPromise.catch(() => {});
    const failure = {
      schemaVersion: 1,
      runId,
      status: "failed",
      error: String(error),
      appBinary: config.appBinary,
      dataDirectory,
      readyFile,
      appExit: appState,
    };
    await writeFile(reportJson, `${JSON.stringify(failure, null, 2)}\n`);
    await writeFile(reportMarkdown, `# ShowNet Release Long-Session Soak\n\nRun failed before a complete report was produced.\n\n\`${String(error)}\`\n`);
    throw error;
  } finally {
    samplerRunning = false;
    await terminateChild(child);
    await targets.close();
    stdoutLog.end();
    stderrLog.end();
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  main().catch((error) => {
    process.stderr.write(`${error.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
