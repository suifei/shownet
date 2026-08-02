import type { CollectionSyncPreview, RequestCollectionWorkspace, RequestDraft, RequestListItem, RequestRecord, Session, SourceType } from "./types";

const commonRequestHeaders = [
  { name: "accept", value: "application/json, text/plain, */*" },
  { name: "accept-language", value: "zh-CN,zh;q=0.9,en;q=0.8" },
  { name: "user-agent", value: "Mozilla/5.0 ShowNet Capture/1.0" },
  { name: "x-client-version", value: "web-4.18.2" },
];

const commonResponseHeaders = [
  { name: "content-type", value: "application/json; charset=utf-8" },
  { name: "cache-control", value: "no-store" },
  { name: "x-request-id", value: "req_01JZ8N5QFK2A6MT" },
  { name: "server", value: "cloudflare" },
];

const response = (data: unknown) => JSON.stringify({ code: 0, data, message: "ok" }, null, 2);

export const initialSessions: Session[] = [
  {
    id: "session-live",
    name: "电商登录链路",
    createdAt: "今天 14:32",
    requestCount: 247,
    errorCount: 3,
    active: true,
    sources: ["browser", "mobile", "terminal"],
    analysisReportCount: 2,
    latestAnalysisStatus: "complete",
  },
  {
    id: "session-app",
    name: "桌面客户端同步",
    createdAt: "今天 11:08",
    requestCount: 86,
    errorCount: 1,
    active: false,
    sources: ["desktop", "script"],
    analysisReportCount: 0,
  },
  {
    id: "session-oauth",
    name: "OAuth 回调排查",
    createdAt: "昨天 18:44",
    requestCount: 132,
    errorCount: 8,
    active: false,
    sources: ["browser"],
    analysisReportCount: 1,
    latestAnalysisStatus: "complete",
  },
  {
    id: "session-iot",
    name: "设备心跳协议",
    createdAt: "7月28日",
    requestCount: 594,
    errorCount: 12,
    active: false,
    sources: ["iot", "mobile"],
    analysisReportCount: 0,
  },
];

type RequestSeed = Pick<
  RequestRecord,
  | "method"
  | "host"
  | "path"
  | "status"
  | "type"
  | "size"
  | "duration"
  | "source"
  | "protocol"
  | "risk"
> &
  Partial<Pick<RequestRecord, "query" | "requestBody" | "responseBody" | "responseBodyMetadata" | "cryptoSnippetCount" | "hook">>;

const seeds: RequestSeed[] = [
  {
    method: "POST",
    host: "api.nova-shop.cn",
    path: "/v2/auth/challenge",
    status: 200,
    type: "xhr",
    size: "1.8 KB",
    duration: 184,
    source: "browser",
    protocol: "h2",
    risk: "info",
    requestBody: JSON.stringify({ phone: "138****5072", scene: "login" }, null, 2),
    responseBody: response({ challenge: "b08f91...a7cd", expiresIn: 120 }),
    responseBodyMetadata: {
      captured: true,
      contentEncoding: "gzip",
      decoded: true,
      truncated: false,
      complete: true,
      wireBytes: 1843,
      decodedBytes: 4276,
      format: "text",
    },
  },
  {
    method: "GET",
    host: "static.nova-shop.cn",
    path: "/assets/login.7db219.js",
    status: 200,
    type: "script",
    size: "184 KB",
    duration: 92,
    source: "browser",
    protocol: "h2",
    risk: "none",
    responseBody: "(()=>{const sign=(e,t)=>crypto.subtle.digest(\"SHA-256\",encode(e+t));/* ... */})();",
    cryptoSnippetCount: 1,
  },
  {
    method: "POST",
    host: "risk.nova-shop.cn",
    path: "/_sec/captcha/verify",
    status: 200,
    type: "fetch",
    size: "3.4 KB",
    duration: 317,
    source: "browser",
    protocol: "h2",
    risk: "warning",
    requestBody: JSON.stringify({ token: "7fd1...e834", fp: "4cb50b..." }, null, 2),
    responseBody: response({ pass: true, riskLevel: "low" }),
    hook: {
      algorithm: "crypto.subtle.digest / SHA-256",
      input: "challenge=b08f91...a7cd&ts=1785393214",
      output: "8cb6d65cc89c6b17...345f0d",
    },
  },
  {
    method: "POST",
    host: "api.nova-shop.cn",
    path: "/v2/auth/login",
    status: 200,
    type: "xhr",
    size: "2.7 KB",
    duration: 426,
    source: "mobile",
    protocol: "h2",
    risk: "critical",
    requestBody: JSON.stringify(
      { account: "138****5072", password: "AES:4ae7...", signature: "8cb6d6..." },
      null,
      2,
    ),
    responseBody: response({ accessToken: "eyJhbGci...", refreshToken: "eyJhbGci...", expiresIn: 7200 }),
    hook: {
      algorithm: "CryptoJS.AES.encrypt / CBC",
      input: "v1|13800135072|1785393214",
      output: "4ae7f0fb46d83b66...9f3a",
    },
  },
  {
    method: "GET",
    host: "api.nova-shop.cn",
    path: "/v2/users/me",
    status: 200,
    type: "fetch",
    size: "4.2 KB",
    duration: 126,
    source: "terminal",
    protocol: "h2",
    risk: "none",
    responseBody: response({ id: "u_80712", nickname: "林川", membership: "pro" }),
  },
  {
    method: "GET",
    host: "api.nova-shop.cn",
    path: "/v2/products/recommend",
    query: "cursor=0&limit=20&scene=home",
    status: 200,
    type: "fetch",
    size: "38.6 KB",
    duration: 218,
    source: "mobile",
    protocol: "h2",
    risk: "none",
    responseBody: response({ items: [{ id: "sku_1928", title: "Air Lamp" }], nextCursor: 20 }),
  },
  {
    method: "POST",
    host: "log.nova-shop.cn",
    path: "/collect/batch",
    status: 204,
    type: "fetch",
    size: "0 B",
    duration: 74,
    source: "browser",
    protocol: "h2",
    risk: "none",
    requestBody: JSON.stringify({ events: ["page_view", "exposure", "click"] }, null, 2),
    responseBody: "",
  },
  {
    method: "OPTIONS",
    host: "api.nova-shop.cn",
    path: "/v2/cart/items",
    status: 204,
    type: "xhr",
    size: "0 B",
    duration: 31,
    source: "browser",
    protocol: "h2",
    risk: "none",
    responseBody: "",
  },
  {
    method: "POST",
    host: "api.nova-shop.cn",
    path: "/v2/cart/items",
    status: 201,
    type: "xhr",
    size: "1.1 KB",
    duration: 168,
    source: "desktop",
    protocol: "h2",
    risk: "none",
    requestBody: JSON.stringify({ skuId: "sku_1928", quantity: 1 }, null, 2),
    responseBody: response({ cartId: "cart_8f213", itemCount: 3 }),
  },
  {
    method: "GET",
    host: "gateway.nova-shop.cn",
    path: "/socket",
    status: 101,
    type: "websocket",
    size: "12.8 KB",
    duration: 1842,
    source: "desktop",
    protocol: "ws",
    risk: "info",
    responseBody: "WebSocket connection upgraded\n← {\"event\":\"order.updated\",\"id\":\"od_29184\"}",
  },
  {
    method: "GET",
    host: "gateway.nova-shop.cn",
    path: "/events/orders",
    query: "channel=current-user",
    status: 200,
    type: "sse",
    size: "9.6 KB",
    duration: 42_180,
    source: "desktop",
    protocol: "h2",
    risk: "info",
    responseBody: "id: evt-1842\nevent: order.updated\ndata: {\"orderId\":\"od_29184\",\"status\":\"paid\"}\n\n",
    responseBodyMetadata: {
      captured: true,
      decoded: false,
      truncated: false,
      complete: false,
      wireBytes: 9_830,
      decodedBytes: 9_830,
      format: "text",
    },
  },
  {
    method: "GET",
    host: "static.nova-shop.cn",
    path: "/fonts/inter-latin.woff2",
    status: 304,
    type: "font",
    size: "memory",
    duration: 8,
    source: "browser",
    protocol: "h2",
    risk: "none",
    responseBody: "(binary font data)",
  },
  {
    method: "GET",
    host: "api.nova-shop.cn",
    path: "/v2/coupons/active",
    status: 500,
    type: "fetch",
    size: "618 B",
    duration: 1260,
    source: "script",
    protocol: "http/1.1",
    risk: "warning",
    responseBody: JSON.stringify({ code: 50013, message: "upstream timeout", traceId: "tr_71fbb" }, null, 2),
  },
  {
    method: "POST",
    host: "pay.nova-shop.cn",
    path: "/v1/orders/prepay",
    status: 401,
    type: "xhr",
    size: "512 B",
    duration: 263,
    source: "mobile",
    protocol: "h2",
    risk: "critical",
    requestBody: JSON.stringify({ orderId: "od_29184", nonce: "3ca8...", sign: "0b56..." }, null, 2),
    responseBody: JSON.stringify({ code: 40103, message: "invalid signature" }, null, 2),
    hook: {
      algorithm: "SM2.sign",
      input: "order_id=od_29184&nonce=3ca8d1&ts=1785393299",
      output: "3046022100b56a...",
    },
  },
  {
    method: "GET",
    host: "device.local",
    path: "/api/v1/heartbeat",
    query: "device_id=lamp_0193",
    status: 200,
    type: "fetch",
    size: "286 B",
    duration: 41,
    source: "iot",
    protocol: "http/1.1",
    risk: "info",
    responseBody: response({ serverTime: 1785393320, update: false }),
  },
];

export const initialRequests: RequestRecord[] = seeds.map((seed, index) => ({
  ...seed,
  id: `request-${index + 1}`,
  order: index + 1,
  time: `14:3${Math.floor(index / 6)}:${String(12 + index * 3).padStart(2, "0")}`,
  tls: seed.protocol === "ws" ? "TLS 1.3" : seed.host === "device.local" ? "明文" : "TLS 1.3",
  ...(index === 0 ? {
    tlsFingerprint: {
      captureMode: "mitm" as const,
      inbound: {
        ja3: "cd08e31494f9531f560d64c695473da9",
        ja3Raw: "771,4865-4866-4867-49195-49199,0-10-11-13-16-43-45-51,29-23-24,0",
        ja4: "t13d0508h2_8daaf6152771_e5627efa2ab1",
        ja4Raw: "t13d0508h2_1301,1302,1303,c02b,c02f_000a,000b,000d,002b,002d,0033_0403,0804",
        sni: seed.host,
        alpn: ["h2", "http/1.1"],
        legacyVersion: "TLS 1.2",
        offeredVersions: ["TLS 1.3", "TLS 1.2"],
        cipherSuites: ["0a0a", "1301", "1302", "1303", "c02b", "c02f"],
        extensions: ["1a1a", "0000", "000a", "000b", "000d", "0010", "002b", "002d", "0033"],
        supportedGroups: ["2a2a", "001d", "0017", "0018"],
        signatureAlgorithms: ["0403", "0804", "0401"],
        grease: true,
      },
      outbound: {
        mode: "independent" as const,
        profile: "rustls-default",
        note: "MITM 使用独立上游握手；目标站看到的是 ShowNet 出站 TLS 指纹。",
      },
    },
  } : {}),
  requestHeaders: [
    ...commonRequestHeaders.filter((header) => seed.type !== "sse" || header.name !== "accept"),
    ...(seed.type === "sse" ? [{ name: "accept", value: "text/event-stream" }] : []),
    { name: "host", value: seed.host },
    ...(seed.method === "POST" ? [{ name: "content-type", value: "application/json" }] : []),
  ],
  responseHeaders: [
    ...commonResponseHeaders.filter((header) => seed.type !== "sse" || header.name !== "content-type"),
    ...(seed.type === "sse" ? [{ name: "content-type", value: "text/event-stream; charset=utf-8" }] : []),
    ...(seed.responseBodyMetadata?.contentEncoding ? [{ name: "content-encoding", value: seed.responseBodyMetadata.contentEncoding }] : []),
    { name: ":status", value: String(seed.status) },
  ],
  responseBody: seed.responseBody ?? response({ ok: true }),
  cryptoSnippetCount: seed.cryptoSnippetCount ?? 0,
}));

const previewDraft = (
  requestIndex: number,
  name: string,
  tags: string[],
  collectionId?: string,
  folderId?: string,
): RequestDraft => {
  const request = initialRequests[requestIndex];
  const query = request.query ? `?${request.query}` : "";
  return {
    id: `preview-draft-${requestIndex + 1}`,
    sessionId: "session-live",
    sourceRequestId: request.id,
    name,
    method: request.method,
    url: `https://${request.host}${request.path}${query}`,
    headers: request.requestHeaders,
    body: request.requestBody ?? "",
    bodyType: request.requestBody ? "json" : "none",
    auth: { kind: "none" },
    settings: { followRedirects: true, verifyTls: true, cookieJar: false },
    collectionId,
    folderId,
    tags,
    createdAt: Date.now() - (requestIndex + 2) * 3_600_000,
    updatedAt: Date.now() - requestIndex * 420_000,
  };
};

export const initialRequestCollectionWorkspace: RequestCollectionWorkspace = {
  collections: [
    {
      id: "preview-commerce", name: "商城核心 API", description: "登录、购物车与支付链路", defaultHeaders: [],
      defaultAuth: { kind: "none" }, sortOrder: 0, draftCount: 5, folderCount: 4,
      sourceFormat: "openapi", sourcePath: "/Users/demo/Documents/nova-shop.openapi.yaml",
      sourceFingerprint: "a".repeat(64), sourceSyncedAt: Date.now() - 3_600_000,
      createdAt: Date.now() - 86_400_000, updatedAt: Date.now(),
    },
    {
      id: "preview-realtime", name: "设备与实时通道", description: "设备心跳与 WebSocket", defaultHeaders: [],
      defaultAuth: { kind: "none" }, sortOrder: 1, draftCount: 2, folderCount: 2,
      createdAt: Date.now() - 72_000_000, updatedAt: Date.now() - 900_000,
    },
  ],
  folders: [
    { id: "preview-auth", collectionId: "preview-commerce", name: "账号与鉴权", depth: 1, sortOrder: 0, draftCount: 1, createdAt: 1, updatedAt: 1 },
    { id: "preview-login", collectionId: "preview-commerce", parentId: "preview-auth", name: "登录流程", depth: 2, sortOrder: 0, draftCount: 2, createdAt: 1, updatedAt: 1 },
    { id: "preview-cart", collectionId: "preview-commerce", name: "购物车", depth: 1, sortOrder: 1, draftCount: 1, createdAt: 1, updatedAt: 1 },
    { id: "preview-orders", collectionId: "preview-commerce", name: "订单与支付", depth: 1, sortOrder: 2, draftCount: 1, createdAt: 1, updatedAt: 1 },
    { id: "preview-device", collectionId: "preview-realtime", name: "设备协议", depth: 1, sortOrder: 0, draftCount: 1, createdAt: 1, updatedAt: 1 },
    { id: "preview-socket", collectionId: "preview-realtime", name: "实时通道", depth: 1, sortOrder: 1, draftCount: 1, createdAt: 1, updatedAt: 1 },
  ],
  drafts: [
    previewDraft(0, "获取登录挑战", ["鉴权", "关键链路", "Smoke"], "preview-commerce", "preview-login"),
    previewDraft(3, "提交账号登录", ["鉴权", "移动端"], "preview-commerce", "preview-login"),
    previewDraft(4, "读取当前用户", ["用户", "回归"], "preview-commerce", "preview-auth"),
    previewDraft(8, "添加购物车商品", ["购物车", "写操作"], "preview-commerce", "preview-cart"),
    previewDraft(12, "创建预支付订单", ["支付", "高风险"], "preview-commerce", "preview-orders"),
    previewDraft(13, "设备心跳", ["IoT", "健康检查"], "preview-realtime", "preview-device"),
    previewDraft(9, "建立实时连接", ["WebSocket", "长连接"], "preview-realtime", "preview-socket"),
    previewDraft(11, "查询可用优惠券", ["待整理", "服务异常"]),
  ],
};

export const initialCollectionSyncPreview: CollectionSyncPreview = {
  collectionId: "preview-commerce",
  collectionName: "商城核心 API",
  sourcePath: "/Users/demo/Documents/nova-shop.openapi.yaml",
  sourceFingerprint: "b".repeat(64),
  unchangedCount: 12,
  warnings: ["OpenAPI 安全方案已识别；规范通常只描述认证方式，不包含实际凭据"],
  changes: [
    {
      kind: "add",
      operationKey: "GET /v2/catalog/recommendations",
      item: {
        name: "获取个性化推荐", method: "GET", url: "https://api.nova-shop.cn/v2/catalog/recommendations",
        headers: [{ name: "Accept", value: "application/json" }], body: "", bodyType: "none",
        folderPath: ["商品目录"], sourceKey: "GET /v2/catalog/recommendations", sourceFingerprint: "c".repeat(64),
      },
      changedFields: ["operation"], localOverride: false,
    },
    {
      kind: "modify",
      operationKey: "POST /v2/auth/challenge",
      draftId: "preview-draft-1", currentName: "获取登录挑战", currentMethod: "POST",
      currentUrl: "https://api.nova-shop.cn/v2/auth/challenge",
      item: {
        name: "创建登录挑战", method: "POST", url: "https://api.nova-shop.cn/v2/auth/challenge?channel=app",
        headers: [{ name: "Content-Type", value: "application/json" }], body: "{\n  \"deviceId\": \"string\"\n}", bodyType: "json",
        folderPath: ["账号与鉴权"], sourceKey: "POST /v2/auth/challenge", sourceFingerprint: "d".repeat(64),
      },
      changedFields: ["name", "url", "body", "folder"], localOverride: true,
    },
    {
      kind: "remove",
      operationKey: "POST /v2/orders/prepay",
      draftId: "preview-draft-13", currentName: "创建预支付订单", currentMethod: "POST",
      currentUrl: "https://api.nova-shop.cn/v2/orders/prepay",
      changedFields: ["operation"], localOverride: true,
    },
  ],
};

export const initialRequestListItems: RequestListItem[] = initialRequests.map((request, index) => {
  const startedAt = Date.now() - (initialRequests.length - index) * 2_400;
  return {
    id: request.id,
    order: request.order,
    startedAt,
    completedAt: startedAt + request.duration,
    state: request.method === "CONNECT"
      ? "tunnel"
      : request.type === "sse" && request.responseBodyMetadata?.complete === false
        ? "streaming"
        : "complete",
    method: request.method,
    scheme: request.tls === "明文" ? "http" : "https",
    host: request.host,
    path: request.path,
    query: request.query,
    status: request.status,
    type: request.type,
    source: request.source,
    sourceInstanceId: request.source === "browser" ? "preview-browser" : `preview-${request.source}`,
    protocol: request.protocol,
    sizeBytes: parseDisplayBytes(request.size),
    durationMs: request.duration,
    risk: request.risk,
    hasHook: Boolean(request.hook),
    cryptoSnippetCount: request.cryptoSnippetCount,
    tlsIntercepted: request.tls !== "明文",
    tlsVersion: request.tls,
  };
});

export function createPreviewRequestWindow(offset: number, limit: number, total = 100_000) {
  const start = Math.max(0, Math.min(total, Math.floor(offset)));
  const count = Math.max(0, Math.min(Math.floor(limit), total - start));
  return Array.from({ length: count }, (_, index) => {
    const absoluteIndex = start + index;
    const seed = initialRequestListItems[absoluteIndex % initialRequestListItems.length];
    const order = absoluteIndex + 1;
    const startedAt = 1_785_393_200_000 + order * 10;
    return {
      ...seed,
      id: `preview-window-${order}`,
      order,
      startedAt,
      completedAt: seed.completedAt == null ? undefined : startedAt + (seed.durationMs ?? 0),
      sourceInstanceId: `${seed.sourceInstanceId}-${absoluteIndex % 8}`,
    } satisfies RequestListItem;
  });
}

function parseDisplayBytes(value: string) {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed)) return 0;
  if (/MB/i.test(value)) return Math.round(parsed * 1024 * 1024);
  if (/KB/i.test(value)) return Math.round(parsed * 1024);
  return Math.round(parsed);
}

export const sourceLabels: Record<SourceType, string> = {
  browser: "浏览器",
  desktop: "桌面应用",
  terminal: "终端",
  script: "脚本",
  mobile: "移动设备",
  iot: "IoT",
  reverse: "免代理接入",
};
