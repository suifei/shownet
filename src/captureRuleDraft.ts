import type { CaptureRule } from "./types";

export type RuleStage = "connection" | "request" | "response";
export type RuleActionKind = "mirror" | "rewrite" | "redirect" | "delay" | "throttle" | "block" | "breakpoint";
export type MirrorIdentity = "original" | "target";
export type RuleOperationTarget = "request.header" | "query" | "request.body" | "response.header" | "response.status" | "response.body";

export interface RuleOperationDraft {
  id: string;
  target: RuleOperationTarget;
  operation: "set" | "delete" | "replace";
  name: string;
  value: string;
  pattern: string;
}

export interface RuleDraft {
  name: string;
  priority: number;
  stage: RuleStage;
  field: string;
  operator: string;
  matchValue: string;
  actionKind: RuleActionKind;
  operations: RuleOperationDraft[];
  targetTemplate: string;
  redirectExcludePattern: string;
  redirectPreserveHost: boolean;
  redirectPreserveCredentials: boolean;
  redirectAllowInsecureDowngrade: boolean;
  latencyMs: number;
  jitterMs: number;
  uploadKbps: number;
  downloadKbps: number;
  packetLossPercent: number;
  breakpointTimeoutSeconds: number;
  breakpointOnTimeout: "continue" | "abort";
  mirrorTargetHost: string;
  mirrorTargetPort: string;
  mirrorIdentity: MirrorIdentity;
}

const NUMERIC_MATCH_OPERATORS = new Set(["gt", "gte", "lt", "lte"]);
const MANAGED_HEADERS = new Set([
  "connection", "content-length", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
]);

function operationId() {
  return typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `rule-operation-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function byteLength(value: string) {
  return new TextEncoder().encode(value).length;
}

const MAX_BODY_PREFILL_BYTES = 60 * 1024;

function editableRequestBody(request?: { requestBody?: string }) {
  const body = request?.requestBody;
  if (body == null || body.startsWith("base64:") || byteLength(body) > MAX_BODY_PREFILL_BYTES) return "";
  return body;
}

export const createEmptyRuleOperation = (stage: RuleStage): RuleOperationDraft => ({
  id: operationId(), target: stage === "response" ? "response.header" : "request.header",
  operation: "set", name: stage === "response" ? "X-Response-Debug" : "X-Debug", value: "1", pattern: "",
});

export const createEmptyRuleDraft = (): RuleDraft => ({
  name: "", priority: 100, stage: "request", field: "host", operator: "contains",
  matchValue: "", actionKind: "rewrite", operations: [createEmptyRuleOperation("request")],
  targetTemplate: "{{path}}", redirectExcludePattern: "", redirectPreserveHost: false,
  redirectPreserveCredentials: false, redirectAllowInsecureDowngrade: false,
  latencyMs: 250, jitterMs: 0, uploadKbps: 0,
  downloadKbps: 0, packetLossPercent: 0, breakpointTimeoutSeconds: 120,
  breakpointOnTimeout: "continue", mirrorTargetHost: "", mirrorTargetPort: "",
  mirrorIdentity: "original",
});

export function changeRuleDraftOperationTarget(
  draft: RuleDraft,
  operationId: string,
  target: RuleOperationTarget,
  request?: { host?: string; requestBody?: string },
): RuleDraft {
  const host = request?.host?.trim();
  const requestBody = target === "request.body" ? editableRequestBody(request) : "";
  const next = {
    ...draft,
    operations: draft.operations.map((operation) => operation.id === operationId ? {
      ...operation,
      target,
      operation: "set" as const,
      name: "",
      value: requestBody,
      pattern: "",
    } : operation),
  };
  if (draft.stage !== "request" || target !== "request.body" || !host) return next;
  return {
    ...next,
    name: draft.name.trim() ? draft.name : `${[...host].slice(0, 110).join("")} 请求正文改写`,
    matchValue: draft.matchValue.trim() || draft.field !== "host" ? draft.matchValue : host,
  };
}

export function changeRuleDraftStage(draft: RuleDraft, stage: RuleStage): RuleDraft {
  const field = stage === "connection"
    ? "host"
    : stage === "response"
    ? "status"
    : draft.field === "status" || draft.field === "responseHeader" ? "host" : draft.field;
  const actionKind = stage === "connection"
    ? "mirror"
    : stage === "response"
      ? draft.actionKind === "breakpoint" ? "breakpoint" : "rewrite"
      : draft.actionKind === "mirror" ? "rewrite" : draft.actionKind;
  return {
    ...draft,
    stage,
    field,
    operator: stage === "connection" ? "wildcard" : field !== "status" && NUMERIC_MATCH_OPERATORS.has(draft.operator) ? "equals" : draft.operator,
    actionKind,
    operations: [createEmptyRuleOperation(stage)],
  };
}

export function prefillMirrorDraftFromRequest(
  draft: RuleDraft,
  request?: { host?: string },
): RuleDraft {
  const host = request?.host?.trim();
  if (draft.stage !== "connection" || !host) return draft;
  const suggestedName = `${[...host].slice(0, 117).join("")} 镜像`;
  return {
    ...draft,
    name: draft.name.trim() ? draft.name : suggestedName,
    matchValue: draft.matchValue.trim() ? draft.matchValue : host,
  };
}

export function captureRuleActionFromDraft(draft: RuleDraft): Record<string, unknown> {
  if (draft.actionKind === "mirror") {
    const action: Record<string, unknown> = {
      kind: "mirror",
      targetHost: draft.mirrorTargetHost.trim(),
      identity: draft.mirrorIdentity,
    };
    if (draft.mirrorTargetPort.trim()) action.targetPort = Number(draft.mirrorTargetPort);
    return action;
  }
  if (draft.actionKind === "breakpoint") return {
    kind: "breakpoint",
    timeoutMs: draft.breakpointTimeoutSeconds * 1000,
    onTimeout: draft.breakpointOnTimeout,
  };
  if (draft.actionKind === "redirect") return {
    kind: "redirect",
    targetTemplate: draft.targetTemplate.trim(),
    ...(draft.redirectExcludePattern.trim() ? { excludePattern: draft.redirectExcludePattern.trim() } : {}),
    ...(draft.redirectPreserveHost ? { preserveHost: true } : {}),
    ...(draft.redirectPreserveCredentials ? { preserveCredentials: true } : {}),
    ...(draft.redirectAllowInsecureDowngrade ? { allowInsecureDowngrade: true } : {}),
  };
  if (draft.actionKind === "delay") return { kind: "delay", latencyMs: draft.latencyMs, jitterMs: draft.jitterMs };
  if (draft.actionKind === "throttle") return {
    kind: "throttle", latencyMs: draft.latencyMs, jitterMs: draft.jitterMs,
    uploadKbps: draft.uploadKbps, downloadKbps: draft.downloadKbps,
    packetLossPercent: draft.packetLossPercent,
  };
  if (draft.actionKind === "block") return { kind: "block", direction: "outbound" };
  return { kind: "rewrite", operations: draft.operations.map((operation) => {
    const output: Record<string, unknown> = { target: operation.target, op: operation.operation };
    if (["request.header", "query", "response.header"].includes(operation.target)) output.name = operation.name;
    if (["request.body", "response.body"].includes(operation.target) && operation.operation === "replace") output.pattern = operation.pattern;
    if (operation.operation !== "delete") output.value = operation.target === "response.status" ? Number(operation.value) : operation.value;
    return output;
  }) };
}

export function captureRuleDraftValidationError(draft: RuleDraft): string | undefined {
  const name = draft.name.trim();
  if (!name) return "请输入规则名称";
  if ([...name].length > 120) return "规则名称不能超过 120 个字符";
  if (!Number.isInteger(draft.priority) || draft.priority < -10000 || draft.priority > 10000) return "优先级必须是 -10000 到 10000 的整数";
  if (draft.operator !== "exists" && !draft.matchValue.trim()) return "请输入匹配值";
  if (draft.operator === "regex" && byteLength(draft.matchValue) > 256) return "匹配正则不能超过 256 字节";
  if (NUMERIC_MATCH_OPERATORS.has(draft.operator) && draft.field !== "status") return "数值比较只适用于响应状态";

  if (draft.actionKind === "mirror") {
    if (draft.stage !== "connection") return "镜像只支持连接阶段";
    if (!validMirrorHost(draft.mirrorTargetHost)) return "镜像目标只填写有效主机或 IP，不包含协议、路径、端口或通配符";
    if (draft.mirrorTargetPort.trim() && (!/^\d+$/.test(draft.mirrorTargetPort.trim()) || Number(draft.mirrorTargetPort) < 1 || Number(draft.mirrorTargetPort) > 65535)) return "镜像目标端口必须在 1 到 65535 之间";
    return undefined;
  }

  if (draft.actionKind === "breakpoint") {
    if (!Number.isInteger(draft.breakpointTimeoutSeconds) || draft.breakpointTimeoutSeconds < 5 || draft.breakpointTimeoutSeconds > 300) return "断点等待时间必须是 5 到 300 秒的整数";
    return undefined;
  }

  if (draft.actionKind === "redirect") {
    if (draft.stage !== "request") return "请求转发只支持请求阶段";
    if (!draft.targetTemplate.trim()) return "请输入转发目标 URL";
    if (byteLength(draft.targetTemplate) > 4096) return "转发目标不能超过 4096 字节";
    if (!validRedirectTargetTemplate(draft.targetTemplate)) return "转发目标必须是同源路径或有效的 HTTP(S) URL，且不能包含凭据或片段";
    if (byteLength(draft.redirectExcludePattern) > 4096) return "排除 URL 不能超过 4096 字节";
    return undefined;
  }
  if (draft.actionKind === "delay") {
    if (draft.stage !== "request") return "延迟只支持请求阶段";
    if (!validDelay(draft.latencyMs, draft.jitterMs)) return "固定延迟与随机抖动之和不能超过 30000 ms";
    return undefined;
  }
  if (draft.actionKind === "throttle") {
    if (draft.stage !== "request") return "弱网条件只支持请求阶段";
    if (!validDelay(draft.latencyMs, draft.jitterMs)) return "弱网延迟与抖动之和不能超过 30000 ms";
    if (![draft.uploadKbps, draft.downloadKbps].every((value) => Number.isInteger(value) && (value === 0 || (value >= 8 && value <= 1000000)))) return "上行和下行带宽必须为 0 或 8 到 1000000 Kbps";
    if (!Number.isFinite(draft.packetLossPercent) || draft.packetLossPercent < 0 || draft.packetLossPercent > 100) return "丢包率必须在 0% 到 100% 之间";
    if (![draft.latencyMs, draft.jitterMs, draft.uploadKbps, draft.downloadKbps, draft.packetLossPercent].some((value) => value > 0)) return "弱网条件至少需要一项有效限制";
    return undefined;
  }
  if (draft.actionKind === "block") return draft.stage === "request" ? undefined : "出站阻断只支持请求阶段";

  if (!draft.operations.length || draft.operations.length > 50) return "重写规则必须包含 1 到 50 个操作";
  for (const [index, operation] of draft.operations.entries()) {
    const number = index + 1;
    const requestTarget = draft.stage === "request" && ["request.header", "query", "request.body"].includes(operation.target);
    const responseTarget = draft.stage === "response" && ["response.header", "response.status", "response.body"].includes(operation.target);
    if (!requestTarget && !responseTarget) return `操作 ${number} 与当前阶段不匹配`;
    if (["request.header", "query", "response.header"].includes(operation.target)) {
      const operationName = operation.name.trim();
      if (!operationName) return `请输入操作 ${number} 的名称`;
      if (byteLength(operationName) > 1024) return `操作 ${number} 的名称不能超过 1024 字节`;
      if (operation.target !== "query") {
        if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(operationName)) return `操作 ${number} 的 Header 名称无效`;
        const normalized = operationName.toLowerCase();
        if (MANAGED_HEADERS.has(normalized) || (draft.stage === "request" && normalized === "host") || (draft.stage === "response" && normalized === "content-encoding")) return `${operationName} 由代理自动维护`;
      }
    }
    if (operation.target === "response.status") {
      const status = Number(operation.value);
      if (!Number.isInteger(status) || status < 100 || status > 599) return `操作 ${number} 的响应状态必须在 100 到 599 之间`;
    }
    if (["request.body", "response.body"].includes(operation.target) && operation.operation === "replace") {
      if (!operation.pattern) return `请输入操作 ${number} 的正文匹配正则`;
      if (byteLength(operation.pattern) > 256) return `操作 ${number} 的正文正则不能超过 256 字节`;
    }
  }
  const encoded = new TextEncoder().encode(JSON.stringify(captureRuleActionFromDraft(draft)));
  return encoded.length <= 64 * 1024 ? undefined : "规则动作不能超过 64 KiB";
}

export function isCaptureRuleDraftValid(draft: RuleDraft) {
  return captureRuleDraftValidationError(draft) === undefined;
}

function validDelay(latencyMs: number, jitterMs: number) {
  return Number.isInteger(latencyMs) && Number.isInteger(jitterMs)
    && latencyMs >= 0 && jitterMs >= 0 && latencyMs + jitterMs <= 30000;
}

function validMirrorHost(input: string) {
  const value = input.trim();
  if (!value || new TextEncoder().encode(value).length > 253 || /[\/@#?*%]/.test(value) || value.includes("://")) return false;
  try {
    const authority = value.includes(":") && !value.startsWith("[") ? `[${value}]` : value;
    const parsed = new URL(`http://${authority}/`);
    return !!parsed.hostname && !parsed.port && !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}

export function captureRuleDraftFromRule(rule: CaptureRule): RuleDraft | undefined {
  if (!(["connection", "request", "response"] as const).includes(rule.stage) || rule.matcher.kind !== "predicate") return undefined;
  const base: RuleDraft = {
    ...createEmptyRuleDraft(), name: rule.name, priority: rule.priority, stage: rule.stage, field: rule.matcher.field,
    operator: rule.matcher.operator, matchValue: rule.matcher.value == null ? "" : String(rule.matcher.value),
    operations: [createEmptyRuleOperation(rule.stage)],
  };
  const kind = String(rule.action.kind ?? "");
  if (kind === "mirror" && rule.stage === "connection") return {
    ...base,
    actionKind: "mirror",
    mirrorTargetHost: String(rule.action.targetHost ?? ""),
    mirrorTargetPort: rule.action.targetPort == null ? "" : String(rule.action.targetPort),
    mirrorIdentity: rule.action.identity === "target" ? "target" : "original",
  };
  if (kind === "breakpoint") {
    const timeoutMs = Number(rule.action.timeoutMs ?? 120_000);
    const onTimeout = rule.action.onTimeout === "abort" ? "abort" : "continue";
    const timeoutSeconds = Math.min(300, Math.max(5, Math.round(timeoutMs / 1000)));
    return { ...base, actionKind: "breakpoint", breakpointTimeoutSeconds: timeoutSeconds, breakpointOnTimeout: onTimeout };
  }
  if (kind === "redirect" && rule.stage === "request") return {
    ...base,
    actionKind: "redirect",
    targetTemplate: String(rule.action.targetTemplate ?? ""),
    redirectExcludePattern: String(rule.action.excludePattern ?? ""),
    redirectPreserveHost: rule.action.preserveHost === true,
    redirectPreserveCredentials: rule.action.preserveCredentials === true,
    redirectAllowInsecureDowngrade: rule.action.allowInsecureDowngrade === true,
  };
  if (kind === "delay" && rule.stage === "request") return { ...base, actionKind: "delay", latencyMs: Number(rule.action.latencyMs ?? 0), jitterMs: Number(rule.action.jitterMs ?? 0) };
  if (kind === "throttle" && rule.stage === "request") return {
    ...base, actionKind: "throttle", latencyMs: Number(rule.action.latencyMs ?? 0), jitterMs: Number(rule.action.jitterMs ?? 0),
    uploadKbps: Number(rule.action.uploadKbps ?? 0), downloadKbps: Number(rule.action.downloadKbps ?? 0),
    packetLossPercent: Number(rule.action.packetLossPercent ?? 0),
  };
  if (kind === "block" && rule.stage === "request") return { ...base, actionKind: "block" };
  if (kind !== "rewrite" || !Array.isArray(rule.action.operations) || !rule.action.operations.length || rule.action.operations.length > 50) return undefined;
  const operations = rule.action.operations.map((item): RuleOperationDraft | undefined => {
    const operation = item as Record<string, unknown>;
    const target = String(operation.target ?? "") as RuleOperationTarget;
    const requestTarget = rule.stage === "request" && ["request.header", "query", "request.body"].includes(target);
    const responseTarget = rule.stage === "response" && ["response.header", "response.status", "response.body"].includes(target);
    if (!requestTarget && !responseTarget) return undefined;
    const op = String(operation.op ?? "set") as RuleOperationDraft["operation"];
    const allowed = ["request.body", "response.body"].includes(target) ? ["set", "replace"] : target === "response.status" ? ["set"] : ["set", "delete"];
    if (!allowed.includes(op)) return undefined;
    return {
      id: operationId(), target, operation: op, name: String(operation.name ?? ""),
      value: String(operation.value ?? ""), pattern: String(operation.pattern ?? ""),
    };
  });
  if (operations.some((operation) => !operation)) return undefined;
  return { ...base, actionKind: "rewrite", operations: operations as RuleOperationDraft[] };
}

function validRedirectTargetTemplate(input: string) {
  const template = input.trim();
  if (!template || template.includes("\\")) return false;
  const rendered = template
    .replace(/\{\{scheme\}\}/g, "https")
    .replace(/\{\{host\}\}/g, "api.example.test")
    .replace(/\{\{port\}\}/g, "443")
    .replace(/\{\{path\}\}/g, "/v1/items")
    .replace(/\{\{query\}\}/g, "page=1");
  try {
    const target = rendered.startsWith("/")
      ? new URL(rendered, "https://api.example.test/")
      : new URL(rendered);
    return ["http:", "https:"].includes(target.protocol)
      && !!target.hostname
      && !target.username
      && !target.password
      && !target.hash;
  } catch {
    return false;
  }
}
