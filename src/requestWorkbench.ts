import type { HeaderEntry, RequestRecord } from "./types";
import { shellQuote } from "./shellQuote.ts";

export const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

export interface WorkbenchVariable {
  name: string;
  value: string;
  secret: boolean;
  enabled?: boolean;
  source: "active" | "global" | "builtin";
}

export interface ResolvedTemplate {
  value: string;
  maskedValue: string;
  unresolved: string[];
  used: Array<{ name: string; source: WorkbenchVariable["source"]; secret: boolean }>;
}

export interface CurlDraft {
  method: string;
  url: string;
  headers: HeaderEntry[];
  body: string;
}

export type DiffKind = "added" | "removed" | "changed";

export interface RequestDiffEntry {
  section: "request" | "response" | "transport" | "evidence";
  path: string;
  kind: DiffKind;
  before?: string;
  after?: string;
}

function enabledVariables(variables: WorkbenchVariable[]) {
  return variables.filter((variable) => variable.enabled !== false && variable.name.trim());
}

export function resolveTemplate(
  template: string,
  active: WorkbenchVariable[],
  global: WorkbenchVariable[],
  builtins: WorkbenchVariable[] = [],
): ResolvedTemplate {
  const variables = new Map<string, WorkbenchVariable>();
  for (const variable of [...enabledVariables(builtins), ...enabledVariables(global), ...enabledVariables(active)]) {
    variables.set(variable.name, variable);
  }
  const unresolved = new Set<string>();
  const used = new Map<string, { name: string; source: WorkbenchVariable["source"]; secret: boolean }>();
  const replace = (masked: boolean) => template.replace(/\{\{\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*\}\}/g, (token, name: string) => {
    const variable = variables.get(name);
    if (!variable) {
      unresolved.add(name);
      return token;
    }
    used.set(name, { name, source: variable.source, secret: variable.secret });
    return masked && variable.secret ? "••••••••" : variable.value;
  });
  return {
    value: replace(false),
    maskedValue: replace(true),
    unresolved: [...unresolved],
    used: [...used.values()],
  };
}

export function redactSecrets(value: string, variables: WorkbenchVariable[]) {
  return enabledVariables(variables)
    .filter((variable) => variable.secret && variable.value)
    .sort((left, right) => right.value.length - left.value.length)
    .reduce((result, variable) => result.split(variable.value).join("••••••••"), value);
}

export function sanitizeReplayHeaders(
  headers: HeaderEntry[],
  options: { includeCookie: boolean; includeAuthorization: boolean; bodyByteLength?: number },
) {
  const connectionTokens = headers
    .filter((header) => header.name.toLowerCase() === "connection")
    .flatMap((header) => header.value.split(","))
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);
  const blocked = new Set([...HOP_BY_HOP_HEADERS, ...connectionTokens]);
  const result = headers.filter((header) => {
    const name = header.name.trim().toLowerCase();
    if (!name || blocked.has(name) || name === "content-length" || name === "host") return false;
    if (!options.includeCookie && name === "cookie") return false;
    if (!options.includeAuthorization && (name === "authorization" || name === "proxy-authorization")) return false;
    return true;
  });
  if (options.bodyByteLength !== undefined) {
    result.push({ name: "Content-Length", value: String(Math.max(0, options.bodyByteLength)) });
  }
  return result;
}

export function draftToCurl(draft: CurlDraft) {
  const parts = ["curl", "--request", shellQuote(draft.method.toUpperCase()), shellQuote(draft.url)];
  for (const header of sanitizeReplayHeaders(draft.headers, {
    includeCookie: true,
    includeAuthorization: true,
    bodyByteLength: draft.body ? new TextEncoder().encode(draft.body).length : undefined,
  })) {
    parts.push("--header", shellQuote(`${header.name}: ${header.value}`));
  }
  if (draft.body) parts.push("--data-raw", shellQuote(draft.body));
  return parts.join(" ");
}

function tokenizeShell(input: string) {
  const tokens: string[] = [];
  let token = "";
  let quote: "'" | '"' | "" = "";
  let escaping = false;
  for (const character of input.trim()) {
    if (escaping) {
      token += character;
      escaping = false;
    } else if (character === "\\" && quote !== "'") {
      escaping = true;
    } else if (quote && character === quote) {
      quote = "";
    } else if (!quote && (character === "'" || character === '"')) {
      quote = character;
    } else if (!quote && /\s/.test(character)) {
      if (token) tokens.push(token);
      token = "";
    } else {
      token += character;
    }
  }
  if (quote) throw new Error("cURL 引号未闭合");
  if (escaping) token += "\\";
  if (token) tokens.push(token);
  return tokens;
}

export function parseCurl(input: string): CurlDraft {
  const tokens = tokenizeShell(input.replace(/\\\r?\n/g, " "));
  if (tokens[0]?.toLowerCase() !== "curl") throw new Error("请输入以 curl 开头的命令");
  const draft: CurlDraft = { method: "GET", url: "", headers: [], body: "" };
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index];
    const next = () => {
      index += 1;
      if (index >= tokens.length) throw new Error(`${token} 缺少参数`);
      return tokens[index];
    };
    if (token === "-X" || token === "--request") draft.method = next().toUpperCase();
    else if (token === "-H" || token === "--header") {
      const header = next();
      const separator = header.indexOf(":");
      if (separator <= 0) throw new Error(`Header 格式无效: ${header}`);
      draft.headers.push({ name: header.slice(0, separator).trim(), value: header.slice(separator + 1).trim() });
    } else if (["-d", "--data", "--data-raw", "--data-binary"].includes(token)) {
      draft.body = next();
      if (draft.method === "GET") draft.method = "POST";
    } else if (token.startsWith("http://") || token.startsWith("https://")) draft.url = token;
    else if (!token.startsWith("-") && !draft.url) draft.url = token;
  }
  if (!/^https?:\/\//i.test(draft.url)) throw new Error("cURL 必须包含 http:// 或 https:// URL");
  return draft;
}

function normalizedHeaders(headers: HeaderEntry[]) {
  const result: Record<string, string[]> = {};
  for (const header of headers) {
    const name = header.name.trim().toLowerCase();
    if (!name) continue;
    (result[name] ??= []).push(header.value);
  }
  return result;
}

function normalizedQuery(query: string | undefined) {
  const result: Record<string, string[]> = {};
  for (const [name, value] of new URLSearchParams(query ?? "")) {
    (result[name] ??= []).push(value);
  }
  return result;
}

function stableValue(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

function parseStructuredBody(body: string | undefined) {
  if (!body) return body ?? "";
  try { return JSON.parse(body) as unknown; } catch { return body; }
}

function collectDiff(
  section: RequestDiffEntry["section"],
  path: string,
  before: unknown,
  after: unknown,
  entries: RequestDiffEntry[],
  ignored: Set<string>,
) {
  if (ignored.has(path.toLowerCase())) return;
  if (Object.is(before, after)) return;
  if (Array.isArray(before) && Array.isArray(after) && JSON.stringify(before) === JSON.stringify(after)) return;
  if (before && after && typeof before === "object" && typeof after === "object" && !Array.isArray(before) && !Array.isArray(after)) {
    const left = before as Record<string, unknown>;
    const right = after as Record<string, unknown>;
    for (const key of [...new Set([...Object.keys(left), ...Object.keys(right)])].sort()) {
      collectDiff(section, path ? `${path}.${key}` : key, left[key], right[key], entries, ignored);
    }
    return;
  }
  entries.push({
    section,
    path,
    kind: before === undefined ? "added" : after === undefined ? "removed" : "changed",
    before: before === undefined ? undefined : stableValue(before),
    after: after === undefined ? undefined : stableValue(after),
  });
}

export function compareRequestRecords(
  before: RequestRecord,
  after: RequestRecord,
  ignoredPaths: string[] = [],
) {
  const entries: RequestDiffEntry[] = [];
  const ignored = new Set(ignoredPaths.map((path) => path.trim().toLowerCase()).filter(Boolean));
  const leftUrl = `${before.host}${before.path}${before.query ? `?${before.query}` : ""}`;
  const rightUrl = `${after.host}${after.path}${after.query ? `?${after.query}` : ""}`;
  collectDiff("request", "method", before.method, after.method, entries, ignored);
  collectDiff("request", "url", leftUrl, rightUrl, entries, ignored);
  collectDiff("request", "query", normalizedQuery(before.query), normalizedQuery(after.query), entries, ignored);
  collectDiff("request", "headers", normalizedHeaders(before.requestHeaders), normalizedHeaders(after.requestHeaders), entries, ignored);
  collectDiff("request", "body", parseStructuredBody(before.requestBody), parseStructuredBody(after.requestBody), entries, ignored);
  collectDiff("response", "status", before.status, after.status, entries, ignored);
  collectDiff("response", "headers", normalizedHeaders(before.responseHeaders), normalizedHeaders(after.responseHeaders), entries, ignored);
  collectDiff("response", "body", parseStructuredBody(before.responseBody), parseStructuredBody(after.responseBody), entries, ignored);
  collectDiff("transport", "protocol", before.protocol, after.protocol, entries, ignored);
  collectDiff("transport", "tls", before.tlsFingerprint ?? before.tls, after.tlsFingerprint ?? after.tls, entries, ignored);
  collectDiff("transport", "durationMs", before.duration, after.duration, entries, ignored);
  collectDiff("evidence", "hook", before.hook, after.hook, entries, ignored);
  return entries;
}
