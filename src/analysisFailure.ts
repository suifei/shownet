/**
 * Turn a stored analysis error — formatted lines, a Responses API event, or a
 * gateway wrapper — into fields the failed-report UI can show. The HTTP status
 * is not the cause; `code` / `type` / `message` are, when present.
 */

export interface AnalysisFailureInfo {
  headline: string;
  detail: string;
  code?: string;
  type?: string;
  model?: string;
  event?: string;
  httpStatus?: string;
}

interface ProviderFields {
  code?: string;
  type?: string;
  message?: string;
  model?: string;
  event?: string;
  status?: string;
}

export function parseAnalysisFailure(raw: string): AnalysisFailureInfo {
  const text = raw.trim();
  if (!text) {
    return { headline: "分析未完成", detail: "分析未完成" };
  }
  const fromJson = fieldsFromUnknown(text);
  const fromLines = fieldsFromFormattedLines(text);
  const fields = mergeFields(fromLines, fromJson);
  if (fields.code || fields.type || fields.message || fields.event === "response.failed") {
    return toInfo(fields, text);
  }
  const http = text.match(/HTTP\s+(\d{3})/i)?.[1];
  return {
    headline: "分析未完成",
    detail: text,
    httpStatus: http,
  };
}

function toInfo(fields: ProviderFields, fallback: string): AnalysisFailureInfo {
  return {
    headline: headlineFor(fields.code, fields.type),
    detail: fields.message?.trim() || fallback,
    code: fields.code,
    type: fields.type,
    model: fields.model,
    event: fields.event,
    httpStatus: fields.status?.match(/^\d{3}$/) ? fields.status : undefined,
  };
}

function headlineFor(code?: string, type?: string): string {
  if (code === "context_length_exceeded") return "分析未完成：上下文超出模型窗口";
  if (code) return `分析未完成：${code}`;
  if (type === "invalid_request_error") return "分析未完成：请求被拒绝";
  return "分析未完成";
}

function fieldsFromFormattedLines(text: string): ProviderFields {
  const field = (label: string) => {
    const match = text.match(new RegExp(`^${label}：(.+)$`, "m"));
    return match?.[1]?.trim() || undefined;
  };
  const http = text.match(/^HTTP：(\d{3})/m)?.[1];
  return {
    code: field("错误码"),
    type: field("类型"),
    message: field("说明"),
    model: field("模型"),
    event: field("事件"),
    status: http,
  };
}

function fieldsFromUnknown(text: string): ProviderFields | undefined {
  const value = parseEmbeddedJson(text);
  return value ? fieldsFromValue(value, 0) : undefined;
}

function fieldsFromValue(value: unknown, depth: number): ProviderFields | undefined {
  if (depth > 3 || !value || typeof value !== "object") return undefined;
  const record = value as Record<string, unknown>;
  const response = isRecord(record.response) ? record.response : undefined;
  const errorNode = firstRecord(response?.error, record.error, asRecord(record.data)?.error);
  let fields: ProviderFields = errorNode ? fieldsFromErrorNode(errorNode, depth) : {};
  const event = asString(record.type);
  const model = asString(response?.model) ?? asString(record.model);
  const status = asString(response?.status) ?? asString(record.status);
  fields = {
    ...fields,
    event: fields.event ?? event,
    model: fields.model ?? model,
    status: fields.status ?? status,
  };
  return fields.code || fields.type || fields.message || fields.event === "response.failed"
    ? fields
    : undefined;
}

function fieldsFromErrorNode(node: unknown, depth: number): ProviderFields {
  if (typeof node === "string") {
    const nested = parseEmbeddedJson(node);
    return nested ? fieldsFromValue(nested, depth + 1) ?? { message: node } : { message: node };
  }
  if (!isRecord(node)) return {};
  let fields: ProviderFields = {
    code: asString(node.code),
    type: asString(node.type),
    message: asString(node.message),
  };
  const raw = isRecord(node.metadata) ? asString(node.metadata.raw) : undefined;
  if (raw) {
    const nested = parseEmbeddedJson(raw);
    const inner = nested ? fieldsFromValue(nested, depth + 1) : undefined;
    if (inner) fields = mergeFields(fields, inner);
  }
  if (fields.message) {
    const nested = parseEmbeddedJson(fields.message);
    const inner = nested ? fieldsFromValue(nested, depth + 1) : undefined;
    if (inner) fields = mergeFields(fields, inner);
  }
  return fields;
}

function mergeFields(base: ProviderFields, overlay?: ProviderFields): ProviderFields {
  if (!overlay) return base;
  return {
    code: overlay.code ?? base.code,
    type: overlay.type ?? base.type,
    message: overlay.message ?? base.message,
    model: overlay.model ?? base.model,
    event: overlay.event ?? base.event,
    status: overlay.status ?? base.status,
  };
}

function parseEmbeddedJson(text: string): unknown {
  const trimmed = text.trim();
  try {
    const value = JSON.parse(trimmed) as unknown;
    if (value && typeof value === "object") return value;
  } catch {
    /* fall through to a slice between the first and last braces */
  }
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start < 0 || end <= start) return undefined;
  try {
    return JSON.parse(trimmed.slice(start, end + 1)) as unknown;
  } catch {
    return undefined;
  }
}

function firstRecord(...values: unknown[]): Record<string, unknown> | undefined {
  for (const value of values) {
    const record = asRecord(value);
    if (record) return record;
  }
  return undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

function asString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return undefined;
}
