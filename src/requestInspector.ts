import { t } from "./i18n.ts";
import type { BodyCaptureMetadata, HeaderEntry } from "./types";

export type InspectorLayout = "right" | "bottom" | "maximized";
export type BodyViewMode = "pretty" | "tree" | "raw" | "wire" | "hex" | "preview";
export type BodyKind = "empty" | "json" | "xml" | "html" | "javascript" | "css" | "image" | "binary" | "text";

export interface InspectorPreferences {
  version: 1;
  layout: InspectorLayout;
  rightWidth: number;
  bottomHeight: number;
}

export interface ParsedQueryEntry {
  name: string;
  value: string;
  duplicate: boolean;
  index: number;
}

export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Record<string, string | boolean>;
  source: "request" | "response";
}

export interface TimingEvidence {
  totalMs: number;
  phases: Array<{ label: string; durationMs: number }>;
  complete: boolean;
  note: string;
}

export const INSPECTOR_PREFERENCES_KEY = "shownet.request-inspector.preferences.v1";
const RIGHT_INSPECTOR_MIN_VIEWPORT = 1360;

export function defaultInspectorPreferences(viewportWidth = 1440): InspectorPreferences {
  return { version: 1, layout: viewportWidth < RIGHT_INSPECTOR_MIN_VIEWPORT ? "bottom" : "right", rightWidth: 390, bottomHeight: 360 };
}

export function parseInspectorPreferences(raw: string | null | undefined, viewportWidth = 1440): InspectorPreferences {
  const fallback = defaultInspectorPreferences(viewportWidth);
  if (!raw) return fallback;
  try {
    const value = JSON.parse(raw) as Partial<InspectorPreferences>;
    if (value.version !== 1 || !["right", "bottom", "maximized"].includes(String(value.layout))) return fallback;
    const layout = viewportWidth < RIGHT_INSPECTOR_MIN_VIEWPORT && value.layout === "right" ? "bottom" : value.layout as InspectorLayout;
    return {
      version: 1,
      layout,
      rightWidth: clamp(Number(value.rightWidth) || fallback.rightWidth, 320, 760),
      bottomHeight: clamp(Number(value.bottomHeight) || fallback.bottomHeight, 240, 720),
    };
  } catch {
    return fallback;
  }
}

export function parseQueryEntries(query: string | undefined): ParsedQueryEntry[] {
  if (!query) return [];
  const params = new URLSearchParams(query);
  const entries = [...params.entries()];
  const counts = new Map<string, number>();
  for (const [name] of entries) counts.set(name, (counts.get(name) ?? 0) + 1);
  return entries.map(([name, value], index) => ({ name, value, duplicate: (counts.get(name) ?? 0) > 1, index }));
}

export function parseCookies(headers: HeaderEntry[]): ParsedCookie[] {
  const cookies: ParsedCookie[] = [];
  for (const header of headers) {
    const lower = header.name.toLowerCase();
    if (lower === "cookie") {
      for (const pair of header.value.split(";")) {
        const [name, ...value] = pair.trim().split("=");
        if (name) cookies.push({ name, value: value.join("="), attributes: {}, source: "request" });
      }
    } else if (lower === "set-cookie") {
      const [pair, ...rawAttributes] = header.value.split(";");
      const [name, ...value] = pair.trim().split("=");
      if (!name) continue;
      const attributes: Record<string, string | boolean> = {};
      for (const rawAttribute of rawAttributes) {
        const [attributeName, ...attributeValue] = rawAttribute.trim().split("=");
        if (attributeName) attributes[attributeName.toLowerCase()] = attributeValue.length ? attributeValue.join("=") : true;
      }
      cookies.push({ name, value: value.join("="), attributes, source: "response" });
    }
  }
  return cookies;
}

export function headerValue(headers: HeaderEntry[], name: string) {
  return headers.find((header) => header.name.toLowerCase() === name.toLowerCase())?.value;
}

export function detectBodyKind(content: string | undefined, headers: HeaderEntry[], metadata?: BodyCaptureMetadata): BodyKind {
  if (!content) return "empty";
  const contentType = (headerValue(headers, "content-type") ?? "").toLowerCase();
  if (contentType.startsWith("image/")) return "image";
  if (metadata?.format === "base64" || metadata?.format === "omitted" || /octet-stream|application\/pdf|font\//.test(contentType)) return "binary";
  if (/json|\+json/.test(contentType) || looksLikeJson(content)) return "json";
  if (/xml|\+xml/.test(contentType) || /^\s*<\?xml\b/i.test(content)) return "xml";
  if (/html/.test(contentType) || /^\s*<!doctype html|^\s*<html\b/i.test(content)) return "html";
  if (/javascript|ecmascript/.test(contentType)) return "javascript";
  if (/text\/css/.test(contentType)) return "css";
  if (/^text\//.test(contentType) || !containsBinaryControl(content)) return "text";
  return "binary";
}

export function availableBodyModes(kind: BodyKind, metadata?: BodyCaptureMetadata): BodyViewMode[] {
  const modes: BodyViewMode[] = ["pretty", "raw"];
  if (kind === "json") modes.splice(1, 0, "tree");
  if (kind === "binary" || kind === "image" || metadata?.format === "base64") modes.push("wire", "hex");
  else modes.push("hex");
  if (["json", "xml", "text", "image"].includes(kind)) modes.push("preview");
  if (kind === "html" || kind === "javascript" || kind === "css") modes.push("preview");
  return [...new Set(modes)];
}

export function prettyBody(content: string, kind: BodyKind) {
  if (kind !== "json") return content;
  try { return JSON.stringify(JSON.parse(content), null, 2); } catch { return content; }
}

export function parseJsonBody(content: string): unknown | undefined {
  try { return JSON.parse(content) as unknown; } catch { return undefined; }
}

export function bodyHex(content: string, maxBytes = 128 * 1024) {
  const bytes = new TextEncoder().encode(content).slice(0, maxBytes);
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const slice = bytes.slice(offset, offset + 16);
    const hex = [...slice].map((byte) => byte.toString(16).padStart(2, "0")).join(" ").padEnd(47, " ");
    const ascii = [...slice].map((byte) => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : ".").join("");
    lines.push(`${offset.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  return lines.join("\n");
}

export function legacyBodyMetadata(content: string | undefined): BodyCaptureMetadata {
  const bytes = content ? new TextEncoder().encode(content).byteLength : 0;
  return {
    captured: Boolean(content),
    decoded: true,
    truncated: false,
    complete: true,
    wireBytes: bytes,
    decodedBytes: bytes,
    format: content ? "text" : "empty",
  };
}

export function bodyPreviewPolicy(kind: BodyKind) {
  if (kind === "html" || kind === "javascript" || kind === "css") return "text-only" as const;
  if (kind === "image") return "image" as const;
  return "structured-text" as const;
}

export function timingEvidence(totalMs: number): TimingEvidence {
  return {
    totalMs: Math.max(0, Math.round(totalMs)),
    phases: [],
    complete: false,
    note: t("traffic.timingNote"),
  };
}

function looksLikeJson(content: string) {
  const trimmed = content.trim();
  if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) return false;
  try { JSON.parse(trimmed); return true; } catch { return false; }
}

function containsBinaryControl(content: string) {
  return /[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(content.slice(0, 4096));
}

function clamp(value: number, minimum: number, maximum: number) {
  return Math.min(maximum, Math.max(minimum, value));
}
