import { CheckCircle2, CircleAlert, Code2, Download, Info, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { t } from "../i18n.ts";
import { availableBodyModes, bodyHex, bodyPreviewPolicy, detectBodyKind, headerValue, legacyBodyMetadata, parseJsonBody, prettyBody, type BodyViewMode } from "../requestInspector";
import type { BodyCaptureMetadata, HeaderEntry } from "../types";
import { formatBytes } from "../format";

export function HttpBodyViewer({ content, headers, metadata: providedMetadata, filename, legacyMetadata: legacy = false }: { content?: string; headers: HeaderEntry[]; metadata?: BodyCaptureMetadata; filename: string; legacyMetadata?: boolean }) {
  const metadata = providedMetadata ?? legacyBodyMetadata(content);
  const kind = detectBodyKind(content, headers, metadata);
  const modes = useMemo(() => availableBodyModes(kind, metadata), [kind, metadata]);
  const [mode, setMode] = useState<BodyViewMode>(modes[0]);
  useEffect(() => { if (!modes.includes(mode)) setMode(modes[0]); }, [mode, modes]);
  const value = content ?? "";
  const parsed = kind === "json" ? parseJsonBody(value) : undefined;
  const contentType = headerValue(headers, "content-type") ?? t("traffic.body.unknownType");
  const labels: Record<BodyViewMode, string> = { pretty: "Pretty", tree: "Tree", raw: "Raw", wire: "Wire/Base64", hex: "Hex", preview: "Preview" };
  return <div className="body-viewer">
    <HttpBodyStatus metadata={metadata} />
    <HttpBodyMetadataGrid metadata={metadata} legacy={legacy} />
    <div className="body-viewer-toolbar"><div className="body-mode-tabs">{modes.map((item) => <button key={item} className={mode === item ? "is-active" : ""} onClick={() => setMode(item)}>{labels[item]}</button>)}</div><span>{kind.toUpperCase()} · {contentType}</span><button className="icon-button" onClick={() => downloadBody(value, filename, contentType)} disabled={!value} title={t("traffic.body.save")}><Download size={14} /></button></div>
    {!value ? <div className="detail-empty"><Code2 size={20} /><span>{metadata.omittedReason ? t("traffic.body.omitted") : t("traffic.body.empty")}</span></div> : <div className="body-viewer-content">
      {mode === "pretty" && <CodeBlock content={prettyBody(value, kind)} />}
      {mode === "tree" && parsed !== undefined && <JsonTree value={parsed} />}
      {mode === "raw" && <CodeBlock content={value} />}
      {mode === "wire" && <CodeBlock content={value} />}
      {mode === "hex" && <CodeBlock content={bodyHex(value)} />}
      {mode === "preview" && <SafeBodyPreview content={value} contentType={contentType} kind={kind} metadata={metadata} />}
    </div>}
  </div>;
}

export function HttpBodyMetadataGrid({ metadata, legacy = false }: { metadata: BodyCaptureMetadata; legacy?: boolean }) {
  return <div className="body-metadata-grid"><span>captured <strong>{String(metadata.captured)}</strong></span><span>decoded <strong>{String(metadata.decoded)}</strong></span><span>truncated <strong>{String(metadata.truncated)}</strong></span><span>complete <strong>{String(metadata.complete)}</strong></span><span>wireBytes <strong>{metadata.wireBytes}</strong></span><span>decodedBytes <strong>{metadata.decodedBytes}</strong></span>{metadata.error && <span className="is-error">error <strong>{metadata.error}</strong></span>}{legacy && <small>{t("traffic.body.legacyMeta")}</small>}</div>;
}

function JsonTree({ value, name, depth = 0 }: { value: unknown; name?: string; depth?: number }) {
  if (value === null || typeof value !== "object") return <div className="json-tree-leaf"><code>{name}</code><span>{JSON.stringify(value)}</span></div>;
  const entries = Object.entries(value as Record<string, unknown>);
  return <details className="json-tree-node" open={depth < 2}><summary>{name && <code>{name}</code>}<span>{Array.isArray(value) ? `Array(${entries.length})` : `Object(${entries.length})`}</span></summary><div>{entries.map(([key, child]) => <JsonTree key={key} value={child} name={key} depth={depth + 1} />)}</div></details>;
}

function SafeBodyPreview({ content, contentType, kind, metadata }: { content: string; contentType: string; kind: ReturnType<typeof detectBodyKind>; metadata: BodyCaptureMetadata }) {
  const policy = bodyPreviewPolicy(kind);
  if (policy === "image" && metadata.format === "base64") return <div className="safe-image-preview"><img src={`data:${contentType};base64,${content}`} alt={t("traffic.body.imageAlt")} /></div>;
  if (policy === "text-only") return <div className="unsafe-preview-note"><ShieldAlert size={15} /><span>{t("traffic.body.unsafePreview")}</span><CodeBlock content={content} /></div>;
  if (kind === "json") return <JsonTree value={parseJsonBody(content)} />;
  return <CodeBlock content={content} />;
}

export function HttpBodyStatus({ metadata }: { metadata: BodyCaptureMetadata }) {
  const omitted = Boolean(metadata.omittedReason);
  // Omission is the configured behaviour, not a fault: 保存二进制响应 is off by
  // default, so treating it as a warning put an alert icon on every image, font
  // and video in a fresh install — next to text saying nothing was affected.
  const warning = Boolean(metadata.error || metadata.truncated || !metadata.complete);
  const encoding = metadata.contentEncoding?.toUpperCase();
  const headline = omitted ? t("traffic.body.binaryOmitted") : encoding ? `${encoding} ${metadata.decoded ? t("traffic.body.decoded") : t("traffic.body.notDecoded")}` : metadata.format === "base64" ? t("traffic.body.binary") : t("traffic.body.captured");
  return <div className={`response-body-status ${warning ? "has-warning" : omitted ? "is-omitted" : "is-ready"}`}><span className="response-body-status__icon">{warning ? <CircleAlert size={14} /> : omitted ? <Info size={14} /> : <CheckCircle2 size={14} />}</span><div><strong>{headline}</strong><span><em>{formatBytes(metadata.wireBytes)} {t("traffic.body.wire")}</em>{metadata.decoded && <em>{formatBytes(metadata.decodedBytes)} {t("traffic.body.afterDecode")}</em>}{metadata.format === "base64" && <em>Base64</em>}{metadata.truncated && <em>{t("traffic.truncated")}</em>}{!metadata.complete && <em>{t("traffic.body.streamOpen")}</em>}</span>{omitted && <small>{t("traffic.body.omittedHint")}</small>}{!omitted && metadata.error && <small>{metadata.error}</small>}</div></div>;
}

function CodeBlock({ content }: { content: string }) { return <pre className="code-block">{content}</pre>; }
function downloadBody(content: string, filename: string, contentType: string) { const url = URL.createObjectURL(new Blob([content], { type: contentType })); const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 0); }
