/**
 * Classify HTTP status for the traffic grid / detail so users can tell
 * ShowNet proxy failures (502 + 连接/出口…) from origin 4xx/5xx.
 */

import { t } from "./i18n.ts";

export type TrafficStatusKind =
  | "pending"
  | "proxy"
  | "origin4xx"
  | "origin5xx"
  | "success"
  | "redirect"
  | "other";

export interface TrafficStatusPresentation {
  kind: TrafficStatusKind;
  /** Short text for the status column */
  label: string;
  /** Tooltip / detail title */
  title: string;
  /** CSS suffix after `status-` (0–5 or special) */
  cssClass: string;
}

/** True when response body looks like a ShowNet-generated proxy/gateway error. */
export function looksLikeProxyErrorBody(body?: string | null): boolean {
  if (!body) return false;
  const text = body.trim();
  if (!text) return false;
  return (
    /连接\s+\S+:\d+\s*(超时|失败)/.test(text)
    || /出口\s+\S+:\d+/.test(text)
    || text.includes("目标 TLS")
    || text.includes("目标 HTTPS")
    || text.includes("出口代理")
    || text.includes("DNS 解析")
    || text.includes("代理循环")
    || text.includes("Bad Gateway")
  );
}

export function classifyTrafficStatus(
  status?: number | null,
  options?: { responseBody?: string | null; server?: string | null },
): TrafficStatusPresentation {
  if (status == null || status === 0) {
    return {
      kind: "pending",
      label: "…",
      title: t("traffic.status.pending"),
      cssClass: "0",
    };
  }

  const body = options?.responseBody;
  const server = options?.server?.trim();

  if (status === 502 || status === 504) {
    const proxyLike = status === 502 && (looksLikeProxyErrorBody(body) || body == null || body === "");
    if (proxyLike || looksLikeProxyErrorBody(body)) {
      const snippet = body?.trim().slice(0, 160) || t("traffic.status.proxyFallback");
      return {
        kind: "proxy",
        label: t("traffic.status.proxyLabel", { status }),
        title: t("traffic.status.proxyTitle", { snippet }),
        cssClass: "proxy",
      };
    }
  }

  if (status >= 400 && status < 500) {
    return {
      kind: "origin4xx",
      label: String(status),
      title: server
        ? t("traffic.status.origin4xxServer", { server })
        : t("traffic.status.origin4xx"),
      cssClass: "4",
    };
  }

  if (status >= 500) {
    return {
      kind: "origin5xx",
      label: String(status),
      title: server ? t("traffic.status.origin5xxServer", { server }) : t("traffic.status.origin5xx"),
      cssClass: "5",
    };
  }

  if (status >= 300 && status < 400) {
    return {
      kind: "redirect",
      label: String(status),
      title: t("traffic.status.redirect"),
      cssClass: "3",
    };
  }

  if (status >= 200 && status < 300) {
    return {
      kind: "success",
      label: String(status),
      title: t("traffic.status.success"),
      cssClass: "2",
    };
  }

  return {
    kind: "other",
    label: String(status),
    title: `HTTP ${status}`,
    cssClass: String(Math.floor(status / 100)),
  };
}
