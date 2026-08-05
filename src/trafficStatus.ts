/**
 * Classify HTTP status for the traffic grid / detail so users can tell
 * ShowNet proxy failures (502 + 连接/出口…) from origin 4xx/5xx.
 */

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
      title: "进行中或无状态码",
      cssClass: "0",
    };
  }

  const body = options?.responseBody;
  const server = options?.server?.trim();

  if (status === 502 || status === 504) {
    const proxyLike = status === 502 && (looksLikeProxyErrorBody(body) || body == null || body === "");
    if (proxyLike || looksLikeProxyErrorBody(body)) {
      const snippet = body?.trim().slice(0, 160) || "代理连接、出站 TLS 或上游失败";
      return {
        kind: "proxy",
        label: `${status}·代理`,
        title: `ShowNet 代理错误：${snippet}`,
        cssClass: "proxy",
      };
    }
  }

  if (status >= 400 && status < 500) {
    return {
      kind: "origin4xx",
      label: String(status),
      title: server
        ? `源站 4xx（Server: ${server}）— 非代理超时；静态 CDN 可试解密绕行`
        : "源站 4xx — 请求到达源站后被拒绝（如 CDN 400）；非本机连接超时",
      cssClass: "4",
    };
  }

  if (status >= 500) {
    return {
      kind: "origin5xx",
      label: String(status),
      title: server ? `源站 5xx（Server: ${server}）` : "源站 5xx 或网关错误",
      cssClass: "5",
    };
  }

  if (status >= 300 && status < 400) {
    return {
      kind: "redirect",
      label: String(status),
      title: "重定向",
      cssClass: "3",
    };
  }

  if (status >= 200 && status < 300) {
    return {
      kind: "success",
      label: String(status),
      title: "成功",
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
