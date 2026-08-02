import type { AnalysisMode, RequestListItem } from "./types";

export interface AnalysisScopeEstimate {
  requestCount: number;
  hookCount: number;
  codeCount: number;
  annotationCount: number;
  estimatedBytes: number;
}

interface AnalysisScopeOptions {
  mode: AnalysisMode;
  includeStatic: boolean;
  manualScope: boolean;
  manualRequestIds: string[];
  includeAnnotations: boolean;
}

export function estimateAnalysisScope(
  requests: RequestListItem[],
  options: AnalysisScopeOptions,
): AnalysisScopeEstimate {
  const manualIds = new Set(options.manualRequestIds);
  const keyRequests = requests.filter((request) =>
    request.risk !== "none" || request.hasHook || (request.status ?? 0) >= 400,
  );
  const scope = options.manualScope
    ? manualIds.size
      ? requests.filter((request) => manualIds.has(request.id))
      : keyRequests
    : requests.length < 20 || options.mode === "performance" || options.includeStatic
      ? requests
      : requests.filter((request) =>
        ["xhr", "fetch", "websocket"].includes(request.type)
        || (request.status ?? 0) >= 400
        || ["POST", "PUT", "PATCH", "DELETE"].includes(request.method)
        || request.hasHook
        || request.cryptoSnippetCount > 0
        || request.risk !== "none",
      );
  const selected = scope.slice(0, 120);
  const hookCount = selected.filter((request) => request.hasHook).length;
  const codeCount = selected.reduce((sum, request) => sum + request.cryptoSnippetCount, 0);
  const annotationCount = options.includeAnnotations
    ? selected.filter((request) => request.annotation).length
    : 0;
  const requestPayload = selected.reduce(
    (sum, request) => sum + 1_100 + Math.min(Math.max(request.sizeBytes, 0), 32 * 1024),
    0,
  );
  const estimatedBytes = Math.min(
    480 * 1024,
    12 * 1024 + requestPayload + hookCount * 4 * 1024 + codeCount * 6 * 1024 + annotationCount * 512,
  );
  return { requestCount: selected.length, hookCount, codeCount, annotationCount, estimatedBytes };
}

export function formatContextSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  return bytes < 1024 * 1024
    ? `${Math.ceil(bytes / 1024)} KiB`
    : `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}
