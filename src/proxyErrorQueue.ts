/**
 * Rate-limits proxy error toasts without losing any of them.
 *
 * The original guard was `if (now - last < 2500) return` — a plain drop. That
 * is fine when the only thing being dropped is a duplicate, and wrong as soon
 * as two *different* failures land close together: the second is discarded
 * purely because of when it arrived. A tunnel closing could swallow the
 * "连接 host:port 超时" that came 300 ms later, and nothing recorded that it had.
 *
 * So a message inside the window is held rather than dropped, and shown when
 * the window opens. Only the newest is kept — an older pending message is
 * already superseded — but the count is carried so the user can tell that more
 * happened than the one line in front of them.
 */
export const PROXY_ERROR_WINDOW_MS = 2500;

/** Longest toast the shell renders before it is cut short. */
export const PROXY_ERROR_MAX_LENGTH = 220;

export interface ProxyErrorQueueHost {
  /** Render a message. */
  show: (message: string) => void;
  now: () => number;
  schedule: (callback: () => void, delayMs: number) => number;
  cancel: (handle: number) => void;
}

export interface ProxyErrorQueue {
  push: (message: string) => void;
  /** Drops any pending flush. Safe to call more than once. */
  dispose: () => void;
}

export function truncateProxyError(message: string): string {
  return message.length > PROXY_ERROR_MAX_LENGTH
    ? `${message.slice(0, PROXY_ERROR_MAX_LENGTH)}…`
    : message;
}

export function createProxyErrorQueue(host: ProxyErrorQueueHost): ProxyErrorQueue {
  // Not 0: "never shown" has to read as infinitely long ago, or the first
  // message is held whenever the clock happens to start near zero.
  let lastShownAt = Number.NEGATIVE_INFINITY;
  let pending: string | null = null;
  let suppressed = 0;
  let flush: number | undefined;

  const render = (message: string, alsoSuppressed: number) => {
    lastShownAt = host.now();
    host.show(
      alsoSuppressed > 0
        ? `${truncateProxyError(message)}（另有 ${alsoSuppressed} 条）`
        : truncateProxyError(message),
    );
  };

  return {
    push(raw: string) {
      const message = String(raw ?? "").trim();
      if (!message) return;

      const sinceLast = host.now() - lastShownAt;
      if (sinceLast >= PROXY_ERROR_WINDOW_MS && flush === undefined) {
        render(message, 0);
        return;
      }

      // Inside the window: hold the newest and report the rest as a count.
      if (pending !== null) suppressed += 1;
      pending = message;

      if (flush === undefined) {
        flush = host.schedule(
          () => {
            flush = undefined;
            const held = pending;
            const extra = suppressed;
            pending = null;
            suppressed = 0;
            if (held !== null) render(held, extra);
          },
          Math.max(0, PROXY_ERROR_WINDOW_MS - sinceLast),
        );
      }
    },
    dispose() {
      if (flush !== undefined) {
        host.cancel(flush);
        flush = undefined;
      }
      pending = null;
      suppressed = 0;
    },
  };
}
