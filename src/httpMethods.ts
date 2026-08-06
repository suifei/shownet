/**
 * The two method sets, which are deliberately different.
 *
 * They were written out in four places and drifted: the observable union was
 * missing HEAD (so a captured HEAD request had no valid type), and the Lab's
 * builder offered HEAD but the filter chips did not.
 */

/**
 * Methods that can appear in captured traffic. CONNECT is here because the
 * proxy sees tunnel setups; it is not something a user composes.
 */
export const OBSERVABLE_METHODS = [
  "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "CONNECT",
] as const;

export type ObservableMethod = (typeof OBSERVABLE_METHODS)[number];

/**
 * Methods the request builder offers. CONNECT is excluded on purpose: hand-
 * building a tunnel request is not a thing the Lab can meaningfully send.
 */
export const BUILDABLE_METHODS = [
  "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
] as const;

export type BuildableMethod = (typeof BUILDABLE_METHODS)[number];

/** Methods offered as one-click chips in the traffic toolbar. */
export const QUICK_FILTER_METHODS = ["GET", "POST", "PUT", "DELETE"] as const;
