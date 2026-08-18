/**
 * Command registry — the single searchable index of everything the app can do.
 *
 * The palette is the one place a user can reach any action without knowing which
 * view owns it, so matching has to work for three different ways people type:
 * the Chinese label, an English alias ("ca", "har", "proxy"), and the pinyin
 * initials of the label ("kbz" for 开始抓包). All three feed the same scorer.
 */

import { t, type MessageKey } from "./i18n.ts";

export type CommandGroupId = "start" | "capture" | "session" | "navigate" | "config";

export interface CommandAction {
  id: string;
  /** Visible label from the active language pack. */
  title: string;
  /** One line of "what this does" shown under the title. */
  subtitle?: string;
  group: CommandGroupId;
  /** English aliases and pinyin initials. Lowercase. */
  keywords?: string[];
  /** Rendered right-aligned, e.g. "⌘K". */
  shortcut?: string;
  /** Short status chip, e.g. "运行中" / "未安装". */
  badge?: string;
  badgeTone?: "neutral" | "ok" | "warn";
  disabled?: boolean;
  /** Shown instead of the subtitle when disabled, so dead controls explain themselves. */
  disabledReason?: string;
  run: () => void;
}

const COMMAND_GROUP_KEYS = {
  start: "cmd.group.start",
  capture: "cmd.group.capture",
  session: "cmd.group.session",
  navigate: "cmd.group.navigate",
  config: "cmd.group.config",
} as const satisfies Record<CommandGroupId, MessageKey>;

export const COMMAND_GROUP_LABELS: Record<CommandGroupId, string> = {
  get start() { return t(COMMAND_GROUP_KEYS.start); },
  get capture() { return t(COMMAND_GROUP_KEYS.capture); },
  get session() { return t(COMMAND_GROUP_KEYS.session); },
  get navigate() { return t(COMMAND_GROUP_KEYS.navigate); },
  get config() { return t(COMMAND_GROUP_KEYS.config); },
};

/** Render order for groups; anything unlisted falls to the end. */
const GROUP_ORDER: CommandGroupId[] = ["start", "capture", "session", "navigate", "config"];

/**
 * Subsequence match. Returns a score where higher is better, or -1 for no match.
 * A run of adjacent matches and a match at the very start both score higher, so
 * "导出" ranks 导出会话 above 重新导出上次结果.
 */
function subsequenceScore(haystack: string, needle: string): number {
  if (!needle) return 0;
  if (!haystack) return -1;
  let score = 0;
  let searchIndex = 0;
  let previousMatch = -2;
  for (const char of needle) {
    const found = haystack.indexOf(char, searchIndex);
    if (found === -1) return -1;
    // Adjacent characters mean the user typed a real substring, not a scatter.
    score += found === previousMatch + 1 ? 12 : 4;
    if (found === 0) score += 10;
    previousMatch = found;
    searchIndex = found + 1;
  }
  // Prefer tight matches: matching 4 chars of a 6-char label beats 4 of a 40-char one.
  return score + Math.max(0, 24 - haystack.length);
}

function bestFieldScore(action: CommandAction, needle: string): number {
  const title = subsequenceScore(action.title.toLowerCase(), needle);
  if (title >= 0) return title + 40;
  for (const keyword of action.keywords ?? []) {
    const score = subsequenceScore(keyword, needle);
    if (score >= 0) return score + 20;
  }
  return subsequenceScore((action.subtitle ?? "").toLowerCase(), needle);
}

/**
 * Filter and rank actions for a query. An empty query keeps registry order so the
 * palette opens on a stable, curated list rather than an arbitrary sort.
 */
export function filterCommands(actions: CommandAction[], query: string): CommandAction[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return actions;
  return actions
    .map((action, index) => ({ action, index, score: bestFieldScore(action, needle) }))
    .filter((entry) => entry.score >= 0)
    .sort((left, right) => right.score - left.score || left.index - right.index)
    .map((entry) => entry.action);
}

export interface CommandGroup {
  id: CommandGroupId;
  label: string;
  actions: CommandAction[];
}

/**
 * Bucket actions into rendered groups.
 *
 * With no query, the curated group order is what the user browses. Once they
 * type, that order actively fights the ranking: the best match for "ca" is
 * 安装 HTTPS 证书, which lives in the last group and would render below every
 * capture and session action. So a search orders groups by how well their
 * best member scored — which is the order `actions` already arrives in.
 */
export function groupCommands(actions: CommandAction[], byRelevance = false): CommandGroup[] {
  const buckets = new Map<CommandGroupId, CommandAction[]>();
  for (const action of actions) {
    const bucket = buckets.get(action.group);
    if (bucket) bucket.push(action);
    else buckets.set(action.group, [action]);
  }
  if (byRelevance) {
    // A Map preserves insertion order, which is the order each group's
    // best-scoring member appeared in.
    return [...buckets].map(([id, bucket]) => ({ id, label: COMMAND_GROUP_LABELS[id] ?? id, actions: bucket }));
  }

  const ordered: CommandGroup[] = [];
  for (const id of GROUP_ORDER) {
    const bucket = buckets.get(id);
    if (bucket?.length) ordered.push({ id, label: COMMAND_GROUP_LABELS[id], actions: bucket });
    buckets.delete(id);
  }
  for (const [id, bucket] of buckets) {
    ordered.push({ id, label: COMMAND_GROUP_LABELS[id] ?? id, actions: bucket });
  }
  return ordered;
}

/**
 * Flat, keyboard-navigable order matching what the grouped view renders, so
 * ArrowDown walks straight through group boundaries.
 */
export function flattenCommands(groups: CommandGroup[]): CommandAction[] {
  return groups.flatMap((group) => group.actions);
}

/** Move the highlight, skipping disabled rows so Enter always has a valid target. */
export function moveCommandCursor(actions: CommandAction[], current: number, offset: number): number {
  const enabled = actions.filter((action) => !action.disabled);
  if (!enabled.length) return current;
  const total = actions.length;
  for (let step = 1; step <= total; step += 1) {
    const next = (current + offset * step + total * step) % total;
    if (!actions[next]?.disabled) return next;
  }
  return current;
}
