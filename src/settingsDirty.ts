/**
 * Unsaved-change tracking for the settings sections.
 *
 * Settings has seven independent save buttons and no shared notion of "you have
 * edits pending". A section that is collapsed — which most are — gives no hint
 * that it holds unsaved edits at all, and leaving the view drops them silently.
 *
 * Dirtiness is computed by diffing the current value of a section against the
 * last value that came from (or went to) the backend. That baseline has to be
 * committed explicitly whenever the backend is the source of the change, which
 * is why `commitBaseline` exists rather than a plain first-render snapshot.
 */

export type SettingsBaselines = Record<string, string>;

/** Stable serialization, so key order in an object literal cannot fake an edit. */
export function serializeSectionValue(value: unknown): string {
  return JSON.stringify(value, (_key, entry: unknown) => {
    if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      const record = entry as Record<string, unknown>;
      return Object.keys(record).sort().reduce<Record<string, unknown>>((sorted, key) => {
        sorted[key] = record[key];
        return sorted;
      }, {});
    }
    return entry;
  }) ?? "null";
}

/**
 * Sections whose current value differs from their baseline, in the order the
 * caller listed them.
 *
 * A section with no baseline yet is never dirty: it has not been compared
 * against anything, and reporting it would light up the whole page on load.
 */
export function computeDirtySections(
  current: Record<string, string>,
  baselines: SettingsBaselines,
): string[] {
  return Object.keys(current).filter((id) => id in baselines && current[id] !== baselines[id]);
}

/**
 * Seed baselines for sections that do not have one yet, without touching those
 * that do — a later load must not silently adopt the user's in-progress edits.
 */
export function seedMissingBaselines(
  current: Record<string, string>,
  baselines: SettingsBaselines,
): SettingsBaselines {
  let next: SettingsBaselines | undefined;
  for (const [id, value] of Object.entries(current)) {
    if (id in baselines) continue;
    next ??= { ...baselines };
    next[id] = value;
  }
  return next ?? baselines;
}

export interface UnsavedSummary {
  count: number;
  /** Section ids, for jumping the user to the first one. */
  ids: string[];
}

export function summarizeUnsaved(dirtyIds: string[]): UnsavedSummary {
  return { count: dirtyIds.length, ids: dirtyIds };
}
