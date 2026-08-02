/**
 * Algorithm-replay export directory selection helpers.
 * UI must always obtain an explicit parent path before writing.
 */

export type ReplayExportDirectoryPick =
  | { status: "ok"; path: string }
  | { status: "cancel" }
  | { status: "error"; message: string };

/**
 * Normalize a directory picker result. `null` / empty = user cancel.
 * Inject `picker` in tests; production passes Tauri `open({ directory: true })`.
 */
export async function pickReplayExportDirectory(
  picker: () => Promise<string | string[] | null>,
): Promise<ReplayExportDirectoryPick> {
  try {
    const selected = await picker();
    if (selected == null) return { status: "cancel" };
    const path = Array.isArray(selected) ? selected[0] : selected;
    if (!path?.trim()) return { status: "cancel" };
    return { status: "ok", path: path.trim() };
  } catch (error) {
    return {
      status: "error",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}
