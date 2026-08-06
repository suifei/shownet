/**
 * Shared display formatting.
 *
 * Byte sizes had six implementations across five files with four different
 * conventions, so the same 5 000-byte body read "4.9 KB" in the request grid
 * and "5 KiB" in the analysis scope panel. Clock formatting had three, one of
 * which lacked a NaN guard and rendered "Invalid Date.NaN" for a frame with no
 * timestamp.
 */

/** Requests at or above this take the slow treatment, everywhere. */
export const SLOW_REQUEST_MS = 1_000;

/**
 * The grid highlight used `> 1000` while the 慢请求 filter used `>= 1000`, so a
 * request timed at exactly 1000 ms matched the filter but rendered unmarked.
 */
export function isSlowRequest(durationMs: number | null | undefined): boolean {
  return typeof durationMs === "number" && durationMs >= SLOW_REQUEST_MS;
}

/** Decimal (KB/MB/GB) byte size, matching what the grid and viewers show. */
export function formatBytes(bytes: number | null | undefined): string {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

/**
 * Denser variant for the request grid, where a column is ~70px wide: whole
 * numbers above 10 KB so the value never wraps.
 */
export function formatListBytes(bytes: number | null | undefined): string {
  if (typeof bytes !== "number" || !Number.isFinite(bytes) || bytes <= 0) return "0 B";
  if (bytes < 1024) return `${Math.round(bytes)} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb < 10 ? kb.toFixed(1) : Math.round(kb)} KB`;
  const mb = kb / 1024;
  return `${mb < 10 ? mb.toFixed(1) : Math.round(mb)} MB`;
}

/** Wall-clock time. Returns a placeholder rather than "Invalid Date" for bad input. */
export function formatClock(value: number | string | null | undefined, withMillis = false): string {
  if (value === null || value === undefined) return withMillis ? "--:--:--.---" : "--:--:--";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return withMillis ? "--:--:--.---" : "--:--:--";
  const clock = date.toLocaleTimeString("zh-CN", { hour12: false });
  return withMillis ? `${clock}.${String(date.getMilliseconds()).padStart(3, "0")}` : clock;
}

/**
 * Flatten GitHub release notes into readable plain text.
 *
 * The notes now come from a release body, which is Markdown — and with
 * `generate_release_notes` the body is a `## What's Changed` heading over a
 * bulleted list. The update dialog renders text, not Markdown, so without this
 * the user reads literal `##` and `**` and it looks broken.
 *
 * Deliberately not a Markdown renderer: it removes the syntax that would show
 * through and leaves everything else, including URLs, exactly as written.
 */
export function formatReleaseNotes(notes: string | null | undefined): string {
  if (!notes) return "";
  return notes
    .split("\n")
    // A table separator and a horizontal rule carry no text at all — they exist
    // to draw something this dialog cannot draw, so they are noise here. The
    // table's own rows read acceptably as pipe-separated columns and stay.
    .filter((line) => !/^\s*\|?[\s:|-]*\|[\s:|-]*\|?\s*$/.test(line) || !line.includes("-"))
    .filter((line) => !/^\s*([-*_])\s*(\1\s*){2,}$/.test(line))
    .map((line) => {
      const trimmed = line.trimEnd();
      // Headings become plain lines; the text is the point, the level is not.
      const heading = /^\s{0,3}#{1,6}\s+(.*)$/.exec(trimmed);
      if (heading) return heading[1].trim();
      // List markers become a bullet, so nesting still reads as a list.
      const item = /^(\s*)[-*+]\s+(.*)$/.exec(trimmed);
      const body = item ? `${item[1]}• ${item[2]}` : trimmed;
      return (
        body
          // Bold and italic markers, innermost first so `**a**` does not leave `*a*`.
          .replace(/\*\*([^*]+)\*\*/g, "$1")
          .replace(/__([^_]+)__/g, "$1")
          .replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1$2")
          // Inline code and links: keep the text, drop the punctuation.
          .replace(/`([^`\n]+)`/g, "$1")
          .replace(/\[([^\]\n]+)\]\(([^)\s]+)\)/g, "$1 ($2)")
      );
    })
    .join("\n")
    // Three or more blank lines is Markdown spacing, not intent.
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}
