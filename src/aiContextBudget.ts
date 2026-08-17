/**
 * The AI context window and the prompt budget derived from it.
 *
 * Every constant here mirrors one in the Rust backend — `DEFAULT/MIN/MAX_AI_CONTEXT_TOKENS`
 * in `src-tauri/src/models.rs` and `PROMPT_BYTES_PER_TOKEN` / `MIN_PROMPT_BYTES` /
 * `MAX_PROMPT_BYTES` in `src-tauri/src/analysis.rs`. The backend decides the real
 * budget; anything the UI shows has to be computed the same way or it is a claim
 * the product does not honour.
 */

/** Mirrors `DEFAULT_AI_CONTEXT_TOKENS` — about 100 KiB of prompt budget. */
export const DEFAULT_AI_CONTEXT_TOKENS = 51_200;
export const LEGACY_DEFAULT_AI_CONTEXT_TOKENS = 200_000;
export const MIN_AI_CONTEXT_TOKENS = 1_024;
export const MAX_AI_CONTEXT_TOKENS = 2_000_000;

const PROMPT_BYTES_PER_TOKEN = 2;
const MIN_PROMPT_BYTES = 32 * 1024;
const MAX_PROMPT_BYTES = 8 * 1024 * 1024;

export function clampContextTokens(value: number): number {
  if (!Number.isFinite(value)) return DEFAULT_AI_CONTEXT_TOKENS;
  const truncated = Math.trunc(value);
  const remapped = truncated === LEGACY_DEFAULT_AI_CONTEXT_TOKENS
    ? DEFAULT_AI_CONTEXT_TOKENS
    : truncated;
  return Math.min(MAX_AI_CONTEXT_TOKENS, Math.max(MIN_AI_CONTEXT_TOKENS, remapped));
}

/** Mirrors `prompt_byte_budget` in src-tauri/src/analysis.rs. */
export function promptBudgetBytes(contextTokens: number): number {
  const scaled = clampContextTokens(contextTokens) * PROMPT_BYTES_PER_TOKEN;
  return Math.min(MAX_PROMPT_BYTES, Math.max(MIN_PROMPT_BYTES, scaled));
}

export function formatContextTokens(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(value % 1_000_000 === 0 ? 0 : 1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(value % 1_000 === 0 ? 0 : 1)}K`;
  return String(value);
}
