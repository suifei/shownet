/**
 * Built-in static CDN hosts that often return HTTP 400 under rustls MITM
 * (e.g. Baidu `pss.bdstatic.com` / JSP3). Must stay in sync with
 * `STATIC_CDN_BYPASS_PRESET` in `src-tauri/src/tls_interception.rs`.
 *
 * Bypassed hosts use end-to-end browser TLS — ShowNet does not decrypt bodies.
 */
export const STATIC_CDN_BYPASS_PRESET = ["*.bdstatic.com", "*.bcebos.com"] as const;

export function mergeStaticCdnBypassRules(existing: readonly string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const rule of existing) {
    const trimmed = rule.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(trimmed);
  }
  for (const rule of STATIC_CDN_BYPASS_PRESET) {
    const key = rule.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(rule);
  }
  return out;
}

export function staticCdnBypassRulesPresent(rules: readonly string[]): boolean {
  const lowered = new Set(rules.map((rule) => rule.trim().toLowerCase()).filter(Boolean));
  return STATIC_CDN_BYPASS_PRESET.every((rule) => lowered.has(rule.toLowerCase()));
}
